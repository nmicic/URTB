/*
 * URTB — PTY reference patterns
 *
 * This file is NOT compiled. It is a reference for implementing:
 *   - src/pty.c  (server side: spawn remote shell in PTY)
 *   - src/session.c (client side: put local terminal into raw mode)
 *
 * URTB PTY model:
 *   SERVER: forkpty() to spawn the shell. Master fd is the PTY master.
 *           Read from master → PTY_DATA frames → send to client.
 *           Write PTY_DATA from client → master fd → shell stdin.
 *   CLIENT: Put its OWN terminal into raw mode so keystrokes pass through.
 *           No forkpty() on the client. Client reads from STDIN_FILENO, sends
 *           as PTY_DATA frames. Receives PTY_DATA, writes to STDOUT_FILENO.
 */

/* ─── Platform includes ──────────────────────────────────────────────────── */

#ifdef __APPLE__
#include <util.h>        /* forkpty() on macOS */
#else
#include <pty.h>         /* forkpty() on Linux — needs -lutil or glibc >= 2.9 */
#endif

#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* ─── SERVER SIDE: spawn shell in PTY ──────────────────────────────────── */
/*
 * Call on the server when a PTY_OPEN frame arrives from the client.
 * The client sends the initial rows/cols in the PTY_OPEN payload.
 */

static int master_fd = -1;
static pid_t child_pid = -1;

/* Returns master_fd on success, -1 on failure. */
int pty_server_open(int rows, int cols)
{
    struct winsize ws = {
        .ws_row = (unsigned short)rows,
        .ws_col = (unsigned short)cols,
        .ws_xpixel = 0,
        .ws_ypixel = 0,
    };

    pid_t pid = forkpty(&master_fd, NULL, NULL, &ws);
    if (pid < 0) return -1;

    if (pid == 0) {
        /* Child: exec the user's shell */
        const char *shell = getenv("SHELL");
        if (!shell) shell = "/bin/sh";

        /* execl passes TERM from environment; set if not already set */
        if (!getenv("TERM")) setenv("TERM", "xterm-256color", 1);

        execl(shell, shell, (char *)NULL);
        perror("execl");
        _exit(127);
    }

    /* Parent: make master fd non-blocking */
    child_pid = pid;
    int flags = fcntl(master_fd, F_GETFL);
    if (flags >= 0) fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);

    return master_fd;
}

/* Forward PTY_DATA from client to the shell. */
int pty_server_write(const uint8_t *data, size_t len)
{
    const uint8_t *p = data;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(master_fd, p, remaining);
        if (n > 0) { p += n; remaining -= (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        return -1;
    }
    return (int)(len - remaining);
}

/* Read output from the shell to send as PTY_DATA to client.
 * Returns bytes read, 0 on EOF, -1 on EAGAIN/EINTR, -2 on error. */
int pty_server_read(uint8_t *buf, size_t len)
{
    ssize_t n = read(master_fd, buf, len);
    if (n > 0) return (int)n;
    if (n == 0) return 0;  /* EOF — shell exited */
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return -1;
    return -2;
}

/* Forward SIGWINCH from client: update PTY window size. */
void pty_server_resize(int rows, int cols)
{
    struct winsize ws = {
        .ws_row = (unsigned short)rows,
        .ws_col = (unsigned short)cols,
    };
    ioctl(master_fd, TIOCSWINSZ, &ws);
}

/* Clean shutdown: close PTY, reap child. */
void pty_server_close(void)
{
    if (child_pid > 1) {
        kill(-child_pid, SIGTERM);
        for (int i = 0; i < 6; i++) {       /* 300ms grace */
            usleep(50000);
            if (waitpid(child_pid, NULL, WNOHANG) != 0) goto reaped;
        }
        kill(-child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);         /* blocking reap after SIGKILL */
    }
reaped:
    if (master_fd >= 0) { close(master_fd); master_fd = -1; }
    child_pid = -1;
}

/* Check if child has exited. Returns true if still alive. */
int pty_server_alive(void)
{
    int status;
    pid_t r = waitpid(child_pid, &status, WNOHANG);
    if (r > 0 || (r < 0 && errno == ECHILD)) return 0;
    return 1;
}

/* ─── CLIENT SIDE: raw terminal mode ────────────────────────────────────── */
/*
 * On PTY_OPEN_ACK: call client_enter_raw() to put the local terminal into
 * raw mode so keystrokes pass through to the remote shell uninterpreted.
 *
 * On session end (PTY exit, CTRL_CLOSE, liveness timeout):
 * ALWAYS call client_leave_raw() before exiting — even from signal handlers.
 *
 * IMPORTANT: URTB does NOT switch to an alternate screen (no \033[?1049h).
 * The user's terminal emulator renders the remote shell output directly.
 * URTB is a transparent pipe — no overlay.
 */

static struct termios orig_termios;
static int raw_mode_active = 0;

void client_enter_raw(void)
{
    if (raw_mode_active) return;

    if (tcgetattr(STDIN_FILENO, &orig_termios) < 0) {
        perror("tcgetattr");
        return;
    }

    struct termios raw = orig_termios;
    /* Input flags: disable break, CR-to-NL, parity check, strip, XON/XOFF */
    raw.c_iflag &= ~(unsigned long)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    /* Output flags: disable post-processing */
    raw.c_oflag &= ~(unsigned long)(OPOST);
    /* Character size: 8 bits */
    raw.c_cflag |= CS8;
    /* Local flags: disable echo, canonical, extended, signals */
    raw.c_lflag &= ~(unsigned long)(ECHO | ICANON | IEXTEN | ISIG);
    /* Read: non-blocking (return immediately with whatever is available) */
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) {
        perror("tcsetattr");
        return;
    }
    raw_mode_active = 1;
}

void client_leave_raw(void)
{
    if (!raw_mode_active) return;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
    raw_mode_active = 0;
}

/* ─── CLIENT SIDE: SIGWINCH → PTY_WINCH frame ───────────────────────────── */
/*
 * When the client window is resized, SIGWINCH fires.
 * The handler queries the new size and sends a PTY_WINCH frame to the server.
 * The server calls pty_server_resize() on receipt.
 *
 * SIGWINCH handler (must be signal-safe — only sets a flag):
 */

static volatile sig_atomic_t winch_pending = 0;

static void sigwinch_handler(int sig) { (void)sig; winch_pending = 1; }

void client_setup_sigwinch(void)
{
    struct sigaction sa;
    sa.sa_handler = sigwinch_handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGWINCH, &sa, NULL);
}

/* Call this in the event loop when winch_pending is set. */
void client_handle_winch(int *rows_out, int *cols_out)
{
    winch_pending = 0;

    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *rows_out = ws.ws_row;
        *cols_out = ws.ws_col;
    }
    /* Caller sends a PTY_WINCH frame with the new rows/cols */
}

/* ─── CLIENT SIDE: initial terminal size ───────────────────────────────── */
/*
 * Send in the PTY_OPEN payload so the server opens the PTY at the right size.
 */
void client_get_terminal_size(int *rows_out, int *cols_out)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *rows_out = ws.ws_row;
        *cols_out = ws.ws_col;
    } else {
        *rows_out = 24;
        *cols_out = 80;
    }
}

/* ─── SIGPIPE handling ──────────────────────────────────────────────────── */
/*
 * Ignore SIGPIPE: write() returns -1/EPIPE instead of killing the process.
 * Set in main() before entering the event loop.
 */
void setup_signal_handlers(void)
{
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, NULL);

    client_setup_sigwinch();
}

/*
 * NOTE on static linking (Linux):
 *   forkpty() is in libutil on older glibc. On musl-libc (Alpine, musl-gcc),
 *   forkpty() is in libc.a directly. For static link with musl-gcc:
 *     LDFLAGS = -static   (no -lutil needed)
 *   For static link with glibc:
 *     LDFLAGS = -static -lutil
 *   On macOS: forkpty() is in libSystem (automatic, no extra flag).
 */
