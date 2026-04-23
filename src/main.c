/*
 * main.c — urtb subcommand dispatch
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Subcommands:
 *   urtb keygen [--out PATH]
 *   urtb listen  --transport unix --socket PATH [--capsule PATH]
 *   urtb listen  --exec "cmd args" [--capsule PATH]
 *   urtb connect --transport unix --socket PATH [--capsule PATH]
 *   urtb connect --exec "cmd args" [--capsule PATH]
 *
 * Default --capsule: ./pairing.capsule
 * Passphrase from terminal (or URTB_PASSPHRASE env var for tests).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
/* macOS hides cfmakeraw + SIGWINCH behind _DARWIN_C_SOURCE when
 * _POSIX_C_SOURCE is defined. */
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include "capsule.h"
#include "crypto.h"
#include "session.h"
#include "transport.h"
#include "channel.h"
#include "channel_pty.h"
#include "frame.h"
#if defined(URTB_TEST_INJECT) && URTB_TEST_INJECT
#include "test_inject.h"
#endif
#include <sys/stat.h>
#if URTB_OTP
#include "otp.h"
#endif

/* LoRa regional defaults — overridden at compile time via Makefile REGION knob.
 * See Makefile URTB_DEFS / PORTING.md "LoRa regional configuration". */
#ifndef URTB_LORA_FREQ_HZ
#  define URTB_LORA_FREQ_HZ  869875000U   /* EU868 g4 default */
#endif
#ifndef URTB_LORA_TXPOWER
#  define URTB_LORA_TXPOWER  7            /* EU868 g4, 7 dBm */
#endif

/* -------------------------------------------------------------------------
 * Client raw-mode + signal forwarding (B-3)
 * ---------------------------------------------------------------------- */

static struct termios g_saved_termios;
static int            g_termios_saved = 0;
static session_t     *g_client_session = NULL;

static void restore_termios_atexit(void)
{
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
        g_termios_saved = 0;
    }
}

static uint8_t * volatile g_wipe_psk = NULL;
static session_t * volatile g_active_session = NULL;

static void fatal_signal_handler(int sig)
{
    if (g_wipe_psk)
        crypto_memzero(g_wipe_psk, 32);
    if (g_active_session) {
        crypto_memzero(g_active_session->psk,         sizeof g_active_session->psk);
        crypto_memzero(g_active_session->hello_key,   sizeof g_active_session->hello_key);
        crypto_memzero(g_active_session->session_key, sizeof g_active_session->session_key);
    }
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
        g_termios_saved = 0;
    }
    _exit(128 + sig);
}

static void fault_signal_handler(int sig)
{
    if (g_wipe_psk)
        crypto_memzero(g_wipe_psk, 32);
    if (g_active_session) {
        crypto_memzero(g_active_session->psk,         sizeof g_active_session->psk);
        crypto_memzero(g_active_session->hello_key,   sizeof g_active_session->hello_key);
        crypto_memzero(g_active_session->session_key, sizeof g_active_session->session_key);
    }
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
        g_termios_saved = 0;
    }
    struct sigaction sa_dfl;
    memset(&sa_dfl, 0, sizeof sa_dfl);
    sa_dfl.sa_handler = SIG_DFL;
    sigaction(sig, &sa_dfl, NULL);
    raise(sig);
}

static int enter_raw_mode(void)
{
    if (!isatty(STDIN_FILENO)) {
        /* stdin not a tty (pipe/heredoc in tests) — nothing to do. */
        return 0;
    }
    if (tcgetattr(STDIN_FILENO, &g_saved_termios) != 0) {
        fprintf(stderr, "tcgetattr(stdin): %s\n", strerror(errno));
        return -1;
    }
    g_termios_saved = 1;
    atexit(restore_termios_atexit);

    struct termios raw = g_saved_termios;
    cfmakeraw(&raw);
    /* Keep OPOST? cfmakeraw turns it off which is correct for PTY. */
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
        fprintf(stderr, "tcsetattr(stdin raw): %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static volatile sig_atomic_t g_pending_sigint    = 0;
static volatile sig_atomic_t g_pending_sigwinch  = 0;
static volatile sig_atomic_t g_loop_should_exit  = 0;

/* Cycle 1: pointer to the session currently inside session_run on the
 * loop-mode listener path. handle_loop_exit sets its should_exit flag so
 * SIGTERM/SIGHUP can break out of an in-flight session, not just the
 * gap between sessions. NULL when no session is active. */
static session_t *g_loop_active_session = NULL;

static void handle_sigint(int sig)  { (void)sig; g_pending_sigint = 1; }
static void handle_sigwinch(int sig){ (void)sig; g_pending_sigwinch = 1; }
/* C-1: signal handler used in --loop mode to break the re-listen loop on
 * SIGTERM/SIGHUP without _exit'ing (so we still wipe PSK / munlock).
 * Cycle 1: also nudge an in-flight session toward CLOSING by setting its
 * should_exit flag, so a SIGTERM mid-PTY-session interrupts promptly via
 * EINTR-on-poll instead of running until the remote shell happens to
 * exit. The struct field is a plain int rather than sig_atomic_t, but the
 * write is a single store and session_run reads it on every loop tick. */
static void handle_loop_exit(int sig)
{
    (void)sig;
    g_loop_should_exit = 1;
    if (g_loop_active_session) g_loop_active_session->should_exit = 1;
}

/* Hook called by channel_pty.c when client receives PTY_OPEN_ACK. */
static void client_on_pty_ack(session_t *s)
{
    (void)s;
    if (g_termios_saved) return; /* already raw */
    if (enter_raw_mode() == 0) {
        fprintf(stderr, "urtb: entered raw mode\n");
    }
}

/* Session tick: pump pending SIGINT / SIGWINCH to the server. */
static void client_session_tick(session_t *s)
{
    if (g_pending_sigint) {
        g_pending_sigint = 0;
        channel_pty_client_send_signal(s, 2 /* SIGINT */);
    }
    if (g_pending_sigwinch) {
        g_pending_sigwinch = 0;
        struct winsize ws;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
            channel_pty_client_send_resize(s, ws.ws_row, ws.ws_col);
        }
    }
}

/* -------------------------------------------------------------------------
 * Transport registry lookup
 * ---------------------------------------------------------------------- */

const transport_ops_t *transport_find(const char *name)
{
    if (!name) return NULL;
    if (strcmp(name, "unix")   == 0) return &transport_unix;
    if (strcmp(name, "heltec") == 0) return &transport_heltec;
    if (strcmp(name, "stdio")  == 0) return &transport_stdio;
    return NULL;
}

/* -------------------------------------------------------------------------
 * Passphrase input (no echo via termios)
 * NEVER prints passphrase to stdout/stderr/log.
 * ---------------------------------------------------------------------- */

static char *read_passphrase(const char *prompt)
{
    /* Check env var first (for tests) */
    const char *env = getenv("URTB_PASSPHRASE");
    if (env) {
        /* EDGE-4 (Cycle 1): truncate at first newline so the env path matches
         * the tty path, which strips trailing \n via fgets. Without this, a
         * passphrase like "foo\n" via env vs "foo" via tty would derive
         * different capsule keys and fail to unlock. */
        size_t n = strcspn(env, "\n");
        /* bound env var to match interactive 255-char limit. */
        if (n > 255) {
            fprintf(stderr, "URTB_PASSPHRASE too long (>255 chars)\n");
            exit(2);
        }
        /* Allocate fixed 256-byte mlock'd buffer so  wipes a known size. */
        char *pp = malloc(256);
        if (!pp) return NULL;
        crypto_mlock(pp, 256);
        crypto_mark_dontdump(pp, 256);
        memset(pp, 0, 256);
        memcpy(pp, env, n);
        pp[n] = '\0';
        return pp;
    }

    /* Read from terminal with echo disabled */
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) tty = stdin;

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    struct termios old_tio, new_tio;
    int restore = 0;
    if (tcgetattr(fileno(tty), &old_tio) == 0) {
        new_tio = old_tio;
        new_tio.c_lflag &= ~(tcflag_t)ECHO;
        new_tio.c_lflag |= ECHONL;
        if (tcsetattr(fileno(tty), TCSAFLUSH, &new_tio) == 0)
            restore = 1;
    }

    char *buf = malloc(256);
    if (!buf) {
        if (restore) tcsetattr(fileno(tty), TCSAFLUSH, &old_tio);
        if (tty != stdin) fclose(tty);
        return NULL;
    }
    crypto_mlock(buf, 256);
    crypto_mark_dontdump(buf, 256);

    if (!fgets(buf, 256, tty)) {
        if (restore) tcsetattr(fileno(tty), TCSAFLUSH, &old_tio);
        if (tty != stdin) fclose(tty);
        crypto_memzero(buf, 256);
        crypto_munlock(buf, 256);
        free(buf);
        return NULL;
    }

    if (restore) tcsetattr(fileno(tty), TCSAFLUSH, &old_tio);
    if (tty != stdin) fclose(tty);

    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';
    if (len > 0 && buf[len - 1] == '\r') buf[--len] = '\0';

    return buf;
}

/* Wipe + munlock + free a passphrase buffer returned by read_passphrase.
 * Pairs each crypto_mlock(buf, 256) inside read_passphrase. Cycle 1 fix:
 * previously the free paths zeroed and freed the buffer without releasing
 * the mlock, leaking a locked page per failed/finished call. */
static void wipe_passphrase(char *pp)
{
    if (!pp) return;
    crypto_memzero(pp, 256);
    crypto_munlock(pp, 256);
    free(pp);
}

/* -------------------------------------------------------------------------
 * keygen subcommand
 * ---------------------------------------------------------------------- */

static int cmd_keygen(int argc, char *argv[])
{
    const char *out_path       = "./pairing.capsule";
    long        espnow_channel = 6;   /* v2 default; see DECISIONS.md D-40. */

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--espnow-channel") == 0 && i + 1 < argc) {
            char *end = NULL;
            espnow_channel = strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' ||
                espnow_channel < 1 || espnow_channel > 13) {
                fprintf(stderr,
                    "keygen: --espnow-channel must be an integer 1..13\n");
                return 1;
            }
        }
    }

    char *pass1 = read_passphrase("Enter passphrase: ");
    if (!pass1) {
        fprintf(stderr, "keygen: failed to read passphrase\n");
        return 1;
    }

    char *pass2 = read_passphrase("Confirm passphrase: ");
    if (!pass2) {
        fprintf(stderr, "keygen: failed to read passphrase confirmation\n");
        wipe_passphrase(pass1);
        return 1;
    }

    if (strcmp(pass1, pass2) != 0) {
        fprintf(stderr, "keygen: passphrases do not match\n");
        wipe_passphrase(pass1);
        wipe_passphrase(pass2);
        return 1;
    }

    /* EDGE-8 (Cycle 1): reject empty passphrase. Argon2id over an empty
     * input still produces a key, so the capsule would unlock with any
     * caller who also typed an empty passphrase — an effectively-public
     * capsule with no warning. */
    if (pass1[0] == '\0') {
        fprintf(stderr, "keygen: empty passphrase rejected\n");
        wipe_passphrase(pass1);
        wipe_passphrase(pass2);
        return 1;
    }

    int r = capsule_generate(out_path, pass1, (uint8_t)espnow_channel);

    wipe_passphrase(pass1);
    wipe_passphrase(pass2);

    if (r != 0) {
        fprintf(stderr, "keygen: failed\n");
        return 1;
    }

    fprintf(stderr, "keygen: capsule written to %s\n", out_path);
    fprintf(stderr, "keygen: PAIR_ID derived from PSK "
                    "(no separate backup needed)\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * OTP key management subcommands (C5-2)
 * ---------------------------------------------------------------------- */

#if URTB_OTP

static char *expand_home(const char *path)
{
    if (path[0] != '~' || path[1] != '/')
        return strdup(path);
    const char *home = getenv("HOME");
    if (!home) return strdup(path);
    size_t hlen = strlen(home);
    size_t plen = strlen(path + 1);
    char *out = malloc(hlen + plen + 1);
    if (!out) return NULL;
    memcpy(out, home, hlen);
    memcpy(out + hlen, path + 1, plen + 1);
    return out;
}

static void mkpath(const char *path, mode_t mode)
{
    char *tmp = strdup(path);
    if (!tmp) return;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, mode);
            *p = '/';
        }
    }
    free(tmp);
}

static int cmd_otp_init(int argc, char *argv[])
{
    const char *type_str = "hotp";
    const char *out_raw  = "~/.config/urtb/otp.key";

    int force = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc)
            type_str = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_raw = argv[++i];
        else if (strcmp(argv[i], "--force") == 0)
            force = 1;
    }

    int otp_type;
    if (strcmp(type_str, "hotp") == 0)
        otp_type = OTP_TYPE_HOTP;
    else if (strcmp(type_str, "totp") == 0)
        otp_type = OTP_TYPE_TOTP;
    else {
        fprintf(stderr, "otp-init: unknown type '%s' (use hotp or totp)\n", type_str);
        return 1;
    }

    char *out_path = expand_home(out_raw);
    if (!out_path) {
        fprintf(stderr, "otp-init: memory allocation failed\n");
        return 1;
    }

    mkpath(out_path, 0700);

    otp_key_t key;
    memset(&key, 0, sizeof(key));
    key.type     = otp_type;
    key.seed_len = 20;
    key.counter  = 0;
    key.window   = (otp_type == OTP_TYPE_HOTP) ? 20 : 1;

    if (crypto_random_bytes(key.seed, 20) != 0) {
        fprintf(stderr, "otp-init: failed to generate random seed\n");
        free(out_path);
        return 1;
    }

    if (!force && access(out_path, F_OK) == 0) {
        fprintf(stderr,
            "otp-init: key file already exists: %s\n"
            "  Use --force to overwrite (existing key will be permanently lost).\n",
            out_path);
        crypto_memzero(&key, sizeof key);
        free(out_path);
        return 1;
    }

    if (otp_key_save(out_path, &key) != 0) {
        fprintf(stderr, "otp-init: failed to write key file %s\n", out_path);
        free(out_path);
        return 1;
    }

    char b32[64];
    base32_encode(key.seed, 20, b32, sizeof(b32));

    printf("OTP key written to: %s\n\n", out_raw);
    printf("Scan this URI with your authenticator app (Google Authenticator,\n"
           "Proton Authenticator, Microsoft Authenticator, Aegis, FreeOTP+):\n\n");

    if (otp_type == OTP_TYPE_HOTP) {
        printf("  otpauth://hotp/urtb?secret=%s&counter=0&issuer=urtb&digits=6\n\n", b32);
        printf("Or enter manually:\n"
               "  Type   : HOTP (counter-based)\n"
               "  Account: urtb\n"
               "  Secret : %s\n"
               "  Counter: 0\n\n", b32);
    } else {
        printf("  otpauth://totp/urtb?secret=%s&issuer=urtb&digits=6&period=30\n\n", b32);
        printf("Or enter manually:\n"
               "  Type   : TOTP (time-based)\n"
               "  Account: urtb\n"
               "  Secret : %s\n\n", b32);
    }

    printf("Keep the key file on this machine only. Never transfer it.\n");

    crypto_memzero(&key, sizeof(key));
    free(out_path);
    return 0;
}

static int cmd_otp_verify(int argc, char *argv[])
{
    const char *otp_path_arg = NULL;
    const char *code_str = NULL;
    int print_mode = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--otp") == 0 && i + 1 < argc)
            otp_path_arg = argv[++i];
        else if (strcmp(argv[i], "--code") == 0 && i + 1 < argc)
            code_str = argv[++i];
        else if (strcmp(argv[i], "--print") == 0)
            print_mode = 1;
    }

    if (!otp_path_arg) {
        fprintf(stderr, "otp-verify: --otp PATH is required\n");
        return 1;
    }
    if (!code_str && !print_mode) {
        fprintf(stderr, "otp-verify: exactly one of --code or --print is required\n");
        return 1;
    }
    if (code_str && print_mode) {
        fprintf(stderr, "otp-verify: --code and --print are mutually exclusive\n");
        return 1;
    }

    char *expanded = expand_home(otp_path_arg);
    if (!expanded) {
        fprintf(stderr, "otp-verify: memory allocation failed\n");
        return 1;
    }

    int rc;
    if (print_mode)
        rc = otp_print_next(expanded);
    else
        rc = otp_verify(expanded, code_str);

    free(expanded);
    return rc == 0 ? 0 : 1;
}

#endif /* URTB_OTP */

/* -------------------------------------------------------------------------
 * secure_unlink: overwrite then unlink — best-effort defense-in-depth
 * ---------------------------------------------------------------------- */

static int secure_unlink(const char *path)
{
    int fd = open(path, O_WRONLY);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > 0) {
            uint8_t zeros[256];
            memset(zeros, 0, sizeof zeros);
            off_t rem = st.st_size;
            while (rem > 0) {
                ssize_t n = write(fd, zeros,
                                  rem < (off_t)sizeof zeros
                                      ? (size_t)rem : sizeof zeros);
                if (n <= 0) break;
                rem -= n;
            }
            fsync(fd);
        }
        close(fd);
    } else {
        fprintf(stderr, "burn: warning: could not overwrite %s before deletion"
                        " (%s) — content may be recoverable\n",
                path, strerror(errno));
    }
    if (unlink(path) != 0) {
        fprintf(stderr, "burn: failed to delete %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    fprintf(stderr, "burn: %s deleted\n", path);
    return 0;
}

/* -------------------------------------------------------------------------
 * listen/connect shared: load capsule, open transport, run session
 * ---------------------------------------------------------------------- */

static int cmd_session(int argc, char *argv[], int is_listen)
{
    const char *capsule_path = "./pairing.capsule";
    const char *transport_name = NULL;
    const char *socket_path = NULL;
    const char *exec_str = NULL;
    const char *device_path = NULL;
    int loop_mode = 0;
    int burn_mode = 0;
#if URTB_OTP
    const char *otp_path = NULL;
#endif

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--capsule") == 0 && i + 1 < argc) {
            capsule_path = argv[++i];
        } else if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc) {
            transport_name = argv[++i];
        } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (strcmp(argv[i], "--exec") == 0 && i + 1 < argc) {
            exec_str = argv[++i];
        } else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            device_path = argv[++i];
            if (!transport_name) transport_name = "heltec";
        } else if (strcmp(argv[i], "--loop") == 0) {
            loop_mode = 1;
        } else if (strcmp(argv[i], "--burn") == 0) {
            burn_mode = 1;
#if URTB_OTP
        } else if (strcmp(argv[i], "--otp") == 0 && i + 1 < argc) {
            otp_path = argv[++i];
#endif
        }
    }

    /* --otp silently ignored on connect (per spec) */
#if URTB_OTP
    if (otp_path && !is_listen)
        otp_path = NULL;
#endif

    /* --loop only makes sense for listeners */
    if (loop_mode && !is_listen) {
        fprintf(stderr, "session: --loop is only valid for 'listen'\n");
        return 1;
    }

    /* Infer transport from flags if not set */
    if (!transport_name) {
        if (exec_str)       transport_name = "stdio";
        else if (socket_path) transport_name = "unix";
        else {
            fprintf(stderr, "session: no transport specified (use --transport or --exec)\n");
            return 1;
        }
    }

    /* Read passphrase */
    char *passphrase = read_passphrase("Passphrase: ");
    if (!passphrase) {
        fprintf(stderr, "session: failed to read passphrase\n");
        return 1;
    }

    /* Load capsule */
    uint8_t psk[32]     = {0};
    uint8_t pair_id[4]  = {0};
    uint8_t capsule_channel = 0;
    crypto_mlock(psk, 32);
    crypto_mark_dontdump(psk, 32);
    g_wipe_psk = psk;

    if (capsule_load(capsule_path, passphrase, psk, pair_id,
                     &capsule_channel) != 0) {
        fprintf(stderr, "session: failed to load capsule %s\n", capsule_path);
        wipe_passphrase(passphrase);
        crypto_munlock(psk, 32);
        crypto_memzero(psk, 32);
        return 1;
    }

    wipe_passphrase(passphrase);
    passphrase = NULL;

    if (burn_mode) {
        fprintf(stderr,
            "burn: deleting capsule %s — key material is now in memory only.\n"
            "  WARNING: this cannot be undone. Ensure a backup exists elsewhere.\n",
            capsule_path);
        if (secure_unlink(capsule_path) != 0) {
            crypto_munlock(psk, 32);
            crypto_memzero(psk, 32);
            g_wipe_psk = NULL;
            return 1;
        }
    }

    /* Open transport */
    const transport_ops_t *ops = transport_find(transport_name);
    if (!ops) {
        fprintf(stderr, "session: unknown transport '%s'\n", transport_name);
        crypto_munlock(psk, 32);
        crypto_memzero(psk, 32);
        return 1;
    }

    transport_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.transport = transport_name;
    cfg.path      = socket_path;
    cfg.listen    = is_listen;
    cfg.exec      = exec_str;
    cfg.tty_device = device_path;
    cfg.tty_baud  = 115200;
    /* propagate pair_id and defaults for heltec USB_CONFIG. */
    memcpy(cfg.pair_id, pair_id, 4);
    cfg.lora_freq_hz   = URTB_LORA_FREQ_HZ;
    cfg.lora_sf        = 7;
    cfg.lora_bw        = 7;
    cfg.lora_cr        = 5;
    cfg.lora_txpower   = URTB_LORA_TXPOWER;
    /* D-40: channel is sealed inside the capsule. v1 capsules default
     * to 6; v2 capsules carry 1..13 chosen at keygen. */
    cfg.espnow_channel = capsule_channel;
    /* ESP-NOW broadcast: the host has no way to know either Heltec's MAC.
     * Use the L2 broadcast address so esp_now_send delivers to every device
     * on the same WiFi channel; the firmware still gates incoming frames by
     * PAIR_ID (on_espnow_recv), and AEAD with hello_key/session_key gates
     * the host. Without this, an all-zero peer_mac causes esp_now_send to
     * silently fail and the device falls over to LoRa half-duplex, where
     * the protocol's simultaneous CTRL_READY exchange deterministically
     * collides on the air. */
    memset(cfg.peer_mac, 0xFF, 6);

    /* C-1: install signal handlers ONCE, before the loop. For client mode
     * these are the existing SIGINT/SIGWINCH forwarders + fatal handlers.
     * For listen+loop mode we install a non-fatal SIGTERM/SIGHUP handler so
     * we can break the loop cleanly (and still wipe PSK / munlock). */
    if (!is_listen) {
        /* Install signal handlers (do NOT exit urtb on SIGINT — forward it) */
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_sigint;
        sigaction(SIGINT, &sa, NULL);
        sa.sa_handler = handle_sigwinch;
        sigaction(SIGWINCH, &sa, NULL);

        /* SIGHUP/SIGTERM/SIGQUIT → restore termios then _exit(128+sig).
         * SA_RESETHAND so a second signal delivers default action if we hang
         * in the handler for any reason. */
        struct sigaction fsa;
        memset(&fsa, 0, sizeof(fsa));
        fsa.sa_handler = fatal_signal_handler;
        fsa.sa_flags   = SA_RESETHAND;
        sigemptyset(&fsa.sa_mask);
        sigaction(SIGHUP,  &fsa, NULL);
        sigaction(SIGTERM, &fsa, NULL);
        sigaction(SIGQUIT, &fsa, NULL);

        /* Ensure stdin is non-blocking so pump_stdin drains without stalling */
        int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (flags >= 0) fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    } else if (loop_mode) {
        /* C-1: loop-mode listener installs a graceful SIGTERM/SIGHUP handler
         * so the do/while loop can exit cleanly and wipe the PSK. */
        struct sigaction lsa;
        memset(&lsa, 0, sizeof(lsa));
        lsa.sa_handler = handle_loop_exit;
        sigemptyset(&lsa.sa_mask);
        sigaction(SIGTERM, &lsa, NULL);
        sigaction(SIGHUP,  &lsa, NULL);
        sigaction(SIGINT,  &lsa, NULL);
        sigaction(SIGQUIT, &lsa, NULL);
    } else {
        struct sigaction lsa;
        memset(&lsa, 0, sizeof(lsa));
        lsa.sa_handler = fatal_signal_handler;
        lsa.sa_flags   = SA_RESETHAND;
        sigemptyset(&lsa.sa_mask);
        sigaction(SIGTERM, &lsa, NULL);
        sigaction(SIGHUP,  &lsa, NULL);
        sigaction(SIGQUIT, &lsa, NULL);
    }

    {
        struct sigaction flt;
        memset(&flt, 0, sizeof(flt));
        flt.sa_handler = fault_signal_handler;
        flt.sa_flags   = SA_RESETHAND;
        sigemptyset(&flt.sa_mask);
        sigaction(SIGSEGV, &flt, NULL);
        sigaction(SIGBUS,  &flt, NULL);
        sigaction(SIGFPE,  &flt, NULL);
    }

#if defined(URTB_TEST_INJECT) && URTB_TEST_INJECT
    /* Test build only: open the loopback control socket so a sibling
     * `urtb test-inject --pid <pid> ...` invocation can flip RF failure
     * bits in the firmware mid-session. The socket is mode 0600 and
     * SO_PEERCRED-checked. */
    (void)test_inject_setup();
#endif

#if URTB_OTP
    otp_key_t *burn_otp_key_template = NULL;
    if (burn_mode && otp_path) {
        char *expanded_otp = expand_home(otp_path);
        if (!expanded_otp) {
            fprintf(stderr, "session: --otp path expansion failed\n");
            crypto_munlock(psk, 32);
            crypto_memzero(psk, 32);
            g_wipe_psk = NULL;
            return 1;
        }
        burn_otp_key_template = calloc(1, sizeof *burn_otp_key_template);
        if (!burn_otp_key_template) {
            fprintf(stderr, "session: out of memory for OTP key\n");
            free(expanded_otp);
            crypto_munlock(psk, 32);
            crypto_memzero(psk, 32);
            g_wipe_psk = NULL;
            return 1;
        }
        crypto_mlock(burn_otp_key_template, sizeof *burn_otp_key_template);
        crypto_mark_dontdump(burn_otp_key_template, sizeof *burn_otp_key_template);

        if (otp_key_load(expanded_otp, burn_otp_key_template) != 0) {
            fprintf(stderr, "session: failed to load OTP key for --burn\n");
            crypto_munlock(burn_otp_key_template, sizeof *burn_otp_key_template);
            crypto_memzero(burn_otp_key_template, sizeof *burn_otp_key_template);
            free(burn_otp_key_template);
            free(expanded_otp);
            crypto_munlock(psk, 32);
            crypto_memzero(psk, 32);
            g_wipe_psk = NULL;
            return 1;
        }
        if (secure_unlink(expanded_otp) != 0) {
            crypto_munlock(burn_otp_key_template, sizeof *burn_otp_key_template);
            crypto_memzero(burn_otp_key_template, sizeof *burn_otp_key_template);
            free(burn_otp_key_template);
            free(expanded_otp);
            crypto_munlock(psk, 32);
            crypto_memzero(psk, 32);
            g_wipe_psk = NULL;
            return 1;
        }
        free(expanded_otp);
        otp_path = NULL;
    }
#endif

    int exit_code = 0;
    int ret;

    /* C-1: do/while wraps the per-session lifecycle. In !loop_mode it runs
     * exactly once. In loop_mode (listen only) it re-opens the transport,
     * recreates the session, and re-listens after each session ends — useful
     * for radio bridges that should auto-recover. PSK stays mlock'd on the
     * stack across iterations and is wiped exactly once after the loop. */
    do {
        transport_t *transport = NULL;
        if (ops->open(&cfg, &transport) != 0) {
            fprintf(stderr, "session: transport open failed\n");
            exit_code = 1;
            break;  /* device gone — exit loop */
        }

        session_t *s = session_create(transport, psk, pair_id);
        if (!s) {
            fprintf(stderr, "session: session_create failed\n");
            ops->close(transport);
            exit_code = 1;
            break;
        }
        g_active_session = s;

        channel_register(s, &channel_control_ops);
        channel_register(s, &channel_pty_ops);

#if URTB_OTP
        if (otp_path) {
            char *expanded = expand_home(otp_path);
            if (!expanded) {
                fprintf(stderr, "session: --otp path expansion failed\n");
                session_destroy(s);
                ops->close(transport);
                exit_code = 1;
                break;
            }
            if (access(expanded, R_OK) != 0) {
                fprintf(stderr, "session: OTP key file not readable: %s\n",
                        expanded);
                free(expanded);
                session_destroy(s);
                ops->close(transport);
                exit_code = 1;
                break;
            }
            s->otp_path = expanded;
        } else if (burn_otp_key_template) {
            s->otp_key_mem = burn_otp_key_template;
        }
#endif

        /* B-3: client-side PTY auto-open + raw mode + signal forwarding */
        if (!is_listen) {
            s->is_client_pty = 1;
            g_client_session = s;
            channel_pty_on_client_ack = client_on_pty_ack;
            session_run_tick = client_session_tick;
        }

        if (is_listen) {
            ret = session_listen(s);
        } else {
            ret = session_connect(s);
        }

        if (ret == 0) {
            /* Cycle 1: publish the active session so handle_loop_exit
             * can set should_exit on a SIGTERM mid-session. */
            if (loop_mode) g_loop_active_session = s;
            ret = session_run(s);
            if (loop_mode) g_loop_active_session = NULL;
        }

        /* if the remote shell exited cleanly (PTY_EOF received),
         * return its exit code regardless of what session_run returned. */
        if (!is_listen && s->pty_eof_seen) {
            exit_code = s->client_exit_code;
        } else if (!is_listen && s->client_exit_code != 0) {
            exit_code = s->client_exit_code;
        } else {
            exit_code = (ret == 0) ? 0 : 1;
        }

#if URTB_OTP
        if (burn_otp_key_template && s->otp_key_mem == burn_otp_key_template)
            s->otp_key_mem = NULL;
#endif
        g_active_session = NULL;
        session_destroy(s);
        ops->close(transport);

        if (loop_mode && !g_loop_should_exit) {
            fprintf(stderr, "urtb: session ended, re-listening...\n");
            sleep(1);
        }
    } while (loop_mode && !g_loop_should_exit);

#if URTB_OTP
    if (burn_otp_key_template) {
        crypto_munlock(burn_otp_key_template, sizeof *burn_otp_key_template);
        crypto_memzero(burn_otp_key_template, sizeof *burn_otp_key_template);
        free(burn_otp_key_template);
        burn_otp_key_template = NULL;
    }
#endif

#if defined(URTB_TEST_INJECT) && URTB_TEST_INJECT
    test_inject_teardown();
#endif

    /* C-5 / : pair the crypto_mlock(psk, 32) above. */
    crypto_munlock(psk, 32);
    crypto_memzero(psk, 32);
    g_wipe_psk = NULL;

    /* Restore termios on client exit */
    restore_termios_atexit();
    return exit_code;
}

/* -------------------------------------------------------------------------
 * status subcommand (C-3)
 *
 * Open the heltec transport (which performs USB_HELLO/USB_CONFIG handshake
 * if the device is paired), send a USB_STATUS_REQ, parse the 16-byte
 * USB_STATUS_RSP body, and print a human-readable table to stdout.
 * ---------------------------------------------------------------------- */

static const char *transport_active_label(uint8_t b)
{
    /* Wire byte: 0 = ESP-NOW primary, 1 = LoRa fallback. */
    if (b == 0) return "ESP-NOW";
    if (b == 1) return "LoRa";
    return "unknown";
}

static int cmd_status(int argc, char *argv[])
{
    const char *capsule_path = "./pairing.capsule";
    const char *device_path  = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--capsule") == 0 && i + 1 < argc) {
            capsule_path = argv[++i];
        } else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            device_path = argv[++i];
        }
    }

    if (!device_path) {
        fprintf(stderr, "status: --device required\n");
        return 1;
    }

    /* Capsule is needed only so the heltec setup handshake can pass its
     * pair_id check. We don't actually need the PSK for USB_STATUS_REQ. */
    char *passphrase = read_passphrase("Passphrase: ");
    if (!passphrase) {
        fprintf(stderr, "status: failed to read passphrase\n");
        return 1;
    }
    uint8_t psk[32]    = {0};
    uint8_t pair_id[4] = {0};
    uint8_t capsule_channel = 0;
    crypto_mlock(psk, 32);
    if (capsule_load(capsule_path, passphrase, psk, pair_id,
                     &capsule_channel) != 0) {
        fprintf(stderr, "status: failed to load capsule %s\n", capsule_path);
        wipe_passphrase(passphrase);
        crypto_munlock(psk, 32);
        crypto_memzero(psk, 32);
        return 1;
    }
    wipe_passphrase(passphrase);
    /* PSK isn't used past this point. Wipe immediately. */
    crypto_munlock(psk, 32);
    crypto_memzero(psk, 32);

    transport_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.transport      = "heltec";
    cfg.tty_device     = device_path;
    cfg.tty_baud       = 115200;
    memcpy(cfg.pair_id, pair_id, 4);
    cfg.lora_freq_hz   = URTB_LORA_FREQ_HZ;
    cfg.lora_sf        = 7;
    cfg.lora_bw        = 7;
    cfg.lora_cr        = 5;
    cfg.lora_txpower   = URTB_LORA_TXPOWER;
    /* D-40: channel is sealed inside the capsule. */
    cfg.espnow_channel = capsule_channel;
    memset(cfg.peer_mac, 0xFF, 6);

    transport_t *t = NULL;
    if (transport_heltec.open(&cfg, &t) != 0) {
        fprintf(stderr, "status: heltec open failed\n");
        return 1;
    }

    uint8_t body[16] = {0};
    int rc = transport_heltec_request_status(t, body, 3000);
    if (rc != 0) {
        fprintf(stderr, "status: USB_STATUS_RSP timeout (no response from device)\n");
        transport_heltec.close(t);
        return 1;
    }
    transport_heltec.close(t);

    int8_t  espnow_rssi = (int8_t)body[1];
    int8_t  lora_rssi   = (int8_t)body[2];
    int8_t  lora_snr10  = (int8_t)body[3];
    uint16_t e_ok   = (uint16_t)body[4]  | ((uint16_t)body[5]  << 8);
    uint16_t e_fail = (uint16_t)body[6]  | ((uint16_t)body[7]  << 8);
    uint16_t l_ok   = (uint16_t)body[8]  | ((uint16_t)body[9]  << 8);
    uint16_t l_fail = (uint16_t)body[10] | ((uint16_t)body[11] << 8);
    /* bytes 12-13 are espnow_ring_drop (firmware TX ring overflow),
     * documented in PROTOCOL.md §1. Bytes 14-15 are reserved. */
    uint16_t e_drop = (uint16_t)body[12] | ((uint16_t)body[13] << 8);

    printf("transport  : %s\n", transport_active_label(body[0]));
    if (espnow_rssi == 0)
        printf("espnow_rssi: -- dBm\n");
    else
        printf("espnow_rssi: %d dBm\n", espnow_rssi);
    if (lora_rssi == 0)
        printf("lora_rssi  : -- dBm\n");
    else
        printf("lora_rssi  : %d dBm\n", lora_rssi);
    /* SNR is signed tenths of dB. */
    int snr_int  = lora_snr10 / 10;
    int snr_frac = lora_snr10 < 0 ? -(lora_snr10 % 10) : (lora_snr10 % 10);
    printf("lora_snr   : %d.%d dB\n", snr_int, snr_frac);
    printf("espnow_tx  : ok=%u fail=%u drop=%u\n", e_ok, e_fail, e_drop);
    printf("lora_tx    : ok=%u fail=%u\n", l_ok, l_fail);
    return 0;
}

/* -------------------------------------------------------------------------
 * Usage
 * ---------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s keygen [--out PATH] [--espnow-channel N]\n"
        "  %s listen  --transport unix   --socket PATH [--capsule PATH] [--loop] [--burn] [--otp PATH]\n"
        "  %s listen  --transport heltec --device DEV  [--capsule PATH] [--loop] [--burn] [--otp PATH]\n"
        "  %s listen  --transport stdio               [--capsule PATH] [--loop] [--burn] [--otp PATH]\n"
        "  %s listen  --exec \"cmd args\" [--capsule PATH] [--loop] [--burn] [--otp PATH]\n"
        "  %s connect --transport unix   --socket PATH [--capsule PATH] [--burn]\n"
        "  %s connect --transport heltec --device DEV  [--capsule PATH] [--burn]\n"
        "  %s connect --transport stdio               [--capsule PATH] [--burn]\n"
        "  %s connect --exec \"cmd args\" [--capsule PATH] [--burn]\n"
        "  %s status  --device DEV [--capsule PATH]\n"
#if URTB_OTP
        "  %s otp-init   [--type hotp|totp] [--out PATH] [--force]\n"
        "  %s otp-verify --otp PATH [--code CODE | --print]\n"
#endif
        "\n"
        "Default --capsule: ./pairing.capsule\n"
        "URTB_PASSPHRASE env var bypasses interactive prompt (for tests).\n"
        "--espnow-channel N: keygen only. Selects the ESP-NOW Wi-Fi channel\n"
        "        (1..13, default 6) baked into the capsule. Both endpoints\n"
        "        automatically agree because they load the same capsule.\n"
        "        There is no runtime override — a typo at keygen is the\n"
        "        only way to get it wrong. See DECISIONS.md D-40.\n"
        "--loop: continuous listener; re-listens after each session ends\n"
        "        (until SIGTERM/SIGHUP/SIGINT or transport open failure).\n"
        "--burn: after loading, securely delete capsule and OTP key files.\n"
        "        Key material lives in mlock'd memory only. Cannot be undone.\n"
        "        With --loop: OTP counter updates are in memory only.\n"
        "--transport stdio: use own stdin/stdout as transport (urtb launched as\n"
        "        a subprocess, e.g. via SSH remote command). See HOWTO_JUMPHOST.md.\n"
#if URTB_OTP
        "--otp:  require OTP code from connecting client before PTY bridge starts.\n"
        "Default OTP key: ~/.config/urtb/otp.key\n"
#endif
        ,
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog
#if URTB_OTP
        , prog, prog
#endif
        );
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    /* C-4: force stderr unbuffered as a defense against forkpty(3)
     * stdio buffer inheritance. Symptom: under the AC-03 pyte harness
     * (which redirects urtb's stderr onto a pipe), pending bytes in the
     * parent's stderr FILE* buffer were being inherited by the forkpty
     * child and dumped onto the PTY slave during shell setup, corrupting
     * the first frames the server sent back. The bug never surfaced in
     * interactive use, only under the harness invocation path.
     *
     * POSIX / C11 §7.21.3 say stderr "is not fully buffered" by default
     * but do not require any specific mode; the actual buffering mode
     * varies by libc and by what the harness does to stderr before
     * exec'ing urtb. Forcing _IONBF here removes the variable —
     * defensive and harmless even on platforms where stderr was already
     * unbuffered. */
    setvbuf(stderr, NULL, _IONBF, 0);

    /* Ignore SIGPIPE — let write() return EPIPE instead */
    signal(SIGPIPE, SIG_IGN);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *subcmd = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    if (strcmp(subcmd, "keygen") == 0) {
        return cmd_keygen(sub_argc, sub_argv);
    } else if (strcmp(subcmd, "listen") == 0) {
        return cmd_session(sub_argc, sub_argv, 1);
    } else if (strcmp(subcmd, "connect") == 0) {
        return cmd_session(sub_argc, sub_argv, 0);
    } else if (strcmp(subcmd, "status") == 0) {
        return cmd_status(sub_argc, sub_argv);
#if URTB_OTP
    } else if (strcmp(subcmd, "otp-init") == 0) {
        return cmd_otp_init(sub_argc, sub_argv);
    } else if (strcmp(subcmd, "otp-verify") == 0) {
        return cmd_otp_verify(sub_argc, sub_argv);
#endif
#if defined(URTB_TEST_INJECT) && URTB_TEST_INJECT
    } else if (strcmp(subcmd, "test-inject") == 0) {
        return test_inject_subcommand(sub_argc, sub_argv);
#endif
    } else if (strcmp(subcmd, "--help") == 0 || strcmp(subcmd, "-h") == 0) {
        usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "Unknown subcommand: %s\n", subcmd);
        usage(argv[0]);
        return 1;
    }
}
