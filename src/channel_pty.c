/*
 * channel_pty.c — PTY channel handler (ch 1) per PROTOCOL.md §5
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frame types (CHAN=1):
 *   0x01  PTY_OPEN       client → server    body: rows u16, cols u16, xpix u16, ypix u16
 *   0x02  PTY_OPEN_ACK   server → client    body: pid u32
 *   0x03  PTY_OPEN_ERR   server → client    body: error_code u16, reserved u16
 *   0x04  PTY_DATA       both               body: raw bytes (MTU-limited)
 *   0x05  PTY_RESIZE     client → server    body: rows u16, cols u16, xpix u16, ypix u16
 *   0x06  PTY_SIGNAL     client → server    body: signum u8 + 3 reserved
 *   0x07  PTY_CLOSE      both               body: empty
 *   0x08  PTY_EOF        server → client    body: exit_code i32
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "channel.h"
#include "channel_pty.h"
#include "frame.h"
#include "pty.h"
#include "session.h"
#if URTB_OTP
#include "otp.h"
#endif

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint8_t pty_chan_byte(void)
{
    /* chan 1, FF=1, MF=0 (single fragment) */
    return (1 << 4) | CHAN_FF_BIT;
}

static int send_pty(session_t *s, uint8_t type,
                    const uint8_t *body, size_t len)
{
    return session_send(s, pty_chan_byte(), type, body, len);
}

/* -------------------------------------------------------------------------
 * OTP challenge (C5-3 / C6-1, server side only)
 * State lives on session_t (per-session, not static globals).
 * ---------------------------------------------------------------------- */

#if URTB_OTP
#define OTP_IDLE    0
#define OTP_PENDING 1
#define OTP_DONE    2

static int otp_handle_input(session_t *s, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        char c = (char)data[i];

        if (c == '\r' || c == '\n') {
            send_pty(s, PTY_DATA, (const uint8_t *)"\r\n", 2);
            s->otp_buf[s->otp_buf_len] = '\0';

            int otp_rc;
            if (s->otp_key_mem)
                otp_rc = otp_verify_mem(s->otp_key_mem, s->otp_buf);
            else
                otp_rc = otp_verify(s->otp_path, s->otp_buf);
            if (otp_rc == 0) {
                s->otp_state = OTP_DONE;
                fprintf(stderr, "channel_pty: OTP verified — bridge open\n");
                return CHAN_OK;
            }

            s->otp_attempts++;
            s->otp_buf_len = 0;
            memset(s->otp_buf, 0, sizeof(s->otp_buf));

            if (s->otp_attempts >= 3) {
                fprintf(stderr, "channel_pty: OTP failed 3 times — closing\n");
                s->otp_state = OTP_IDLE;
                pty_close(s->pty_master_fd, s->pty_child_pid);
                s->pty_master_fd = -1;
                s->pty_child_pid = 0;
                session_close(s);
                return CHAN_ERR;
            }

            send_pty(s, PTY_DATA,
                     (const uint8_t *)"Access denied.\r\nOTP: ", 21);
            return CHAN_OK;
        }

        if ((c == '\x7f' || c == '\x08') && s->otp_buf_len > 0) {
            s->otp_buf_len--;
            send_pty(s, PTY_DATA, (const uint8_t *)"\b \b", 3);
            continue;
        }

        if (s->otp_buf_len < 6 && c >= ' ') {
            s->otp_buf[s->otp_buf_len++] = c;
            uint8_t echo = (uint8_t)c;
            send_pty(s, PTY_DATA, &echo, 1);
        }
    }
    return CHAN_OK;
}
#endif /* URTB_OTP */

/* -------------------------------------------------------------------------
 * Server: handle PTY_OPEN → spawn, reply with PTY_OPEN_ACK or PTY_OPEN_ERR
 * ---------------------------------------------------------------------- */

static int handle_pty_open(session_t *s, const uint8_t *data, size_t len)
{
    /* PROTOCOL.md §5 fixes PTY_OPEN body at 8 bytes exactly. */
    if (len != 8) {
        fprintf(stderr, "channel_pty: PTY_OPEN wrong length %zu (expected 8)\n", len);
        return CHAN_OK;
    }
    uint16_t rows = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
    uint16_t cols = (uint16_t)data[2] | ((uint16_t)data[3] << 8);
    if (!rows) rows = 24;
    if (!cols) cols = 80;
    /* clamp to sane range. */
    if (rows > 1000) rows = 1000;
    if (cols > 1000) cols = 1000;

    if (s->pty_master_fd >= 0) {
        /* Already have a PTY — treat as idempotent re-ACK */
        uint8_t ack[4];
        uint32_t pid = (uint32_t)s->pty_child_pid;
        ack[0] = (uint8_t)(pid & 0xFF);
        ack[1] = (uint8_t)((pid >> 8) & 0xFF);
        ack[2] = (uint8_t)((pid >> 16) & 0xFF);
        ack[3] = (uint8_t)((pid >> 24) & 0xFF);
        send_pty(s, PTY_OPEN_ACK, ack, 4);
        return CHAN_OK;
    }

    int master = -1;
    pid_t pid = 0;
    if (pty_spawn(NULL, rows, cols, &master, &pid) != 0) {
        uint16_t code = ERR_RESOURCE;
        uint8_t body[4];
        body[0] = (uint8_t)(code & 0xFF);
        body[1] = (uint8_t)((code >> 8) & 0xFF);
        body[2] = 0; body[3] = 0;
        send_pty(s, PTY_OPEN_ERR, body, 4);
        fprintf(stderr, "channel_pty: pty_spawn failed: %s\n", strerror(errno));
        return CHAN_OK;
    }

    s->pty_master_fd  = master;
    s->pty_child_pid  = pid;
    fprintf(stderr, "channel_pty: server spawned PTY pid=%d fd=%d (%ux%u)\n",
            (int)pid, master, cols, rows);

    uint8_t ack[4];
    uint32_t pid32 = (uint32_t)pid;
    ack[0] = (uint8_t)(pid32 & 0xFF);
    ack[1] = (uint8_t)((pid32 >> 8) & 0xFF);
    ack[2] = (uint8_t)((pid32 >> 16) & 0xFF);
    ack[3] = (uint8_t)((pid32 >> 24) & 0xFF);
    send_pty(s, PTY_OPEN_ACK, ack, 4);

#if URTB_OTP
    if (s->otp_path || s->otp_key_mem) {
        s->otp_state    = OTP_PENDING;
        s->otp_attempts = 0;
        s->otp_buf_len  = 0;
        send_pty(s, PTY_DATA, (const uint8_t *)"OTP: ", 5);
        fprintf(stderr, "channel_pty: OTP challenge active\n");
    }
#endif

    return CHAN_OK;
}

/* -------------------------------------------------------------------------
 * Client: handle PTY_OPEN_ACK / PTY_OPEN_ERR / PTY_DATA / PTY_EOF
 * ---------------------------------------------------------------------- */

channel_pty_on_ack_fn channel_pty_on_client_ack = NULL;

static int handle_pty_open_ack(session_t *s, const uint8_t *data, size_t len)
{
    (void)data; (void)len;
    s->pty_open_ack_seen = 1;
    fprintf(stderr, "channel_pty: client received PTY_OPEN_ACK\n");
    if (channel_pty_on_client_ack) channel_pty_on_client_ack(s);
    return CHAN_OK;
}

static int handle_pty_open_err(session_t *s, const uint8_t *data, size_t len)
{
    (void)s;
    uint16_t code = 0;
    if (len >= 2) code = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
    fprintf(stderr, "channel_pty: PTY_OPEN_ERR code=0x%04X — staying ESTABLISHED\n",
            code);
    return CHAN_OK;
}

static int handle_pty_data_server(session_t *s, const uint8_t *data, size_t len)
{
#if URTB_OTP
    if (s->otp_state == OTP_PENDING)
        return otp_handle_input(s, data, len);
#endif

    /* Server: write stdin bytes from client to PTY master */
    if (s->pty_master_fd < 0) return CHAN_OK;

    /* if we have a backlog, append first (preserving order).
     * if the append would overflow, do NOT silently drop bytes —
     * tear down the session via CTRL_CLOSE so the peer learns it stopped
     * making progress instead of seeing corrupted shell input. */
    if (s->pty_master_backlog_len > 0) {
        size_t room = sizeof(s->pty_master_backlog) - s->pty_master_backlog_len;
        if (len > room) {
            fprintf(stderr,
                    "channel_pty: master backlog overflow (%zu > %zu) — closing session\n",
                    len, room);
            /* Zero the backlog before session_close so the in-flight
             * CTRL_CLOSE retransmit window doesn't try to flush stale
             * bytes to the master fd. */
            s->pty_master_backlog_len = 0;
            session_close(s);
            return CHAN_ERR;
        }
        memcpy(s->pty_master_backlog + s->pty_master_backlog_len, data, len);
        s->pty_master_backlog_len += len;
        return CHAN_OK;
    }

    size_t off = 0;
    while (off < len) {
        ssize_t n = write(s->pty_master_fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* stash remaining bytes in backlog for POLLOUT flush.
                 * if remainder won't fit, close the session rather
                 * than silently truncating shell stdin. */
                size_t remain = len - off;
                size_t room = sizeof(s->pty_master_backlog);
                if (remain > room) {
                    fprintf(stderr,
                            "channel_pty: master backlog cannot hold %zu bytes — closing session\n",
                            remain);
                    /* Zero before close (see above). */
                    s->pty_master_backlog_len = 0;
                    session_close(s);
                    return CHAN_ERR;
                }
                memcpy(s->pty_master_backlog, data + off, remain);
                s->pty_master_backlog_len = remain;
                return CHAN_OK;
            }
            fprintf(stderr, "channel_pty: write to master: %s\n", strerror(errno));
            return CHAN_OK;
        }
        off += (size_t)n;
    }
    return CHAN_OK;
}

/* flush master backlog when POLLOUT fires. Called from session_run. */
int channel_pty_flush_master_backlog(session_t *s)
{
    if (s->pty_master_fd < 0 || s->pty_master_backlog_len == 0) return 0;
    size_t off = 0;
    while (off < s->pty_master_backlog_len) {
        ssize_t n = write(s->pty_master_fd,
                          s->pty_master_backlog + off,
                          s->pty_master_backlog_len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            fprintf(stderr, "channel_pty: flush_master_backlog: %s\n", strerror(errno));
            s->pty_master_backlog_len = 0;
            return -1;
        }
        off += (size_t)n;
    }
    if (off > 0) {
        memmove(s->pty_master_backlog,
                s->pty_master_backlog + off,
                s->pty_master_backlog_len - off);
        s->pty_master_backlog_len -= off;
    }
    return 0;
}

static int handle_pty_data_client(session_t *s, const uint8_t *data, size_t len)
{
    (void)s;
    /* Client: write bytes received from server to stdout */
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(STDOUT_FILENO, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += (size_t)n;
    }
    return CHAN_OK;
}

static int handle_pty_resize(session_t *s, const uint8_t *data, size_t len)
{
#if URTB_OTP
    if (s->otp_state == OTP_PENDING) return CHAN_OK;
#endif
    /* PROTOCOL.md §5 fixes PTY_RESIZE body at 8 bytes exactly. */
    if (len != 8) {
        fprintf(stderr, "channel_pty: PTY_RESIZE wrong length %zu (expected 8)\n", len);
        return CHAN_OK;
    }
    if (s->pty_master_fd < 0) return CHAN_OK;
    uint16_t rows = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
    uint16_t cols = (uint16_t)data[2] | ((uint16_t)data[3] << 8);
    /* clamp to [1, 1000] to prevent ncurses/readline DoS. */
    if (rows == 0 || cols == 0) return CHAN_OK;
    if (rows > 1000) rows = 1000;
    if (cols > 1000) cols = 1000;
    pty_resize(s->pty_master_fd, rows, cols);
    return CHAN_OK;
}

static int handle_pty_signal(session_t *s, const uint8_t *data, size_t len)
{
#if URTB_OTP
    if (s->otp_state == OTP_PENDING) return CHAN_OK;
#endif
    /* PROTOCOL.md §5 fixes PTY_SIGNAL body at 4 bytes exactly. */
    if (len != 4) {
        fprintf(stderr, "channel_pty: PTY_SIGNAL wrong length %zu (expected 4)\n", len);
        return CHAN_OK;
    }
    if (s->pty_child_pid <= 0) return CHAN_OK;
    int signum = data[0];
    if (signum > 0 && signum < 64) {
        kill(s->pty_child_pid, signum);
    }
    return CHAN_OK;
}

static int handle_pty_eof(session_t *s, const uint8_t *data, size_t len)
{
    int32_t code = 0;
    if (len >= 4) {
        code = (int32_t)((uint32_t)data[0]
                | ((uint32_t)data[1] << 8)
                | ((uint32_t)data[2] << 16)
                | ((uint32_t)data[3] << 24));
    }
    fprintf(stderr, "channel_pty: PTY_EOF exit_code=%d\n", code);
    /* Write a newline for clean terminal state */
    (void)!write(STDOUT_FILENO, "\r\n", 2);
    s->client_exit_code = code;
    s->should_exit      = 1;
    s->pty_eof_seen     = 1;
    return CHAN_OK;
}

/* log misdirected PTY subtypes once per session so a flooding peer
 * cannot fill stderr with the same drop message. The bitmask lives on
 * session_t (pty_quiet_log_mask); bit (1 << type) gates the log. */
static void log_misdirected_once(session_t *s, const char *side, uint8_t type)
{
    uint16_t bit = (uint16_t)(1u << (type & 0x0F));
    if (s->pty_quiet_log_mask & bit) return;
    s->pty_quiet_log_mask |= bit;
    fprintf(stderr,
            "channel_pty: %s received misdirected PTY subtype 0x%02X — "
            "dropped (further drops will be silent)\n",
            side, type);
}

/* -------------------------------------------------------------------------
 * Dispatch
 * ---------------------------------------------------------------------- */

static int pty_on_open(session_t *s)
{
    /* Client side: auto-request a PTY immediately on ESTABLISHED if flagged
     * via is_client_pty. Server side: nothing to do until we receive
     * PTY_OPEN from the peer. */
    if (!s->is_server && s->is_client_pty) {
        uint16_t rows = 24, cols = 80;
        struct winsize ws;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
            rows = ws.ws_row;
            cols = ws.ws_col;
        }
        fprintf(stderr, "channel_pty: client sending PTY_OPEN (%ux%u)\n", cols, rows);
        channel_pty_client_send_open(s, rows, cols);
    }
    return 0;
}

static int pty_on_data(session_t *s, uint8_t chan_byte, uint8_t type,
                       const uint8_t *data, size_t len)
{
    (void)chan_byte;

    switch (type) {
    case PTY_OPEN:
        if (!s->is_server) {
            log_misdirected_once(s, "client", type);
            return CHAN_OK;
        }
        return handle_pty_open(s, data, len);

    case PTY_OPEN_ACK:
        if (s->is_server) {
            log_misdirected_once(s, "server", type);
            return CHAN_OK;
        }
        return handle_pty_open_ack(s, data, len);

    case PTY_OPEN_ERR:
        if (s->is_server) {
            log_misdirected_once(s, "server", type);
            return CHAN_OK;
        }
        return handle_pty_open_err(s, data, len);

    case PTY_DATA:
        if (s->is_server) return handle_pty_data_server(s, data, len);
        else              return handle_pty_data_client(s, data, len);

    case PTY_RESIZE:
        if (!s->is_server) {
            log_misdirected_once(s, "client", type);
            return CHAN_OK;
        }
        return handle_pty_resize(s, data, len);

    case PTY_SIGNAL:
        if (!s->is_server) {
            log_misdirected_once(s, "client", type);
            return CHAN_OK;
        }
        return handle_pty_signal(s, data, len);

    case PTY_EOF:
        if (s->is_server) {
            log_misdirected_once(s, "server", type);
            return CHAN_OK;
        }
        return handle_pty_eof(s, data, len);

    case PTY_CLOSE:
        fprintf(stderr, "channel_pty: PTY_CLOSE received\n");
        return CHAN_OK;

    default:
        fprintf(stderr, "channel_pty: unknown type 0x%02X\n", type);
        return CHAN_OK;
    }
}

static int pty_on_close(session_t *s)
{
    if (s->pty_master_fd >= 0 || s->pty_child_pid > 0) {
        int code = pty_close(s->pty_master_fd, s->pty_child_pid);
        fprintf(stderr, "channel_pty: PTY closed (exit=%d)\n", code);
        s->pty_master_fd = -1;
        s->pty_child_pid = 0;
    }
    /* OTP state cleaned up automatically by session_destroy (calloc'd struct) */
    return 0;
}

const channel_ops_t channel_pty = {
    .id       = 1,
    .name     = "pty",
    .on_open  = pty_on_open,
    .on_data  = pty_on_data,
    .on_close = pty_on_close,
};

/* -------------------------------------------------------------------------
 * Server pump: master → radio
 * ---------------------------------------------------------------------- */

/* shared LoRa append helper. Appends n bytes to s->lora_buf,
 * flushing on fill and handling overflow via flush-then-copy retry.
 * Only force-flushes when buffer is full (: no longer on every >=72). */
static void lora_append(session_t *s, const uint8_t *buf, size_t n)
{
    size_t room = sizeof(s->lora_buf) - s->lora_buf_len;
    /* if incoming chunk doesn't fit, flush first then copy. */
    if (n > room) {
        channel_pty_flush_lora(s);
        room = sizeof(s->lora_buf) - s->lora_buf_len;
        if (n > room) {
            /* Still too big — flush whatever is there and copy tail. */
            channel_pty_flush_lora(s);
            room = sizeof(s->lora_buf) - s->lora_buf_len;
        }
    }
    size_t copy = n > room ? room : n;
    memcpy(s->lora_buf + s->lora_buf_len, buf, copy);
    s->lora_buf_len += copy;
    if (s->lora_flush_deadline_ms == 0) {
        /* C-4: LoRa duty-cycle backpressure.
         * EU g4 at 869.875 MHz: 1% duty cycle → ~8.6 frames/min at 72-byte
         * MTU. Enforce one-frame-per-7s minimum window in LoRa mode so a
         * runaway producer (cat /dev/urandom, top, etc.) cannot exhaust the
         * regulatory budget in ~4 minutes and starve PTY_SIGNAL delivery.
         * PTY_SIGNAL (CTRL+C) bypasses lora_append entirely via send_pty
         * → send_frame, so SIGINT always reaches the peer regardless of
         * this throttle. ESP-NOW mode keeps the original 500 ms window. */
        int64_t window_ms = (s->transport_active == 2) ? 7000 : 500;
        s->lora_flush_deadline_ms = mono_ms() + window_ms;
    }
    /* only force-flush when the buffer is effectively full
     * (>= MTU - small margin). Otherwise respect the coalescing
     * deadline (7s LoRa / 500ms ESP-NOW; see C-4 ternary above). */
    if (s->lora_buf_len >= sizeof(s->lora_buf) - 16) {
        channel_pty_flush_lora(s);
    }
}

int channel_pty_pump_master(session_t *s)
{
    if (s->pty_master_fd < 0) return 0;

#if URTB_OTP
    if (s->otp_state == OTP_PENDING) {
        uint8_t discard[256];
        ssize_t n = read(s->pty_master_fd, discard, sizeof(discard));
        if (n == 0 || (n < 0 && (errno == EIO || errno == 0))) {
            /* Shell died before OTP auth — fall through to normal EOF */
            goto pty_eof;
        }
        return 0;
    }
#endif

    size_t mtu = s->current_mtu ? s->current_mtu : 222;
    /* Leave some headroom for coalescing buffer */
    uint8_t buf[256];
    size_t cap = mtu > sizeof(buf) ? sizeof(buf) : mtu;

    ssize_t n = read(s->pty_master_fd, buf, cap);
    if (n > 0) {
        if (s->transport_active == 2) {
            lora_append(s, buf, (size_t)n);
        } else {
            /* ESP-NOW / UNIX: send immediately. session_send_data
             * handles §7 fragmentation if the chunk exceeds MTU. */
            session_send_data(s, 1, PTY_DATA, buf, (size_t)n);
        }
        return 0;
    }

    if (n == 0 || (n < 0 && (errno == EIO || errno == 0))) {
pty_eof:
        /* Child exited — shell closed PTY.
         * send a best-effort PTY_EOF before pty_close blocks for
         * up to 500ms in waitpid. Without this, an in-flight keepalive ACK
         * from the peer can be dropped during the reap window and the
         * client's liveness watchdog may fire before the real PTY_EOF
         * (with exit code) arrives. The second send_pty below carries the
         * accurate exit code; the early one only signals "shell is gone".
         * The peer's handle_pty_eof tolerates len=0 (code defaults to 0). */
        send_pty(s, PTY_EOF, NULL, 0);

        int code = pty_close(s->pty_master_fd, s->pty_child_pid);
        s->pty_master_fd = -1;
        s->pty_child_pid = 0;

        int32_t code32 = (int32_t)code;
        uint8_t body[4];
        body[0] = (uint8_t)(code32 & 0xFF);
        body[1] = (uint8_t)((code32 >> 8) & 0xFF);
        body[2] = (uint8_t)((code32 >> 16) & 0xFF);
        body[3] = (uint8_t)((code32 >> 24) & 0xFF);
        send_pty(s, PTY_EOF, body, 4);
        fprintf(stderr, "channel_pty: shell exited (code=%d) — sending PTY_EOF + CTRL_CLOSE\n",
                code);
        session_close(s);
        return -1;
    }

    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return 0;
    }
    return 0;
}

int channel_pty_flush_lora(session_t *s)
{
    if (s->lora_buf_len == 0) {
        s->lora_flush_deadline_ms = 0;
        return 0;
    }
    /* §7: send the full coalesced batch as a fragmented PTY_DATA message.
     * session_send_data splits at current_mtu (72 on LoRa) and stamps
     * FF/MF flags so the peer reassembles. */
    size_t pre_len = s->lora_buf_len;
    int rc = session_send_data(s, /*chan_id=*/1, PTY_DATA,
                                s->lora_buf, s->lora_buf_len);
    if (rc != 0) {
        /* Cycle 1: be loud about the byte count so the operator can
         * correlate the drop with downstream output corruption. The
         * deliberate-drop semantics are unchanged: keeping the buffer on
         * failure would deadlock lora_append's overflow recovery (see
         * ), so we trade durability for liveness here. A future
         * fix would push backpressure into channel_pty_pump_master so
         * the PTY master read pauses until the radio recovers — left
         * as a Phase C item, KNOWN_ISSUES candidate. */
        fprintf(stderr,
                "channel_pty: lora flush send failed — DROPPING %zu PTY bytes\n",
                pre_len);
    }
    s->lora_buf_len = 0;
    s->lora_flush_deadline_ms = 0;
    return rc;
}

/* -------------------------------------------------------------------------
 * Client pump: stdin → radio
 * ---------------------------------------------------------------------- */

int channel_pty_pump_stdin(session_t *s)
{
    uint8_t buf[256];
    size_t mtu = s->current_mtu ? s->current_mtu : 222;
    size_t cap = mtu > sizeof(buf) ? sizeof(buf) : mtu;

    ssize_t n = read(STDIN_FILENO, buf, cap);
    if (n > 0) {
        /* mirror transport_active==2 coalescing on the client side
         * so per-keystroke typing doesn't burn LoRa's 8.6-frame/min budget. */
        if (s->transport_active == 2) {
            lora_append(s, buf, (size_t)n);
        } else {
            session_send_data(s, 1, PTY_DATA, buf, (size_t)n);
        }
        return 0;
    }
    if (n == 0) {
        /* stdin EOF — mark the client so session_run stops polling stdin,
         * but DON'T close the session yet. The remote shell is still running
         * and we want its output + PTY_EOF to arrive normally. */
        fprintf(stderr, "channel_pty: stdin EOF — stopping stdin pump\n");
        s->stdin_closed = 1;
        return 0;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    return -1;
}

/* -------------------------------------------------------------------------
 * Client-side helpers used by main.c
 * ---------------------------------------------------------------------- */

int channel_pty_client_send_open(session_t *s, uint16_t rows, uint16_t cols)
{
    uint8_t body[8];
    body[0] = (uint8_t)(rows & 0xFF);
    body[1] = (uint8_t)((rows >> 8) & 0xFF);
    body[2] = (uint8_t)(cols & 0xFF);
    body[3] = (uint8_t)((cols >> 8) & 0xFF);
    body[4] = 0; body[5] = 0; body[6] = 0; body[7] = 0;
    return send_pty(s, PTY_OPEN, body, sizeof(body));
}

int channel_pty_client_send_resize(session_t *s, uint16_t rows, uint16_t cols)
{
    uint8_t body[8];
    body[0] = (uint8_t)(rows & 0xFF);
    body[1] = (uint8_t)((rows >> 8) & 0xFF);
    body[2] = (uint8_t)(cols & 0xFF);
    body[3] = (uint8_t)((cols >> 8) & 0xFF);
    body[4] = 0; body[5] = 0; body[6] = 0; body[7] = 0;
    return send_pty(s, PTY_RESIZE, body, sizeof(body));
}

int channel_pty_client_send_signal(session_t *s, uint8_t signum)
{
    uint8_t body[4];
    body[0] = signum;
    body[1] = 0; body[2] = 0; body[3] = 0;
    return send_pty(s, PTY_SIGNAL, body, sizeof(body));
}
