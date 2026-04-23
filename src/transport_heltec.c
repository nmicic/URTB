/*
 * transport_heltec.c — TTY/serial transport stub for Heltec V3
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * B-2 scope: open device, set 115200 8N1 raw mode, stub send/recv with
 * USB_DATA_TX/RX wrapping. Full USB_HELLO/USB_CONFIG setup sequence is B-3.
 *
 * Framing: send wraps bytes in USB_DATA_TX frame, recv reads USB frames and
 * returns body of USB_DATA_RX frames; other frame types handled or discarded.
 */

#define _POSIX_C_SOURCE 200809L
/* cfmakeraw requires _BSD_SOURCE or _DEFAULT_SOURCE */
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
/* macOS hides cfmakeraw and Bxxx baud constants behind _DARWIN_C_SOURCE
 * when _POSIX_C_SOURCE is defined. */
#define _DARWIN_C_SOURCE 1
#endif

/* Full Heltec USB handshake (USB_HELLO, USB_CONFIG, USB_STATUS_RSP) is
 * implemented below. Post-setup USB_HELLO_ACK renegotiation and full
 * §9 stats field parsing are tracked in KNOWN_ISSUES.md. */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include "transport.h"
#include "frame.h"

#ifndef URTB_LORA_FREQ_HZ
#  define URTB_LORA_FREQ_HZ  869875000U
#endif
#ifndef URTB_LORA_TXPOWER
#  define URTB_LORA_TXPOWER  7
#endif

/* Forward declaration needed by transport_heltec_consume_pending_mode, which
 * is defined before transport_heltec at the bottom of the file. */
extern const transport_ops_t transport_heltec;

/* -------------------------------------------------------------------------
 * Internal state
 * ---------------------------------------------------------------------- */

typedef struct {
    transport_t      base;
    int              fd;
    transport_stats_t stats;

    /* serial framing accumulator. Bytes read from the TTY are
     * appended here; the decoder scans for magic, reads LEN, and waits
     * until a complete USB frame is present before decoding. */
    uint8_t          acc[USB_MAX_FRAME * 2];
    size_t           acc_len;

    /* latest transport_active byte seen in USB_STATUS_RSP.
     * 0 = unset, 1 = ESP-NOW, 2 = LoRa. Consumed by the session loop. */
    uint8_t          pending_transport_mode;

    /* C-3: latest full USB_STATUS_RSP body (16 bytes per PROTOCOL.md).
     * have_status_rsp is set whenever a fresh frame arrives and cleared by
     * transport_heltec_consume_status_rsp(). */
    int              have_status_rsp;
    uint8_t          last_status_body[16];
} transport_heltec_t;

static int heltec_perform_setup(transport_heltec_t *t, const transport_config_t *cfg);

/* -------------------------------------------------------------------------
 * Write all bytes
 * ---------------------------------------------------------------------- */

static int heltec_write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, buf + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        written += (size_t)n;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * open: open TTY, set 115200 8N1 raw
 * ---------------------------------------------------------------------- */

static int heltec_open(const transport_config_t *cfg, transport_t **out)
{
    if (!cfg || !cfg->tty_device) {
        fprintf(stderr, "transport_heltec: tty_device required\n");
        return -1;
    }

    transport_heltec_t *t = calloc(1, sizeof(*t));
    if (!t) {
        fprintf(stderr, "transport_heltec: calloc failed\n");
        return -1;
    }
    t->base.ops = &transport_heltec;

    t->fd = open(cfg->tty_device, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (t->fd < 0) {
        fprintf(stderr, "transport_heltec: open(%s): %s\n",
                cfg->tty_device, strerror(errno));
        free(t);
        return -1;
    }

    /* check fcntl() return values. */
    int flags = fcntl(t->fd, F_GETFL, 0);
    if (flags < 0) {
        fprintf(stderr, "transport_heltec: fcntl(F_GETFL): %s\n", strerror(errno));
        close(t->fd);
        free(t);
        return -1;
    }
    if (fcntl(t->fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        fprintf(stderr, "transport_heltec: fcntl(F_SETFL): %s\n", strerror(errno));
        close(t->fd);
        free(t);
        return -1;
    }
    /* FD_CLOEXEC so spawned shell can't talk out-of-band. */
    (void)fcntl(t->fd, F_SETFD, FD_CLOEXEC);

    /* Configure 115200 8N1 raw */
    struct termios tio;
    memset(&tio, 0, sizeof(tio));
    cfmakeraw(&tio);

    uint32_t baud = cfg->tty_baud ? cfg->tty_baud : 115200;
    speed_t speed;
    switch (baud) {
        case 115200: speed = B115200; break;
        case 57600:  speed = B57600;  break;
        case 38400:  speed = B38400;  break;
        default:
            fprintf(stderr, "transport_heltec: unsupported baud %u, using 115200\n", baud);
            speed = B115200;
    }
    cfsetispeed(&tio, speed);
    cfsetospeed(&tio, speed);

    tio.c_cflag |= (CLOCAL | CREAD);
    tio.c_cflag &= ~(PARENB | CSTOPB | CSIZE);
    tio.c_cflag |= CS8;
    tio.c_cc[VMIN]  = 1;
    tio.c_cc[VTIME] = 0;

    if (tcsetattr(t->fd, TCSANOW, &tio) != 0) {
        fprintf(stderr, "transport_heltec: tcsetattr: %s\n", strerror(errno));
        close(t->fd);
        free(t);
        return -1;
    }

    fprintf(stderr, "transport_heltec: opened %s at %u baud\n",
            cfg->tty_device, baud);

    /* B-3: USB_HELLO / USB_HELLO_ACK / USB_CONFIG / USB_CONFIG_ACK setup.
     * Set URTB_HELTEC_SKIP_SETUP=1 to disable entirely (CI, tests). */
    if (getenv("URTB_HELTEC_SKIP_SETUP") == NULL) {
        if (heltec_perform_setup(t, cfg) != 0) {
#if URTB_TEST_INJECT
            fprintf(stderr, "transport_heltec: setup failed — stub mode (test build)\n");
#else
            fprintf(stderr, "transport_heltec: setup failed — firmware not responding.\n"
                            "  Check: device path, USB cable, firmware flash.\n"
                            "  Run: pio run -t upload to re-flash.\n");
            close(t->fd);
            free(t);
            return -1;
#endif
        }
    }

    *out = &t->base;
    return 0;
}

/* -------------------------------------------------------------------------
 * send: wrap in USB_DATA_TX frame, write to serial
 * ---------------------------------------------------------------------- */

static int heltec_send(transport_t *base, const uint8_t *data, size_t len)
{
    transport_heltec_t *t = (transport_heltec_t *)base;
    uint8_t frame[USB_MAX_FRAME];

    int n = urtb_usb_encode(USB_DATA_TX, 0, data, len, frame, sizeof(frame));
    if (n < 0) {
        fprintf(stderr, "transport_heltec: send: usb_encode failed (len=%zu)\n", len);
        t->stats.tx_fail++;
        return -1;
    }
    if (heltec_write_all(t->fd, frame, (size_t)n) != 0) {
        fprintf(stderr, "transport_heltec: write failed: %s\n", strerror(errno));
        t->stats.tx_fail++;
        return -1;
    }
    t->stats.tx_ok++;
    return 0;
}

/* -------------------------------------------------------------------------
 * recv: read USB frames, return body of USB_DATA_RX frames
 * Discards non-data frames silently (or processes USB_STATUS_RSP stats).
 * ---------------------------------------------------------------------- */

/* scan the accumulator for a complete USB frame. Returns:
 *   >0  length of frame consumed from head of acc
 *    0  not enough data yet
 *   -1  garbage at head (one byte dropped) — caller may retry
 */
static int heltec_scan_frame(transport_heltec_t *t, size_t *frame_len_out)
{
    /* Drop leading garbage until we find the magic or run out. */
    while (t->acc_len >= 2 &&
           !(t->acc[0] == USB_MAGIC0 && t->acc[1] == USB_MAGIC1)) {
        memmove(t->acc, t->acc + 1, t->acc_len - 1);
        t->acc_len--;
    }
    if (t->acc_len < USB_HEADER_LEN) return 0;

    /* LEN at offset 5..6 (LE). */
    size_t body_len = (size_t)t->acc[5] | ((size_t)t->acc[6] << 8);
    if (body_len > USB_MAX_BODY) {
        /* Bad LEN: advance one byte to resync. */
        memmove(t->acc, t->acc + 1, t->acc_len - 1);
        t->acc_len--;
        return -1;
    }
    size_t total = USB_OVERHEAD + body_len;
    if (t->acc_len < total) return 0;
    *frame_len_out = total;
    return 1;
}

static int heltec_recv(transport_t *base, uint8_t *buf, size_t max, int timeout_ms)
{
    transport_heltec_t *t = (transport_heltec_t *)base;
    uint8_t body[USB_MAX_BODY];

    for (;;) {
        /* Try to decode a frame from whatever we already have. */
        size_t frame_len = 0;
        int scan;
        while ((scan = heltec_scan_frame(t, &frame_len)) != 0) {
            if (scan < 0) {
                t->stats.rx_drop++;
                continue;
            }
            uint8_t type = 0, flags = 0;
            int blen = urtb_usb_decode(t->acc, frame_len, &type, &flags,
                                       body, sizeof(body));
            /* Consume this frame from the accumulator regardless. */
            memmove(t->acc, t->acc + frame_len, t->acc_len - frame_len);
            t->acc_len -= frame_len;

            if (blen < 0) {
                t->stats.rx_drop++;
                continue;
            }

            switch (type) {
            case USB_DATA_RX:
                if ((size_t)blen > max) {
                    t->stats.rx_drop++;
                    return -1;
                }
                memcpy(buf, body, (size_t)blen);
                t->stats.rx_ok++;
                return blen;

            case USB_STATUS_RSP:
                /* parse transport_active from body[0] and
                 * stash RSSI. RSSI sentinel: raw 0x00 -> INT16_MIN ().
                 * wire byte uses ESPNOW_PRIMARY=0, LORA_FALLBACK=1;
                 * internal uses 1=ESPNOW, 2=LORA. Map explicitly. */
                if (blen >= 1) {
                    t->pending_transport_mode = (body[0] == 1) ? 2 : 1;
                }
                if (blen >= 2) {
                    uint8_t raw = body[1];
                    t->stats.rssi_last = (raw == 0) ? INT16_MIN : (int16_t)(int8_t)raw;
                }
                /* C-3: stash the full body for session-side wrap reconciliation
                 * (espnow/lora rssi+snr+counters). Short bodies are zero-padded
                 * so consumers can read fixed offsets safely. */
                memset(t->last_status_body, 0, sizeof(t->last_status_body));
                {
                    size_t copy = (blen > 0 && (size_t)blen <= sizeof(t->last_status_body))
                                    ? (size_t)blen : sizeof(t->last_status_body);
                    if (blen > 0) memcpy(t->last_status_body, body, copy);
                }
                t->have_status_rsp = 1;
                continue;

            case USB_ERROR:
                /* decode 2-byte error_code and log. */
                if (blen >= 2) {
                    uint16_t ec = (uint16_t)body[0] | ((uint16_t)body[1] << 8);
                    fprintf(stderr, "transport_heltec: USB_ERROR code=0x%04X\n", ec);
                } else {
                    fprintf(stderr, "transport_heltec: USB_ERROR (short body=%d)\n", blen);
                }
                t->stats.rx_drop++;
                continue;

            case USB_HELLO_ACK:
                /* Post-setup USB_HELLO_ACK (renegotiation) is currently
                 * discarded; full parsing of firmware version and capability
                 * flags is deferred — see KNOWN_ISSUES.md. */
                continue;

            default:
                /* Silently discard */
                continue;
            }
        }

        /* Need more data: poll + read. */
        struct pollfd pfd = { .fd = t->fd, .events = POLLIN };
        int r = poll(&pfd, 1, timeout_ms);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1; /* timeout or error */

        if (t->acc_len >= sizeof(t->acc)) {
            /* Accumulator full — shouldn't happen, reset. */
            t->acc_len = 0;
            t->stats.rx_drop++;
        }
        ssize_t n = read(t->fd, t->acc + t->acc_len, sizeof(t->acc) - t->acc_len);
        if (n <= 0) return -1;
        t->acc_len += (size_t)n;
    }
}

/* -------------------------------------------------------------------------
 * close
 * ---------------------------------------------------------------------- */

static void heltec_close(transport_t *base)
{
    transport_heltec_t *t = (transport_heltec_t *)base;
    if (t->fd >= 0) {
        close(t->fd);
        t->fd = -1;
    }
    free(t);
}

/* -------------------------------------------------------------------------
 * stats
 * ---------------------------------------------------------------------- */

static int heltec_stats(transport_t *base, transport_stats_t *out)
{
    transport_heltec_t *t = (transport_heltec_t *)base;
    *out = t->stats;
    out->transport_id = 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * Export
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Public accessor used by session_run to pick up LoRa failover.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * USB_HELLO / USB_CONFIG setup sequence (B-3)
 *
 * 1. send USB_HELLO
 * 2. wait up to 5s for USB_HELLO_ACK
 *    - pair_id 0x00000000  → fresh device, proceed
 *    - pair_id matches     → already configured, proceed
 *    - pair_id mismatch    → wrong device, abort
 * 3. send USB_CONFIG (PAIR_ID, LoRa params, mac_addr, espnow_channel)
 * 4. wait up to 2s for USB_CONFIG_ACK
 * 5. ready
 *
 * This runs inline in heltec_open() when a real device is present. On any
 * timeout or I/O error it returns -1; production builds fail the open,
 * URTB_TEST_INJECT builds continue in stub mode for testing.
 * ---------------------------------------------------------------------- */

/* read a frame, ignoring unsolicited USB_STATUS_RSP frames until
 * we get something else (or overall timeout). If expected_type != 0, also
 * skip any frame type that isn't expected_type (logging at each skip). */
static int heltec_read_one_frame_expecting(transport_heltec_t *t,
                                           int overall_timeout_ms,
                                           uint8_t expected_type,
                                           uint8_t *type_out, uint8_t *body,
                                           size_t body_max, int *body_len_out)
{
    struct timespec deadline, now;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec  += overall_timeout_ms / 1000;
    deadline.tv_nsec += (long)(overall_timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }

    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        int rem = (int)((deadline.tv_sec - now.tv_sec) * 1000
                        + (deadline.tv_nsec - now.tv_nsec) / 1000000);
        if (rem <= 0) return -1;

        size_t frame_len = 0;
        int scan;
        int got = 0;
        while ((scan = heltec_scan_frame(t, &frame_len)) != 0) {
            if (scan < 0) continue;
            uint8_t flags = 0;
            int blen = urtb_usb_decode(t->acc, frame_len, type_out, &flags,
                                       body, body_max);
            memmove(t->acc, t->acc + frame_len, t->acc_len - frame_len);
            t->acc_len -= frame_len;
            if (blen < 0) continue;

            /* ignore unsolicited USB_STATUS_RSP; stash transport_active. */
            if (*type_out == USB_STATUS_RSP) {
                if (blen >= 1) {
                    t->pending_transport_mode = (body[0] == 1) ? 2 : 1;
                }
                /* C-3: also keep the full body, same as steady-state recv. */
                memset(t->last_status_body, 0, sizeof(t->last_status_body));
                {
                    size_t copy = (blen > 0 && (size_t)blen <= sizeof(t->last_status_body))
                                    ? (size_t)blen : sizeof(t->last_status_body);
                    if (blen > 0) memcpy(t->last_status_body, body, copy);
                }
                t->have_status_rsp = 1;
                fprintf(stderr, "transport_heltec: setup: skipped USB_STATUS_RSP\n");
                continue;
            }
            /* surface USB_ERROR during setup. */
            if (*type_out == USB_ERROR) {
                if (blen >= 2) {
                    uint16_t ec = (uint16_t)body[0] | ((uint16_t)body[1] << 8);
                    fprintf(stderr, "transport_heltec: setup: USB_ERROR code=0x%04X\n", ec);
                }
                return -1;
            }
            if (expected_type != 0 && *type_out != expected_type) {
                fprintf(stderr, "transport_heltec: setup: skipped unexpected type 0x%02X\n",
                        *type_out);
                continue;
            }
            *body_len_out = blen;
            got = 1;
            return 0;
        }
        (void)got;

        struct pollfd pfd = { .fd = t->fd, .events = POLLIN };
        int r = poll(&pfd, 1, rem);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        if (t->acc_len >= sizeof(t->acc)) { t->acc_len = 0; }
        ssize_t n = read(t->fd, t->acc + t->acc_len, sizeof(t->acc) - t->acc_len);
        if (n <= 0) return -1;
        t->acc_len += (size_t)n;
    }
}


static int heltec_perform_setup(transport_heltec_t *t, const transport_config_t *cfg)
{
    /* Step 1: send USB_HELLO (body: version=0x01, reserved=0) */
    uint8_t hello_body[2] = { 0x01, 0x00 };
    uint8_t hello_frame[USB_MAX_FRAME];
    int hn = urtb_usb_encode(USB_HELLO, 0, hello_body, sizeof(hello_body),
                             hello_frame, sizeof(hello_frame));
    if (hn < 0) return -1;
    if (heltec_write_all(t->fd, hello_frame, (size_t)hn) != 0) return -1;
    fprintf(stderr, "transport_heltec: sent USB_HELLO\n");

    /* Step 2: wait up to 5s for USB_HELLO_ACK (skipping USB_STATUS_RSP) */
    uint8_t type = 0, body[USB_MAX_BODY];
    int blen = 0;
    if (heltec_read_one_frame_expecting(t, 5000, USB_HELLO_ACK, &type,
                                        body, sizeof(body), &blen) != 0) {
        fprintf(stderr, "transport_heltec: USB_HELLO_ACK timeout\n");
        return -1;
    }
    if (blen < 8) {
        fprintf(stderr, "transport_heltec: USB_HELLO_ACK body too short (%d)\n", blen);
        return -1;
    }
    /* pair_id at offset 4..7 */
    uint8_t fw_pair[4];
    memcpy(fw_pair, body + 4, 4);
    int fw_zero = (fw_pair[0] | fw_pair[1] | fw_pair[2] | fw_pair[3]) == 0;
    int cfg_zero = !cfg ||
        (cfg->pair_id[0] | cfg->pair_id[1] | cfg->pair_id[2] | cfg->pair_id[3]) == 0;

    /* if both sides non-zero and mismatch → abort. */
    if (!fw_zero && !cfg_zero && memcmp(fw_pair, cfg->pair_id, 4) != 0) {
        fprintf(stderr, "transport_heltec: PAIR_ID mismatch (fw=%02X%02X%02X%02X, "
                        "host=%02X%02X%02X%02X) — aborting\n",
                fw_pair[0], fw_pair[1], fw_pair[2], fw_pair[3],
                cfg->pair_id[0], cfg->pair_id[1], cfg->pair_id[2], cfg->pair_id[3]);
        return -1;
    }

    /* Step 3: send USB_CONFIG from cfg. : host-supplied pair_id, LoRa
     * params, mac_addr, espnow_channel. */
    uint8_t cfg_body[20];
    memset(cfg_body, 0, sizeof(cfg_body));
    if (cfg) {
        memcpy(cfg_body, cfg->pair_id, 4);
        uint32_t freq = cfg->lora_freq_hz ? cfg->lora_freq_hz : URTB_LORA_FREQ_HZ;
        cfg_body[4] = (uint8_t)(freq & 0xFF);
        cfg_body[5] = (uint8_t)((freq >> 8) & 0xFF);
        cfg_body[6] = (uint8_t)((freq >> 16) & 0xFF);
        cfg_body[7] = (uint8_t)((freq >> 24) & 0xFF);
        cfg_body[8]  = cfg->lora_sf      ? cfg->lora_sf      : 7;
        cfg_body[9]  = cfg->lora_bw      ? cfg->lora_bw      : 7;
        cfg_body[10] = cfg->lora_cr      ? cfg->lora_cr      : 5;
        cfg_body[11] = cfg->lora_txpower ? cfg->lora_txpower : URTB_LORA_TXPOWER;
        memcpy(cfg_body + 12, cfg->peer_mac, 6);
        /* D-40: channel is authoritative from cfg->espnow_channel,
         * which capsule_load() populates (v1 → 6, v2 → 1..13). A zero here
         * now indicates a caller bug — surface it via firmware rejecting
         * USB_CONFIG rather than papering over with a fallback. */
        cfg_body[18] = cfg->espnow_channel;
        cfg_body[19] = 0;
    } else {
        uint32_t freq = URTB_LORA_FREQ_HZ;
        cfg_body[4] = (uint8_t)(freq & 0xFF);
        cfg_body[5] = (uint8_t)((freq >> 8) & 0xFF);
        cfg_body[6] = (uint8_t)((freq >> 16) & 0xFF);
        cfg_body[7] = (uint8_t)((freq >> 24) & 0xFF);
        cfg_body[8] = 7; cfg_body[9] = 7; cfg_body[10] = 5; cfg_body[11] = URTB_LORA_TXPOWER;
        /* Defaults-only path (no cfg supplied — test/fake-firmware).
         * Channel 6 is intentional; the production channel source is
         * cfg->espnow_channel populated by capsule_load(). */
        cfg_body[18] = 6;
    }
    uint8_t cfg_frame[USB_MAX_FRAME];
    int cn = urtb_usb_encode(USB_CONFIG, 0, cfg_body, sizeof(cfg_body),
                             cfg_frame, sizeof(cfg_frame));
    if (cn < 0) return -1;
    if (heltec_write_all(t->fd, cfg_frame, (size_t)cn) != 0) return -1;
    fprintf(stderr, "transport_heltec: sent USB_CONFIG (pair_id=%02X%02X%02X%02X)\n",
            cfg_body[0], cfg_body[1], cfg_body[2], cfg_body[3]);

    /* Step 4: wait up to 2s for USB_CONFIG_ACK (skipping USB_STATUS_RSP) */
    if (heltec_read_one_frame_expecting(t, 2000, USB_CONFIG_ACK, &type,
                                        body, sizeof(body), &blen) != 0) {
        fprintf(stderr, "transport_heltec: USB_CONFIG_ACK timeout\n");
        return -1;
    }
    fprintf(stderr, "transport_heltec: setup complete\n");
    return 0;
}

uint8_t transport_heltec_consume_pending_mode(transport_t *base)
{
    if (!base || base->ops != &transport_heltec) return 0;
    transport_heltec_t *t = (transport_heltec_t *)base;
    uint8_t mode = t->pending_transport_mode;
    t->pending_transport_mode = 0;
    return mode;
}

/* C-3: pop the latest USB_STATUS_RSP body. Returns 1 if one was pending
 * (16 bytes copied into out[]) and clears the flag, 0 otherwise. */
int transport_heltec_consume_status_rsp(transport_t *base, uint8_t out[16])
{
    if (!base || base->ops != &transport_heltec || !out) return 0;
    transport_heltec_t *t = (transport_heltec_t *)base;
    if (!t->have_status_rsp) return 0;
    memcpy(out, t->last_status_body, 16);
    t->have_status_rsp = 0;
    return 1;
}

/* C-3: send a USB_STATUS_REQ frame and block until USB_STATUS_RSP arrives.
 * Used by the `urtb status` subcommand. We drive the accumulator directly
 * (rather than calling heltec_read_one_frame_expecting) so that we can
 * return as soon as a USB_STATUS_RSP is decoded — that helper is built
 * around skipping STATUS_RSP, which is the opposite of what we need here. */
int transport_heltec_request_status(transport_t *base, uint8_t out[16],
                                    int timeout_ms)
{
    if (!base || base->ops != &transport_heltec || !out) return -1;
    transport_heltec_t *t = (transport_heltec_t *)base;

    /* Send a zero-body USB_STATUS_REQ. */
    uint8_t reqframe[USB_OVERHEAD];
    int n = urtb_usb_encode(USB_STATUS_REQ, 0, NULL, 0, reqframe, sizeof(reqframe));
    if (n < 0) return -1;
    if (heltec_write_all(t->fd, reqframe, (size_t)n) != 0) return -1;

    /* Spin on the framing accumulator until either a USB_STATUS_RSP gets
     * decoded (have_status_rsp flips) or the deadline passes. */
    struct timespec deadline, now;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec  += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }

    uint8_t body[USB_MAX_BODY];

    for (;;) {
        /* Drain any complete frames already in the accumulator. */
        size_t frame_len = 0;
        int scan;
        while ((scan = heltec_scan_frame(t, &frame_len)) != 0) {
            if (scan < 0) continue;
            uint8_t type = 0, flags = 0;
            int blen = urtb_usb_decode(t->acc, frame_len, &type, &flags,
                                       body, sizeof(body));
            memmove(t->acc, t->acc + frame_len, t->acc_len - frame_len);
            t->acc_len -= frame_len;
            if (blen < 0) continue;

            if (type == USB_STATUS_RSP) {
                if (blen >= 1) {
                    t->pending_transport_mode = (body[0] == 1) ? 2 : 1;
                }
                memset(t->last_status_body, 0, sizeof(t->last_status_body));
                size_t copy = ((size_t)blen <= sizeof(t->last_status_body))
                                ? (size_t)blen : sizeof(t->last_status_body);
                if (blen > 0) memcpy(t->last_status_body, body, copy);
                t->have_status_rsp = 1;
                memcpy(out, t->last_status_body, 16);
                t->have_status_rsp = 0;
                return 0;
            }
            /* Other frame types: ignore and keep scanning. */
        }

        /* No complete STATUS_RSP yet — wait for more bytes. */
        clock_gettime(CLOCK_MONOTONIC, &now);
        int rem = (int)((deadline.tv_sec - now.tv_sec) * 1000
                        + (deadline.tv_nsec - now.tv_nsec) / 1000000);
        if (rem <= 0) return -1;

        struct pollfd pfd = { .fd = t->fd, .events = POLLIN };
        int r = poll(&pfd, 1, rem);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        if (t->acc_len >= sizeof(t->acc)) { t->acc_len = 0; }
        ssize_t rd = read(t->fd, t->acc + t->acc_len, sizeof(t->acc) - t->acc_len);
        if (rd <= 0) return -1;
        t->acc_len += (size_t)rd;
    }
}

static int heltec_get_fd(transport_t *base)
{
    transport_heltec_t *t = (transport_heltec_t *)base;
    /* The heltec recv() buffers reads in an accumulator, so returning the
     * raw fd only works when the accumulator is empty — for B-3 this is
     * acceptable: session_run polls, then calls recv() which drains the
     * accumulator first. */
    return t->fd;
}

const transport_ops_t transport_heltec = {
    .name   = "heltec",
    .open   = heltec_open,
    .send   = heltec_send,
    .recv   = heltec_recv,
    .close  = heltec_close,
    .stats  = heltec_stats,
    .get_fd = heltec_get_fd,
};
