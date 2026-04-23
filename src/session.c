/*
 * session.c — full session state machine per PROTOCOL.md §8
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements:
 *   - CTRL_HELLO retransmit schedule (1s/2s/4s/8s + 16s wait → IDLE, 5 total)
 *   - CTRL_HELLO_ACK: derive hello_key, then session_key, send CTRL_READY
 *   - KEY_DERIVING: wait for peer CTRL_READY (10s timeout)
 *   - ESTABLISHED: keepalive every 2s, liveness watchdog 6s
 *   - Replay window per PROTOCOL.md §3 (additive form, 256-entry bitmap)
 *   - AEAD failure policy per PROTOCOL.md §3
 *   - Idempotent CTRL_HELLO in KEY_DERIVING (same nonce_a = re-send ACK)
 *   - CTRL_CLOSE retransmit (3 frames, 1s/2s/force)
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "monocypher.h"
#include "session.h"
#include "frame.h"
#include "crypto.h"
#include "channel.h"
#include "channel_pty.h"
#if defined(URTB_TEST_INJECT) && URTB_TEST_INJECT
#include "test_inject.h"
#endif

/* -------------------------------------------------------------------------
 * CTRL_HELLO payload layout (32 bytes plaintext).
 * Phase C-4 (D-39): version is 0x02; on the wire the AEAD ciphertext for
 * this struct is preceded by a cleartext 24-byte hello_nonce in the body.
 * See PROTOCOL.md §4 "Handshake wire format".
 * ---------------------------------------------------------------------- */
typedef struct {
    uint8_t version;
    uint8_t caps;
    uint8_t nonce_a[16];
    uint8_t reserved[14];
} ctrl_hello_t;

typedef struct {
    uint8_t version;
    uint8_t caps;
    uint8_t nonce_b[16];
    uint8_t reserved[14];
} ctrl_hello_ack_t;

/* CTRL_ERROR payload (4 bytes) */
typedef struct {
    uint16_t error_code;
    uint16_t reserved;
} ctrl_error_t;

/* AEAD data-frame consecutive failure threshold before closing. */
#define AEAD_FAIL_THRESHOLD 10

/* B-3: client tick hook (see session.h) */
session_tick_fn session_run_tick = NULL;

/* static assert on stored_hello_ack sizing.
 * Phase C-4 (D-39): body grew by 24 bytes for the cleartext hello_nonce.
 * Use sizeof(ctrl_hello_ack_t) so the assert tracks any future struct
 * change rather than a magic 32. */
_Static_assert(sizeof(((struct session *)0)->stored_hello_ack)
                   >= 12 + 24 + sizeof(ctrl_hello_ack_t) + 16,
               "stored_hello_ack too small for hdr(12)+nonce(24)+ack_pt+tag(16)");

/* -------------------------------------------------------------------------
 * Monotonic clock helper (returns ms)
 * ---------------------------------------------------------------------- */
static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* -------------------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------------- */
static int  send_ctrl_error(session_t *s, uint16_t code);
static void track_err_session(session_t *s);
static void replay_stashed_frame(session_t *s);

/* -------------------------------------------------------------------------
 * Replay window
 * ---------------------------------------------------------------------- */

static int replay_accept(replay_window_t *r, uint32_t seq)
{
    /* assert the replay window fits in the 31-bit modular newness
     * comparison used below. PROTOCOL.md §3 L275: any replay window that
     * exceeds 2^31 - 1 makes (seq - hwm) < 0x80000000 ambiguous between
     * "newer" and "old enough to wrap". Place adjacent to the use site
     * so a future widener of REPLAY_WINDOW trips the assert immediately. */
    _Static_assert(REPLAY_WINDOW <= 0x7FFFFFFF,
        "replay window must fit in 31 bits for modular comparison "
        "(PROTOCOL §3 L275)");

    if (!r->initialized) {
        r->hwm = seq;
        memset(r->bitmap, 0, sizeof(r->bitmap));
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        r->initialized = 1;
        return 1;
    }
    /* Use modular comparison: seq is newer if (seq - hwm) < 0x80000000 */
    if ((uint32_t)(seq - r->hwm) < 0x80000000U && seq != r->hwm) {
        /* seq > hwm (modular) */
        uint32_t advance = seq - r->hwm;
        if (advance >= REPLAY_WINDOW) {
            /* Whole-window wipe: every existing slot is now older than
             * the window. */
            memset(r->bitmap, 0, sizeof(r->bitmap));
        } else if (advance >= 16) {
            /* clear `advance` consecutive circular slots starting
             * at (hwm+1) % REPLAY_WINDOW with at most two memsets, instead
             * of walking up to 255 individual bytes. The bitmap is a
             * circular array of 1-byte flags indexed by seq%W, so a memset
             * on the cleared range is logically equivalent to the per-slot
             * loop in the else branch below — just much faster. */
            uint32_t start = (r->hwm + 1) % REPLAY_WINDOW;
            uint32_t end_excl = start + advance;
            if (end_excl <= REPLAY_WINDOW) {
                memset(r->bitmap + start, 0, advance);
            } else {
                memset(r->bitmap + start, 0, REPLAY_WINDOW - start);
                memset(r->bitmap, 0, end_excl - REPLAY_WINDOW);
            }
        } else {
            /* Small advance: keep the per-slot loop with the
             * underflow guard for the early-window phase (hwm+i < W,
             * slot was never written, and is already 0). */
            for (uint32_t i = 1; i <= advance; i++) {
                if ((uint64_t)r->hwm + i >= REPLAY_WINDOW) {
                    uint32_t evict = r->hwm + i - REPLAY_WINDOW;
                    r->bitmap[evict % REPLAY_WINDOW] = 0;
                }
            }
        }
        r->hwm = seq;
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        return 1;
    }
    /* seq < hwm (modular): accept only if within REPLAY_WINDOW behind hwm.
     * use modular distance, not (uint64_t)seq+W>hwm — that widening
     * ignores wrap and accepts seq=0xFFFFFFFE when hwm=5. PROTOCOL.md §3
     * requires all replay comparisons to be modular. */
    uint32_t back = r->hwm - seq;
    if (back < REPLAY_WINDOW) {
        if (r->bitmap[seq % REPLAY_WINDOW]) return 0;  /* already seen */
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        return 1;
    }
    return 0; /* below window */
}

/* -------------------------------------------------------------------------
 * session_create
 * ---------------------------------------------------------------------- */

session_t *session_create(transport_t *t,
                          const uint8_t psk[32],
                          const uint8_t pair_id[4])
{
    session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        fprintf(stderr, "session_create: calloc failed\n");
        return NULL;
    }

    s->transport = t;
    memcpy(s->psk,     psk,     32);
    memcpy(s->pair_id, pair_id, 4);

    /* mlock key material */
    crypto_mlock(s->psk,         32);
    crypto_mlock(s->hello_key,   32);
    crypto_mlock(s->session_key, 32);
    crypto_mark_dontdump(s, sizeof *s);

    s->state = SESSION_IDLE;
    s->keepalive_period_ms = 2000;  /* ESP-NOW default; B-2 over UNIX socket */
    /* 4 × 2s keepalive. Must exceed firmware FAILOVER_EMPTY_WINDOWS × WINDOW_MS
     * (3 × 2s = 6s) by a comfortable margin so window_tick failover always wins
     * the race against host liveness — exposed by deterministic RF injection. */
    s->liveness_timeout_ms = 8000;

    /* B-3: PTY defaults */
    s->pty_master_fd      = -1;
    s->pty_child_pid      = 0;
    s->current_mtu        = 222;    /* ESP-NOW / UNIX default */
    s->transport_active   = 1;      /* ESPNOW_PRIMARY by default */
    s->lora_buf_len       = 0;
    s->lora_flush_deadline_ms = 0;
    s->client_exit_code   = 0;
    s->should_exit        = 0;
    s->raw_mode_active    = 0;
    s->pty_open_ack_seen  = 0;
    s->is_client_pty      = 0;

    return s;
}

/* -------------------------------------------------------------------------
 * session_destroy
 * ---------------------------------------------------------------------- */

void session_destroy(session_t *s)
{
    if (!s) return;
    /* always call channel_close_all so channels get a clean shutdown
     * hook even in client mode (where pty state may be stale across reconnect). */
    channel_close_all(s);
    /* Wipe all key material */
    crypto_memzero(s->psk,         32);
    crypto_memzero(s->hello_key,   32);
    crypto_memzero(s->session_key, 32);
    crypto_memzero(s->nonce_a,     16);
    crypto_memzero(s->nonce_b,     16);
    /* Cycle 1 fix: route through crypto_munlock so failures match
     * crypto_mlock semantics and a future audit of mlock/munlock pairing
     * sees a single function name on both sides. */
    crypto_munlock(s->psk,         32);
    crypto_munlock(s->hello_key,   32);
    crypto_munlock(s->session_key, 32);
#if URTB_OTP
    free((void *)s->otp_path);
    if (s->otp_key_mem) {
        crypto_munlock(s->otp_key_mem, sizeof *s->otp_key_mem);
        crypto_memzero(s->otp_key_mem, sizeof *s->otp_key_mem);
        free(s->otp_key_mem);
        s->otp_key_mem = NULL;
    }
#endif
    free(s);
}

/* -------------------------------------------------------------------------
 * Build radio frame: encrypt plaintext, encode header, write to transport
 * key_to_use: if NULL, uses s->session_key; else uses supplied key.
 * direction: 0x00 = we are client, 0x01 = we are server
 * ---------------------------------------------------------------------- */

static int send_frame(session_t *s,
                      const uint8_t *key,
                      uint8_t chan_byte, uint8_t type,
                      const uint8_t *plaintext, size_t pt_len)
{
    uint8_t direction = s->is_server ? 0x01 : 0x00;

    /* Build AD: PAIR_ID(4) || SEQ(4) || CHAN(1) || TYPE(1) */
    uint8_t ad[10];
    memcpy(ad, s->pair_id, 4);
    uint32_t seq = s->tx_seq;
    ad[4] = (uint8_t)(seq        & 0xFF);
    ad[5] = (uint8_t)((seq >>  8) & 0xFF);
    ad[6] = (uint8_t)((seq >> 16) & 0xFF);
    ad[7] = (uint8_t)((seq >> 24) & 0xFF);
    ad[8] = chan_byte;
    ad[9] = type;

    /* Encrypt */
    uint8_t ct[512 + 16]; /* max radio plaintext + tag */
    /* avoid unsigned wrap in size check */
    if (pt_len > sizeof(ct) - 16) {
        fprintf(stderr, "send_frame: plaintext too large (%zu)\n", pt_len);
        return -1;
    }
    size_t ct_len = 0;
    if (crypto_encrypt(key, seq, direction, ad,
                       plaintext, pt_len,
                       ct, &ct_len) != 0)
        return -1;

    /* Build radio frame */
    uint8_t frame[300];
    int n = urtb_radio_encode(s->pair_id, seq, chan_byte, type,
                              ct, ct_len,
                              frame, sizeof(frame));
    if (n < 0) {
        fprintf(stderr, "send_frame: radio_encode failed\n");
        return -1;
    }

    s->tx_seq++;

    /* transport send first, then check wrap. The previous order
     * dropped the just-encrypted frame AND its follow-up CTRL_CLOSE because
     * tx_seq had already advanced past the threshold. PROTOCOL.md §11
     * requires CTRL_CLOSE to be transmitted before SEQ wraps. */
    int rc = s->transport->ops->send(s->transport, frame, (size_t)n);

    /* SEQ wrap check per D-08 / PROTOCOL.md §11: close before 0xFFFFFFFF - 1000 */
    if (s->tx_seq >= 0xFFFFFFFFU - 1000U && s->state != SESSION_CLOSING && s->state != SESSION_IDLE) {
        fprintf(stderr, "session: SEQ approaching wrap threshold — initiating renegotiation\n");
        session_close(s);
    }

    return rc;
}

/* -------------------------------------------------------------------------
 * Convenience: send on channel 0 (control) using hello_key or session_key
 * ---------------------------------------------------------------------- */

static int send_ctrl(session_t *s, uint8_t type,
                     const uint8_t *plaintext, size_t pt_len,
                     const uint8_t *key)
{
    /* CHAN byte for control: id=0, FF=1 (single frame), MF=0 */
    uint8_t chan_byte = (0 << 4) | CHAN_FF_BIT; /* 0x02 */
    return send_frame(s, key, chan_byte, type, plaintext, pt_len);
}

/* -------------------------------------------------------------------------
 * Send CTRL_ERROR
 * ---------------------------------------------------------------------- */

/* works in CONNECTING (hello_key) and KEY_DERIVING/ESTABLISHED/
 * CLOSING (session_key). IDLE: no keys available → no-op. */
static int send_ctrl_error(session_t *s, uint16_t code)
{
    const uint8_t *key = NULL;
    if (s->state == SESSION_CONNECTING) {
        key = s->hello_key;
    } else if (s->state == SESSION_KEY_DERIVING ||
               s->state == SESSION_ESTABLISHED ||
               s->state == SESSION_CLOSING) {
        key = s->have_session_key ? s->session_key : s->hello_key;
    } else {
        return 0;
    }
    uint8_t buf[4];
    buf[0] = (uint8_t)(code & 0xFF);
    buf[1] = (uint8_t)((code >> 8) & 0xFF);
    buf[2] = 0;
    buf[3] = 0;
    return send_ctrl(s, CTRL_ERROR, buf, 4, key);
}

/* -------------------------------------------------------------------------
 * send_hello — used by client (and retransmit)
 *
 * Phase C-4 (D-39): wire body is hello_nonce[24] || ciphertext[48], where
 * hello_nonce is freshly sampled per send and used directly as the AEAD
 * nonce instead of build_nonce(direction, seq). This avoids Poly1305
 * one-time-key reuse across sessions for hello_key (which is deterministic
 * from PSK alone). The inner ctrl_hello_t.nonce_a is unchanged and still
 * mixes into session_key via crypto_derive_session_key.
 *
 * Bypasses send_ctrl/send_frame (which would call crypto_encrypt with
 * build_nonce); does its own AD assembly and radio_encode.
 *
 * AUDIT NOTE: frame_test 3-10..3-13 cover the crypto_encrypt_with_nonce
 * wrapper but NOT this caller. If you change the AEAD call below, verify
 * by hand that you are still using crypto_encrypt_with_nonce with a
 * freshly-sampled per-send nonce — silently reverting to crypto_encrypt
 * here would re-open the D-39 BLOCKER and the regression sentinels
 * would not catch it.
 * ---------------------------------------------------------------------- */

static int send_hello(session_t *s)
{
    ctrl_hello_t hello;
    memset(&hello, 0, sizeof(hello));
    hello.version = 0x02;             /* C-4: protocol bump for explicit hello_nonce */
    hello.caps    = 0x01;              /* bit 0 = PTY */
    memcpy(hello.nonce_a, s->nonce_a, 16);

    uint8_t hello_nonce[24];
    if (crypto_random_bytes(hello_nonce, 24) != 0) {
        fprintf(stderr, "send_hello: hello_nonce gen failed\n");
        return -1;
    }

    uint32_t seq = s->tx_seq;
    uint8_t  chan_byte = (0 << 4) | CHAN_FF_BIT; /* ch0, FF=1, MF=0 */

    uint8_t ad[10];
    memcpy(ad, s->pair_id, 4);
    ad[4] = (uint8_t)(seq        & 0xFF);
    ad[5] = (uint8_t)((seq >>  8) & 0xFF);
    ad[6] = (uint8_t)((seq >> 16) & 0xFF);
    ad[7] = (uint8_t)((seq >> 24) & 0xFF);
    ad[8] = chan_byte;
    ad[9] = CTRL_HELLO;

    /* body = hello_nonce[24] || ciphertext[48] = 72 bytes */
    uint8_t body[24 + sizeof(ctrl_hello_t) + 16];
    memcpy(body, hello_nonce, 24);
    size_t ct_len = 0;
    if (crypto_encrypt_with_nonce(s->hello_key, hello_nonce, ad,
                                  (uint8_t *)&hello, sizeof(hello),
                                  body + 24, &ct_len) != 0) {
        crypto_memzero(hello_nonce, 24);
        return -1;
    }
    crypto_memzero(hello_nonce, 24);

    uint8_t frame[300];
    int n = urtb_radio_encode(s->pair_id, seq, chan_byte, CTRL_HELLO,
                              body, 24 + ct_len, frame, sizeof(frame));
    if (n < 0) {
        fprintf(stderr, "send_hello: radio_encode failed\n");
        return -1;
    }

    s->tx_seq++;

    int rc = s->transport->ops->send(s->transport, frame, (size_t)n);
    if (rc == 0)
        fprintf(stderr, "session: sent CTRL_HELLO (attempt %d)\n",
                s->hello_tx_count + 1);

    /* No SEQ wrap guard here — by construction tx_seq is at most a small
     * constant during CONNECTING (≤ 5 hello retries before IDLE), so the
     * threshold check from send_frame is structurally unreachable. Adding
     * one would also be harmful: triggering session_close() mid-handshake
     * would leave the peer waiting on a state we're tearing down.
     * The wrap invariant is enforced at send_frame for all data-path
     * frames once the session reaches ESTABLISHED. */
    return rc;
}

/* -------------------------------------------------------------------------
 * Enter IDLE — wipe session key, reset state
 * ---------------------------------------------------------------------- */

static void enter_idle(session_t *s)
{
    crypto_memzero(s->session_key,       32);
    crypto_memzero(s->hello_key,         32);  /* wipe hello_key too */
    crypto_memzero(s->nonce_a,           16);
    crypto_memzero(s->nonce_b,           16);
    memset(&s->replay, 0, sizeof(s->replay));
    s->tx_seq                  = 0;
    s->sent_ready              = 0;
    s->recv_ready              = 0;
    s->hello_tx_count          = 0;
    s->hello_backoff_ms        = 1000;
    s->hello_next_send_ms      = 0;
    s->close_tx_count          = 0;
    s->consecutive_aead_failures = 0;
    s->stored_hello_ack_len    = 0;
    s->err_session_count       = 0;
    s->have_session_key        = 0;
    s->stashed_valid           = 0;
    /* reset stale PTY state so reconnect starts fresh. channel_close_all
     * handles the actual fd/pid reap; here we just clear the handles to -1/0
     * in case close_all was never called. */
    s->pty_master_fd           = -1;
    s->pty_child_pid           = 0;
    s->pty_open_ack_seen       = 0;
    s->raw_mode_active         = 0;
    s->stdin_closed            = 0;
    s->lora_buf_len            = 0;
    s->lora_flush_deadline_ms  = 0;
    reasm_reset(&s->reasm);
    s->state = SESSION_IDLE;
    fprintf(stderr, "session: → IDLE\n");
}

/* -------------------------------------------------------------------------
 * session_connect — client: send first CTRL_HELLO
 * ---------------------------------------------------------------------- */

int session_connect(session_t *s)
{
    s->is_server = 0;

    /* Derive hello_key from PSK */
    if (crypto_derive_hello_key(s->psk, s->hello_key) != 0) return -1;

    /* Generate nonce_a for this handshake attempt */
    if (crypto_random_bytes(s->nonce_a, 16) != 0) return -1;

    s->hello_tx_count      = 0;
    s->hello_backoff_ms    = 1000;
    s->state = SESSION_CONNECTING;
    fprintf(stderr, "session: → CONNECTING\n");

    if (send_hello(s) != 0) return -1;
    s->hello_tx_count = 1;
    s->hello_next_send_ms = mono_ms() + s->hello_backoff_ms;
    s->hello_backoff_ms *= 2;

    return 0;
}

/* -------------------------------------------------------------------------
 * session_listen — server: prepare to receive CTRL_HELLO
 * ---------------------------------------------------------------------- */

int session_listen(session_t *s)
{
    s->is_server = 1;
    if (crypto_derive_hello_key(s->psk, s->hello_key) != 0) return -1;
    s->state = SESSION_IDLE;
    fprintf(stderr, "session: server mode, waiting for CTRL_HELLO\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Handle incoming CTRL_HELLO (server side)
 * ---------------------------------------------------------------------- */

static void handle_hello(session_t *s, uint32_t seq,
                         const uint8_t *plaintext, size_t pt_len)
{
    (void)seq;
    /* client must never accept CTRL_HELLO */
    if (!s->is_server) {
        fprintf(stderr, "session: client received CTRL_HELLO — ERR_SESSION\n");
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        return;
    }
    if (pt_len < sizeof(ctrl_hello_t)) {
        fprintf(stderr, "session: CTRL_HELLO too short\n");
        return;
    }
    const ctrl_hello_t *hello = (const ctrl_hello_t *)plaintext;

    /* C-4 (D-39): hello protocol version is 0x02. A peer sending 0x01 is
     * pre-C-4 and incompatible (different wire format for the hello body).
     * Surface as ERR_VERSION rather than degrading to a silent handshake
     * stall. Do NOT call track_err_session here: a buggy or pre-C-4 peer
     * will retry indefinitely on its 1s/2s/4s/8s backoff, and feeding the
     * 3-in-10s rate limiter would force the server to close every 10
     * seconds. ERR_VERSION is a hard incompatibility, not protocol
     * confusion — the server should reply, log, and remain ready. */
    if (hello->version != 0x02) {
        fprintf(stderr, "session: CTRL_HELLO version=0x%02X (expected 0x02) — ERR_VERSION\n",
                hello->version);
        send_ctrl_error(s, ERR_VERSION);
        return;
    }

    if (s->state == SESSION_KEY_DERIVING) {
        /* Idempotent CTRL_HELLO check */
        if (memcmp(hello->nonce_a, s->nonce_a, 16) == 0) {
            /* Same nonce_a: re-send stored CTRL_HELLO_ACK */
            fprintf(stderr, "session: idempotent CTRL_HELLO (same nonce_a) — re-sending ACK\n");
            if (s->stored_hello_ack_len > 0) {
                if (s->transport->ops->send(s->transport,
                                            s->stored_hello_ack,
                                            s->stored_hello_ack_len) != 0) {
                    fprintf(stderr, "session: stored CTRL_HELLO_ACK re-send failed\n");
                }
            }
            return;
        } else {
            /* Different nonce_a: client started fresh handshake */
            fprintf(stderr, "session: new nonce_a in KEY_DERIVING — aborting, re-handling\n");
            enter_idle(s);
            /* Re-derive hello_key (already done) and fall through to handle fresh */
        }
    }

    if (s->state != SESSION_IDLE) {
        /* Unexpected state for a fresh CTRL_HELLO */
        fprintf(stderr, "session: CTRL_HELLO in unexpected state %d — ERR_SESSION\n", s->state);
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        return;
    }

    /* Store nonce_a */
    memcpy(s->nonce_a, hello->nonce_a, 16);

    /* Generate nonce_b */
    if (crypto_random_bytes(s->nonce_b, 16) != 0) {
        fprintf(stderr, "session: failed to generate nonce_b\n");
        return;
    }

    /* Derive session_key */
    if (crypto_derive_session_key(s->psk, s->nonce_a, s->nonce_b,
                                  s->session_key) != 0) {
        fprintf(stderr, "session: key derivation failed\n");
        return;
    }
    s->have_session_key = 1;

    s->state = SESSION_KEY_DERIVING;
    s->key_deriving_deadline_ms = mono_ms() + 10000;
    fprintf(stderr, "session: → KEY_DERIVING (server)\n");

    /* Send CTRL_HELLO_ACK (encrypted with hello_key).
     * Phase C-4 (D-39): wire body is hello_nonce[24] || ciphertext[48]; the
     * 24-byte nonce is freshly sampled and used directly for AEAD. */
    ctrl_hello_ack_t ack;
    memset(&ack, 0, sizeof(ack));
    ack.version = 0x02;       /* C-4: protocol bump */
    ack.caps    = 0x01;
    memcpy(ack.nonce_b, s->nonce_b, 16);

    /* Save current tx_seq so we can store the encoded frame for re-send */
    uint32_t ack_seq = s->tx_seq;

    uint8_t hello_nonce[24];
    if (crypto_random_bytes(hello_nonce, 24) != 0) {
        fprintf(stderr, "session: hello_nonce gen failed\n");
        enter_idle(s);
        return;
    }

    uint8_t ad[10];
    memcpy(ad, s->pair_id, 4);
    ad[4] = (uint8_t)(ack_seq        & 0xFF);
    ad[5] = (uint8_t)((ack_seq >>  8) & 0xFF);
    ad[6] = (uint8_t)((ack_seq >> 16) & 0xFF);
    ad[7] = (uint8_t)((ack_seq >> 24) & 0xFF);
    uint8_t chan_byte = (0 << 4) | CHAN_FF_BIT; /* ch0, FF=1, MF=0 */
    ad[8] = chan_byte;
    ad[9] = CTRL_HELLO_ACK;

    /* body = hello_nonce[24] || ciphertext[48] */
    uint8_t body[24 + sizeof(ctrl_hello_ack_t) + 16];
    memcpy(body, hello_nonce, 24);
    size_t ct_len = 0;
    if (crypto_encrypt_with_nonce(s->hello_key, hello_nonce, ad,
                                  (uint8_t *)&ack, sizeof(ack),
                                  body + 24, &ct_len) != 0) {
        fprintf(stderr, "session: CTRL_HELLO_ACK encrypt failed\n");
        crypto_memzero(hello_nonce, 24);
        enter_idle(s);
        return;
    }
    crypto_memzero(hello_nonce, 24);

    uint8_t frame[300];
    int n = urtb_radio_encode(s->pair_id, ack_seq, chan_byte, CTRL_HELLO_ACK,
                              body, 24 + ct_len, frame, sizeof(frame));
    if (n < 0) {
        fprintf(stderr, "session: CTRL_HELLO_ACK encode failed\n");
        enter_idle(s);
        return;
    }

    s->tx_seq++;

    /* Store for idempotent re-send */
    if ((size_t)n <= sizeof(s->stored_hello_ack)) {
        memcpy(s->stored_hello_ack, frame, (size_t)n);
        s->stored_hello_ack_len = (size_t)n;
    }

    /* Send */
    if (s->transport->ops->send(s->transport, frame, (size_t)n) != 0) {
        fprintf(stderr, "session: CTRL_HELLO_ACK send failed\n");
        enter_idle(s);
        return;
    }
    fprintf(stderr, "session: sent CTRL_HELLO_ACK\n");

    /* No SEQ wrap guard here either — tx_seq is small during a fresh
     * handshake and triggering session_close() mid-handle_hello would
     * leave the ACK sent but CTRL_READY un-sent, stranding the client.
     * See send_hello above for the full rationale. */

    /* HW-DIAG: stagger the server CTRL_READY by 250ms so the client (which
     * sends its own CTRL_READY immediately on receiving CTRL_HELLO_ACK) gets
     * the air first. Over a half-duplex link, a back-to-back
     * CTRL_HELLO_ACK+CTRL_READY burst from the server collides with the
     * client's CTRL_READY response — both sides miss the peer's READY and
     * KEY_DERIVING times out. Applies unconditionally (both ESP-NOW and LoRa). */
    {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 250 * 1000 * 1000 };
        struct timespec rem;
        while (nanosleep(&ts, &rem) == -1 && errno == EINTR) {
            ts = rem;
        }
    }

    /* Send CTRL_READY (first frame under session_key) */
    if (send_ctrl(s, CTRL_READY, NULL, 0, s->session_key) != 0) {
        fprintf(stderr, "session: CTRL_READY send failed\n");
        enter_idle(s);
        return;
    }
    s->sent_ready = 1;
    fprintf(stderr, "session: sent CTRL_READY\n");
}

/* -------------------------------------------------------------------------
 * Handle incoming CTRL_HELLO_ACK (client side)
 * ---------------------------------------------------------------------- */

static void handle_hello_ack(session_t *s,
                             const uint8_t *plaintext, size_t pt_len)
{
    /* server must never accept CTRL_HELLO_ACK */
    if (s->is_server) {
        fprintf(stderr, "session: server received CTRL_HELLO_ACK — ERR_SESSION\n");
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        return;
    }
    if (s->state != SESSION_CONNECTING) {
        if (s->state == SESSION_KEY_DERIVING) {
            /* Silently ignore — may be a retransmit */
            return;
        }
        fprintf(stderr, "session: unexpected CTRL_HELLO_ACK in state %d\n", s->state);
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        return;
    }
    if (pt_len < sizeof(ctrl_hello_ack_t)) {
        fprintf(stderr, "session: CTRL_HELLO_ACK too short\n");
        return;
    }
    const ctrl_hello_ack_t *ack = (const ctrl_hello_ack_t *)plaintext;

    /* C-4 (D-39): hello protocol version is 0x02. A peer sending 0x01 is
     * pre-C-4 and incompatible. Surface as ERR_VERSION rather than letting
     * the handshake stall in KEY_DERIVING. Do NOT call track_err_session
     * (see handle_hello above for rationale). */
    if (ack->version != 0x02) {
        fprintf(stderr, "session: CTRL_HELLO_ACK version=0x%02X (expected 0x02) — ERR_VERSION\n",
                ack->version);
        send_ctrl_error(s, ERR_VERSION);
        return;
    }

    memcpy(s->nonce_b, ack->nonce_b, 16);

    /* Derive session_key */
    if (crypto_derive_session_key(s->psk, s->nonce_a, s->nonce_b,
                                  s->session_key) != 0) {
        fprintf(stderr, "session: key derivation failed\n");
        return;
    }
    s->have_session_key = 1;

    s->state = SESSION_KEY_DERIVING;
    s->key_deriving_deadline_ms = mono_ms() + 10000;
    fprintf(stderr, "session: → KEY_DERIVING (client)\n");

    /* Send CTRL_READY */
    if (send_ctrl(s, CTRL_READY, NULL, 0, s->session_key) != 0) {
        fprintf(stderr, "session: CTRL_READY send failed\n");
        enter_idle(s);
        return;
    }
    s->sent_ready = 1;
    fprintf(stderr, "session: sent CTRL_READY\n");

    /* If a CTRL_READY (or other session-keyed frame) arrived early
     * while we were CONNECTING, we stashed it. Replay it now. */
    if (s->stashed_valid) {
        replay_stashed_frame(s);
    }
}

/* -------------------------------------------------------------------------
 * Handle incoming CTRL_READY
 * ---------------------------------------------------------------------- */

static void handle_ready(session_t *s)
{
    if (s->state == SESSION_ESTABLISHED) {
        /* Silently ignore — late delivery */
        return;
    }
    if (s->state != SESSION_KEY_DERIVING) {
        fprintf(stderr, "session: CTRL_READY in unexpected state %d — ignoring\n", s->state);
        return;
    }
    s->recv_ready = 1;
    fprintf(stderr, "session: received CTRL_READY\n");

    if (s->sent_ready && s->recv_ready) {
        s->state = SESSION_ESTABLISHED;
        s->last_authenticated_ms = mono_ms();
        s->next_keepalive_ms = mono_ms() + s->keepalive_period_ms;
        fprintf(stderr, "session: → ESTABLISHED\n");
        /* do NOT wipe PSK here; we may need it for reconnects.
         * PSK is only wiped in session_destroy. */
        channel_open_all(s);
    }
}

/* -------------------------------------------------------------------------
 * ERR_SESSION rate limit check
 * ---------------------------------------------------------------------- */

static void track_err_session(session_t *s)
{
    int64_t now = mono_ms();
    if (s->err_session_count == 0 ||
        now - s->err_session_window_start_ms > 10000) {
        s->err_session_count = 1;
        s->err_session_window_start_ms = now;
    } else {
        s->err_session_count++;
    }
    if (s->err_session_count >= 3) {
        fprintf(stderr, "session: 3 ERR_SESSION within 10s — closing\n");
        session_close(s);
    }
}

/* -------------------------------------------------------------------------
 * Dispatch decrypted control frame
 * ---------------------------------------------------------------------- */

static void dispatch_control(session_t *s, uint8_t type,
                             const uint8_t *plaintext, size_t pt_len,
                             uint32_t seq)
{
    switch (type) {
    case CTRL_HELLO:
        handle_hello(s, seq, plaintext, pt_len);
        break;

    case CTRL_HELLO_ACK:
        handle_hello_ack(s, plaintext, pt_len);
        break;

    case CTRL_READY:
        handle_ready(s);
        break;

    case CTRL_KEEPALIVE:
        if (s->state == SESSION_ESTABLISHED) {
            /* Reply with ACK */
            send_ctrl(s, CTRL_KEEPALIVE_ACK, NULL, 0, s->session_key);
        } else if (s->state == SESSION_KEY_DERIVING) {
            /* explicitly ignore per §8 */
        } else {
            send_ctrl_error(s, ERR_SESSION);
            track_err_session(s);
        }
        break;

    case CTRL_KEEPALIVE_ACK:
        /* RTT measurement — not implemented in B-2 */
        break;

    case CTRL_CLOSE:
        fprintf(stderr, "session: received CTRL_CLOSE\n");
        if (s->state == SESSION_CLOSING) {
            /* Both sides closing simultaneously — IDLE immediately */
            send_ctrl(s, CTRL_CLOSE, NULL, 0, s->session_key);
            channel_close_all(s);
            enter_idle(s);
        } else if (s->state == SESSION_KEY_DERIVING) {
            /* Abort handshake */
            enter_idle(s);
        } else if (s->state == SESSION_ESTABLISHED) {
            /* Acknowledge and close */
            send_ctrl(s, CTRL_CLOSE, NULL, 0, s->session_key);
            channel_close_all(s);
            enter_idle(s);
        }
        /* CONNECTING branch deleted — pre-ESTABLISHED CTRL_CLOSE is
         * only reachable via the  stash replay, which the above
         * KEY_DERIVING branch now handles after handle_hello_ack. */
        break;

    case CTRL_ERROR:
        if (pt_len >= 2) {
            uint16_t code = (uint16_t)plaintext[0] | ((uint16_t)plaintext[1] << 8);
            fprintf(stderr, "session: received CTRL_ERROR code=0x%04X\n", code);
            if (code == ERR_AUTH_FAIL) {
                channel_close_all(s);
                enter_idle(s);
            }
        }
        break;

    default:
        fprintf(stderr, "session: unknown control type 0x%02X — ERR_SESSION\n", type);
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        break;
    }
}

/* -------------------------------------------------------------------------
 * session_set_transport_mode
 * transport_active: 1 = ESP-NOW (2s/6s), 2 = LoRa (30s/90s)
 * ---------------------------------------------------------------------- */

void session_set_transport_mode(session_t *s, uint8_t transport_active)
{
    if (!s) return;
    /* if leaving LoRa for ESP-NOW, force-flush the coalescer BEFORE
     * switching mode — otherwise queued bytes sit forever (500ms tick is
     * canceled in ESP-NOW path). */
    uint8_t old_mode = s->transport_active;
    if (old_mode == 2 && transport_active != 2 && s->lora_buf_len > 0) {
        fprintf(stderr, "session: flushing lora_buf (%zu bytes) on mode switch\n",
                s->lora_buf_len);
        channel_pty_flush_lora(s);
    }

    if (transport_active == 2) {
        s->keepalive_period_ms = 30000;
        s->liveness_timeout_ms = 90000;
        s->current_mtu         = 72;
    } else {
        /* default (ESP-NOW or unknown) */
        s->keepalive_period_ms = 2000;
        s->liveness_timeout_ms = 8000;  /* 4 × 2s; see init for rationale */
        s->current_mtu         = 222;
    }
    s->transport_active = transport_active ? transport_active : 1;
    s->next_keepalive_ms = mono_ms() + s->keepalive_period_ms;
    /* reset liveness baseline so the new, longer window doesn't fire
     * immediately due to a stale last_authenticated_ms. */
    s->last_authenticated_ms = mono_ms();
    fprintf(stderr, "session: transport mode %u → keepalive=%lldms liveness=%lldms mtu=%u\n",
            transport_active,
            (long long)s->keepalive_period_ms,
            (long long)s->liveness_timeout_ms,
            s->current_mtu);
}

/* -------------------------------------------------------------------------
 * Process one incoming radio frame
 * ---------------------------------------------------------------------- */

static void process_frame(session_t *s, const uint8_t *frame, size_t frame_len);

/* replay a frame that was stashed in CONNECTING, after session_key
 * becomes available. */
static void replay_stashed_frame(session_t *s)
{
    if (!s->stashed_valid) return;
    s->stashed_valid = 0;

    uint8_t plaintext[512];
    size_t  pt_len = 0;

    uint8_t dec_direction = s->is_server ? 0x00 : 0x01;
    if (s->stashed_ct_len < 16 ||
        s->stashed_ct_len - 16 > sizeof(plaintext)) {
        fprintf(stderr, "session: stashed frame too large — dropped\n");
        return;
    }
    if (crypto_decrypt(s->session_key, s->stashed_seq, dec_direction,
                       s->stashed_ad,
                       s->stashed_ct, s->stashed_ct_len,
                       plaintext, &pt_len) != 0) {
        fprintf(stderr, "session: stashed frame AEAD failed — dropped\n");
        crypto_memzero(plaintext, sizeof(plaintext));
        return;
    }

    /* Successful decrypt: update replay window + dispatch */
    if (!replay_accept(&s->replay, s->stashed_seq)) {
        fprintf(stderr, "session: stashed frame replay check failed\n");
        crypto_memzero(plaintext, sizeof(plaintext));
        return;
    }
    s->consecutive_aead_failures = 0;
    s->last_authenticated_ms = mono_ms();

    uint8_t chan_id = (s->stashed_chan_byte >> 4) & 0x0F;
    if (chan_id == 0) {
        dispatch_control(s, s->stashed_type, plaintext, pt_len, s->stashed_seq);
    }
    crypto_memzero(plaintext, sizeof(plaintext));
}

static void process_frame(session_t *s, const uint8_t *frame, size_t frame_len)
{
    uint8_t  pair_id[4], chan_byte, type;
    uint32_t seq;
    const uint8_t *ct;
    size_t ct_len;

    if (urtb_radio_decode(frame, frame_len, pair_id, &seq,
                          &chan_byte, &type, &ct, &ct_len) != 0) {
        fprintf(stderr, "session: radio_decode failed\n");
        return;
    }

    /* Check PAIR_ID */
    if (memcmp(pair_id, s->pair_id, 4) != 0) {
        /* Wrong pair — discard silently */
        return;
    }

    uint8_t chan_id = (chan_byte >> 4) & 0x0F;
    uint8_t direction_incoming = s->is_server ? 0x00 : 0x01;
    /* direction_incoming: if we're server, incoming is from client (0x00) */

    /* an unsolicited CTRL_HELLO_ACK arriving at an IDLE server has
     * nothing to decrypt against (no session_key, and the wrong key path
     * leads it into the data-frame AEAD-failure branch which increments
     * consecutive_aead_failures). A remote attacker could prime a premature
     * close by sending crafted CTRL_HELLO_ACKs before any legitimate
     * CTRL_HELLO. Discard the frame, count it as an ERR_SESSION event for
     * rate-limiting, and skip the AEAD path entirely. */
    if (s->is_server && s->state == SESSION_IDLE &&
        chan_id == 0 && type == CTRL_HELLO_ACK) {
        fprintf(stderr,
                "session: unsolicited CTRL_HELLO_ACK in IDLE — discarded\n");
        track_err_session(s);
        return;
    }

    /* Build AD */
    uint8_t ad[10];
    memcpy(ad, pair_id, 4);
    ad[4] = (uint8_t)(seq        & 0xFF);
    ad[5] = (uint8_t)((seq >>  8) & 0xFF);
    ad[6] = (uint8_t)((seq >> 16) & 0xFF);
    ad[7] = (uint8_t)((seq >> 24) & 0xFF);
    ad[8] = chan_byte;
    ad[9] = type;

    /* Determine which key to use for decryption */
    const uint8_t *decrypt_key = NULL;
    int is_hello_frame = (chan_id == 0 &&
                          (type == CTRL_HELLO || type == CTRL_HELLO_ACK));

    /* Server receives CTRL_HELLO with hello_key */
    /* Client receives CTRL_HELLO_ACK with hello_key */
    if (chan_id == 0 && type == CTRL_HELLO && s->is_server) {
        decrypt_key = s->hello_key;
    } else if (chan_id == 0 && type == CTRL_HELLO_ACK && !s->is_server) {
        decrypt_key = s->hello_key;
    } else {
        decrypt_key = s->session_key;
        is_hello_frame = 0;
    }

    /* For CTRL_HELLO/CTRL_HELLO_ACK: direction is fixed */
    uint8_t dec_direction = direction_incoming;
    if (is_hello_frame) {
        /* CTRL_HELLO: sent by client (direction 0x00), so nonce uses 0x00 */
        /* CTRL_HELLO_ACK: sent by server (direction 0x01) */
        if (type == CTRL_HELLO)     dec_direction = 0x00;
        if (type == CTRL_HELLO_ACK) dec_direction = 0x01;
    }

    /* AEAD decrypt */
    uint8_t plaintext[512];
    size_t pt_len = 0;

    /* Phase C-4 (D-39): for hello frames, the wire body carries a 24-byte
     * cleartext hello_nonce prefix used directly as the AEAD nonce. Peel it
     * off here so the decrypt path sees the bare ciphertext. Other frames
     * are unchanged. */
    const uint8_t *dec_ct = ct;
    size_t         dec_ct_len = ct_len;
    uint8_t        hello_nonce[24];
    int            have_hello_nonce = 0;
    if (is_hello_frame) {
        if (ct_len < 24 + 16) {
            fprintf(stderr, "session: hello frame body too short (%zu) — dropped\n",
                    ct_len);
            return;
        }
        memcpy(hello_nonce, ct, 24);
        dec_ct      = ct + 24;
        dec_ct_len  = ct_len - 24;
        have_hello_nonce = 1;
    }

    /* bound ciphertext length against plaintext buffer. */
    if (dec_ct_len < 16 || dec_ct_len - 16 > sizeof(plaintext)) {
        fprintf(stderr, "session: frame too large (ct_len=%zu) — dropped\n", dec_ct_len);
        if (have_hello_nonce) crypto_memzero(hello_nonce, 24);
        return;
    }

    /* if we are CONNECTING and a non-HELLO control frame arrived, we
     * don't yet have a session_key. Stash it so we can decrypt after
     * handle_hello_ack derives the key. */
    if (s->state == SESSION_CONNECTING && !is_hello_frame && !s->have_session_key) {
        if (ct_len <= sizeof(s->stashed_ct) && !s->stashed_valid) {
            s->stashed_valid    = 1;
            s->stashed_chan_byte = chan_byte;
            s->stashed_type      = type;
            s->stashed_seq       = seq;
            memcpy(s->stashed_ad, ad, 10);
            memcpy(s->stashed_ct, ct, ct_len);
            s->stashed_ct_len    = ct_len;
            fprintf(stderr, "session: stashed early frame (type=0x%02X) in CONNECTING\n", type);
        }
        return;
    }

    int decrypt_rc;
    if (is_hello_frame) {
        decrypt_rc = crypto_decrypt_with_nonce(decrypt_key, hello_nonce, ad,
                                               dec_ct, dec_ct_len,
                                               plaintext, &pt_len);
        crypto_memzero(hello_nonce, 24);
        have_hello_nonce = 0;
    } else {
        decrypt_rc = crypto_decrypt(decrypt_key, seq, dec_direction, ad,
                                    dec_ct, dec_ct_len, plaintext, &pt_len);
    }

    if (decrypt_rc != 0) {
        crypto_memzero(plaintext, sizeof(plaintext));
        /* AEAD failure */
        if (chan_id == 0 && type == CTRL_HELLO) {
            /* PROTOCOL.md §3: discard silently, no response */
            return;
        } else if (chan_id == 0 && type == CTRL_HELLO_ACK) {
            /* Discard silently, remain in CONNECTING */
            return;
        } else if (chan_id == 0 && type == CTRL_READY) {
            fprintf(stderr, "session: CTRL_READY AEAD failed — sending ERR_AUTH_FAIL\n");
            /* emit CTRL_ERROR(ERR_AUTH_FAIL) encrypted with hello_key
             * (session_key can't be trusted), then return to IDLE. */
            if (s->state == SESSION_KEY_DERIVING) {
                uint8_t buf[4];
                buf[0] = (uint8_t)(ERR_AUTH_FAIL & 0xFF);
                buf[1] = (uint8_t)((ERR_AUTH_FAIL >> 8) & 0xFF);
                buf[2] = 0;
                buf[3] = 0;
                send_ctrl(s, CTRL_ERROR, buf, 4, s->hello_key);
                enter_idle(s);
            }
            return;
        } else {
            /* Data frame AEAD failure */
            fprintf(stderr, "session: AEAD failure on data frame (seq=%u)\n", seq);
            s->consecutive_aead_failures++;
            if (s->consecutive_aead_failures >= AEAD_FAIL_THRESHOLD) {
                fprintf(stderr, "session: %d consecutive AEAD failures — closing\n",
                        s->consecutive_aead_failures);
                session_close(s);
            }
            return;
        }
    }

    /* Replay check runs AFTER successful AEAD verification, using the
     * SEQ that was authenticated. Only for session frames (not pre-session
     * hello). This prevents a forged frame from poisoning the replay window. */
    if (!is_hello_frame) {
        if (!replay_accept(&s->replay, seq)) {
            fprintf(stderr, "session: replay detected (seq=%u) — dropped\n", seq);
            crypto_memzero(plaintext, sizeof(plaintext));
            return;
        }
    }

    /* Successful decrypt: reset AEAD failure counter and update liveness */
    s->consecutive_aead_failures = 0;
    s->last_authenticated_ms = mono_ms();

    /* Dispatch */
    if (chan_id == 0) {
        dispatch_control(s, type, plaintext, pt_len, seq);
    } else {
        /* Channel dispatch (PTY and others) */
        if (s->state != SESSION_ESTABLISHED) {
            /* Ignore data frames before established */
            crypto_memzero(plaintext, sizeof(plaintext));
            return;
        }

        /* §7 fragment reassembly. Intercept the FF/MF flags before
         * dispatching to the channel handler. Single-fragment frames
         * (FF=1, MF=0) deliver directly with no copy. */
        int ff_flag = (chan_byte & CHAN_FF_BIT) ? 1 : 0;
        int mf_flag = (chan_byte & CHAN_MF_BIT) ? 1 : 0;
        int64_t now_for_reasm = mono_ms();
        int64_t reasm_to_ms = (s->transport_active == 2)
                              ? REASM_TIMEOUT_LORA_MS
                              : REASM_TIMEOUT_ESPNOW_MS;
        const uint8_t *deliver_buf = NULL;
        size_t         deliver_len = 0;
        int rc = reasm_feed(&s->reasm, chan_id, type,
                            ff_flag, mf_flag,
                            plaintext, pt_len,
                            now_for_reasm, reasm_to_ms,
                            &deliver_buf, &deliver_len);
        if (rc == REASM_DELIVER) {
            channel_dispatch(s, chan_byte, type, deliver_buf, deliver_len);
        } else if (rc == REASM_ERROR) {
            fprintf(stderr,
                    "session: reasm error on ch%u type=0x%02X (ff=%d mf=%d len=%zu) — buffer reset\n",
                    chan_id, type, ff_flag, mf_flag, pt_len);
        }
        /* REASM_DROP: fragment buffered or discarded silently. */
    }

    crypto_memzero(plaintext, sizeof(plaintext));
}

/* -------------------------------------------------------------------------
 * session_close — send CTRL_CLOSE, enter CLOSING
 * ---------------------------------------------------------------------- */

void session_close(session_t *s)
{
    if (s->state == SESSION_IDLE || s->state == SESSION_CLOSING) return;
    fprintf(stderr, "session: initiating close\n");
    session_state_t old_state = s->state;
    s->state = SESSION_CLOSING;
    s->close_tx_count = 0;
    if (old_state != SESSION_CONNECTING) {
        /* Only send CTRL_CLOSE if we have a session_key */
        const uint8_t *key = (old_state == SESSION_KEY_DERIVING || old_state == SESSION_ESTABLISHED)
                             ? s->session_key : s->hello_key;
        send_ctrl(s, CTRL_CLOSE, NULL, 0, key);
    }
    s->close_tx_count = 1;
    s->close_next_send_ms = mono_ms() + 1000;
}

/* -------------------------------------------------------------------------
 * session_send — send plaintext payload
 * ---------------------------------------------------------------------- */

/* session_send() gates on ESTABLISHED to prevent any data send
 * from leaking out during IDLE/CONNECTING/KEY_DERIVING/CLOSING. session_close()
 * intentionally bypasses this gate by calling send_ctrl() directly, because
 * CTRL_CLOSE must remain transmittable from any post-handshake state — including
 * during teardown initiated from inside session_run(), where the state has
 * already flipped to SESSION_CLOSING by the time we send the close frame.
 * See PROTOCOL.md §11. */
int session_send(session_t *s, uint8_t chan_byte, uint8_t type,
                 const uint8_t *plaintext, size_t plaintext_len)
{
    if (s->state != SESSION_ESTABLISHED) {
        fprintf(stderr, "session_send: not ESTABLISHED\n");
        return -1;
    }
    return send_frame(s, s->session_key, chan_byte, type, plaintext, plaintext_len);
}

int session_send_data(session_t *s, uint8_t chan_id, uint8_t type,
                      const uint8_t *plaintext, size_t plaintext_len)
{
    if (s->state != SESSION_ESTABLISHED) {
        fprintf(stderr, "session_send_data: not ESTABLISHED\n");
        return -1;
    }
    if (chan_id >= 16) return -1;

    size_t mtu = s->current_mtu ? s->current_mtu : 222;
    /* Hard floor: a 1-byte MTU would loop. The smallest legal LoRa MTU
     * the host ever sets is 72; but defend against zero/garbage. */
    if (mtu < 16) mtu = 16;

    /* Fast path: single fragment fits in one frame. */
    if (plaintext_len <= mtu) {
        uint8_t chan_byte = (uint8_t)((chan_id << 4) | CHAN_FF_BIT);
        return send_frame(s, s->session_key, chan_byte, type,
                          plaintext, plaintext_len);
    }

    /* Multi-fragment send. §7 sender rules:
     *   first  : FF=1, MF=1
     *   middle : FF=0, MF=1
     *   last   : FF=0, MF=0
     */
    size_t nfrags = (plaintext_len + mtu - 1) / mtu;
    fprintf(stderr,
            "session: fragmenting %zu bytes into %zu fragments at mtu=%zu chan=%u type=%u\n",
            plaintext_len, nfrags, mtu, (unsigned)chan_id, (unsigned)type);
    size_t off = 0;
    int first = 1;
    while (off < plaintext_len) {
        size_t take = plaintext_len - off;
        if (take > mtu) take = mtu;
        int last = (off + take == plaintext_len);

        uint8_t flags = 0;
        if (first) flags |= CHAN_FF_BIT;
        if (!last) flags |= CHAN_MF_BIT;
        uint8_t chan_byte = (uint8_t)((chan_id << 4) | flags);

        if (send_frame(s, s->session_key, chan_byte, type,
                       plaintext + off, take) != 0) {
            fprintf(stderr,
                    "session_send_data: fragment send failed at offset %zu/%zu\n",
                    off, plaintext_len);
            return -1;
        }
        off += take;
        first = 0;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * session_run — main event loop
 * ---------------------------------------------------------------------- */

int session_run(session_t *s)
{
    uint8_t buf[600];

    /* Track whether we have ever left IDLE; this ensures the server's initial
     * IDLE state doesn't cause an immediate exit before the first CTRL_HELLO. */
    int ever_active = !s->is_server; /* client starts CONNECTING (non-IDLE) */

    for (;;) {
        /* Exit condition: reached IDLE after being active */
        if (s->state == SESSION_IDLE && ever_active) break;
        if (s->state != SESSION_IDLE) ever_active = 1;

        int64_t now = mono_ms();
        /* 100ms default poll timeout. The SIGINT/SIGWINCH pump on
         * the client may see up to 100ms of tail latency under an idle
         * link, because handle_sigint only sets a sig_atomic_t flag and
         * the loop only checks it after poll() returns. EINTR from the
         * signal handler typically breaks poll sooner on Linux glibc and
         * macOS libSystem, but POSIX does not require it. Acceptable for
         * an interactive terminal; reduce if sub-100ms signal latency
         * becomes a requirement. */
        int poll_ms = 100; /* default poll timeout */

        /* ---- Timer: CTRL_HELLO retransmit (client, CONNECTING) ----
         * Schedule: send 5 total (1 initial + 4 retries), backoffs 1s/2s/4s/8s.
         * After 5th send, backoff is 16s — peer has 16s to reply.
         * When that 16s expires (t≈31s), give up. Total ≈31s (D-33). */
        if (s->state == SESSION_CONNECTING) {
            if (now >= s->hello_next_send_ms) {
                if (s->hello_tx_count < 5) {
                    if (send_hello(s) == 0) {
                        s->hello_tx_count++;
                        s->hello_next_send_ms = now + s->hello_backoff_ms;
                        s->hello_backoff_ms *= 2;
                        fprintf(stderr, "session: CTRL_HELLO attempt %d/5\n",
                                s->hello_tx_count);
                    }
                } else {
                    fprintf(stderr, "session: handshake timeout after 5 attempts (31s)\n");
                    if (s->transport && s->transport->ops &&
                        strcmp(s->transport->ops->name, "heltec") == 0)
                        fprintf(stderr, "  Hint: verify both endpoints use the same REGION "
                                        "(same LoRa frequency).\n");
                    enter_idle(s);
                    break;
                }
            }
            int64_t wait = s->hello_next_send_ms - now;
            if (wait > 0 && wait < poll_ms) poll_ms = (int)wait;
        }

        /* ---- Timer: KEY_DERIVING timeout (10s) ---- */
        if (s->state == SESSION_KEY_DERIVING) {
            if (now >= s->key_deriving_deadline_ms) {
                fprintf(stderr, "session: KEY_DERIVING timeout\n");
                enter_idle(s);
                break;
            }
            int64_t wait = s->key_deriving_deadline_ms - now;
            if (wait > 0 && wait < poll_ms) poll_ms = (int)wait;
        }

        /* ---- Timer: keepalive (ESTABLISHED) ---- */
        if (s->state == SESSION_ESTABLISHED) {
            if (now >= s->next_keepalive_ms) {
                send_ctrl(s, CTRL_KEEPALIVE, NULL, 0, s->session_key);
                s->next_keepalive_ms = now + s->keepalive_period_ms;
            }
            int64_t wait = s->next_keepalive_ms - now;
            if (wait > 0 && wait < poll_ms) poll_ms = (int)wait;

            /* Liveness watchdog */
            int64_t since_last = now - s->last_authenticated_ms;
            if (since_last > s->liveness_timeout_ms) {
                fprintf(stderr, "session: liveness timeout (%lldms) — closing\n",
                        (long long)since_last);
                session_close(s);
                continue;
            }
            int64_t watchdog_remaining = s->liveness_timeout_ms - since_last;
            if (watchdog_remaining < poll_ms) poll_ms = (int)watchdog_remaining;
        }

        /* ---- Timer: CTRL_CLOSE retransmit (CLOSING) ---- */
        if (s->state == SESSION_CLOSING) {
            if (now >= s->close_next_send_ms) {
                if (s->close_tx_count < 3) {
                    /* Only retransmit if we have a session_key (ESTABLISHED/KEY_DERIVING path).
                     * From CONNECTING path, we never had a session_key, so just force-close. */
                    if (s->have_session_key) {
                        send_ctrl(s, CTRL_CLOSE, NULL, 0, s->session_key);
                        s->close_tx_count++;
                        int64_t wait_after = (s->close_tx_count == 1) ? 1000 : 2000;
                        s->close_next_send_ms = now + wait_after;
                        fprintf(stderr, "session: CTRL_CLOSE %d/3\n", s->close_tx_count);
                    } else {
                        /* No session key — force close immediately */
                        channel_close_all(s);
                        enter_idle(s);
                        break;
                    }
                } else {
                    /* Force close */
                    fprintf(stderr, "session: force close after CTRL_CLOSE retransmits\n");
                    channel_close_all(s);
                    enter_idle(s);
                    break;
                }
            }
            int64_t wait = s->close_next_send_ms - now;
            if (wait > 0 && wait < poll_ms) poll_ms = (int)wait;
        }

        /* ---- B-3: LoRa coalescing timer ---- */
        if (s->state == SESSION_ESTABLISHED &&
            s->lora_buf_len > 0 && s->lora_flush_deadline_ms > 0) {
            if (now >= s->lora_flush_deadline_ms) {
                channel_pty_flush_lora(s);
            } else {
                int64_t wait = s->lora_flush_deadline_ms - now;
                if (wait > 0 && wait < poll_ms) poll_ms = (int)wait;
            }
        }

        /* ---- §7 reassembly timeouts ---- */
        if (s->state == SESSION_ESTABLISHED) {
            reasm_tick(&s->reasm, now);
        }

        /* ---- Poll transport, PTY master (server), stdin (client) ---- */
        int tfd = s->transport->ops->get_fd ? s->transport->ops->get_fd(s->transport) : -1;
        int use_poll = (tfd >= 0);

        if (use_poll) {
            struct pollfd pfds[4];
            int nfds = 0;

            pfds[nfds].fd = tfd;
            pfds[nfds].events = POLLIN;
            int idx_transport = nfds++;

            int idx_pty = -1;
            if (s->state == SESSION_ESTABLISHED && s->pty_master_fd >= 0) {
                pfds[nfds].fd = s->pty_master_fd;
                pfds[nfds].events = POLLIN;
                /* also poll for POLLOUT when we have a backlog. */
                if (s->pty_master_backlog_len > 0) {
                    pfds[nfds].events |= POLLOUT;
                }
                idx_pty = nfds++;
            }

            int idx_stdin = -1;
            if (s->state == SESSION_ESTABLISHED && s->is_client_pty &&
                s->pty_open_ack_seen && !s->is_server && !s->stdin_closed) {
                pfds[nfds].fd = STDIN_FILENO;
                pfds[nfds].events = POLLIN;
                idx_stdin = nfds++;
            }

            int idx_inject = -1;
#if defined(URTB_TEST_INJECT) && URTB_TEST_INJECT
            int inject_fd = test_inject_listen_fd();
            if (inject_fd >= 0) {
                pfds[nfds].fd = inject_fd;
                pfds[nfds].events = POLLIN;
                idx_inject = nfds++;
            }
#endif

            int pr = poll(pfds, (nfds_t)nfds, poll_ms);
            if (pr < 0) {
                if (errno == EINTR) { errno = 0; continue; }
                fprintf(stderr, "session: poll: %s — closing\n", strerror(errno));
                channel_close_all(s);
                enter_idle(s);
                break;
            }

            /* PTY master readable (server) */
            if (idx_pty >= 0 && (pfds[idx_pty].revents & (POLLIN|POLLHUP|POLLERR))) {
                channel_pty_pump_master(s);
            }
            /* PTY master writable (server backlog flush) */
            if (idx_pty >= 0 && (pfds[idx_pty].revents & POLLOUT)) {
                channel_pty_flush_master_backlog(s);
            }

            /* stdin readable (client) */
            if (idx_stdin >= 0 && (pfds[idx_stdin].revents & (POLLIN|POLLHUP|POLLERR))) {
                if (channel_pty_pump_stdin(s) < 0) {
                    /* stdin EOF — session_close already called */
                }
            }

#if defined(URTB_TEST_INJECT) && URTB_TEST_INJECT
            if (idx_inject >= 0 && (pfds[idx_inject].revents & POLLIN)) {
                /* Pass the heltec serial fd directly so the test_inject
                 * handler can write a USB_TEST_INJECT frame without going
                 * through transport->send (which would wrap it as
                 * USB_DATA_TX). */
                test_inject_handle_accept(tfd);
            }
#else
            (void)idx_inject;
#endif

            /* Transport readable */
            if (pfds[idx_transport].revents & (POLLHUP|POLLERR|POLLNVAL)) {
                fprintf(stderr, "session: transport poll hup/err — closing\n");
                channel_close_all(s);
                enter_idle(s);
                break;
            }
            if (pfds[idx_transport].revents & POLLIN) {
                /* Pass a small positive timeout so transports that need to
                 * read a full frame (e.g. length prefix + body) don't
                 * spuriously time out between reads. */
                int n = s->transport->ops->recv(s->transport, buf, sizeof(buf), 500);
                if (n > 0) {
                    process_frame(s, buf, (size_t)n);
                } else if (n < 0) {
                    if (errno == EBADF || errno == EPIPE || errno == EIO ||
                        errno == ECONNRESET || errno == ENOTCONN) {
                        fprintf(stderr, "session: transport recv error (%s) — closing\n",
                                strerror(errno));
                        channel_close_all(s);
                        enter_idle(s);
                        break;
                    }
                    errno = 0;
                }
            }
        } else {
            /* No pollable fd (shouldn't happen with current transports) —
             * fall back to blocking recv with timeout. */
            int n = s->transport->ops->recv(s->transport, buf, sizeof(buf), poll_ms);
            if (n < 0) {
                if (errno == EBADF || errno == EPIPE || errno == EIO ||
                    errno == ECONNRESET || errno == ENOTCONN) {
                    fprintf(stderr, "session: transport recv error (%s) — closing\n",
                            strerror(errno));
                    channel_close_all(s);
                    enter_idle(s);
                    break;
                }
                errno = 0;
                continue;
            }
            if (n > 0) process_frame(s, buf, (size_t)n);
        }

        /* pick up USB_STATUS_RSP transport_active from heltec. */
        uint8_t pending = transport_heltec_consume_pending_mode(s->transport);
        if (pending != 0) {
            session_set_transport_mode(s, pending);
        }

        /* C-3: pick up the full USB_STATUS_RSP body and apply wrap
         * reconciliation for the four uint16 rolling counters. */
        {
            uint8_t sb[16];
            if (transport_heltec_consume_status_rsp(s->transport, sb)) {
                /* RSSI / SNR sentinel: 0x00 in the wire byte means "no data".
                 * Store as raw int8_t in the session — display layer (urtb
                 * status, OLED) is responsible for printing "--" on 0. */
                s->espnow_rssi_last     = (int8_t)sb[1];
                s->lora_rssi_last       = (int8_t)sb[2];
                s->lora_snr_last_decideb = (int8_t)sb[3];

                uint16_t e_ok   = (uint16_t)sb[4]  | ((uint16_t)sb[5]  << 8);
                uint16_t e_fail = (uint16_t)sb[6]  | ((uint16_t)sb[7]  << 8);
                uint16_t l_ok   = (uint16_t)sb[8]  | ((uint16_t)sb[9]  << 8);
                uint16_t l_fail = (uint16_t)sb[10] | ((uint16_t)sb[11] << 8);
                uint16_t e_drop = (uint16_t)sb[12] | ((uint16_t)sb[13] << 8);

                if (s->stats_have_prev) {
                    s->espnow_tx_ok_total      += (uint32_t)(uint16_t)(e_ok   - s->espnow_tx_ok_prev);
                    s->espnow_tx_fail_total    += (uint32_t)(uint16_t)(e_fail - s->espnow_tx_fail_prev);
                    s->espnow_ring_drop_total  += (uint32_t)(uint16_t)(e_drop - s->espnow_ring_drop_prev);
                    s->lora_tx_ok_total        += (uint32_t)(uint16_t)(l_ok   - s->lora_tx_ok_prev);
                    s->lora_tx_fail_total      += (uint32_t)(uint16_t)(l_fail - s->lora_tx_fail_prev);
                } else {
                    s->stats_have_prev = 1;
                }
                s->espnow_tx_ok_prev      = e_ok;
                s->espnow_tx_fail_prev    = e_fail;
                s->espnow_ring_drop_prev  = e_drop;
                s->lora_tx_ok_prev        = l_ok;
                s->lora_tx_fail_prev      = l_fail;
            }
        }

        /* Client should_exit flag from PTY_EOF */
        if (s->should_exit) {
            session_close(s);
            s->should_exit = 0;
        }

        /* B-3: client tick hook — flush pending SIGINT/SIGWINCH */
        if (session_run_tick) session_run_tick(s);
    }

    return (s->state == SESSION_IDLE) ? 0 : -1;
}
