/*
 * session.h — session state machine
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * States: SESSION_IDLE → SESSION_CONNECTING → SESSION_KEY_DERIVING
 *         → SESSION_ESTABLISHED → SESSION_CLOSING → SESSION_IDLE
 */
#ifndef URTB_SESSION_H
#define URTB_SESSION_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>

#include <sys/types.h>

#include "transport.h"
#include "channel.h"
#include "reasm.h"
#if URTB_OTP
#include "otp.h"
#endif

/* -------------------------------------------------------------------------
 * Session state enum
 * ---------------------------------------------------------------------- */

typedef enum {
    SESSION_IDLE         = 0,
    SESSION_CONNECTING   = 1,  /* client only: waiting for CTRL_HELLO_ACK */
    SESSION_KEY_DERIVING = 2,  /* both: CTRL_READY sent, waiting for peer's */
    SESSION_ESTABLISHED  = 3,
    SESSION_CLOSING      = 4,
} session_state_t;

/* -------------------------------------------------------------------------
 * Replay window (PROTOCOL.md §3)
 * ---------------------------------------------------------------------- */

#define REPLAY_WINDOW 256

typedef struct {
    uint32_t hwm;
    int      initialized;
    uint8_t  bitmap[REPLAY_WINDOW];
} replay_window_t;

/* -------------------------------------------------------------------------
 * Session struct (opaque to callers via forward decl in channel.h)
 * ---------------------------------------------------------------------- */

struct session {
    /* Transport */
    transport_t *transport;

    /* Identity */
    uint8_t psk[32];           /* mlock'd */
    uint8_t pair_id[4];

    /* Keys */
    uint8_t hello_key[32];     /* derived from PSK, mlock'd */
    uint8_t session_key[32];   /* derived on handshake, mlock'd */

    /* Nonces */
    uint8_t nonce_a[16];       /* our nonce (client) or stored peer nonce (server) */
    uint8_t nonce_b[16];       /* peer nonce */

    /* State */
    session_state_t state;
    int is_server;             /* 1 = listening side */

    /* Sequence counters */
    uint32_t tx_seq;           /* our outgoing SEQ */
    uint32_t rx_hwm;           /* used only for replay window */

    /* Replay window (incoming from peer) */
    replay_window_t replay;

    /* CTRL_HELLO retransmit state (client) */
    int     hello_tx_count;    /* number of CTRL_HELLO sent (max 5) */
    int64_t hello_next_send_ms; /* monotonic ms when next CTRL_HELLO is due */
    int64_t hello_backoff_ms;   /* current backoff interval */

    /* Stored CTRL_HELLO_ACK for idempotent re-send (server in KEY_DERIVING).
     * Phase C-4 (D-39): body now carries a 24-byte cleartext hello_nonce
     * prefix in addition to the 32-byte plaintext + 16-byte tag. */
    uint8_t stored_hello_ack[12 + 24 + 32 + 16]; /* hdr + nonce + ct + tag */
    size_t  stored_hello_ack_len;

    /* Key derivation state tracking */
    int     sent_ready;        /* 1 = sent CTRL_READY */
    int     recv_ready;        /* 1 = received peer CTRL_READY */
    int64_t key_deriving_deadline_ms; /* 10s timeout */

    /* AEAD failure tracking (data frames in ESTABLISHED) */
    int     consecutive_aead_failures;

    /* Explicit flag: session_key has been derived (replaces has_key heuristic) */
    int     have_session_key;

    /* Stashed frame buffered in CONNECTING (e.g., early CTRL_READY) to be
     * decrypted after handle_hello_ack derives session_key. */
    int      stashed_valid;
    uint8_t  stashed_chan_byte;
    uint8_t  stashed_type;
    uint32_t stashed_seq;
    uint8_t  stashed_ct[600];
    size_t   stashed_ct_len;
    uint8_t  stashed_ad[10];

    /* Keepalive / liveness */
    int64_t last_authenticated_ms; /* monotonic ms of last successfully decrypted frame */
    int64_t next_keepalive_ms;
    /* widen to int64_t. The compare sites in session.c and the
     * setter in session_set_transport_mode all do timer arithmetic against
     * int64_t monotonic ms; the previous int risked truncation when set
     * to multi-second LoRa values combined with future keepalive scaling. */
    int64_t keepalive_period_ms;   /* 2000 for ESP-NOW/unix, 30000 for LoRa */
    int64_t liveness_timeout_ms;   /* ESP-NOW: 4 × 2s = 8s; LoRa: 3 × 30s = 90s */

    /* CTRL_CLOSE retransmit state */
    int     close_tx_count;
    int64_t close_next_send_ms;

    /* ERR_SESSION rate limiting (3 in 10s → close) */
    int     err_session_count;
    int64_t err_session_window_start_ms;

    /* Channel registry */
    const channel_ops_t *channels[CHANNEL_MAX];

    /* ---- PTY (B-3) ---- */
    /* Server-side PTY state */
    int     pty_master_fd;       /* -1 if not open */
    pid_t   pty_child_pid;       /* 0 if not spawned */

    /* Client-side PTY session flags */
    int     is_client_pty;       /* 1 = client has spawned a PTY session mode */
    int     raw_mode_active;     /* 1 if stdin is in raw mode (client) */
    int     pty_open_ack_seen;   /* client received PTY_OPEN_ACK */
    int     stdin_closed;        /* client stdin reached EOF — stop polling it */

    /* Current transport mode: 1=ESPNOW_PRIMARY, 2=LORA_FALLBACK */
    uint8_t transport_active;
    uint16_t current_mtu;        /* 222 or 72 */

    /* LoRa PTY coalescing buffer (server→client PTY_DATA, or client→server) */
    uint8_t lora_buf[512];
    size_t  lora_buf_len;
    int64_t lora_flush_deadline_ms;

    /* server-side write backlog for PTY master when write() returns
     * EAGAIN. Flushed via POLLOUT in session_run. */
    uint8_t pty_master_backlog[4096];
    size_t  pty_master_backlog_len;

    /* Exit code returned by the client when PTY_EOF arrives */
    int     client_exit_code;
    int     should_exit;         /* set by client PTY handlers to break session_run */
    int     pty_eof_seen;        /* PTY_EOF was received on client */

    /* §7 fragmentation reassembler (per-channel). */
    reasm_t reasm;

#if URTB_OTP
    const char    *otp_path;
    otp_key_t     *otp_key_mem;    /* pre-loaded in-memory key (--burn mode) */
    int            otp_state;      /* 0=IDLE, 1=PENDING, 2=DONE */
    int            otp_attempts;
    char           otp_buf[17];
    size_t         otp_buf_len;
#endif

    /* bitmask of misdirected PTY subtypes already logged once for
     * this session. Bit (1 << type) is set after the first quiet-drop log so
     * a flooding peer doesn't fill stderr. Cleared on session_create. */
    uint16_t pty_quiet_log_mask;

    /* C-3: full USB_STATUS_RSP parse — last-known per-transport stats */
    int8_t   espnow_rssi_last;     /* dBm; 0 = no data */
    int8_t   lora_rssi_last;       /* dBm; 0 = no data */
    int8_t   lora_snr_last_decideb;/* signed tenths of dB */
    int8_t   _stats_pad;           /* explicit padding for alignment */
    uint32_t espnow_tx_ok_total;   /* host-side wrap-reconciled counter */
    uint32_t espnow_tx_fail_total;
    uint32_t espnow_ring_drop_total;
    uint32_t lora_tx_ok_total;
    uint32_t lora_tx_fail_total;
    /* Last raw uint16 values seen from the device, for delta calc. */
    uint16_t espnow_tx_ok_prev;
    uint16_t espnow_tx_fail_prev;
    uint16_t espnow_ring_drop_prev;
    uint16_t lora_tx_ok_prev;
    uint16_t lora_tx_fail_prev;
    int      stats_have_prev;      /* 1 once we've seen at least one RSP */
};

/* -------------------------------------------------------------------------
 * Session API
 * ---------------------------------------------------------------------- */

/*
 * Create a new session.
 * PSK is copied into mlock'd memory; caller should wipe original after call.
 * Returns NULL on failure.
 */
session_t *session_create(transport_t *t,
                          const uint8_t psk[32],
                          const uint8_t pair_id[4]);

/*
 * Destroy session and free all resources. Wipes key material.
 */
void session_destroy(session_t *s);

/*
 * Client: initiate connection (send CTRL_HELLO). State → CONNECTING.
 * Returns 0 on success, -1 on failure.
 */
int session_connect(session_t *s);

/*
 * Server: wait for connection (enter listen loop). State stays IDLE until
 * first CTRL_HELLO arrives, then transitions to KEY_DERIVING.
 * Typically just sets is_server=1; actual handling in session_run().
 * Returns 0.
 */
int session_listen(session_t *s);

/*
 * Main event loop. Runs until session closes or error.
 * Uses poll() on transport fd + clock_gettime() for timer math.
 * Returns 0 on clean close, -1 on error.
 */
int session_run(session_t *s);

/*
 * Initiate graceful close. Sends CTRL_CLOSE and enters CLOSING state.
 */
void session_close(session_t *s);

/*
 * Send a plaintext payload on the given channel.
 * Encrypts with session_key and current tx_seq, encodes radio frame,
 * and hands to transport.
 * chan_byte: bits 7-4 = channel id, bits 1-0 = fragment flags.
 * Returns 0 on success, -1 on failure.
 */
int session_send(session_t *s, uint8_t chan_byte, uint8_t type,
                 const uint8_t *plaintext, size_t plaintext_len);

/*
 * Fragmenting send (PROTOCOL.md §7).
 * Splits `plaintext_len` into fragments of at most `current_mtu` bytes,
 * stamping FIRST_FRAGMENT / MORE_FRAGMENTS flags in the CHAN byte for
 * each fragment as required by §7. Use this for any payload that may
 * exceed the current transport MTU (notably PTY_DATA on LoRa).
 *
 * chan_id: 0..15 (will be placed in the high nibble of the CHAN byte).
 * Returns 0 if all fragments were successfully handed to the transport,
 * -1 on the first send error.
 */
int session_send_data(session_t *s, uint8_t chan_id, uint8_t type,
                      const uint8_t *plaintext, size_t plaintext_len);

/*
 * Reconfigure keepalive / liveness timers to match current transport mode.
 * transport_active: 1 = ESP-NOW (2s/6s), 2 = LoRa (30s/90s).
 */
void session_set_transport_mode(session_t *s, uint8_t transport_active);

/*
 * Optional hook invoked by session_run() once per iteration. Used by the
 * client to pump pending SIGINT / SIGWINCH flags into PTY_SIGNAL / PTY_RESIZE
 * frames. NULL by default.
 */
typedef void (*session_tick_fn)(session_t *s);
extern session_tick_fn session_run_tick;

#endif /* URTB_SESSION_H */
