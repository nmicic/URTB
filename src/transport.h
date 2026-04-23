/*
 * transport.h — transport abstraction interface
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Defines transport_ops_t, transport_t, transport_config_t, transport_stats_t
 * exactly as in PROTOCOL.md §9.
 */
#ifndef URTB_TRANSPORT_H
#define URTB_TRANSPORT_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

/* -------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

typedef struct transport_config {
    const char *transport;      /* "unix", "heltec", "stdio" */
    /* unix transport */
    const char *path;           /* UNIX domain socket path */
    int         listen;         /* 1 = listen mode, 0 = connect mode */
    /* heltec transport */
    const char *tty_device;     /* e.g. "/dev/ttyUSB0" */
    uint32_t    tty_baud;       /* baud rate, default 115200 */
    /* stdio transport */
    const char *exec;           /* argv[] for execvp() fork (NULL = use fd 0/1) */
    /* B-3 : heltec USB_CONFIG fields populated from capsule */
    uint8_t     pair_id[4];     /* capsule pair_id (zero = unset) */
    uint32_t    lora_freq_hz;   /* e.g. 915000000 */
    uint8_t     lora_sf;        /* spreading factor */
    uint8_t     lora_bw;        /* bandwidth index */
    uint8_t     lora_cr;        /* coding rate */
    uint8_t     lora_txpower;   /* TX power dBm */
    uint8_t     peer_mac[6];    /* ESPNOW peer MAC */
    uint8_t     espnow_channel; /* ESPNOW channel */
} transport_config_t;

/* -------------------------------------------------------------------------
 * Stats
 * ---------------------------------------------------------------------- */

typedef struct transport_stats {
    uint32_t  tx_ok;
    uint32_t  tx_fail;
    uint32_t  rx_ok;
    uint32_t  rx_drop;
    int16_t   rssi_last;       /* dBm, INT16_MIN if unknown */
    int8_t    snr_last;        /* tenths of dB, INT8_MIN if unknown */
    uint8_t   transport_id;   /* 0=unix, 1=heltec, 2=stdio */
} transport_stats_t;

/* -------------------------------------------------------------------------
 * Opaque transport handle
 * ---------------------------------------------------------------------- */

typedef struct transport transport_t;

/* -------------------------------------------------------------------------
 * Operations interface
 * ---------------------------------------------------------------------- */

typedef struct transport_ops {
    const char *name;
    int  (*open)  (const transport_config_t *cfg, transport_t **out);
    int  (*send)  (transport_t *t, const uint8_t *data, size_t len);
    int  (*recv)  (transport_t *t, uint8_t *buf, size_t max, int timeout_ms);
    void (*close) (transport_t *t);
    int  (*stats) (transport_t *t, transport_stats_t *out);
    /* Optional (B-3): return underlying pollable fd or -1 if not supported.
     * When present, session_run can poll this fd in the same poll() set as
     * the PTY master / stdin. Used by transport_unix (always) and transport_heltec
     * (when backed by a real serial device). */
    int  (*get_fd)(transport_t *t);
} transport_ops_t;

/* -------------------------------------------------------------------------
 * Transport implementations (defined in transport_*.c)
 * ---------------------------------------------------------------------- */

extern const transport_ops_t transport_unix;
extern const transport_ops_t transport_heltec;
extern const transport_ops_t transport_stdio;

/* -------------------------------------------------------------------------
 * Helper: get transport_ops_t by name string
 * Returns NULL if not found.
 * ---------------------------------------------------------------------- */
const transport_ops_t *transport_find(const char *name);

/* -------------------------------------------------------------------------
 * Heltec-specific: consume and return any pending USB_STATUS_RSP
 * transport_active byte. Returns 0 if none pending, 1 for ESP-NOW, 2 for
 * LoRa. No-op for non-heltec transports (returns 0). Used by session_run
 * to call session_set_transport_mode on LoRa failover. See  / .
 * ---------------------------------------------------------------------- */
uint8_t transport_heltec_consume_pending_mode(transport_t *t);

/* -------------------------------------------------------------------------
 * C-3: full USB_STATUS_RSP plumbing.
 *
 * consume_status_rsp: pop the most recently received USB_STATUS_RSP body
 * (16 bytes). Returns 1 if a body was available (filled into out[]) and
 * clears the internal flag, 0 if nothing pending. The 16-byte body is the
 * raw firmware payload; the caller is responsible for parsing fields and
 * applying wrap reconciliation for the four uint16 rolling counters.
 *
 * request_status: send a USB_STATUS_REQ frame to the firmware and block
 * until either a USB_STATUS_RSP arrives (returns 0 and fills out[16]) or
 * timeout_ms expires (returns -1). Used by the `urtb status` subcommand.
 * No-op for non-heltec transports.
 * ---------------------------------------------------------------------- */
int  transport_heltec_consume_status_rsp(transport_t *t, uint8_t out[16]);
int  transport_heltec_request_status   (transport_t *t, uint8_t out[16],
                                        int timeout_ms);

/* -------------------------------------------------------------------------
 * transport_t base struct — each implementation embeds this at offset 0
 * ---------------------------------------------------------------------- */

struct transport {
    const transport_ops_t *ops;
};

#endif /* URTB_TRANSPORT_H */
