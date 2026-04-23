/*
 * reasm.h — per-channel fragment reassembler (PROTOCOL.md §7)
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Receiver-side state machine for the FIRST_FRAGMENT / MORE_FRAGMENTS
 * flags carried in the radio frame's CHAN byte (§2). Sender-side
 * fragmentation is in session.c (session_send_data).
 *
 * Per spec:
 *   - 16 channels max.
 *   - Per-channel reassembly buffer, max 4 KB.
 *   - Timeout: 5s ESP-NOW, 30s LoRa, from first fragment.
 *   - 6 valid flag combinations — see reasm_feed() below.
 *   - Type validation: all fragments of a message share TYPE.
 *
 * Self-contained: only depends on <stdint.h>, <stddef.h>. Both
 * src/session.c and tools/frame_test.c link this file.
 */
#ifndef URTB_REASM_H
#define URTB_REASM_H

#include <stdint.h>
#include <stddef.h>

#define REASM_MAX_BUFFER   4096   /* §7: max reassembly buffer */
#define REASM_MAX_CHANNELS 16     /* CHAN byte high nibble */

#define REASM_TIMEOUT_ESPNOW_MS  5000
#define REASM_TIMEOUT_LORA_MS    30000

typedef struct {
    int      open;                  /* 1 = buffer in-flight */
    uint8_t  type;                  /* type of in-flight message */
    int64_t  deadline_ms;           /* monotonic ms when this buffer expires */
    size_t   len;
    uint8_t  buf[REASM_MAX_BUFFER];
} reasm_chan_t;

typedef struct {
    reasm_chan_t chans[REASM_MAX_CHANNELS];
} reasm_t;

/* Result codes */
#define REASM_DROP     0  /* fragment consumed, no message ready */
#define REASM_DELIVER  1  /* full message ready: caller dispatches *out_buf,*out_len */
#define REASM_ERROR   -1  /* protocol violation; buffer (if any) has been reset */

/*
 * Feed a single decrypted fragment into the reassembler.
 *
 * chan_id    0..15 (high nibble of CHAN byte)
 * type       per-channel TYPE byte from the radio frame
 * ff,mf      FIRST_FRAGMENT and MORE_FRAGMENTS flags (0/1)
 * data,len   fragment plaintext
 * now_ms     current monotonic ms (used to set/check deadlines)
 * timeout_ms timeout to apply to a *new* buffer (5000 / 30000)
 *
 * On REASM_DELIVER, *out_buf and *out_len point at the assembled
 * message (either the input fragment for single-fragment messages,
 * or the per-channel buffer for multi-fragment). Caller must consume
 * before any further reasm_feed() call on the same channel.
 *
 * On REASM_DROP / REASM_ERROR, *out_buf / *out_len are not touched.
 */
int reasm_feed(reasm_t *r,
               uint8_t chan_id, uint8_t type,
               int ff, int mf,
               const uint8_t *data, size_t len,
               int64_t now_ms, int64_t timeout_ms,
               const uint8_t **out_buf, size_t *out_len);

/* Sweep timed-out buffers. Call from session_run main loop. */
void reasm_tick(reasm_t *r, int64_t now_ms);

/* Drop all in-flight buffers (e.g., on enter_idle). */
void reasm_reset(reasm_t *r);

/* Drop one channel's in-flight buffer (no-op if not open). */
void reasm_reset_chan(reasm_t *r, uint8_t chan_id);

#endif /* URTB_REASM_H */
