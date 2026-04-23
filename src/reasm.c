/*
 * reasm.c — per-channel fragment reassembler (PROTOCOL.md §7)
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "reasm.h"

void reasm_reset(reasm_t *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

void reasm_reset_chan(reasm_t *r, uint8_t chan_id)
{
    if (!r || chan_id >= REASM_MAX_CHANNELS) return;
    r->chans[chan_id].open = 0;
    r->chans[chan_id].len  = 0;
    r->chans[chan_id].deadline_ms = 0;
}

void reasm_tick(reasm_t *r, int64_t now_ms)
{
    if (!r) return;
    for (int i = 0; i < REASM_MAX_CHANNELS; i++) {
        reasm_chan_t *c = &r->chans[i];
        if (c->open && now_ms >= c->deadline_ms) {
            c->open = 0;
            c->len  = 0;
            c->deadline_ms = 0;
        }
    }
}

int reasm_feed(reasm_t *r,
               uint8_t chan_id, uint8_t type,
               int ff, int mf,
               const uint8_t *data, size_t len,
               int64_t now_ms, int64_t timeout_ms,
               const uint8_t **out_buf, size_t *out_len)
{
    if (!r || chan_id >= REASM_MAX_CHANNELS) return REASM_ERROR;

    reasm_chan_t *c = &r->chans[chan_id];

    /* Per-fragment cap: if the fragment alone exceeds the assembly cap,
     * reject regardless of state. */
    if (len > REASM_MAX_BUFFER) {
        c->open = 0; c->len = 0;
        return REASM_ERROR;
    }

    /* Single-fragment message (FF=1, MF=0):
     * Per §7, FF=1 always discards any in-flight buffer first. */
    if (ff && !mf) {
        c->open = 0; c->len = 0; c->deadline_ms = 0;
        *out_buf = data;
        *out_len = len;
        return REASM_DELIVER;
    }

    /* First fragment of a multi-fragment message (FF=1, MF=1):
     * Discard any prior buffer, open new buffer, store fragment. */
    if (ff && mf) {
        c->open = 1;
        c->type = type;
        c->len  = 0;
        c->deadline_ms = now_ms + timeout_ms;
        if (len > REASM_MAX_BUFFER) { /* impossible — already checked */
            c->open = 0;
            return REASM_ERROR;
        }
        memcpy(c->buf, data, len);
        c->len = len;
        return REASM_DROP;
    }

    /* Continuation (FF=0, MF=1): append to open buffer. */
    if (!ff && mf) {
        if (!c->open) {
            /* Lost first fragment — discard. */
            return REASM_DROP;
        }
        if (type != c->type) {
            /* Spec: fragments of the same message share TYPE. Reset. */
            c->open = 0; c->len = 0;
            return REASM_ERROR;
        }
        if (c->len + len > REASM_MAX_BUFFER) {
            /* Overflow — drop the entire message. */
            c->open = 0; c->len = 0;
            return REASM_ERROR;
        }
        memcpy(c->buf + c->len, data, len);
        c->len += len;
        return REASM_DROP;
    }

    /* Final fragment (FF=0, MF=0): append, deliver, close. */
    if (!ff && !mf) {
        if (!c->open) {
            /* Orphaned terminal fragment — discard. */
            return REASM_DROP;
        }
        if (type != c->type) {
            c->open = 0; c->len = 0;
            return REASM_ERROR;
        }
        if (c->len + len > REASM_MAX_BUFFER) {
            c->open = 0; c->len = 0;
            return REASM_ERROR;
        }
        memcpy(c->buf + c->len, data, len);
        c->len += len;
        c->open = 0;
        c->deadline_ms = 0;
        *out_buf = c->buf;
        *out_len = c->len;
        return REASM_DELIVER;
    }

    return REASM_ERROR; /* unreachable */
}
