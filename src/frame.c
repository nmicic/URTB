/*
 * frame.c — USB + radio frame encode/decode
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Mirrors tools/frame_test.c reference implementation exactly:
 * same CRC-16/CCITT-FALSE, same little-endian encoding.
 */

#define _POSIX_C_SOURCE 200809L

#include <string.h>
#include "frame.h"

/* -------------------------------------------------------------------------
 * CRC-16/CCITT-FALSE
 * poly=0x1021, init=0xFFFF, no reflect, xorout=0
 * ---------------------------------------------------------------------- */

uint16_t crc16_ccitt_false(const uint8_t *buf, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)buf[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000)
                ? (uint16_t)((crc << 1) ^ 0x1021)
                : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/* -------------------------------------------------------------------------
 * USB frame encode
 * ---------------------------------------------------------------------- */

int urtb_usb_encode(uint8_t type, uint8_t flags,
                    const uint8_t *body, size_t body_len,
                    uint8_t *out, size_t out_max)
{
    if (body_len > USB_MAX_BODY) return -1;
    size_t need = USB_OVERHEAD + body_len;
    if (need > out_max) return -1;

    out[0] = USB_MAGIC0;
    out[1] = USB_MAGIC1;
    out[2] = USB_VER;
    out[3] = type;
    out[4] = flags;
    out[5] = (uint8_t)(body_len & 0xFF);
    out[6] = (uint8_t)((body_len >> 8) & 0xFF);
    if (body_len && body) memcpy(out + USB_HEADER_LEN, body, body_len);

    uint16_t crc = crc16_ccitt_false(out, USB_HEADER_LEN + body_len);
    out[USB_HEADER_LEN + body_len + 0] = (uint8_t)(crc & 0xFF);
    out[USB_HEADER_LEN + body_len + 1] = (uint8_t)((crc >> 8) & 0xFF);
    return (int)need;
}

/* -------------------------------------------------------------------------
 * USB frame decode
 * ---------------------------------------------------------------------- */

int urtb_usb_decode(const uint8_t *frame, size_t frame_len,
                    uint8_t *type_out, uint8_t *flags_out,
                    uint8_t *body_out, size_t body_out_max)
{
    if (frame_len < USB_OVERHEAD) return -1;
    if (frame[0] != USB_MAGIC0 || frame[1] != USB_MAGIC1) return -1;
    if (frame[2] != USB_VER) return -1;

    size_t body_len = (size_t)frame[5] | ((size_t)frame[6] << 8);
    if (body_len > USB_MAX_BODY) return -1;
    if (USB_OVERHEAD + body_len > frame_len) return -1;

    uint16_t want_crc = crc16_ccitt_false(frame, USB_HEADER_LEN + body_len);
    uint16_t got_crc  = (uint16_t)frame[USB_HEADER_LEN + body_len + 0]
                     | ((uint16_t)frame[USB_HEADER_LEN + body_len + 1] << 8);
    if (want_crc != got_crc) return -1;

    if (body_len > body_out_max) return -1;
    if (type_out)  *type_out  = frame[3];
    if (flags_out) *flags_out = frame[4];
    if (body_len && body_out) memcpy(body_out, frame + USB_HEADER_LEN, body_len);
    return (int)body_len;
}

/* -------------------------------------------------------------------------
 * Radio frame encode
 * ---------------------------------------------------------------------- */

int urtb_radio_encode(const uint8_t pair_id[4], uint32_t seq,
                      uint8_t chan, uint8_t type,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t *out, size_t out_max)
{
    if (ct_len < RADIO_MIN_CT_LEN) return -1;
    if (RADIO_HEADER_LEN + ct_len > out_max) return -1;

    memcpy(out, pair_id, 4);
    out[4]  = (uint8_t)(seq        & 0xFF);
    out[5]  = (uint8_t)((seq >> 8)  & 0xFF);
    out[6]  = (uint8_t)((seq >> 16) & 0xFF);
    out[7]  = (uint8_t)((seq >> 24) & 0xFF);
    out[8]  = chan;
    out[9]  = type;
    out[10] = (uint8_t)(ct_len & 0xFF);
    out[11] = (uint8_t)((ct_len >> 8) & 0xFF);
    memcpy(out + RADIO_HEADER_LEN, ct, ct_len);
    return (int)(RADIO_HEADER_LEN + ct_len);
}

/* -------------------------------------------------------------------------
 * Radio frame decode
 * ---------------------------------------------------------------------- */

int urtb_radio_decode(const uint8_t *frame, size_t frame_len,
                      uint8_t pair_id_out[4], uint32_t *seq_out,
                      uint8_t *chan_out, uint8_t *type_out,
                      const uint8_t **ct_out, size_t *ct_len_out)
{
    if (frame_len < RADIO_HEADER_LEN) return -1;

    size_t ct_len = (size_t)frame[10] | ((size_t)frame[11] << 8);
    if (ct_len < RADIO_MIN_CT_LEN) return -1;
    if (RADIO_HEADER_LEN + ct_len > frame_len) return -1;

    if (pair_id_out) memcpy(pair_id_out, frame, 4);
    if (seq_out) {
        *seq_out = (uint32_t)frame[4]
                 | ((uint32_t)frame[5] << 8)
                 | ((uint32_t)frame[6] << 16)
                 | ((uint32_t)frame[7] << 24);
    }
    if (chan_out)    *chan_out    = frame[8];
    if (type_out)   *type_out   = frame[9];
    if (ct_out)     *ct_out     = frame + RADIO_HEADER_LEN;
    if (ct_len_out) *ct_len_out = ct_len;
    return 0;
}
