/*
 * frame.h — USB frame + radio frame encode/decode
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef URTB_FRAME_H
#define URTB_FRAME_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Constants (PROTOCOL.md §1, §2)
 * ---------------------------------------------------------------------- */

#define USB_MAGIC0          0xAB
#define USB_MAGIC1          0xCD
#define USB_VER             0x01
#define USB_HEADER_LEN      7   /* MAGIC[2] VER[1] TYPE[1] FLAGS[1] LEN[2] */
#define USB_TRAILER_LEN     2   /* CRC16 */
#define USB_OVERHEAD        9
#define USB_MAX_BODY        510
#define USB_MAX_FRAME       519

/* USB frame types */
#define USB_DATA_TX         0x01
#define USB_DATA_RX         0x02
#define USB_STATUS_REQ      0x03
#define USB_STATUS_RSP      0x04
#define USB_HELLO           0x05
#define USB_HELLO_ACK       0x06
#define USB_CONFIG          0x07
#define USB_CONFIG_ACK      0x08
#define USB_ERROR           0x09
#define USB_RESET           0x0A

/* Radio frame constants */
#define RADIO_HEADER_LEN    12  /* PAIR_ID[4] SEQ[4] CHAN[1] TYPE[1] LEN[2] */
#define RADIO_TAG_LEN       16  /* Poly1305 auth tag */
#define RADIO_MIN_CT_LEN    16  /* empty plaintext + tag */
#define RADIO_MIN_FRAME_LEN (RADIO_HEADER_LEN + RADIO_MIN_CT_LEN)  /* 28 */
#define RADIO_MAX_ESPNOW    250
#define RADIO_MAX_LORA_SF7  100

/* Channel byte fragment flags */
#define CHAN_FF_BIT          0x02  /* FIRST_FRAGMENT */
#define CHAN_MF_BIT          0x01  /* MORE_FRAGMENTS */

/* Control channel types (CHAN=0) */
#define CTRL_HELLO          0x01
#define CTRL_HELLO_ACK      0x02
#define CTRL_READY          0x03
#define CTRL_CLOSE          0x04
#define CTRL_KEEPALIVE      0x05
#define CTRL_KEEPALIVE_ACK  0x06
/* 0x07 RESERVED */
#define CTRL_ERROR          0x08

/* Error codes */
#define ERR_AUTH_FAIL       0x0001
#define ERR_REPLAY          0x0002
#define ERR_VERSION         0x0003
#define ERR_CAPS            0x0004
#define ERR_SESSION         0x0005
#define ERR_RESOURCE        0x0006
#define ERR_TIMEOUT         0x0007

/* PTY channel types (CHAN=1) */
#define PTY_OPEN            0x01
#define PTY_OPEN_ACK        0x02
#define PTY_OPEN_ERR        0x03
#define PTY_DATA            0x04
#define PTY_RESIZE          0x05
#define PTY_SIGNAL          0x06
#define PTY_CLOSE           0x07
#define PTY_EOF             0x08

/* -------------------------------------------------------------------------
 * CRC-16/CCITT-FALSE
 * ---------------------------------------------------------------------- */

uint16_t crc16_ccitt_false(const uint8_t *buf, size_t len);

/* -------------------------------------------------------------------------
 * USB frame encode/decode
 * ---------------------------------------------------------------------- */

/*
 * Encode a USB frame.
 * Returns total bytes written (>0), or -1 on error.
 */
int urtb_usb_encode(uint8_t type, uint8_t flags,
                    const uint8_t *body, size_t body_len,
                    uint8_t *out, size_t out_max);

/*
 * Decode a USB frame.
 * Fills type_out, flags_out; copies body to body_out.
 * Returns body length (>=0), or -1 on error (bad magic, bad CRC, truncated).
 */
int urtb_usb_decode(const uint8_t *frame, size_t frame_len,
                    uint8_t *type_out, uint8_t *flags_out,
                    uint8_t *body_out, size_t body_out_max);

/* -------------------------------------------------------------------------
 * Radio frame encode/decode
 * ---------------------------------------------------------------------- */

/*
 * Encode a radio frame (header + ciphertext).
 * ct must already be the full CIPHERTEXT (ciphertext + tag concatenated).
 * Returns total bytes written, or -1 on error.
 */
int urtb_radio_encode(const uint8_t pair_id[4], uint32_t seq,
                      uint8_t chan, uint8_t type,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t *out, size_t out_max);

/*
 * Decode a radio frame header.
 * Fills pair_id_out, seq_out, chan_out, type_out.
 * Sets ct_out to point into frame (zero-copy). Sets ct_len_out.
 * Returns 0 on success, -1 on truncated/invalid frame.
 * Does NOT validate AEAD tag — caller must decrypt.
 */
int urtb_radio_decode(const uint8_t *frame, size_t frame_len,
                      uint8_t pair_id_out[4], uint32_t *seq_out,
                      uint8_t *chan_out, uint8_t *type_out,
                      const uint8_t **ct_out, size_t *ct_len_out);

#endif /* URTB_FRAME_H */
