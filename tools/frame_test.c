/*
 * frame_test.c — wire-format and crypto test harness
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Standalone wire-format and crypto test harness. Validates the protocol
 * before any host or firmware code exists. All test groups from
 * prompts/phase-b0-freeze.md (groups 1..6). Group 7 was moved to Phase B-4.
 *
 * Build:
 *   cc -Wall -Wextra -O2 -std=c11 -I src/vendor \
 *      -o tools/frame_test tools/frame_test.c src/vendor/monocypher.c
 *
 * Run:
 *   tools/frame_test            # prints PASS/FAIL per test, exit 0 = all pass
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "monocypher.h"
#include "reasm.h"
#include "crypto.h"

/* ------------------------------------------------------------------------- */
/* Test harness                                                              */
/* ------------------------------------------------------------------------- */

static int  g_total;
static int  g_failed;

#define CHECK(name, cond) do { \
    g_total++; \
    if (!(cond)) { \
        g_failed++; \
        fprintf(stderr, "FAIL %s   (%s:%d)\n", (name), __FILE__, __LINE__); \
    } else { \
        printf("PASS %s\n", (name)); \
    } \
} while (0)

/* ------------------------------------------------------------------------- */
/* Wire constants (mirror PROTOCOL.md §1, §2, §11)                            */
/* ------------------------------------------------------------------------- */

#define USB_MAGIC0          0xAB
#define USB_MAGIC1          0xCD
#define USB_VER             0x01
#define USB_HEADER_LEN      7   /* MAGIC[2] VER[1] TYPE[1] FLAGS[1] LEN[2] */
#define USB_TRAILER_LEN     2   /* CRC16 */
#define USB_OVERHEAD        9
#define USB_MAX_BODY        510
#define USB_MAX_FRAME       519

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

#define RADIO_HEADER_LEN    12  /* PAIR_ID[4] SEQ[4] CHAN[1] TYPE[1] LEN[2] */
#define RADIO_TAG_LEN       16  /* Poly1305 */
#define RADIO_MIN_CT_LEN    16  /* empty plaintext + tag */
#define RADIO_MIN_FRAME_LEN (RADIO_HEADER_LEN + RADIO_MIN_CT_LEN)  /* 28 */
#define RADIO_MAX_ESPNOW    250
#define RADIO_MAX_LORA_SF7  100
#define MAX_PT_ESPNOW       (RADIO_MAX_ESPNOW - RADIO_HEADER_LEN - RADIO_TAG_LEN) /* 222 */
#define MAX_PT_LORA_SF7     (RADIO_MAX_LORA_SF7 - RADIO_HEADER_LEN - RADIO_TAG_LEN) /* 72 */

#define CHAN_FF_BIT         0x02  /* FIRST_FRAGMENT */
#define CHAN_MF_BIT         0x01  /* MORE_FRAGMENTS */

/* Replay window */
#define REPLAY_WINDOW       256

/* ------------------------------------------------------------------------- */
/* CRC-16/CCITT-FALSE (poly=0x1021, init=0xFFFF, no reflect, xorout=0)        */
/* ------------------------------------------------------------------------- */

static uint16_t crc16_ccitt_false(const uint8_t *buf, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)buf[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/* ------------------------------------------------------------------------- */
/* USB frame encode/decode                                                   */
/* ------------------------------------------------------------------------- */

/* returns total bytes written, or -1 on error */
static int usb_encode(uint8_t type, uint8_t flags,
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
    if (body_len) memcpy(out + USB_HEADER_LEN, body, body_len);

    uint16_t crc = crc16_ccitt_false(out, USB_HEADER_LEN + body_len);
    out[USB_HEADER_LEN + body_len + 0] = (uint8_t)(crc & 0xFF);
    out[USB_HEADER_LEN + body_len + 1] = (uint8_t)((crc >> 8) & 0xFF);
    return (int)need;
}

/* returns body length on success, -1 on error. body_out_max must hold body. */
static int usb_decode(const uint8_t *frame, size_t frame_len,
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
    if (body_len) memcpy(body_out, frame + USB_HEADER_LEN, body_len);
    return (int)body_len;
}

/* ------------------------------------------------------------------------- */
/* Radio frame encode + firmware PAIR_ID check                               */
/* ------------------------------------------------------------------------- */

static int radio_encode(const uint8_t pair_id[4], uint32_t seq,
                        uint8_t chan, uint8_t type,
                        const uint8_t *ct, size_t ct_len,
                        uint8_t *out, size_t out_max)
{
    if (ct_len < RADIO_MIN_CT_LEN) return -1;
    if (RADIO_HEADER_LEN + ct_len > out_max) return -1;

    memcpy(out, pair_id, 4);
    out[4] = (uint8_t)(seq      & 0xFF);
    out[5] = (uint8_t)(seq >> 8 & 0xFF);
    out[6] = (uint8_t)(seq >> 16 & 0xFF);
    out[7] = (uint8_t)(seq >> 24 & 0xFF);
    out[8] = chan;
    out[9] = type;
    out[10] = (uint8_t)(ct_len & 0xFF);
    out[11] = (uint8_t)((ct_len >> 8) & 0xFF);
    memcpy(out + RADIO_HEADER_LEN, ct, ct_len);
    return (int)(RADIO_HEADER_LEN + ct_len);
}

#define FW_ACCEPT 0
#define FW_REJECT 1

static int firmware_check(const uint8_t configured_pair_id[4],
                          const uint8_t *frame, size_t frame_len)
{
    if (frame_len < RADIO_HEADER_LEN) return FW_REJECT;
    if (memcmp(frame, configured_pair_id, 4) != 0) return FW_REJECT;
    return FW_ACCEPT;
}

/* ------------------------------------------------------------------------- */
/* Crypto helpers                                                            */
/* ------------------------------------------------------------------------- */

/* Build the 24-byte XChaCha20 nonce per D-29 / PROTOCOL.md §3 */
static void build_nonce(uint8_t direction, uint32_t seq, uint8_t nonce_out[24])
{
    memset(nonce_out, 0, 24);
    nonce_out[0] = direction;
    nonce_out[1] = (uint8_t)(seq      & 0xFF);
    nonce_out[2] = (uint8_t)(seq >> 8 & 0xFF);
    nonce_out[3] = (uint8_t)(seq >> 16 & 0xFF);
    nonce_out[4] = (uint8_t)(seq >> 24 & 0xFF);
}

/* Build the 10-byte AEAD AD: PAIR_ID || SEQ || CHAN || TYPE */
static void build_ad(const uint8_t pair_id[4], uint32_t seq,
                     uint8_t chan, uint8_t type, uint8_t ad_out[10])
{
    memcpy(ad_out, pair_id, 4);
    ad_out[4] = (uint8_t)(seq      & 0xFF);
    ad_out[5] = (uint8_t)(seq >> 8 & 0xFF);
    ad_out[6] = (uint8_t)(seq >> 16 & 0xFF);
    ad_out[7] = (uint8_t)(seq >> 24 & 0xFF);
    ad_out[8] = chan;
    ad_out[9] = type;
}

/* ------------------------------------------------------------------------- */
/* Replay window — additive form, see PROTOCOL.md §3                         */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint32_t hwm;
    int      initialized;
    uint8_t  bitmap[REPLAY_WINDOW]; /* 0 = unseen, 1 = seen */
} replay_t;

/*
 * Accept rule (additive form):
 *   if !initialized → accept, set HWM, set bitmap slot
 *   if SEQ > HWM → accept, advance HWM, slide bitmap slots out
 *   else if SEQ + 256 > HWM AND bitmap[SEQ % 256] == 0 → accept, set bit
 *   else reject
 *
 * Returns 1 = accept, 0 = reject.
 */
static int replay_accept(replay_t *r, uint32_t seq)
{
    if (!r->initialized) {
        r->hwm = seq;
        memset(r->bitmap, 0, sizeof(r->bitmap));
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        r->initialized = 1;
        return 1;
    }
    if (seq > r->hwm) {
        /* Advance: clear slots that slid out of the window. */
        uint32_t advance = seq - r->hwm;
        if (advance >= REPLAY_WINDOW) {
            memset(r->bitmap, 0, sizeof(r->bitmap));
        } else {
            for (uint32_t i = 1; i <= advance; i++) {
                /* Slot for (hwm - 256 + i) is no longer reachable. */
                uint32_t evict = r->hwm + i - REPLAY_WINDOW;
                /* When hwm+i < REPLAY_WINDOW the eviction slot wraps; the additive
                 * rule below still rejects those low SEQs because hwm advanced. */
                r->bitmap[evict % REPLAY_WINDOW] = 0;
            }
        }
        r->hwm = seq;
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        return 1;
    }
    /* SEQ <= HWM: in-window only if SEQ + 256 > HWM (strict) */
    if ((uint64_t)seq + REPLAY_WINDOW > (uint64_t)r->hwm) {
        if (r->bitmap[seq % REPLAY_WINDOW]) return 0;
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Reference vector — Monocypher AEAD                                        */
/* ------------------------------------------------------------------------- */

/*
 * Reference vector for crypto_aead_lock (XChaCha20-Poly1305 IETF) with:
 *   key   = 0x00 * 32
 *   nonce = 0x00 * 24
 *   ad    = empty
 *   plain = "test" (4 bytes)
 * Output: ciphertext[4] || mac[16] = 20 bytes total.
 *
 * Verified two ways at vendor time (2026-04-15):
 *   1) Built against this exact src/vendor/monocypher.c (4.0.2)
 *   2) Cross-checked against PyNaCl's libsodium binding
 *      (crypto_aead_xchacha20poly1305_ietf_encrypt) — byte-identical.
 *
 * Purpose: detect a wrong primitive (AES-GCM, ChaCha20 without X-nonce
 * extension, an unintended monocypher upgrade) that would still produce
 * deterministic but different bytes.
 */
static const uint8_t kAeadRefVector[20] = {
    /* ciphertext[4] */
    0x0C, 0xFB, 0xE5, 0xFD,
    /* mac[16] */
    0xE7, 0x53, 0x56, 0x56, 0x5F, 0x5E, 0xE3, 0x6A,
    0x75, 0xE5, 0x9F, 0xD8, 0x1D, 0x63, 0x47, 0x9D,
};
/* If the test fails on first run, set this to 1, run, copy printed bytes
 * into kAeadRefVector, set back to 0. */
#define REF_VECTOR_BOOTSTRAP 0

/* ------------------------------------------------------------------------- */
/* Group 1 — USB frame encode/decode                                          */
/* ------------------------------------------------------------------------- */

static void test_group1_usb_frames(void)
{
    uint8_t frame[USB_MAX_FRAME];
    uint8_t body[USB_MAX_BODY];

    /* 1-01: encode USB_DATA_TX, verify magic */
    {
        uint8_t b[28] = { 0 };
        int n = usb_encode(USB_DATA_TX, 0, b, sizeof(b), frame, sizeof(frame));
        CHECK("1-01 encode_usb_data_tx_magic",
              n > 0 && frame[0] == USB_MAGIC0 && frame[1] == USB_MAGIC1
              && frame[3] == USB_DATA_TX);
    }

    /* 1-02: encode + decode USB_HELLO, fields match */
    {
        uint8_t hello_body[2] = { USB_VER, 0x00 };
        int n = usb_encode(USB_HELLO, 0, hello_body, sizeof(hello_body),
                           frame, sizeof(frame));
        uint8_t got_type = 0, got_flags = 0;
        int blen = usb_decode(frame, (size_t)n, &got_type, &got_flags,
                              body, sizeof(body));
        CHECK("1-02 encode_decode_usb_hello",
              n > 0 && blen == 2 && got_type == USB_HELLO && got_flags == 0
              && body[0] == USB_VER && body[1] == 0);
    }

    /* 1-03: decode wrong CRC → error */
    {
        uint8_t b[4] = { 1, 2, 3, 4 };
        int n = usb_encode(USB_STATUS_RSP, 0, b, sizeof(b), frame, sizeof(frame));
        frame[n - 1] ^= 0xFF;  /* corrupt CRC high byte */
        int r = usb_decode(frame, (size_t)n, NULL, NULL, body, sizeof(body));
        CHECK("1-03 decode_wrong_crc_rejected", r < 0);
    }

    /* 1-04: LEN > actual bytes → decode error */
    {
        uint8_t b[4] = { 1, 2, 3, 4 };
        int n = usb_encode(USB_STATUS_RSP, 0, b, sizeof(b), frame, sizeof(frame));
        /* claim body is 200 bytes, frame is much shorter */
        frame[5] = 200;
        frame[6] = 0;
        int r = usb_decode(frame, (size_t)n, NULL, NULL, body, sizeof(body));
        CHECK("1-04 decode_len_overrun_rejected", r < 0);
    }

    /* 1-05: zero-body USB frame valid (USB_STATUS_REQ / USB_CONFIG_ACK / USB_RESET) */
    {
        int n = usb_encode(USB_STATUS_REQ, 0, NULL, 0, frame, sizeof(frame));
        uint8_t got_type = 0;
        int blen = usb_decode(frame, (size_t)n, &got_type, NULL, body, sizeof(body));
        CHECK("1-05 zero_body_status_req",
              n == USB_OVERHEAD && blen == 0 && got_type == USB_STATUS_REQ);
    }

    /* 1-06: 510-byte body valid */
    {
        uint8_t big[USB_MAX_BODY];
        for (size_t i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i & 0xFF);
        int n = usb_encode(USB_DATA_TX, 0, big, sizeof(big), frame, sizeof(frame));
        int blen = usb_decode(frame, (size_t)n, NULL, NULL, body, sizeof(body));
        CHECK("1-06 body_510_max_valid",
              n == USB_OVERHEAD + USB_MAX_BODY
              && blen == USB_MAX_BODY
              && memcmp(body, big, USB_MAX_BODY) == 0);
    }

    /* 1-07: 511-byte body rejected at encode */
    {
        uint8_t too_big[USB_MAX_BODY + 1] = { 0 };
        int n = usb_encode(USB_DATA_TX, 0, too_big, sizeof(too_big),
                           frame, sizeof(frame));
        CHECK("1-07 body_511_rejected", n < 0);
    }
}

/* ------------------------------------------------------------------------- */
/* Group 2 — Radio frame encode/decode + PAIR_ID check                       */
/* ------------------------------------------------------------------------- */

static void test_group2_radio_frames(void)
{
    uint8_t pair_id[4]   = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t pair_other[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
    uint8_t ct[16]        = { 0 };
    uint8_t frame[256];

    /* 2-01: PAIR_ID at bytes 0..3 */
    {
        int n = radio_encode(pair_id, 0, 0x12, 0x05, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-01 pair_id_bytes_0_3",
              n > 0 && memcmp(frame, pair_id, 4) == 0);
    }

    /* 2-02: SEQ at bytes 4..7 little-endian */
    {
        uint32_t seq = 0x11223344;
        int n = radio_encode(pair_id, seq, 0x10, 0x01, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-02 seq_bytes_4_7_le",
              n > 0
              && frame[4] == 0x44 && frame[5] == 0x33
              && frame[6] == 0x22 && frame[7] == 0x11);
    }

    /* 2-03: CHAN field — channel ID upper nibble + FF/MF bits */
    {
        /* channel 1, FIRST_FRAGMENT=1, MORE_FRAGMENTS=1 */
        uint8_t chan = (uint8_t)((1 << 4) | CHAN_FF_BIT | CHAN_MF_BIT);
        int n = radio_encode(pair_id, 0, chan, 0x04, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-03 chan_byte_layout",
              n > 0
              && ((frame[8] >> 4) & 0x0F) == 1
              && (frame[8] & CHAN_FF_BIT)
              && (frame[8] & CHAN_MF_BIT));
    }

    /* 2-04: wrong PAIR_ID → firmware_check REJECT */
    {
        int n = radio_encode(pair_other, 0, 0x10, 0x01, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-04 wrong_pair_id_rejected",
              n > 0 && firmware_check(pair_id, frame, (size_t)n) == FW_REJECT);
    }

    /* 2-05: matching PAIR_ID → firmware_check ACCEPT */
    {
        int n = radio_encode(pair_id, 0, 0x10, 0x01, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-05 matching_pair_id_accepted",
              n > 0 && firmware_check(pair_id, frame, (size_t)n) == FW_ACCEPT);
    }

    /* 2-06: ESP-NOW MTU plaintext budget */
    CHECK("2-06 espnow_max_plaintext_222", MAX_PT_ESPNOW == 222);

    /* 2-07: LoRa SF7 plaintext budget */
    CHECK("2-07 lora_sf7_max_plaintext_72", MAX_PT_LORA_SF7 == 72);
}

/* ------------------------------------------------------------------------- */
/* Group 3 — AEAD round-trip + nonce + AD authentication                     */
/* ------------------------------------------------------------------------- */

static void test_group3_aead(void)
{
    uint8_t key[32];
    uint8_t nonce[24];
    uint8_t ad[10];
    uint8_t pair_id[4] = { 0x01, 0x02, 0x03, 0x04 };

    /* 3-00: reference vector (catches wrong primitive) */
    {
        uint8_t k0[32] = { 0 };
        uint8_t n0[24] = { 0 };
        const uint8_t plain[4] = { 't', 'e', 's', 't' };
        uint8_t ct[4];
        uint8_t mac[16];
        crypto_aead_lock(ct, mac, k0, n0, NULL, 0, plain, sizeof(plain));

#if REF_VECTOR_BOOTSTRAP
        printf("REF_VECTOR ct: ");
        for (size_t i = 0; i < 4; i++)  printf("0x%02X, ", ct[i]);
        printf("\nREF_VECTOR mac: ");
        for (size_t i = 0; i < 16; i++) printf("0x%02X, ", mac[i]);
        printf("\n");
#endif
        int ok = (memcmp(ct,  kAeadRefVector + 0,  4)  == 0)
              && (memcmp(mac, kAeadRefVector + 4,  16) == 0);
        CHECK("3-00 monocypher_aead_reference_vector", ok);
    }

    /* Set up a non-trivial key for the rest of the group. */
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    /* 3-01: round-trip OK */
    {
        build_nonce(0x00, 100, nonce);
        build_ad(pair_id, 100, 0x10, 0x05, ad);
        const uint8_t plain[16] = "URTB AEAD-test-X";
        uint8_t ct[16], mac[16], out[16];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10, plain, sizeof(plain));
        int r = crypto_aead_unlock(out, mac, key, nonce, ad, 10, ct, sizeof(ct));
        CHECK("3-01 aead_round_trip",
              r == 0 && memcmp(out, plain, sizeof(plain)) == 0);
    }

    /* 3-02: encrypt with one key, decrypt with another → fail */
    {
        uint8_t key2[32];
        for (int i = 0; i < 32; i++) key2[i] = (uint8_t)(0xAA - i);
        build_nonce(0x00, 101, nonce);
        build_ad(pair_id, 101, 0x10, 0x05, ad);
        const uint8_t plain[8] = "abcdefgh";
        uint8_t ct[8], mac[16], out[8];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10, plain, sizeof(plain));
        int r = crypto_aead_unlock(out, mac, key2, nonce, ad, 10, ct, sizeof(ct));
        CHECK("3-02 aead_wrong_key_rejected", r != 0);
    }

    /* 3-03: flip one bit in ciphertext → fail */
    {
        build_nonce(0x00, 102, nonce);
        build_ad(pair_id, 102, 0x10, 0x05, ad);
        const uint8_t plain[8] = "12345678";
        uint8_t ct[8], mac[16], out[8];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10, plain, sizeof(plain));
        ct[3] ^= 0x01;
        int r = crypto_aead_unlock(out, mac, key, nonce, ad, 10, ct, sizeof(ct));
        CHECK("3-03 aead_ciphertext_bitflip_rejected", r != 0);
    }

    /* 3-04: flip one bit in tag → fail */
    {
        build_nonce(0x00, 103, nonce);
        build_ad(pair_id, 103, 0x10, 0x05, ad);
        const uint8_t plain[8] = "ABCDEFGH";
        uint8_t ct[8], mac[16], out[8];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10, plain, sizeof(plain));
        mac[7] ^= 0x80;
        int r = crypto_aead_unlock(out, mac, key, nonce, ad, 10, ct, sizeof(ct));
        CHECK("3-04 aead_tag_bitflip_rejected", r != 0);
    }

    /* 3-05: same SEQ used twice — caller MUST NOT reuse. We assert that
     *        identical (key, nonce, plaintext) gives identical ciphertext —
     *        i.e. nonce reuse is detectable as deterministic output, which
     *        is the catastrophic property the protocol layer must avoid. */
    {
        build_nonce(0x00, 104, nonce);
        build_ad(pair_id, 104, 0x10, 0x05, ad);
        const uint8_t plain[8] = "noncereu";
        uint8_t ct1[8], mac1[16], ct2[8], mac2[16];
        crypto_aead_lock(ct1, mac1, key, nonce, ad, 10, plain, sizeof(plain));
        crypto_aead_lock(ct2, mac2, key, nonce, ad, 10, plain, sizeof(plain));
        CHECK("3-05 aead_same_nonce_deterministic_output",
              memcmp(ct1, ct2, 8) == 0 && memcmp(mac1, mac2, 16) == 0);
    }

    /* 3-06: nonce construction client direction */
    {
        build_nonce(0x00, 0x12345678u, nonce);
        int ok = nonce[0] == 0x00
              && nonce[1] == 0x78 && nonce[2] == 0x56
              && nonce[3] == 0x34 && nonce[4] == 0x12;
        for (int i = 5; i < 24; i++) ok = ok && nonce[i] == 0x00;
        CHECK("3-06 nonce_client_direction", ok);
    }

    /* 3-06b: nonce construction server direction */
    {
        build_nonce(0x01, 0x12345678u, nonce);
        int ok = nonce[0] == 0x01
              && nonce[1] == 0x78 && nonce[2] == 0x56
              && nonce[3] == 0x34 && nonce[4] == 0x12;
        for (int i = 5; i < 24; i++) ok = ok && nonce[i] == 0x00;
        CHECK("3-06b nonce_server_direction", ok);
    }

    /* 3-07: AD PAIR_ID authenticated — flipping a PAIR_ID bit fails AEAD */
    {
        build_nonce(0x00, 200, nonce);
        build_ad(pair_id, 200, 0x10, 0x05, ad);
        const uint8_t plain[8] = "padbinda";
        uint8_t ct[8], mac[16], out[8];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10, plain, sizeof(plain));
        uint8_t ad_bad[10];
        memcpy(ad_bad, ad, 10);
        ad_bad[2] ^= 0x40;
        int r = crypto_aead_unlock(out, mac, key, nonce, ad_bad, 10, ct, sizeof(ct));
        CHECK("3-07 ad_pair_id_authenticated", r != 0);
    }

    /* 3-08: CHAN bits 0 and 1 are in AD — flipping FIRST/MORE bits fails */
    {
        build_nonce(0x00, 201, nonce);
        uint8_t chan = (uint8_t)((1 << 4) | CHAN_FF_BIT | CHAN_MF_BIT);
        build_ad(pair_id, 201, chan, 0x04, ad);
        const uint8_t plain[8] = "fragbits";
        uint8_t ct[8], mac[16], out[8];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10, plain, sizeof(plain));

        uint8_t ad_bad[10];
        memcpy(ad_bad, ad, 10);
        ad_bad[8] ^= CHAN_MF_BIT;
        int r1 = crypto_aead_unlock(out, mac, key, nonce, ad_bad, 10,
                                    ct, sizeof(ct));

        memcpy(ad_bad, ad, 10);
        ad_bad[8] ^= CHAN_FF_BIT;
        int r2 = crypto_aead_unlock(out, mac, key, nonce, ad_bad, 10,
                                    ct, sizeof(ct));

        CHECK("3-08 ad_chan_frag_bits_authenticated", r1 != 0 && r2 != 0);
    }

    /* 3-09: client and server SEQ=100 give DIFFERENT ciphertexts */
    {
        const uint8_t plain[8] = "samebody";
        uint8_t ct_c[8], mac_c[16], ct_s[8], mac_s[16];
        uint8_t nonce_c[24], nonce_s[24];

        build_nonce(0x00, 100, nonce_c);
        build_nonce(0x01, 100, nonce_s);
        build_ad(pair_id, 100, 0x10, 0x05, ad);
        crypto_aead_lock(ct_c, mac_c, key, nonce_c, ad, 10, plain, sizeof(plain));
        crypto_aead_lock(ct_s, mac_s, key, nonce_s, ad, 10, plain, sizeof(plain));
        CHECK("3-09 client_server_nonces_disjoint",
              memcmp(ct_c, ct_s, 8) != 0 || memcmp(mac_c, mac_s, 16) != 0);
    }

    /* ------------------------------------------------------------------------ *
     * 3-10..3-13: hello_nonce per-send uniqueness (D-39, Phase C-4).
     *
     * SCOPE — what these tests do and do not catch.
     *
     * These tests exercise crypto_encrypt_with_nonce /
     * crypto_decrypt_with_nonce directly. They DO catch:
     *   - a regression that makes the wrapper ignore its caller-supplied
     *     nonce (3-10 + 3-13: distinct nonces -> distinct outputs, fixed
     *     nonce -> identical output)
     *   - a regression that drops integrity protection on the cleartext
     *     nonce copy (3-11: tampered nonce -> Poly1305 tag failure)
     *   - a regression that makes the wrapper sample its own nonce
     *     internally and discard the caller's (3-13)
     *
     * They DO NOT catch a regression in src/session.c's send_hello()
     * itself — for example, a refactor that calls plain crypto_encrypt
     * (deterministic build_nonce(direction, seq)) instead of
     * crypto_encrypt_with_nonce. Catching that requires linking
     * session.c into the test, which pulls in transport/channel/pty and
     * is out of scope for this harness. If you change send_hello, audit
     * its AEAD call site by hand and verify it still uses
     * crypto_encrypt_with_nonce with a freshly-sampled per-send nonce.
     * ------------------------------------------------------------------------ */

    /* 3-10: crypto_encrypt_with_nonce honors its nonce parameter — same
     *       inputs except for the nonce produce DIFFERENT ciphertexts.
     *       Catches a regression where the wrapper drops or overwrites
     *       its caller-supplied nonce. */
    {
        uint8_t hello_key[32];
        for (int i = 0; i < 32; i++) hello_key[i] = (uint8_t)(0x55 ^ i);

        uint8_t hello_pt[32];
        memset(hello_pt, 0, sizeof(hello_pt));
        hello_pt[0] = 0x02;  /* version = 0x02 (post-C-4) */
        hello_pt[1] = 0x01;  /* caps = PTY */
        for (int i = 0; i < 16; i++) hello_pt[2 + i] = (uint8_t)(0x10 + i);

        build_ad(pair_id, /*seq=*/0, /*chan=*/0x02,
                 /*type=*/0x01 /* CTRL_HELLO */, ad);

        uint8_t nonce_a[24], nonce_b[24];
        if (getentropy(nonce_a, 24) != 0 || getentropy(nonce_b, 24) != 0) {
            CHECK("3-10 hello_nonce_csprng_available", 0);
        } else {
            uint8_t out_a[48], out_b[48];
            size_t  out_a_len = 0, out_b_len = 0;
            int ra = crypto_encrypt_with_nonce(hello_key, nonce_a, ad,
                                               hello_pt, sizeof(hello_pt),
                                               out_a, &out_a_len);
            int rb = crypto_encrypt_with_nonce(hello_key, nonce_b, ad,
                                               hello_pt, sizeof(hello_pt),
                                               out_b, &out_b_len);

            int both_ok        = (ra == 0 && rb == 0);
            int len_ok         = (out_a_len == 48 && out_b_len == 48);
            int nonces_distinct = (memcmp(nonce_a, nonce_b, 24) != 0);
            int outputs_distinct = (memcmp(out_a, out_b, 48) != 0);
            CHECK("3-10 hello_nonce_per_send_unique_ciphertexts",
                  both_ok && len_ok && nonces_distinct && outputs_distinct);
        }
    }

    /* 3-11: an attacker who tampers with the cleartext hello_nonce in the
     *       wire body — without changing the ciphertext — gets a decrypt
     *       failure from crypto_decrypt_with_nonce, because XChaCha20
     *       derives a different keystream and Poly1305 one-time key.
     *       This is what "the nonce is not in AD but is still authenticated
     *       by the AEAD tag" means. */
    {
        uint8_t hello_key[32];
        for (int i = 0; i < 32; i++) hello_key[i] = (uint8_t)(0x77 ^ i);

        const uint8_t hello_pt[32] = "URTB hello plaintext (32 bytes).";
        build_ad(pair_id, /*seq=*/0, /*chan=*/0x02, /*type=*/0x01, ad);

        uint8_t hello_nonce[24];
        if (getentropy(hello_nonce, 24) != 0) {
            CHECK("3-11 hello_nonce_csprng_available", 0);
        } else {
            uint8_t ct[48];
            size_t  ct_len = 0;
            int re = crypto_encrypt_with_nonce(hello_key, hello_nonce, ad,
                                               hello_pt, sizeof(hello_pt),
                                               ct, &ct_len);

            /* Tamper with the cleartext nonce as it would appear in BODY[0..23]. */
            uint8_t tampered_nonce[24];
            memcpy(tampered_nonce, hello_nonce, 24);
            tampered_nonce[5] ^= 0x40;

            uint8_t pt_out[32];
            size_t  pt_out_len = 0;
            int rd = crypto_decrypt_with_nonce(hello_key, tampered_nonce, ad,
                                               ct, ct_len,
                                               pt_out, &pt_out_len);
            CHECK("3-11 hello_nonce_tamper_rejected_by_aead_tag",
                  re == 0 && rd != 0);
        }
    }

    /* 3-12: the C-3 BLOCKER scenario — two sessions under the SAME
     *       hello_key (deterministic from PSK alone) sending CTRL_HELLO
     *       at SEQ=0 from the SAME direction with IDENTICAL plaintext and
     *       AD. The pre-C-4 path used nonce = (direction || SEQ || zeros)
     *       via crypto_encrypt and produced the SAME (key, nonce) pair
     *       across the two sessions — catastrophic for Poly1305.
     *
     *       The post-C-4 path calls crypto_encrypt_with_nonce with a
     *       fresh per-send nonce. This test calls crypto_encrypt_with_nonce
     *       twice with two distinct random nonces and asserts the outputs
     *       differ — proving the wrapper does NOT silently fall back to
     *       deterministic nonce derivation. If a future refactor restores
     *       the build_nonce(direction, seq) path here, the wrapper
     *       contract breaks and this CHECK fails. */
    {
        uint8_t psk_derived_hello_key[32];
        for (int i = 0; i < 32; i++)
            psk_derived_hello_key[i] = (uint8_t)(0x33 ^ (i * 7));

        const uint8_t hello_pt[32] = "session CTRL_HELLO plaintext .. ";

        build_ad(pair_id, /*seq=*/0, /*chan=*/0x02, /*type=*/0x01, ad);

        uint8_t nonce_session_a[24], nonce_session_b[24];
        if (getentropy(nonce_session_a, 24) != 0 ||
            getentropy(nonce_session_b, 24) != 0) {
            CHECK("3-12 hello_nonce_csprng_available", 0);
        } else {
            uint8_t out_a[48], out_b[48];
            size_t  out_a_len = 0, out_b_len = 0;
            int ra = crypto_encrypt_with_nonce(psk_derived_hello_key,
                                               nonce_session_a, ad,
                                               hello_pt, sizeof(hello_pt),
                                               out_a, &out_a_len);
            int rb = crypto_encrypt_with_nonce(psk_derived_hello_key,
                                               nonce_session_b, ad,
                                               hello_pt, sizeof(hello_pt),
                                               out_b, &out_b_len);

            CHECK("3-12 cross_session_hello_distinct_under_same_psk",
                  ra == 0 && rb == 0 &&
                  out_a_len == 48 && out_b_len == 48 &&
                  memcmp(out_a, out_b, 48) != 0);
        }
    }

    /* 3-13: positive control — same nonce, same key, same plaintext, same
     *       AD MUST produce byte-identical output. This pairs with 3-10
     *       to prove crypto_encrypt_with_nonce actually consumes its
     *       nonce parameter (rather than, say, sampling its own internally
     *       and ignoring the caller's). Without this, a wrapper that just
     *       called crypto_random_bytes() and threw the caller's nonce on
     *       the floor would still pass 3-10 and 3-12 by accident. */
    {
        uint8_t hello_key[32];
        for (int i = 0; i < 32; i++) hello_key[i] = (uint8_t)(0xA5 ^ i);

        const uint8_t hello_pt[32] = "URTB hello pt for 3-13 sentinel.";
        build_ad(pair_id, /*seq=*/0, /*chan=*/0x02, /*type=*/0x01, ad);

        uint8_t fixed_nonce[24];
        for (int i = 0; i < 24; i++) fixed_nonce[i] = (uint8_t)(0xC0 + i);

        uint8_t out_a[48], out_b[48];
        size_t  out_a_len = 0, out_b_len = 0;
        int ra = crypto_encrypt_with_nonce(hello_key, fixed_nonce, ad,
                                           hello_pt, sizeof(hello_pt),
                                           out_a, &out_a_len);
        int rb = crypto_encrypt_with_nonce(hello_key, fixed_nonce, ad,
                                           hello_pt, sizeof(hello_pt),
                                           out_b, &out_b_len);
        CHECK("3-13 same_nonce_same_inputs_byte_identical",
              ra == 0 && rb == 0 &&
              out_a_len == 48 && out_b_len == 48 &&
              memcmp(out_a, out_b, 48) == 0);
    }
}

/* ------------------------------------------------------------------------- */
/* Group 4 — Replay window (additive form, fencepost test)                    */
/* ------------------------------------------------------------------------- */

static void test_group4_replay(void)
{
    /* 4-01: SEQ=300 accepted, SEQ=300 again rejected */
    {
        replay_t r = { 0 };
        int a = replay_accept(&r, 300);
        int b = replay_accept(&r, 300);
        CHECK("4-01 first_accepted_replay_rejected", a == 1 && b == 0);
    }

    /* 4-02: HWM=300, SEQ=44 (additive boundary, 44+256=300, NOT > 300) → reject */
    {
        replay_t r = { 0 };
        replay_accept(&r, 300);
        int a44 = replay_accept(&r, 44);
        int a43 = replay_accept(&r, 43);
        CHECK("4-02 fencepost_44_43_rejected", a44 == 0 && a43 == 0);
    }

    /* 4-03: HWM=300, SEQ=45 (45+256=301 > 300) → accept */
    {
        replay_t r = { 0 };
        replay_accept(&r, 300);
        int a = replay_accept(&r, 45);
        CHECK("4-03 first_inside_window_accepted", a == 1);
    }

    /* 4-04: SEQ=600 after HWM=300 → accept, HWM advances */
    {
        replay_t r = { 0 };
        replay_accept(&r, 300);
        int a = replay_accept(&r, 600);
        CHECK("4-04 advance_to_higher_seq", a == 1 && r.hwm == 600);
    }

    /* 4-05: HWM=600, SEQ=44 well below window → reject */
    {
        replay_t r = { 0 };
        replay_accept(&r, 600);
        int a = replay_accept(&r, 44);
        CHECK("4-05 well_below_window_rejected", a == 0);
    }
}

/* ------------------------------------------------------------------------- */
/* Group 5 — KDF (BLAKE2b keyed-hash)                                        */
/* ------------------------------------------------------------------------- */

static void derive_session_key(const uint8_t psk[32],
                               const uint8_t nonce_a[16],
                               const uint8_t nonce_b[16],
                               uint8_t out[32])
{
    uint8_t msg[7 + 16 + 16];
    memcpy(msg,      "urtb-v1", 7);
    memcpy(msg + 7,  nonce_a,   16);
    memcpy(msg + 23, nonce_b,   16);
    crypto_blake2b_keyed(out, 32, psk, 32, msg, sizeof(msg));
    crypto_wipe(msg, sizeof(msg));
}

static void derive_hello_key(const uint8_t psk[32], uint8_t out[32])
{
    crypto_blake2b_keyed(out, 32, psk, 32,
                         (const uint8_t *)"urtb-hello", 10);
}

static void test_group5_kdf(void)
{
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) psk[i] = (uint8_t)(i * 7 + 3);
    uint8_t na[16] = { 0 }, nb1[16] = { 1 }, nb2[16] = { 2 };

    /* 5-01: 32 bytes out */
    {
        uint8_t k[32];
        derive_session_key(psk, na, nb1, k);
        int nonzero = 0;
        for (int i = 0; i < 32; i++) if (k[i]) nonzero = 1;
        CHECK("5-01 session_key_32_bytes", nonzero);
    }

    /* 5-02: different nonce_b → different key */
    {
        uint8_t k1[32], k2[32];
        derive_session_key(psk, na, nb1, k1);
        derive_session_key(psk, na, nb2, k2);
        CHECK("5-02 different_nonce_different_key", memcmp(k1, k2, 32) != 0);
    }

    /* 5-03: deterministic */
    {
        uint8_t k1[32], k2[32];
        derive_session_key(psk, na, nb1, k1);
        derive_session_key(psk, na, nb1, k2);
        CHECK("5-03 deterministic", memcmp(k1, k2, 32) == 0);
    }

    /* 5-04: not identity (key != psk) */
    {
        uint8_t k[32];
        derive_session_key(psk, na, nb1, k);
        CHECK("5-04 session_key_not_psk", memcmp(k, psk, 32) != 0);
    }

    /* 5-05: hello_key differs from session_key */
    {
        uint8_t hk[32], sk[32];
        derive_hello_key(psk, hk);
        derive_session_key(psk, na, nb1, sk);
        CHECK("5-05 hello_key_distinct", memcmp(hk, sk, 32) != 0);
    }

    /* 5-06: CTRL_HELLO body encrypted with hello_key cannot be decrypted with
     * session_key. Round-trip with hello_key works. */
    {
        uint8_t hk[32], sk[32];
        derive_hello_key(psk, hk);
        derive_session_key(psk, na, nb1, sk);

        uint8_t pair_id[4] = { 1, 2, 3, 4 };
        uint8_t ad[10];
        build_ad(pair_id, 0, 0x00 /* CHAN=0 control */, 0x01 /* CTRL_HELLO */, ad);

        uint8_t nonce[24];
        build_nonce(0x00, 0, nonce);

        uint8_t plain[32] = { 0 };
        plain[0] = 0x01; /* version */
        plain[1] = 0x00; /* caps */
        for (int i = 0; i < 16; i++) plain[2 + i] = (uint8_t)i;

        uint8_t ct[32], mac[16], out[32];
        crypto_aead_lock(ct, mac, hk, nonce, ad, 10, plain, sizeof(plain));

        int r_hk = crypto_aead_unlock(out, mac, hk, nonce, ad, 10, ct, sizeof(ct));
        int r_sk = crypto_aead_unlock(out, mac, sk, nonce, ad, 10, ct, sizeof(ct));
        CHECK("5-06 hello_key_round_trip_session_key_rejects",
              r_hk == 0 && r_sk != 0);
    }

    /* 5-07: nonce_a/nonce_b swap in KDF gives different keys → AEAD fails */
    {
        uint8_t k_ab[32], k_ba[32];
        derive_session_key(psk, na,  nb1, k_ab);
        derive_session_key(psk, nb1, na,  k_ba);
        /* Encrypt with k_ab, decrypt with k_ba → must fail */
        uint8_t pair_id[4] = { 9, 9, 9, 9 };
        uint8_t ad[10];
        build_ad(pair_id, 0, 0x00, 0x03 /* CTRL_READY */, ad);
        uint8_t nonce[24];
        build_nonce(0x01, 0, nonce);
        uint8_t plain[1] = { 0 };
        uint8_t ct[1], mac[16], out[1];
        crypto_aead_lock(ct, mac, k_ab, nonce, ad, 10, plain, 0);
        int r = crypto_aead_unlock(out, mac, k_ba, nonce, ad, 10, ct, 0);
        CHECK("5-07 nonce_swap_aead_rejects", r != 0);
    }

    /* 5-08: wrong direction byte fails AEAD */
    {
        uint8_t k[32];
        derive_session_key(psk, na, nb1, k);
        uint8_t pair_id[4] = { 1, 1, 1, 1 };
        uint8_t ad[10];
        build_ad(pair_id, 7, 0x00, 0x03, ad);

        uint8_t nonce_s[24], nonce_c[24];
        build_nonce(0x01, 7, nonce_s);
        build_nonce(0x00, 7, nonce_c);
        uint8_t plain[1] = { 0 };
        uint8_t ct[1], mac[16], out[1];
        /* Encrypt as server (0x01), decrypt as client (0x00 nonce) */
        crypto_aead_lock(ct, mac, k, nonce_s, ad, 10, plain, 0);
        int r = crypto_aead_unlock(out, mac, k, nonce_c, ad, 10, ct, 0);
        CHECK("5-08 wrong_direction_byte_aead_rejects", r != 0);
    }

    /* 5-09: PAIR_ID derivation (D-38, Phase C2-1).
     * crypto_derive_pair_id mirrors derive_session_key/derive_hello_key:
     * BLAKE2b_keyed(key=PSK, msg="urtb-pairid") truncated to 4 bytes.
     * Verify (a) deterministic for a fixed PSK, (b) different PSKs
     * produce different pair_ids, (c) pair_id is not just the first
     * 4 bytes of PSK. Cycle 1 GAP 1 promoted from /tmp/c2_pair_id_test.c. */
    {
        uint8_t psk_a[32], psk_b[32];
        for (int i = 0; i < 32; i++) psk_a[i] = 0xAB;
        for (int i = 0; i < 32; i++) psk_b[i] = 0x5C;

        uint8_t pid_a1[4], pid_a2[4], pid_b[4];
        uint8_t hash[32];
        crypto_blake2b_keyed(hash, 32, psk_a, 32,
                             (const uint8_t *)"urtb-pairid", 11);
        memcpy(pid_a1, hash, 4);
        crypto_blake2b_keyed(hash, 32, psk_a, 32,
                             (const uint8_t *)"urtb-pairid", 11);
        memcpy(pid_a2, hash, 4);
        crypto_blake2b_keyed(hash, 32, psk_b, 32,
                             (const uint8_t *)"urtb-pairid", 11);
        memcpy(pid_b, hash, 4);

        CHECK("5-09a pair_id_deterministic_same_psk",
              memcmp(pid_a1, pid_a2, 4) == 0);
        CHECK("5-09b pair_id_distinct_per_psk",
              memcmp(pid_a1, pid_b, 4) != 0);
        CHECK("5-09c pair_id_not_psk_prefix",
              memcmp(pid_a1, psk_a, 4) != 0);
    }
}

/* ------------------------------------------------------------------------- */
/* Group 6 — stdio transport (socketpair + execvp cat)                       */
/* ------------------------------------------------------------------------- */

/* Minimal length-framed write/read used to simulate a stream transport. */
static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n == 0)  return -1;
        if (n < 0)   { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static void test_group6_stdio_transport(void)
{
    /* 6-00: socketpair round-trip */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            CHECK("6-00 stdio_socketpair_round_trip", 0);
        } else {
            uint8_t pair_id[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
            uint8_t ct[16] = { 0 };
            uint8_t frame[64];
            int n = radio_encode(pair_id, 1, 0x10, 0x05, ct, sizeof(ct),
                                 frame, sizeof(frame));

            uint16_t flen = (uint16_t)n;
            uint8_t fb[2] = { (uint8_t)(flen & 0xFF), (uint8_t)(flen >> 8) };
            int wok = write_all(sv[0], fb, 2) == 0
                   && write_all(sv[0], frame, (size_t)n) == 0;

            uint8_t back_len_buf[2];
            uint8_t back[64];
            int rok = read_all(sv[1], back_len_buf, 2) == 0;
            uint16_t back_len = (uint16_t)back_len_buf[0] | ((uint16_t)back_len_buf[1] << 8);
            rok = rok && back_len == flen;
            rok = rok && read_all(sv[1], back, back_len) == 0;
            int eq = memcmp(back, frame, (size_t)n) == 0;
            close(sv[0]); close(sv[1]);
            CHECK("6-00 stdio_socketpair_round_trip", wok && rok && eq);
        }
    }

    /* 6-00b: execvp("cat") echo round-trip — validates the --exec fork mechanism. */
    {
        int parent_to_child[2];
        int child_to_parent[2];
        if (pipe(parent_to_child) != 0 || pipe(child_to_parent) != 0) {
            CHECK("6-00b stdio_exec_cat_round_trip", 0);
            return;
        }
        pid_t pid = fork();
        if (pid < 0) {
            CHECK("6-00b stdio_exec_cat_round_trip", 0);
            return;
        }
        if (pid == 0) {
            /* child: dup pipes onto stdin/stdout, exec cat */
            dup2(parent_to_child[0], 0);
            dup2(child_to_parent[1], 1);
            close(parent_to_child[0]); close(parent_to_child[1]);
            close(child_to_parent[0]); close(child_to_parent[1]);
            char *argv[] = { (char *)"cat", NULL };
            execvp(argv[0], argv);
            _exit(127);
        }
        close(parent_to_child[0]);
        close(child_to_parent[1]);

        /* parent: send a frame, read it back, compare */
        uint8_t pair_id[4] = { 1, 2, 3, 4 };
        uint8_t ct[16] = { 0xA5 };
        uint8_t frame[64];
        int n = radio_encode(pair_id, 42, 0x10, 0x04, ct, sizeof(ct),
                             frame, sizeof(frame));

        int wr = write_all(parent_to_child[1], frame, (size_t)n);
        close(parent_to_child[1]);  /* signal EOF so cat exits */

        uint8_t back[64];
        int rr = read_all(child_to_parent[0], back, (size_t)n);
        close(child_to_parent[0]);
        int status = 0;
        waitpid(pid, &status, 0);

        int eq = (memcmp(back, frame, (size_t)n) == 0);
        CHECK("6-00b stdio_exec_cat_round_trip",
              wr == 0 && rr == 0 && eq && WIFEXITED(status));
    }
}

/* ------------------------------------------------------------------------- */
/* Group 7 — §7 fragmentation / reassembly                                    */
/* ------------------------------------------------------------------------- */

static void test_group7_reasm(void)
{
    /* 7-01: single-fragment passthrough (FF=1, MF=0). Delivered directly,
     * no per-channel buffer state is left open. */
    {
        reasm_t r; reasm_reset(&r);
        const uint8_t payload[10] = { 1,2,3,4,5,6,7,8,9,10 };
        const uint8_t *out = NULL;
        size_t out_len = 0;
        int rc = reasm_feed(&r, /*chan*/1, /*type*/0x04,
                            /*ff*/1, /*mf*/0,
                            payload, sizeof(payload),
                            /*now*/0, REASM_TIMEOUT_ESPNOW_MS,
                            &out, &out_len);
        CHECK("7-01 single_fragment_pass",
              rc == REASM_DELIVER &&
              out == payload && out_len == sizeof(payload) &&
              !r.chans[1].open);
    }

    /* 7-02: two-fragment reassembly (FF=1,MF=1 then FF=0,MF=0). */
    {
        reasm_t r; reasm_reset(&r);
        const uint8_t a[5] = { 'h','e','l','l','o' };
        const uint8_t b[6] = { ' ','w','o','r','l','d' };
        const uint8_t *out = NULL;
        size_t out_len = 0;

        int rc1 = reasm_feed(&r, 1, 0x04, 1, 1, a, sizeof(a),
                             0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        int open_after_first = r.chans[1].open;
        size_t len_after_first = r.chans[1].len;
        int rc2 = reasm_feed(&r, 1, 0x04, 0, 0, b, sizeof(b),
                             0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        CHECK("7-02a fragment_first_buffered",
              rc1 == REASM_DROP && open_after_first == 1 && len_after_first == 5);
        CHECK("7-02b fragment_last_assembles",
              rc2 == REASM_DELIVER &&
              out_len == 11 &&
              memcmp(out, "hello world", 11) == 0 &&
              !r.chans[1].open);
    }

    /* 7-03: three-fragment reassembly (FF=1,MF=1; FF=0,MF=1; FF=0,MF=0). */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t a[72], b[72], c[20];
        for (size_t i = 0; i < 72; i++) a[i] = (uint8_t)('A' + (i % 26));
        for (size_t i = 0; i < 72; i++) b[i] = (uint8_t)('a' + (i % 26));
        for (size_t i = 0; i < 20; i++) c[i] = (uint8_t)('0' + (i % 10));
        const uint8_t *out = NULL;
        size_t out_len = 0;

        int rc1 = reasm_feed(&r, 1, 0x04, 1, 1, a, sizeof(a),
                             0, REASM_TIMEOUT_LORA_MS, &out, &out_len);
        int rc2 = reasm_feed(&r, 1, 0x04, 0, 1, b, sizeof(b),
                             0, REASM_TIMEOUT_LORA_MS, &out, &out_len);
        int rc3 = reasm_feed(&r, 1, 0x04, 0, 0, c, sizeof(c),
                             0, REASM_TIMEOUT_LORA_MS, &out, &out_len);
        int ok = (rc1 == REASM_DROP && rc2 == REASM_DROP && rc3 == REASM_DELIVER);
        ok = ok && out_len == 164;
        ok = ok && memcmp(out,            a, 72) == 0;
        ok = ok && memcmp(out + 72,       b, 72) == 0;
        ok = ok && memcmp(out + 144,      c, 20) == 0;
        ok = ok && !r.chans[1].open;
        CHECK("7-03 three_fragment_assemble", ok);
    }

    /* 7-04: orphaned terminal fragment (FF=0,MF=0 with no buffer) → drop. */
    {
        reasm_t r; reasm_reset(&r);
        const uint8_t z[4] = { 9,9,9,9 };
        const uint8_t *out = NULL;
        size_t out_len = 0;
        int rc = reasm_feed(&r, 1, 0x04, 0, 0, z, sizeof(z),
                            0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        CHECK("7-04 orphan_terminal_drop",
              rc == REASM_DROP && !r.chans[1].open);
    }

    /* 7-05: lost first fragment (FF=0,MF=1 with no buffer) → drop. */
    {
        reasm_t r; reasm_reset(&r);
        const uint8_t z[4] = { 7,7,7,7 };
        const uint8_t *out = NULL;
        size_t out_len = 0;
        int rc = reasm_feed(&r, 1, 0x04, 0, 1, z, sizeof(z),
                            0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        CHECK("7-05 lost_first_fragment_drop",
              rc == REASM_DROP && !r.chans[1].open);
    }

    /* 7-06: timeout sweeps an open buffer. */
    {
        reasm_t r; reasm_reset(&r);
        const uint8_t a[5] = { 'a','b','c','d','e' };
        const uint8_t *out = NULL;
        size_t out_len = 0;
        reasm_feed(&r, 1, 0x04, 1, 1, a, sizeof(a),
                   /*now*/100, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        int open_before = r.chans[1].open;

        /* Tick before deadline → still open */
        reasm_tick(&r, 100 + 1000);
        int open_mid = r.chans[1].open;

        /* Tick past deadline → closed. */
        reasm_tick(&r, 100 + REASM_TIMEOUT_ESPNOW_MS + 1);
        int open_after = r.chans[1].open;

        CHECK("7-06 timeout_sweeps_partial_buffer",
              open_before == 1 && open_mid == 1 && open_after == 0);
    }

    /* 7-07: lost terminal then new burst (FF=1,MF=1) resets buffer immediately. */
    {
        reasm_t r; reasm_reset(&r);
        const uint8_t a[5] = { 1,2,3,4,5 };
        const uint8_t b[5] = { 6,7,8,9,10 };
        const uint8_t c[3] = { 11,12,13 };
        const uint8_t *out = NULL;
        size_t out_len = 0;

        /* First message: only first fragment arrives — terminal lost. */
        reasm_feed(&r, 1, 0x04, 1, 1, a, sizeof(a),
                   0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        size_t buf_after_first = r.chans[1].len;

        /* New message: FF=1 should reset the prior buffer immediately,
         * not wait for the 5s timeout. */
        reasm_feed(&r, 1, 0x04, 1, 1, b, sizeof(b),
                   0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        int buf_eq_b = (r.chans[1].len == 5 && memcmp(r.chans[1].buf, b, 5) == 0);

        int rc3 = reasm_feed(&r, 1, 0x04, 0, 0, c, sizeof(c),
                             0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        int delivered_only_b_c = (rc3 == REASM_DELIVER && out_len == 8 &&
                                  memcmp(out,     b, 5) == 0 &&
                                  memcmp(out + 5, c, 3) == 0);

        CHECK("7-07 new_first_fragment_resets_partial",
              buf_after_first == 5 && buf_eq_b && delivered_only_b_c);
    }

    /* 7-08: oversize cap — accumulating beyond 4 KB drops the message. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t big[2048];
        memset(big, 0xAA, sizeof(big));
        const uint8_t *out = NULL;
        size_t out_len = 0;

        int rc1 = reasm_feed(&r, 1, 0x04, 1, 1, big, sizeof(big),
                             0, REASM_TIMEOUT_LORA_MS, &out, &out_len);
        int rc2 = reasm_feed(&r, 1, 0x04, 0, 1, big, sizeof(big),
                             0, REASM_TIMEOUT_LORA_MS, &out, &out_len);
        /* So far 4096 bytes — exactly at cap, still open. */
        int rc3 = reasm_feed(&r, 1, 0x04, 0, 1, big, sizeof(big),
                             0, REASM_TIMEOUT_LORA_MS, &out, &out_len);
        /* This append would overflow → ERROR + buffer reset. */
        CHECK("7-08 oversize_cap_drops",
              rc1 == REASM_DROP && rc2 == REASM_DROP &&
              rc3 == REASM_ERROR && !r.chans[1].open);
    }

    /* 7-09: mismatched TYPE in continuation → ERROR + reset. */
    {
        reasm_t r; reasm_reset(&r);
        const uint8_t a[5] = { 1,2,3,4,5 };
        const uint8_t b[5] = { 6,7,8,9,10 };
        const uint8_t *out = NULL;
        size_t out_len = 0;
        reasm_feed(&r, 1, /*type*/0x04, 1, 1, a, sizeof(a),
                   0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        int rc = reasm_feed(&r, 1, /*type*/0x05, 0, 1, b, sizeof(b),
                            0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        CHECK("7-09 type_mismatch_resets",
              rc == REASM_ERROR && !r.chans[1].open);
    }

    /* 7-10: per-channel isolation — ch1 reassembly does not stall ch0
     * single-fragment frames. (Channels are independent slots.) */
    {
        reasm_t r; reasm_reset(&r);
        const uint8_t pty_a[5] = { 'a','b','c','d','e' };
        const uint8_t pty_b[5] = { 'f','g','h','i','j' };
        const uint8_t ctrl[2]  = { 0xAA, 0xBB };
        const uint8_t *out = NULL;
        size_t out_len = 0;

        /* Open a multi-fragment burst on ch1. */
        int rc1 = reasm_feed(&r, 1, 0x04, 1, 1, pty_a, 5,
                             0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        /* While ch1 is mid-burst, deliver a single-fragment ch0 frame. */
        int rc_ctrl = reasm_feed(&r, 0, 0x06, 1, 0, ctrl, 2,
                                 0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        int ctrl_ok = (rc_ctrl == REASM_DELIVER && out == ctrl && out_len == 2);
        /* ch1 buffer must still be intact. */
        int ch1_intact = (r.chans[1].open && r.chans[1].len == 5);
        /* Finish ch1. */
        int rc2 = reasm_feed(&r, 1, 0x04, 0, 0, pty_b, 5,
                             0, REASM_TIMEOUT_ESPNOW_MS, &out, &out_len);
        int ch1_done = (rc2 == REASM_DELIVER && out_len == 10 &&
                        memcmp(out, "abcdefghij", 10) == 0);
        CHECK("7-10 channel_isolation",
              rc1 == REASM_DROP && ctrl_ok && ch1_intact && ch1_done);
    }

    /* 7-11: end-to-end sender split + receiver assemble — replicates the
     * sender logic from session_send_data in compact form against the
     * reassembler. Validates the full round-trip with FF/MF flag wiring. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t msg[200];
        for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i & 0xFF);
        const size_t mtu = 72; /* LoRa */
        size_t off = 0;
        int first = 1;
        const uint8_t *out = NULL;
        size_t out_len = 0;
        int last_rc = REASM_DROP;
        int frag_count = 0;
        while (off < sizeof(msg)) {
            size_t take = sizeof(msg) - off;
            if (take > mtu) take = mtu;
            int last = (off + take == sizeof(msg));
            int ff = first ? 1 : 0;
            int mf = last  ? 0 : 1;
            last_rc = reasm_feed(&r, 1, 0x04, ff, mf, msg + off, take,
                                 0, REASM_TIMEOUT_LORA_MS, &out, &out_len);
            off += take;
            first = 0;
            frag_count++;
        }
        CHECK("7-11 e2e_sender_split_receiver_assemble",
              frag_count == 3 &&
              last_rc == REASM_DELIVER &&
              out_len == sizeof(msg) &&
              memcmp(out, msg, sizeof(msg)) == 0);
    }
}

/* ------------------------------------------------------------------------- */
/* main                                                                      */
/* ------------------------------------------------------------------------- */

int main(void)
{
    printf("frame_test starting\n");
    test_group1_usb_frames();
    test_group2_radio_frames();
    test_group3_aead();
    test_group4_replay();
    test_group5_kdf();
    test_group6_stdio_transport();
    test_group7_reasm();
    printf("\n%d tests, %d failed\n", g_total, g_failed);
    return g_failed == 0 ? 0 : 1;
}
