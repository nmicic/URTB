/*
 * crypto.c — BLAKE2b KDF + XChaCha20-Poly1305 AEAD wrappers
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h>   /* getentropy() */
#else
#include <sys/random.h>   /* getrandom() */
#endif

#include "monocypher.h"
#include "crypto.h"

/* -------------------------------------------------------------------------
 * Key derivation
 * ---------------------------------------------------------------------- */

int crypto_derive_session_key(const uint8_t psk[32],
                              const uint8_t nonce_a[16],
                              const uint8_t nonce_b[16],
                              uint8_t session_key_out[32])
{
    /* msg = "urtb-v1" || nonce_a || nonce_b  (7 + 16 + 16 = 39 bytes) */
    uint8_t msg[39];
    memcpy(msg,      "urtb-v1", 7);
    memcpy(msg + 7,  nonce_a, 16);
    memcpy(msg + 23, nonce_b, 16);
    crypto_blake2b_keyed(session_key_out, 32, psk, 32, msg, sizeof(msg));
    crypto_wipe(msg, sizeof(msg));
    return 0;
}

int crypto_derive_hello_key(const uint8_t psk[32],
                            uint8_t hello_key_out[32])
{
    crypto_blake2b_keyed(hello_key_out, 32, psk, 32,
                         (const uint8_t *)"urtb-hello", 10);
    return 0;
}

int crypto_derive_pair_id(const uint8_t psk[32],
                          uint8_t pair_id_out[4])
{
    uint8_t hash[32];
    crypto_blake2b_keyed(hash, 32, psk, 32,
                         (const uint8_t *)"urtb-pairid", 11);
    memcpy(pair_id_out, hash, 4);
    crypto_wipe(hash, sizeof(hash));
    return 0;
}

/* -------------------------------------------------------------------------
 * AEAD helpers
 * ---------------------------------------------------------------------- */

static void build_nonce(uint8_t direction, uint32_t seq, uint8_t nonce[24])
{
    memset(nonce, 0, 24);
    nonce[0] = direction;
    nonce[1] = (uint8_t)(seq        & 0xFF);
    nonce[2] = (uint8_t)((seq >>  8) & 0xFF);
    nonce[3] = (uint8_t)((seq >> 16) & 0xFF);
    nonce[4] = (uint8_t)((seq >> 24) & 0xFF);
}

/* -------------------------------------------------------------------------
 * AEAD encrypt
 * Wire format: ciphertext_out = cipher_text || mac[16]
 * ---------------------------------------------------------------------- */

int crypto_encrypt(const uint8_t key[32],
                   uint32_t seq,
                   uint8_t direction,
                   const uint8_t ad[10],
                   const uint8_t *plaintext, size_t plaintext_len,
                   uint8_t *ciphertext_out, size_t *ciphertext_len_out)
{
    uint8_t nonce[24];
    build_nonce(direction, seq, nonce);

    /* crypto_aead_lock writes cipher_text in-place, mac separately */
    uint8_t mac[16];
    crypto_aead_lock(ciphertext_out, mac,
                     key, nonce,
                     ad, 10,
                     plaintext, plaintext_len);

    /* Append mac after ciphertext (wire format: ct || tag) */
    memcpy(ciphertext_out + plaintext_len, mac, 16);
    crypto_wipe(mac, 16);
    crypto_wipe(nonce, 24);

    if (ciphertext_len_out)
        *ciphertext_len_out = plaintext_len + 16;
    return 0;
}

/* -------------------------------------------------------------------------
 * AEAD decrypt
 * Wire format: ciphertext = cipher_text || mac[16]
 * ---------------------------------------------------------------------- */

int crypto_decrypt(const uint8_t key[32],
                   uint32_t seq,
                   uint8_t direction,
                   const uint8_t ad[10],
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   uint8_t *plaintext_out, size_t *plaintext_len_out)
{
    if (ciphertext_len < 16) {
        fprintf(stderr, "crypto_decrypt: ciphertext too short (%zu)\n",
                ciphertext_len);
        return -1;
    }
    size_t pt_len = ciphertext_len - 16;
    const uint8_t *mac = ciphertext + pt_len;

    uint8_t nonce[24];
    build_nonce(direction, seq, nonce);

    int r = crypto_aead_unlock(plaintext_out, mac,
                               key, nonce,
                               ad, 10,
                               ciphertext, pt_len);
    crypto_wipe(nonce, 24);

    if (r != 0) return -1;  /* auth failure */

    if (plaintext_len_out) *plaintext_len_out = pt_len;
    return 0;
}

/* -------------------------------------------------------------------------
 * Explicit-nonce AEAD (Phase C-4, hello handshake)
 *
 * Identical to crypto_encrypt/decrypt except the 24-byte XChaCha20 nonce
 * is supplied by the caller instead of derived from (direction, seq).
 * Used only for CTRL_HELLO / CTRL_HELLO_ACK; all other frames continue
 * to use the (direction, seq) path. See DECISIONS.md D-39.
 * ---------------------------------------------------------------------- */

int crypto_encrypt_with_nonce(const uint8_t key[32],
                              const uint8_t nonce[24],
                              const uint8_t ad[10],
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext_out, size_t *ciphertext_len_out)
{
    uint8_t mac[16];
    crypto_aead_lock(ciphertext_out, mac,
                     key, nonce,
                     ad, 10,
                     plaintext, plaintext_len);
    memcpy(ciphertext_out + plaintext_len, mac, 16);
    crypto_wipe(mac, 16);
    if (ciphertext_len_out)
        *ciphertext_len_out = plaintext_len + 16;
    return 0;
}

int crypto_decrypt_with_nonce(const uint8_t key[32],
                              const uint8_t nonce[24],
                              const uint8_t ad[10],
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext_out, size_t *plaintext_len_out)
{
    if (ciphertext_len < 16) {
        fprintf(stderr, "crypto_decrypt_with_nonce: ciphertext too short (%zu)\n",
                ciphertext_len);
        return -1;
    }
    size_t pt_len = ciphertext_len - 16;
    const uint8_t *mac = ciphertext + pt_len;

    int r = crypto_aead_unlock(plaintext_out, mac,
                               key, nonce,
                               ad, 10,
                               ciphertext, pt_len);
    if (r != 0) return -1;

    if (plaintext_len_out) *plaintext_len_out = pt_len;
    return 0;
}

/* -------------------------------------------------------------------------
 * Memory security
 * ---------------------------------------------------------------------- */

void crypto_memzero(void *buf, size_t len)
{
    crypto_wipe(buf, len);
}

int crypto_mlock(void *buf, size_t len)
{
    if (mlock(buf, len) != 0) {
        fprintf(stderr, "crypto_mlock: mlock failed (non-fatal): %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

int crypto_munlock(void *buf, size_t len)
{
    if (munlock(buf, len) != 0) {
        /* Non-fatal: matches crypto_mlock failure semantics. The caller
         * has already wiped (or is about to wipe) the buffer. */
        return -1;
    }
    return 0;
}

void crypto_mark_dontdump(void *addr, size_t len)
{
#ifdef MADV_DONTDUMP
    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz <= 0) return;
    uintptr_t base = (uintptr_t)addr & ~(uintptr_t)(pgsz - 1);
    size_t rlen    = len + ((uintptr_t)addr - base);
    madvise((void *)base, rlen, MADV_DONTDUMP);
#else
    (void)addr; (void)len;
#endif
}

int crypto_random_bytes(void *buf, size_t len)
{
    /* loop on EINTR and short reads. */
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
#ifdef __APPLE__
    /* macOS: getentropy(3) caps each call at 256 bytes, never short-returns,
     * and is documented as uninterruptible (no EINTR), so just loop in
     * chunks and bail on any failure. */
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;
        if (getentropy(p + off, chunk) != 0) {
            fprintf(stderr, "crypto_random_bytes: getentropy failed: %s\n",
                    strerror(errno));
            return -1;
        }
        off += chunk;
    }
#else
    while (off < len) {
        ssize_t got = getrandom(p + off, len - off, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "crypto_random_bytes: getrandom failed: %s\n",
                    strerror(errno));
            return -1;
        }
        if (got == 0) {
            fprintf(stderr, "crypto_random_bytes: getrandom returned 0\n");
            return -1;
        }
        off += (size_t)got;
    }
#endif
    return 0;
}
