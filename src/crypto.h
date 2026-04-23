/*
 * crypto.h — crypto wrappers
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 * Provides:
 *   KDF:     crypto_derive_session_key, crypto_derive_hello_key (BLAKE2b)
 *   AEAD:    crypto_encrypt, crypto_decrypt (XChaCha20-Poly1305 via monocypher)
 *   Util:    crypto_memzero, crypto_mlock, crypto_random_bytes
 */
#ifndef URTB_CRYPTO_H
#define URTB_CRYPTO_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Key derivation
 * ---------------------------------------------------------------------- */

/*
 * Derive session key from PSK + nonces.
 * session_key = BLAKE2b_keyed(key=PSK, msg="urtb-v1"||nonce_a||nonce_b)
 * Returns 0 on success, -1 on error.
 */
int crypto_derive_session_key(const uint8_t psk[32],
                              const uint8_t nonce_a[16],
                              const uint8_t nonce_b[16],
                              uint8_t session_key_out[32]);

/*
 * Derive pre-session hello key from PSK.
 * hello_key = BLAKE2b_keyed(key=PSK, msg="urtb-hello")
 * Returns 0 on success, -1 on error.
 */
int crypto_derive_hello_key(const uint8_t psk[32],
                            uint8_t hello_key_out[32]);

/*
 * Derive 4-byte PAIR_ID deterministically from PSK (C2-1, DECISIONS.md D-38).
 * pair_id = BLAKE2b_keyed(key=PSK, msg="urtb-pairid")[:4]
 * Domain-separated from session/hello key derivations.
 */
int crypto_derive_pair_id(const uint8_t psk[32],
                          uint8_t pair_id_out[4]);

/* -------------------------------------------------------------------------
 * AEAD wrappers
 *
 * ad = PAIR_ID(4) || SEQ(4) || CHAN(1) || TYPE(1) = 10 bytes
 * CHAN byte MUST include MORE_FRAGMENTS bit (bit 0) in the AD.
 *
 * Nonce construction (internal):
 *   nonce[0]     = direction byte
 *   nonce[1..4]  = SEQ as uint32_t little-endian
 *   nonce[5..23] = 0x00
 * ---------------------------------------------------------------------- */

/*
 * Encrypt plaintext into ciphertext (includes 16-byte appended tag).
 * ciphertext_out must be at least plaintext_len + 16 bytes.
 * Returns 0 on success, -1 on error.
 */
int crypto_encrypt(const uint8_t key[32],
                   uint32_t seq,
                   uint8_t direction,        /* 0x00=client→server, 0x01=server→client */
                   const uint8_t ad[10],
                   const uint8_t *plaintext, size_t plaintext_len,
                   uint8_t *ciphertext_out, size_t *ciphertext_len_out);

/*
 * Decrypt ciphertext. ciphertext_len must include the 16-byte tag.
 * Returns 0 on success, -1 on auth failure.
 */
int crypto_decrypt(const uint8_t key[32],
                   uint32_t seq,
                   uint8_t direction,
                   const uint8_t ad[10],
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   uint8_t *plaintext_out, size_t *plaintext_len_out);

/*
 * Explicit-nonce AEAD variants — used by the CTRL_HELLO / CTRL_HELLO_ACK
 * handshake (Phase C-4, DECISIONS.md D-39) where the nonce is sampled
 * randomly per send and carried in cleartext in the frame body, not
 * derived from (direction, seq). Required to avoid Poly1305 one-time-key
 * reuse across sessions for keys that are deterministic from PSK alone
 * (hello_key). All other frames keep the (direction, seq) path above.
 *
 * nonce[24] is the full 24-byte XChaCha20 nonce, supplied by the caller.
 * AD layout is identical to crypto_encrypt above.
 */
int crypto_encrypt_with_nonce(const uint8_t key[32],
                              const uint8_t nonce[24],
                              const uint8_t ad[10],
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext_out, size_t *ciphertext_len_out);

int crypto_decrypt_with_nonce(const uint8_t key[32],
                              const uint8_t nonce[24],
                              const uint8_t ad[10],
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext_out, size_t *plaintext_len_out);

/* -------------------------------------------------------------------------
 * Memory security
 * ---------------------------------------------------------------------- */

/* Zero a buffer in a way the compiler cannot optimize away (calls crypto_wipe). */
void crypto_memzero(void *buf, size_t len);

/* Lock a buffer into RAM (mlock). Returns 0 on success, -1 on failure (non-fatal). */
int crypto_mlock(void *buf, size_t len);

/* Unlock a previously crypto_mlock'd buffer. Returns 0 on success, -1 on failure. */
int crypto_munlock(void *buf, size_t len);

/* Fill buf with cryptographically random bytes via getrandom(). */
int crypto_random_bytes(void *buf, size_t len);

/* Mark a buffer as excluded from core dumps (MADV_DONTDUMP on Linux).
 * No-op on platforms where MADV_DONTDUMP is unavailable. Non-fatal. */
void crypto_mark_dontdump(void *addr, size_t len);

#endif /* URTB_CRYPTO_H */
