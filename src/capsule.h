/*
 * capsule.h — pairing capsule API
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Capsule format: 173 bytes, see references/capsule_format.md
 * PSK + PAIR_ID wrapped with Argon2id(passphrase) + XChaCha20-Poly1305
 *
 * Version history:
 *   v1 (0x01)  legacy; reserved[68..95] zero. Load-only; the runtime
 *              assigns espnow_channel = 6 for any v1 capsule (default).
 *   v2 (0x02)  current; reserved[0] (plaintext byte 68) carries
 *              espnow_channel in 1..13. See references/capsule_format.md
 *              and DECISIONS.md D-40.
 */
#ifndef URTB_CAPSULE_H
#define URTB_CAPSULE_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>

/*
 * Generate new capsule at path, with caller-chosen ESP-NOW channel.
 * File created with O_EXCL | mode 0600. Verified with fstat() after creation.
 * All intermediate key material wiped on every exit path.
 * `espnow_channel` must be in 1..13. Passing 0 or out-of-range returns -1
 * without writing the file.
 * Returns 0 on success, -1 on failure (error logged to stderr).
 */
int capsule_generate(const char *path, const char *passphrase,
                     uint8_t espnow_channel);

/*
 * Load and decrypt capsule from path.
 * Caller must mlock(psk_out, 32) and crypto_memzero(psk_out, 32) when done.
 * On return:
 *   *espnow_channel_out receives the channel stored in the capsule, or
 *   6 for v1 capsules (which pre-date this field).
 * Returns 0 on success, -1 on failure (wrong passphrase, tampered header, etc.)
 */
int capsule_load(const char *path, const char *passphrase,
                 uint8_t psk_out[32], uint8_t pair_id_out[4],
                 uint8_t *espnow_channel_out);

#ifdef URTB_TEST_V1_EMIT
/*
 * Test-only: emit a v1 capsule for backward-compat loader tests.
 * MUST NOT be compiled into production builds. See DECISIONS.md D-40.
 * Returns 0 on success, -1 on failure.
 */
int capsule_generate_v1_testonly(const char *path, const char *passphrase);
#endif

#endif /* URTB_CAPSULE_H */
