/*
 * capsule.c — pairing capsule generate + load
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wire format (173 bytes total):
 *   [0..3]   magic 0x55 0x52 0x54 0x42
 *   [4]      version (v1=0x01, v2=0x02 = CURRENT)
 *   [5..20]  salt (16 bytes, Argon2id salt)
 *   [21..24] time_cost (uint32_t LE, default=3)
 *   [25..28] mem_cost  (uint32_t LE, default=65536)
 *   [29..32] parallelism (uint32_t LE, default=1)
 *   [33..56] nonce (24 bytes, XChaCha20)
 *   [57..60] ciphertext_len (uint32_t LE, = 96+16=112)
 *   [61..172] ciphertext (112 bytes = 96 plaintext + 16 tag)
 *
 * Plaintext (96 bytes inside ciphertext):
 *   v1:
 *     [0..31]  psk (32 bytes)
 *     [32..35] pair_id (4 bytes)
 *     [36..67] label (32 bytes, null-terminated)
 *     [68..95] reserved (28 bytes, zero)
 *   v2:
 *     [0..31]  psk (32 bytes)
 *     [32..35] pair_id (4 bytes)
 *     [36..67] label (32 bytes, null-terminated)
 *     [68]     espnow_channel (1..13)
 *     [69..95] reserved (27 bytes, zero)
 *
 * AD = header[0..32] (33 bytes = magic+version+salt+costs)
 * Version byte is part of AD, so post-creation version tampering fails
 * AEAD verification.
 */

#define _POSIX_C_SOURCE 200809L
/* htole32 / le32toh require _BSD_SOURCE or _DEFAULT_SOURCE */
#define _DEFAULT_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#else
#include <endian.h>
#endif

#include "monocypher.h"
#include "capsule.h"
#include "crypto.h"

/* -------------------------------------------------------------------------
 * Format version constants
 * ---------------------------------------------------------------------- */

#define CAPSULE_VERSION_V1       0x01
#define CAPSULE_VERSION_V2       0x02
#define CAPSULE_VERSION_CURRENT  CAPSULE_VERSION_V2
#define CAPSULE_CHANNEL_DEFAULT  6  /* historical default for v1 */

/* -------------------------------------------------------------------------
 * Wire format structs
 * ---------------------------------------------------------------------- */

#pragma pack(push, 1)
typedef struct {
    uint8_t  magic[4];       /* 0x55 0x52 0x54 0x42 */
    uint8_t  version;        /* v1=0x01, v2=0x02 */
    uint8_t  salt[16];
    uint32_t time_cost;      /* little-endian */
    uint32_t mem_cost;       /* little-endian */
    uint32_t parallelism;    /* little-endian */
    uint8_t  nonce[24];
    uint32_t ciphertext_len; /* little-endian, includes 16-byte tag */
} urtb_capsule_hdr_t;
#pragma pack(pop)

typedef struct {
    uint8_t psk[32];
    uint8_t pair_id[4];
    char    label[32];
    uint8_t reserved[28];    /* v2: reserved[0] = espnow_channel; rest zero. */
} urtb_capsule_payload_t;

static const uint8_t CAPSULE_MAGIC[4] = { 0x55, 0x52, 0x54, 0x42 };

#define CAPSULE_ARGON2_TIME_COST    3
#define CAPSULE_ARGON2_MEM_COST     65536   /* 64 MB in KB */
#define CAPSULE_ARGON2_PARALLELISM  1

/* -------------------------------------------------------------------------
 * Argon2id helper — derives 32-byte capsule_key from passphrase + salt
 * ---------------------------------------------------------------------- */

/* hard upper bounds on Argon2id parameters (DoS protection) */
#define CAPSULE_MAX_MEM_COST     (1u << 20)   /* 1 GiB of KB blocks */
#define CAPSULE_MAX_TIME_COST    64u
#define CAPSULE_MAX_PARALLELISM  4u

static int derive_capsule_key(const char *passphrase, const uint8_t salt[16],
                               uint32_t time_cost, uint32_t mem_cost,
                               uint32_t parallelism,
                               uint8_t capsule_key_out[32])
{
    /* reject adversarial cost parameters before any allocation. */
    if (mem_cost == 0 || mem_cost > CAPSULE_MAX_MEM_COST ||
        time_cost == 0 || time_cost > CAPSULE_MAX_TIME_COST ||
        parallelism == 0 || parallelism > CAPSULE_MAX_PARALLELISM) {
        fprintf(stderr, "capsule: Argon2id params out of bounds "
                        "(mem=%u time=%u par=%u)\n",
                mem_cost, time_cost, parallelism);
        return -1;
    }
    size_t work_size = (size_t)mem_cost * 1024;
    /* Allocate Argon2id work area. mlock is best-effort (non-fatal). */
    uint8_t *work_area = (uint8_t *)calloc(1, work_size);
    if (!work_area) {
        fprintf(stderr, "capsule: calloc %zu bytes for Argon2id failed\n", work_size);
        return -1;
    }
    /* mlock via crypto_mlock wrapper (best-effort, non-fatal) */
    crypto_mlock(work_area, work_size);

    crypto_argon2_config config;
    crypto_argon2_inputs inputs;
    crypto_argon2_extras extras;
    memset(&config, 0, sizeof(config));
    memset(&inputs, 0, sizeof(inputs));
    memset(&extras, 0, sizeof(extras));
    config.algorithm  = CRYPTO_ARGON2_ID;
    config.nb_blocks  = mem_cost;
    config.nb_passes  = time_cost;
    config.nb_lanes   = parallelism;
    inputs.pass       = (const uint8_t *)passphrase;
    inputs.pass_size  = (uint32_t)strlen(passphrase);
    inputs.salt       = salt;
    inputs.salt_size  = 16;

    crypto_argon2(capsule_key_out, 32, work_area, config, inputs, extras);

    crypto_wipe(work_area, work_size);
    /* Cycle 1: route through crypto_munlock to match crypto_mlock semantics
     * (the work_area was mlock'd above for Argon2). */
    (void)crypto_munlock(work_area, work_size);
    free(work_area);
    return 0;
}

/* -------------------------------------------------------------------------
 * Per-version plaintext parsers (post-AEAD).
 *
 * Each load_vN_plaintext() function defines exactly which fields exist at
 * which offsets in that wire version. Adding a new version adds a new
 * parser + one case in the dispatch switch in capsule_load(). See
 * DECISIONS.md D-40 for the template.
 * ---------------------------------------------------------------------- */

/* v1: pre-channel format. Always returns channel = 6. */
static int load_v1_plaintext(const uint8_t *plain, size_t len,
                             uint8_t psk_out[32], uint8_t pair_id_out[4],
                             uint8_t *channel_out)
{
    if (len != 96) return -1;
    memcpy(psk_out,     plain + 0,  32);
    memcpy(pair_id_out, plain + 32, 4);
    /* plain[36..67] = label, ignored by runtime */
    /* plain[68..95] = reserved, ignored */
    *channel_out = CAPSULE_CHANNEL_DEFAULT;
    return 0;
}

/* v2: channel at offset 68, reserved shrunk to 27 bytes. */
static int load_v2_plaintext(const uint8_t *plain, size_t len,
                             uint8_t psk_out[32], uint8_t pair_id_out[4],
                             uint8_t *channel_out)
{
    if (len != 96) return -1;
    uint8_t ch = plain[68];
    if (ch < 1 || ch > 13) {
        /* Defense-in-depth: refuse a corrupt-but-somehow-authenticated v2
         * capsule. generate-time validation is the primary gate; this
         * fires only if an attacker compromises both the passphrase and
         * produced a forged plaintext with an out-of-range channel. */
        fprintf(stderr, "capsule_load: v2 channel %u out of range (1..13)\n",
                (unsigned)ch);
        return -1;
    }
    memcpy(psk_out,     plain + 0,  32);
    memcpy(pair_id_out, plain + 32, 4);
    *channel_out = ch;
    return 0;
}

/* -------------------------------------------------------------------------
 * Internal generate helper — shared body for v2 (production) and the
 * URTB_TEST_V1_EMIT test-only v1 shim.
 *
 * `version` selects the header byte and the plaintext layout:
 *   CAPSULE_VERSION_V1 — reserved[0..27] zero (espnow_channel ignored).
 *   CAPSULE_VERSION_V2 — reserved[0] = espnow_channel (1..13).
 * ---------------------------------------------------------------------- */

static int capsule_generate_versioned(const char *path, const char *passphrase,
                                      uint8_t version, uint8_t espnow_channel)
{
    urtb_capsule_hdr_t hdr;
    urtb_capsule_payload_t payload;
    uint8_t capsule_key[32];
    uint8_t ct[sizeof(urtb_capsule_payload_t)];
    uint8_t mac[16];
    uint8_t ad[33];
    int fd = -1;
    int ret = -1;

    memset(&hdr, 0, sizeof(hdr));
    memset(&payload, 0, sizeof(payload));

    /* The plaintext PSK is in `payload` from crypto_random_bytes through
     * crypto_aead_lock; mlock the window so swap can't page it out before
     * crypto_wipe runs at done:. capsule_key likewise. Best-effort. */
    crypto_mlock(&payload, sizeof(payload));
    crypto_mlock(capsule_key, sizeof(capsule_key));

    /* 1. Generate PSK; derive PAIR_ID from PSK (C2-1, DECISIONS.md D-38).
     * PAIR_ID = BLAKE2b_keyed(key=PSK, msg="urtb-pairid")[:4] — eliminates
     * the independent-PAIR_ID secret so passphrase alone is sufficient to
     * reconstruct a capsule. Wire format unchanged. */
    if (crypto_random_bytes(payload.psk, 32) != 0) goto done;
    if (crypto_derive_pair_id(payload.psk, payload.pair_id) != 0) goto done;
    strncpy(payload.label, "urtb-pair", sizeof(payload.label) - 1);

    /* v2: reserved[0] IS plaintext byte 68 given the current layout.
     * No struct rename needed — only the semantics of reserved[0] change
     * at v2. v1 leaves the full reserved block zero. */
    if (version == CAPSULE_VERSION_V2) {
        payload.reserved[0] = espnow_channel;
        /* reserved[1..27] stay zero */
    }

    /* 2. Build header */
    memcpy(hdr.magic, CAPSULE_MAGIC, 4);
    hdr.version     = version;
    hdr.time_cost   = htole32(CAPSULE_ARGON2_TIME_COST);
    hdr.mem_cost    = htole32(CAPSULE_ARGON2_MEM_COST);
    hdr.parallelism = htole32(CAPSULE_ARGON2_PARALLELISM);

    if (crypto_random_bytes(hdr.salt, 16) != 0) goto done;
    if (crypto_random_bytes(hdr.nonce, 24) != 0) goto done;

    /* 3. Derive capsule_key */
    if (derive_capsule_key(passphrase, hdr.salt,
                           CAPSULE_ARGON2_TIME_COST,
                           CAPSULE_ARGON2_MEM_COST,
                           CAPSULE_ARGON2_PARALLELISM,
                           capsule_key) != 0)
        goto done;

    /* 4. AD = first 33 bytes of header (magic+version+salt+costs) */
    memcpy(ad, &hdr, 33);

    /* 5. Encrypt payload */
    hdr.ciphertext_len = htole32((uint32_t)(sizeof(ct) + 16));

    crypto_aead_lock(ct, mac,
                     capsule_key, hdr.nonce,
                     ad, 33,
                     (const uint8_t *)&payload, sizeof(payload));

    /* 6. Write file with O_EXCL and mode 0600 */
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "capsule_generate: open(%s): %s\n", path, strerror(errno));
        goto done;
    }

    /* Verify permissions via fstat (AC-01-06) */
    {
        struct stat st;
        if (fstat(fd, &st) != 0) {
            fprintf(stderr, "capsule_generate: fstat failed: %s\n", strerror(errno));
            goto done;
        }
        if ((st.st_mode & 0777) != 0600) {
            fprintf(stderr, "capsule_generate: file mode is not 0600\n");
            goto done;
        }
    }

    /* Write header */
    if (write(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        fprintf(stderr, "capsule_generate: write header failed: %s\n", strerror(errno));
        goto done;
    }
    /* Write ciphertext (ct) */
    if (write(fd, ct, sizeof(ct)) != (ssize_t)sizeof(ct)) {
        fprintf(stderr, "capsule_generate: write ct failed: %s\n", strerror(errno));
        goto done;
    }
    /* Write mac (tag) */
    if (write(fd, mac, 16) != 16) {
        fprintf(stderr, "capsule_generate: write mac failed: %s\n", strerror(errno));
        goto done;
    }

    ret = 0;

done:
    if (fd >= 0) {
        close(fd);
        /* If failed after creating file, remove it */
        if (ret != 0) unlink(path);
    }
    crypto_wipe(capsule_key, 32);
    crypto_wipe(&payload, sizeof(payload));
    crypto_wipe(ct, sizeof(ct));
    crypto_wipe(mac, 16);
    crypto_wipe(ad, 33);
    /* Pair the mlock with munlock. errno set by munlock on a path where
     * the prior mlock returned EPERM (macOS dev RLIMIT) is intentionally
     * swallowed via (void) cast. Route through crypto_munlock to match
     * crypto_mlock semantics. */
    (void)crypto_munlock(&payload, sizeof(payload));
    (void)crypto_munlock(capsule_key, sizeof(capsule_key));
    return ret;
}

/* -------------------------------------------------------------------------
 * capsule_generate (public) — always emits the CURRENT version (v2).
 * ---------------------------------------------------------------------- */

int capsule_generate(const char *path, const char *passphrase,
                     uint8_t espnow_channel)
{
    if (espnow_channel < 1 || espnow_channel > 13) {
        fprintf(stderr,
                "capsule: --espnow-channel must be 1..13 (got %u)\n",
                (unsigned)espnow_channel);
        return -1;
    }
    return capsule_generate_versioned(path, passphrase,
                                      CAPSULE_VERSION_CURRENT,
                                      espnow_channel);
}

#ifdef URTB_TEST_V1_EMIT
/* Test-only: emit a v1 capsule for backward-compat loader tests.
 * Gated behind URTB_TEST_V1_EMIT so no production binary ships a v1
 * emitter (would make a capsule with a fresh PSK that looks legitimate
 * but was never intended as a real credential — see DECISIONS.md D-40
 * rationale). */
int capsule_generate_v1_testonly(const char *path, const char *passphrase)
{
    return capsule_generate_versioned(path, passphrase,
                                      CAPSULE_VERSION_V1,
                                      /* channel ignored for v1 */ 0);
}
#endif

/* -------------------------------------------------------------------------
 * capsule_load
 * ---------------------------------------------------------------------- */

int capsule_load(const char *path, const char *passphrase,
                 uint8_t psk_out[32], uint8_t pair_id_out[4],
                 uint8_t *espnow_channel_out)
{
    urtb_capsule_hdr_t hdr;
    uint8_t capsule_key[32];
    uint8_t ad[33];
    urtb_capsule_payload_t payload;
    /* fixed-size stack buffer sized to spec. No malloc. */
    uint8_t ct[sizeof(urtb_capsule_payload_t)];
    uint8_t mac_buf[16];
    int fd = -1;
    int ret = -1;

    /* lock the plaintext PSK window so swap can't write the
     * decrypted PSK to disk between unlock and wipe. Best-effort. */
    crypto_mlock(&payload, sizeof(payload));
    crypto_mlock(capsule_key, sizeof(capsule_key));

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "capsule_load: open(%s): %s\n", path, strerror(errno));
        /* Must reach `done:` so the mlock'd payload and capsule_key
         * buffers are unlocked. A bare `return -1` here leaks the mlock
         * until process exit. */
        goto done;
    }

    /* 1. Read header */
    if (read(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        fprintf(stderr, "capsule_load: short read on header\n");
        goto done;
    }

    /* 2. Validate magic + version (pre-AEAD accept-list).
     *
     * The version byte is also part of the AEAD AD (see step 6 below), so
     * a forged or swapped version byte still fails the tag check. This
     * pre-AEAD gate only guards against obviously-bogus files (saves a
     * pointless Argon2id + AEAD round). Accept every version whose parser
     * is compiled in — adding a new version means one more entry here
     * plus one more case in the dispatch switch. See DECISIONS.md D-40. */
    if (memcmp(hdr.magic, CAPSULE_MAGIC, 4) != 0) {
        fprintf(stderr, "capsule_load: bad magic\n");
        goto done;
    }
    if (hdr.version != CAPSULE_VERSION_V1 &&
        hdr.version != CAPSULE_VERSION_V2) {
        fprintf(stderr, "capsule_load: unsupported version %u\n", hdr.version);
        goto done;
    }

    /* 3. Validate ciphertext_len — MUST match exactly (96 payload + 16 tag). */
    uint32_t ct_total = le32toh(hdr.ciphertext_len);
    if (ct_total != (uint32_t)(sizeof(ct) + 16)) {
        fprintf(stderr, "capsule_load: ciphertext_len %u != expected %zu\n",
                ct_total, sizeof(ct) + 16);
        goto done;
    }

    /* 4. Read ciphertext body + tag into fixed buffers. */
    if (read(fd, ct, sizeof(ct)) != (ssize_t)sizeof(ct)) {
        fprintf(stderr, "capsule_load: short read on ciphertext body\n");
        goto done;
    }
    if (read(fd, mac_buf, 16) != 16) {
        fprintf(stderr, "capsule_load: short read on mac\n");
        goto done;
    }

    /* 5. Derive capsule_key ( bounds checks inside) */
    if (derive_capsule_key(passphrase, hdr.salt,
                           le32toh(hdr.time_cost),
                           le32toh(hdr.mem_cost),
                           le32toh(hdr.parallelism),
                           capsule_key) != 0)
        goto done;

    /* 6. Build AD = first 33 bytes of header */
    memcpy(ad, &hdr, 33);

    /* 7. Decrypt */
    memset(&payload, 0, sizeof(payload));
    int r = crypto_aead_unlock((uint8_t *)&payload, mac_buf,
                               capsule_key, hdr.nonce,
                               ad, 33,
                               ct, sizeof(ct));
    if (r != 0) {
        fprintf(stderr, "capsule_load: AEAD verification failed (wrong passphrase?)\n");
        goto done;
    }

    /* 8. Version dispatch. The plaintext layout is version-specific; the
     * generic part is dispatch, the explicit part is the per-version
     * parser's field list. See DECISIONS.md D-40. */
    switch (hdr.version) {
    case CAPSULE_VERSION_V1:
        ret = load_v1_plaintext((const uint8_t *)&payload, sizeof(payload),
                                psk_out, pair_id_out, espnow_channel_out);
        break;
    case CAPSULE_VERSION_V2:
        ret = load_v2_plaintext((const uint8_t *)&payload, sizeof(payload),
                                psk_out, pair_id_out, espnow_channel_out);
        break;
    default:
        /* Unreachable: the pre-AEAD accept-list rejected anything else. */
        fprintf(stderr, "capsule: unsupported format version 0x%02x\n",
                hdr.version);
        ret = -1;
        break;
    }

done:
    if (fd >= 0) close(fd);
    crypto_wipe(capsule_key, 32);
    crypto_wipe(&payload, sizeof(payload));
    crypto_wipe(ad, 33);
    crypto_wipe(ct, sizeof(ct));
    crypto_wipe(mac_buf, 16);
    /* Cycle 1: route through crypto_munlock to match crypto_mlock semantics. */
    crypto_munlock(&payload, sizeof(payload));
    crypto_munlock(capsule_key, sizeof(capsule_key));
    return ret;
}
