# URTB Capsule Wire Format — Implementation Reference
# Source: SECURITY.md §capsule + DECISIONS.md D-12
# Date: 2026-04-15

---

## Wire layout (173 bytes total)

```
Offset  Size  Field         Notes
------  ----  -----         -----
     0     4  magic         0x55 0x52 0x54 0x42  ("URTB")
     4     1  version       0x01
     5    16  salt          random, 16 bytes (Argon2id salt)
    21     4  time_cost     uint32_t little-endian, default = 3
    25     4  mem_cost      uint32_t little-endian, default = 65536 (64 MB in KB)
    29     4  parallelism   uint32_t little-endian, default = 1
 --- header ends here (33 bytes) ---
    33    24  nonce         XChaCha20 nonce, random, 24 bytes
    57     4  ciphertext_len uint32_t little-endian (= 96 + 16 = 112 for Phase B plaintext)
    61   112  ciphertext    XChaCha20-Poly1305 ciphertext (96 bytes payload + 16 byte tag)
 --- total: 173 bytes ---
```

## Plaintext inside ciphertext (96 bytes)

```
Offset  Size  Field    Notes
------  ----  -----    -----
     0    32  psk      raw PSK bytes (random, 32 bytes)
    32     4  pair_id  4-byte PAIR_ID (random)
    36    32  label    null-terminated human label (optional, pad with 0x00)
    68    28  reserved set to 0x00, reserved for future use
 --- total: 96 bytes ---
```

## AEAD construction

```
capsule_key = Argon2id(
    pass       = passphrase (user-entered),
    salt       = salt[16],
    nb_blocks  = mem_cost,    /* 65536 */
    nb_passes  = time_cost,   /* 3 */
    nb_lanes   = parallelism  /* 1 */
) → 32 bytes

AD = magic[4] || version[1] || salt[16] || time_cost[4] || mem_cost[4] || parallelism[4]
   = 33 bytes (the entire plaintext header)

ciphertext[112] = XChaCha20-Poly1305-lock(
    key   = capsule_key,
    nonce = nonce[24],
    ad    = AD[33],
    plain = plaintext[96]
)
```

**Why AD includes KDF params:** An attacker who modifies `time_cost` or `mem_cost`
in the header changes the AD, so AEAD verification fails. Without this, an attacker
could rewrite time_cost=1/mem_cost=64 to make brute-force cheap.

## C struct

```c
#pragma pack(push, 1)
typedef struct {
    uint8_t  magic[4];       /* 0x55 0x52 0x54 0x42 */
    uint8_t  version;        /* 0x01 */
    uint8_t  salt[16];
    uint32_t time_cost;      /* little-endian */
    uint32_t mem_cost;       /* little-endian */
    uint32_t parallelism;    /* little-endian */
    uint8_t  nonce[24];
    uint32_t ciphertext_len; /* little-endian */
    /* ciphertext follows immediately */
} urtb_capsule_hdr_t;
#pragma pack(pop)

/* Plaintext (inside ciphertext) */
typedef struct {
    uint8_t  psk[32];
    uint8_t  pair_id[4];
    char     label[32];
    uint8_t  reserved[28];
} urtb_capsule_payload_t;
```

## capsule_generate() pseudocode

```c
int capsule_generate(const char *path, const char *passphrase) {
    /* 1. Generate PSK and PAIR_ID */
    uint8_t psk[32], pair_id[4];
    arc4random_buf(psk, 32);      /* or getrandom() on Linux */
    arc4random_buf(pair_id, 4);

    /* 2. Prepare plaintext payload */
    urtb_capsule_payload_t payload = {0};
    memcpy(payload.psk, psk, 32);
    memcpy(payload.pair_id, pair_id, 4);
    strncpy(payload.label, "urtb-pair", sizeof(payload.label) - 1);

    /* 3. Generate salt, derive capsule_key via Argon2id */
    uint8_t salt[16];
    arc4random_buf(salt, 16);
    /* ... allocate 64MB work area, call crypto_argon2(), see monocypher_api.md §3 ... */
    uint8_t capsule_key[32];
    /* ... crypto_argon2(capsule_key, ...) ... */

    /* 4. Build AEAD additional data (= plaintext header) */
    urtb_capsule_hdr_t hdr = {0};
    memcpy(hdr.magic, "\x55\x52\x54\x42", 4);
    hdr.version = 0x01;
    memcpy(hdr.salt, salt, 16);
    hdr.time_cost    = htole32(3);
    hdr.mem_cost     = htole32(65536);
    hdr.parallelism  = htole32(1);
    arc4random_buf(hdr.nonce, 24);

    uint8_t ad[33];
    memcpy(ad, &hdr, 33);  /* magic+version+salt+time_cost+mem_cost+parallelism */

    /* 5. Encrypt */
    uint8_t mac[16];
    uint8_t ct[sizeof(urtb_capsule_payload_t)];
    crypto_aead_lock(ct, mac, capsule_key, hdr.nonce,
                     ad, 33,
                     (uint8_t *)&payload, sizeof(payload));
    hdr.ciphertext_len = htole32(sizeof(ct) + 16);

    /* 6. Write file: header || ct || mac */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    write(fd, &hdr, sizeof(hdr));
    write(fd, ct,   sizeof(ct));
    write(fd, mac,  16);
    close(fd);

    /* 7. Wipe secrets */
    crypto_wipe(psk, 32);
    crypto_wipe(&payload, sizeof(payload));
    crypto_wipe(capsule_key, 32);
    return 0;
}
```

## capsule_load() pseudocode

```c
int capsule_load(const char *path, const char *passphrase,
                 uint8_t psk_out[32], uint8_t pair_id_out[4]) {
    /* 1. Read and validate header */
    urtb_capsule_hdr_t hdr;
    int fd = open(path, O_RDONLY);
    read(fd, &hdr, sizeof(hdr));
    if (memcmp(hdr.magic, "\x55\x52\x54\x42", 4) != 0) return -1;
    if (hdr.version != 0x01) return -1;

    uint32_t ct_total = le32toh(hdr.ciphertext_len);  /* includes 16-byte tag */
    if (ct_total < 16) return -1;
    uint32_t ct_len = ct_total - 16;

    uint8_t *ct = malloc(ct_len);
    uint8_t mac[16];
    read(fd, ct, ct_len);
    read(fd, mac, 16);
    close(fd);

    /* 2. Derive capsule_key via Argon2id */
    uint8_t capsule_key[32];
    /* ... crypto_argon2(capsule_key, le32toh(hdr.time_cost), le32toh(hdr.mem_cost), ...) ... */

    /* 3. Build AD (same as generate) and decrypt */
    uint8_t ad[33];
    memcpy(ad, &hdr, 33);

    urtb_capsule_payload_t payload;
    int r = crypto_aead_unlock((uint8_t *)&payload, mac, capsule_key,
                               hdr.nonce, ad, 33, ct, ct_len);
    crypto_wipe(capsule_key, 32);
    free(ct);
    if (r != 0) return -1;  /* wrong passphrase or tampered header */

    memcpy(psk_out,     payload.psk,     32);
    memcpy(pair_id_out, payload.pair_id, 4);
    crypto_wipe(&payload, sizeof(payload));
    return 0;
}
```

## Notes

- Use `arc4random_buf()` on macOS, `getrandom(buf, len, 0)` on Linux for random bytes.
  For portability: wrap in a `crypto_random_bytes()` function that picks at compile time.
- `htole32()` / `le32toh()` — from `<endian.h>` on Linux, `<machine/endian.h>` on macOS.
  Or write portable helpers.
- File permissions: open with O_EXCL + mode 0600. Verify with fstat() after creation (AC-01-06).
- AC-01-08: KDF-param AD binding is tested by modifying salt or time_cost in the header
  and attempting to unlock with the correct passphrase — must fail with AEAD error.

---

## Version 2 (current)

Introduced 2026-04-17. Adds per-pair ESP-NOW channel selection. See
`DECISIONS.md` D-40 for rationale.

### Plaintext layout (96 bytes, same total size as v1)

| Offset | Size | Field          | Notes                                 |
|--------|------|----------------|---------------------------------------|
|    0   |  32  | psk            | unchanged from v1                     |
|   32   |   4  | pair_id        | unchanged from v1                     |
|   36   |  32  | label          | unchanged from v1                     |
|   68   |   1  | espnow_channel | 1..13, selected at keygen time        |
|   69   |  27  | reserved       | zero, reserved for future use         |

### Header change

Byte at offset 4 becomes `0x02` for v2 capsules. AEAD construction is
unchanged: the version byte is part of AD (see "AEAD construction"
above), so post-creation version tampering fails the Poly1305 tag.

The v2 plaintext struct is binary-identical to v1's
`urtb_capsule_payload_t`; only the semantics of `reserved[0]` change at
v2 (it now carries `espnow_channel`). No struct rename needed.

### Backward compatibility

v1 capsules (version byte = 0x01) continue to load. The runtime
assigns `espnow_channel = 6` for any v1 capsule. To migrate a v1
capsule to a non-default channel, regenerate with:

    urtb keygen --out new.capsule --espnow-channel 11

### Version dispatch

`capsule_load()` has a pre-AEAD accept-list (reject obviously-bogus
version bytes cheaply) and, after AEAD decrypt succeeds, a switch on
`hdr.version` that calls the per-version plaintext parser
(`load_v1_plaintext` / `load_v2_plaintext`). Adding v3 later is:

1. New `load_v3_plaintext()` with the v3 field list.
2. One case in the post-AEAD dispatch switch.
3. One entry in the pre-AEAD accept-list.
4. Bump `CAPSULE_VERSION_CURRENT`.
5. Grow `capsule_load()`'s signature by one out-param per new field
   (the "explicit" part per the generic-pipeline principle — callers
   touch each new field deliberately).

No runtime CLI surface added; channel is selected at keygen time only.
