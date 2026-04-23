# Monocypher API Quick Reference — URTB Phase B
# Source: Monocypher 4.x (vendor in src/vendor/monocypher.c + monocypher.h)
# Date: 2026-04-15
#
# Download: https://monocypher.org/  (single .c + .h file, drop into src/vendor/)
# Version: 4.0.2 (latest stable as of 2026-04)

---

## 1. AEAD — XChaCha20-Poly1305

```c
#include "monocypher.h"

/* ENCRYPT — produces ciphertext in-place + 16-byte MAC */
void crypto_aead_lock(
    uint8_t       *cipher_text,        /* output: same size as plain_text */
    uint8_t        mac[16],            /* output: 16-byte authentication tag */
    const uint8_t  key[32],            /* session_key or hello_key */
    const uint8_t  nonce[24],          /* direction(1) || seq_le32(4) || zeros(19) */
    const uint8_t *ad,                 /* additional data (may be NULL if ad_size=0) */
    size_t         ad_size,            /* 10 bytes: PAIR_ID(4)||SEQ(4)||CHAN(1)||TYPE(1) */
    const uint8_t *plain_text,
    size_t         text_size
);

/* DECRYPT — returns 0 on success, -1 on auth failure */
int crypto_aead_unlock(
    uint8_t       *plain_text,         /* output: same size as cipher_text */
    const uint8_t  mac[16],            /* the 16-byte tag (prefix of ciphertext in wire format) */
    const uint8_t  key[32],
    const uint8_t  nonce[24],
    const uint8_t *ad,
    size_t         ad_size,
    const uint8_t *cipher_text,
    size_t         text_size
);
```

### Wire format (URTB): tag is APPENDED, not prepended
```
ciphertext_on_wire = crypto_aead_lock output || mac[16]
total wire size    = plaintext_len + 16
```

### Nonce construction
```c
uint8_t nonce[24];
memset(nonce, 0, 24);
nonce[0] = direction;          /* 0x00 = client→server, 0x01 = server→client */
nonce[1] = (seq >>  0) & 0xFF; /* seq_le32: little-endian */
nonce[2] = (seq >>  8) & 0xFF;
nonce[3] = (seq >> 16) & 0xFF;
nonce[4] = (seq >> 24) & 0xFF;
/* bytes 5–23 remain 0x00 */
```

### AD construction (10 bytes)
```c
uint8_t ad[10];
memcpy(ad + 0, pair_id, 4);    /* PAIR_ID, 4 bytes */
ad[4] = (seq >>  0) & 0xFF;    /* SEQ little-endian, 4 bytes */
ad[5] = (seq >>  8) & 0xFF;
ad[6] = (seq >> 16) & 0xFF;
ad[7] = (seq >> 24) & 0xFF;
ad[8] = chan;                  /* CHAN byte incl. FIRST_FRAGMENT(bit1) + MORE_FRAGMENTS(bit0) */
ad[9] = type;                  /* frame TYPE byte */
```

---

## 2. KDF — BLAKE2b keyed hash

```c
/* General form */
void crypto_blake2b_keyed(
    uint8_t       *hash,         /* output buffer */
    size_t         hash_size,    /* 32 for URTB (256-bit output) */
    const uint8_t *key,          /* PSK, 32 bytes */
    size_t         key_size,     /* 32 */
    const uint8_t *message,
    size_t         message_size
);
```

### Session key derivation
```c
/* session_key = BLAKE2b_keyed(key=PSK, msg="urtb-v1" || nonce_a || nonce_b) */
uint8_t msg[7 + 16 + 16];
memcpy(msg,      "urtb-v1", 7);
memcpy(msg + 7,  nonce_a,   16);
memcpy(msg + 23, nonce_b,   16);
crypto_blake2b_keyed(session_key, 32, psk, 32, msg, sizeof(msg));
crypto_wipe(msg, sizeof(msg));
```

### Hello key derivation
```c
/* hello_key = BLAKE2b_keyed(key=PSK, msg="urtb-hello") */
crypto_blake2b_keyed(hello_key, 32, psk, 32,
                     (const uint8_t *)"urtb-hello", 10);
```

---

## 3. Argon2id — capsule KDF

```c
#include "monocypher.h"

/* Argon2id config structure */
crypto_argon2_config config = {
    .algorithm  = CRYPTO_ARGON2_ID,   /* Argon2id */
    .nb_blocks  = 65536,              /* 64 MB (mem_cost in KB) */
    .nb_passes  = 3,                  /* time_cost = 3 iterations */
    .nb_lanes   = 1,                  /* parallelism = 1 */
};

crypto_argon2_inputs inputs = {
    .pass      = (const uint8_t *)passphrase,
    .pass_size = (uint32_t)strlen(passphrase),
    .salt      = salt,               /* 16 random bytes */
    .salt_size = 16,
};

crypto_argon2_extras extras = {0};   /* no secret key, no associated data */

/* Allocate work area (64 MB = nb_blocks * 1024 bytes) */
size_t work_size = (size_t)65536 * 1024;
void *work_area = malloc(work_size);
if (!work_area) { /* OOM */ }

/* mlock before use (best-effort; don't fail if mlock fails on this platform) */
mlock(work_area, work_size);

uint8_t capsule_key[32];
crypto_argon2(capsule_key, 32, work_area, config, inputs, extras);

/* Wipe work area before free */
crypto_wipe(work_area, work_size);
munlock(work_area, work_size);
free(work_area);
```

**Note on mlock:** `mlock()` requires `<sys/mman.h>`. It may fail (EPERM) if the process
doesn't have CAP_IPC_LOCK. Treat failure as non-fatal — just log and continue. The
capsule_key itself must still be mlock'd independently (see section 5).

---

## 4. Secure wipe

```c
/* Zero a buffer in a way the compiler cannot optimize away */
void crypto_wipe(void *secret, size_t size);
```

Use `crypto_wipe` instead of `memset` for any key material, PSK, passphrase copy,
or intermediate secret. `memset` can be optimized out by the compiler.

---

## 5. Memory locking (POSIX, not monocypher)

```c
#include <sys/mman.h>

/* Lock key buffers to prevent swap — call immediately after allocation */
mlock(psk, 32);
mlock(session_key, 32);
mlock(hello_key, 32);
mlock(capsule_key, 32);

/* On free: wipe first, then unlock */
crypto_wipe(session_key, 32);
munlock(session_key, 32);
```

`mlock()` may fail with EPERM if not root and RLIMIT_MEMLOCK is hit.
Log the failure but do not abort — the key is still secure in RAM, just swappable.
Production hardening: set `RLIMIT_MEMLOCK` or run with CAP_IPC_LOCK.

---

## 6. Monocypher 4.x vs 3.x API changes

If monocypher 3.x headers are found instead of 4.x:
  - 3.x: `crypto_lock()` + `crypto_unlock()` (XChacha20-Poly1305, same semantics)
  - 4.x: `crypto_aead_lock()` + `crypto_aead_unlock()` (renamed)
  - 3.x: `crypto_argon2i()` (no Argon2id variant)
  - 4.x: `crypto_argon2()` with config.algorithm = CRYPTO_ARGON2_ID

**Use 4.x.** The phase-b2 Makefile should vendor 4.x from monocypher.org.
Check version: grep for `MONOCYPHER_VERSION` in monocypher.h.

---

## 7. Compile flags

```makefile
# Monocypher is a single translation unit — just compile it
SRCS += src/vendor/monocypher.c
CFLAGS += -I src/vendor/

# No -DMONOCYPHER_* flags needed for Phase B
# Monocypher has no optional features to enable/disable
```
