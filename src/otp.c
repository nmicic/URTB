/*
 * otp.c — HOTP/TOTP OTP implementation
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#if URTB_OTP

#define _POSIX_C_SOURCE 200809L

#include "otp.h"
#include "crypto.h"
#include "vendor/sha1/sha1.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * HMAC-SHA1 (RFC 2104)
 * ---------------------------------------------------------------------- */

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *msg, size_t msg_len,
               uint8_t mac[20])
{
    uint8_t k[64];
    memset(k, 0, 64);

    if (key_len > 64) {
        sha1_ctx hk;
        sha1_init(&hk);
        sha1_update(&hk, key, key_len);
        sha1_final(&hk, k);
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, 64);
    sha1_update(&ctx, msg, msg_len);
    uint8_t inner[20];
    sha1_final(&ctx, inner);

    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, inner, 20);
    sha1_final(&ctx, mac);

    crypto_memzero(k,     sizeof k);
    crypto_memzero(ipad,  sizeof ipad);
    crypto_memzero(opad,  sizeof opad);
    crypto_memzero(inner, sizeof inner);
}

/* -------------------------------------------------------------------------
 * HOTP (RFC 4226 §5.3)
 * ---------------------------------------------------------------------- */

uint32_t hotp_code(const uint8_t *seed, size_t seed_len, uint64_t counter)
{
    uint8_t counter_be[8];
    for (int i = 7; i >= 0; i--) {
        counter_be[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }

    uint8_t mac[20];
    hmac_sha1(seed, seed_len, counter_be, 8, mac);

    int offset = mac[19] & 0x0F;
    uint32_t code = ((uint32_t)(mac[offset]   & 0x7F) << 24)
                  | ((uint32_t)(mac[offset+1] & 0xFF) << 16)
                  | ((uint32_t)(mac[offset+2] & 0xFF) <<  8)
                  | ((uint32_t)(mac[offset+3] & 0xFF));
    return code % 1000000;
}

/* -------------------------------------------------------------------------
 * TOTP (RFC 6238)
 * ---------------------------------------------------------------------- */

uint32_t totp_code(const uint8_t *seed, size_t seed_len, time_t now)
{
    if (now == 0) now = time(NULL);
    uint64_t step = (uint64_t)now / 30;
    return hotp_code(seed, seed_len, step);
}

/* -------------------------------------------------------------------------
 * Base32 (RFC 4648 §6, uppercase, no padding)
 * ---------------------------------------------------------------------- */

static const char b32_alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int base32_encode(const uint8_t *data, size_t len, char *out, size_t out_max)
{
    size_t bits = 0, val = 0, out_len = 0;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (out_len + 1 >= out_max) return -1;
            out[out_len++] = b32_alpha[(val >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        if (out_len + 1 >= out_max) return -1;
        out[out_len++] = b32_alpha[(val << (5 - bits)) & 0x1F];
    }
    out[out_len] = '\0';
    return (int)out_len;
}

/* -------------------------------------------------------------------------
 * OTP key file I/O
 * ---------------------------------------------------------------------- */

static int hex_decode(const char *hex, uint8_t *out, size_t max, size_t *out_len)
{
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t n = hlen / 2;
    if (n > max) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    *out_len = n;
    return 0;
}

static void hex_encode(const uint8_t *data, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i*2, "%02x", data[i]);
    }
    out[len*2] = '\0';
}

int otp_key_load(const char *path, otp_key_t *key)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    memset(key, 0, sizeof(*key));
    key->window = 20;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *val = colon + 1;
        while (*val == ' ') val++;
        size_t vlen = strlen(val);
        if (vlen > 0 && val[vlen-1] == '\n') val[--vlen] = '\0';

        if (strcmp(line, "type") == 0) {
            if (strcmp(val, "hotp") == 0) key->type = OTP_TYPE_HOTP;
            else if (strcmp(val, "totp") == 0) key->type = OTP_TYPE_TOTP;
            else { fclose(f); return -1; }
        } else if (strcmp(line, "seed") == 0) {
            if (hex_decode(val, key->seed, sizeof(key->seed), &key->seed_len) != 0) {
                fclose(f); return -1;
            }
        } else if (strcmp(line, "counter") == 0) {
            key->counter = (uint64_t)strtoull(val, NULL, 10);
        } else if (strcmp(line, "window") == 0) {
            key->window = atoi(val);
            if (key->window < 0) key->window = 0;
        } else if (strcmp(line, "last_totp_step") == 0) {
            key->last_totp_step = (int64_t)strtoll(val, NULL, 10);
        }
    }
    fclose(f);

    if (key->type == 0 || key->seed_len == 0) return -1;
    return 0;
}

int otp_key_save(const char *path, const otp_key_t *key)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;

    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return -1; }

    char hex_seed[41];
    hex_encode(key->seed, key->seed_len, hex_seed);

    fprintf(f, "# URTB OTP key file\n");
    fprintf(f, "type: %s\n", key->type == OTP_TYPE_HOTP ? "hotp" : "totp");
    fprintf(f, "seed: %s\n", hex_seed);
    if (key->type == OTP_TYPE_HOTP)
        fprintf(f, "counter: %llu\n", (unsigned long long)key->counter);
    if (key->type == OTP_TYPE_TOTP && key->last_totp_step > 0)
        fprintf(f, "last_totp_step: %lld\n", (long long)key->last_totp_step);
    fprintf(f, "window: %d\n", key->window);

    if (fflush(f) != 0 || fsync(fd) != 0) {
        fclose(f); unlink(tmp); return -1;
    }
    fclose(f);

    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * OTP verification
 * ---------------------------------------------------------------------- */

int otp_verify(const char *path, const char *code_str)
{
    if (strlen(code_str) != 6) return -1;
    for (int i = 0; i < 6; i++) {
        if (!isdigit((unsigned char)code_str[i])) return -1;
    }

    otp_key_t key;
    if (otp_key_load(path, &key) != 0) return -1;

    uint32_t user_code = (uint32_t)strtoul(code_str, NULL, 10);

    if (key.type == OTP_TYPE_HOTP) {
        for (int i = 0; i <= key.window; i++) {
            uint32_t expected = hotp_code(key.seed, key.seed_len,
                                          key.counter + (uint64_t)i);
            if (user_code == expected) {
                key.counter = key.counter + (uint64_t)i + 1;
                int rc = otp_key_save(path, &key);
                crypto_memzero(&key, sizeof key);
                return rc == 0 ? 0 : -1;
            }
        }
        crypto_memzero(&key, sizeof key);
        return -1;
    } else {
        time_t now = time(NULL);
        for (int i = -key.window; i <= key.window; i++) {
            time_t t = now + i * 30;
            int64_t step = (int64_t)(t / 30);
            uint32_t expected = totp_code(key.seed, key.seed_len, t);
            if (user_code == expected) {
                if (step <= key.last_totp_step) {
                    crypto_memzero(&key, sizeof key);
                    return -1;
                }
                key.last_totp_step = step;
                int rc = otp_key_save(path, &key);
                crypto_memzero(&key, sizeof key);
                return rc == 0 ? 0 : -1;
            }
        }
        crypto_memzero(&key, sizeof key);
        return -1;
    }
}

int otp_verify_mem(otp_key_t *key, const char *code_str)
{
    if (strlen(code_str) != 6) return -1;
    for (int i = 0; i < 6; i++) {
        if (!isdigit((unsigned char)code_str[i])) return -1;
    }

    uint32_t user_code = (uint32_t)strtoul(code_str, NULL, 10);

    if (key->type == OTP_TYPE_HOTP) {
        for (int i = 0; i <= key->window; i++) {
            uint32_t expected = hotp_code(key->seed, key->seed_len,
                                          key->counter + (uint64_t)i);
            if (user_code == expected) {
                key->counter = key->counter + (uint64_t)i + 1;
                return 0;
            }
        }
        return -1;
    } else {
        time_t now = time(NULL);
        for (int i = -key->window; i <= key->window; i++) {
            time_t t = now + i * 30;
            int64_t step = (int64_t)(t / 30);
            uint32_t expected = totp_code(key->seed, key->seed_len, t);
            if (user_code == expected) {
                if (step <= key->last_totp_step) {
                    return -1;
                }
                key->last_totp_step = step;
                return 0;
            }
        }
        return -1;
    }
}

int otp_print_next(const char *path)
{
    otp_key_t key;
    if (otp_key_load(path, &key) != 0) return -1;

    uint32_t code;
    if (key.type == OTP_TYPE_HOTP)
        code = hotp_code(key.seed, key.seed_len, key.counter);
    else
        code = totp_code(key.seed, key.seed_len, 0);

    printf("%06u\n", code);
    crypto_memzero(&key, sizeof key);
    return 0;
}

#endif /* URTB_OTP */
