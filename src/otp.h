/*
 * otp.h — HOTP/TOTP OTP interface
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef URTB_OTP_H
#define URTB_OTP_H

#if URTB_OTP

#include <stdint.h>
#include <stddef.h>
#include <time.h>

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *msg, size_t msg_len,
               uint8_t mac[20]);

uint32_t hotp_code(const uint8_t *seed, size_t seed_len, uint64_t counter);

uint32_t totp_code(const uint8_t *seed, size_t seed_len, time_t now);

int base32_encode(const uint8_t *data, size_t len, char *out, size_t out_max);

#define OTP_TYPE_HOTP 1
#define OTP_TYPE_TOTP 2

typedef struct {
    int      type;        /* OTP_TYPE_HOTP or OTP_TYPE_TOTP */
    uint8_t  seed[20];
    size_t   seed_len;
    uint64_t counter;       /* HOTP only */
    int      window;
    int64_t  last_totp_step; /* TOTP only: last accepted step (t/30); 0 = none */
} otp_key_t;

int  otp_key_load(const char *path, otp_key_t *key);
int  otp_key_save(const char *path, const otp_key_t *key);
int  otp_verify(const char *path, const char *code_str);
int  otp_verify_mem(otp_key_t *key, const char *code_str);
int  otp_print_next(const char *path);

#endif /* URTB_OTP */
#endif /* URTB_OTP_H */
