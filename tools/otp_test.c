/*
 * otp_test.c — RFC 4226 + RFC 6238 test vectors for HOTP/TOTP
 *
 * All vectors must pass before OTP integration into the session layer.
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "otp.h"

static int g_pass = 0, g_fail = 0;

#define CHECK(name, cond) do { \
    if (cond) { printf("PASS %s\n", name); g_pass++; } \
    else      { printf("FAIL %s\n", name); g_fail++; } \
} while(0)

/* RFC 4226 Appendix D — HOTP test vectors
 * Seed = "12345678901234567890" (20 bytes) */
static void test_hotp_vectors(void)
{
    const uint8_t seed[] = "12345678901234567890";
    const uint32_t expected[] = {
        755224, 287082, 359152, 969429, 338314,
        254676, 287922, 162583, 399871, 520489
    };

    for (int i = 0; i < 10; i++) {
        uint32_t got = hotp_code(seed, 20, (uint64_t)i);
        char name[64];
        snprintf(name, sizeof(name), "RFC4226 HOTP counter=%d (expect %06u, got %06u)",
                 i, expected[i], got);
        CHECK(name, got == expected[i]);
    }
}

/* RFC 6238 Appendix B — TOTP test vectors (SHA1, 8 digits)
 * Verify that our 6-digit code matches the last 6 digits of the 8-digit value.
 * Seed = "12345678901234567890" (20 bytes), period = 30s */
static void test_totp_vectors(void)
{
    const uint8_t seed[] = "12345678901234567890";
    struct { time_t t; uint32_t expected_8digit; } tests[] = {
        { 59,          94287082 },
        { 1111111109,   7081804 },
        { 1111111111,  14050471 },
        { 1234567890,  89005924 },
        { 2000000000,  69279037 },
    };
    /* Skip T=20000000000 — exceeds 32-bit time_t on some platforms */

    for (int i = 0; i < 5; i++) {
        uint32_t got = totp_code(seed, 20, tests[i].t);
        uint32_t expect_6 = tests[i].expected_8digit % 1000000;
        char name[128];
        snprintf(name, sizeof(name),
                 "RFC6238 TOTP T=%lld (expect %06u, got %06u)",
                 (long long)tests[i].t, expect_6, got);
        CHECK(name, got == expect_6);
    }
}

/* Base32 encoding test — verify the RFC 4226 seed encodes to the expected
 * value that authenticator apps would accept. */
static void test_base32(void)
{
    const uint8_t seed[] = "12345678901234567890";
    char out[64];
    int rc = base32_encode(seed, 20, out, sizeof(out));
    CHECK("base32 encode returns >0", rc > 0);
    /* "12345678901234567890" in Base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" */
    CHECK("base32 encode correct", strcmp(out, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") == 0);
}

/* HMAC-SHA1 basic test — RFC 2202 test case 1 */
static void test_hmac_sha1(void)
{
    /* Key = 0x0b repeated 20 times, Data = "Hi There" */
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const uint8_t data[] = "Hi There";
    uint8_t mac[20];
    hmac_sha1(key, 20, data, 8, mac);

    /* Expected: b617318655057264e28bc0b6fb378c8ef146be00 */
    const uint8_t expected[] = {
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
        0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
        0xf1, 0x46, 0xbe, 0x00
    };
    CHECK("HMAC-SHA1 RFC2202 test 1", memcmp(mac, expected, 20) == 0);
}

int main(void)
{
    printf("--- OTP test vectors ---\n");
    test_hmac_sha1();
    test_hotp_vectors();
    test_totp_vectors();
    test_base32();

    printf("\n%d tests, %d failed\n", g_pass + g_fail, g_fail);
    return g_fail ? 1 : 0;
}
