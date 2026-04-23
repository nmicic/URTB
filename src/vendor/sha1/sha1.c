/* SHA1 — public domain. Original by Steve Reid, 1991.
 * Source: RFC 3174 sample implementation (adapted from the original
 * Steve Reid implementation widely distributed since 1991).
 * No copyright claimed. Used as-is with no modifications beyond
 * style normalisation to match URTB coding conventions (stdint types,
 * static helpers, explicit padding). Algorithm unchanged. */

#include "sha1.h"
#include <string.h>

static uint32_t rol(uint32_t v, int bits)
{
    return (v << bits) | (v >> (32 - bits));
}

static void sha1_transform(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4]     << 24)
             | ((uint32_t)block[i*4 + 1] << 16)
             | ((uint32_t)block[i*4 + 2] <<  8)
             | ((uint32_t)block[i*4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    uint32_t a = state[0], b = state[1], c = state[2],
             d = state[3], e = state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t tmp = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = tmp;
    }

    state[0] += a; state[1] += b; state[2] += c;
    state[3] += d; state[4] += e;
}

void sha1_init(sha1_ctx *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t idx = (size_t)(ctx->count % 64);
    ctx->count += len;

    size_t i = 0;
    if (idx) {
        size_t fill = 64 - idx;
        if (len < fill) {
            memcpy(ctx->buf + idx, data, len);
            return;
        }
        memcpy(ctx->buf + idx, data, fill);
        sha1_transform(ctx->state, ctx->buf);
        i = fill;
    }
    for (; i + 64 <= len; i += 64) {
        sha1_transform(ctx->state, data + i);
    }
    if (i < len) {
        memcpy(ctx->buf, data + i, len - i);
    }
}

void sha1_final(sha1_ctx *ctx, uint8_t digest[20])
{
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);

    uint8_t zero = 0;
    while (ctx->count % 64 != 56) {
        sha1_update(ctx, &zero, 1);
    }

    uint8_t len_be[8];
    for (int i = 7; i >= 0; i--) {
        len_be[i] = (uint8_t)(bits & 0xFF);
        bits >>= 8;
    }
    sha1_update(ctx, len_be, 8);

    for (int i = 0; i < 5; i++) {
        digest[i*4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        digest[i*4 + 3] = (uint8_t)(ctx->state[i]);
    }
}
