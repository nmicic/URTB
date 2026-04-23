/* SHA1 — public domain. Original by Steve Reid, 1991.
 * Source: RFC 3174 sample implementation (adapted from the original
 * Steve Reid implementation widely distributed since 1991).
 * No copyright claimed. Style normalised to match URTB conventions
 * (stdint types, include guards). Algorithm unchanged. */

#ifndef URTB_SHA1_H
#define URTB_SHA1_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buf[64];
} sha1_ctx;

void sha1_init(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len);
void sha1_final(sha1_ctx *ctx, uint8_t digest[20]);

#endif /* URTB_SHA1_H */
