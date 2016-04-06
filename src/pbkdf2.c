/*
 * These are heavily modified versions of openBSDs pkcs5_pbkdf2 from
 * libutil/pkcs5_pbkdf2.c, whose copyright appears here:
 *
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */
#include <include/wally_bip39.h>
#include "pbkdf2.h"
#include "internal.h"
#include "hmac.h"
#include <string.h>
#include "ccan/ccan/endian/endian.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
#include "ccan/ccan/build_assert/build_assert.h"

/* https://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2 */
inline static int is_power_of_two(size_t n)
{
    return !(n & (n - 1));
}

int pbkdf2_hmac_sha512(const unsigned char *pass, size_t pass_len,
                       unsigned char *salt, size_t salt_len,
                       size_t cost,
                       unsigned char *bytes_out, size_t len)
{
    struct sha512 d1, d2;
    size_t n, c, j;

    BUILD_ASSERT(sizeof(beint32_t) == PBKDF2_SALT_BYTES);
    BUILD_ASSERT(sizeof(d1) == PBKDF2_HMAC_SHA512_LEN);

    if (salt_len <= PBKDF2_SALT_BYTES)
        return -1;

    if (!len || len % PBKDF2_HMAC_SHA512_LEN)
        return -1;

    if (cost < 1 || !is_power_of_two(cost))
        return -1;

    for (n = 0; n < len / PBKDF2_HMAC_SHA512_LEN; ++n) {
        beint32_t block = cpu_to_be32(n + 1); /* Block number */

        memcpy(salt + salt_len - sizeof(block), &block, sizeof(block));
        hmac_sha512(&d1, pass, pass_len, salt, salt_len);
        d2 = d1;

        for (c = 0; c < cost - 1; ++c) {
            hmac_sha512(&d1, pass, pass_len, d1.u.u8, sizeof(d1));
            for (j = 0; j < sizeof(d1); ++j)
                d2.u.u8[j] ^= d1.u.u8[j];
        }
        memcpy(bytes_out, d2.u.u8, sizeof(d2));
        bytes_out += PBKDF2_HMAC_SHA512_LEN;
    }

    clear_n(2, &d1, sizeof(d1), &d2, sizeof(d2));
    return 0;
}
