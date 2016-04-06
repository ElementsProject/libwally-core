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
#include <string.h>
#include "internal.h"
#include "hmac.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"


void pbkdf2_hmac_sha256(unsigned char *bytes_out,
                        const unsigned char *pass, size_t pass_len,
                        unsigned char *salt, size_t salt_len)
{
    /* FIXME */
}

void pbkdf2_hmac_sha512(unsigned char *bytes_out,
                        const unsigned char *pass, size_t pass_len,
                        unsigned char *salt, size_t salt_len)
{
    struct sha512 d1, d2;
    size_t i, j;

    salt[salt_len - 4] = 0;
    salt[salt_len - 3] = 0;
    salt[salt_len - 2] = 0;
    salt[salt_len - 1] = 1;

    hmac_sha512(&d1, pass, pass_len, salt, salt_len);
    memcpy(bytes_out, d1.u.u8, sizeof(d1));

    for (i = 1; i < 2048u; ++i) {
        hmac_sha512(&d2, pass, pass_len, d1.u.u8, sizeof(d1));
        d1 = d2;
        for (j = 0; j < sizeof(d1); ++j)
            bytes_out[j] ^= d1.u.u8[j];
    }
    clear_n(2, &d1, sizeof(d1), &d2, sizeof(d2));
}
