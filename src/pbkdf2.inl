/*
 * This is a heavily modified version of openBSDs pkcs5_pbkdf2 from
 * libutil/pkcs5_pbkdf2.c, whose copyright appears here:
 *
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

int SHA_POST(pbkdf2_hmac_)(const unsigned char *pass, size_t pass_len,
                           unsigned char *salt, size_t salt_len,
                           size_t cost,
                           unsigned char *bytes_out, size_t len)
{
    struct SHA_T d1, d2, *sha_cp = &d2;
    size_t n, c, j;

    BUILD_ASSERT(sizeof(beint32_t) == PBKDF2_SALT_BYTES);
    BUILD_ASSERT(sizeof(d1) == PBKDF2_HMAC_SHA_LEN);

    if (salt_len <= PBKDF2_SALT_BYTES)
        return -1;

    if (!len || len % PBKDF2_HMAC_SHA_LEN)
        return -1;

    /* If bytes out is suitably aligned, we can work on it directly */
    if (alignment_ok(bytes_out, sizeof(SHA_ALIGN_T)))
        sha_cp = (struct SHA_T *)bytes_out;

    for (n = 0; n < len / PBKDF2_HMAC_SHA_LEN; ++n) {
        beint32_t block = cpu_to_be32(n + 1); /* Block number */

        memcpy(salt + salt_len - sizeof(block), &block, sizeof(block));
        SHA_POST(hmac_)(&d1, pass, pass_len, salt, salt_len);
        memcpy(sha_cp, &d1, sizeof(d1));

        for (c = 0; cost && c < cost - 1; ++c) {
            SHA_POST(hmac_)(&d1, pass, pass_len, d1.u.u8, sizeof(d1));
            for (j = 0; j < sizeof(d1.u.SHA_MEM)/sizeof(d1.u.SHA_MEM[0]); ++j)
                sha_cp->u.SHA_MEM[j] ^= d1.u.SHA_MEM[j];
        }
        if (sha_cp == &d2)
            memcpy(bytes_out, sha_cp, sizeof(*sha_cp));
        else
            ++sha_cp;

        bytes_out += PBKDF2_HMAC_SHA_LEN;
    }

    clear_n(2, &d1, sizeof(d1), &d2, sizeof(d2));
    return 0;
}
