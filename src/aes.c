#include <include/wally_core.h>
#include <include/wally_crypto.h>
#include "internal.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "ctaes/ctaes.h"
#include "ctaes/ctaes.c"

#define ALL_OPS (AES_FLAG_ENCRYPT | AES_FLAG_DECRYPT)

static bool is_valid_key_len(size_t key_len)
{
    return key_len == AES_KEY_LEN_128 || key_len == AES_KEY_LEN_192 ||
           key_len == AES_KEY_LEN_256;
}

static bool are_valid_args(const unsigned char *key, size_t key_len,
                           const unsigned char *bytes_in,
                           unsigned char *bytes_out, size_t len)
{
    return key && is_valid_key_len(key_len) && bytes_in &&
           bytes_out && len && !(len % AES_BLOCK_LEN);
}

static void aes_enc(AES256_ctx *ctx,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *bytes_in, size_t len_in,
                    unsigned char *bytes_out)
{
    len_in /= AES_BLOCK_LEN;

    switch (key_len) {
    case AES_KEY_LEN_128:
        AES128_init((AES128_ctx *)ctx, key);
        AES128_encrypt((AES128_ctx *)ctx, len_in, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_192:
        AES192_init((AES192_ctx *)ctx, key);
        AES192_encrypt((AES192_ctx *)ctx, len_in, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_256:
        AES256_init(ctx, key);
        AES256_encrypt(ctx, len_in, bytes_out, bytes_in);
        break;
    }
}

static void aes_dec(AES256_ctx *ctx,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *bytes_in, size_t len_in,
                    unsigned char *bytes_out)
{
    len_in /= AES_BLOCK_LEN;

    switch (key_len) {
    case AES_KEY_LEN_128:
        AES128_init((AES128_ctx *)ctx, key);
        AES128_decrypt((AES128_ctx *)ctx, len_in, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_192:
        AES192_init((AES192_ctx *)ctx, key);
        AES192_decrypt((AES192_ctx *)ctx, len_in, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_256:
        AES256_init(ctx, key);
        AES256_decrypt(ctx, len_in, bytes_out, bytes_in);
        break;
    }
}

int wally_aes(const unsigned char *key, size_t key_len,
              const unsigned char *bytes_in, size_t len_in,
              uint32_t flags,
              unsigned char *bytes_out, size_t len)
{
    AES256_ctx ctx;

    if (!are_valid_args(key, key_len, bytes_in, bytes_out, len) ||
        !len_in || len_in % AES_BLOCK_LEN ||
        flags & ~ALL_OPS || (flags & ALL_OPS) == ALL_OPS)
        return WALLY_EINVAL;

    if (flags & AES_FLAG_ENCRYPT)
        aes_enc(&ctx, key, key_len, bytes_in, len_in, bytes_out);
    else
        aes_dec(&ctx, key, key_len, bytes_in, len_in, bytes_out);

    clear(&ctx, sizeof(ctx));
    return WALLY_OK;
}

int wally_aes_cbc(const unsigned char *key, size_t key_len,
                  const unsigned char *iv, size_t iv_len,
                  const unsigned char *bytes_in, size_t len_in,
                  uint32_t flags,
                  unsigned char *bytes_out, size_t len)
{
    unsigned char buf[AES_BLOCK_LEN];
    AES256_ctx ctx;
    size_t i, n, blocks;
    unsigned char remainder;

    if (!are_valid_args(key, key_len, bytes_in, bytes_out, len) ||
        !iv || iv_len != AES_BLOCK_LEN ||
        flags & ~ALL_OPS || (flags & ALL_OPS) == ALL_OPS)
        return WALLY_EINVAL;

    blocks = len_in / AES_BLOCK_LEN;
    if (len < (blocks + 1) * AES_BLOCK_LEN)
        return WALLY_EINVAL;

    for (i = 0; i < blocks; ++i) {
        for (n = 0; n < AES_BLOCK_LEN; ++n)
            buf[n] = bytes_in[n] ^ iv[n];
        aes_enc(&ctx, key, key_len, buf, AES_BLOCK_LEN, bytes_out);
        iv = bytes_out;
        bytes_in += AES_BLOCK_LEN;
        bytes_out += AES_BLOCK_LEN;
    }

    remainder = len_in % AES_BLOCK_LEN;
    for (n = 0; n < remainder; ++n)
        buf[n] = bytes_in[n] ^ iv[n];
    remainder = 16 - remainder;
    for (; n < AES_BLOCK_LEN; ++n)
        buf[n] = remainder ^ iv[n];
    aes_enc(&ctx, key, key_len, buf, AES_BLOCK_LEN, bytes_out);

    clear_n(2, buf, sizeof(buf), &ctx, sizeof(ctx));
    return WALLY_OK;
}
