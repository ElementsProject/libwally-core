#include <include/wally_core.h>
#include <include/wally_crypto.h>
#include "internal.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "ctaes/ctaes.h"
#include "ctaes/ctaes.c"

int wally_aes(const unsigned char *key, size_t key_len,
              const unsigned char *bytes_in, size_t len_in,
              uint32_t flags,
              unsigned char *bytes_out, size_t len)
{
    const uint32_t all_ops = AES_FLAG_ENCRYPT | AES_FLAG_DECRYPT;
    AES256_ctx ctx256;
    AES128_ctx *ctx128 = (AES128_ctx *)&ctx256;
    AES192_ctx *ctx192 = (AES192_ctx *)&ctx256;

    if (!key || !bytes_in || !len_in || len_in % AES_BLOCK_LEN ||
        !bytes_out || !len || len % AES_BLOCK_LEN ||
        flags & ~all_ops || (flags & all_ops) == all_ops)
        return WALLY_EINVAL;

    switch (key_len) {
    case AES_KEY_LEN_128:
        AES128_init(ctx128, key);
        if (flags & AES_FLAG_ENCRYPT)
            AES128_encrypt(ctx128, len / AES_BLOCK_LEN, bytes_out, bytes_in);
        else
            AES128_decrypt(ctx128, len / AES_BLOCK_LEN, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_192:
        AES192_init(ctx192, key);
        if (flags & AES_FLAG_ENCRYPT)
            AES192_encrypt(ctx192, len / AES_BLOCK_LEN, bytes_out, bytes_in);
        else
            AES192_decrypt(ctx192, len / AES_BLOCK_LEN, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_256:
        AES256_init(&ctx256, key);
        if (flags & AES_FLAG_ENCRYPT)
            AES256_encrypt(&ctx256, len / AES_BLOCK_LEN, bytes_out, bytes_in);
        else
            AES256_decrypt(&ctx256, len / AES_BLOCK_LEN, bytes_out, bytes_in);
        break;

    default:
        return WALLY_EINVAL;
    }

    clear(&ctx256, sizeof(ctx256));
    return WALLY_OK;
}
