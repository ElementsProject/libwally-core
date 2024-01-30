#include "internal.h"
#include <include/wally_crypto.h>

#include "ccan/ccan/build_assert/build_assert.h"
#include "ctaes/ctaes.h"
#include "ctaes/ctaes.c"

#define ALL_OPS (AES_FLAG_ENCRYPT | AES_FLAG_DECRYPT)

static bool is_valid_key_len(size_t key_len)
{
    return key_len == AES_KEY_LEN_128 || key_len == AES_KEY_LEN_192 ||
           key_len == AES_KEY_LEN_256;
}

static bool are_valid_args(const unsigned char *key, size_t key_len,
                           const unsigned char *bytes, size_t bytes_len, uint32_t flags)
{
    return key && is_valid_key_len(key_len) &&
           (bytes != NULL || (bytes == NULL && bytes_len == 0 && (flags & AES_FLAG_ENCRYPT))) &&
           (flags == AES_FLAG_ENCRYPT || flags == AES_FLAG_DECRYPT);
}

static void aes_enc(AES256_ctx *ctx,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *bytes, size_t bytes_len,
                    unsigned char *bytes_out)
{
    bytes_len /= AES_BLOCK_LEN;

    switch (key_len) {
    case AES_KEY_LEN_128:
        AES128_init((AES128_ctx *)ctx, key);
        AES128_encrypt((AES128_ctx *)ctx, bytes_len, bytes_out, bytes);
        break;

    case AES_KEY_LEN_192:
        AES192_init((AES192_ctx *)ctx, key);
        AES192_encrypt((AES192_ctx *)ctx, bytes_len, bytes_out, bytes);
        break;

    case AES_KEY_LEN_256:
        AES256_init(ctx, key);
        AES256_encrypt(ctx, bytes_len, bytes_out, bytes);
        break;
    }
}

static void aes_dec(AES256_ctx *ctx,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *bytes, size_t bytes_len,
                    unsigned char *bytes_out)
{
    bytes_len /= AES_BLOCK_LEN;

    switch (key_len) {
    case AES_KEY_LEN_128:
        AES128_init((AES128_ctx *)ctx, key);
        AES128_decrypt((AES128_ctx *)ctx, bytes_len, bytes_out, bytes);
        break;

    case AES_KEY_LEN_192:
        AES192_init((AES192_ctx *)ctx, key);
        AES192_decrypt((AES192_ctx *)ctx, bytes_len, bytes_out, bytes);
        break;

    case AES_KEY_LEN_256:
        AES256_init(ctx, key);
        AES256_decrypt(ctx, bytes_len, bytes_out, bytes);
        break;
    }
}

int wally_aes_len(const unsigned char *key, size_t key_len,
                  const unsigned char *bytes, size_t bytes_len,
                  uint32_t flags, size_t *written)
{
    if (written)
        *written = 0;
    if (!are_valid_args(key, key_len, bytes, bytes_len, flags) ||
        !bytes_len || bytes_len % AES_BLOCK_LEN || !written)
        return WALLY_EINVAL;
    *written = bytes_len;
    return WALLY_OK;
}

int wally_aes(const unsigned char *key, size_t key_len,
              const unsigned char *bytes, size_t bytes_len,
              uint32_t flags,
              unsigned char *bytes_out, size_t len)
{
    AES256_ctx ctx;

    if (!are_valid_args(key, key_len, bytes, bytes_len, flags) ||
        len % AES_BLOCK_LEN || !bytes_len || bytes_len % AES_BLOCK_LEN ||
        !bytes_out || !len)
        return WALLY_EINVAL;

    if (flags & AES_FLAG_ENCRYPT)
        aes_enc(&ctx, key, key_len, bytes, bytes_len, bytes_out);
    else
        aes_dec(&ctx, key, key_len, bytes, bytes_len, bytes_out);

    wally_clear(&ctx, sizeof(ctx));
    return WALLY_OK;
}

int wally_aes_cbc_get_maximum_length(const unsigned char *key, size_t key_len,
                                     const unsigned char *iv, size_t iv_len,
                                     const unsigned char *bytes, size_t bytes_len,
                                     uint32_t flags,
                                     size_t *written)
{
    if (written)
        *written = 0;

    if (!are_valid_args(key, key_len, bytes, bytes_len, flags) ||
        ((flags & AES_FLAG_DECRYPT) && (bytes_len % AES_BLOCK_LEN)) ||
        !iv || iv_len != AES_BLOCK_LEN || !written)
        return WALLY_EINVAL;

    *written = ((bytes_len / AES_BLOCK_LEN) + 1) * AES_BLOCK_LEN;
    return WALLY_OK;
}

int wally_aes_cbc(const unsigned char *key, size_t key_len,
                  const unsigned char *iv, size_t iv_len,
                  const unsigned char *bytes, size_t bytes_len,
                  uint32_t flags,
                  unsigned char *bytes_out, size_t len,
                  size_t *written)
{
    unsigned char buf[AES_BLOCK_LEN];
    AES256_ctx ctx;
    size_t i, n, blocks;
    unsigned char remainder;

    if (written)
        *written = 0;

    if (!are_valid_args(key, key_len, bytes, bytes_len, flags) ||
        ((flags & AES_FLAG_ENCRYPT) && (len % AES_BLOCK_LEN)) ||
        ((flags & AES_FLAG_DECRYPT) && (bytes_len % AES_BLOCK_LEN)) ||
        !iv || iv_len != AES_BLOCK_LEN || !written)
        return WALLY_EINVAL;

    blocks = bytes_len / AES_BLOCK_LEN;

    if (flags & AES_FLAG_ENCRYPT) {
        /* Determine output length from input length */
        remainder = bytes_len % AES_BLOCK_LEN;
        *written = (blocks + 1) * AES_BLOCK_LEN;
    } else {
        /* Determine output length from decrypted final block */
        const unsigned char *last = bytes + bytes_len - AES_BLOCK_LEN;
        const unsigned char *prev = last - AES_BLOCK_LEN;

        if (!--blocks)
            prev = iv;
        aes_dec(&ctx, key, key_len, last, AES_BLOCK_LEN, buf);
        for (n = 0; n < AES_BLOCK_LEN; ++n)
            buf[n] = prev[n] ^ buf[n];

        /* Modulo the resulting padding amount to the block size - we do
         * not attempt to verify the decryption by checking the padding in
         * the decrypted block. */
        remainder = AES_BLOCK_LEN - (buf[AES_BLOCK_LEN - 1] % AES_BLOCK_LEN);
        if (remainder == AES_BLOCK_LEN)
            remainder = 0;
        *written = blocks * AES_BLOCK_LEN + remainder;
    }
    if (len < *written || !*written)
        goto finish; /* Inform caller how much space is needed */

    if (!bytes_out) {
        wally_clear_2(buf, sizeof(buf), &ctx, sizeof(ctx));
        return WALLY_EINVAL;
    }

    if (flags & AES_FLAG_DECRYPT)
        memcpy(bytes_out + blocks * AES_BLOCK_LEN, buf, remainder);

    for (i = 0; i < blocks; ++i) {
        if (flags & AES_FLAG_ENCRYPT) {
            for (n = 0; n < AES_BLOCK_LEN; ++n)
                buf[n] = bytes[n] ^ iv[n];
            aes_enc(&ctx, key, key_len, buf, AES_BLOCK_LEN, bytes_out);
            iv = bytes_out;
        } else {
            aes_dec(&ctx, key, key_len, bytes, AES_BLOCK_LEN, bytes_out);
            for (n = 0; n < AES_BLOCK_LEN; ++n)
                bytes_out[n] = bytes_out[n] ^ iv[n];
            iv = bytes;
        }
        bytes += AES_BLOCK_LEN;
        bytes_out += AES_BLOCK_LEN;
    }

    if (flags & AES_FLAG_ENCRYPT) {
        for (n = 0; n < remainder; ++n)
            buf[n] = bytes[n] ^ iv[n];
        remainder = 16 - remainder;
        for (; n < AES_BLOCK_LEN; ++n)
            buf[n] = remainder ^ iv[n];
        aes_enc(&ctx, key, key_len, buf, AES_BLOCK_LEN, bytes_out);
    }

finish:
    wally_clear_2(buf, sizeof(buf), &ctx, sizeof(ctx));
    return WALLY_OK;
}

int wally_aes_cbc_with_ecdh_key_get_maximum_length(
    const unsigned char *priv_key, size_t priv_key_len,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *bytes, size_t bytes_len,
    const unsigned char *pub_key, size_t pub_key_len,
    const unsigned char *label, size_t label_len, uint32_t flags,
    size_t *written)
{
    if (written)
        *written = 0;

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN || !bytes ||
        !pub_key || pub_key_len != EC_PUBLIC_KEY_LEN || !label || !label_len ||
        (flags != AES_FLAG_ENCRYPT && flags != AES_FLAG_DECRYPT) || !written)
        return WALLY_EINVAL;

    if (flags & AES_FLAG_ENCRYPT) {
        /* Must provide IV + minimum 1 byte of payload for encryption */
        if (!iv || iv_len != AES_BLOCK_LEN || !bytes_len)
            return WALLY_EINVAL;
        /* Output is IV + encrypted payload + HMAC */
        *written = AES_BLOCK_LEN + HMAC_SHA256_LEN
                   + ((bytes_len / AES_BLOCK_LEN) + 1) * AES_BLOCK_LEN;
    } else {
        /* Must not provide an IV for decryption */
        if (iv || iv_len)
            return WALLY_EINVAL;
         /* Payload must contain IV, payload and the HMAC for decryption */
        if (bytes_len < AES_BLOCK_LEN + AES_BLOCK_LEN + HMAC_SHA256_LEN)
            return WALLY_EINVAL;
        /* Output is the decrypted payload without the IV and HMAC */
        bytes_len = bytes_len - AES_BLOCK_LEN - HMAC_SHA256_LEN;
        if (bytes_len % AES_BLOCK_LEN)
            return WALLY_EINVAL; /* Payload isn't a block size multiple */
        /* Actual bytes written may be less due to padding, but the
         * caller must pass a buffer of the padded size. */
        *written = bytes_len;
    }
    return WALLY_OK;
}

int wally_aes_cbc_with_ecdh_key(
    const unsigned char *priv_key, size_t priv_key_len,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *bytes, size_t bytes_len,
    const unsigned char *pub_key, size_t pub_key_len,
    const unsigned char *label, size_t label_len, uint32_t flags,
    unsigned char *bytes_out, size_t len, size_t *written)
{
    unsigned char secret[SHA256_LEN], keys[HMAC_SHA512_LEN];
    const unsigned char *enc_key = keys, *hmac_key = keys + AES_KEY_LEN_256;
    size_t expected_len;
    const bool is_encrypt = flags & AES_FLAG_ENCRYPT;
    int ret;

    /* Derived key sizes must match the derived keys buffer */
    BUILD_ASSERT(sizeof(keys) == AES_KEY_LEN_256 + SHA256_LEN);

    if (written)
        *written = 0;

    if (!bytes_out || !len || !written)
        return WALLY_EINVAL;
    ret = wally_aes_cbc_with_ecdh_key_get_maximum_length(
                  priv_key, priv_key_len, iv, iv_len, bytes, bytes_len,
                  pub_key, pub_key_len, label, label_len, flags,
                  &expected_len);
    if (ret == WALLY_OK && expected_len > len) {
        *written = expected_len;
        return ret; /* Tell the caller how much space is needed */
    }
    if (ret != WALLY_OK)
        return ret;

    if (is_encrypt) {
        /* Copy the IV to the start of the encrypted output */
        memcpy(bytes_out, iv, iv_len);
    } else {
        /* The IV is the first AES_BLOCK_LEN bytes of the payload */
        iv = bytes;
        iv_len = AES_BLOCK_LEN;
    }

    /* Shared secret is ECDH(their pubkey, our private key) */
    ret = wally_ecdh(pub_key, pub_key_len, priv_key, priv_key_len,
                     secret, sizeof(secret));
    /* Generate encryption/HMAC keys using the shared secret and label */
    if (ret == WALLY_OK)
        ret = wally_hmac_sha512(secret, sizeof(secret), label, label_len, keys, sizeof(keys));
    if (ret == WALLY_OK && !is_encrypt) {
        /* Verify the IV + encrypted data's HMAC */
        unsigned char hmac[HMAC_SHA256_LEN];
        ret = wally_hmac_sha256(hmac_key, SHA256_LEN,
                                bytes, bytes_len - sizeof(hmac),
                                hmac, sizeof(hmac));
        if (ret == WALLY_OK &&
            memcmp(hmac, bytes + bytes_len - sizeof(hmac), sizeof(hmac)))
            ret = WALLY_EINVAL; /* Invalid HMAC */
    }

    /* Encrypt/decrypt the payload */
    if (ret == WALLY_OK) {
        /* Trim our output length to a block size multiple for aes_cbc */
        size_t out_len = (len - (is_encrypt ? (iv_len + HMAC_SHA256_LEN) : 0)) & ~((size_t)0xf);
        if (is_encrypt)
            ret = wally_aes_cbc(enc_key, AES_KEY_LEN_256, iv, iv_len,
                                bytes, bytes_len, flags,
                                bytes_out + iv_len, out_len, written);
        else
            ret = wally_aes_cbc(enc_key, AES_KEY_LEN_256, iv, iv_len,
                                bytes + iv_len, bytes_len - iv_len - HMAC_SHA256_LEN,
                                flags, bytes_out, out_len, written);
    }

    if (ret == WALLY_OK && is_encrypt) {
        /* append the HMAC of the IV + encrypted data */
        *written += AES_BLOCK_LEN; /* Include the IV */
        ret = wally_hmac_sha256(hmac_key, SHA256_LEN,
                                bytes_out, *written,
                                bytes_out + *written, HMAC_SHA256_LEN);
        *written = ret == WALLY_OK ? *written + HMAC_SHA256_LEN : 0;
    }

    if (ret == WALLY_OK && *written > expected_len)
        ret = WALLY_ERROR; /* Should never happen! */
    wally_clear_2(secret, sizeof(secret), keys, sizeof(keys));
    return ret;
}
