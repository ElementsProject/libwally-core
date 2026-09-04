/* MIT (BSD) license - see LICENSE file for details */
/* HMAC code adapted from the Bitcoin project's C++:
 *
 * src/crypto/hmac_sha512.cpp f914f1a746d7f91951c1da262a4a749dd3ebfa71
 * Copyright (c) 2014 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
 */
static void SHA_PRE(_mix)(struct SHA_T *sha, const unsigned char *pad,
                          const unsigned char *data, size_t data_len)
{
    struct SHA_PRE(_ctx) ctx;
    SHA_PRE(_init)(&ctx);
    SHA_PRE(_update)(&ctx, pad, SHA_BLOCK_LEN);
    SHA_PRE(_update)(&ctx, data, data_len);
    SHA_PRE(_done)(&ctx, sha);
    wally_clear(&ctx, sizeof(ctx));
}

void HMAC_FUNCTION(struct SHA_T *sha,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *msg, size_t msg_len)
{
    /* The key block doubles as the buffer for the inner hash result */
    union {
        unsigned char u8[SHA_BLOCK_LEN];
        struct SHA_T sha;
    } key_block;
    unsigned char ipad[SHA_BLOCK_LEN];
    unsigned char opad[SHA_BLOCK_LEN];
    size_t i;

    BUILD_ASSERT(sizeof(struct SHA_T) <= SHA_BLOCK_LEN);
    wally_clear(&key_block, sizeof(key_block));

    if (key_len <= SHA_BLOCK_LEN)
        memcpy(key_block.u8, key, key_len);
    else
        SHA_T(&key_block.sha, key, key_len);

    for (i = 0; i < SHA_BLOCK_LEN; ++i) {
        opad[i] = key_block.u8[i] ^ 0x5c;
        ipad[i] = key_block.u8[i] ^ 0x36;
    }

    SHA_PRE(_mix)(&key_block.sha, ipad, msg, msg_len);
    SHA_PRE(_mix)(sha, opad, key_block.u8, sizeof(*sha));
    wally_clear_3(&key_block, sizeof(key_block), ipad, sizeof(ipad), opad, sizeof(opad));
}

int WALLY_HMAC_FUNCTION(const unsigned char *key, size_t key_len,
                        const unsigned char *bytes, size_t bytes_len,
                        unsigned char *bytes_out, size_t len)
{
    struct SHA_T sha;
    bool aligned = alignment_ok(bytes_out, sizeof(sha.u.u8));
    struct SHA_T *sha_p = aligned ? (void *)bytes_out : (void*)&sha;

    if (!key || !key_len || !bytes || !bytes_len ||
        !bytes_out || len != sizeof(struct SHA_T))
        return WALLY_EINVAL;

    HMAC_FUNCTION(sha_p, key, key_len, bytes, bytes_len);
    if (!aligned) {
        memcpy(bytes_out, sha_p, sizeof(*sha_p));
        wally_clear(sha_p, sizeof(*sha_p));
    }
    return WALLY_OK;
}
