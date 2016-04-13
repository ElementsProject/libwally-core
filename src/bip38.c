#include <include/wally-core.h>
#include <include/wally_bip38.h>
#include "internal.h"
#include "base58.h"
#include "scrypt.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/endian/endian.h"
#include "ccan/ccan/build_assert/build_assert.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "ctaes/ctaes.h"
#include "ctaes/ctaes.c"

#define BIP38_FLAG_DEFAULT   (0x40 | 0x80)
#define BIP38_FLAG_COMPRESSED 0x20
#define BIP38_FLAG_RESERVED1  0x10
#define BIP38_FLAG_RESERVED2  0x08
#define BIP38_FLAG_HAVE_LOT   0x04
#define BIP38_FLAG_RESERVED3  0x02
#define BIP38_FLAG_RESERVED4  0x01
#define BIP38_FLAGS_RESERVED (BIP38_FLAG_RESERVED1 | BIP38_FLAG_RESERVED2 | \
                              BIP38_FLAG_RESERVED3 | BIP38_FLAG_RESERVED4)

#define BITCOIN_PRIVATE_KEY_LEN 32
#define BIP38_DERVIED_KEY_LEN 64u
#define AES256_BLOCK_LEN 16u

#define BIP38_PREFIX   0x01
#define BIP38_ECMUL    0x43
#define BIP38_NO_ECMUL 0x42

struct derived_t {
    unsigned char half1_lo[BIP38_DERVIED_KEY_LEN / 4];
    unsigned char half1_hi[BIP38_DERVIED_KEY_LEN / 4];
    unsigned char half2[BIP38_DERVIED_KEY_LEN / 2];
};

struct bip38_layout_t {
    unsigned char pad1;
    unsigned char prefix;
    unsigned char ec_type;
    unsigned char flags;
    uint32_t hash;
    unsigned char half1[AES256_BLOCK_LEN];
    unsigned char half2[AES256_BLOCK_LEN];
};

/* Check assumptions we expect to hold true */
static void assert_assumptions(void)
{
    /* derived_t/bip38_layout_t must be contiguous */
    BUILD_ASSERT(sizeof(struct derived_t) == BIP38_DERVIED_KEY_LEN);
    BUILD_ASSERT(sizeof(struct bip38_layout_t) == 40u); /* 39 + pad1 */
}

/* FIXME: Share this with key_compute_pub_key in bip32.c */
static int compute_pub_key(const unsigned char *priv_key, size_t priv_len,
                           unsigned char *pub_key_out, bool compressed)
{
    secp256k1_pubkey pk;
    const secp256k1_context *ctx = secp_ctx();
    unsigned int flags = compressed ? PUBKEY_COMPRESSED : PUBKEY_UNCOMPRESSED;
    size_t len = compressed ? 33 : 65;
    int ret = priv_len == BITCOIN_PRIVATE_KEY_LEN &&
              pubkey_create(ctx, &pk, priv_key) &&
              pubkey_serialize(ctx, pub_key_out, &len, &pk, flags) ? 0 : -1;
    clear(&pk, sizeof(pk));
    return ret;
}


/* FIXME: Export this with other address functions */
static int address_from_private_key(const unsigned char *priv_key,
                                    size_t priv_len,
                                    unsigned char network,
                                    bool compressed,
                                    char **output)
{
    struct sha256 sha;
    unsigned char pub_key[65];
    struct
    {
        unsigned char pad1[3];
        unsigned char network;
        struct ripemd160 hash160;
        uint32_t checksum;
    } buf;
    int ret;

    BUILD_ASSERT(&buf.network + 1 == (void *)&buf.hash160);

    if (compute_pub_key(priv_key, priv_len, pub_key, compressed))
        return -1;

    sha256(&sha, pub_key, compressed ? 33 : 65);
    ripemd160(&buf.hash160, &sha, sizeof(sha));
    buf.network = network;
    buf.checksum = base58_get_checksum(&buf.network, 1 + 20);
    ret = base58_from_bytes(&buf.network, 1 + 20 + 4, 0, output);
    clear_n(3, &sha, sizeof(sha), pub_key, sizeof(pub_key), &buf, sizeof(buf));
    return ret;
}

static void aes_enc(const unsigned char *src, const unsigned char *xor,
                    const unsigned char *key, unsigned char *bytes_out)
{
    uint32_t plaintext[AES256_BLOCK_LEN / sizeof(uint32_t)];
    AES256_ctx ctx;
    size_t i;

    for (i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); ++i)
        plaintext[i] = ((uint32_t *)src)[i] ^ ((uint32_t *)xor)[i];

    AES256_init(&ctx, key);
    AES256_encrypt(&ctx, 1, bytes_out, (unsigned char *)plaintext);
    clear_n(2, plaintext, sizeof(plaintext), &ctx, sizeof(ctx));
}

int bip38_from_private_key(const unsigned char *priv_key, size_t len,
                           const unsigned char *password, size_t password_len,
                           unsigned char network, bool compressed,
                           char **output)
{
    struct derived_t derived;
    struct bip38_layout_t buf;
    char *addr58 = NULL;
    int ret = -1;

    *output = NULL;

    if (address_from_private_key(priv_key, len, network, compressed, &addr58))
        goto finish;

    buf.hash = base58_get_checksum((unsigned char *)addr58, strlen(addr58));
    if (scrypt(password, password_len,
               (unsigned char *)&buf.hash, sizeof(buf.hash), 16384, 8, 8,
               (unsigned char *)&derived, sizeof(derived)))
        goto finish;

    buf.prefix = BIP38_PREFIX;
    buf.ec_type = BIP38_NO_ECMUL; /* FIXME: EC-Multiply support */
    buf.flags = BIP38_FLAG_DEFAULT | (compressed ? BIP38_FLAG_COMPRESSED : 0);
    aes_enc(priv_key + 0, derived.half1_lo, derived.half2, buf.half1);
    aes_enc(priv_key + 16, derived.half1_hi, derived.half2, buf.half2);
    ret = base58_from_bytes(&buf.prefix, sizeof(buf) - 1,
                            BASE58_FLAG_CHECKSUM, output);
finish:
    wally_free_string(addr58);
    clear_n(2, &derived, sizeof(derived), &buf, sizeof(buf));
    return ret;
}
