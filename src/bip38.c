/*#include <include/wally_bip38.h>*/
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


static int address_from_private_key(unsigned char *priv_key,
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
    ret = base58_from_bytes(&buf.network, 1 + 20 + 4,
                            BASE58_FLAG_CHECKSUM, output);
    clear_n(3, &sha, sizeof(sha), pub_key, sizeof(pub_key), &buf, sizeof(buf));
    return ret;
}

static void aes_inc(unsigned char *block_in_out, const unsigned char *xor,
                    const unsigned char *key, unsigned char *bytes_out)
{
    AES256_ctx ctx;
    size_t i;

    memset(bytes_out, 0, AES256_BLOCK_LEN);
    for (i = 0; i < AES256_BLOCK_LEN; ++i)
        block_in_out[i] ^= xor[i];

    AES256_init(&ctx, key);
    AES256_encrypt(&ctx, 1, bytes_out, block_in_out);
    clear(&ctx, sizeof(ctx));
}

int bip38_from_private_key(unsigned char *priv_key, size_t len,
                           const unsigned char *pass, size_t pass_len,
                           char **output)
{
    const size_t l16 = 0, r16 = AES256_BLOCK_LEN; /* halves of derivedhalf1 */
    const size_t half2 = AES256_BLOCK_LEN * 2; /* derivedhalf2 */
    const size_t addr_len = 1 + 20 + 4; /* network, hash160, checksum */
    const size_t prefix_len = 3 + sizeof(addr_len); /* 0x0142, flags, salt */
    unsigned char derived_key[BIP38_DERVIED_KEY_LEN];
    uint32_t addr_hash;
    unsigned char result[prefix_len + AES256_BLOCK_LEN * 2];
    char *addr58 = NULL;

    *output = NULL;

    /* Convert the private key to an address and get its hash */
    unsigned char network = 0x00; /* MAIN : FIXME */
    bool compressed = true;
    if (address_from_private_key(priv_key, len, network, compressed, &addr58))
        return -1; /* Invalid private key */

    addr_hash = base58_get_checksum((unsigned char *)addr58, strlen(addr58));

    /* Compute derived key */
    if (scrypt(pass, pass_len,
               (unsigned char *)&addr_hash, sizeof(addr_hash),
               16382, 8, 8,
               derived_key, sizeof(derived_key)))
        return -1;

    /* Construct encypted output */
    result[0] = 0x01;
    result[1] = 0x42; /* FIXME: Compression */
    result[2] = BIP38_FLAG_DEFAULT; /* FIXME: Compression */
    memcpy(result + prefix_len - sizeof(addr_hash),
           &addr_hash, sizeof(addr_hash));
    aes_inc(priv_key + l16, derived_key + l16,
            derived_key + half2, result + prefix_len + l16);
    aes_inc(priv_key + r16, derived_key + r16,
            derived_key + half2, result + prefix_len + r16);

    /* Return base 58 encoded result with checksum */
    base58_from_bytes(result, sizeof(result),
                      BASE58_FLAG_CHECKSUM, output);

    clear_n(2, derived_key, sizeof(derived_key),
            result, sizeof(result));
    return 0;
}
