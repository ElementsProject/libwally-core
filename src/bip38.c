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

struct btc_address
{
    unsigned char pad1[3];
    unsigned char version;
    struct ripemd160 ripemd160;
};

static void assert_assumptions(void)
{
#define addr_off(member) offsetof(struct btc_address,  member)

    /* Our address members must be contiguous */
    BUILD_ASSERT(addr_off(version) == 3u);
    BUILD_ASSERT(addr_off(ripemd160) == 4u);
}


static int address_from_private_key(unsigned char *priv_key, size_t priv_key_len,
                                    struct btc_address *address)
{
    if (priv_key_len != BITCOIN_PRIVATE_KEY_LEN)
        return -1;

    /* FIXME */
    (void)priv_key;
    (void)address;
    return 0;
}

/* Compute the Bitcoin address (ASCII), and take the first four bytes of
 * SHA256(SHA256()) of it. Let's call this "addresshash".
 */
static int get_address_hash(struct btc_address *address_in_out, uint32_t *hash_out)
{
    char *base58;
    size_t base58_len;

    /* FIXME: return an error code from base58_from_bytes  */

    /* Get the ASCII representation (i.e. base 58 check encoded) */
    base58_from_bytes(&address_in_out->version,
                      sizeof(unsigned char) + sizeof(struct ripemd160),
                      BASE58_FLAG_CHECKSUM, &base58);
    if (!base58)
        return -1;

    /* Compute and return double sha256 */
    base58_len = strlen(base58);
    /* FIXME: return an error code from base58_get_checksum */
    *hash_out = base58_get_checksum((const unsigned char *)base58, base58_len);
    clear(base58, base58_len);
    free(base58);
    return 0;
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
    const size_t addr_len = 1 + 20 + 4; /* version, ripemd160, hash */
    const size_t prefix_len = 3 + sizeof(addr_len); /* 0x0142, flags, salt */
    unsigned char derived_key[BIP38_DERVIED_KEY_LEN];
    struct btc_address address;
    uint32_t address_hash;
    unsigned char result[prefix_len + AES256_BLOCK_LEN * 2];

    *output = NULL;

    /* Convert the private key to an address and get its hash */
    if (address_from_private_key(priv_key, len, &address) ||
        get_address_hash(&address, &address_hash))
        return -1; /* Invalid private key */

    /* Compute derived key */
    if (scrypt(pass, pass_len,
               (unsigned char *)&address_hash, sizeof(address_hash),
               16382, 8, 8,
               derived_key, sizeof(derived_key)))
        return -1;

    /* Construct encypted output */
    result[0] = 0x01;
    result[1] = 0x42; /* FIXME: Compression */
    result[2] = BIP38_FLAG_DEFAULT; /* FIXME: Compression */
    memcpy(result + prefix_len - sizeof(address_hash),
           &address_hash, sizeof(address_hash));
    aes_inc(priv_key + l16, derived_key + l16,
            derived_key + half2, result + prefix_len + l16);
    aes_inc(priv_key + r16, derived_key + r16,
            derived_key + half2, result + prefix_len + r16);

    /* Return base 58 encoded result with checksum */
    base58_from_bytes(result, sizeof(result),
                      BASE58_FLAG_CHECKSUM, output);

    clear_n(3, derived_key, sizeof(derived_key),
            result, sizeof(result), &address, sizeof(address));
    return 0;
}
