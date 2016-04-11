#include <include/wally_bip32.h>
#include "internal.h"
#include "hmac.h"
#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
#include "ccan/ccan/endian/endian.h"
#include "ccan/ccan/build_assert/build_assert.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

static const unsigned char SEED[] = {
    'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'
};

/* Check assumptions we expect to hold true */
static void assert_assumptions(void)
{
#define key_off(member) offsetof(struct ext_key,  member)
#define key_size(member) sizeof(((struct ext_key *)0)->member)

    /* Our ripend buffers must be uint32_t aligned and the correct size */
    BUILD_ASSERT(key_off(parent160) % sizeof(uint32_t) == 0);
    BUILD_ASSERT(key_off(hash160) % sizeof(uint32_t) == 0);
    BUILD_ASSERT(key_size(parent160) == sizeof(struct ripemd160));
    BUILD_ASSERT(key_size(hash160) == sizeof(struct ripemd160));

    /* Our keys following the parity byte must be uint64_t aligned */
    BUILD_ASSERT((key_off(priv_key) + 1) % sizeof(uint64_t) == 0);
    BUILD_ASSERT((key_off(pub_key) + 1) % sizeof(uint64_t) == 0);

    /* child_num must be contigous after priv_key */
    BUILD_ASSERT((key_off(priv_key) + key_size(priv_key)) == key_off(child_num));

    /* We use priv_key[0] to determine if this extended key is public or
     * private, If priv_key[0] is BIP32_KEY_PRIVATE then this key is private
     * with a computed public key present. If set to BIP32_KEY_PUBLIC then
     * this is a public key with no private key (A BIP32 'neutered' key).
     *
     * For this to work BIP32_KEY_PRIVATE must be zero so the whole 33 byte
     * private key is valid when serialised, and BIP32_KEY_PUBLIC cannot be
     * 2 or 3 as they are valid parity bytes for public keys.
     */
    BUILD_ASSERT(BIP32_KEY_PRIVATE == 0);
    BUILD_ASSERT(BIP32_KEY_PUBLIC != BIP32_KEY_PRIVATE &&
                 BIP32_KEY_PUBLIC != 2u &&
                 BIP32_KEY_PUBLIC != 3u);

#undef key_size
#undef key_off
}

static bool mem_is_zero(const void *mem, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i)
        if (((const unsigned char *)mem)[i])
            return false;
    return true;
}

/* Overflow check reproduced from secp256k1/src/scalar_4x64_impl.h,
 * Copyright (c) 2013, 2014 Pieter Wuille */
#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

static int key_overflow(const uint64_t *a)
{
    int yes = 0;
    int no = 0;
    no |= (a[3] < SECP256K1_N_3); /* No need for a > check. */
    no |= (a[2] < SECP256K1_N_2);
    yes |= (a[2] > SECP256K1_N_2) & ~no;
    no |= (a[1] < SECP256K1_N_1);
    yes |= (a[1] > SECP256K1_N_1) & ~no;
    yes |= (a[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

static int key_zero(const uint64_t *a)
{
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

static bool child_is_hardened(uint32_t child_num)
{
    return child_num >= BIP32_INITIAL_HARDENED_CHILD;
}

static bool version_is_valid(uint32_t ver, uint32_t flags)
{
    if (ver == BIP32_VER_MAIN_PRIVATE || ver == BIP32_VER_TEST_PRIVATE)
        return true;

    return flags == BIP32_KEY_PUBLIC &&
           (ver == BIP32_VER_MAIN_PUBLIC || ver == BIP32_VER_TEST_PUBLIC);
}

static bool version_is_mainnet(uint32_t ver)
{
    return ver == BIP32_VER_MAIN_PRIVATE || ver == BIP32_VER_MAIN_PUBLIC;
}

static bool key_is_private(const struct ext_key *key_in)
{
    return key_in->priv_key[0] == BIP32_KEY_PRIVATE;
}

static void key_strip_private_key(struct ext_key *key_out)
{
    key_out->priv_key[0] = BIP32_KEY_PUBLIC;
    memset(key_out->priv_key + 1, 0, sizeof(key_out->priv_key) - 1);
}

/* Compute a public key from a private key */
static int key_compute_pub_key(struct ext_key *key_out)
{
    secp256k1_pubkey pub_key;
    size_t len = sizeof(key_out->pub_key);
    const secp256k1_context *ctx = secp_ctx();

    int ret = (pubkey_create(ctx, &pub_key, key_out->priv_key + 1) &&
               pubkey_serialize(ctx, key_out->pub_key, &len, &pub_key,
                                PUBKEY_COMPRESSED) &&
               len == sizeof(key_out->pub_key)) ? 0 : -1;

    clear(&pub_key, sizeof(pub_key));
    if (ret != 0)
        clear(key_out->pub_key, sizeof(key_out->pub_key));
    return ret;
}

static void key_compute_hash160(struct ext_key *key_out)
{
    struct sha256 sha;
    sha256(&sha, key_out->pub_key, sizeof(key_out->pub_key));
    ripemd160((struct ripemd160 *)key_out->hash160, &sha, sizeof(sha));
    clear(&sha, sizeof(sha));
}


int bip32_key_from_bytes(const unsigned char *bytes_in, size_t len,
                         uint32_t version, struct ext_key *key_out)
{
    struct sha512 sha;

    if (len != BIP32_ENTROPY_LEN_256 && len != BIP32_ENTROPY_LEN_128)
        return -1;

    if (!version_is_valid(key_out->version = version, BIP32_KEY_PRIVATE))
        return -1;

    /* Generate key and chain code */
    hmac_sha512(&sha, SEED, sizeof(SEED), bytes_in, len);

    /* Check that key lies between 0 and order(secp256k1) exclusive */
    if (key_overflow(sha.u.u64) || key_zero(sha.u.u64)) {
        clear(&sha, sizeof(sha));
        return -1; /* Out of bounds */
    }

    /* Copy the private key and set its prefix */
    key_out->priv_key[0] = BIP32_KEY_PRIVATE;
    memcpy(key_out->priv_key + 1, sha.u.u8, sizeof(sha) / 2);
    if (key_compute_pub_key(key_out)) {
        clear_n(2, &sha, sizeof(sha),
                key_out->priv_key, sizeof(key_out->priv_key));
        return -1;
    }

    /* Copy the chain code */
    memcpy(key_out->chain_code, sha.u.u8 + sizeof(sha) / 2, sizeof(sha) / 2);

    key_out->depth = 0; /* Master key, depth 0 */
    key_out->child_num = 0;
    memset(key_out->parent160, 0, sizeof(key_out->parent160));

    key_compute_hash160(key_out);
    clear(&sha, sizeof(sha));
    return 0;
}

static unsigned char *copy_out(unsigned char *dest,
                               const void *src, size_t len)
{
    memcpy(dest, src, len);
    return dest + len;
}

static bool key_is_valid(const struct ext_key *key_in)
{
    bool is_private = key_is_private(key_in);
    bool is_master = !key_in->child_num;
    uint8_t ver_flags = is_private ? BIP32_KEY_PRIVATE : BIP32_KEY_PUBLIC;

    if (!version_is_valid(key_in->version, ver_flags))
        return false;

    if (mem_is_zero(key_in->chain_code, sizeof(key_in->chain_code)) ||
        (key_in->pub_key[0] != 0x2 && key_in->pub_key[0] != 0x3) ||
        mem_is_zero(key_in->pub_key + 1, sizeof(key_in->pub_key) - 1))
        return false;

    if (key_in->priv_key[0] != BIP32_KEY_PUBLIC &&
        key_in->priv_key[0] != BIP32_KEY_PRIVATE)
        return false;

    if (is_private &&
        mem_is_zero(key_in->priv_key + 1, sizeof(key_in->priv_key) - 1))
        return false;

    if (is_master && !is_private)
        return false;

    if (is_master &&
        !mem_is_zero(key_in->parent160, sizeof(key_in->parent160)))
        return false;

    return true;
}

/* Wipe memory and return failure for the caller to propigate */
static int wipe_mem_fail(unsigned char *bytes_out, size_t len)
{
    clear(bytes_out, len);
    return -1;
}

int bip32_key_serialise(const struct ext_key *key_in, uint32_t flags,
                        unsigned char *bytes_out, size_t len)
{
    const bool serialise_private = !(flags & BIP32_KEY_PUBLIC);
    unsigned char *out = bytes_out;
    uint32_t tmp32;
    beint32_t tmp32_be;

    /* Validate our arguments and then the input key */
    if (len != BIP32_SERIALISED_LEN ||
        (serialise_private && !key_is_private(key_in)) ||
        !key_is_valid(key_in))
        return wipe_mem_fail(bytes_out, len);

    tmp32 = key_in->version;
    if (!serialise_private) {
        /* Change version if serialising the public part of a private key */
        if (tmp32 == BIP32_VER_MAIN_PRIVATE)
            tmp32 = BIP32_VER_MAIN_PUBLIC;
        else if (tmp32 == BIP32_VER_TEST_PRIVATE)
            tmp32 = BIP32_VER_TEST_PUBLIC;
    }
    tmp32_be = cpu_to_be32(tmp32);
    out = copy_out(out, &tmp32_be, sizeof(tmp32_be));

    *out++ = key_in->depth;

    /* Save the first 32 bits of the parent key (aka fingerprint) only */
    out = copy_out(out, key_in->parent160, sizeof(uint32_t));

    tmp32_be = cpu_to_be32(key_in->child_num);
    out = copy_out(out, &tmp32_be, sizeof(tmp32_be));

    out = copy_out(out, key_in->chain_code, sizeof(key_in->chain_code));

    if (serialise_private)
        copy_out(out, key_in->priv_key, sizeof(key_in->priv_key));
    else
        copy_out(out, key_in->pub_key, sizeof(key_in->pub_key));

    return 0;
}

static const unsigned char *copy_in(void *dest,
                                    const unsigned char *src, size_t len)
{
    memcpy(dest, src, len);
    return src + len;
}

/* Wipe a key and return failure for the caller to propigate */
static int wipe_key_fail(struct ext_key *key_out)
{
    clear(key_out, sizeof(key_out));
    return -1;
}

int bip32_key_unserialise(const unsigned char *bytes_in, size_t len,
                          struct ext_key *key_out)
{
    if (len != BIP32_SERIALISED_LEN)
        return wipe_key_fail(key_out);

    bytes_in = copy_in(&key_out->version, bytes_in, sizeof(key_out->version));
    key_out->version = be32_to_cpu(key_out->version);
    if (!version_is_valid(key_out->version, BIP32_KEY_PUBLIC))
        return wipe_key_fail(key_out);

    bytes_in = copy_in(&key_out->depth, bytes_in, sizeof(key_out->depth));

    /* We only have a partial fingerprint available. Copy it, but the
     * user will need to call bip32_key_set_parent() (FIXME: Implement)
     * later if they want it to be fully populated.
     */
    bytes_in = copy_in(key_out->parent160, bytes_in, sizeof(uint32_t));
    memset(key_out->parent160 + sizeof(uint32_t), 0,
           sizeof(key_out->parent160) - sizeof(uint32_t));

    bytes_in = copy_in(&key_out->child_num, bytes_in, sizeof(key_out->child_num));
    key_out->child_num = be32_to_cpu(key_out->child_num);

    bytes_in = copy_in(key_out->chain_code, bytes_in, sizeof(key_out->chain_code));

    if (bytes_in[0] == BIP32_KEY_PRIVATE) {
        if (key_out->version == BIP32_VER_MAIN_PUBLIC ||
            key_out->version == BIP32_VER_TEST_PUBLIC)
            return wipe_key_fail(key_out); /* Private key data in public key */

        copy_in(key_out->priv_key, bytes_in, sizeof(key_out->priv_key));
        if (key_compute_pub_key(key_out))
            return wipe_key_fail(key_out);
    } else {
        if (key_out->version == BIP32_VER_MAIN_PRIVATE ||
            key_out->version == BIP32_VER_TEST_PRIVATE)
            return wipe_key_fail(key_out); /* Public key data in private key */

        copy_in(key_out->pub_key, bytes_in, sizeof(key_out->pub_key));
        key_strip_private_key(key_out);
    }

    key_compute_hash160(key_out);
    return 0;
}

/* BIP32: Child Key Derivations
 *
 * The spec doesn't have a simple table of derivations, its:
 *
 * Parent   Child    Hardened  Status  Path  In Spec
 * private  private  no        OK      m/n   Y
 * private  private  yes       OK      m/nH  Y
 * private  public   no        OK      -     N
 * private  public   yes       OK      -     N
 * public   private  no        FAIL   (N/A) (N/A)
 * public   private  yes       FAIL   (N/A) (N/A)
 * public   public   no        OK      M/n   N
 * public   public   yes       FAIL    M/nH (N/A)
 *
 * The spec path nomenclature only expresses derivations where the parent
 * and desired child type match. For private->public the derivation is
 * described in terms of private-private and public->public, but there are
 * no test vectors or paths describing these values to validate against.
 * Further, there are no public-public vectors in the BIP32 spec either.
 */
int bip32_key_from_parent(const struct ext_key *key_in, uint32_t child_num,
                          uint32_t flags, struct ext_key *key_out)
{
    struct sha512 sha;
    const secp256k1_context *ctx = secp_ctx();
    const bool we_are_private = key_is_private(key_in);
    const bool derive_private = !(flags & BIP32_KEY_PUBLIC);
    const bool hardened = child_is_hardened(child_num);

    if (!we_are_private && (derive_private || hardened))
        return wipe_key_fail(key_out); /* Unsupported derivation */

    if (key_in->depth == 0xff)
        return wipe_key_fail(key_out); /* Maximum depth reached */

    /*
     *  Private parent -> private child:
     *    CKDpriv((kpar, cpar), i) -> (ki, ci)
     *
     *  Private parent -> public child:
     *    N(CKDpriv((kpar, cpar), i) -> (ki, ci))
     *  As we always calculate the public key, we can derive a public
     *  child by deriving a private one and stripping its private key.
     *
     * Public parent -> non hardened public child
     *    CKDpub((Kpar, cpar), i) -> (Ki, ci)
     */

    /* NB: We use the key_outs' priv_key+child_num to hold 'Data' here */
    if (hardened) {
        /* Hardened: Data = 0x00 || ser256(kpar) || ser32(i)) */
        memcpy(key_out->priv_key, key_in->priv_key, sizeof(key_in->priv_key));
    } else {
        /* Non Hardened Private: Data = serP(point(kpar)) || ser32(i)
         * Non Hardened Public : Data = serP(kpar) || ser32(i)
         *   point(kpar) when par is private is the public key.
         */
        memcpy(key_out->priv_key, key_in->pub_key, sizeof(key_in->pub_key));
    }

    /* This is the '|| ser32(i)' part of the above */
    key_out->child_num = cpu_to_be32(child_num);

    /* I = HMAC-SHA512(Key = cpar, Data) */
    hmac_sha512(&sha, key_in->chain_code, sizeof(key_in->chain_code),
                key_out->priv_key,
                sizeof(key_out->priv_key) + sizeof(key_out->child_num));

    /* Split I into two 32-byte sequences, IL and IR
     * The returned chain code ci is IR (i.e. the 2nd half of our hmac sha512)
     */
    memcpy(key_out->chain_code, sha.u.u8 + sizeof(sha) / 2,
           sizeof(key_out->chain_code));

    if (we_are_private) {
        /* The returned child key ki is parse256(IL) + kpar (mod n)
         * In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid
         * (NOTE: privkey_tweak_add checks both conditions)
         */
        memcpy(key_out->priv_key, key_in->priv_key, sizeof(key_in->priv_key));
        if (!privkey_tweak_add(ctx, key_out->priv_key + 1, sha.u.u8)) {
            clear(&sha, sizeof(sha));
            return wipe_key_fail(key_out); /* Out of bounds FIXME: Iterate to the next? */
        }

        if (key_compute_pub_key(key_out)) {
            clear(&sha, sizeof(sha));
            return wipe_key_fail(key_out);
        }
    } else {
        /* The returned child key ki is point(parse256(IL) + kpar)
         * In case parse256(IL) ≥ n or Ki is the point at infinity, the
         * resulting key is invalid (NOTE: pubkey_tweak_add checks both
         * conditions)
         */
        secp256k1_pubkey pub_key;
        size_t len = sizeof(key_out->pub_key);

        /* FIXME: Out of bounds on pubkey_tweak_add */
        if (!pubkey_parse(ctx, &pub_key, key_in->pub_key,
                          sizeof(key_in->pub_key)) ||
            !pubkey_tweak_add(ctx, &pub_key, sha.u.u8) ||
            !pubkey_serialize(ctx, key_out->pub_key, &len, &pub_key,
                              PUBKEY_COMPRESSED) ||
            len != sizeof(key_out->pub_key)) {
            clear(&sha, sizeof(sha));
            return wipe_key_fail(key_out);
        }
    }

    if (derive_private) {
        if (version_is_mainnet(key_in->version))
            key_out->version = BIP32_VER_MAIN_PRIVATE;
        else
            key_out->version = BIP32_VER_TEST_PRIVATE;

    } else {
        if (version_is_mainnet(key_in->version))
            key_out->version = BIP32_VER_MAIN_PUBLIC;
        else
            key_out->version = BIP32_VER_TEST_PUBLIC;

        key_strip_private_key(key_out);
    }

    key_out->depth = key_in->depth + 1;
    key_out->child_num = child_num;
    memcpy(key_out->parent160, key_in->hash160, sizeof(key_in->hash160));
    key_compute_hash160(key_out);
    clear(&sha, sizeof(sha));
    return 0;
}
