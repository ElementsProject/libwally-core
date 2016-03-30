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

/* If priv_key[0] is KEY_PRIVATE then this is a private key,
 * with a public key also present. If set to KEY_PUBLIC then
 * this is a public key with an empty private key (In BIP32
 * terms, a 'neutered' key).
 */
#define KEY_PRIVATE 0
#define KEY_PUBLIC 1u

static const unsigned char SEED[] = {
    'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'
};

/* Check assumptions we expect to hold true */
void assert_assumptions(void)
{
#define key_off(member) offsetof(struct ext_key,  member)

    /* Our ripend buffers must be uint32_t aligned and the correct size */
    BUILD_ASSERT(key_off(parent160) % sizeof(uint32_t) == 0);
    BUILD_ASSERT(key_off(hash160) % sizeof(uint32_t) == 0);
    BUILD_ASSERT(sizeof(((struct ext_key *)0)->parent160) == sizeof(struct ripemd160));
    BUILD_ASSERT(sizeof(((struct ext_key *)0)->hash160) == sizeof(struct ripemd160));

    /* Our keys following the parity byte must be uint64_t aligned */
    BUILD_ASSERT((key_off(priv_key) + 1) % sizeof(uint64_t) == 0);
    BUILD_ASSERT((key_off(pub_key) + 1) % sizeof(uint64_t) == 0);

#undef key_off
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

static bool key_is_private(const struct ext_key *key_in)
{
    return key_in->priv_key[0] == KEY_PRIVATE;
}

static int key_compute_pub_key(struct ext_key *key_out)
{
    secp256k1_pubkey pub_key;
    size_t len = sizeof(key_out->pub_key);
    const secp256k1_context *ctx = secp_ctx();

    if (!secp256k1_ec_pubkey_create(ctx, &pub_key, key_out->priv_key + 1) ||
        !secp256k1_ec_pubkey_serialize(ctx, key_out->pub_key, &len, &pub_key,
                                       SECP256K1_EC_COMPRESSED) ||
        len != sizeof(key_out->pub_key))
        return -1;

    return 0;
}

static void key_compute_hash160(struct ext_key *key_out)
{
    struct sha256 sha;
    struct ripemd160 ripemd;

    sha256(&sha, key_out->priv_key, sizeof(key_out->priv_key));
    ripemd160(&ripemd, &sha, sizeof(sha));

    memcpy(key_out->hash160, &ripemd, sizeof(ripemd));
}


int bip32_key_from_bytes(const unsigned char *bytes_in, size_t len,
                         struct ext_key *key_out)
{
    struct sha512 sha;

    if (len != BIP32_ENTROPY_LEN_256 && len != BIP32_ENTROPY_LEN_128)
        return -1;

    /* Generate key and chain code */
    hmac_sha512(&sha, SEED, sizeof(SEED), bytes_in, len);

    /* Check that key lies between 0 and order(secp256k1) exclusive */
    if (key_overflow(sha.u.u64) || key_zero(sha.u.u64))
        return -1; /* Out of bounds */

    /* Copy the key and set its prefix */
    key_out->priv_key[0] = KEY_PRIVATE;
    memcpy(key_out->priv_key + 1, sha.u.u8, sizeof(sha) / 2);

    /* Copy the chain code */
    memcpy(key_out->chain_code, sha.u.u8 + sizeof(sha) / 2, sizeof(sha) / 2);

    key_out->depth = 0; /* Master key, depth 0 */
    key_out->child_num = 0;
    memset(key_out->parent160, 0, sizeof(key_out->parent160));
    if (key_compute_pub_key(key_out))
        return -1;
    key_compute_hash160(key_out);
    return 0;
}

/* FIXME: ccan should have endian functions for reading/writing to buffers */
static inline uint32_t pbe8_to_cpu(const unsigned char **pp)
{
    const unsigned char *p = *pp;
    uint8_t v = p[0];
    *pp += sizeof(v);
    return v;
}

static inline uint32_t pbe32_to_cpu(const unsigned char **pp)
{
    const unsigned char *p = *pp;
    uint32_t v = (p[0] << 24u) | (p[1] << 16u) | (p[2] << 8u) | p[3];
    *pp += sizeof(v);
    return v;
}

int bip32_key_serialise(const struct ext_key *key_in,
                        unsigned char *bytes_out, size_t len)
{
    /* FIXME */
    (void)key_in;
    (void)bytes_out;
    (void)len;
    return 0;
}

int bip32_key_unserialise(const unsigned char *bytes_in, size_t len,
                          struct ext_key *key_out)
{
    uint32_t version;
    const unsigned char *fingerprint;

    if (len != BIP32_SERIALISED_LEN && len != BIP32_FULL_SERIALISED_LEN)
        return -1;

    version = pbe32_to_cpu(&bytes_in);
    /* FIXME: Test version */
    (void)version;
    key_out->depth = pbe8_to_cpu(&bytes_in);
    fingerprint = bytes_in;
    bytes_in += sizeof(uint32_t);
    key_out->child_num = pbe32_to_cpu(&bytes_in);
    memcpy(key_out->chain_code, bytes_in, sizeof(key_out->chain_code));
    bytes_in += sizeof(key_out->chain_code);

    if (bytes_in[0] == KEY_PRIVATE)
        memcpy(key_out->priv_key, bytes_in, sizeof(key_out->priv_key));
    else {
        memcpy(key_out->pub_key, bytes_in, sizeof(key_out->pub_key));
        key_out->priv_key[0] = KEY_PUBLIC;
    }
    bytes_in += sizeof(key_out->pub_key);

    if (len == BIP32_SERIALISED_LEN) {
        /* We only have the partial fingerprint available. Copy it,
         * but the user will need to call bip32_key_set_parent()
         * later if they want it to be fully populated.
         */
        memcpy(key_out->parent160, fingerprint, sizeof(uint32_t));
        memset(key_out->parent160 + sizeof(uint32_t), 0,
               sizeof(key_out->parent160) - sizeof(uint32_t));
        if (key_is_private(key_out) && key_compute_pub_key(key_out))
            return -1;
        key_compute_hash160(key_out);
    } else {
        if (key_is_private(key_out))
            memcpy(key_out->pub_key, bytes_in, sizeof(key_out->pub_key));
        else {
            /* Make sure no private key info was serialised for this key */
            memcpy(key_out->priv_key, bytes_in, sizeof(key_out->priv_key));
            if (key_out->priv_key[0] != KEY_PUBLIC ||
                !key_zero((const uint64_t *)(key_out->priv_key + 1)))
                return -1;
        }

        bytes_in += sizeof(key_out->pub_key);
        memcpy(key_out->parent160, bytes_in, sizeof(key_out->parent160));
        if (memcmp(key_out->parent160, fingerprint, sizeof(uint32_t)))
            return -1; /* Fingerprints don't match */

        bytes_in += sizeof(key_out->parent160);
        memcpy(key_out->hash160, bytes_in, sizeof(key_out->hash160));
        bytes_in += sizeof(key_out->hash160);
    }
    return 0;
}

static const secp256k1_context *dummy_secp(void)
{
    return (const secp256k1_context *)1;
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
                          struct ext_key *key_out)
{
    if (key_in->depth == 0xff)
        return -1; /* Maximum depth reached */

    if (key_is_private(key_in)) {
        /*
         *  Private parent -> private child:
         *     CKDpriv((kpar, cpar), i) -> (ki, ci)
         */
        /* FIXME: Put child_num after priv_key and use that buffer directly? */
        unsigned char buf[sizeof(key_in->priv_key) + sizeof(child_num)];
        const beint32_t child_num_be = cpu_to_be32(child_num);
        struct sha512 sha;

        if (child_is_hardened(child_num)) {
            /* Hardened: Data = 0x00 || ser256(kpar) || ser32(i)) */
            memcpy(buf, key_in->priv_key, sizeof(key_in->priv_key));
        } else {
            /* Non Hardened: Data = serP(point(kpar)) || ser32(i) */
            memcpy(buf, key_in->pub_key, sizeof(key_in->pub_key));
        }

        /* This is the '|| ser32(i)' part of the above */
        memcpy(buf + sizeof(key_in->priv_key),
               &child_num_be, sizeof(child_num_be));

        /* I = HMAC-SHA512(Key = cpar, Data) */
        hmac_sha512(&sha, key_in->chain_code, sizeof(key_in->chain_code),
                    buf, sizeof(buf));

        /* Split I into two 32-byte sequences, IL and IR
         * The returned chain code ci is IR
         */
        memcpy(key_out->chain_code, sha.u.u8 + sizeof(sha) / 2,
               sizeof(key_out->chain_code));

        /* The returned child key ki is parse256(IL) + kpar (mod n)
         * In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid
         * (NOTE: secp256k1_ec_privkey_tweak_add checks both conditions)
         */
        memcpy(key_out->priv_key, key_in->priv_key, sizeof(key_in->priv_key));
        if (!secp256k1_ec_privkey_tweak_add(dummy_secp(),
                                            key_out->priv_key + 1, sha.u.u8))
            return -1;     /* Out of bounds FIXME: Iterate to the next? */

        if (key_compute_pub_key(key_out))
            return -1;
    } else {
        /* Public parent -> public child */
        if (child_is_hardened(child_num))
            return -1; /* Hardened child cannot be made from public parent */
        /* FIXME */
        return -1;
    }

    key_out->depth = key_in->depth + 1;
    key_out->child_num = child_num;
    memcpy(key_out->parent160, key_in->hash160, sizeof(key_in->hash160));
    key_compute_hash160(key_out);
    return 0;
}
