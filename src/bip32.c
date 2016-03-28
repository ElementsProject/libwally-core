#include <include/wally_bip32.h>
#include "hmac.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
/*#include "secp256k1/include/secp256k1.h"*/
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define KEY_PRIVATE ((unsigned char)0)

static const unsigned char SEED[] = {
    'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'
};

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
    return child_num >= BIP32_INITIAL_HARDENED_KEY;
}


int bip32_key_from_bytes(const unsigned char *bytes_in, size_t len,
                         struct ext_key *key_out)
{
    struct sha512 sha;

    if (len != BIP32_ENTROPY_LEN_256)
        return -1;

    /* Generate key and chain code */
    hmac_sha512(&sha, SEED, sizeof(SEED), bytes_in, len);

    /* Check that key lies between 0 and order(secp256k1) exclusive */
    if (key_overflow(sha.u.u64) || key_zero(sha.u.u64))
        return -1; /* Out of bounds */

    /* The real size of the left and right (key/chain code) parts */
    const size_t actual_len = sizeof(struct sha512) / 2;

    /* Copy the key and set its prefix */
    key_out->key[0] = KEY_PRIVATE;
    memcpy(key_out->key + 1, sha.u.u8, actual_len);

    /* Copy the chain code */
    memcpy(key_out->chain_code, sha.u.u8 + actual_len, actual_len);

    key_out->child_num = 0;
    return 0;
}


int bip32_key_from_parent(const struct ext_key *key_in, uint32_t child_num,
                          struct ext_key *key_out)
{
    key_out->child_num = child_num;

    if (key_in->key[0] == KEY_PRIVATE) {
        /* Private parent -> private child */
        /* FIXME */
    }
    else {
        /* Public parent -> public child */
        if (child_is_hardened(child_num))
            return -1; /* Hardened child cannot be made from public parent */
        /* FIXME */
    }

    return 0;
}
