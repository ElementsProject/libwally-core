#include <include/wally_bip32.h>
#include "hmac.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
/*#include "secp256k1/include/secp256k1.h"*/
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

static const unsigned char SEED[] = {
    'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'
};

/* Overflow check reproduced from secp256k1/src/scalar_4x64_impl.h,
 * Copyright (c) 2013, 2014 Pieter Wuille */
#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

static int secp256k1_scalar_check_overflow(const struct sha512 *a)
{
    int yes = 0;
    int no = 0;
    no |= (a->u.u64[3] < SECP256K1_N_3); /* No need for a > check. */
    no |= (a->u.u64[2] < SECP256K1_N_2);
    yes |= (a->u.u64[2] > SECP256K1_N_2) & ~no;
    no |= (a->u.u64[1] < SECP256K1_N_1);
    yes |= (a->u.u64[1] > SECP256K1_N_1) & ~no;
    yes |= (a->u.u64[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

int bip32_ext_key_from_bytes(const unsigned char *bytes, size_t len,
                             struct ext_key *dest)
{
    struct sha512 *sha = (struct sha512 *)dest;

    int overflow = 0;

    if (len != BIP32_ENTROPY_LEN_256)
        return -1;

    hmac_sha512((struct sha512 *)dest, SEED, sizeof(SEED), bytes, len);

    if (!sha->u.u64[0] && !sha->u.u64[1] && !sha->u.u64[2] && !sha->u.u64[3])
        return -1;

    if (secp256k1_scalar_check_overflow(sha))
        return -1;

    return 0;
}

