#ifndef LIBWALLY_CORE_BIP32_H
#define LIBWALLY_CORE_BIP32_H

#include "wally-core.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/** The required lengths of entropy for @bip32_key_from_bytes */
#define BIP32_ENTROPY_LEN_128 16u
#define BIP32_ENTROPY_LEN_256 32u

/* Child number of the first hardened child */
#define BIP32_INITIAL_HARDENED_CHILD 0x80000000

/** An extended key */
struct ext_key {
    /* The chain code for this key */
    unsigned char chain_code[32];
    /* The private or public key with prefix byte */
    unsigned char key[33];
    /* The child number of the parent key that this key represents */
    uint32_t child_num;
};


/** FIXME */
WALLY_CORE_API struct ext_key *bip32_key_alloc(
    const unsigned char *chain_code,
    size_t chain_code_len,
    const unsigned char *bytes,
    size_t len,
    uint32_t child_num);

/** FIXME */
WALLY_CORE_API void bip32_key_free(struct ext_key *key_in);

/**
 * Create a new master extended key from entropy.
 *
 * This creates a new master key, i.e. the root of a new HD tree.
 * @bytes_in Entropy to use.
 * @len Size of @bytes_in in bytes.
 * @dest Destination for the resulting master extended key.
 */
WALLY_CORE_API int bip32_key_from_bytes(
    const unsigned char *bytes_in,
    size_t len,
    struct ext_key *key_out);


/**
 * Create a new child extended key from a parent extended key.
 *
 * If @key_in is private, this computes either a hardened or normal private
 * child extended key, depending on whether @child_num is hardened.
 *
 * If @key_in is public, this computes a public child extended key if
 * @child_num is normal, or returns an error if @child_num is hardened.
 *
 * @key_in The parent extended key.
 * @child The child number to create.
 * @key_out Destination for the resulting child extended key.
 */
WALLY_CORE_API int bip32_key_from_parent(
    const struct ext_key *key_in,
    uint32_t child_num,
    struct ext_key *key_out);


/* FIXME: Name and interface */
WALLY_CORE_API int bip32_public_key_from_parent(
    const struct ext_key *key_in,
    uint32_t child_num,
    struct ext_key *key_out);

#endif /* LIBWALLY_CORE_BIP32_H */
