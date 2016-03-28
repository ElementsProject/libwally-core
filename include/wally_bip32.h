#ifndef LIBWALLY_CORE_BIP32_H
#define LIBWALLY_CORE_BIP32_H

#include "wally-core.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/** The required length of entropy for @bip32_key_from_bytes */
#define BIP32_ENTROPY_LEN_256 32u

/* Child number of the first hardened key */
#define BIP32_INITIAL_HARDENED_KEY 0x80000000

/* Flag determining whether this key is private or not */
#define BIP32_EXT_KEY_PRIVATE 0x1

/** An extended key */
struct ext_key {
    /* The private or public key */
    unsigned char key[32];
    /* The chain code for this key */
    unsigned char chain_code[32];
    /* The child number of the parent key that this key represents */
    uint32_t child_num;
    /* BIP32_EXT_KEY_* flags for this key */
    uint32_t flags;
};


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
