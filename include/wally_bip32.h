#ifndef LIBWALLY_CORE_BIP32_H
#define LIBWALLY_CORE_BIP32_H

#include "wally-core.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/** The required lengths of entropy for @bip32_key_from_bytes */
#define BIP32_ENTROPY_LEN_128 16u
#define BIP32_ENTROPY_LEN_256 32u

/** Length of an ext_key serialised using BIP32 format */
#define BIP32_SERIALISED_LEN ((size_t)(4 + 1 + 4 + 4 + 32 + 33))

/** Length of an ext_key serialised using wally format */
#define BIP32_FULL_SERIALISED_LEN ((size_t)(BIP32_SERIALISED_LEN + 33 + 20 + 20))

/** Child number of the first hardened child */
#define BIP32_INITIAL_HARDENED_CHILD 0x80000000

/** Indicate that we want to derive a private key in @bip32_key_from_parent */
#define BIP32_KEY_DERIVE_PRIVATE 0x0
/** Indicate that we want to derive a public key in @bip32_key_from_parent */
#define BIP32_KEY_DERIVE_PUBLIC  0x1

/** An extended key */
struct ext_key {
    /** The chain code for this key */
    unsigned char chain_code[32];
    /** The Hash160 of this keys parent */
    unsigned char parent160[20];
    /** The depth of this key */
    uint8_t depth;
    unsigned char pad1[10];
    /** The private key with prefix byte 0 */
    unsigned char priv_key[33];
    /** The Hash160 of this key */
    unsigned char hash160[20];
    /** The child number of the parent key that this key represents */
    uint32_t child_num;
    unsigned char pad2[7];
    /** The public key with prefix byte 0x2 or 0x3 */
    unsigned char pub_key[33];
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
 * Serialise an extended key to memory.
 *
 * The key is always serialised using BIP32 format. If @len is passed as
 * @BIP32_FULL_SERIALISED_LEN then the 'other' key and hash160 of the key
 * and its parent are serialised after the BIP32 data.
 *
 * @key_in The extended key to serialise.
 * @bytes_out Storage for the serialised key.
 * @len Size of @bytes_out in bytes, either @BIP32_SERIALISED_LEN
 *      or @BIP32_FULL_SERIALISED_LEN.
 */
WALLY_CORE_API int bip32_key_serialise(
    const struct ext_key *key_in,
    unsigned char *bytes_out,
    size_t len);

/**
 * Un-serialise an extended key from memory.
 *
 * @bytes_in Storage holding the serialised key.
 * @len Size of @bytes_in in bytes, either @BIP32_SERIALISED_LEN
 *      or @BIP32_FULL_SERIALISED_LEN.
 * @key_out Destination for the resulting extended key.
 */
WALLY_CORE_API int bip32_key_unserialise(
    const unsigned char *bytes_in,
    size_t len,
    struct ext_key *key_out);


/**
 * Create a new child extended key from a parent extended key.
 *
 * This computes either a hardened or normal private
 * child extended key, depending on whether @child_num is hardened.
 *
 * If @key_in is public, this computes a public child extended key if
 * @child_num is normal, or returns an error if @child_num is hardened.
 *
 * @key_in The parent extended key.
 * @child_num The child number to create. Numbers greater
 *            than @BIP32_INITIAL_HARDENED_CHILD are hardened keys.
 * @flags BIP32_KEY_DERIVE_ Flags indicating the type of derivation wanted.
 * @key_out Destination for the resulting child extended key.
 */
WALLY_CORE_API int bip32_key_from_parent(
    const struct ext_key *key_in,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key *key_out);

#endif /* LIBWALLY_CORE_BIP32_H */
