#ifndef LIBWALLY_CORE_BIP32_H
#define LIBWALLY_CORE_BIP32_H

#include "wally_core.h"

#include <stdint.h>

/** The required lengths of entropy for @bip32_key_from_seed */
#define BIP32_ENTROPY_LEN_128 16
#define BIP32_ENTROPY_LEN_256 32

/** Length of an ext_key serialised using BIP32 format */
#define BIP32_SERIALISED_LEN 78

/** Child number of the first hardened child */
#define BIP32_INITIAL_HARDENED_CHILD 0x80000000

/** Indicate that we want to derive a private key in @bip32_key_from_parent */
#define BIP32_KEY_PRIVATE 0x0
/** Indicate that we want to derive a public key in @bip32_key_from_parent */
#define BIP32_KEY_PUBLIC  0x1

/** Version codes for extended keys */
#define BIP32_VER_MAIN_PUBLIC  0x0488B21E
#define BIP32_VER_MAIN_PRIVATE 0x0488ADE4
#define BIP32_VER_TEST_PUBLIC  0x043587CF
#define BIP32_VER_TEST_PRIVATE 0x04358394

#ifdef SWIG
struct ext_key;
#else
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
    /** The child number of the parent key that this key represents */
    uint32_t child_num;
    /** The Hash160 of this key */
    unsigned char hash160[20];
    /** The child number of the parent key that this key represents */
    uint32_t version;
    unsigned char pad2[3];
    /** The public key with prefix byte 0x2 or 0x3 */
    unsigned char pub_key[33];
};
#endif /* SWIG */

/**
 * Create a new master extended key from entropy.
 *
 * This creates a new master key, i.e. the root of a new HD tree.
 * @bytes_in Entropy to use.
 * @len_in Size of @bytes_in in bytes.
 * @version Either @BIP32_VER_MAIN_PRIVATE or @BIP32_VER_TEST_PRIVATE.
 * @output Destination for the resulting master extended key.
 *
 * @dest Destination for the resulting master extended key.
 */
#ifndef SWIG
WALLY_CORE_API int bip32_key_from_seed(
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t version,
    struct ext_key *output);
#endif

WALLY_CORE_API int bip32_key_from_seed_alloc(
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t version,
    const struct ext_key **output);

/**
 * Serialise an extended key to memory using BIP32 format.
 *
 * @key_in The extended key to serialise.
 * @flags BIP32_KEY_ Flags indicating which key to serialise. You can not
 *        serialise a private extended key from a public extended key.
 * @bytes_out Destination for the serialised key.
 * @len Size of @bytes_out in bytes. Must be @BIP32_SERIALISED_LEN.
 */
WALLY_CORE_API int bip32_key_serialise(
    const struct ext_key *key_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);


/**
 * Un-serialise an extended key from memory.
 *
 * @bytes_in Storage holding the serialised key.
 * @len_in Size of @bytes_in in bytes. Must be @BIP32_SERIALISED_LEN.
 * @output Destination for the resulting extended key.
 */
WALLY_CORE_API int bip32_key_unserialise(
    const unsigned char *bytes_in,
    size_t len_in,
    struct ext_key *output);


/**
 * Create a new child extended key from a parent extended key.
 *
 * @key_in The parent extended key.
 * @child_num The child number to create. Numbers greater
 *            than or equal to @BIP32_INITIAL_HARDENED_CHILD represent
 *            hardened keys that cannot be created from public parent
 *            extended keys.
 * @flags BIP32_KEY_ Flags indicating the type of derivation wanted.
 *        You can not derive a private child extended key from a public
 *        parent extended key.
 * @output Destination for the resulting child extended key.
 */
WALLY_CORE_API int bip32_key_from_parent(
    const struct ext_key *key_in,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key *output);

#endif /* LIBWALLY_CORE_BIP32_H */
