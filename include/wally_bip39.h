#ifndef LIBWALLY_CORE_BIP39_H
#define LIBWALLY_CORE_BIP39_H

#include "wally-core.h"

#include <stdint.h>
#include <stdbool.h>

struct words;

/** Valid entropy lengths */
#define BIP39_ENTROPY_LEN_128 16u
#define BIP39_ENTROPY_LEN_160 20u
#define BIP39_ENTROPY_LEN_192 24u
#define BIP39_ENTROPY_LEN_224 28u
#define BIP39_ENTROPY_LEN_256 32u

/** The required size of the output buffer for @bip39_mnemonic_to_seed */
#define BIP39_SEED_LEN_512 64u

/**
 * Get the list of default supported languages.
 *
 * The string returned should be freed using @wally_free_string().
 */
WALLY_CORE_API void bip39_get_languages(char **output);

/**
 * Get the default word list for language @lang.
 *
 * If @lang is NULL or not found the default English list is returned.
 */
WALLY_CORE_API const struct words *bip39_get_wordlist(
    const char *lang);

/**
 * Generate a mnemonic sentence from the entropy in @bytes_in.
 * @w Word list to use. Pass NULL to use the default English list.
 * @bytes_in: Entropy to convert.
 * @len: The length of @bytes_in in bytes.
 *
 * The string returned should be freed using @wally_free_string().
 */
WALLY_CORE_API void bip39_mnemonic_from_bytes(
    const struct words *w,
    const unsigned char *bytes_in,
    size_t len,
    char **output);

/**
 * Convert a mnemonic sentence into entropy at @bytes_out.
 * @w Word list to use. Pass NULL to use the default English list.
 * @mnemonic Mnemonic to convert.
 * @bytes_out: Where to store the resulting entropy.
 * @len: The length of @bytes_out in bytes.
 *
 * Returns The number of bytes writen on success, zero otherwise.
 */
WALLY_CORE_API size_t bip39_mnemonic_to_bytes(
    const struct words *w,
    const char *mnemonic,
    unsigned char *bytes_out,
    size_t len);

/**
 * Validate the checksum embedded in the mnemonic sentence @mnemonic.
 * @w Word list to use. Pass NULL to use the default English list.
 * @mnemonic Mnemonic to validate.
 */
WALLY_CORE_API bool bip39_mnemonic_is_valid(
    const struct words *w,
    const char *mnemonic);

/**
 * Convert a mnemonic into a binary seed.
 * @mnemonic Mnemonic to convert.
 * @password Mnemonic password or NULL if no password is needed.
 * @bytes_out The destination for the binary seed.
 * @len The length of @bytes_out in bytes. Currently This must
 *      be @BIP39_SEED_LEN_512.
 *
 * Returns @BIP39_SEED_LEN_512 on success, zero otherwise.
 */
WALLY_CORE_API size_t bip39_mnemonic_to_seed(
    const char *mnemonic,
    const char *password,
    unsigned char *bytes_out,
    size_t len);

#endif /* LIBWALLY_CORE_BIP39_H */
