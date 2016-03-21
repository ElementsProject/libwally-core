#ifndef LIBWALLY_CORE_BIP39_H
#define LIBWALLY_CORE_BIP39_H

#include "wally-core.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

struct words;

/** Valid entropy lengths */
#define BIP39_ENTROPY_LEN_128 16u
#define BIP39_ENTROPY_LEN_160 20u
#define BIP39_ENTROPY_LEN_192 24u
#define BIP39_ENTROPY_LEN_224 28u
#define BIP39_ENTROPY_LEN_256 32u

/* Returned seed length */
#define BIP39_SEED_LEN_512 64u

/**
 * Get the list of default supported languages.
 *
 * The names are returned separated by ' ' as a constant string.
 */
WALLY_CORE_API const char *bip39_get_languages(void);

/**
 * Get the default word list for language @lang.
 *
 * If @lang is NULL or not found the default English list is returned.
 */
WALLY_CORE_API const struct words *bip39_get_wordlist(
    const char *lang);

/**
 * Generate a mnemonic sentence from the entropy in @bytes.
 * @w Word list to use. Pass NULL to use the default English list.
 * @bytes: Entropy to covert.
 * @len: The length of @bytes in bytes.
 */
WALLY_CORE_API char *bip39_mnemonic_from_bytes(
    const struct words *w,
    const unsigned char *bytes,
    size_t len);

/**
 * Convert a mnemonic sentence into entropy at @bytes.
 * @w Word list to use. Pass NULL to use the default English list.
 * @mnemonic Mnemonic to convert.
 * @bytes: Where to store the resulting entropy.
 * @len: The length of @bytes in bytes.
 */
WALLY_CORE_API size_t bip39_mnemonic_to_bytes(
    const struct words *w,
    const char *mnemonic,
    unsigned char *bytes,
    size_t len);

/**
 * Validate the checksum embedded in the mnemonic sentence @mnemonic.
 * @w Word list to use. Pass NULL to use the default English list.
 * @mnemonic Mnemonic to validate.
 */
WALLY_CORE_API bool bip39_mnemonic_is_valid(const struct words *w,
                                            const char *mnemonic);

#endif /* LIBWALLY_CORE_BIP39_H */
