#ifndef LIBWALLY_CORE_BIP85_H
#define LIBWALLY_CORE_BIP85_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ext_key;

/**
 * Get the list of default supported languages.
 *
 * .. note:: The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int bip85_get_languages(
    char **output);

/**
 * Generate bip39 mnemonic entropy according to bip85.
 *
 * :param hdkey: The parent extended key to derive entropy from.
 * :param lang: The intended language. Pass NULL to use the default English value.
 * :param num_words: The intended number of words.  Must be 12, 18 or 24.
 * :param index: The index used to create the entropy. Must be less than
 *|    `BIP32_INITIAL_HARDENED_CHILD`.
 * :param bytes_out: Where to store the resulting entropy.
 * MAX_SIZED_OUTPUT(len, bytes_out, HMAC_SHA512_LEN)
 * :param written: Number of bytes in ``bytes_out`` to be used as entropy.
 */
WALLY_CORE_API int bip85_get_bip39_entropy(
    const struct ext_key *hdkey,
    const char *lang,
    uint32_t num_words,
    uint32_t index,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_BIP85_H */
