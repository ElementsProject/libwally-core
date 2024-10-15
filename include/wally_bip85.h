#ifndef LIBWALLY_CORE_BIP85_H
#define LIBWALLY_CORE_BIP85_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ext_key;

/**
 * Get the list of default supported languages for BIP85.
 *
 * .. note:: The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int bip85_get_languages(
    char **output);

/**
 * Generate BIP39 mnemonic entropy according to BIP85.
 *
 * :param hdkey: The parent extended key to derive mnemonic entropy from.
 * :param lang: The intended language. Pass NULL to use the default English value.
 * :param num_words: The intended number of words.  Must be 12, 18 or 24.
 * :param index: The index used to create the entropy. Must be less than
 *|    `BIP32_INITIAL_HARDENED_CHILD`.
 * :param bytes_out: Destination for the resulting entropy.
 * MAX_SIZED_OUTPUT(len, bytes_out, HMAC_SHA512_LEN)
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int bip85_get_bip39_entropy(
    const struct ext_key *hdkey,
    const char *lang,
    uint32_t num_words,
    uint32_t index,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Generate entropy for seeding RSA key generation according to BIP85.
 *
 * :param hdkey: The parent extended key to derive RSA entropy from.
 * :param key_bits: The intended RSA key size in bits.
 * :param index: The index used to create the entropy. Must be less than
 *|    `BIP32_INITIAL_HARDENED_CHILD`.
 * :param bytes_out: Destination for the resulting entropy.
 * MAX_SIZED_OUTPUT(len, bytes_out, HMAC_SHA512_LEN)
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 *
 * .. note:: This function always returns HMAC_SHA512_LEN bytes on success.
 *
 * .. note:: The returned entropy must be given to BIP85-DRNG in order
 *|    to derive the RSA key to use. It MUST NOT be used directly.
 */
WALLY_CORE_API int bip85_get_rsa_entropy(
    const struct ext_key *hdkey,
    uint32_t key_bits,
    uint32_t index,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_BIP85_H */
