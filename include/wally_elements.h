#ifndef LIBWALLY_CORE_ELEMENTS_H
#define LIBWALLY_CORE_ELEMENTS_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILD_ELEMENTS

#define ASSET_TAG_LEN 32 /** Length of an Asset Tag */

#define ASSET_GENERATOR_LEN 33 /** Length of an Asset Generator */

#define ASSET_COMMITMENT_LEN 33 /** Length of an Asset Value Commitment */

#define ASSET_RANGEPROOF_MAX_LEN 5134 /** Maximum length of an Asset Range Proof */

/**
 * Create a blinded Asset Generator from an Asset Tag and Asset Blinding Factor.
 *
 * :param asset: Asset Tag to create a blinding generator for.
 * :param asset_len: Length of ``asset`` in bytes. Must be ``ASSET_TAG_LEN``.
 * :param abf: Asset Blinding Factor (Random entropy to blind with).
 * :param abf_len: Length of ``abf`` in bytes. Must be ``ASSET_TAG_LEN``.
 * :param bytes_out: Destination for the resulting Asset Generator.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``ASSET_GENERATOR_LEN``.
 */
WALLY_CORE_API int wally_asset_generator_from_bytes(
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    unsigned char *bytes_out,
    size_t len);

WALLY_CORE_API int wally_asset_final_vbf(
    const uint64_t *values,
    size_t values_len,
    size_t num_inputs,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *vbf,
    size_t vbf_len,
    unsigned char *bytes_out,
    size_t len);

WALLY_CORE_API int wally_asset_value_commitment(
    uint64_t value,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *bytes_out,
    size_t len);

WALLY_CORE_API int wally_asset_rangeproof_with_nonce(
    uint64_t value,
    const unsigned char *nonce_hash,
    size_t nonce_hash_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *extra,
    size_t extra_len,
    const unsigned char *generator,
    size_t generator_len,
    uint64_t min_value,
    int exp,
    int min_bits,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

WALLY_CORE_API int wally_asset_rangeproof(
    uint64_t value,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *extra,
    size_t extra_len,
    const unsigned char *generator,
    size_t generator_len,
    uint64_t min_value,
    int exp,
    int min_bits,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

WALLY_CORE_API int wally_asset_surjectionproof_size(
    size_t num_inputs,
    size_t *written);

WALLY_CORE_API int wally_asset_surjectionproof(
    const unsigned char *output_asset,
    size_t output_asset_len,
    const unsigned char *output_abf,
    size_t output_abf_len,
    const unsigned char *output_generator,
    size_t output_generator_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

WALLY_CORE_API int wally_asset_unblind_with_nonce(
    const unsigned char *nonce_hash,
    size_t nonce_hash_len,
    const unsigned char *proof,
    size_t proof_len,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *extra,
    size_t extra_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *asset_out,
    size_t asset_out_len,
    unsigned char *abf_out,
    size_t abf_out_len,
    unsigned char *vbf_out,
    size_t vbf_out_len,
    uint64_t *value_out);

WALLY_CORE_API int wally_asset_unblind(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *proof,
    size_t proof_len,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *extra,
    size_t extra_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *asset_out,
    size_t asset_out_len,
    unsigned char *abf_out,
    size_t abf_out_len,
    unsigned char *vbf_out,
    size_t vbf_out_len,
    uint64_t *value_out);

WALLY_CORE_API int wally_asset_blinding_key_from_seed(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

WALLY_CORE_API int wally_asset_blinding_key_to_ec_private_key(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *script,
    size_t script_len,
    unsigned char *bytes_out,
    size_t len);

/*
 * Calculate the size in bytes of the whitelist proof.
 *
 * :param num_keys: The number of offline/online keys.
 * :param written: Destination for the number of bytes needed for the proof.
 */
WALLY_CORE_API int wally_asset_pak_whitelistproof_size(
    size_t num_keys,
    size_t *written);

/*
 * Generate the whitelist proof for the pegout script.
 *
 * :param online_keys: The list of online keys.
 * :param online_keys_len: Length of ``online_keys_len`` in bytes. Must be a multiple of ``EC_PUBLIC_KEY_LEN``.
 * :param offline_keys: The list of offline keys.
 * :param offline_keys_len: Length of ``offline_keys_len`` in bytes. Must be a multiple of ``EC_PUBLIC_KEY_LEN``.
 * :param sub_pubkey: The key to be whitelisted.
 * :param sub_pubkey_len: Length of ``sub_pubkey`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 * :param online_priv_key: The secret key to the signer's online pubkey.
 * :param online_priv_key_len: Length of ``online_priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param summed_key: The secret key to the sum of (whitelisted key, signer's offline pubkey).
 * :param summed_key_len: Length of ``summed_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param bytes_out: Destination for the resulting whitelist proof.
 * :param len: Length of ``bytes_out`` in bytes.
 */
WALLY_CORE_API int wally_asset_pak_whitelistproof(
    const unsigned char *online_keys,
    size_t online_keys_len,
    const unsigned char *offline_keys,
    size_t offline_keys_len,
    size_t key_index,
    const unsigned char *sub_pubkey,
    size_t sub_pubkey_len,
    const unsigned char *online_priv_key,
    size_t online_priv_key_len,
    const unsigned char *summed_key,
    size_t summed_key_len,
    unsigned char *bytes_out,
    size_t len);

#endif /* BUILD_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_ELEMENTS_H */
