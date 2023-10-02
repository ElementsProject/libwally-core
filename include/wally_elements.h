#ifndef LIBWALLY_CORE_ELEMENTS_H
#define LIBWALLY_CORE_ELEMENTS_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ASSET_TAG_LEN 32 /** Length of an Asset Tag */

#define BLINDING_FACTOR_LEN 32 /** Length of a Blinding Factor (or blinder) */

#define ASSET_GENERATOR_LEN 33 /** Length of an Asset Generator */

#define ASSET_COMMITMENT_LEN 33 /** Length of an Asset Value Commitment */

#define ASSET_RANGEPROOF_MAX_LEN 5134 /** Maximum length of an Asset Value Range Proof */
#define ASSET_EXPLICIT_RANGEPROOF_MAX_LEN 73 /** Maximum length of an Explicit Asset Value Range Proof */

/* Size of proof with 256 inputs and 3 used inputs */
#define ASSET_SURJECTIONPROOF_MAX_LEN 162 /** Maximum length of a wally-produced Asset Surjection Proof */
#define ASSET_EXPLICIT_SURJECTIONPROOF_LEN 67 /** Length of an Explicit Asset Surjection Proof */

#ifndef WALLY_ABI_NO_ELEMENTS
/**
 * Create an Asset Generator from an either an asset commitment or asset tag plus blinding factor.
 *
 * :param asset: Asset Commitment or Tag to create a generator for.
 * :param asset_len: Length of ``asset`` in bytes. Must be `ASSET_COMMITMENT_LEN` or `ASSET_TAG_LEN`.
 * :param abf: Asset Blinding Factor (Random entropy to blind with). Must be NULL when ``asset`` is a commitment.
 * :param abf_len: Length of ``abf`` in bytes. Must be `BLINDING_FACTOR_LEN` if ``abf`` is non-NULL.
 * :param bytes_out: Destination for the resulting Asset Generator.
 * FIXED_SIZED_OUTPUT(len, bytes_out, ASSET_GENERATOR_LEN)
 */
WALLY_CORE_API int wally_asset_generator_from_bytes(
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Generate a rangeproof nonce hash via SHA256(ECDH(pub_key, priv_key).
 *
 * :param pub_key: Public blinding key.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_LEN`
 * :param priv_key: Ephemeral (randomly generated) private key.
 * :param priv_key_len: Length of ``priv_key`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param bytes_out: Destination for the resulting nonce hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 *
 * .. note:: The public blinding key can be retrieved from a confidential
 *|    address using `wally_confidential_addr_to_ec_public_key`. If ``priv_key``
 *|    is invalid, then `WALLY_ERROR` is returned.
 * .. note:: The computation can also be performed with the private key
 *|    corresponding to ``pub_key`` and the public key corresponding
 *|    to ``priv_key`` giving the same result.
 */
WALLY_CORE_API int wally_ecdh_nonce_hash(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Generate the final value blinding factor required for blinding a confidential transaction.
 *
 * :param values: Array of values in satoshi
 * :param num_values: Length of ``values``, also the number of elements in all three of the input arrays, which is equal
 *|     to ``num_inputs`` plus the number of outputs.
 * :param num_inputs: Number of elements in the input arrays that represent inputs. The number of outputs is
 *|     implicitly ``num_values`` - ``num_inputs``.
 * :param abf:  Array of bytes representing ``num_values`` asset blinding factors.
 * :param abf_len: Length of ``abf`` in bytes. Must be ``num_values`` * `BLINDING_FACTOR_LEN`.
 * :param vbf: Array of bytes representing (``num_values`` - 1) value blinding factors.
 * :param vbf_len: Length of ``vbf`` in bytes. Must be (``num_values`` - 1) * `BLINDING_FACTOR_LEN`.
 * :param bytes_out: Buffer to receive the final value blinding factor.
 * FIXED_SIZED_OUTPUT(len, bytes_out, BLINDING_FACTOR_LEN)
 */
WALLY_CORE_API int wally_asset_final_vbf(
    const uint64_t *values,
    size_t num_values,
    size_t num_inputs,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *vbf,
    size_t vbf_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Compute the scalar offset used for blinding a confidential transaction.
 *
 * :param value: The value in satoshi.
 * :param abf: Asset blinding factor.
 * :param abf_len: Length of ``abf``. Must be `BLINDING_FACTOR_LEN`.
 * :param vbf: Value blinding factor.
 * :param vbf_len: Length of ``vbf``. Must be `BLINDING_FACTOR_LEN`.
 * :param bytes_out: Destination to receive the scalar offset.
 * FIXED_SIZED_OUTPUT(len, bytes_out, EC_SCALAR_LEN)
 */
WALLY_CORE_API int wally_asset_scalar_offset(
    uint64_t value,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *vbf,
    size_t vbf_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Calculate a value commitment.
 *
 * :param value: Output value in satoshi.
 * :param vbf: Value Blinding Factor.
 * :param vbf_len: Length of ``vbf``. Must be `BLINDING_FACTOR_LEN`.
 * :param generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param generator_len: Length of ``generator``. Must be `ASSET_GENERATOR_LEN`.
 * :param bytes_out: Buffer to receive value commitment.
 * FIXED_SIZED_OUTPUT(len, bytes_out, ASSET_COMMITMENT_LEN)
 */
WALLY_CORE_API int wally_asset_value_commitment(
    uint64_t value,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Calculate the maximum size of a rangeproof.
 *
 * :param value: The maximum possible value of the output in satoshi.
 * :param min_bits: The min_bits value that will be passed to `wally_asset_rangeproof`.
 * :param written: Destination for the maximum rangeproof size in bytes.
 */
WALLY_CORE_API int wally_asset_rangeproof_get_maximum_len(
    uint64_t value,
    int min_bits,
    size_t *written);

/**
 * Generate a rangeproof using a nonce.
 *
 * :param value: Value of the output in satoshi.
 * :param nonce_hash: Nonce for rangeproof generation, usually from `wally_ecdh_nonce_hash`.
 * :param nonce_hash_len: Length of ``nonce_hash``. Must be `SHA256_LEN`.
 * :param asset: Asset id of output.
 * :param asset_len: Length of ``asset``. Must be `ASSET_TAG_LEN`.
 * :param abf: Asset blinding factor. Randomly generated for each output.
 * :param abf_len: Length of ``abf``. Must be `BLINDING_FACTOR_LEN`.
 * :param vbf: Value blinding factor. Randomly generated for each output except the last, which is generate by calling
 *|     `wally_asset_final_vbf`.
 * :param vbf_len: Length of ``vbf``. Must be `BLINDING_FACTOR_LEN`.
 * :param commitment: Value commitment from `wally_asset_value_commitment`.
 * :param commitment_len: Length of ``commitment``. Must be `ASSET_COMMITMENT_LEN`.
 * :param extra: Set this to the scriptPubkey of the output.
 * :param extra_len: Length of ``extra``, i.e. scriptPubkey.
 * :param generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param generator_len: Length of ``generator``. Must be `ASSET_GENERATOR_LEN`.
 * :param min_value: Recommended value 1.
 * :param exp: Exponent value. -1 >= ``exp`` >= 18. Recommended value 0.
 * :param min_bits: 0 >= min_bits >= 64. Recommended value 52.
 * :param bytes_out: Buffer to receive rangeproof.
 * MAX_SIZED_OUTPUT(len, bytes_out, ASSET_RANGEPROOF_MAX_LEN)
 * :param written: Number of bytes actually written to ``bytes_out``.
 */
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

/**
 * Generate a rangeproof.
 *
 * This convenience function generates a nonce hash with `wally_ecdh_nonce_hash`
 * and then calls `wally_asset_rangeproof_with_nonce`.
 *
 * MAX_SIZED_OUTPUT(len, bytes_out, ASSET_RANGEPROOF_MAX_LEN)
 */
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

/**
 * Generate an explicit value rangeproof.
 *
 * The nonce for this function should be randomly generated.
 * See `wally_asset_rangeproof_with_nonce`.
 *
 * MAX_SIZED_OUTPUT(len, bytes_out, ASSET_EXPLICIT_RANGEPROOF_MAX_LEN)
 */
WALLY_CORE_API int wally_explicit_rangeproof(
    uint64_t value,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Verify an explicit value rangeproof proves a given value.
 *
 * :param rangeproof: The explicit value rangeproof to validate.
 * :param rangeproof_len: Length of ``rangeproof`` in bytes.
 * :param value: The expected value that the explicit rangeproof proves.
 * :param commitment: Value commitment from `wally_asset_value_commitment`.
 * :param commitment_len: Length of ``commitment``. Must be `ASSET_COMMITMENT_LEN`.
 * :param generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param generator_len: Length of ``generator``. Must be `ASSET_GENERATOR_LEN`.
 */
WALLY_CORE_API int wally_explicit_rangeproof_verify(
    const unsigned char *rangeproof,
    size_t rangeproof_len,
    uint64_t value,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *generator,
    size_t generator_len);

/**
 * Return the required buffer size for receiving a surjection proof
 *
 * :param num_inputs: Number of inputs.
 * :param written: Destination for the surjection proof size.
 */
WALLY_CORE_API int wally_asset_surjectionproof_size(
    size_t num_inputs,
    size_t *written);

/**
 * Compute the length of an asset surjection proof.
 *
 * :param output_asset: asset id for the output.
 * :param output_asset_len: Length of ``asset``. Must be `ASSET_TAG_LEN`.
 * :param output_abf: Asset blinding factor for the output. Generated randomly for each output.
 * :param output_abf_len: Length of ``output_abf``. Must be `BLINDING_FACTOR_LEN`.
 * :param output_generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param output_generator_len: Length of ``output_generator``. Must be `ASSET_GENERATOR_LEN`.
 * :param bytes: Must be generated randomly for each output.
 * :param bytes_len: Length of ``bytes``. Must be 32.
 * :param asset: Array of input asset tags.
 * :param asset_len: Length of ``asset``. Must be `ASSET_TAG_LEN` * number of inputs.
 * :param abf: Array of input asset blinding factors.
 * :param abf_len: Length of ``abf``. Must be `BLINDING_FACTOR_LEN` * number of inputs.
 * :param generator: Array of input asset generators.
 * :param generator_len: Length of ``generator``. Must be `ASSET_GENERATOR_LEN` * number of inputs.
 * :param written: Number of bytes actually written to ``bytes_out``.
 */
WALLY_CORE_API int wally_asset_surjectionproof_len(
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
    size_t *written);

/**
 * Generate an asset surjection proof.
 *
 * :param output_asset: asset id for the output.
 * :param output_asset_len: Length of ``asset``. Must be `ASSET_TAG_LEN`.
 * :param output_abf: Asset blinding factor for the output. Generated randomly for each output.
 * :param output_abf_len: Length of ``output_abf``. Must be `BLINDING_FACTOR_LEN`.
 * :param output_generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param output_generator_len: Length of ``output_generator``. Must be `ASSET_GENERATOR_LEN`.
 * :param bytes: Must be generated randomly for each output.
 * :param bytes_len: Length of ``bytes``. Must be 32.
 * :param asset: Array of input asset tags.
 * :param asset_len: Length of ``asset``. Must be `ASSET_TAG_LEN` * number of inputs.
 * :param abf: Array of input asset blinding factors.
 * :param abf_len: Length of ``abf``. Must be `BLINDING_FACTOR_LEN` * number of inputs.
 * :param generator: Array of input asset generators.
 * :param generator_len: Length of ``generator``. Must be `ASSET_GENERATOR_LEN` * number of inputs.
 * :param bytes_out: Buffer to receive surjection proof.
 * :param len: Length of ``bytes_out``. See `wally_asset_surjectionproof_len`.
 * :param written: Number of bytes actually written to ``bytes_out``.
 */
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

/**
 * Generate an explicit asset surjection proof.
 *
 * :param output_asset: asset id for the output.
 * :param output_asset_len: Length of ``asset``. Must be `ASSET_TAG_LEN`.
 * :param output_abf: Asset blinding factor for the output. Generated randomly for each output.
 * :param output_abf_len: Length of ``output_abf``. Must be `BLINDING_FACTOR_LEN`.
 * :param output_generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param output_generator_len: Length of ``output_generator``. Must be `ASSET_GENERATOR_LEN`.
 * :param bytes_out: Buffer to receive surjection proof.
 * FIXED_SIZED_OUTPUT(len, bytes_out, ASSET_EXPLICIT_SURJECTIONPROOF_LEN)
 */
WALLY_CORE_API int wally_explicit_surjectionproof(
    const unsigned char *output_asset,
    size_t output_asset_len,
    const unsigned char *output_abf,
    size_t output_abf_len,
    const unsigned char *output_generator,
    size_t output_generator_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Verify an explicit asset surjection proof proves a given asset.
 *
 * :param surjectionproof: The explicit asset surjection proof.
 * :param surjectionproof_len: Length of ``surjectionproof``.
 * :param output_asset: The unblinded asset we expect ``surjectionproof`` to prove.
 * :param output_asset_len: Length of ``asset``. Must be `ASSET_TAG_LEN`.
 * :param output_generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param output_generator_len: Length of ``output_generator``. Must be `ASSET_GENERATOR_LEN`.
 */
WALLY_CORE_API int wally_explicit_surjectionproof_verify(
    const unsigned char *surjectionproof,
    size_t surjectionproof_len,
    const unsigned char *output_asset,
    size_t output_asset_len,
    const unsigned char *output_generator,
    size_t output_generator_len);

/**
 * Unblind a confidential transaction output.
 *
 * :param nonce_hash: SHA-256 hash of the generated nonce.
 * :param nonce_hash_len: Length of ``nonce_hash``. Must be `SHA256_LEN`.
 * :param proof: Rangeproof from `wally_tx_get_output_rangeproof`.
 * :param proof_len: Length of ``proof``.
 * :param commitment: Value commitment from `wally_tx_get_output_value`.
 * :param commitment_len: Length of ``commitment``.
 * :param extra: scriptPubkey from `wally_tx_get_output_script`.
 * :param extra_len: Length of ``extra``.
 * :param generator: Asset generator from `wally_tx_get_output_asset`.
 * :param generator_len: Length of ``generator``. Must be `ASSET_GENERATOR_LEN`.
 * :param asset_out: Buffer to receive unblinded asset id.
 * FIXED_SIZED_OUTPUT(asset_out_len, asset_out, ASSET_TAG_LEN)
 * :param abf_out: Buffer to receive asset blinding factor.
 * FIXED_SIZED_OUTPUT(abf_out_len, abf_out, BLINDING_FACTOR_LEN)
 * :param vbf_out: Buffer to receive asset blinding factor.
 * FIXED_SIZED_OUTPUT(vbf_out_len, vbf_out, BLINDING_FACTOR_LEN)
 * :param value_out: Destination for unblinded transaction output value.
 */
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

/**
 * Unblind a confidential transaction output.
 *
 * :param pub_key: From `wally_tx_get_output_nonce`.
 * :param pub_key_len: Length of ``pub_key``. Must be `EC_PUBLIC_KEY_LEN`.
 * :param priv_key: Private blinding key corresponding to public blinding key used to generate destination address. See
 *|     `wally_asset_blinding_key_to_ec_private_key`.
 * :param proof: Rangeproof from `wally_tx_get_output_rangeproof`.
 * :param proof_len: Length of ``proof``.
 * :param commitment: Value commitment from `wally_tx_get_output_value`.
 * :param commitment_len: Length of ``commitment``.
 * :param extra: scriptPubkey from `wally_tx_get_output_script`.
 * :param extra_len: Length of ``extra``.
 * :param generator: Asset generator from `wally_tx_get_output_asset`.
 * :param generator_len: Length of ``generator``. Must be `ASSET_GENERATOR_LEN`.
 * :param asset_out: Buffer to receive unblinded asset id.
 * FIXED_SIZED_OUTPUT(asset_out_len, asset_out, ASSET_TAG_LEN)
 * :param abf_out: Buffer to receive asset blinding factor.
 * FIXED_SIZED_OUTPUT(abf_out_len, abf_out, BLINDING_FACTOR_LEN)
 * :param vbf_out: Buffer to receive asset blinding factor.
 * FIXED_SIZED_OUTPUT(vbf_out_len, vbf_out, BLINDING_FACTOR_LEN)
 * :param value_out: Destination for unblinded transaction output value.
 */
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

/**
 * Generate a master blinding key from a seed as specified in SLIP-0077.
 *
 * :param bytes: Seed value. See `bip39_mnemonic_to_seed`.
 * :param bytes_len: Length of ``bytes``. Must be one of `BIP32_ENTROPY_LEN_128`, `BIP32_ENTROPY_LEN_256` or
 *|     `BIP32_ENTROPY_LEN_512`.
 * :param bytes_out: Buffer to receive master blinding key. The master blinding key can be used to generate blinding
 *|     keys for specific outputs by passing it to `wally_asset_blinding_key_to_ec_private_key`.
 * FIXED_SIZED_OUTPUT(len, bytes_out, HMAC_SHA512_LEN)
 */
WALLY_CORE_API int wally_asset_blinding_key_from_seed(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Generate a blinding private key for a scriptPubkey.
 *
 * :param bytes: A full master blinding key, e.g. from `wally_asset_blinding_key_from_seed`,
 *|    or a partial key of length `SHA256_LEN`, typically from the last half of the full key.
 * :param bytes_len: Length of ``bytes``. Must be `HMAC_SHA512_LEN` or `SHA256_LEN`.
 * :param script: The scriptPubkey for the confidential output address.
 * :param script_len: Length of ``script``.
 * :param bytes_out: Destination for the resulting blinding private key.
 * FIXED_SIZED_OUTPUT(len, bytes_out, EC_PRIVATE_KEY_LEN)
 */
WALLY_CORE_API int wally_asset_blinding_key_to_ec_private_key(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *script,
    size_t script_len,
    unsigned char *bytes_out,
    size_t len);

#define WALLY_ABF_VBF_LEN 64

/**
 * Generate asset and value blinding factors for a transaction output.
 *
 * :param bytes: A full master blinding key, e.g. from `wally_asset_blinding_key_from_seed`,
 *|    or a partial key of length `SHA256_LEN`, typically from the last half of the full key.
 * :param bytes_len: Length of ``bytes``. Must be `HMAC_SHA512_LEN` or `SHA256_LEN`.
 * :param hash_prevouts: The hashPrevouts of the transaction from `wally_get_hash_prevouts`.
 * :param hash_prevouts_len: Length of ``hash_prevouts`` in bytes. Must be `SHA256_LEN`.
 * :param output_index: The zero-based index of the transaction output to be blinded.
 * :param bytes_out: Destination for the concatenated asset and value blinding factors.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_ABF_VBF_LEN)
 */
WALLY_CORE_API int wally_asset_blinding_key_to_abf_vbf(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *hash_prevouts,
    size_t hash_prevouts_len,
    uint32_t output_index,
    unsigned char *bytes_out,
    size_t len);

/**
 * Generate an asset blinding factor for a transaction output.
 *
 * :param bytes: A full master blinding key, e.g. from `wally_asset_blinding_key_from_seed`,
 *|    or a partial key of length `SHA256_LEN`, typically from the last half of the full key.
 * :param bytes_len: Length of ``bytes``. Must be `HMAC_SHA512_LEN` or `SHA256_LEN`.
 * :param hash_prevouts: The hashPrevouts of the transaction from `wally_get_hash_prevouts`.
 * :param hash_prevouts_len: Length of ``hash_prevouts`` in bytes. Must be `SHA256_LEN`.
 * :param output_index: The zero-based index of the transaction output to be blinded.
 * :param bytes_out: Destination for the resulting asset blinding factor.
 * FIXED_SIZED_OUTPUT(len, bytes_out, BLINDING_FACTOR_LEN)
 */
WALLY_CORE_API int wally_asset_blinding_key_to_abf(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *hash_prevouts,
    size_t hash_prevouts_len,
    uint32_t output_index,
    unsigned char *bytes_out,
    size_t len);

/**
 * Generate a value blinding factor for a transaction output.
 *
 * :param bytes: A full master blinding key, e.g. from `wally_asset_blinding_key_from_seed`,
 *|    or a partial key of length `SHA256_LEN`, typically from the last half of the full key.
 * :param bytes_len: Length of ``bytes``. Must be `HMAC_SHA512_LEN` or `SHA256_LEN`.
 * :param hash_prevouts: The hashPrevouts of the transaction from `wally_get_hash_prevouts`.
 * :param hash_prevouts_len: Length of ``hash_prevouts`` in bytes. Must be `SHA256_LEN`.
 * :param output_index: The zero-based index of the transaction output to be blinded.
 * :param bytes_out: Destination for the resulting value blinding factor.
 * FIXED_SIZED_OUTPUT(len, bytes_out, BLINDING_FACTOR_LEN)
 */
WALLY_CORE_API int wally_asset_blinding_key_to_vbf(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *hash_prevouts,
    size_t hash_prevouts_len,
    uint32_t output_index,
    unsigned char *bytes_out,
    size_t len);

/**
 * Calculate the size in bytes of a whitelist proof.
 *
 * :param num_keys: The number of offline/online keys.
 * :param written: Destination for the number of bytes needed for the proof.
 *
 * .. note:: This function is a simpler variant of `wally_asset_pak_whitelistproof_len`.
 */
WALLY_CORE_API int wally_asset_pak_whitelistproof_size(
    size_t num_keys,
    size_t *written);

/**
 * Generate a whitelist proof for a pegout script.
 *
 * :param online_keys: The list of concatenated online keys.
 * :param online_keys_len: Length of ``online_keys`` in bytes. Must be a multiple of `EC_PUBLIC_KEY_LEN`.
 * :param offline_keys: The list of concatenated offline keys.
 * :param offline_keys_len: Length of ``offline_keys`` in bytes. Must match ``online_keys_len``.
 * :param key_index: The index in the PAK list of the key signing this whitelist proof.
 * :param sub_pubkey: The public key to be whitelisted.
 * :param sub_pubkey_len: Length of ``sub_pubkey`` in bytes. Must be `EC_PUBLIC_KEY_LEN`.
 * :param online_priv_key: The secret key to the signer's online pubkey.
 * :param online_priv_key_len: Length of ``online_priv_key`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param summed_key: The secret key to the sum of (whitelisted key, signer's offline pubkey).
 * :param summed_key_len: Length of ``summed_key`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param bytes_out: Destination for the resulting whitelist proof.
 * :param len: Length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
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
    size_t len,
    size_t *written);

/**
 * Calculate the size in bytes of a whitelist proof.
 *
 * :param online_keys: The list of concatenated online keys.
 * :param online_keys_len: Length of ``online_keys`` in bytes. Must be a multiple of `EC_PUBLIC_KEY_LEN`.
 * :param offline_keys: The list of concatenated offline keys.
 * :param offline_keys_len: Length of ``offline_keys`` in bytes. Must match ``online_keys_len``.
 * :param key_index: The index in the PAK list of the key signing this whitelist proof.
 * :param sub_pubkey: The public key to be whitelisted.
 * :param sub_pubkey_len: Length of ``sub_pubkey`` in bytes. Must be `EC_PUBLIC_KEY_LEN`.
 * :param online_priv_key: The secret key to the signer's online pubkey.
 * :param online_priv_key_len: Length of ``online_priv_key`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param summed_key: The secret key to the sum of (whitelisted key, signer's offline pubkey).
 * :param summed_key_len: Length of ``summed_key`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param written: Destination for resulting proof size in bytes.
 *
 * .. note:: Use `wally_asset_pak_whitelistproof_size` for a simpler call interface.
 */
WALLY_CORE_API int wally_asset_pak_whitelistproof_len(
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
    size_t *written);

#endif /* WALLY_ABI_NO_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_ELEMENTS_H */
