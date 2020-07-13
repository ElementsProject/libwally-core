#ifndef LIBWALLY_CORE_PSBT_H
#define LIBWALLY_CORE_PSBT_H

#include "wally_transaction.h"
#include "wally_bip32.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WALLY_PSBT_SEPARATOR 0x00

/* The proprietary type is the same for all scopes */
#define WALLY_PSBT_PROPRIETARY_TYPE 0xFC

#define WALLY_PSBT_GLOBAL_UNSIGNED_TX 0x00
#define WALLY_PSBT_GLOBAL_VERSION 0xFB

#define WALLY_PSBT_IN_NON_WITNESS_UTXO 0x00
#define WALLY_PSBT_IN_WITNESS_UTXO 0x01
#define WALLY_PSBT_IN_PARTIAL_SIG 0x02
#define WALLY_PSBT_IN_SIGHASH_TYPE 0x03
#define WALLY_PSBT_IN_REDEEM_SCRIPT 0x04
#define WALLY_PSBT_IN_WITNESS_SCRIPT 0x05
#define WALLY_PSBT_IN_BIP32_DERIVATION 0x06
#define WALLY_PSBT_IN_FINAL_SCRIPTSIG 0x07
#define WALLY_PSBT_IN_FINAL_SCRIPTWITNESS 0x08

#ifdef BUILD_ELEMENTS
#define WALLY_PSBT_IN_ELEMENTS_VALUE 0x00
#define WALLY_PSBT_IN_ELEMENTS_VALUE_BLINDER 0x01
#define WALLY_PSBT_IN_ELEMENTS_ASSET 0x02
#define WALLY_PSBT_IN_ELEMENTS_ASSET_BLINDER 0x03
#define WALLY_PSBT_IN_ELEMENTS_PEG_IN_TX 0x04
#define WALLY_PSBT_IN_ELEMENTS_TXOUT_PROOF 0x05
#define WALLY_PSBT_IN_ELEMENTS_GENESIS_HASH 0x06
#define WALLY_PSBT_IN_ELEMENTS_CLAIM_SCRIPT 0x07
#endif /* BUILD ELEMENTS */

#define WALLY_PSBT_OUT_REDEEM_SCRIPT 0x00
#define WALLY_PSBT_OUT_WITNESS_SCRIPT 0x01
#define WALLY_PSBT_OUT_BIP32_DERIVATION 0x02

#ifdef BUILD_ELEMENTS
#define WALLY_PSBT_OUT_ELEMENTS_VALUE_COMMITMENT 0x00
#define WALLY_PSBT_OUT_ELEMENTS_VALUE_BLINDER 0x01
#define WALLY_PSBT_OUT_ELEMENTS_ASSET_COMMITMENT 0x02
#define WALLY_PSBT_OUT_ELEMENTS_ASSET_BLINDER 0x03
#define WALLY_PSBT_OUT_ELEMENTS_RANGE_PROOF 0x04
#define WALLY_PSBT_OUT_ELEMENTS_SURJECTION_PROOF 0x05
#define WALLY_PSBT_OUT_ELEMENTS_BLINDING_PUBKEY 0x06
#define WALLY_PSBT_OUT_ELEMENTS_NONCE_COMMITMENT 0x07
#endif /* BUILD ELEMENTS */

/* PSBT Version number */
#define WALLY_PSBT_HIGHEST_VERSION 0

#ifdef SWIG
struct wally_keypath_map;
struct wally_partial_sigs_map;
struct wally_unknowns_map;
struct wally_psbt_input;
struct wally_psbt_output;
struct wally_psbt;
#else

/** A BIP 32 path and fingerprint with associated public key */
struct wally_keypath_item {
    uint32_t *path;
    size_t path_len;
    unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
};

/** A map of public keys to BIP 32 fingerprint and derivation paths */
struct wally_keypath_map {
    struct wally_keypath_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** A signature with associated public key */
struct wally_partial_sigs_item {
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    unsigned char *sig;
    size_t sig_len;
};

/** A map of public keys to signatures */
struct wally_partial_sigs_map {
    struct wally_partial_sigs_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** Unknown item */
struct wally_unknowns_item {
    unsigned char *key;
    size_t key_len;
    unsigned char *value;
    size_t value_len;
};

/** A map of unknown key,value pairs */
struct wally_unknowns_map {
    struct wally_unknowns_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** A PSBT input */
struct wally_psbt_input {
    struct wally_tx *non_witness_utxo;
    struct wally_tx_output *witness_utxo;
    unsigned char *redeem_script;
    size_t redeem_script_len;
    unsigned char *witness_script;
    size_t witness_script_len;
    unsigned char *final_script_sig;
    size_t final_script_sig_len;
    struct wally_tx_witness_stack *final_witness;
    struct wally_keypath_map *keypaths;
    struct wally_partial_sigs_map *partial_sigs;
    struct wally_unknowns_map *unknowns;
    uint32_t sighash_type;
#ifdef BUILD_ELEMENTS
    uint64_t value;
    uint32_t has_value;
    unsigned char *value_blinder;
    size_t value_blinder_len;
    unsigned char *asset;
    size_t asset_len;
    unsigned char *asset_blinder;
    size_t asset_blinder_len;
    struct wally_tx *peg_in_tx;
    unsigned char *txout_proof;
    size_t txout_proof_len;
    unsigned char *genesis_hash;
    size_t genesis_hash_len;
    unsigned char *claim_script;
    size_t claim_script_len;
#endif /* BUILD_ELEMENTS */
};

/** A PSBT output map */
struct wally_psbt_output {
    unsigned char *redeem_script;
    size_t redeem_script_len;
    unsigned char *witness_script;
    size_t witness_script_len;
    struct wally_keypath_map *keypaths;
    struct wally_unknowns_map *unknowns;
#ifdef BUILD_ELEMENTS
    unsigned char *blinding_pubkey;
    size_t blinding_pubkey_len;
    unsigned char *value_commitment;
    size_t value_commitment_len;
    unsigned char *value_blinder;
    size_t value_blinder_len;
    unsigned char *asset_commitment;
    size_t asset_commitment_len;
    unsigned char *asset_blinder;
    size_t asset_blinder_len;
    unsigned char *nonce_commitment;
    size_t nonce_commitment_len;
    unsigned char *range_proof;
    size_t range_proof_len;
    unsigned char *surjection_proof;
    size_t surjection_proof_len;
#endif /* BUILD_ELEMENTS */
};

/** A partially signed bitcoin transaction */
struct wally_psbt {
    unsigned char magic[5];
    struct wally_tx *tx;
    struct wally_psbt_input *inputs;
    size_t num_inputs;
    size_t inputs_allocation_len;
    struct wally_psbt_output *outputs;
    size_t num_outputs;
    size_t outputs_allocation_len;
    struct wally_unknowns_map *unknowns;
    uint32_t version;
};
#endif /* SWIG */

/**
 * Allocate and initialize a new keypath map.
 *
 * :param allocation_len: The number of items to allocate.
 * :param output: Destination for the new keypath map.
 */
WALLY_CORE_API int wally_keypath_map_init_alloc(
    size_t allocation_len,
    struct wally_keypath_map **output);

#ifndef SWIG_PYTHON
/**
 * Free a keypath map allocated by `wally_keypath_map_init_alloc`.
 *
 * :param keypaths: The keypath map to free.
 */
WALLY_CORE_API int wally_keypath_map_free(
    struct wally_keypath_map *keypaths);
#endif /* SWIG_PYTHON */


/**
 * Find an item in a keypath map.
 *
 * :param keypaths: The keypath map to find ``pubkey`` in.
 * :param pubkey: The pubkey to find.
 * :param pubkey_len: Length of ``pubkey`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_keypath_map_find(
    const struct wally_keypath_map *keypaths,
    const unsigned char *pubkey,
    size_t pubkey_len,
    size_t *written);

/**
 * Add an item to a keypath map.
 *
 * :param keypaths: The keypath map to add to.
 * :param pubkey: The pubkey to add.
 * :param pubkey_len: Length of ``pubkey`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be ``BIP32_KEY_FINGERPRINT_LEN``.
 * :param path: The BIP32 derivation path for the pubkey.
 * :param path_len: The number of items in path.
 */
WALLY_CORE_API int wally_keypath_map_add(
    struct wally_keypath_map *keypaths,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *path,
    size_t path_len);

/**
 * Allocate and initialize a new partial sigs map.
 *
 * :param allocation_len: The number of items to allocate.
 * :param output: Destination for the new partial sigs map.
 */
WALLY_CORE_API int wally_partial_sigs_map_init_alloc(
    size_t allocation_len,
    struct wally_partial_sigs_map **output);

#ifndef SWIG_PYTHON
/**
 * Free a partial sigs map allocated by `wally_partial_sigs_map_init_alloc`.
 *
 * :param sigs: The partial sigs map to free.
 */
WALLY_CORE_API int wally_partial_sigs_map_free(
    struct wally_partial_sigs_map *sigs);
#endif /* SWIG_PYTHON */

/**
 * Find an item in a partial sigs map.
 *
 * :param sigs: The partial sigs map to find ``pubkey`` in.
 * :param pubkey: The pubkey to find.
 * :param pubkey_len: Length of ``pubkey`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_partial_sigs_map_find(
    const struct wally_partial_sigs_map *sigs,
    const unsigned char *pubkey,
    size_t pubkey_len,
    size_t *written);

/**
 * Add an item to a partial sigs map.
 *
 * :param sigs: The partial sigs map to add to.
 * :param pubkey: The pubkey to add.
 * :param pubkey_len: Length of ``pubkey`` in bytes. Must be ``EC_PUBLIC_KEY_LEN`` or ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN``
 * :param sig: The DER-encoded signature to add.
 * :param sig_len: Length of ``sig`` in bytes.
 */
WALLY_CORE_API int wally_partial_sigs_map_add(
    struct wally_partial_sigs_map *sigs,
    const unsigned char *pubkey,
    size_t pubkey_len,
    const unsigned char *sig,
    size_t sig_len);

/**
 * Allocate and initialize a new unknowns map.
 *
 * :param allocation_len: The number of items to allocate.
 * :param output: Destination for the new unknowns map.
 */
WALLY_CORE_API int wally_unknowns_map_init_alloc(
    size_t allocation_len,
    struct wally_unknowns_map **output);

#ifndef SWIG_PYTHON
/**
 * Free an unknowns map allocated by `wally_unknowns_map_init_alloc`.
 *
 * :param unknowns: The unknowns map to free.
 */
WALLY_CORE_API int wally_unknowns_map_free(
    struct wally_unknowns_map *unknowns);
#endif /* SWIG_PYTHON */

/**
 * Find an item in an unknowns map.
 *
 * :param unknowns: The unknowns map to find ``key`` in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_keypath_map_find(
    const struct wally_keypath_map *keypaths,
    const unsigned char *pubkey,
    size_t pubkey_len,
    size_t *written);

/**
 * Add an item to an unknowns map.
 *
 * :param unknowns: The unknowns map to add to.
 * :param key: The key to add.
 * :param key_len: Length of ``key`` in bytes.
 * :param value: The value to add.
 * :param value_len: Length of ``value`` in bytes.
 */
WALLY_CORE_API int wally_unknowns_map_add(
    struct wally_unknowns_map *unknowns,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *value,
    size_t value_len);

/**
 * Allocate and initialize a new PSBT input.
 *
 * :param non_witness_utxo: The non witness utxo for this input if it exists.
 * :param witness_utxo: The witness utxo for this input if it exists.
 * :param redeem_script: The redeem script for this input.
 * :param redeem_script_len: Length of ``redeem_script`` in bytes.
 * :param witness_script: The witness script for this input.
 * :param witness_script_len: Length of ``witness_script`` in bytes.
 * :param final_script_sig: The scriptSig for this input.
 * :param final_script_sig_len: Length of ``final_script_sig`` in bytes.
 * :param final_witness: The witness stack for the input, or NULL if no witness is present.
 * :param keypaths: The HD keypaths for this input.
 * :param partial_sigs: The partial signatures for this input.
 * :param unknowns: The unknown key value pairs for this input.
 * :param sighash_type: The sighash type for this input.
 * :param output: Destination for the resulting PSBT input.
 */
WALLY_CORE_API int wally_psbt_input_init_alloc(
    const struct wally_tx *non_witness_utxo,
    const struct wally_tx_output *witness_utxo,
    const unsigned char *redeem_script,
    size_t redeem_script_len,
    const unsigned char *witness_script,
    size_t witness_script_len,
    const unsigned char *final_script_sig,
    size_t final_script_sig_len,
    const struct wally_tx_witness_stack *final_witness,
    const struct wally_keypath_map *keypaths,
    const struct wally_partial_sigs_map *partial_sigs,
    const struct wally_unknowns_map *unknowns,
    uint32_t sighash_type,
    struct wally_psbt_input **output);

/**
 * Set the non_witness_utxo in an input.
 *
 * :param input: The input to update.
 * :param non_witness_utxo: The non witness utxo for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_input_set_non_witness_utxo(
    struct wally_psbt_input *input,
    const struct wally_tx *non_witness_utxo);

/**
 * Set the witness_utxo in an input.
 *
 * :param input: The input to update.
 * :param witness_utxo: The witness utxo for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_input_set_witness_utxo(
    struct wally_psbt_input *input,
    const struct wally_tx_output *witness_utxo);

/**
 * Set the redeem_script in an input.
 *
 * :param input: The input to update.
 * :param redeem_script: The redeem script for this input.
 * :param redeem_script_len: Length of ``redeem_script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_redeem_script(
    struct wally_psbt_input *input,
    const unsigned char *redeem_script,
    size_t redeem_script_len);

/**
 * Set the witness_script in an input.
 *
 * :param input: The input to update.
 * :param witness_script: The witness script for this input.
 * :param witness_script_len: Length of ``witness_script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_witness_script(
    struct wally_psbt_input *input,
    const unsigned char *witness_script,
    size_t witness_script_len);

/**
 * Set the final_script_sig in an input.
 *
 * :param input: The input to update.
 * :param final_script_sig: The scriptSig for this input.
 * :param final_script_sig_len: Length of ``final_script_sig`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_final_script_sig(
    struct wally_psbt_input *input,
    const unsigned char *final_script_sig,
    size_t final_script_sig_len);

/**
 * Set the final_witness in an input.
 *
 * :param input: The input to update.
 * :param final_witness: The witness stack for the input, or NULL if no witness is present.
 */
WALLY_CORE_API int wally_psbt_input_set_final_witness(
    struct wally_psbt_input *input,
    const struct wally_tx_witness_stack *final_witness);

/**
 * Set the keypaths in an input.
 *
 * :param input: The input to update.
 * :param keypaths: The HD keypaths for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_keypaths(
    struct wally_psbt_input *input,
    const struct wally_keypath_map *keypaths);

/**
 * Set the partial_sigs in an input.
 *
 * :param input: The input to update.
 * :param partial_sigs: The partial signatures for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_partial_sigs(
    struct wally_psbt_input *input,
    const struct wally_partial_sigs_map *partial_sigs);

/**
 * Set the partial_sigs in an input.
 *
 * :param input: The input to update.
 * :param unknowns: The unknown key value pairs for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_unknowns(
    struct wally_psbt_input *input,
    const struct wally_unknowns_map *unknowns);

/**
 * Set the partial_sigs in an input.
 *
 * :param input: The input to update.
 * :param sighash_type: The sighash type for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_sighash_type(
    struct wally_psbt_input *input,
    uint32_t sighash_type);

#ifndef SWIG_PYTHON
/**
 * Free a PSBT input allocated by `wally_psbt_input_init_alloc`.
 *
 * :param input: The PSBT input to free.
 */
WALLY_CORE_API int wally_psbt_input_free(
    struct wally_psbt_input *input);
#endif /* SWIG_PYTHON */

/**
 * Allocate and initialize a new PSBT output.
 *
 * :param redeem_script: The redeem script needed for spending this output.
 * :param redeem_script_len: Length of ``redeem_script`` in bytes.
 * :param witness_script: The witness script needed for spending for this output.
 * :param witness_script_len: Length of ``witness_script`` in bytes.
 * :param keypaths: The HD keypaths for the keys needed for spending this output.
 * :param unknowns: The unknown key value pairs for this output.
 * :param output: Destination for the resulting PSBT output.
 */
WALLY_CORE_API int wally_psbt_output_init_alloc(
    const unsigned char *redeem_script,
    size_t redeem_script_len,
    const unsigned char *witness_script,
    size_t witness_script_len,
    const struct wally_keypath_map *keypaths,
    const struct wally_unknowns_map *unknowns,
    struct wally_psbt_output **output);

/**
 * Set the redeem_script in an output.
 *
 * :param output: The input to update.
 * :param redeem_script: The redeem script for this output.
 * :param redeem_script_len: Length of ``redeem_script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_redeem_script(
    struct wally_psbt_output *output,
    const unsigned char *redeem_script,
    size_t redeem_script_len);

/**
 * Set the witness_script in an output.
 *
 * :param output: The output to update.
 * :param witness_script: The witness script for this output.
 * :param witness_script_len: Length of ``witness_script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_witness_script(
    struct wally_psbt_output *output,
    const unsigned char *witness_script,
    size_t witness_script_len);

/**
 * Set the keypaths in an output.
 *
 * :param output: The output to update.
 * :param keypaths: The HD keypaths for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_keypaths(
    struct wally_psbt_output *output,
    const struct wally_keypath_map *keypaths);

/**
 * Set the partial_sigs in an output.
 *
 * :param output: The output to update.
 * :param unknowns: The unknown key value pairs for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_unknowns(
    struct wally_psbt_output *output,
    const struct wally_unknowns_map *unknowns);

#ifndef SWIG_PYTHON
/**
 * Free a PSBT output allocated by `wally_psbt_output_init_alloc`.
 *
 * :param output: The PSBT output to free.
 */
WALLY_CORE_API int wally_psbt_output_free(
    struct wally_psbt_output *output);
#endif /* SWIG_PYTHON */

/**
 * Allocate and initialize a new PSBT.
 *
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param global_unknowns_allocation_len: The number of global unknowns to allocate space for.
 * :param output: Destination for the resulting PSBT output.
 */
WALLY_CORE_API int wally_psbt_init_alloc(
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    struct wally_psbt **output);

#ifndef SWIG_PYTHON
/**
 * Free a PSBT allocated by `wally_psbt_init_alloc`.
 *
 * :param psbt: The PSBT to free.
 */
WALLY_CORE_API int wally_psbt_free(
    struct wally_psbt *psbt);
#endif /* SWIG_PYTHON */

/**
 * Set the global transaction for a PSBT.
 *
 * :param psbt: The PSBT to set the transaction for.
 * :param tx: The transaction to set.
 */
WALLY_CORE_API int wally_psbt_set_global_tx(
    struct wally_psbt *psbt,
    const struct wally_tx *tx);

/**
 * Create a PSBT from its serialized bytes.
 *
 * :param bytes: Bytes to create the PSBT from.
 * :param len: Length of ``bytes`` in bytes.
 * :param output: Destination for the resulting PSBT.
 */
WALLY_CORE_API int wally_psbt_from_bytes(
    const unsigned char *bytes,
    size_t len,
    struct wally_psbt **output);

/**
 * Get the length of a PSBT when serialized to bytes.
 *
 * :param psbt: the PSBT.
 * :param written: Destination for the length in bytes when serialized.
 */
WALLY_CORE_API int wally_psbt_get_length(
    const struct wally_psbt *psbt,
    uint32_t flags,
    size_t *written);

/**
 * Serialize a PSBT to bytes.
 *
 * :param psbt: the PSBT to serialize.
 * :param bytes_out: Bytes to create the transaction from.
 * :param len: Length of ``bytes`` in bytes (use `wally_psbt_get_length`).
 * :param written: number of bytes written to bytes_out.
 */
WALLY_CORE_API int wally_psbt_to_bytes(
    const struct wally_psbt *psbt,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create a PSBT from its serialized base64 string.
 *
 * :param base64: Base64 string to create the PSBT from.
 * :param output: Destination for the resulting PSBT.
 */
WALLY_CORE_API int wally_psbt_from_base64(
    const char *base64,
    struct wally_psbt **output);

/**
 * Serialize a PSBT to a base64 string.
 *
 * :param psbt: the PSBT to serialize.
 * :param output: Destination for the resulting serialized PSBT.
 */
WALLY_CORE_API int wally_psbt_to_base64(
    const struct wally_psbt *psbt,
    uint32_t flags,
    char **output);

/**
 * Combine the metadata from multiple PSBTs into one PSBT.
 *
 * :param psbts: Array of PSBTs to combine.
 * :param psbts_len: Number of PSBTs in ``psbts``.
 * :param output: Destination for resulting PSBT.
 */
WALLY_CORE_API int wally_psbt_combine(
    const struct wally_psbt *psbts,
    size_t psbts_len,
    struct wally_psbt **output);

/**
 * Sign a PSBT using the simple signer algorithm.
 *
 * :param psbt: PSBT to sign. Directly modifies this PSBT.
 * :param key: Private key to sign PSBT with.
 * :param key_len: Length of key in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 *
 * .. note:: See https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#simple-signer-algorithm
 *|    for a description of the simple signer algorithm.
 */
WALLY_CORE_API int wally_psbt_sign(
    struct wally_psbt *psbt,
    const unsigned char *key,
    size_t key_len);

/**
 * Finalize a PSBT.
 *
 * :param psbt: PSBT to finalize. Directly modifies this PSBT.
 */
WALLY_CORE_API int wally_psbt_finalize(
    struct wally_psbt *psbt);

/**
 * Extract a network transaction from a finalized PSBT.
 *
 * :param psbt: PSBT to extract from.
 * :param output: Destination for the resulting transaction.
 */
WALLY_CORE_API int wally_psbt_extract(
    const struct wally_psbt *psbt,
    struct wally_tx **output);

/**
 * Determine if a PSBT is an elements PSBT.
 *
 * :param psbt: The PSBT to check.
 * :param written: 1 if the PSBT is an elements PSBT, otherwise 0.
 */
WALLY_CORE_API int wally_psbt_is_elements(
    const struct wally_psbt *psbt,
    size_t *written);

#ifdef BUILD_ELEMENTS
/**
 * Allocate and initialize a new elements PSBT.
 *
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param global_unknowns_allocation_len: The number of global unknowns to allocate space for.
 * :param output: Destination for the resulting PSBT output.
 */
WALLY_CORE_API int wally_psbt_elements_init_alloc(
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    struct wally_psbt **output);

/**
 * Allocate and initialize a new PSBT elements input.
 *
 * :param non_witness_utxo: The non witness utxo for this input if it exists.
 * :param witness_utxo: The witness utxo for this input if it exists.
 * :param redeem_script: The redeem script for this input
 * :param redeem_script_len: Length of ``redeem_script`` in bytes.
 * :param witness_script: The witness script for this input
 * :param witness_script_len: Length of ``witness_script`` in bytes.
 * :param final_script_sig: The scriptSig for this input
 * :param final_script_sig_len: Length of ``final_script_sig`` in bytes.
 * :param final_witness: The witness stack for the input, or NULL if no witness is present.
 * :param keypaths: The HD keypaths for this input.
 * :param partial_sigs: The partial signatures for this input.
 * :param unknowns: The unknown key value pairs for this input.
 * :param sighash_type: The sighash type for this input
 * :param value: The value for this input
 * :param value_blinder: The value blinder for ths input
 * :param value_blinder_len: Length of ``value_blinder`` in bytes.
 * :param asset: The asset for this input.
 * :param asset_len: Length of ``asset`` in bytes.
 * :param asset_blinder: The asset blinder for this input.
 * :param asset_blinder_len: Length of ``asset_blinder`` in bytes.
 * :param peg_in_tx: The The peg in tx for this input
 * :param txout_proof: The txout proof for this input
 * :param txout_proof_len: Length of ``txout_proof`` in bytes.
 * :param genesis_hash: The genesis hash for this input
 * :param genesis_hash_len: Length of ``genesis_hash`` in bytes.
 * :param claim_script: The claim script for this input
 * :param claim_script_len: Length of ``claim_script`` in bytes.
 * :param output: Destination for the resulting PSBT input.
 */
WALLY_CORE_API int wally_psbt_elements_input_init_alloc(
    const struct wally_tx *non_witness_utxo,
    const struct wally_tx_output *witness_utxo,
    const unsigned char *redeem_script,
    size_t redeem_script_len,
    const unsigned char *witness_script,
    size_t witness_script_len,
    const unsigned char *final_script_sig,
    size_t final_script_sig_len,
    const struct wally_tx_witness_stack *final_witness,
    const struct wally_keypath_map *keypaths,
    const struct wally_partial_sigs_map *partial_sigs,
    const struct wally_unknowns_map *unknowns,
    uint32_t sighash_type,
    uint64_t value,
    uint32_t has_value,
    const unsigned char *value_blinder,
    size_t value_blinder_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *asset_blinder,
    size_t asset_blinder_len,
    const struct wally_tx *peg_in_tx,
    const unsigned char *txout_proof,
    size_t txout_proof_len,
    const unsigned char *genesis_hash,
    size_t genesis_hash_len,
    const unsigned char *claim_script,
    size_t claim_script_len,
    struct wally_psbt_input **output);

/**
 * Set the value in an elements input.
 *
 * :param input: The input to update.
 * :param value: The value for this input.
 */
WALLY_CORE_API int wally_psbt_elements_input_set_value(
    struct wally_psbt_input *input,
    uint64_t value);

/**
 * Set the value blinder in an elements input.
 *
 * :param input: The input to update.
 * :param value_blinder: The value blinder for this input.
 * :param value_blinder_len: Length of ``value_blinder`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_input_set_value_blinder(
    struct wally_psbt_input *input,
    const unsigned char *value_blinder,
    size_t value_blinder_len);

/**
 * Set the asset in an elements input.
 *
 * :param input: The input to update.
 * :param asset: The asset for this input.
 * :param asset_len: Length of ``asset`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_input_set_asset(
    struct wally_psbt_input *input,
    const unsigned char *asset,
    size_t asset_len);

/**
 * Set the asset blinder in an elements input
 *
 * :param input: The input to update.
 * :param asset_blinder: The asset blinder for this input.
 * :param asset_blinder_len: Length of ``asset_blinder`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_input_set_asset_blinder(
    struct wally_psbt_input *input,
    const unsigned char *asset_blinder,
    size_t asset_blinder_len);

/**
 * Set the peg in tx in an input.
 *
 * :param input: The input to update.
 * :param peg_in_tx: The peg in tx for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_elements_input_set_peg_in_tx(
    struct wally_psbt_input *input,
    const struct wally_tx *peg_in_tx);

/**
 * Set the txout proof in an elements input.
 *
 * :param input: The input to update.
 * :param txout_proof: The txout proof for this input.
 * :param txout_proof_len: Length of ``txout_proof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_input_set_txout_proof(
    struct wally_psbt_input *input,
    const unsigned char *txout_proof,
    size_t txout_proof_len);

/**
 * Set the genesis hash in an elements input.
 *
 * :param input: The input to update.
 * :param genesis_hash: The genesis hash for this input.
 * :param genesis_hash_len: Length of ``genesis_hash`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_input_set_genesis_hash(
    struct wally_psbt_input *input,
    const unsigned char *genesis_hash,
    size_t genesis_hash_len);

/**
 * Set the claim script in an elements input.
 *
 * :param input: The input to update.
 * :param claim_script: The claim script for this input.
 * :param claim_script_len: Length of ``claim_script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_input_set_claim_script(
    struct wally_psbt_input *input,
    const unsigned char *claim_script,
    size_t claim_script_len);

/**
 * Allocate and initialize a new PSBT elements output.
 *
 * :param redeem_script: The redeem script needed for spending this output.
 * :param redeem_script_len: Length of ``redeem_script`` in bytes.
 * :param witness_script: The witness script needed for spending for this output.
 * :param witness_script_len: Length of ``witness_script`` in bytes.
 * :param keypaths: The HD keypaths for the keys needed for spending this output.
 * :param unknowns: The unknown key value pairs for this output.
 * :param blinding_pubkey: The blinding pubkey for this output.
 * :param value_commitment: The value commitment for this output.
 * :param value_commitment_len: Length of ``value_commitment`` in bytes.
 * :param value_blinder: The value blinder for this output.
 * :param value_blinder_len: Length of ``value_blinder`` in bytes.
 * :param asset_commitment: The asset commitment for this output.
 * :param asset_commitment_len: Length of ``asset_commitment`` in bytes.
 * :param asset_blinder: The asset blinder for this output.
 * :param asset_blinder_len: Length of ``asset_blinder`` in bytes.
 * :param nonce_commitment: The nonce commitment for this output.
 * :param nonce_commitment_len: Length of ``nonce_commitment`` in bytes.
 * :param range_proof: The range proof for this output.
 * :param range_proof_len: Length of ``range_proof`` in bytes.
 * :param surjection_proof: The surjection proof for this output.
 * :param surjection_proof_len: Length of ``surjection_proof`` in bytes.
 * :param output: Destination for the resulting PSBT output.
 */
WALLY_CORE_API int wally_psbt_elements_output_init_alloc(
    const unsigned char *redeem_script,
    size_t redeem_script_len,
    const unsigned char *witness_script,
    size_t witness_script_len,
    const struct wally_keypath_map *keypaths,
    const struct wally_unknowns_map *unknowns,
    const unsigned char *blinding_pubkey,
    size_t blinding_pubkey_len,
    const unsigned char *value_commitment,
    size_t value_commitment_len,
    const unsigned char *value_blinder,
    size_t value_blinder_len,
    const unsigned char *asset_commitment,
    size_t asset_commitment_len,
    const unsigned char *asset_blinder,
    size_t asset_blinder_len,
    const unsigned char *nonce_commitment,
    size_t nonce_commitment_len,
    const unsigned char *range_proof,
    size_t range_proof_len,
    const unsigned char *surjection_proof,
    size_t surjection_proof_len,
    struct wally_psbt_output **output);

/**
 * Set the blinding pubkey in an elements output.
 *
 * :param output: The output to update.
 * :param blinding_pubkey: The blinding pubkey for this output.
 * :param blinding_pubkey_len: Length of ``blinding_pubkey`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_output_set_blinding_pubkey(
    struct wally_psbt_output *output,
    const unsigned char *blinding_pubkey,
    size_t blinding_pubkey_len);

/**
 * Set the value commitment in an elements output.
 *
 * :param output: The output to update.
 * :param value_commitment: The value commitment for this output.
 * :param value_commitment_len: Length of ``value_commitment`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_output_set_value_commitment(
    struct wally_psbt_output *output,
    const unsigned char *value_commitment,
    size_t value_commitment_len);

/**
 * Set the value blinder in an elements output.
 *
 * :param output: The output to update.
 * :param value_blinder: The value blinder for this output.
 * :param value_blinder_len: Length of ``value_blinder`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_output_set_value_blinder(
    struct wally_psbt_output *output,
    const unsigned char *value_blinder,
    size_t value_blinder_len);

/**
 * Set the asset commitment in an elements output.
 *
 * :param output: The output to update.
 * :param asset_commitment: The asset commitment for this output.
 * :param asset_commitment_len: Length of ``asset_commitment`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_output_set_asset_commitment(
    struct wally_psbt_output *output,
    const unsigned char *asset_commitment,
    size_t asset_commitment_len);

/**
 * Set the asset blinder in an elements output.
 *
 * :param output: The output to update.
 * :param asset_blinder: The asset blinder for this output.
 * :param asset_blinder_len: Length of ``asset_blinder`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_output_set_asset_blinder(
    struct wally_psbt_output *output,
    const unsigned char *asset_blinder,
    size_t asset_blinder_len);

/**
 * Set the nonce commitment in an elements output.
 *
 * :param output: The output to update.
 * :param nonce_commitment: The nonce commitment for this output.
 * :param nonce_commitment_len: Length of ``nonce_commitment`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_output_set_nonce_commitment(
    struct wally_psbt_output *output,
    const unsigned char *nonce_commitment,
    size_t nonce_commitment_len);

/**
 * Set the range proof in an elements output.
 *
 * :param output: The output to update.
 * :param range_proof: The range_proof for this output.
 * :param range_proof_len: Length of ``range_proof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_output_set_range_proof(
    struct wally_psbt_output *output,
    const unsigned char *range_proof,
    size_t range_proof_len);

/**
 * Set the surjection proof in an elements output.
 *
 * :param output: The output to update.
 * :param surjection_proof: The surjection proof for this output.
 * :param surjection_proof_len: Length of ``surjection_proof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_elements_output_set_surjection_proof(
    struct wally_psbt_output *output,
    const unsigned char *surjection_proof,
    size_t surjection_proof_len);

#endif /* BUILD_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_PSBT_H */
