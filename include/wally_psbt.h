#ifndef LIBWALLY_CORE_PSBT_H
#define LIBWALLY_CORE_PSBT_H

#include "wally_transaction.h"
#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WALLY_PSBT_SEPARATOR 0x00

#define WALLY_PSBT_GLOBAL_UNSIGNED_TX 0x00

#define WALLY_PSBT_IN_NON_WITNESS_UTXO 0x00
#define WALLY_PSBT_IN_WITNESS_UTXO 0x01
#define WALLY_PSBT_IN_PARTIAL_SIG 0x02
#define WALLY_PSBT_IN_SIGHASH_TYPE 0x03
#define WALLY_PSBT_IN_REDEEM_SCRIPT 0x04
#define WALLY_PSBT_IN_WITNESS_SCRIPT 0x05
#define WALLY_PSBT_IN_BIP32_DERIVATION 0x06
#define WALLY_PSBT_IN_FINAL_SCRIPTSIG 0x07
#define WALLY_PSBT_IN_FINAL_SCRIPTWITNESS 0x08

#define WALLY_PSBT_OUT_REDEEM_SCRIPT 0x00
#define WALLY_PSBT_OUT_WITNESS_SCRIPT 0x01
#define WALLY_PSBT_OUT_BIP32_DERIVATION 0x02

#ifdef SWIG
struct wally_key_origin_info;
struct wally_keypath_map;
struct wally_partial_sigs_map;
struct wally_unknowns_map;
struct wally_psbt_input;
struct wally_psbt_output;
struct wally_psbt;
#else

/** Key origin data. Contains a BIP 32 fingerprint and the derivation path */
struct wally_key_origin_info {
    unsigned char fingerprint[FINGERPRINT_LEN];
    uint32_t *path;
    size_t path_len;
};

/** Item in keypath map */
struct wally_keypath_item {
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    struct wally_key_origin_info origin;
};

/** A map of public keys to BIP 32 fingerprint and derivation paths */
struct wally_keypath_map {
    struct wally_keypath_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** Item in partial signatures map */
struct wally_partial_sigs_item {
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    unsigned char *sig;
    size_t sig_len;
};

/** A map of public key's to signatures */
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

/** Unknown items map */
struct wally_unknowns_map {
    struct wally_unknowns_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** A psbt input map */
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
};

/** A psbt output map */
struct wally_psbt_output {
    unsigned char *redeem_script;
    size_t redeem_script_len;
    unsigned char *witness_script;
    size_t witness_script_len;
    struct wally_keypath_map *keypaths;
    struct wally_unknowns_map *unknowns;
};

/** A partially signed bitcoin transaction */
struct wally_psbt {
    struct wally_tx *tx;
    struct wally_psbt_input *inputs;
    size_t num_inputs;
    size_t inputs_allocation_len;
    struct wally_psbt_output *outputs;
    size_t num_outputs;
    size_t outputs_allocation_len;
    struct wally_unknowns_map *unknowns;
};
#endif /* SWIG */

/**
 * Allocate and initialize a new keypath map.
 *
 * :param alloc_len: The number of items to allocate.
 * :param output: Destination for the new keypath map
 */
WALLY_CORE_API int wally_keypath_map_init_alloc(size_t alloc_len, struct wally_keypath_map **output);

#ifndef SWIG_PYTHON
/**
 * Free a keypath map allocated by `wally_keypath_map_init_alloc`.
 *
 * :param keypaths: The keypath map to free.
 */
WALLY_CORE_API int wally_keypath_map_free(struct wally_keypath_map *keypaths);
#endif /* SWIG_PYTHON */

/**
 * Add an item to a keypath map
 *
 * :param keypaths: The keypath map to add to
 * :param pubkey: The pubkey to add
 * :param pubkey_len: The length of the pubkey. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``
 * :param fingerprint: The master key fingerprint for the pubkey
 * :param fingerprint_len: The length of the fingerprint. Must be ``FINGERPRINT_LEN``
 * :param path: The BIP32 derivation path for the pubkey
 * :param path_len: The number of items in path
 */
WALLY_CORE_API int wally_add_new_keypath(struct wally_keypath_map *keypaths,
                                         unsigned char *pubkey,
                                         size_t pubkey_len,
                                         unsigned char *fingerprint,
                                         size_t fingerprint_len,
                                         uint32_t *path,
                                         size_t path_len);

/**
 * Allocate and initialize a new partial sigs map.
 *
 * :param alloc_len: The number of items to allocate.
 * :param output: Destination for the new partial sigs map
 */
WALLY_CORE_API int wally_partial_sigs_map_init_alloc(size_t alloc_len, struct wally_partial_sigs_map **output);

#ifndef SWIG_PYTHON
/**
 * Free a partial sigs map allocated by `wally_partial_sigs_map_init_alloc`.
 *
 * :param sigs: The partial sigs map to free.
 */
WALLY_CORE_API int wally_partial_sigs_map_free(struct wally_partial_sigs_map *sigs);
#endif /* SWIG_PYTHON */

/**
 * Add an item to a partial sigs map
 *
 * :param sigs: The partial sigs map to add to
 * :param pubkey: The pubkey to add
 * :param pubkey_len: Length of the public key. Must be ``EC_PUBLIC_KEY_LEN`` or ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN``
 * :param sig: The signature to add
 * :param sig_len: The length of sig
 */
WALLY_CORE_API int wally_add_new_partial_sig(struct wally_partial_sigs_map *sigs,
                                             unsigned char *pubkey,
                                             size_t pubkey_len,
                                             unsigned char *sig,
                                             size_t sig_len);

/**
 * Allocate and initialize a new unknowns map
 *
 * :param alloc_len: The number of items to allocate.
 * :param output: Destination for the new unknowns map
 */
WALLY_CORE_API int wally_unknowns_map_init_alloc(size_t alloc_len, struct wally_unknowns_map **output);

#ifndef SWIG_PYTHON
/**
 * Free an unknowns map allocated by `wally_unknowns_map_init_alloc`.
 *
 * :param unknowns: The unknowns map map to free.
 */
WALLY_CORE_API int wally_unknowns_map_free(struct wally_unknowns_map *unknowns);
#endif /* SWIG_PYTHON */

/**
 * Add an item to an unknowns map
 *
 * :param unknowns: The unknowns map to add to
 * :param key: The key to add
 * :param key_len: The length of the key
 * :param value: The value to add
 * :param value_len: The length of value
 */
WALLY_CORE_API int wally_add_new_unknown(struct wally_unknowns_map *unknowns,
                                         unsigned char *key,
                                         size_t key_len,
                                         unsigned char *value,
                                         size_t value_len);

/**
 * Allocate and initialize a new psbt input.
 *
 * :param non_witness_utxo: The non witness utxo for this input if it exists.
 * :param witness_utxo: The witness utxo for this input if it exists.
 * :param redeem_script: The redeem script for this input
 * :param redeem_script_len: The length of the redeem script.
 * :param witness_script: The witness script for this input
 * :param witness_script_len: The length of the witness script.
 * :param final_script_sig: The scriptSig for this input
 * :param final_script_sig_len: Size of ``final_script_sig`` in bytes.
 * :param final_witness: The witness stack for the input, or NULL if no witness is present.
 * :param keypaths: The HD keypaths for this input.
 * :param partial_sigs: The partial signatures for this input.
 * :param unknowns: The unknown key value pairs for this input.
 * :param sighash_type: The sighash type for this input
 * :param output: Destination for the resulting psbt input.
 */
WALLY_CORE_API int wally_psbt_input_init_alloc(
    struct wally_tx *non_witness_utxo,
    struct wally_tx_output *witness_utxo,
    unsigned char *redeem_script,
    size_t redeem_script_len,
    unsigned char *witness_script,
    size_t witness_script_len,
    unsigned char *final_script_sig,
    size_t final_script_sig_len,
    struct wally_tx_witness_stack *final_witness,
    struct wally_keypath_map *keypaths,
    struct wally_partial_sigs_map *partial_sigs,
    struct wally_unknowns_map *unknowns,
    uint32_t sighash_type,
    struct wally_psbt_input **output);

/**
 * Set the non_witness_utxo in an input
 *
 * :param input: The input to update.
 * :param non_witness_utxo: The non witness utxo for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_input_set_non_witness_utxo(
    struct wally_psbt_input *input,
    struct wally_tx *non_witness_utxo);

/**
 * Set the witness_utxo in an input
 *
 * :param input: The input to update.
 * :param witness_utxo: The witness utxo for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_input_set_witness_utxo(
    struct wally_psbt_input *input,
    struct wally_tx_output *witness_utxo);

/**
 * Set the redeem_script in an input
 *
 * :param input: The input to update.
 * :param redeem_script: The redeem script for this input
 * :param redeem_script_len: The length of the redeem script.
 */
WALLY_CORE_API int wally_psbt_input_set_redeem_script(
    struct wally_psbt_input *input,
    unsigned char *redeem_script,
    size_t redeem_script_len);

/**
 * Set the witness_script in an input
 *
 * :param input: The input to update.
 * :param witness_script: The witness script for this input
 * :param witness_script_len: The length of the witness script.
 */
WALLY_CORE_API int wally_psbt_input_set_witness_script(
    struct wally_psbt_input *input,
    unsigned char *witness_script,
    size_t witness_script_len);

/**
 * Set the final_script_sig in an input
 *
 * :param input: The input to update.
 * :param final_script_sig: The scriptSig for this input
 * :param final_script_sig_len: Size of ``final_script_sig`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_final_script_sig(
    struct wally_psbt_input *input,
    unsigned char *final_script_sig,
    size_t final_script_sig_len);

/**
 * Set the final_witness in an input
 *
 * :param input: The input to update.
 * :param final_witness: The witness stack for the input, or NULL if no witness is present.
 */
WALLY_CORE_API int wally_psbt_input_set_final_witness(
    struct wally_psbt_input *input,
    struct wally_tx_witness_stack *final_witness);

/**
 * Set the keypaths in an input
 *
 * :param input: The input to update.
 * :param keypaths: The HD keypaths for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_keypaths(
    struct wally_psbt_input *input,
    struct wally_keypath_map *keypaths);

/**
 * Set the partial_sigs in an input
 *
 * :param input: The input to update.
 * :param partial_sigs: The partial signatures for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_partial_sigs(
    struct wally_psbt_input *input,
    struct wally_partial_sigs_map *partial_sigs);

/**
 * Set the partial_sigs in an input
 *
 * :param input: The input to update.
 * :param unknowns: The unknown key value pairs for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_unknowns(
    struct wally_psbt_input *input,
    struct wally_unknowns_map *unknowns);

/**
 * Set the partial_sigs in an input
 *
 * :param input: The input to update.
 * :param sighash_type: The sighash type for this input
 */
WALLY_CORE_API int wally_psbt_input_set_sighash_type(
    struct wally_psbt_input *input,
    uint32_t sighash_type);

#ifndef SWIG_PYTHON
/**
 * Free a psbt input allocated by `wally_psbt_input_init_alloc`.
 *
 * :param input: The psbt input to free.
 */
WALLY_CORE_API int wally_psbt_input_free(struct wally_psbt_input *input);
#endif /* SWIG_PYTHON */

/**
 * Allocate and initialize a new psbt output.
 *
 * :param redeem_script: The redeem script needed for spending this output
 * :param redeem_script_len: The length of the redeem script.
 * :param witness_script: The witness script needed for spending for this output
 * :param witness_script_len: The length of the witness script.
 * :param keypaths: The HD keypaths for the keys needed for spending this output
 * :param unknowns: The unknown key value pairs for this output.
 * :param output: Destination for the resulting psbt output.
 */
WALLY_CORE_API int wally_psbt_output_init_alloc(
    unsigned char *redeem_script,
    size_t redeem_script_len,
    unsigned char *witness_script,
    size_t witness_script_len,
    struct wally_keypath_map *keypaths,
    struct wally_unknowns_map *unknowns,
    struct wally_psbt_output **output);

/**
 * Set the redeem_script in an output
 *
 * :param output: The input to update.
 * :param redeem_script: The redeem script for this output
 * :param redeem_script_len: The length of the redeem script.
 */
WALLY_CORE_API int wally_psbt_output_set_redeem_script(
    struct wally_psbt_output *output,
    unsigned char *redeem_script,
    size_t redeem_script_len);

/**
 * Set the witness_script in an output
 *
 * :param output: The output to update.
 * :param witness_script: The witness script for this output
 * :param witness_script_len: The length of the witness script.
 */
WALLY_CORE_API int wally_psbt_output_set_witness_script(
    struct wally_psbt_output *output,
    unsigned char *witness_script,
    size_t witness_script_len);

/**
 * Set the keypaths in an output
 *
 * :param output: The output to update.
 * :param keypaths: The HD keypaths for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_keypaths(
    struct wally_psbt_output *output,
    struct wally_keypath_map *keypaths);

/**
 * Set the partial_sigs in an output
 *
 * :param output: The output to update.
 * :param unknowns: The unknown key value pairs for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_unknowns(
    struct wally_psbt_output *output,
    struct wally_unknowns_map *unknowns);

#ifndef SWIG_PYTHON
/**
 * Free a psbt output allocated by `wally_psbt_output_init_alloc`.
 *
 * :param output: The psbt output to free.
 */
WALLY_CORE_API int wally_psbt_output_free(struct wally_psbt_output *output);
#endif /* SWIG_PYTHON */

/**
 * Allocate and initialize a new psbt.
 *
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param global_unknowns_allocation_len: The number of global unknowns to allocate space for.
 * :param output: Destination for the resulting psbt output.
 */
WALLY_CORE_API int wally_psbt_init_alloc(
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    struct wally_psbt **output);

#ifndef SWIG_PYTHON
/**
 * Free a psbt allocated by `wally_psbt_init_alloc`.
 *
 * :param psbt: The psbt to free.
 */
WALLY_CORE_API int wally_psbt_free(struct wally_psbt *psbt);
#endif /* SWIG_PYTHON */

/**
 * Set the global transaction for a psbt.
 * Also initializes all of the wally_psbt_input and wally_psbt_outputs necessary
 *
 * :param tx: The transaction to set.
 * :param psbt: The psbt to set the transaction for
 */
WALLY_CORE_API int wally_psbt_set_global_tx(
    struct wally_psbt *psbt,
    struct wally_tx *tx);

/**
 * Create a psbt from its serialized bytes.
 *
 * :param bytes: Bytes to create the psbt from.
 * :param bytes_len: Length of ``bytes`` in bytes.
 * :param output: Destination for the resulting psbt.
 */
WALLY_CORE_API int wally_psbt_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_psbt **output);

/**
 * Get length of psbt when serialized to bytes.
 *
 * :param psbt: the PSBT.
 * :param len: Length in bytes when serialized.
 */
WALLY_CORE_API int wally_psbt_get_length(
    const struct wally_psbt *psbt,
    size_t *len);

/**
 * Serialize a psbt to bytes.
 *
 * :param psbt: the PSBT to serialize.
 * :param bytes_out: Bytes to create the transaction from.
 * :param bytes_len: Length of ``bytes`` in bytes (use `wally_psbt_get_length`).
 * :param bytes_written: number of bytes written to bytes_out
 */
WALLY_CORE_API int wally_psbt_to_bytes(
    const struct wally_psbt *psbt,
    unsigned char *bytes_out, size_t bytes_len,
    size_t *bytes_written);

/**
 * Create a psbt from the base64 string.
 *
 * :param string: Base64 string to create the psbt from.
 * :param output: Destination for the resulting psbt.
 */
WALLY_CORE_API int wally_psbt_from_base64(
    const char *string,
    struct wally_psbt **output);

/**
 * Create a base64 string for a psbt
 *
 * :param psbt: the PSBT to serialize.
 * :param output: Destination for the resulting psbt.
 */
WALLY_CORE_API int wally_psbt_to_base64(
    struct wally_psbt *psbt,
    char **output);

/**
 * Combine the metadata from multiple PSBTs into one
 *
 * :param psbts: Array of PSBTs to combine
 * :param psbts_len: Number of PSBTs in psbts
 * :param output: Destination for resulting psbt
 */
WALLY_CORE_API int wally_combine_psbts(
    const struct wally_psbt *psbts,
    size_t psbts_len,
    struct wally_psbt **output);

/**
 * Sign a PSBT using the simple signer algorithm: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#simple-signer-algorithm
 *
 * :param psbt: PSBT to sign. Directly modifies this PSBT
 * :param key: Private key to sign PSBT with
 * :param key_len: Length of key in bytes. Must be ``EC_PRIVATE_KEY_LEN``
 */
WALLY_CORE_API int wally_sign_psbt(
    struct wally_psbt *psbt,
    const unsigned char *key,
    size_t key_len);

/**
 * Finalize a PSBT
 *
 * :param psbt: PSBT to finalize. Directly modifies this PSBT
 */
WALLY_CORE_API int wally_finalize_psbt(
    struct wally_psbt *psbt);

/**
 * Convert a finalized PSBT to a network transaction, i.e. extract
 *
 * :param psbt: PSBT to extract. Directly modifies this PSBT
 * :param output: Resulting transaction
 */
WALLY_CORE_API int wally_extract_psbt(
    struct wally_psbt *psbt,
    struct wally_tx **output);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_PSBT_H */
