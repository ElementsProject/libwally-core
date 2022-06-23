#ifndef LIBWALLY_CORE_PSBT_H
#define LIBWALLY_CORE_PSBT_H

#include "wally_bip32.h"
#include "wally_map.h"
#include "wally_transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PSBT Version number */
#define WALLY_PSBT_VERSION_0 0x0
#define WALLY_PSBT_VERSION_2 0x2
#define WALLY_PSBT_HIGHEST_VERSION 0x2

/* Create an elements PSET */
#define WALLY_PSBT_INIT_PSET 0x1

/* Ignore scriptsig and witness when adding an input */
#define WALLY_PSBT_FLAG_NON_FINAL 0x1

/* Key prefix for proprietary keys in our unknown maps */
#define WALLY_PSBT_PROPRIETARY_TYPE 0xFC

/* Transaction flags indicating modifiable fields */
#define WALLY_PSBT_TXMOD_INPUTS 0x1 /* Inputs can be modified */
#define WALLY_PSBT_TXMOD_OUTPUTS 0x2 /* Outputs can be modified */
#define WALLY_PSBT_TXMOD_SINGLE 0x4 /* SIGHASH_SINGLE signature is present */

#define WALLY_PSET_TXMOD_UNBLINDED 0x1 /* Elements: transaction is not blinded. */

/* ID flags indicating unique id calculation */
#define WALLY_PSBT_ID_AS_V2 0x1 /* Compute PSBT v0 IDs like v2 by setting inputs sequence to 0 */
#define WALLY_PSBT_ID_NO_LOCKTIME 0x2 /* Set locktime to 0 before calculating id */

#define WALLY_SCALAR_OFFSET_LEN 32 /* Length of a PSET scalar offset */

#ifdef SWIG
struct wally_psbt_input;
struct wally_psbt_output;
struct wally_psbt;
#else

/** A PSBT input */
struct wally_psbt_input {
    unsigned char txhash[WALLY_TXHASH_LEN]; /* 'previous txid' */
    uint32_t index;
    uint32_t sequence;
    struct wally_tx *utxo;
    struct wally_tx_output *witness_utxo;
    unsigned char *redeem_script;
    size_t redeem_script_len;
    unsigned char *witness_script;
    size_t witness_script_len;
    unsigned char *final_scriptsig;
    size_t final_scriptsig_len;
    struct wally_tx_witness_stack *final_witness;
    struct wally_map keypaths;
    struct wally_map signatures;
    struct wally_map unknowns;
    uint32_t sighash;
    uint32_t required_locktime; /* Required tx locktime or 0 if not given */
    uint32_t required_lockheight; /* Required tx lockheight or 0 if not given */
#ifdef BUILD_ELEMENTS
    uint64_t issuance_amount; /* Issuance amount, or 0 if not given */
    uint64_t inflation_keys; /* Number of reissuance tokens, or 0 if none given */
    uint64_t pegin_amount; /* Peg-in amount, or 0 if none given */
    struct wally_tx *pegin_tx;
    struct wally_tx_witness_stack *pegin_witness;
    struct wally_map pset_fields; /* Commitments/scripts/proofs etc */
#endif /* BUILD_ELEMENTS */
};

/** A PSBT output */
struct wally_psbt_output {
    unsigned char *redeem_script;
    size_t redeem_script_len;
    unsigned char *witness_script;
    size_t witness_script_len;
    struct wally_map keypaths;
    struct wally_map unknowns;
    uint64_t amount;
    uint32_t has_amount;
    unsigned char *script;
    size_t script_len;
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
    struct wally_map unknowns;
    struct wally_map global_xpubs;
    uint32_t version;
    uint32_t tx_version;
    uint32_t fallback_locktime;
    uint32_t has_fallback_locktime;
    uint32_t tx_modifiable_flags;
#ifdef BUILD_ELEMENTS
    struct wally_map global_scalars;
    uint32_t pset_modifiable_flags;
#endif /* BUILD_ELEMENTS */
};
#endif /* SWIG */

#ifndef SWIG
/**
 * Set the previous txid in an input.
 *
 * :param input: The input to update.
 * :param txhash: The previous hash for this input.
 * :param txhash_len: Length of ``txhash`` in bytes. Must be ``WALLY_TXHASH_LEN``.
 */
WALLY_CORE_API int wally_psbt_input_set_previous_txid(
    struct wally_psbt_input *input,
    const unsigned char *txhash,
    size_t txhash_len);

/**
 * Set the output index in an input.
 *
 * :param input: The input to update.
 * :param index: The index of the spent output for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_output_index(
    struct wally_psbt_input *input,
    uint32_t index);

/**
 * Set the sequence number in an input.
 *
 * :param input: The input to update.
 * :param sequence: The sequence number for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_sequence(
    struct wally_psbt_input *input,
    uint32_t sequence);

/**
 * Clear the sequence number in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_sequence(
    struct wally_psbt_input *input);

/**
 * Set the utxo in an input.
 *
 * :param input: The input to update.
 * :param utxo: The (non witness) utxo for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_input_set_utxo(
    struct wally_psbt_input *input,
    const struct wally_tx *utxo);

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
 * :param script: The redeem script for this input.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_redeem_script(
    struct wally_psbt_input *input,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the witness_script in an input.
 *
 * :param input: The input to update.
 * :param script: The witness script for this input.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_witness_script(
    struct wally_psbt_input *input,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the final_scriptsig in an input.
 *
 * :param input: The input to update.
 * :param final_scriptsig: The scriptSig for this input.
 * :param final_scriptsig_len: Length of ``final_scriptsig`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_final_scriptsig(
    struct wally_psbt_input *input,
    const unsigned char *final_scriptsig,
    size_t final_scriptsig_len);

/**
 * Set the final witness in an input.
 *
 * :param input: The input to update.
 * :param witness: The witness stack for the input, or NULL if not present.
 */
WALLY_CORE_API int wally_psbt_input_set_final_witness(
    struct wally_psbt_input *input,
    const struct wally_tx_witness_stack *witness);

/**
 * Set the keypaths in an input.
 *
 * :param input: The input to update.
 * :param map_in: The HD keypaths for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_keypaths(
    struct wally_psbt_input *input,
    const struct wally_map *map_in);

/**
 * Find a keypath matching a pubkey in an input.
 *
 * :param input: The input to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_input_find_keypath(
    struct wally_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    size_t *written);

/**
 * Convert and add a pubkey/keypath to an input.
 *
 * :param input: The input to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be ``BIP32_KEY_FINGERPRINT_LEN``.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_psbt_input_keypath_add(
    struct wally_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

/**
 * Set the partial signatures in an input.
 *
 * :param input: The input to update.
 * :param map_in: The partial signatures for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_signatures(
    struct wally_psbt_input *input,
    const struct wally_map *map_in);

/**
 * Find a partial signature matching a pubkey in an input.
 *
 * :param input: The input to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_input_find_signature(
    struct wally_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    size_t *written);

/**
 * Add a pubkey/partial signature item to an input.
 *
 * :param input: The input to add the partial signature to.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param sig: The DER-encoded signature plus sighash byte to add.
 * :param sig_len: The length of ``sig`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_add_signature(
    struct wally_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *sig,
    size_t sig_len);

/**
 * Set the unknown values in an input.
 *
 * :param input: The input to update.
 * :param map_in: The unknown key value pairs for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_unknowns(
    struct wally_psbt_input *input,
    const struct wally_map *map_in);

/**
 * Find an unknown item matching a key in an input.
 *
 * :param input: The input to search in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_input_find_unknown(
    struct wally_psbt_input *input,
    const unsigned char *key,
    size_t key_len,
    size_t *written);

/**
 * Set the sighash type in an input.
 *
 * :param input: The input to update.
 * :param sighash: The sighash type for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_sighash(
    struct wally_psbt_input *input,
    uint32_t sighash);

/**
 * Set the required lock time in an input.
 *
 * :param input: The input to update.
 * :param required_locktime: The required locktime for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_required_locktime(
    struct wally_psbt_input *input,
    uint32_t required_locktime);

/**
 * Clear the required lock time in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_required_locktime(
    struct wally_psbt_input *input);

/**
 * Set the required lock height in an input.
 *
 * :param input: The input to update.
 * :param required_lockheight: The required locktime for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_required_lockheight(
    struct wally_psbt_input *input,
    uint32_t required_lockheight);

/**
 * Clear the required lock height in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_required_lockheight(
    struct wally_psbt_input *input);

#ifdef BUILD_ELEMENTS
/**
 * Set the unblinded token issuance amount in an input.
 *
 * :param input: The input to update.
 * :param amount: The issuance amount.
 *
 * .. note:: Setting the amount to zero indicates no issuance.
 */
WALLY_CORE_API int wally_psbt_input_set_issuance_amount(
    struct wally_psbt_input *input,
    uint64_t amount);

/**
 * Set the unblinded number of inflation (reissuance) keys in an input.
 *
 * :param input: The input to update.
 * :param value: The number of inflation keys.
 */
WALLY_CORE_API int wally_psbt_input_set_inflation_keys(
    struct wally_psbt_input *input,
    uint64_t value);

/**
 * Set the peg-in amount in an input.
 *
 * :param input: The input to update.
 * :param amount: The peg-in amount.
 */
WALLY_CORE_API int wally_psbt_input_set_pegin_amount(
    struct wally_psbt_input *input,
    uint64_t amount);

/**
 * Set the peg-in transaction in an input.
 *
 * :param input: The input to update.
 * :param tx: The (non witness) peg-in transaction for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_input_set_pegin_tx(
    struct wally_psbt_input *input,
    const struct wally_tx *tx);

/**
 * Set the peg-in witness in an input.
 *
 * :param input: The input to update.
 * :param witness: The peg-in witness stack for the input, or NULL if not present.
 */
WALLY_CORE_API int wally_psbt_input_set_pegin_witness(
    struct wally_psbt_input *input,
    const struct wally_tx_witness_stack *witness);

/**
 * Get the peg-in transaction output proof from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the peg-in transaction output proof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF``.
 */
WALLY_CORE_API int wally_psbt_input_get_pegin_txout_proof(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a peg-in transaction output proof from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_pegin_txout_proof_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the peg-in transaction output proof in an input.
 *
 * :param input: The input to update.
 * :param txout_proof: The peg-in transaction output proof.
 * :param txout_proof_len: Size of ``txout_proof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_pegin_txout_proof(
    struct wally_psbt_input *input,
    const unsigned char *txout_proof,
    size_t txout_proof_len);

/**
 * Clear the peg-in transaction output proof in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_pegin_txout_proof(
    struct wally_psbt_input *input);

/**
 * Get the peg-in genesis blockhash from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the peg-in genesis blockhash.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 */
WALLY_CORE_API int wally_psbt_input_get_pegin_genesis_blockhash(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a peg-in genesis blockhash from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_PEG_IN_GENESIS``.
 */
WALLY_CORE_API int wally_psbt_input_get_pegin_genesis_blockhash_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the peg-in genesis blockhash in an input.
 *
 * :param input: The input to update.
 * :param genesis_blockhash: The peg-in genesis blockhash.
 * :param genesis_blockhash_len: Size of ``genesis_blockhash`` in bytes. Must
 *|    be ``WALLY_TXHASH_LEN``.
 */
WALLY_CORE_API int wally_psbt_input_set_pegin_genesis_blockhash(
    struct wally_psbt_input *input,
    const unsigned char *genesis_blockhash,
    size_t genesis_blockhash_len);

/**
 * Clear the peg-in genesis blockhash in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_pegin_genesis_blockhash(
    struct wally_psbt_input *input);

/**
 * Get the peg-in claim script from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the peg-in claim script.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT``.
 */
WALLY_CORE_API int wally_psbt_input_get_pegin_claim_script(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a peg-in claim script from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_pegin_claim_script_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the peg-in claim script in an input.
 *
 * :param input: The input to update.
 * :param script: The peg-in claim script.
 * :param script_len: Size of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_pegin_claim_script(
    struct wally_psbt_input *input,
    const unsigned char *script,
    size_t script_len);

/**
 * Clear the peg-in claim script in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_pegin_claim_script(
    struct wally_psbt_input *input);

/**
 * Get the blinded token issuance amount from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the blinded issuance amount.
 * :param len: Size of ``bytes_out`` in bytes. Must be ``ASSET_COMMITMENT_LEN``.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT``.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_amount_commitment(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a blinded token issuance amount from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_amount_commitment_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the blinded token issuance amount in an input.
 *
 * :param input: The input to update.
 * :param commitment: The blinded issuance amount commitment.
 * :param commitment_len: Size of ``commitment`` in bytes. Must
 *|    be ``ASSET_COMMITMENT_LEN``.
 */
WALLY_CORE_API int wally_psbt_input_set_issuance_amount_commitment(
    struct wally_psbt_input *input,
    const unsigned char *commitment,
    size_t commitment_len);

/**
 * Clear the blinded token issuance amount in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_issuance_amount_commitment(
    struct wally_psbt_input *input);

/**
 * Get the issuance amount rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the issuance amount rangeproof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF``.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_amount_rangeproof(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the issuance amount rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_amount_rangeproof_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the issuance amount rangeproof in an input.
 *
 * :param input: The input to update.
 * :param rangeproof: The issuance amount rangeproof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_issuance_amount_rangeproof(
    struct wally_psbt_input *input,
    const unsigned char *rangeproof,
    size_t rangeproof_len);

/**
 * Clear the issuance amount rangeproof in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_issuance_amount_rangeproof(
    struct wally_psbt_input *input);

/**
 * Get the asset issuance blinding nonce from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the asset issuance blinding nonce.
 * :param len: Size of ``bytes_out`` in bytes. Must be ``BLINDING_FACTOR_LEN``.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE``.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_blinding_nonce(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a asset issuance blinding nonce from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_blinding_nonce_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the asset issuance blinding nonce in an input.
 *
 * :param input: The input to update.
 * :param nonce: Asset issuance or revelation blinding nonce.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be ``WALLY_TX_ASSET_TAG_LEN``.
 */
WALLY_CORE_API int wally_psbt_input_set_issuance_blinding_nonce(
    struct wally_psbt_input *input,
    const unsigned char *nonce,
    size_t nonce_len);

/**
 * Clear the asset issuance blinding nonce in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_issuance_blinding_nonce(
    struct wally_psbt_input *input);

/**
 * Get the asset issuance entropy from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the asset issuance entropy.
 * :param len: Size of ``bytes_out`` in bytes. Must be ``BLINDING_FACTOR_LEN``.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY``.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_asset_entropy(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a asset issuance entropy from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_asset_entropy_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the asset issuance entropy in an input.
 *
 * :param input: The input to update.
 * :param entropy: The asset issuance entropy.
 * :param entropy_len: Size of ``entropy`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_issuance_asset_entropy(
    struct wally_psbt_input *input,
    const unsigned char *entropy,
    size_t entropy_len);

/**
 * Clear the asset issuance entropy in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_issuance_asset_entropy(
    struct wally_psbt_input *input);

/**
 * Get the issuance amount blinding rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the issuance amount blinding rangeproof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF``.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_amount_blinding_rangeproof(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a issuance amount blinding rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_issuance_amount_blinding_rangeproof_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the issuance amount blinding rangeproof in an input.
 *
 * :param input: The input to update.
 * :param rangeproof: The issuance amount blinding rangeproof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_issuance_amount_blinding_rangeproof(
    struct wally_psbt_input *input,
    const unsigned char *rangeproof,
    size_t rangeproof_len);

/**
 * Clear the issuance amount blinding rangeproof in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_issuance_amount_blinding_rangeproof(
    struct wally_psbt_input *input);

/**
 * Get the blinded number of reissuance tokens from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the blinded number of reissuance tokens.
 * :param len: Size of ``bytes_out`` in bytes. Must be ``ASSET_COMMITMENT_LEN``.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_INFLATION_KEYS_COMMITMENT``.
 */
WALLY_CORE_API int wally_psbt_input_get_inflation_keys_commitment(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the blinded number of reissuance tokens from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_inflation_keys_commitment_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the blinded number of reissuance tokens in an input.
 *
 * :param input: The input to update.
 * :param commitment: The blinded number of reissuance tokens.
 * :param commitment_len: Size of ``commitment`` in bytes. Must
 *|    be ``ASSET_COMMITMENT_LEN``.
 */
WALLY_CORE_API int wally_psbt_input_set_inflation_keys_commitment(
    struct wally_psbt_input *input,
    const unsigned char *commitment,
    size_t commitment_len);

/**
 * Clear the blinded number of reissuance tokens in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_inflation_keys_commitment(
    struct wally_psbt_input *input);

/**
 * Get the reissuance tokens rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the reissuance tokens rangeproof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_INFLATION_KEYS_RANGEPROOF``.
 */
WALLY_CORE_API int wally_psbt_input_get_inflation_keys_rangeproof(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a reissuance tokens rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_inflation_keys_rangeproof_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the reissuance tokens rangeproof in an input.
 *
 * :param input: The input to update.
 * :param rangeproof: The reissuance tokens rangeproof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_inflation_keys_rangeproof(
    struct wally_psbt_input *input,
    const unsigned char *rangeproof,
    size_t rangeproof_len);

/**
 * Clear the reissuance tokens rangeproof in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_inflation_keys_rangeproof(
    struct wally_psbt_input *input);

/**
 * Get the reissuance tokens blinding rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the reissuance tokens blinding rangeproof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF``.
 */
WALLY_CORE_API int wally_psbt_input_get_inflation_keys_blinding_rangeproof(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a reissuance tokens blinding rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_inflation_keys_blinding_rangeproof_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the reissuance tokens blinding rangeproof in an input.
 *
 * :param input: The input to update.
 * :param rangeproof: The reissuance tokens blinding rangeproof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_inflation_keys_blinding_rangeproof(
    struct wally_psbt_input *input,
    const unsigned char *rangeproof,
    size_t rangeproof_len);

/**
 * Clear the reissuance tokens blinding rangeproof in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_inflation_keys_blinding_rangeproof(
    struct wally_psbt_input *input);

/**
 * Get the UTXO rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the UTXO rangeproof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: this operates on the PSET field ``PSBT_ELEMENTS_IN_UTXO_RANGEPROOF``.
 */
WALLY_CORE_API int wally_psbt_input_get_utxo_rangeproof(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a UTXO rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_utxo_rangeproof_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the UTXO rangeproof in an input.
 *
 * :param input: The input to update.
 * :param rangeproof: The UTXO rangeproof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_utxo_rangeproof(
    struct wally_psbt_input *input,
    const unsigned char *rangeproof,
    size_t rangeproof_len);

/**
 * Clear the UTXO rangeproof in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_utxo_rangeproof(
    struct wally_psbt_input *input);
#endif /* BUILD_ELEMENTS */

/**
 * Determine if a PSBT input is finalized.
 *
 * :param input: The input to check.
 * :param written: On success, set to one if the input is finalized, otherwise zero.
 */
WALLY_CORE_API int wally_psbt_input_is_finalized(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the redeem_script in an output.
 *
 * :param output: The input to update.
 * :param script: The redeem script for this output.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_redeem_script(
    struct wally_psbt_output *output,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the witness_script in an output.
 *
 * :param output: The output to update.
 * :param script: The witness script for this output.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_witness_script(
    struct wally_psbt_output *output,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the keypaths in an output.
 *
 * :param output: The output to update.
 * :param map_in: The HD keypaths for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_keypaths(
    struct wally_psbt_output *output,
    const struct wally_map *map_in);

/**
 * Find a keypath matching a pubkey in an output.
 *
 * :param output: The output to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_output_find_keypath(
    struct wally_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len,
    size_t *written);

/**
 * Convert and add a pubkey/keypath to an output.
 *
 * :param output: The output to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be ``BIP32_KEY_FINGERPRINT_LEN``.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_psbt_output_keypath_add(
    struct wally_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

/**
 * Set the unknown map in an output.
 *
 * :param output: The output to update.
 * :param map_in: The unknown key value pairs for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_unknowns(
    struct wally_psbt_output *output,
    const struct wally_map *map_in);

/**
 * Find an unknown item matching a key in an output.
 *
 * :param output: The output to search in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_output_find_unknown(
    struct wally_psbt_output *output,
    const unsigned char *key,
    size_t key_len,
    size_t *written);

/**
 * Set the amount in an output.
 *
 * :param output: The output to update.
 * :param amount: The amount for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_amount(
    struct wally_psbt_output *output,
    uint64_t amount);

/**
 * Clear the amount in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_amount(
    struct wally_psbt_output *output);

/**
 * Set the script in an output.
 *
 * :param output: The output to update.
 * :param script: The script for this output.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_script(
    struct wally_psbt_output *output,
    const unsigned char *script,
    size_t script_len);
#endif /* SWIG */

/**
 * Allocate and initialize a new PSBT.
 *
 * :param version: The version of the PSBT. Must be WALLY_PSBT_VERSION_0 or WALLY_PSBT_VERSION_0.
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param global_unknowns_allocation_len: The number of global unknowns to allocate space for.
 * :param flags: Flags controlling psbt creation. Must be 0 or WALLY_PSBT_INIT_PSET.
 * :param output: Destination for the resulting PSBT output.
 */
WALLY_CORE_API int wally_psbt_init_alloc(
    uint32_t version,
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    uint32_t flags,
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
 * Set the version for a PSBT.
 *
 * :param psbt: The PSBT to set the version for.
 * :param flags: Flags controlling the version upgrade/downgrade. Must be 0.
 * :param version: The version to use for the PSBT. Must be WALLY_PSBT_VERSION_0
 *|    or WALLY_PSBT_VERSION_2.
 *
 * .. note:: This call converts the PSBT in place to the specified version.
 */
WALLY_CORE_API int wally_psbt_set_version(
    struct wally_psbt *psbt,
    uint32_t flags,
    uint32_t version);

/**
 * Return the BIP-370 unique id of a PSBT.
 *
 * :param psbt: The PSBT to compute the id of.
 * :param flags: WALLY_PSBT_ID_ flags to change the id calculation, or
 *|   pass 0 to compute a BIP-370 compatible id.
 * :param bytes_out: Destination for the id.
 * :param len: Size of ``bytes_out`` in bytes. Must be ``WALLY_TXHASH_LEN``.
 *
 * .. note:: The id is expensive to compute.
 */
WALLY_CORE_API int wally_psbt_get_id(
    const struct wally_psbt *psbt,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Return the calculated transaction lock time of a PSBT.
 *
 * :param psbt: The PSBT to compute the lock time of. Must be a v2 PSBT.
 * :param written: Destination for the calculated transaction lock time.
 *
 * .. note:: The calculated lock time may change as the PSBT is modified.
 */
WALLY_CORE_API int wally_psbt_get_locktime(
    const struct wally_psbt *psbt,
    size_t *written);

/**
 * Determine if all PSBT inputs are finalized.
 *
 * :param psbt: The PSBT to check.
 * :param written: On success, set to one if the PSBT is finalized, otherwise zero.
 */
WALLY_CORE_API int wally_psbt_is_finalized(
    const struct wally_psbt *psbt,
    size_t *written);

/**
 * Set the global transaction for a PSBT.
 *
 * :param psbt: The PSBT to set the transaction for.
 * :param tx: The transaction to set.
 *
 * The global transaction can only be set on a newly created version 0 PSBT.
 * After this call completes the PSBT will have empty inputs and outputs for
 * each input and output in the transaction ``tx`` given.
 */
WALLY_CORE_API int wally_psbt_set_global_tx(
    struct wally_psbt *psbt,
    const struct wally_tx *tx);

/**
 * Set the transaction version for a PSBT.
 *
 * :param psbt: The PSBT to set the transaction version for. Must be a v2 PSBT.
 * :param version: The version to use for the transaction. Must be at least 2.
 */
WALLY_CORE_API int wally_psbt_set_tx_version(
    struct wally_psbt *psbt,
    uint32_t tx_version);

/**
 * Get the transaction version of a PSBT.
 *
 * :param psbt: The PSBT to get the transaction version for. Must be v2 PSBT.
 * :param written: Destination for the PSBT's transaction version.
 *
 * .. note:: Returns the default version 2 if none has been explicitly set.
 */
WALLY_CORE_API int wally_psbt_get_tx_version(
    const struct wally_psbt *psbt,
    size_t *written);

/**
 * Set the fallback locktime for a PSBT.
 *
 * :param psbt: The PSBT to set the fallback locktime for.
 * :param locktime: The fallback locktime to set.
 *
 * Sets the fallback locktime field in the transaction.
 * Cannot be set on V0 PSBTs.
 */
WALLY_CORE_API int wally_psbt_set_fallback_locktime(
    struct wally_psbt *psbt,
    uint32_t locktime);

/**
 * Clear the fallback locktime for a PSBT.
 *
 * :param psbt: The PSBT to update.
 */
WALLY_CORE_API int wally_psbt_clear_fallback_locktime(
    struct wally_psbt *psbt);

/**
 * Set the transaction modifiable flags for a PSBT.
 *
 * :param psbt: The PSBT to set the flags for.
 * :param flags: WALLY_PSBT_TXMOD_ flags indicating what can be modified.
 */
WALLY_CORE_API int wally_psbt_set_tx_modifiable_flags(
    struct wally_psbt *psbt,
    uint32_t flags);

#ifdef BUILD_ELEMENTS
/**
 * Set the scalar offsets in a PSBT.
 *
 * :param psbt: The psbt to update. Must be a PSET.
 * :param map_in: The scalar offsets for this PSBT.
 */
WALLY_CORE_API int wally_psbt_set_global_scalars(
    struct wally_psbt *psbt,
    const struct wally_map *map_in);

/**
 * Add a scalar offset to a PSBT.
 *
 * :param psbt: The PSBT to add to. Must be a PSET.
 * :param scalar: The scalar offset to add.
 * :param scalar_len: The length of the scalar offset. Must be 32.
 */
WALLY_CORE_API int wally_psbt_add_global_scalar(
    struct wally_psbt *psbt,
    const unsigned char *scalar,
    size_t scalar_len);

/**
 * Find a scalar offset in a PSBT.
 *
 * :param psbt: The PSBT to find in. Must be a PSET.
 * :param scalar: The scalar offset to find.
 * :param scalar_len: The length of the scalar offset. Must be 32.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_find_global_scalar(
    struct wally_psbt *psbt,
    const unsigned char *scalar,
    size_t scalar_len,
    size_t *written);

/**
 * Set the Elements transaction modifiable flags for a PSBT.
 *
 * :param psbt: The PSBT to set the flags for.
 * :param flags: PSBT_ELEMENTS_TX_MODIFIABLE_FLAGS_ flags indicating what can be modified.
 */
WALLY_CORE_API int wally_psbt_set_pset_modifiable_flags(
    struct wally_psbt *psbt,
    uint32_t flags);
#endif /* BUILD_ELEMENTS */

/**
 * Add a transaction input to a PSBT at a given position.
 *
 * :param psbt: The PSBT to add the input to.
 * :param index: The zero-based index of the position to add the input at.
 * :param flags: Flags controlling input insertion. Must be 0 or ``WALLY_PSBT_FLAG_NON_FINAL``.
 * :param input: The transaction input to add.
 */
WALLY_CORE_API int wally_psbt_add_tx_input_at(
    struct wally_psbt *psbt,
    uint32_t index,
    uint32_t flags,
    const struct wally_tx_input *input);

/**
 * Remove a transaction input from a PSBT.
 *
 * :param psbt: The PSBT to remove the input from.
 * :param index: The zero-based index of the input to remove.
 */
WALLY_CORE_API int wally_psbt_remove_input(
    struct wally_psbt *psbt,
    uint32_t index);

/**
 * Add a transaction output to a PSBT at a given position.
 *
 * :param psbt: The PSBT to add the output to.
 * :param index: The zero-based index of the position to add the output at.
 * :param flags: Flags controlling output insertion. Must be 0.
 * :param output: The transaction output to add.
 */
WALLY_CORE_API int wally_psbt_add_tx_output_at(
    struct wally_psbt *psbt,
    uint32_t index,
    uint32_t flags,
    const struct wally_tx_output *output);

/**
 * Remove a transaction output from a PSBT.
 *
 * :param psbt: The PSBT to remove the output from.
 * :param index: The zero-based index of the output to remove.
 */
WALLY_CORE_API int wally_psbt_remove_output(
    struct wally_psbt *psbt,
    uint32_t index);

/**
 * Create a PSBT from its serialized bytes.
 *
 * :param bytes: Bytes to create the PSBT from.
 * :param bytes_len: Length of ``bytes`` in bytes.
 * :param output: Destination for the resulting PSBT.
 */
WALLY_CORE_API int wally_psbt_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_psbt **output);

/**
 * Get the length of a PSBT when serialized to bytes.
 *
 * :param psbt: the PSBT.
 * :param flags: Flags controlling length determination. Must be 0.
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
 * :param flags: Flags controlling serialization. Must be 0.
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
 * :param flags: Flags controlling serialization. Must be 0.
 * :param output: Destination for the resulting serialized PSBT.
 */
WALLY_CORE_API int wally_psbt_to_base64(
    const struct wally_psbt *psbt,
    uint32_t flags,
    char **output);

/**
 * Combine the metadata from a source PSBT into another PSBT.
 *
 * :param psbt: the PSBT to combine into.
 * :param source: the PSBT to copy data from.
 */
WALLY_CORE_API int wally_psbt_combine(
    struct wally_psbt *psbt,
    const struct wally_psbt *source);

/**
 * Clone a PSBT into a newly allocated copy.
 *
 * :param psbt: the PSBT to clone.
 * :param flags: Flags controlling PSBT creation. Must be 0.
 * :param output: Destination for the resulting cloned PSBT.
 */
WALLY_CORE_API int wally_psbt_clone_alloc(
    const struct wally_psbt *psbt,
    uint32_t flags,
    struct wally_psbt **output);

/**
 * Sign a PSBT using the simple signer algorithm.
 *
 * :param psbt: PSBT to sign. Directly modifies this PSBT.
 * :param key: Private key to sign PSBT with.
 * :param key_len: Length of key in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param flags: Flags controlling sigining. Must be 0 or EC_FLAG_GRIND_R.
 *
 * .. note:: See https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#simple-signer-algorithm
 *|    for a description of the simple signer algorithm.
 */
WALLY_CORE_API int wally_psbt_sign(
    struct wally_psbt *psbt,
    const unsigned char *key,
    size_t key_len,
    uint32_t flags);

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

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_PSBT_H */
