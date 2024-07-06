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

/*** psbt-txmod Transaction modification flags */
#define WALLY_PSBT_TXMOD_INPUTS 0x1 /* Inputs can be modified */
#define WALLY_PSBT_TXMOD_OUTPUTS 0x2 /* Outputs can be modified */
#define WALLY_PSBT_TXMOD_SINGLE 0x4 /* SIGHASH_SINGLE signature is present */
#define WALLY_PSET_TXMOD_RESERVED 0x1 /* Elements: Reserved: not used and ignored if set */

#define WALLY_PSBT_PARSE_FLAG_STRICT 0x1 /* Parse strictly according to the PSBT/PSET spec */

/** Include redundant information to match some buggy PSBT implementations */
#define WALLY_PSBT_SERIALIZE_FLAG_REDUNDANT 0x1

/*** psbt-extract Transaction extraction flags */
#define WALLY_PSBT_EXTRACT_FINAL     0x0 /* Extract a final transaction; fail if any inputs aren't finalized */
#define WALLY_PSBT_EXTRACT_NON_FINAL 0x1 /* Extract without any final scriptsig and witness */
#define WALLY_PSBT_EXTRACT_OPT_FINAL 0x2 /* Extract only final scriptsigs and witnesses that are present (partial finalization) */

#define WALLY_PSBT_FINALIZE_NO_CLEAR 0x1 /* Finalize without clearing redeem/witness scripts etc */

/*** psbt-id-flags PSBT ID calculation flags */
#define WALLY_PSBT_ID_BIP370 0x0 /* BIP370 compatible */
#define WALLY_PSBT_ID_AS_V2 0x1 /* Compute PSBT v0 IDs like v2 by setting inputs sequence to 0 */
#define WALLY_PSBT_ID_USE_LOCKTIME 0x2 /* Do not set locktime to 0 before calculating id */

/* Output blinding status */
#define WALLY_PSET_BLINDED_NONE     0x0 /* Unblinded */
#define WALLY_PSET_BLINDED_REQUIRED 0x1 /* Blinding key present with no other blinding data */
#define WALLY_PSET_BLINDED_PARTIAL  0x2 /* Blinding key present with partial blinding data */
#define WALLY_PSET_BLINDED_FULL     0x4 /* Blinding key present with full blinding data */

#define WALLY_PSET_BLIND_ALL 0xffffffff /* Blind all outputs in wally_psbt_blind */

#define WALLY_SCALAR_OFFSET_LEN 32 /* Length of a PSET scalar offset */

struct ext_key;

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
    struct wally_tx_witness_stack *final_witness;
    struct wally_map keypaths;
    struct wally_map signatures;
    struct wally_map unknowns;
    uint32_t sighash;
    uint32_t required_locktime; /* Required tx locktime or 0 if not given */
    uint32_t required_lockheight; /* Required tx lockheight or 0 if not given */
    struct wally_map preimages; /* Preimage hash to data keyed by PSBT keytype + hash */
    struct wally_map psbt_fields; /* Binary fields keyed by PSBT keytype */
    struct wally_map taproot_leaf_signatures;
    struct wally_map taproot_leaf_scripts;
    /* Hashes and paths for taproot bip32 derivation path */
    struct wally_map taproot_leaf_hashes;
    struct wally_map taproot_leaf_paths;
#ifndef WALLY_ABI_NO_ELEMENTS
    uint64_t issuance_amount; /* Issuance amount, or 0 if not given */
    uint64_t inflation_keys; /* Number of reissuance tokens, or 0 if none given */
    uint64_t pegin_amount; /* Peg-in amount, or 0 if none given */
    struct wally_tx *pegin_tx;
    struct wally_tx_witness_stack *pegin_witness;
    struct wally_map pset_fields; /* Commitments/scripts/proofs etc keyed by PSET keytype*/
    uint64_t amount; /* Explicit amount (not normally present, used for mixed-creator txs) */
    uint32_t has_amount;
#endif /* WALLY_ABI_NO_ELEMENTS */
};

/** A PSBT output */
struct wally_psbt_output {
    struct wally_map keypaths;
    struct wally_map unknowns;
    uint64_t amount;
    uint32_t has_amount;
    unsigned char *script;
    size_t script_len;
    struct wally_map psbt_fields; /* Binary fields keyed by PSBT keytype */
    /* Map of 1-based position to taproot leaf script, in depth first order.
    * TODO: replace this with actual TR representaion when TR implemented */
    struct wally_map taproot_tree;
    /* Hashes and paths for taproot bip32 derivation path */
    struct wally_map taproot_leaf_hashes;
    struct wally_map taproot_leaf_paths;
#ifndef WALLY_ABI_NO_ELEMENTS
    uint32_t blinder_index; /* Index of the input whose owner should blind this output */
    uint32_t has_blinder_index;
    struct wally_map pset_fields; /* Commitments/pubkeys/proofs etc keyed by PSET keytype*/
#endif /* WALLY_ABI_NO_ELEMENTS */
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
#ifndef WALLY_ABI_NO_ELEMENTS
    struct wally_map global_scalars;
    uint32_t pset_modifiable_flags;
#endif /* WALLY_ABI_NO_ELEMENTS */
};
#endif /* SWIG */

/**
 * Set the previous txid in an input.
 *
 * :param input: The input to update.
 * :param txhash: The previous hash for this input.
 * :param txhash_len: Length of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
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
 * Set the witness_utxo in an input from a transaction output.
 *
 * :param input: The input to update.
 * :param utxo: The transaction containing the output to add.
 * :param index: The output index in ``utxo`` to add.
 */
WALLY_CORE_API int wally_psbt_input_set_witness_utxo_from_tx(
    struct wally_psbt_input *input,
    const struct wally_tx *utxo,
    uint32_t index);

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
 * Set the non-taproot keypaths in an input.
 *
 * :param input: The input to update.
 * :param map_in: The non-taproot HD keypaths to set for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_keypaths(
    struct wally_psbt_input *input,
    const struct wally_map *map_in);

/**
 * Find a keypath matching a pubkey in an input.
 *
 * :param input: The input to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 *
 * .. note:: This function only finds non-taproot keypaths.
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
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be `BIP32_KEY_FINGERPRINT_LEN`.
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
 * Convert and add a pubkey/taproot keypath to a PSBT input.
 *
 * :param input: The input to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_XONLY_PUBLIC_KEY_LEN`.
 * :param tapleaf_hashes: Series of 32-byte leaf hashes.
 * :param tapleaf_hashes_len: Length of ``tapleaf_hashes`` in bytes. Must be a multiple of `SHA256_LEN`.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be `BIP32_KEY_FINGERPRINT_LEN`.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_psbt_input_taproot_keypath_add(
    struct wally_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *tapleaf_hashes,
    size_t tapleaf_hashes_len,
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
 * Set the taproot key signature in an input.
 *
 * :param input: The input to update.
 * :param tap_sig: The taproot keyspend signature for this input.
 * :param tap_sig_len: The length of ``tap_sig``. Must be 64 or 65.
 */
WALLY_CORE_API int wally_psbt_input_set_taproot_signature(
    struct wally_psbt_input *input,
    const unsigned char *tap_sig,
    size_t tap_sig_len);

/**
 * Find a partial signature matching a pubkey in an input.
 *
 * :param input: The input to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
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
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
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

#ifndef WALLY_ABI_NO_ELEMENTS
/**
 * Set the unblinded amount in an input.
 *
 * :param input: The input to update.
 * :param amount: The amount of the input.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_EXPLICIT_VALUE``.
 */
WALLY_CORE_API int wally_psbt_input_set_amount(
    struct wally_psbt_input *input,
    uint64_t amount);

/**
 * Get the explicit amount rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the explicit amount rangeproof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_VALUE_PROOF``.
 */
WALLY_CORE_API int wally_psbt_input_get_amount_rangeproof(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the explicit amount rangeproof from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_amount_rangeproof_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the explicit amount rangeproof in an input.
 *
 * :param input: The input to update.
 * :param rangeproof: The explicit amount rangeproof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_amount_rangeproof(
    struct wally_psbt_input *input,
    const unsigned char *rangeproof,
    size_t rangeproof_len);

/**
 * Clear the explicit amount rangeproof in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_amount_rangeproof(
    struct wally_psbt_input *input);

/**
 * Get the explicit asset tag from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the explicit asset tag.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_EXPLICIT_ASSET``.
 */
WALLY_CORE_API int wally_psbt_input_get_asset(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the explicit asset tag from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_asset_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the explicit asset tag in an input.
 *
 * :param input: The input to update.
 * :param asset: The explicit asset tag.
 * :param asset_len: Size of ``asset`` in bytes. Must be `ASSET_TAG_LEN`.
 */
WALLY_CORE_API int wally_psbt_input_set_asset(
    struct wally_psbt_input *input,
    const unsigned char *asset,
    size_t asset_len);

/**
 * Clear the explicit asset tag in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_asset(
    struct wally_psbt_input *input);

/**
 * Get the explicit asset surjection proof from an input.
 *
 * :param input: The input to get from.
 * :param bytes_out: Destination for the explicit asset surjection proof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_ASSET_PROOF``.
 */
WALLY_CORE_API int wally_psbt_input_get_asset_surjectionproof(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the explicit asset surjection proof from an input.
 *
 * :param input: The input to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_input_get_asset_surjectionproof_len(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the explicit asset surjection proof in an input.
 *
 * :param input: The input to update.
 * :param surjectionproof: The explicit asset surjection proof.
 * :param surjectionproof_len: Size of ``surjectionproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_asset_surjectionproof(
    struct wally_psbt_input *input,
    const unsigned char *surjectionproof,
    size_t surjectionproof_len);

/**
 * Clear the explicit asset surjection proof in an input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_asset_surjectionproof(
    struct wally_psbt_input *input);

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
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF``.
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
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_PEG_IN_GENESIS_HASH``.
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
 *|    be `WALLY_TXHASH_LEN`.
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
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT``.
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
 * :param len: Size of ``bytes_out`` in bytes. Must be `ASSET_COMMITMENT_LEN`.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT``.
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
 *|    be `ASSET_COMMITMENT_LEN`.
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
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF``.
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
 * :param len: Size of ``bytes_out`` in bytes. Must be `BLINDING_FACTOR_LEN`.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE``.
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
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `ASSET_TAG_LEN`.
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
 * :param len: Size of ``bytes_out`` in bytes. Must be `BLINDING_FACTOR_LEN`.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY``.
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
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF``.
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
 * :param len: Size of ``bytes_out`` in bytes. Must be `ASSET_COMMITMENT_LEN`.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_INFLATION_KEYS_COMMITMENT``.
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
 *|    be `ASSET_COMMITMENT_LEN`.
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
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_INFLATION_KEYS_RANGEPROOF``.
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
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF``.
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
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_IN_UTXO_RANGEPROOF``.
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

/**
 * Generate explicit proofs and unblinded values from an inputs UTXO.
 *
 * :param input: The input to generate proofs for.
 * :param satoshi: The explicit value of the input.
 * :param asset: The explicit asset tag.
 * :param asset_len: Size of ``asset`` in bytes. Must be `ASSET_TAG_LEN`.
 * :param abf: Asset blinding factor.
 * :param abf_len: Length of ``abf``. Must be `BLINDING_FACTOR_LEN`.
 * :param vbf: Value blinding factor.
 * :param vbf_len: Length of ``vbf``. Must be `BLINDING_FACTOR_LEN`.
 * :param entropy: Random entropy for explicit range proof generation.
 * :param entropy_len: Size of ``entropy`` in bytes. Must be `BLINDING_FACTOR_LEN`.
 *
 * .. note:: This function exposes the unblinded asset and value in the PSET,
 *           which is only appropriate in certain multi-party protocols.
 * .. note:: This function can only be called on v2 PSETs. It is strongly
 *           recommended to use `wally_psbt_generate_input_explicit_proofs`
 *           which ensures this, instead of this function.
 */
WALLY_CORE_API int wally_psbt_input_generate_explicit_proofs(
    struct wally_psbt_input *input,
    uint64_t satoshi,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *entropy,
    size_t entropy_len);
#endif /* WALLY_ABI_NO_ELEMENTS */

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
 * Set the non-taproot keypaths in an output.
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
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 *
 * .. note:: This function only finds non-taproot keypaths.
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
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be `BIP32_KEY_FINGERPRINT_LEN`.
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
 * Convert and add a pubkey/taproot keypath to a PSBT output.
 *
 * :param output: The output to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_XONLY_PUBLIC_KEY_LEN`.
 * :param tapleaf_hashes: Series of 32-byte leaf hashes.
 * :param tapleaf_hashes_len: Length of ``tapleaf_hashes`` in bytes. Must be a multiple of `SHA256_LEN`.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be `BIP32_KEY_FINGERPRINT_LEN`.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_psbt_output_taproot_keypath_add(
    struct wally_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *tapleaf_hashes,
    size_t tapleaf_hashes_len,
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

#ifndef WALLY_ABI_NO_ELEMENTS
/**
 * Set the input blinder index in an output.
 *
 * :param output: The output to update.
 * :param index: The input blinder index for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_blinder_index(
    struct wally_psbt_output *output,
    uint32_t index);

/**
 * Clear the input blinder index from an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_blinder_index(
    struct wally_psbt_output *output);

/**
 * Get the blinded asset value from an output.
 *
 * :param output: The output to get from.
 * :param bytes_out: Destination for the blinded asset value.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_OUT_VALUE_COMMITMENT``.
 */
WALLY_CORE_API int wally_psbt_output_get_value_commitment(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the blinded asset value from an output.
 *
 * :param output: The output to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_output_get_value_commitment_len(
    const struct wally_psbt_output *output,
    size_t *written);

/**
 * Set the blinded asset value in an output.
 *
 * :param output: The output to update.
 * :param commitment: The blinded asset value.
 * :param commitment_len: Size of ``commitment`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_value_commitment(
    struct wally_psbt_output *output,
    const unsigned char *commitment,
    size_t commitment_len);

/**
 * Clear the blinded asset value in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_value_commitment(
    struct wally_psbt_output *output);

/**
 * Get the asset tag from an output.
 *
 * :param output: The output to get from.
 * :param bytes_out: Destination for the asset tag.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_OUT_ASSET``.
 */
WALLY_CORE_API int wally_psbt_output_get_asset(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the asset tag from an output.
 *
 * :param output: The output to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_output_get_asset_len(
    const struct wally_psbt_output *output,
    size_t *written);

/**
 * Set the asset tag in an output.
 *
 * :param output: The output to update.
 * :param asset: The asset tag.
 * :param asset_len: Size of ``asset`` in bytes. Must be `ASSET_TAG_LEN`.
 */
WALLY_CORE_API int wally_psbt_output_set_asset(
    struct wally_psbt_output *output,
    const unsigned char *asset,
    size_t asset_len);

/**
 * Clear the asset tag in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_asset(
    struct wally_psbt_output *output);

/**
 * Get the blinded asset tag from an output.
 *
 * :param output: The output to get from.
 * :param bytes_out: Destination for the blinded asset tag.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_OUT_ASSET_COMMITMENT``.
 */
WALLY_CORE_API int wally_psbt_output_get_asset_commitment(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the blinded asset tag from an output.
 *
 * :param output: The output to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_output_get_asset_commitment_len(
    const struct wally_psbt_output *output,
    size_t *written);

/**
 * Set the blinded asset tag in an output.
 *
 * :param output: The output to update.
 * :param commitment: The blinded asset tag.
 * :param commitment_len: Size of ``commitment`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_asset_commitment(
    struct wally_psbt_output *output,
    const unsigned char *commitment,
    size_t commitment_len);

/**
 * Clear the blinded asset tag in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_asset_commitment(
    struct wally_psbt_output *output);

/**
 * Get the output value range proof from an output.
 *
 * :param output: The output to get from.
 * :param bytes_out: Destination for the output value range proof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF``.
 */
WALLY_CORE_API int wally_psbt_output_get_value_rangeproof(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the output value range proof from an output.
 *
 * :param output: The output to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_output_get_value_rangeproof_len(
    const struct wally_psbt_output *output,
    size_t *written);

/**
 * Set the output value range proof in an output.
 *
 * :param output: The output to update.
 * :param rangeproof: The output value range proof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_value_rangeproof(
    struct wally_psbt_output *output,
    const unsigned char *rangeproof,
    size_t rangeproof_len);

/**
 * Clear the output value range proof in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_value_rangeproof(
    struct wally_psbt_output *output);

/**
 * Get the asset surjection proof from an output.
 *
 * :param output: The output to get from.
 * :param bytes_out: Destination for the asset surjection proof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF``.
 */
WALLY_CORE_API int wally_psbt_output_get_asset_surjectionproof(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the asset surjection proof from an output.
 *
 * :param output: The output to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_output_get_asset_surjectionproof_len(
    const struct wally_psbt_output *output,
    size_t *written);

/**
 * Set the asset surjection proof in an output.
 *
 * :param output: The output to update.
 * :param surjectionproof: The asset surjection proof.
 * :param surjectionproof_len: Size of ``surjectionproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_asset_surjectionproof(
    struct wally_psbt_output *output,
    const unsigned char *surjectionproof,
    size_t surjectionproof_len);

/**
 * Clear the asset surjection proof in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_asset_surjectionproof(
    struct wally_psbt_output *output);

/**
 * Get the blinding public key from an output.
 *
 * :param output: The output to get from.
 * :param bytes_out: Destination for the blinding public key.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_OUT_BLINDING_PUBKEY``.
 */
WALLY_CORE_API int wally_psbt_output_get_blinding_public_key(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the blinding public key from an output.
 *
 * :param output: The output to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_output_get_blinding_public_key_len(
    const struct wally_psbt_output *output,
    size_t *written);

/**
 * Set the blinding public key in an output.
 *
 * :param output: The output to update.
 * :param pub_key: The blinding public key.
 * :param pub_key_len: Size of ``pub_key`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_blinding_public_key(
    struct wally_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len);

/**
 * Clear the blinding public key in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_blinding_public_key(
    struct wally_psbt_output *output);

/**
 * Get the ephemeral ECDH public key from an output.
 *
 * :param output: The output to get from.
 * :param bytes_out: Destination for the ephemeral ECDH public key.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_OUT_ECDH_PUBKEY``.
 */
WALLY_CORE_API int wally_psbt_output_get_ecdh_public_key(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the ephemeral ECDH public key from an output.
 *
 * :param output: The output to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_output_get_ecdh_public_key_len(
    const struct wally_psbt_output *output,
    size_t *written);

/**
 * Set the ephemeral ECDH public key in an output.
 *
 * :param output: The output to update.
 * :param pub_key: The ephemeral ECDH public key.
 * :param pub_key_len: Size of ``pub_key`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_ecdh_public_key(
    struct wally_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len);

/**
 * Clear the ephemeral ECDH public key in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_ecdh_public_key(
    struct wally_psbt_output *output);

/**
 * Get the asset value blinding rangeproof from an output.
 *
 * :param output: The output to get from.
 * :param bytes_out: Destination for the asset value blinding rangeproof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF``.
 */
WALLY_CORE_API int wally_psbt_output_get_value_blinding_rangeproof(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the asset value blinding rangeproof from an output.
 *
 * :param output: The output to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_output_get_value_blinding_rangeproof_len(
    const struct wally_psbt_output *output,
    size_t *written);

/**
 * Set the asset value blinding rangeproof in an output.
 *
 * :param output: The output to update.
 * :param rangeproof: The asset value blinding rangeproof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_value_blinding_rangeproof(
    struct wally_psbt_output *output,
    const unsigned char *rangeproof,
    size_t rangeproof_len);

/**
 * Clear the asset value blinding rangeproof in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_value_blinding_rangeproof(
    struct wally_psbt_output *output);

/**
 * Get the asset tag blinding surjection proof from an output.
 *
 * :param output: The output to get from.
 * :param bytes_out: Destination for the asset tag blinding surjection proof.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written
 *|    to ``bytes_out``. Will be zero if the value is not present.
 *
 * .. note:: This operates on the PSET field ``PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF``.
 */
WALLY_CORE_API int wally_psbt_output_get_asset_blinding_surjectionproof(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the asset tag blinding surjection proof from an output.
 *
 * :param output: The output to get from.
 * :param written: Destination for the length, or zero if not present.
 */
WALLY_CORE_API int wally_psbt_output_get_asset_blinding_surjectionproof_len(
    const struct wally_psbt_output *output,
    size_t *written);

/**
 * Set the asset tag blinding surjection proof in an output.
 *
 * :param output: The output to update.
 * :param surjectionproof: The asset tag blinding surjection proof.
 * :param surjectionproof_len: Size of ``surjectionproof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_asset_blinding_surjectionproof(
    struct wally_psbt_output *output,
    const unsigned char *surjectionproof,
    size_t surjectionproof_len);

/**
 * Clear the asset tag blinding surjection proof in an output.
 *
 * :param output: The output to update.
 */
WALLY_CORE_API int wally_psbt_output_clear_asset_blinding_surjectionproof(
    struct wally_psbt_output *output);

/**
 * Get the blinding status of an output.
 *
 * :param output: The output to get the blinding status from.
 * :param flags: Flags controlling the checks to perform. Must be 0.
 * :param written: Destination for the blinding status: `WALLY_PSET_BLINDED_NONE`
 *|    if unblinded, `WALLY_PSET_BLINDED_REQUIRED` if only the blinding public
 *|    key is present, `WALLY_PSET_BLINDED_FULL` or `WALLY_PSET_BLINDED_PARTIAL`
 *|    if the blinding public key and all or only some blinding fields respectively
 *|    are present.
 *
 * .. note:: Returns WALLY_ERROR if the value or asset tag blinding key is invalid.
 */
WALLY_CORE_API int wally_psbt_output_get_blinding_status(
    const struct wally_psbt_output *output,
    uint32_t flags,
    size_t *written);
#endif /* WALLY_ABI_NO_ELEMENTS */

/**
 * Allocate and initialize a new PSBT.
 *
 * :param version: The version of the PSBT. Must be ``WALLY_PSBT_VERSION_0`` or ``WALLY_PSBT_VERSION_2``.
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param global_unknowns_allocation_len: The number of global unknowns to allocate space for.
 * :param flags: Flags controlling psbt creation. Must be 0 or `WALLY_PSBT_INIT_PSET`.
 * :param output: Destination for the resulting PSBT.
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
 * :param version: The version to use for the PSBT. Must be ``WALLY_PSBT_VERSION_0``
 *|    or ``WALLY_PSBT_VERSION_2``.
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
 * :param flags: :ref:`psbt-id-flags`.
 * :param bytes_out: Destination for the id.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_TXHASH_LEN)
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
 * Determine if a given PSBT input is finalized.
 *
 * :param psbt: The PSBT to check.
 * :param index: The zero-based index of the input to check.
 * :param written: On success, set to one if the input is finalized, otherwise zero.
 */
WALLY_CORE_API int wally_psbt_is_input_finalized(
    const struct wally_psbt *psbt,
    size_t index,
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
    uint32_t version);

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
 * :param flags: :ref:`psbt-txmod` indicating what can be modified.
 */
WALLY_CORE_API int wally_psbt_set_tx_modifiable_flags(
    struct wally_psbt *psbt,
    uint32_t flags);

#ifndef WALLY_ABI_NO_ELEMENTS
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
 * :param flags: :ref:`psbt-txmod` indicating what can be modified.
 */
WALLY_CORE_API int wally_psbt_set_pset_modifiable_flags(
    struct wally_psbt *psbt,
    uint32_t flags);
#endif /* WALLY_ABI_NO_ELEMENTS */

/**
 * Find the index of the PSBT input that spends a given UTXO.
 *
 * :param psbt: The PSBT to find in.
 * :param txhash: The transaction hash of the UTXO to search for.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` to
 *|     search for.
 * :param written: On success, set to zero if no matching input is found, otherwise
 *|    the index of the matching input plus one.
 */
WALLY_CORE_API int wally_psbt_find_input_spending_utxo(
    const struct wally_psbt *psbt,
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    size_t *written);

/**
 * Add a taproot keypath to a given PSBT input.
 *
 * :param psbt: The PSBT to add the taproot keypath to.
 * :param index: The zero-based index of the input to add to.
 * :param flags: Flags controlling keypath insertion. Must be 0.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_XONLY_PUBLIC_KEY_LEN`.
 * :param tapleaf_hashes: Series of 32-byte leaf hashes.
 * :param tapleaf_hashes_len: Length of ``tapleaf_hashes`` in bytes. Must be a multiple of `SHA256_LEN`.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be `BIP32_KEY_FINGERPRINT_LEN`.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_psbt_add_input_taproot_keypath(
    struct wally_psbt *psbt,
    uint32_t index,
    uint32_t flags,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *tapleaf_hashes,
    size_t tapleaf_hashes_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

/**
 * Add a transaction input to a PSBT at a given position.
 *
 * :param psbt: The PSBT to add the input to.
 * :param index: The zero-based index of the position to add the input at.
 * :param flags: Flags controlling input insertion. Must be 0 or `WALLY_PSBT_FLAG_NON_FINAL`.
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
 * Return a BIP32 derived key matching a keypath in a PSBT input.
 *
 * :param psbt: The PSBT containing the input whose keypaths to search.
 * :param index: The zero-based index of the input in the PSBT.
 * :param subindex: The zero-based index of the keypath to start searching from.
 * :param flags: Flags controlling the keypath search. Must be 0.
 * :param hdkey: The BIP32 parent key to derive matches from.
 * :param output: Destination for the resulting derived key, if any.
 *
 * .. note:: See `wally_map_keypath_get_bip32_key_from_alloc`.
 */
WALLY_CORE_API int wally_psbt_get_input_bip32_key_from_alloc(
    const struct wally_psbt *psbt,
    size_t index,
    size_t subindex,
    uint32_t flags,
    const struct ext_key *hdkey,
    struct ext_key **output);

/**
 * Get the length of the scriptPubKey or redeem script from a PSBT input.
 *
 * :param psbt: The PSBT containing the input to get from.
 * :param index: The zero-based index of the input to get the script length from.
 * :param written: Destination for the length of the script.
 */
WALLY_CORE_API int wally_psbt_get_input_signing_script_len(
    const struct wally_psbt *psbt,
    size_t index,
    size_t *written);

/**
 * Get the scriptPubKey or redeem script from a PSBT input.
 *
 * :param psbt: The PSBT containing the input to get from.
 * :param index: The zero-based index of the input to get the script from.
 * :param bytes_out: Destination for the scriptPubKey or redeem script.
 * :param len: Length of ``bytes`` in bytes.
 * :param written: Destination for the number of bytes written to bytes_out.
 */
WALLY_CORE_API int wally_psbt_get_input_signing_script(
    const struct wally_psbt *psbt,
    size_t index,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the scriptCode for signing a PSBT input.
 *
 * :param psbt: The PSBT containing the input to get from.
 * :param index: The zero-based index of the input to get the script from.
 * :param script: scriptPubKey/redeem script from `wally_psbt_get_input_signing_script`.
 * :param script_len: Length of ``script`` in bytes.
 * :param written: Destination for the length of the scriptCode.
 */
WALLY_CORE_API int wally_psbt_get_input_scriptcode_len(
    const struct wally_psbt *psbt,
    size_t index,
    const unsigned char *script,
    size_t script_len,
    size_t *written);

/**
 * Get the scriptCode for signing a PSBT input given its scriptPubKey/redeem script.
 *
 * :param psbt: The PSBT containing the input to get from.
 * :param index: The zero-based index of the input to get the script from.
 * :param script: scriptPubKey/redeem script from `wally_psbt_get_input_signing_script`.
 * :param script_len: Length of ``script`` in bytes.
 * :param bytes_out: Destination for the scriptCode.
 * :param len: Length of ``bytes`` in bytes.
 * :param written: Destination for the number of bytes written to bytes_out.
 */
WALLY_CORE_API int wally_psbt_get_input_scriptcode(
    const struct wally_psbt *psbt,
    size_t index,
    const unsigned char *script,
    size_t script_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create a transaction for signing a PSBT input and return its hash.
 *
 * :param psbt: The PSBT containing the input to compute a signature hash for.
 * :param index: The zero-based index of the PSBT input to sign.
 * :param tx: The transaction to generate the signature hash from.
 * :param script: The (unprefixed) scriptCode for the input being signed.
 * :param script_len: Length of ``script`` in bytes.
 * :param flags: Flags controlling signature hash generation. Must be 0.
 * :param bytes_out: Destination for the signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_psbt_get_input_signature_hash(
    struct wally_psbt *psbt,
    size_t index,
    const struct wally_tx *tx,
    const unsigned char *script,
    size_t script_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Add a taproot keypath to a given PSBT output.
 *
 * :param psbt: The PSBT to add the taproot keypath to.
 * :param index: The zero-based index of the output to add to.
 * :param flags: Flags controlling keypath insertion. Must be 0.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_XONLY_PUBLIC_KEY_LEN`.
 * :param tapleaf_hashes: Series of 32-byte leaf hashes.
 * :param tapleaf_hashes_len: Length of ``tapleaf_hashes`` in bytes. Must be a multiple of `SHA256_LEN`.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be `BIP32_KEY_FINGERPRINT_LEN`.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_psbt_add_output_taproot_keypath(
    struct wally_psbt *psbt,
    uint32_t index,
    uint32_t flags,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *tapleaf_hashes,
    size_t tapleaf_hashes_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

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
 * :param flags: `WALLY_PSBT_PARSE_FLAG_STRICT` or 0.
 * :param output: Destination for the resulting PSBT.
 */
WALLY_CORE_API int wally_psbt_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
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
 * :param bytes_out: Destination for the serialized PSBT.
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
 * :param flags: `WALLY_PSBT_PARSE_FLAG_STRICT` or 0.
 * :param output: Destination for the resulting PSBT.
 */
WALLY_CORE_API int wally_psbt_from_base64(
    const char *base64,
    uint32_t flags,
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
 * Create a PSBT from an existing transaction.
 *
 * :param tx: The transaction to create the PSBT from.
 * :param version: The PSBT version to create. Must be ``WALLY_PSBT_VERSION_0`` or ``WALLY_PSBT_VERSION_2``.
 * :param flags: Flags controlling psbt creation. Must be 0 or `WALLY_PSBT_INIT_PSET`.
 * :param output: Destination for the resulting PSBT.
 *
 * .. note:: Any input scriptSigs and witnesses from the transaction's inputs
 *|    are ignored when creating the PSBT.
 */
WALLY_CORE_API int wally_psbt_from_tx(
    const struct wally_tx *tx,
    uint32_t version,
    uint32_t flags,
    struct wally_psbt **output);

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

#ifndef WALLY_ABI_NO_ELEMENTS
/**
 * Blind a PSBT.
 *
 * :param psbt: PSBT to blind. Directly modifies this PSBT.
 * :param values: Integer map of input index to value for the callers inputs.
 * :param vbfs: Integer map of input index to value blinding factor for the callers inputs.
 * :param assets: Integer map of input index to asset tags for the callers inputs.
 * :param abfs: Integer map of input index to asset blinding factors for the callers inputs.
 * :param entropy: Random entropy for asset and blinding factor generation.
 * :param entropy_len: Size of ``entropy`` in bytes. Must be a multiple
 *|    of 5 * `BLINDING_FACTOR_LEN` for each non-fee output to be blinded, with
 *|    an additional 2 * `BLINDING_FACTOR_LEN` bytes for any issuance outputs.
 * :param output_index: The zero based index of the output to blind, or `WALLY_PSET_BLIND_ALL`.
 * :param flags: Flags controlling blinding. Must be 0.
 * :param output: Destination for a map of integer output index to the
 *|    ephemeral private key used to blind the output. Ignored if NULL.
 */
WALLY_CORE_API int wally_psbt_blind(
    struct wally_psbt *psbt,
    const struct wally_map *values,
    const struct wally_map *vbfs,
    const struct wally_map *assets,
    const struct wally_map *abfs,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t output_index,
    uint32_t flags,
    struct wally_map *output);

/**
 * Blind a PSBT.
 *
 * As per `wally_psbt_blind`, but allocates the ``output`` map.
 */
WALLY_CORE_API int wally_psbt_blind_alloc(
    struct wally_psbt *psbt,
    const struct wally_map *values,
    const struct wally_map *vbfs,
    const struct wally_map *assets,
    const struct wally_map *abfs,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t output_index,
    uint32_t flags,
    struct wally_map **output);
#endif /* WALLY_ABI_NO_ELEMENTS */

/**
 * Sign PSBT inputs corresponding to a given private key.
 *
 * :param psbt: PSBT to sign. Directly modifies this PSBT.
 * :param key: Private key to sign PSBT with.
 * :param key_len: Length of ``key`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param flags: Flags controlling signing. Must be 0 or EC_FLAG_GRIND_R.
 *
 * .. note:: See https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#simple-signer-algorithm
 *|    for a description of the signing algorithm.
 */
WALLY_CORE_API int wally_psbt_sign(
    struct wally_psbt *psbt,
    const unsigned char *key,
    size_t key_len,
    uint32_t flags);

/**
 * Sign PSBT inputs corresponding to a given BIP32 parent key.
 *
 * :param psbt: PSBT to sign. Directly modifies this PSBT.
 * :param hdkey: The parent extended key to derive signing keys from.
 * :param flags: Flags controlling signing. Must be 0 or EC_FLAG_GRIND_R.
 *
 * .. note:: See https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#simple-signer-algorithm
 *|    for a description of the signing algorithm.
 */
WALLY_CORE_API int wally_psbt_sign_bip32(
    struct wally_psbt *psbt,
    const struct ext_key *hdkey,
    uint32_t flags);

/**
 * Sign a single PSBT input with a given BIP32 key.
 *
 * :param psbt: PSBT containing the input to sign. Directly modifies this PSBT.
 * :param index: The zero-based index of the input in the PSBT.
 * :param subindex: The zero-based index of the keypath to start searching from.
 * :param txhash: The signature hash to sign, from `wally_psbt_get_input_signature_hash`.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
 * :param hdkey: The derived extended key to sign with.
 * :param flags: Flags controlling signing. Must be 0 or EC_FLAG_GRIND_R.
 */
WALLY_CORE_API int wally_psbt_sign_input_bip32(
    struct wally_psbt *psbt,
    size_t index,
    size_t subindex,
    const unsigned char *txhash,
    size_t txhash_len,
    const struct ext_key *hdkey,
    uint32_t flags);

/**
 * Finalize a PSBT.
 *
 * :param psbt: PSBT to finalize. Directly modifies this PSBT.
 * :param flags: Flags controlling finalization. Must be 0 or `WALLY_PSBT_FINALIZE_NO_CLEAR`.
 *
 * .. note:: This call does not return an error if no finalization is
 * performed. Use `wally_psbt_is_finalized` or `wally_psbt_input_is_finalized`
 * to determine the finalization status after calling.
 */
WALLY_CORE_API int wally_psbt_finalize(
    struct wally_psbt *psbt,
    uint32_t flags);

/**
 * Finalize a PSBT input.
 *
 * :param psbt: PSBT whose input to finalize. Directly modifies this PSBT.
 * :param index: The zero-based index of the input in the PSBT to finalize.
 * :param flags: Flags controlling finalization. Must be 0 or `WALLY_PSBT_FINALIZE_NO_CLEAR`.
 *
 * .. note:: This call does not return an error if no finalization is
 * performed. Use `wally_psbt_is_finalized` or `wally_psbt_input_is_finalized`
 * to determine the finalization status after calling.
 */
WALLY_CORE_API int wally_psbt_finalize_input(
    struct wally_psbt *psbt,
    size_t index,
    uint32_t flags);

/**
 * Extract a network transaction from a partially or fully finalized PSBT.
 *
 * :param psbt: PSBT to extract from.
 * :param flags: :ref:`psbt-extract` controlling extraction.
 * :param output: Destination for the resulting transaction.
 */
WALLY_CORE_API int wally_psbt_extract(
    const struct wally_psbt *psbt,
    uint32_t flags,
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
