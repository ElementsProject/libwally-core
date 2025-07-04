#ifndef LIBWALLY_CORE_TRANSACTION_H
#define LIBWALLY_CORE_TRANSACTION_H

#include "wally_core.h"
#include "wally_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WALLY_TX_SEQUENCE_FINAL 0xffffffff
#define WALLY_TX_VERSION_1 1
#define WALLY_TX_VERSION_2 2
#define WALLY_TX_IS_ELEMENTS 1
#define WALLY_TX_IS_ISSUANCE 2
#define WALLY_TX_IS_PEGIN 4
#define WALLY_TX_IS_COINBASE 8

#define WALLY_SATOSHI_PER_BTC 100000000
#define WALLY_BTC_MAX 21000000

#define WALLY_TXHASH_LEN 32 /** Size of a transaction hash in bytes */

#define WALLY_TX_FLAG_USE_WITNESS   0x1 /* Encode witness data if present */
#define WALLY_TX_FLAG_USE_ELEMENTS  0x2 /* Encode/Decode as an elements transaction */
#define WALLY_TX_FLAG_ALLOW_PARTIAL 0x4 /* Allow partially complete transactions */
/* Note: This flag encodes/parses transactions that are ambiguous to decode.
   Unless you have a good reason to do so you will most likely not need it */
#define WALLY_TX_FLAG_PRE_BIP144    0x8 /* Encode/Decode using pre-BIP 144 serialization */

#define WALLY_TX_FLAG_BLINDED_INITIAL_ISSUANCE 0x1

/*** tx-clone Transaction cloning flags */
#define WALLY_TX_CLONE_FLAG_NON_FINAL 0x1 /* Ignore scriptsig and witness when cloning */

#define WALLY_TX_DUMMY_NULL 0x1 /* An empty witness item */
#define WALLY_TX_DUMMY_SIG  0x2 /* A dummy signature */
#define WALLY_TX_DUMMY_SIG_LOW_R  0x4 /* A dummy signature created with EC_FLAG_GRIND_R */

/** Sighash flags for transaction signing */
#define WALLY_SIGHASH_DEFAULT      0x00
#define WALLY_SIGHASH_ALL          0x01
#define WALLY_SIGHASH_NONE         0x02
#define WALLY_SIGHASH_SINGLE       0x03
#define WALLY_SIGHASH_FORKID       0x40
#define WALLY_SIGHASH_RANGEPROOF   0x40  /* Liquid/Elements only */
#define WALLY_SIGHASH_ANYPREVOUT   0x40 /* BIP118 only */
#define WALLY_SIGHASH_ANYPREVOUTANYSCRIPT 0xc0 /* BIP118 only */
#define WALLY_SIGHASH_ANYONECANPAY 0x80

#define WALLY_SIGHASH_MASK         0x1f /* Mask for determining ALL/NONE/SINGLE */
#define WALLY_SIGHASH_TR_IN_MASK   0xc0 /* Taproot mask for determining input hash type */

/*** tx-sig-type Transaction signature type flags */
#define WALLY_SIGTYPE_PRE_SW  0x1 /* Pre-segwit signature hash */
#define WALLY_SIGTYPE_SW_V0   0x2 /* Segwit v0 signature hash */
#define WALLY_SIGTYPE_SW_V1   0x3 /* Segwit v1 (taproot) signature hash */
#define WALLY_SIGTYPE_MASK    0xf /* Mask for signature type in flags */

#define WALLY_TX_ASSET_CT_EMPTY_PREFIX    0x00
#define WALLY_TX_ASSET_CT_EXPLICIT_PREFIX 0x01
#define WALLY_TX_ASSET_CT_VALUE_PREFIX_A  0x08
#define WALLY_TX_ASSET_CT_VALUE_PREFIX_B  0x09
#define WALLY_TX_ASSET_CT_ASSET_PREFIX_A  0x0a
#define WALLY_TX_ASSET_CT_ASSET_PREFIX_B  0x0b
#define WALLY_TX_ASSET_CT_NONCE_PREFIX_A  0x02
#define WALLY_TX_ASSET_CT_NONCE_PREFIX_B  0x03

#define WALLY_TX_ASSET_TAG_LEN 32
#define WALLY_TX_ASSET_CT_VALUE_LEN 33 /* version byte + 32 bytes */
#define WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN 9 /* version byte + 8 bytes */
#define WALLY_TX_ASSET_CT_ASSET_LEN 33 /* version byte + 32 bytes */
#define WALLY_TX_ASSET_CT_NONCE_LEN 33 /* version byte + 32 bytes */
#define WALLY_TX_ASSET_CT_LEN 33       /* version byte + 32 bytes */

#define WALLY_TX_ISSUANCE_FLAG 0x80000000
#define WALLY_TX_PEGIN_FLAG 0x40000000
#define WALLY_TX_INDEX_MASK 0x3fffffff

#define WALLY_NO_CODESEPARATOR 0xffffffff /* No BIP342 code separator position */

struct wally_map;
#ifdef SWIG
struct wally_tx_witness_item;
struct wally_tx_witness_stack;
struct wally_tx_input;
struct wally_tx_output;
struct wally_tx;
#else
/** A transaction witness item */
struct wally_tx_witness_item {
    unsigned char *witness;
    size_t witness_len;
};

/** A transaction witness stack */
struct wally_tx_witness_stack {
    struct wally_tx_witness_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** A transaction input */
struct wally_tx_input {
    unsigned char txhash[WALLY_TXHASH_LEN];
    uint32_t index;
    uint32_t sequence;
    unsigned char *script;
    size_t script_len;
    struct wally_tx_witness_stack *witness;
    uint8_t features;
#ifndef WALLY_ABI_NO_ELEMENTS
    unsigned char blinding_nonce[SHA256_LEN];
    unsigned char entropy[SHA256_LEN];
    unsigned char *issuance_amount;
    size_t issuance_amount_len;
    unsigned char *inflation_keys;
    size_t inflation_keys_len;
    unsigned char *issuance_amount_rangeproof;
    size_t issuance_amount_rangeproof_len;
    unsigned char *inflation_keys_rangeproof;
    size_t inflation_keys_rangeproof_len;
    struct wally_tx_witness_stack *pegin_witness;
#endif /* WALLY_ABI_NO_ELEMENTS */
};

/** A transaction output */
struct wally_tx_output {
    uint64_t satoshi;
    unsigned char *script;
    size_t script_len;
    uint8_t features;
#ifndef WALLY_ABI_NO_ELEMENTS
    unsigned char *asset;
    size_t asset_len;
    unsigned char *value;
    size_t value_len;
    unsigned char *nonce;
    size_t nonce_len;
    unsigned char *surjectionproof;
    size_t surjectionproof_len;
    unsigned char *rangeproof;
    size_t rangeproof_len;
#endif /* WALLY_ABI_NO_ELEMENTS */
};

/** A parsed bitcoin transaction */
struct wally_tx {
    uint32_t version;
    uint32_t locktime;
    struct wally_tx_input *inputs;
    size_t num_inputs;
    size_t inputs_allocation_len;
    struct wally_tx_output *outputs;
    size_t num_outputs;
    size_t outputs_allocation_len;
};
#endif /* SWIG */

/**
 * Allocate and initialize a new witness stack.
 *
 * :param allocation_len: The number of items to pre-allocate space for.
 * :param output: Destination for the resulting witness stack.
 */
WALLY_CORE_API int wally_tx_witness_stack_init_alloc(
    size_t allocation_len,
    struct wally_tx_witness_stack **output);

/**
 * Create a copy of a witness stack.
 *
 * :param stack: The witness stack to copy.
 * :param output: Destination for the resulting copy.
 */
WALLY_CORE_API int wally_tx_witness_stack_clone_alloc(
    const struct wally_tx_witness_stack *stack,
    struct wally_tx_witness_stack **output);

/**
 * Return the number of witness items in a witness stack.
 *
 * :param stack: The witness stack to get the number of items from.
 * :param written: Destination for the number of items.
 */
WALLY_CORE_API int wally_tx_witness_stack_get_num_items(
    const struct wally_tx_witness_stack *stack,
    size_t *written);

/**
 * Add a witness to a witness stack.
 *
 * :param stack: The witness stack to add to.
 * :param witness: The witness data to add to the stack.
 * :param witness_len: Length of ``witness`` in bytes.
 */
WALLY_CORE_API int wally_tx_witness_stack_add(
    struct wally_tx_witness_stack *stack,
    const unsigned char *witness,
    size_t witness_len);

/**
 * Add a dummy witness item to a witness stack.
 *
 * :param stack: The witness stack to add to.
 * :param flags: ``WALLY_TX_DUMMY_`` Flags indicating the type of dummy to add.
 */
WALLY_CORE_API int wally_tx_witness_stack_add_dummy(
    struct wally_tx_witness_stack *stack,
    uint32_t flags);

/**
 * Set a witness item to a witness stack.
 *
 * :param stack: The witness stack to add to.
 * :param index: Index of the item to set. The stack will grow if needed to this many items.
 * :param witness: The witness data to add to the stack.
 * :param witness_len: Length of ``witness`` in bytes.
 */
WALLY_CORE_API int wally_tx_witness_stack_set(
    struct wally_tx_witness_stack *stack,
    size_t index,
    const unsigned char *witness,
    size_t witness_len);

/**
 * Set a dummy witness item to a witness stack.
 *
 * :param stack: The witness stack to add to.
 * :param index: Index of the item to set. The stack will grow if needed to this many items.
 * :param flags: ``WALLY_TX_DUMMY_`` Flags indicating the type of dummy to set.
 */
WALLY_CORE_API int wally_tx_witness_stack_set_dummy(
    struct wally_tx_witness_stack *stack,
    size_t index,
    uint32_t flags);

/**
 * Create a new witness stack from its BIP 144 serialization.
 *
 * :param bytes: Bytes to create the witness stack from.
 * :param bytes_len: Length of ``bytes`` in bytes.
 * :param output: Destination for the resulting witness stack.
 */
WALLY_CORE_API int wally_tx_witness_stack_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_tx_witness_stack **output);

/**
 * Return the length of a witness stacks BIP 144 serialization.
 *
 * :param stack: The witness stack to find the serialized length of.
 * :param written: Destination for the length of the serialized bytes.
 */
WALLY_CORE_API int wally_tx_witness_stack_get_length(
    const struct wally_tx_witness_stack *stack,
    size_t *written);

/**
 * Serialize a witness stack to its BIP 144 serialization.
 *
 * :param stack: The witness stack to serialize.
 * :param bytes_out: Destination for the serialized witness stack.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the length of the serialized witness stack.
 */
WALLY_CORE_API int wally_tx_witness_stack_to_bytes(
    const struct wally_tx_witness_stack *stack,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Free a transaction witness stack allocated by `wally_tx_witness_stack_init_alloc`.
 *
 * :param stack: The transaction witness stack to free.
 */
WALLY_CORE_API int wally_tx_witness_stack_free(
    struct wally_tx_witness_stack *stack);

/**
 * Allocate and initialize a new transaction input.
 *
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param output: Destination for the resulting transaction input.
 */
WALLY_CORE_API int wally_tx_input_init_alloc(
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    uint32_t sequence,
    const unsigned char *script,
    size_t script_len,
    const struct wally_tx_witness_stack *witness,
    struct wally_tx_input **output);

/**
 * Create a new copy of a transaction input.
 *
 * :param tx_input_in: The transaction input to clone.
 * :param input: Destination for the resulting transaction input copy.
 */
WALLY_CORE_API int wally_tx_input_clone_alloc(
    const struct wally_tx_input *tx_input_in,
    struct wally_tx_input **input);

/**
 * Create a new copy of a transaction input in place.
 *
 * :param tx_input_in: The transaction input to clone.
 * :param input: Destination for the resulting transaction input copy.
 *
 * .. note:: ``input`` is overwritten in place, and not cleared first.
 */
WALLY_CORE_API int wally_tx_input_clone(
    const struct wally_tx_input *tx_input_in,
    struct wally_tx_input *input);

/**
 * Free a transaction input allocated by `wally_tx_input_init_alloc`.
 *
 * :param input: The transaction input to free.
 */
WALLY_CORE_API int wally_tx_input_free(struct wally_tx_input *input);

/**
 * Initialize a new transaction output.
 *
 * :param satoshi: The amount of the output in satoshi.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param output: Transaction output to initialize.
 */
WALLY_CORE_API int wally_tx_output_init(uint64_t satoshi,
                                        const unsigned char *script,
                                        size_t script_len,
                                        struct wally_tx_output *output);

/**
 * Allocate and initialize a new transaction output.
 *
 * :param satoshi: The amount of the output in satoshi.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param output: Destination for the resulting transaction output.
 */
WALLY_CORE_API int wally_tx_output_init_alloc(
    uint64_t satoshi,
    const unsigned char *script,
    size_t script_len,
    struct wally_tx_output **output);

/**
 * Create a new copy of a transaction output.
 *
 * :param tx_output_in: The transaction output to clone.
 * :param output: Destination for the resulting transaction output copy.
 */
WALLY_CORE_API int wally_tx_output_clone_alloc(
    const struct wally_tx_output *tx_output_in,
    struct wally_tx_output **output);

/**
 * Create a new copy of a transaction output in place.
 *
 * :param tx_output_in: The transaction output to clone.
 * :param output: Destination for the resulting transaction output copy.
 *
 * .. note:: ``output`` is overwritten in place, and not cleared first.
 */
WALLY_CORE_API int wally_tx_output_clone(
    const struct wally_tx_output *tx_output_in,
    struct wally_tx_output *output);

/**
 * Free a transaction output allocated by `wally_tx_output_init_alloc`.
 *
 * :param output: The transaction output to free.
 */
WALLY_CORE_API int wally_tx_output_free(struct wally_tx_output *output);

/**
 * Allocate and initialize a new transaction.
 *
 * :param version: The version of the transaction.
 * :param locktime: The locktime of the transaction.
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param output: Destination for the resulting transaction.
 */
WALLY_CORE_API int wally_tx_init_alloc(
    uint32_t version,
    uint32_t locktime,
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    struct wally_tx **output);

/**
 * Create a new copy of a transaction.
 *
 * :param tx: The transaction to clone.
 * :param flags: :ref:`tx-clone` controlling new transaction creation.
 * :param output: Destination for the resulting transaction copy.
 */
WALLY_CORE_API int wally_tx_clone_alloc(
    const struct wally_tx *tx,
    uint32_t flags,
    struct wally_tx **output);

/**
 * Add a transaction input to a transaction.
 *
 * :param tx: The transaction to add the input to.
 * :param input: The transaction input to add to ``tx``.
 */
WALLY_CORE_API int wally_tx_add_input(
    struct wally_tx *tx,
    const struct wally_tx_input *input);

/**
 * Add a transaction input to a transaction at a given position.
 *
 * :param tx: The transaction to add the input to.
 * :param index: The zero-based index of the position to add the input at.
 * :param input: The transaction input to add to ``tx``.
 */
WALLY_CORE_API int wally_tx_add_input_at(
    struct wally_tx *tx,
    uint32_t index,
    const struct wally_tx_input *input);

/**
 * Add a transaction input to a transaction.
 *
 * :param tx: The transaction to add the input to.
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param flags: Flags controlling input creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_raw_input(
    struct wally_tx *tx,
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    uint32_t sequence,
    const unsigned char *script,
    size_t script_len,
    const struct wally_tx_witness_stack *witness,
    uint32_t flags);

/**
 * Add a transaction input to a transaction in a given position.
 *
 * :param tx: The transaction to add the input to.
 * :param index: The zero-based index of the position to add the input at.
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param flags: Flags controlling input creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_raw_input_at(
    struct wally_tx *tx,
    uint32_t index,
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    uint32_t sequence,
    const unsigned char *script,
    size_t script_len,
    const struct wally_tx_witness_stack *witness,
    uint32_t flags);

/**
 * Remove a transaction input from a transaction.
 *
 * :param tx: The transaction to remove the input from.
 * :param index: The zero-based index of the input to remove.
 */
WALLY_CORE_API int wally_tx_remove_input(
    struct wally_tx *tx,
    size_t index);

/**
 * Set the scriptsig for an input in a transaction.
 *
 * :param tx: The transaction to operate on.
 * :param index: The zero-based index of the input to set the script on.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 */
WALLY_CORE_API int wally_tx_set_input_script(
    const struct wally_tx *tx,
    size_t index,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the witness stack for an input in a transaction.
 *
 * :param tx: The transaction to operate on.
 * :param index: The zero-based index of the input to set the witness stack on.
 * :param stack: The transaction witness stack to set.
 */

WALLY_CORE_API int wally_tx_set_input_witness(
    const struct wally_tx *tx,
    size_t index,
    const struct wally_tx_witness_stack *stack);

/**
 * Add a transaction output to a transaction.
 *
 * :param tx: The transaction to add the output to.
 * :param output: The transaction output to add to ``tx``.
 */
WALLY_CORE_API int wally_tx_add_output(
    struct wally_tx *tx,
    const struct wally_tx_output *output);

/**
 * Add a transaction output to a transaction at a given position.
 *
 * :param tx: The transaction to add the output to.
 * :param index: The zero-based index of the position to add the output at.
 * :param output: The transaction output to add to ``tx``.
 */
WALLY_CORE_API int wally_tx_add_output_at(
    struct wally_tx *tx,
    uint32_t index,
    const struct wally_tx_output *output);

/**
 * Add a transaction output to a transaction.
 *
 * :param tx: The transaction to add the output to.
 * :param satoshi: The amount of the output in satoshi.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param flags: Flags controlling output creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_raw_output(
    struct wally_tx *tx,
    uint64_t satoshi,
    const unsigned char *script,
    size_t script_len,
    uint32_t flags);

/**
 * Add a transaction output to a transaction at a given position.
 *
 * :param tx: The transaction to add the output to.
 * :param index: The zero-based index of the position to add the output at.
 * :param satoshi: The amount of the output in satoshi.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param flags: Flags controlling output creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_raw_output_at(
    struct wally_tx *tx,
    uint32_t index,
    uint64_t satoshi,
    const unsigned char *script,
    size_t script_len,
    uint32_t flags);

/**
 * Remove a transaction output from a transaction.
 *
 * :param tx: The transaction to remove the output from.
 * :param index: The zero-based index of the output to remove.
 */
WALLY_CORE_API int wally_tx_remove_output(
    struct wally_tx *tx,
    size_t index);

/**
 * Get the number of inputs in a transaction that have witness data.
 *
 * :param tx: The transaction to get the witnesses count from.
 * :param written: Destination for the number of witness-containing inputs.
 */
WALLY_CORE_API int wally_tx_get_witness_count(
    const struct wally_tx *tx,
    size_t *written);

/**
 * Free a transaction allocated by `wally_tx_init_alloc`.
 *
 * :param tx: The transaction to free.
 */
WALLY_CORE_API int wally_tx_free(struct wally_tx *tx);

/**
 * Return the txid of a transaction.
 *
 * :param tx: The transaction to compute the txid of.
 * :param bytes_out: Destination for the txid.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_TXHASH_LEN)
 *
 * .. note:: The txid is expensive to compute.
 */
WALLY_CORE_API int wally_tx_get_txid(
    const struct wally_tx *tx,
    unsigned char *bytes_out,
    size_t len);

/**
 * Calculate the BIP 143 hashPrevouts of a list of input txids and output indices.
 *
 * :param txhashes: The input txids to compute the hash from.
 * :param txhashes_len: Length of ``txhashes`` in bytes. Must be a multiple of `WALLY_TXHASH_LEN`.
 * :param utxo_indices: The output indices of the txids in ``txhashes``.
 * :param num_utxo_indices: The number of output indices in ``utxo_indices``. You must
 *|    pass one index for every txhash in ``txhashes``.
 * :param bytes_out: Destination for the hashPrevouts bytes.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_get_hash_prevouts(
    const unsigned char *txhashes,
    size_t txhashes_len,
    const uint32_t *utxo_indices,
    size_t num_utxo_indices,
    unsigned char *bytes_out,
    size_t len);

/**
 * Return the BIP 143 hashPrevouts of a transaction.
 *
 * :param tx: The transaction to compute the hashPrevouts of.
 * :param index: The zero-based index of the input to start hashing from.
 *|    Pass 0 to start from the first input.
 * :param num_inputs: The number of inputs to hash starting from the first.
 *|    If ``index`` is given as 0, you can pass 0xffffffff to use all inputs.
 * :param bytes_out: Destination for the hashPrevouts bytes.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 *
 * .. note:: The hash is computed without reference to any sighash flags,
 *|    and so will not match BIP143 for `WALLY_SIGHASH_ANYONECANPAY`.
 */
WALLY_CORE_API int wally_tx_get_hash_prevouts(
    const struct wally_tx *tx,
    size_t index,
    size_t num_inputs,
    unsigned char *bytes_out,
    size_t len);

/**
 * Return the length of transaction once serialized into bytes.
 *
 * :param tx: The transaction to find the serialized length of.
 * :param flags: ``WALLY_TX_FLAG_`` Flags controlling serialization options.
 * :param written: Destination for the length of the serialized bytes.
 */
WALLY_CORE_API int wally_tx_get_length(
    const struct wally_tx *tx,
    uint32_t flags,
    size_t *written);

/**
 * Create a transaction from its serialized bytes.
 *
 * :param bytes: Bytes to create the transaction from.
 * :param bytes_len: Length of ``bytes`` in bytes.
 * :param flags: ``WALLY_TX_FLAG_`` Flags controlling serialization options.
 * :param output: Destination for the resulting transaction.
 */
WALLY_CORE_API int wally_tx_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    struct wally_tx **output);

/**
 * Create a transaction from its serialized bytes in hexadecimal.
 *
 * :param hex: Hexadecimal string containing the transaction.
 * :param flags: ``WALLY_TX_FLAG_`` Flags controlling serialization options.
 * :param output: Destination for the resulting transaction.
 */
WALLY_CORE_API int wally_tx_from_hex(
    const char *hex,
    uint32_t flags,
    struct wally_tx **output);

/**
 * Serialize a transaction to bytes.
 *
 * :param tx: The transaction to serialize.
 * :param flags: ``WALLY_TX_FLAG_`` Flags controlling serialization options.
 * :param bytes_out: Destination for the serialized transaction.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the length of the serialized transaction.
 */
WALLY_CORE_API int wally_tx_to_bytes(
    const struct wally_tx *tx,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Serialize a transaction to hex.
 *
 * :param tx: The transaction to serialize.
 * :param flags: ``WALLY_TX_FLAG_`` Flags controlling serialization options.
 * :param output: Destination for the resulting hexadecimal string.
 *
 * .. note:: The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_tx_to_hex(
    const struct wally_tx *tx,
    uint32_t flags,
    char **output);

/**
 * Get the weight of a transaction.
 *
 * :param tx: The transaction to get the weight of.
 * :param written: Destination for the weight.
 */
WALLY_CORE_API int wally_tx_get_weight(
    const struct wally_tx *tx,
    size_t *written);

/**
 * Get the virtual size of a transaction.
 *
 * :param tx: The transaction to get the virtual size of.
 * :param written: Destination for the virtual size.
 */
WALLY_CORE_API int wally_tx_get_vsize(
    const struct wally_tx *tx,
    size_t *written);

/**
 * Compute transaction vsize from transaction weight.
 *
 * :param weight: The weight to convert to a virtual size.
 * :param written: Destination for the virtual size.
 */
WALLY_CORE_API int wally_tx_vsize_from_weight(
    size_t weight,
    size_t *written);

/**
 * Compute the total sum of all outputs in a transaction.
 *
 * :param tx: The transaction to compute the total from.
 * :param value_out: Destination for the output total.
 */
WALLY_CORE_API int wally_tx_get_total_output_satoshi(
    const struct wally_tx *tx,
    uint64_t *value_out);

/**
 * Get the hash of the preimage for signing a BTC transaction input.
 *
 * Deprecated, this call will be removed in a future release. Please
 * use ``wally_tx_get_input_signature_hash``.
 *
 * :param tx: The transaction to generate the signature hash from.
 * :param index: The input index of the input being signed for.
 * :param script: The (unprefixed) scriptCode for the input being signed.
 * :param script_len: Size of ``script`` in bytes.
 * :param satoshi: The amount spent by the input being signed for. Only used if
 *|     flags includes `WALLY_TX_FLAG_USE_WITNESS`, pass 0 otherwise.
 * :param sighash: ``WALLY_SIGHASH_`` flags specifying the type of signature desired.
 * :param flags: `WALLY_TX_FLAG_USE_WITNESS` to generate a BIP 143 signature, or 0
 *|     to generate a pre-segwit Bitcoin signature.
 * :param bytes_out: Destination for the signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_tx_get_btc_signature_hash(
    const struct wally_tx *tx,
    size_t index,
    const unsigned char *script,
    size_t script_len,
    uint64_t satoshi,
    uint32_t sighash,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Get the hash of the preimage for signing a BTC taproot transaction input.
 *
 * Deprecated, this call will be removed in a future release. Please
 * use ``wally_tx_get_input_signature_hash``.
 *
 * :param tx: The transaction to generate the signature hash from.
 * :param index: The input index of the input being signed for.
 * :param scripts: Map of input index to (unprefixed) scriptCodes for each input in ``tx``.
 * :param values: The value in satoshi for each input in ``tx``.
 * :param num_values: The number of elements in ``values``.
 * :param tapleaf_script: BIP342 tapscript being spent.
 * :param tapleaf_script_len: Length of ``tapleaf_script`` in bytes.
 * :param key_version: Version of pubkey in tapscript. Must be set to 0x00 or 0x01.
 * :param codesep_position: BIP342 codeseparator position or ``WALLY_NO_CODESEPARATOR`` if none.
 * :param annex: BIP341 annex, or NULL if none.
 * :param annex_len: Length of ``annex`` in bytes.
 * :param sighash: ``WALLY_SIGHASH_`` flags specifying the type of signature desired.
 * :param flags: Flags controlling signature generation. Must be 0.
 * :param bytes_out: Destination for the resulting signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
*/
WALLY_CORE_API int wally_tx_get_btc_taproot_signature_hash(
    const struct wally_tx *tx,
    size_t index,
    const struct wally_map *scripts,
    const uint64_t *values,
    size_t num_values,
    const unsigned char *tapleaf_script,
    size_t tapleaf_script_len,
    uint32_t key_version,
    uint32_t codesep_position,
    const unsigned char *annex,
    size_t annex_len,
    uint32_t sighash,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Get the hash of the preimage for signing a BTC transaction input.
 *
 * Deprecated, this call will be removed in a future release. Please
 * use ``wally_tx_get_input_signature_hash``.
 *
 * :param tx: The transaction to generate the signature hash from.
 * :param index: The input index of the input being signed for.
 * :param script: The (unprefixed) scriptCode for the input being signed.
 * :param script_len: Size of ``script`` in bytes.
 * :param extra: Extra bytes to include in the transaction preimage.
 * :param extra_len: Size of ``extra`` in bytes.
 * :param extra_offset: Offset within the preimage to store ``extra``. To store
 *|     it at the end of the preimage, use 0xffffffff.
 * :param satoshi: The amount spent by the input being signed for. Only used if
 *|     flags includes `WALLY_TX_FLAG_USE_WITNESS`, pass 0 otherwise.
 * :param sighash: ``WALLY_SIGHASH_`` flags specifying the type of signature desired.
 * :param tx_sighash: The 32bit sighash value to include in the preimage to hash.
 *|     This must be given in host CPU endianness; For normal Bitcoin signing
 *|     the value of ``sighash`` should be given.
 * :param flags: `WALLY_TX_FLAG_USE_WITNESS` to generate a BIP 143 signature, or 0
 *|     to generate a pre-segwit Bitcoin signature.
 * :param bytes_out: Destination for the signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_tx_get_signature_hash(
    const struct wally_tx *tx,
    size_t index,
    const unsigned char *script,
    size_t script_len,
    const unsigned char *extra,
    size_t extra_len,
    uint32_t extra_offset,
    uint64_t satoshi,
    uint32_t sighash,
    uint32_t tx_sighash,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Get the hash of the preimage for signing a transaction input.
 *
 * :param tx: The transaction to generate the signature hash from.
 * :param index: The input index of the input being signed for.
 * :param scripts: The scriptpubkeys of each input in the transaction, indexed
 *|    by their 0-based input index. For non-taproot signing, only the
 *|    scriptpubkey of ``index`` is required.
 * :param assets: The asset commitments of each input in the transaction,
 *|    or NULL for non-Elements transactions. Ignored for non-taproot signing.
 * :param values: The satoshi values(BTC) or value commitments(Elements) of
 *|    each input in the transaction. BTC values must be stored as bytes with
 *|    uint64/host endiannes. For non-taproot signing, only the value
 *|    of ``index`` is required.
 * :param script: For segwit v0 signing, the scriptcode of the input to sign
 *|    for. For taproot, the leaf script to sign with if any. Ignored for
 *|    pre-segwit signing.
 * :param script_len: Length of ``script`` in bytes.
 * :param key_version: For taproot signing, the version of the pubkey
 *|    in ``script`` when signing with a script path. Currently must be ``1``
 *|    for this case. For non-taproot or keypath signing, it must be ``0``.
 * :param codesep_position: BIP342 codeseparator position
 *|    or ``WALLY_NO_CODESEPARATOR`` if none. Only used for taproot signing.
 * :param annex: BIP341 annex, or NULL if none.
 * :param annex_len: Length of ``annex`` in bytes. Only used for taproot signing.
 * :param genesis_blockhash: The genesis blockhash of the chain to sign for,
 *|    or NULL for non-Elements transactions. Only used for taproot signing.
 * :param genesis_blockhash_len: Length of ``genesis_blockhash`` in bytes. Must
 *|    be `SHA256_LEN` or 0.
 * :param sighash: ``WALLY_SIGHASH_`` flags specifying the sighash flags
 *|    to sign with.
 * :param flags: :ref:`tx-sig-type` controlling signature hash generation.
 * :param cache: An opaque cache for faster generation, or NULL to disable
 *|    caching. Must be empty on the first call to this function for a given
 *|    transaction, and only used for signing the inputs of the same ``tx``.
 * :param bytes_out: Destination for the resulting signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_tx_get_input_signature_hash(
    const struct wally_tx *tx,
    size_t index,
    const struct wally_map *scripts,
    const struct wally_map *assets,
    const struct wally_map *values,
    const unsigned char *script,
    size_t script_len,
    uint32_t key_version,
    uint32_t codesep_position,
    const unsigned char *annex,
    size_t annex_len,
    const unsigned char *genesis_blockhash,
    size_t genesis_blockhash_len,
    uint32_t sighash,
    uint32_t flags,
    struct wally_map *cache,
    unsigned char *bytes_out,
    size_t len);

/**
 * Determine if a transaction is a coinbase transaction.
 *
 * :param tx: The transaction to check.
 * :param written: 1 if the transaction is a coinbase transaction, otherwise 0.
 */
WALLY_CORE_API int wally_tx_is_coinbase(
    const struct wally_tx *tx,
    size_t *written);

#ifndef WALLY_ABI_NO_ELEMENTS
/**
 * Calculate any applicable transaction weight discount for an Elements transaction.
 *
 * :param tx: The transaction to compute the weight discount for.
 * :param flags: Unused, must be 0.
 * :param written: Destination for the weight discount.
 *
 * .. note:: The discount may be 0 if the transaction has no confidential outputs.
 */
WALLY_CORE_API int wally_tx_get_elements_weight_discount(
    const struct wally_tx *tx,
    uint32_t flags,
    size_t *written);

/**
 * Set issuance data on an input.
 *
 * :param input: The input to add to.
 * :param nonce: Asset issuance or revelation blinding factor.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `SHA256_LEN`.
 * :param entropy: Entropy for the asset tag calculation.
 * :param entropy_len: Size of ``entropy`` in bytes. Must be `SHA256_LEN`.
 * :param issuance_amount: The (blinded) issuance amount.
 * :param issuance_amount_len: Size of ``issuance_amount`` in bytes.
 * :param inflation_keys: The (blinded) token reissuance amount.
 * :param inflation_keys_len: Size of ``ìnflation_keys`` in bytes.
 * :param issuance_amount_rangeproof: Issuance amount rangeproof.
 * :param issuance_amount_rangeproof_len: Size of ``issuance_amount_rangeproof`` in bytes.
 * :param inflation_keys_rangeproof: Inflation keys rangeproof.
 * :param inflation_keys_rangeproof_len: Size of ``inflation_keys_rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_tx_elements_input_issuance_set(
    struct wally_tx_input *input,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *entropy,
    size_t entropy_len,
    const unsigned char *issuance_amount,
    size_t issuance_amount_len,
    const unsigned char *inflation_keys,
    size_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof,
    size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof,
    size_t inflation_keys_rangeproof_len);

/**
 * Free issuance data on an input.
 *
 * :param input: The input issuance data to free.
 */
WALLY_CORE_API int wally_tx_elements_input_issuance_free(
    struct wally_tx_input *input);

/**
 * Allocate and initialize a new elements transaction input.
 *
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param nonce: Asset issuance or revelation blinding factor.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `SHA256_LEN`.
 * :param entropy: Entropy for the asset tag calculation.
 * :param entropy_len: Size of ``entropy`` in bytes. Must be `SHA256_LEN`.
 * :param issuance_amount: The (blinded) issuance amount.
 * :param issuance_amount_len: Size of ``issuance_amount`` in bytes.
 * :param inflation_keys: The (blinded) token reissuance amount.
 * :param inflation_keys_len: Size of ``ìnflation_keys`` in bytes.
 * :param issuance_amount_rangeproof: Issuance amount rangeproof.
 * :param issuance_amount_rangeproof_len: Size of ``issuance_amount_rangeproof`` in bytes.
 * :param inflation_keys_rangeproof: Inflation keys rangeproof.
 * :param inflation_keys_rangeproof_len: Size of ``inflation_keys_rangeproof`` in bytes.
 * :param pegin_witness: The pegin witness stack for the input, or NULL if no witness is present.
 * :param output: Destination for the resulting transaction input.
 */
WALLY_CORE_API int wally_tx_elements_input_init_alloc(
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    uint32_t sequence,
    const unsigned char *script,
    size_t script_len,
    const struct wally_tx_witness_stack *witness,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *entropy,
    size_t entropy_len,
    const unsigned char *issuance_amount,
    size_t issuance_amount_len,
    const unsigned char *inflation_keys,
    size_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof,
    size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof,
    size_t inflation_keys_rangeproof_len,
    const struct wally_tx_witness_stack *pegin_witness,
    struct wally_tx_input **output);

/**
 * Determine if an input is a pegin.
 *
 * :param input: The input to check.
 * :param written: 1 if the input is a pegin, otherwise 0.
 */
WALLY_CORE_API int wally_tx_elements_input_is_pegin(
    const struct wally_tx_input *input,
    size_t *written);

/**
 * Set commitment data on an output.
 *
 * :param output: The output to add to.
 * :param asset: The commitment to a possibly blinded asset.
 * :param asset_len: Size of ``asset`` in bytes. Must be `WALLY_TX_ASSET_CT_ASSET_LEN`.
 * :param value: The commitment to a possibly blinded value.
 * :param value_len: Size of ``value`` in bytes. Must be `WALLY_TX_ASSET_CT_VALUE_LEN` or `WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN`.
 * :param nonce: The commitment used to create the nonce (with the blinding key) for the range proof.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `WALLY_TX_ASSET_CT_NONCE_LEN`.
 * :param surjectionproof: surjection proof.
 * :param surjectionproof_len: Size of ``surjectionproof`` in bytes.
 * :param rangeproof: rangeproof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 */
WALLY_CORE_API int wally_tx_elements_output_commitment_set(
    struct wally_tx_output *output,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *value,
    size_t value_len,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *surjectionproof,
    size_t surjectionproof_len,
    const unsigned char *rangeproof,
    size_t rangeproof_len);

/**
 * Free commitment data on an output.
 *
 * :param output: The output with the commitment data to free.
 */
WALLY_CORE_API int wally_tx_elements_output_commitment_free(
    struct wally_tx_output *output);

/**
 * Initialize a new elements transaction output in place.
 *
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param asset: The asset tag of the output.
 * :param asset_len: Size of ``asset`` in bytes. Must be `WALLY_TX_ASSET_CT_ASSET_LEN`.
 * :param value: The commitment to a possibly blinded value.
 * :param value_len: Size of ``value`` in bytes. Must be `WALLY_TX_ASSET_CT_VALUE_LEN` or `WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN`.
 * :param nonce: The commitment used to create the nonce (with the blinding key) for the range proof.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `WALLY_TX_ASSET_CT_NONCE_LEN`.
 * :param surjectionproof: The surjection proof.
 * :param surjectionproof_len: Size of ``surjectionproof`` in bytes.
 * :param rangeproof: The range proof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 * :param output: Destination for the resulting transaction output copy.
 *
 * .. note:: ``output`` is overwritten in place, and not cleared first.
 */
WALLY_CORE_API int wally_tx_elements_output_init(
    const unsigned char *script,
    size_t script_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *value,
    size_t value_len,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *surjectionproof,
    size_t surjectionproof_len,
    const unsigned char *rangeproof,
    size_t rangeproof_len,
    struct wally_tx_output *output);

/**
 * Allocate and initialize a new elements transaction output.
 *
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param asset: The asset tag of the output.
 * :param asset_len: Size of ``asset`` in bytes. Must be `WALLY_TX_ASSET_CT_ASSET_LEN`.
 * :param value: The commitment to a possibly blinded value.
 * :param value_len: Size of ``value`` in bytes. Must be `WALLY_TX_ASSET_CT_VALUE_LEN` or `WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN`.
 * :param nonce: The commitment used to create the nonce (with the blinding key) for the range proof.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `WALLY_TX_ASSET_CT_NONCE_LEN`.
 * :param surjectionproof: The surjection proof.
 * :param surjectionproof_len: Size of ``surjectionproof`` in bytes.
 * :param rangeproof: The range proof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 * :param output: Destination for the resulting transaction output.
 */
WALLY_CORE_API int wally_tx_elements_output_init_alloc(
    const unsigned char *script,
    size_t script_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *value,
    size_t value_len,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *surjectionproof,
    size_t surjectionproof_len,
    const unsigned char *rangeproof,
    size_t rangeproof_len,
    struct wally_tx_output **output);

/**
 * Add an elements transaction input to a transaction.
 *
 * :param tx: The transaction to add the input to.
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param nonce: Asset issuance or revelation blinding factor.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `SHA256_LEN`.
 * :param entropy: Entropy for the asset tag calculation.
 * :param entropy_len: Size of ``entropy`` in bytes. Must be `SHA256_LEN`.
 * :param issuance_amount: The (blinded) issuance amount.
 * :param issuance_amount_len: Size of ``issuance_amount`` in bytes.
 * :param inflation_keys: The (blinded) token reissuance amount.
 * :param inflation_keys_len: Size of ``ìnflation_keys`` in bytes.
 * :param issuance_amount_rangeproof: Issuance amount rangeproof.
 * :param issuance_amount_rangeproof_len: Size of ``issuance_amount_rangeproof`` in bytes.
 * :param inflation_keys_rangeproof: Inflation keys rangeproof.
 * :param inflation_keys_rangeproof_len: Size of ``inflation_keys_rangeproof`` in bytes.
 * :param pegin_witness: The pegin witness stack for the input, or NULL if no witness is present.
 * :param flags: Flags controlling input creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_elements_raw_input(
    struct wally_tx *tx,
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    uint32_t sequence,
    const unsigned char *script,
    size_t script_len,
    const struct wally_tx_witness_stack *witness,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *entropy,
    size_t entropy_len,
    const unsigned char *issuance_amount,
    size_t issuance_amount_len,
    const unsigned char *inflation_keys,
    size_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof,
    size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof,
    size_t inflation_keys_rangeproof_len,
    const struct wally_tx_witness_stack *pegin_witness,
    uint32_t flags);

/**
 * Add an elements transaction input to a transaction at a given position.
 *
 * :param tx: The transaction to add the input to.
 * :param index: The zero-based index of the position to add the input at.
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param nonce: Asset issuance or revelation blinding factor.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `SHA256_LEN`.
 * :param entropy: Entropy for the asset tag calculation.
 * :param entropy_len: Size of ``entropy`` in bytes. Must be `SHA256_LEN`.
 * :param issuance_amount: The (blinded) issuance amount.
 * :param issuance_amount_len: Size of ``issuance_amount`` in bytes.
 * :param inflation_keys: The (blinded) token reissuance amount.
 * :param inflation_keys_len: Size of ``ìnflation_keys`` in bytes.
 * :param issuance_amount_rangeproof: Issuance amount rangeproof.
 * :param issuance_amount_rangeproof_len: Size of ``issuance_amount_rangeproof`` in bytes.
 * :param inflation_keys_rangeproof: Inflation keys rangeproof.
 * :param inflation_keys_rangeproof_len: Size of ``inflation_keys_rangeproof`` in bytes.
 * :param pegin_witness: The pegin witness stack for the input, or NULL if no witness is present.
 * :param flags: Flags controlling input creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_elements_raw_input_at(
    struct wally_tx *tx,
    uint32_t index,
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    uint32_t sequence,
    const unsigned char *script,
    size_t script_len,
    const struct wally_tx_witness_stack *witness,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *entropy,
    size_t entropy_len,
    const unsigned char *issuance_amount,
    size_t issuance_amount_len,
    const unsigned char *inflation_keys,
    size_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof,
    size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof,
    size_t inflation_keys_rangeproof_len,
    const struct wally_tx_witness_stack *pegin_witness,
    uint32_t flags);

/**
 * Add a elements transaction output to a transaction.
 *
 * :param tx: The transaction to add the output to.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param asset: The asset tag of the output.
 * :param asset_len: Size of ``asset`` in bytes. Must be `WALLY_TX_ASSET_CT_ASSET_LEN`.
 * :param value: The commitment to a possibly blinded value.
 * :param value_len: Size of ``value`` in bytes. Must be `WALLY_TX_ASSET_CT_VALUE_LEN` or `WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN`.
 * :param nonce: The commitment used to create the nonce (with the blinding key) for the range proof.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `WALLY_TX_ASSET_CT_NONCE_LEN`.
 * :param surjectionproof: The surjection proof.
 * :param surjectionproof_len: Size of ``surjectionproof`` in bytes.
 * :param rangeproof: The range proof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 * :param flags: Flags controlling output creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_elements_raw_output(
    struct wally_tx *tx,
    const unsigned char *script,
    size_t script_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *value,
    size_t value_len,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *surjectionproof,
    size_t surjectionproof_len,
    const unsigned char *rangeproof,
    size_t rangeproof_len,
    uint32_t flags);

/**
 * Add a elements transaction output to a transaction at a given position.
 *
 * :param tx: The transaction to add the output to.
 * :param index: The zero-based index of the position to add the output at.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param asset: The asset tag of the output.
 * :param asset_len: Size of ``asset`` in bytes. Must be `WALLY_TX_ASSET_CT_ASSET_LEN`.
 * :param value: The commitment to a possibly blinded value.
 * :param value_len: Size of ``value`` in bytes. Must be `WALLY_TX_ASSET_CT_VALUE_LEN` or `WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN`.
 * :param nonce: The commitment used to create the nonce (with the blinding key) for the range proof.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be `WALLY_TX_ASSET_CT_NONCE_LEN`.
 * :param surjectionproof: The surjection proof.
 * :param surjectionproof_len: Size of ``surjectionproof`` in bytes.
 * :param rangeproof: The range proof.
 * :param rangeproof_len: Size of ``rangeproof`` in bytes.
 * :param flags: Flags controlling output creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_elements_raw_output_at(
    struct wally_tx *tx,
    uint32_t index,
    const unsigned char *script,
    size_t script_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *value,
    size_t value_len,
    const unsigned char *nonce,
    size_t nonce_len,
    const unsigned char *surjectionproof,
    size_t surjectionproof_len,
    const unsigned char *rangeproof,
    size_t rangeproof_len,
    uint32_t flags);

/**
 * Determine if a transaction is an elements transaction.
 *
 * :param tx: The transaction to check.
 * :param written: 1 if the transaction is an elements transaction, otherwise 0.
 */
WALLY_CORE_API int wally_tx_is_elements(
    const struct wally_tx *tx,
    size_t *written);

/**
 * Convert satoshi to an explicit confidential value representation.
 *
 * :param satoshi: The value in satoshi to convert.
 * :param bytes_out: Destination for the confidential value bytes.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN)
 */
WALLY_CORE_API int wally_tx_confidential_value_from_satoshi(
    uint64_t satoshi,
    unsigned char *bytes_out,
    size_t len);

/**
 * Convert an explicit confidential value representation to satoshi.
 *
 * :param value: The confidential value bytes.
 * :param value_len: Size of ``value`` in bytes. Must be `WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN`.
 * :param value_out: The converted value in satoshi.
 */
WALLY_CORE_API int wally_tx_confidential_value_to_satoshi(
    const unsigned char *value,
    size_t value_len,
    uint64_t *value_out);

/**
 * Get the hash of the preimage for signing an Elements transaction input.
 *
 * Deprecated, this call will be removed in a future release. Please
 * use ``wally_tx_get_input_signature_hash``.
 *
 * :param tx: The transaction to generate the signature hash from.
 * :param index: The input index of the input being signed for.
 * :param script: The (unprefixed) scriptCode for the input being signed.
 * :param script_len: Size of ``script`` in bytes.
 * :param value: The (confidential) value spent by the input being signed for. Only used if
 *|     flags includes `WALLY_TX_FLAG_USE_WITNESS`, pass NULL otherwise.
 * :param value_len: Size of ``value`` in bytes.
 * :param sighash: ``WALLY_SIGHASH_`` flags specifying the type of signature desired.
 * :param flags: `WALLY_TX_FLAG_USE_WITNESS` to generate a BIP 143 signature, or 0
 *|     to generate a pre-segwit Bitcoin signature.
 * :param bytes_out: Destination for the signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_tx_get_elements_signature_hash(
    const struct wally_tx *tx,
    size_t index,
    const unsigned char *script,
    size_t script_len,
    const unsigned char *value,
    size_t value_len,
    uint32_t sighash,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Calculate the asset entropy from a prevout and the Ricardian contract hash.
 *
 * :param txhash: The prevout transaction hash.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `WALLY_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output
 *|     in ``txhash`` to use.
 * :param contract_hash: The issuer specified Ricardian contract hash.
 * :param contract_hash_len: Size of ``contract hash`` in bytes. Must be `SHA256_LEN`.
 * :param bytes_out: Destination for the asset entropy.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_tx_elements_issuance_generate_entropy(
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    const unsigned char *contract_hash,
    size_t contract_hash_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Calculate the asset from the entropy.
 *
 * :param entropy: The asset entropy.
 * :param entropy_len: Size of ``entropy`` in bytes. Must be `SHA256_LEN`.
 * :param bytes_out: Destination for the asset tag.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_tx_elements_issuance_calculate_asset(
    const unsigned char *entropy,
    size_t entropy_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Calculate a re-issuance token from an asset's entropy.
 *
 * :param entropy: The asset entropy.
 * :param entropy_len: Size of ``entropy`` in bytes. Must be `SHA256_LEN`.
 * :param flags: `WALLY_TX_FLAG_BLINDED_INITIAL_ISSUANCE` if initial issuance was blinded,
 *|     pass 0 otherwise.
 * :param bytes_out: Destination for the re-issuance token.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_tx_elements_issuance_calculate_reissuance_token(
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

#endif /* WALLY_ABI_NO_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_TRANSACTION_H */
