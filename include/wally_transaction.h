#ifndef LIBWALLY_CORE_TRANSACTION_H
#define LIBWALLY_CORE_TRANSACTION_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WALLY_TX_SEQUENCE_FINAL 0xffffffff
#define WALLY_TX_VERSION_2 2
#define WALLY_TX_MAX_VERSION 2

#define WALLY_TXHASH_LEN 32 /** Size of a transaction hash in bytes */

#define WALLY_TX_FLAG_USE_WITNESS 0x1 /* Encode witness data if present */

#define WALLY_TX_DUMMY_NULL 0x1 /* An empty witness item */
#define WALLY_TX_DUMMY_SIG  0x2 /* A dummy signature */

/** Sighash flags for transaction signing */
#define WALLY_SIGHASH_ALL          0x01
#define WALLY_SIGHASH_NONE         0x02
#define WALLY_SIGHASH_SINGLE       0x03
#define WALLY_SIGHASH_FORKID       0x40
#define WALLY_SIGHASH_ANYONECANPAY 0x80

#ifdef SWIG
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
};

/** A transaction output */
struct wally_tx_output {
    uint64_t satoshi;
    unsigned char *script;
    size_t script_len;
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
 * @allocation_len The number of items to pre-allocate space for.
 * @output Destination for the resulting witness stack.
 */
WALLY_CORE_API int wally_tx_witness_stack_init_alloc(
    size_t allocation_len,
    struct wally_tx_witness_stack **output);

/**
 * Add a witness to a witness stack.
 *
 * @tx_witness_stack_in The witness stack to add to.
 * @witness_in The witness data to add to the stack.
 * @witness_in_len Length of @witness_in in bytes.
 */
WALLY_CORE_API int wally_tx_witness_stack_add(
    struct wally_tx_witness_stack *tx_witness_stack_in,
    const unsigned char *witness_in,
    size_t witness_len_in);

/**
 * Add a dummy witness item to a witness stack.
 *
 * @tx_witness_stack_in The witness stack to add to.
 * @flags WALLY_TX_DUMMY_ Flags indicating the type of dummy to add.
 */
WALLY_CORE_API int wally_tx_witness_stack_add_dummy(
    struct wally_tx_witness_stack *tx_witness_stack_in,
    uint32_t flags);

/**
 * Set a witness item to a witness stack.
 *
 * @tx_witness_stack_in The witness stack to add to.
 * @index Index of the item to set. The stack will grow if needed to this many items.
 * @witness_in The witness data to add to the stack.
 * @witness_in_len Length of @witness_in in bytes.
 */
WALLY_CORE_API int wally_tx_witness_stack_set(
    struct wally_tx_witness_stack *tx_witness_stack_in,
    size_t index,
    const unsigned char *witness_in,
    size_t witness_len_in);

/**
 * Set a dummy witness item to a witness stack.
 *
 * @tx_witness_stack_in The witness stack to add to.
 * @index Index of the item to set. The stack will grow if needed to this many items.
 * @flags WALLY_TX_DUMMY_ Flags indicating the type of dummy to set.
 */
WALLY_CORE_API int wally_tx_witness_stack_set_dummy(
    struct wally_tx_witness_stack *tx_witness_stack_in,
    size_t index,
    uint32_t flags);

#ifndef SWIG_PYTHON
/**
 * Free a transaction witness stack allocated by @wally_tx_witness_stack_init_alloc.
 *
 * @tx_witness_stack_in Transaction input to free.
 */
WALLY_CORE_API int wally_tx_witness_stack_free(
    struct wally_tx_witness_stack *tx_witness_stack_in);
#endif /* SWIG_PYTHON */

/**
 * Allocate and initialize a new transaction input.
 *
 * @txhash_in The transaction hash of the transaction this input comes from.
 * @txhash_len_in Size of @txhash_in in bytes. Must be @WALLY_TXHASH_LEN.
 * @index The zero-based index of the transaction output in @txhash_in that
 *     this input comes from.
 * @sequence The sequence number for the input.
 * @script_in The scriptSig for the input.
 * @script_len_in Size of @script_in in bytes.
 * @witness_in The witness stack for the input, or NULL if no witness is present.
 * @output Destination for the resulting transaction input.
 */
WALLY_CORE_API int wally_tx_input_init_alloc(
    const unsigned char *txhash_in,
    size_t txhash_len_in,
    uint32_t index,
    uint32_t sequence,
    const unsigned char *script_in,
    size_t script_len_in,
    const struct wally_tx_witness_stack *witness_in,
    struct wally_tx_input **output);

#ifndef SWIG_PYTHON
/**
 * Free a transaction input allocated by @wally_tx_input_init_alloc.
 *
 * @tx_input_in Transaction input to free.
 */
WALLY_CORE_API int wally_tx_input_free(struct wally_tx_input *tx_input_in);
#endif /* SWIG_PYTHON */

/**
 * Allocate and initialize a new transaction output.
 *
 * @satoshi The amount of the output in satoshi.
 * @script_in The scriptPubkey for the output.
 * @script_len_in Size of @script_in in bytes.
 * @output Destination for the resulting transaction output.
 */
WALLY_CORE_API int wally_tx_output_init_alloc(
    uint64_t satoshi,
    const unsigned char *script_in,
    size_t script_len_in,
    struct wally_tx_output **output);

#ifndef SWIG_PYTHON
/**
 * Free a transaction output allocated by @wally_tx_output_init_alloc.
 *
 * @tx_output_in Transaction output to free.
 */
WALLY_CORE_API int wally_tx_output_free(struct wally_tx_output *tx_output_in);
#endif /* SWIG_PYTHON */

/**
 * Allocate and initialize a new transaction.
 *
 * @version The version of the transaction. Currently must be @WALLY_TX_VERSION_2.
 * @locktime The locktime of the transaction.
 * @inputs_allocation_len The number of inputs to pre-allocate space for.
 * @outputs_allocation_len The number of outputs to pre-allocate space for.
 * @output Destination for the resulting transaction output.
 */
WALLY_CORE_API int wally_tx_init_alloc(
    uint32_t version,
    uint32_t locktime,
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    struct wally_tx **output);

/**
 * Add a transaction input to a transaction.
 *
 * @tx_in: The transaction to add the input to.
 * @tx_input_in The transaction input to add to @tx_in.
 */
WALLY_CORE_API int wally_tx_add_input(
    struct wally_tx *tx_in,
    const struct wally_tx_input *tx_input_in);

/**
 * Add a transaction input to a transaction.
 *
 * @tx_in: The transaction to add the input to.
 * @txhash_in The transaction hash of the transaction this input comes from.
 * @txhash_len_in Size of @txhash_in in bytes. Must be @WALLY_TXHASH_LEN.
 * @index The zero-based index of the transaction output in @txhash_in that
 *     this input comes from.
 * @sequence The sequence number for the input.
 * @script_in The scriptSig for the input.
 * @script_len_in Size of @script_in in bytes.
 * @witness_in The witness stack for the input, or NULL if no witness is present.
 * @flags: Flags controlling script creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_raw_input(
    struct wally_tx *tx_in,
    const unsigned char *txhash_in,
    size_t txhash_len_in,
    uint32_t index,
    uint32_t sequence,
    const unsigned char *script_in,
    size_t script_len_in,
    const struct wally_tx_witness_stack *witness_in,
    uint32_t flags);

/**
 * Remove a transaction input from a transaction.
 *
 * @tx_in: The transaction to remove the input from.
 * @index The zero-based index of the input to remove.
 */
WALLY_CORE_API int wally_tx_remove_input(
    struct wally_tx *tx_in,
    size_t index);

WALLY_CORE_API int wally_tx_set_input_script(
    const struct wally_tx *tx_in,
    size_t index,
    const unsigned char *script_in,
    size_t script_len_in);

WALLY_CORE_API int wally_tx_set_input_witness(
    const struct wally_tx *tx_in,
    size_t index,
    const struct wally_tx_witness_stack *tx_witness_stack_in);

/**
 * Add a transaction output to a transaction.
 *
 * @tx_in: The transaction to add the input to.
 * @tx_output_in The transaction output to add to @tx_in.
 */
WALLY_CORE_API int wally_tx_add_output(
    struct wally_tx *tx_in,
    const struct wally_tx_output *tx_output_in);

/**
 * Add a transaction output to a transaction.
 *
 * @tx_in: The transaction to add the input to.
 * @satoshi The amount of the output in satoshi.
 * @script_in The scriptPubkey for the output.
 * @script_len_in Size of @script_in in bytes.
 * @flags: Flags controlling script creation. Must be 0.
 */
WALLY_CORE_API int wally_tx_add_raw_output(
    struct wally_tx *tx_in,
    uint64_t satoshi,
    const unsigned char *script_in,
    size_t script_len_in,
    uint32_t flags);

/**
 * Remove a transaction output from a transaction.
 *
 * @tx_in: The transaction to remove the output from.
 * @index The zero-based index of the output to remove.
 */
WALLY_CORE_API int wally_tx_remove_output(
    struct wally_tx *tx_in,
    size_t index);

/**
 * Get the number of inputs in a transaction that have witness data.
 *
 * @tx_in: The transaction to remove the output from.
 * @written: Destination for the number of witness-containing inputs.
 */
WALLY_CORE_API int wally_tx_get_witness_count(
    const struct wally_tx *tx_in,
    size_t *written);

#ifndef SWIG_PYTHON
/**
 * Free a transaction allocated by @wally_tx_init_alloc.
 *
 * @tx_in Transaction to free.
 */
WALLY_CORE_API int wally_tx_free(struct wally_tx *tx_in);
#endif /* SWIG_PYTHON */

/**
 * Return the length of transaction once serialized into bytes.
 *
 * @tx_in: The transaction to find the serialized length of.
 * @flags: WALLY_TX_FLAG_ Flags controlling serialization options.
 * @written: Destination for the length of the serialized bytes.
 */
WALLY_CORE_API int wally_tx_get_length(
    const struct wally_tx *tx_in,
    uint32_t flags,
    size_t *written);

/**
 * Create a transaction from its serialized bytes.
 *
 * @bytes_in: Bytes to create the transaction from.
 * @len_in: Length of @bytes_in in bytes.
 * @flags: Flags controlling serialization options. Must be 0.
 * @output: Destination for the resulting transaction.
 */
WALLY_CORE_API int wally_tx_from_bytes(
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t flags,
    struct wally_tx **output);

/**
 * Create a transaction from its serialized bytes in hexadecimal.
 *
 * @hex: Hexadecimal string containing the transaction.
 * @flags: Flags controlling serialization options. Must be 0.
 * @output: Destination for the resulting transaction.
 */
WALLY_CORE_API int wally_tx_from_hex(
    const char *hex,
    uint32_t flags,
    struct wally_tx **output);

/**
 * Serialize a transaction to bytes.
 *
 * @tx_in: The transaction to serialize.
 * @flags: WALLY_TX_FLAG_ Flags controlling serialization options.
 * @bytes_out Destination for the serialized transaction.
 * @len Size of @bytes_out in bytes.
 * @written: Destination for the length of the serialized transaction.
 */
WALLY_CORE_API int wally_tx_to_bytes(
    const struct wally_tx *tx_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Serialize a transaction to hex.
 *
 * @tx_in: The transaction to serialize.
 * @flags: WALLY_TX_FLAG_ Flags controlling serialization options.
 * @output Destination for the resulting hexadecimal string.
 *
 * The string returned should be freed using @wally_free_string.
 */
WALLY_CORE_API int wally_tx_to_hex(
    const struct wally_tx *tx,
    uint32_t flags,
    char **output);

/**
 * Get the weight of a transaction.
 *
 * @tx_in: The transaction to get the weight of.
 * @written: Destination for the weight.
 */
WALLY_CORE_API int wally_tx_get_weight(
    const struct wally_tx *tx_in,
    size_t *written);

/**
 * Get the virtual size of a transaction.
 *
 * @tx_in: The transaction to get the virtual size of.
 * @written: Destination for the virtual size.
 */
WALLY_CORE_API int wally_tx_get_vsize(
    const struct wally_tx *tx_in,
    size_t *written);

/**
 * Compute transaction vsize from transaction weight.
 *
 * @weight: The weight to convert to a virtual size.
 * @written: Destination for the virtual size.
 */
WALLY_CORE_API int wally_tx_vsize_from_weight(
    size_t weight,
    size_t *written);

/**
 * Create a BTC transaction for signing and return its hash.
 *
 * @tx_in: The transaction to generate the signature hash from.
 * @index: The input index of the input being signed for.
 * @script_in: The scriptSig for the input represented by @index.
 * @script_len_in: Size of @script_in in bytes.
 * @satoshi: The amount spent by the input being signed for. Only used if
 *     flags includes WALLY_TX_FLAG_USE_WITNESS, pass 0 otherwise.
 * @sighash: WALLY_SIGHASH_ flags specifying the type of signature desired.
 * @flags: WALLY_TX_FLAG_USE_WITNESS to generate a BIP 143 signature, or 0
 *     to generate a pre-segwit Bitcoin signature.
 * @bytes_out Destination for the signature.
 * @len Size of @bytes_out in bytes. Must be at least @SHA256_LEN.
 */
WALLY_CORE_API int wally_tx_get_btc_signature_hash(
    const struct wally_tx *tx_in,
    size_t index,
    const unsigned char *script_in,
    size_t script_len_in,
    uint64_t satoshi,
    uint32_t sighash,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Create a transaction for signing and return its hash.
 *
 * @tx_in: The transaction to generate the signature hash from.
 * @index: The input index of the input being signed for.
 * @script_in: The scriptSig for the input represented by @index.
 * @script_len_in: Size of @script_in in bytes.
 * @extra_in: Extra bytes to include in the transaction preimage.
 * @extra_len_in: Size of @extra_in in bytes.
 * @extra_offset: Offset with the preimage to store @extra_in. To store
 *     it and the end of the preimage, use 0xffffffff.
 * @satoshi: The amount spent by the input being signed for. Only used if
 *     flags includes WALLY_TX_FLAG_USE_WITNESS, pass 0 otherwise.
 * @sighash: WALLY_SIGHASH_ flags specifying the type of signature desired.
 * @tx_sighash: The 32bit sighash value to include in the preimage to hash.
 *     This must be given in host CPU endianess; For normal Bitcoin signing
 *     the value of @sighash should be given.
 * @flags: WALLY_TX_FLAG_USE_WITNESS to generate a BIP 143 signature, or 0
 *     to generate a pre-segwit Bitcoin signature.
 * @bytes_out Destination for the signature.
 * @len Size of @bytes_out in bytes. Must be at least @SHA256_LEN.
 */
WALLY_CORE_API int wally_tx_get_signature_hash(
    const struct wally_tx *tx_in,
    size_t index,
    const unsigned char *script_in,
    size_t script_len_in,
    const unsigned char *extra_in,
    size_t extra_len_in,
    uint32_t extra_offset,
    uint64_t satoshi,
    uint32_t sighash,
    uint32_t tx_sighash,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_TRANSACTION_H */
