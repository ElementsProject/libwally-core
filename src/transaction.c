#include "internal.h"

#include "ccan/ccan/build_assert/build_assert.h"

#include <include/wally_crypto.h>
#include <include/wally_transaction.h>
#include <include/wally_map.h>
#include <include/wally_script.h>

#include <limits.h>
#include "pullpush.h"
#include "script_int.h"
#include "transaction_int.h"

#define WALLY_TX_ALL_FLAGS \
    (WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_USE_ELEMENTS | \
     WALLY_TX_FLAG_ALLOW_PARTIAL | WALLY_TX_FLAG_PRE_BIP144)

/* We use the maximum DER sig length (plus a byte for the sighash) so that
 * we overestimate the size by a byte or two per tx sig. This allows using
 * e.g. the minimum fee rate/bump rate without core rejecting it for low fees.
 */
static const unsigned char DUMMY_SIG[EC_SIGNATURE_DER_MAX_LEN + 1]; /* +1 for sighash */

/* Bytes of stack space to use to avoid allocations for tx serializing */
#define TX_STACK_SIZE 2048

#define TX_COPY_ELSE_CLEAR(dst, src, siz) \
    if (src) \
        memcpy(dst, src, siz); \
    else \
        wally_clear(dst, siz);

#define MAX_INVALID_SATOSHI ((uint64_t) -1)

#define EXT_FLAG_BIP342 0x1 /* Indicates BIP342 tapscript message extension */

/* Extra options when serializing for hashing */
struct tx_serialize_opts
{
    uint32_t sighash;                /* 8 bit sighash value for sig */
    uint32_t tx_sighash;             /* 32 bit sighash value for tx */
    size_t index;                    /* index of input we are signing */
    const unsigned char *script;     /* scriptPubkey spent by the input we are signing */
    size_t script_len;               /* length of 'script' in bytes */
    uint64_t satoshi;                /* Amount of the input we are signing */
    bool bip143;                     /* Serialize for BIP143 hash */
    const unsigned char *value;      /* Confidential value of the input we are signing */
    size_t value_len;                /* length of 'value' in bytes */
    bool bip341;                     /* Serialize for BIP341 taproot hash */
    unsigned char ext_flag;          /* 1 = serialize for BIP342 tapscript hash */
    const uint64_t *prev_satoshis;   /* Output amounts for BIP341/342 sha_amounts */
    size_t num_prev_satoshis;        /* Number of items in prev_satoshis */
    const struct wally_map *scripts; /* Output scripts for BIP341/342 sha_scriptpubkeys  */
    const unsigned char *tapleaf_script; /* Executed BIP342 tapscript */
    size_t tapleaf_script_len;       /* Length of executed tapscript */
    uint32_t key_version;            /* BIP342 key version */
    uint32_t codesep_position;       /* BIP342 codeseparator position */
    const unsigned char *annex;      /* Annex data to be put under sighash */
    size_t annex_len;                /* Length of sighash data, including 0x50 prefix */
};

static const unsigned char EMPTY_OUTPUT[9] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00
};

#define WALLY_SATOSHI_MAX ((uint64_t)WALLY_BTC_MAX * WALLY_SATOSHI_PER_BTC)

/* LCOV_EXCL_START */
/* Check assumptions we expect to hold true */
static void assert_tx_assumptions(void)
{
    BUILD_ASSERT(WALLY_TXHASH_LEN == SHA256_LEN);
    BUILD_ASSERT(sizeof(DUMMY_SIG) == EC_SIGNATURE_DER_MAX_LEN + 1);
    BUILD_ASSERT(sizeof(DUMMY_SIG) - 1 == EC_SIGNATURE_DER_MAX_LOW_R_LEN + 1);
}
/* LCOV_EXCL_STOP */

static bool is_valid_witness_stack(const struct wally_tx_witness_stack *stack)
{
    return stack &&
           BYTES_VALID(stack->items, stack->items_allocation_len) &&
           (stack->items != NULL || stack->num_items == 0);
}

static bool is_valid_tx(const struct wally_tx *tx)
{
    /* Note: The last two conditions are redundant, but having them here
     *       ensures accurate static analysis from tools like clang.
     */
    return tx &&
           BYTES_VALID(tx->inputs, tx->inputs_allocation_len) &&
           BYTES_VALID(tx->outputs, tx->outputs_allocation_len) &&
           (tx->num_inputs == 0 || tx->inputs != NULL) &&
           (tx->num_outputs == 0 || tx->outputs != NULL);
}

static bool is_valid_tx_input(const struct wally_tx_input *input)
{
    return input &&
           BYTES_VALID(input->script, input->script_len) &&
           (!input->witness || is_valid_witness_stack(input->witness))
#ifdef BUILD_ELEMENTS
           && (!input->pegin_witness || is_valid_witness_stack(input->pegin_witness))
#endif
    ;
}

static bool is_valid_tx_output(const struct wally_tx_output *output)
{
    return output &&
           BYTES_VALID(output->script, output->script_len) &&
           output->satoshi <= WALLY_SATOSHI_MAX;
}

static bool is_valid_elements_tx_input(const struct wally_tx_input *input)
{
    return is_valid_tx_input(input) && (input->features & WALLY_TX_IS_ELEMENTS);
}

static bool is_valid_elements_tx_input_pegin(const struct wally_tx_input *input)
{
    return is_valid_elements_tx_input(input) && (input->features & WALLY_TX_IS_PEGIN);
}

static bool is_null_bytes(const unsigned char *bytes, size_t bytes_len)
{
    size_t i;
    for (i = 0; i < bytes_len; ++i)
        if (bytes[i])
            return false;
    return true;
}

static bool is_coinbase_bytes(const unsigned char *bytes, size_t bytes_len, uint32_t index)
{
    return index == 0xffffffff && is_null_bytes(bytes, bytes_len);
}

static bool is_valid_coinbase_input(const struct wally_tx_input *input)
{
    return input && is_coinbase_bytes(input->txhash, sizeof(input->txhash), input->index);
}

static bool is_valid_elements_tx_output(const struct wally_tx_output *output)
{
    return output &&
           BYTES_VALID(output->script, output->script_len) &&
           (output->features & WALLY_TX_IS_ELEMENTS);
}

static bool is_valid_elements_tx(const struct wally_tx *tx)
{
    size_t i;

    if (!tx->num_inputs && !tx->num_outputs)
        return false; /* No inputs & no outputs, treat as non-elements tx */

    for (i = 0; i < tx->num_inputs; ++i)
        if (!is_valid_elements_tx_input(tx->inputs + i))
            return false;

    for (i = 0; i < tx->num_outputs; ++i)
        if (!is_valid_elements_tx_output(tx->outputs + i))
            return false;

    return true;
}

int wally_tx_witness_stack_clone_alloc(const struct wally_tx_witness_stack *stack,
                                       struct wally_tx_witness_stack **output)
{
    size_t i;
    int ret;

    OUTPUT_CHECK;
    if (!stack)
        return WALLY_EINVAL;

    ret = wally_tx_witness_stack_init_alloc(stack->items_allocation_len, output);
    for (i = 0; ret == WALLY_OK && i < stack->num_items; ++i) {
        ret = wally_tx_witness_stack_set(*output, i,
                                         stack->items[i].witness,
                                         stack->items[i].witness_len);
    }
    if (ret != WALLY_OK) {
        wally_tx_witness_stack_free(*output);
        *output = NULL;
    }
    return ret;
}

int wally_tx_witness_stack_init_alloc(size_t allocation_len,
                                      struct wally_tx_witness_stack **output)
{
    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_tx_witness_stack);

    if (allocation_len) {
        if (allocation_len > MAX_WITNESS_ITEMS_ALLOC)
            allocation_len = MAX_WITNESS_ITEMS_ALLOC;
        (*output)->items = wally_calloc(allocation_len * sizeof(struct wally_tx_witness_item));
        if (!(*output)->items) {
            wally_free(*output);
            *output = NULL;
            return WALLY_ENOMEM;
        }
    }
    (*output)->items_allocation_len = allocation_len;
    (*output)->num_items = 0;
    return WALLY_OK;
}

static int tx_witness_stack_free(struct wally_tx_witness_stack *stack,
                                 bool free_parent)
{
    size_t i;

    if (stack) {
        if (stack->items) {
            for (i = 0; i < stack->num_items; ++i) {
                if (stack->items[i].witness)
                    clear_and_free(stack->items[i].witness,
                                   stack->items[i].witness_len);
            }
            clear_and_free(stack->items, stack->num_items * sizeof(*stack->items));
        }
        wally_clear(stack, sizeof(*stack));
        if (free_parent)
            wally_free(stack);
    }
    return WALLY_OK;
}

int wally_tx_witness_stack_get_num_items(
    const struct wally_tx_witness_stack *stack, size_t *written)
{
    if (written)
        *written = 0;
    if (!stack || !written)
        return WALLY_EINVAL;
    *written = stack->num_items;
    return WALLY_OK;
}


int wally_tx_witness_stack_from_bytes(const unsigned char *bytes, size_t bytes_len,
                                      struct wally_tx_witness_stack **output)
{
    if (output)
        *output = NULL;
    if (!bytes || !bytes_len || !output)
        return WALLY_EINVAL;
    return pull_witness(&bytes, &bytes_len, output, false);
}

int wally_tx_witness_stack_get_length(
    const struct wally_tx_witness_stack *stack,
    size_t *written)
{
    if (written)
        *written = 0;
    if (!stack || !written)
        return WALLY_EINVAL;
    push_witness_stack(NULL, written, stack);
    return WALLY_OK;
}

int wally_tx_witness_stack_to_bytes(
    const struct wally_tx_witness_stack *stack,
    unsigned char *bytes_out,
    size_t len,
    size_t *written)
{
    int ret;
    if (written)
        *written = 0;
    if (!stack || !bytes_out || !written)
        return WALLY_EINVAL;
    ret = wally_tx_witness_stack_get_length(stack, written);
    if (ret == WALLY_OK && len >= *written)
        push_witness_stack(&bytes_out, &len, stack);
    return ret;
}

int wally_tx_witness_stack_free(struct wally_tx_witness_stack *stack)
{
    return tx_witness_stack_free(stack, true);
}

int wally_tx_witness_stack_add(
    struct wally_tx_witness_stack *stack,
    const unsigned char *witness, size_t witness_len)
{
    if (!stack)
        return WALLY_EINVAL;
    return wally_tx_witness_stack_set(stack, stack->num_items,
                                      witness, witness_len);
}

int wally_tx_witness_stack_add_dummy(
    struct wally_tx_witness_stack *stack, uint32_t flags)
{
    if (!stack)
        return WALLY_EINVAL;
    return wally_tx_witness_stack_set_dummy(stack, stack->num_items, flags);
}


int wally_tx_witness_stack_set(struct wally_tx_witness_stack *stack, size_t index,
                               const unsigned char *witness, size_t witness_len)
{
    unsigned char *new_witness = NULL;

    if (!is_valid_witness_stack(stack) || (!witness && witness_len))
        return WALLY_EINVAL;

    if (!clone_bytes(&new_witness, witness, witness_len))
        return WALLY_ENOMEM;

    if (index >= stack->num_items) {
        if (index >= stack->items_allocation_len) {
            /* Expand the witness array */
            struct wally_tx_witness_item *p;
            p = array_realloc(stack->items, stack->items_allocation_len,
                              index + 1, sizeof(*stack->items));
            if (!p) {
                clear_and_free(new_witness, witness_len);
                return WALLY_ENOMEM;
            }
            clear_and_free(stack->items, stack->num_items * sizeof(*stack->items));
            stack->items = p;
            stack->items_allocation_len = index + 1;
        }
        stack->num_items = index + 1;
    }
    clear_and_free(stack->items[index].witness, stack->items[index].witness_len);
    stack->items[index].witness = new_witness;
    stack->items[index].witness_len = witness_len;
    return WALLY_OK;
}

int wally_tx_witness_stack_set_dummy(struct wally_tx_witness_stack *stack,
                                     size_t index, uint32_t flags)
{
    const unsigned char *p = NULL;
    size_t len = 0;

    if (flags == WALLY_TX_DUMMY_SIG) {
        p = DUMMY_SIG;
        len = sizeof(DUMMY_SIG);
    } else if (flags == WALLY_TX_DUMMY_SIG_LOW_R) {
        p = DUMMY_SIG;
        len = sizeof(DUMMY_SIG) - 1; /* Low-R signatures are always at least 1 byte shorter */
    } else if (flags != WALLY_TX_DUMMY_NULL)
        return WALLY_EINVAL;
    return wally_tx_witness_stack_set(stack, index, p, len);
}

static bool clone_input_to(
    struct wally_tx_input *dst,
    const struct wally_tx_input *src)
{
    unsigned char *new_script = NULL;
#ifdef BUILD_ELEMENTS
    unsigned char *new_issuance_amount = NULL, *new_inflation_keys = NULL,
                  *new_issuance_amount_rangeproof = NULL, *new_inflation_keys_rangeproof = NULL;
    struct wally_tx_witness_stack *new_pegin_witness = NULL;
#endif
    struct wally_tx_witness_stack *new_witness = NULL;

    if (src->witness)
        wally_tx_witness_stack_clone_alloc(src->witness, &new_witness);

#ifdef BUILD_ELEMENTS
    if (src->pegin_witness)
        wally_tx_witness_stack_clone_alloc(src->pegin_witness, &new_pegin_witness);
#endif

    if (!clone_bytes(&new_script, src->script, src->script_len) ||
#ifdef BUILD_ELEMENTS
        !clone_bytes(&new_issuance_amount, src->issuance_amount, src->issuance_amount_len) ||
        !clone_bytes(&new_inflation_keys, src->inflation_keys, src->inflation_keys_len) ||
        !clone_bytes(&new_issuance_amount_rangeproof, src->issuance_amount_rangeproof, src->issuance_amount_rangeproof_len) ||
        !clone_bytes(&new_inflation_keys_rangeproof, src->inflation_keys_rangeproof, src->inflation_keys_rangeproof_len) ||
#endif
        (src->witness && !new_witness)) {
        clear_and_free(new_script, src->script_len);
#ifdef BUILD_ELEMENTS
        clear_and_free(new_issuance_amount, src->issuance_amount_len);
        clear_and_free(new_inflation_keys, src->inflation_keys_len);
        clear_and_free(new_issuance_amount_rangeproof, src->issuance_amount_rangeproof_len);
        clear_and_free(new_inflation_keys_rangeproof, src->inflation_keys_rangeproof_len);
        wally_tx_witness_stack_free(new_pegin_witness);
#endif
        wally_tx_witness_stack_free(new_witness);
        return false;
    }

    memcpy(dst, src, sizeof(*src));
    dst->script = new_script;
#ifdef BUILD_ELEMENTS
    dst->issuance_amount = new_issuance_amount;
    dst->inflation_keys = new_inflation_keys;
    dst->issuance_amount_rangeproof = new_issuance_amount_rangeproof;
    dst->inflation_keys_rangeproof = new_inflation_keys_rangeproof;
    dst->pegin_witness = new_pegin_witness;
#endif
    dst->witness = new_witness;
    return true;
}

static int tx_elements_input_issuance_proof_init(
    struct wally_tx_input *input,
    const unsigned char *issuance_amount_rangeproof,
    size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof,
    size_t inflation_keys_rangeproof_len)
{
#ifdef BUILD_ELEMENTS
    unsigned char *new_issuance_amount_rangeproof = NULL, *new_inflation_keys_rangeproof = NULL;
#endif
    (void) input;

    if (BYTES_INVALID(issuance_amount_rangeproof, issuance_amount_rangeproof_len) ||
        BYTES_INVALID(inflation_keys_rangeproof, inflation_keys_rangeproof_len))
        return WALLY_EINVAL;

#ifdef BUILD_ELEMENTS
    if (!clone_bytes(&new_issuance_amount_rangeproof, issuance_amount_rangeproof, issuance_amount_rangeproof_len) ||
        !clone_bytes(&new_inflation_keys_rangeproof, inflation_keys_rangeproof, inflation_keys_rangeproof_len)) {
        clear_and_free(new_issuance_amount_rangeproof, issuance_amount_rangeproof_len);
        clear_and_free(new_inflation_keys_rangeproof, inflation_keys_rangeproof_len);
        return WALLY_ENOMEM;
    }

    input->issuance_amount_rangeproof = new_issuance_amount_rangeproof;
    input->issuance_amount_rangeproof_len = issuance_amount_rangeproof_len;
    input->inflation_keys_rangeproof = new_inflation_keys_rangeproof;
    input->inflation_keys_rangeproof_len = inflation_keys_rangeproof_len;
#endif
    return WALLY_OK;
}

static int tx_elements_input_issuance_init(
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
    size_t inflation_keys_rangeproof_len,
    bool is_elements)
{
#ifdef BUILD_ELEMENTS
    int ret;
    unsigned char *new_issuance_amount = NULL, *new_inflation_keys = NULL;
#endif

    if (!input ||
        BYTES_INVALID_N(nonce, nonce_len, WALLY_TX_ASSET_TAG_LEN) ||
        BYTES_INVALID_N(entropy, entropy_len, WALLY_TX_ASSET_TAG_LEN) ||
        BYTES_INVALID(issuance_amount, issuance_amount_len) ||
        BYTES_INVALID(inflation_keys, inflation_keys_len) ||
        BYTES_INVALID(issuance_amount_rangeproof, issuance_amount_rangeproof_len) ||
        BYTES_INVALID(inflation_keys_rangeproof, inflation_keys_rangeproof_len))
        return WALLY_EINVAL;

#ifdef BUILD_ELEMENTS
    if (!clone_bytes(&new_issuance_amount, issuance_amount, issuance_amount_len) ||
        !clone_bytes(&new_inflation_keys, inflation_keys, inflation_keys_len))
        ret = WALLY_ENOMEM;
    else
        ret = tx_elements_input_issuance_proof_init(input,
                                                    issuance_amount_rangeproof,
                                                    issuance_amount_rangeproof_len,
                                                    inflation_keys_rangeproof,
                                                    inflation_keys_rangeproof_len);

    if (ret != WALLY_OK) {
        clear_and_free(new_issuance_amount, issuance_amount_len);
        clear_and_free(new_inflation_keys, inflation_keys_len);
        return ret;
    }

    TX_COPY_ELSE_CLEAR(input->blinding_nonce, nonce, sizeof(input->blinding_nonce));
    TX_COPY_ELSE_CLEAR(input->entropy, entropy, sizeof(input->entropy));
    input->issuance_amount = new_issuance_amount;
    input->issuance_amount_len = issuance_amount_len;
    input->inflation_keys = new_inflation_keys;
    input->inflation_keys_len = inflation_keys_len;
#endif

    if (is_elements) {
        input->features |= WALLY_TX_IS_ELEMENTS;
        if (nonce || entropy)
            input->features |= WALLY_TX_IS_ISSUANCE;
    }

    return WALLY_OK;
}

int wally_tx_elements_input_issuance_set(
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
    size_t inflation_keys_rangeproof_len)
{
#ifdef BUILD_ELEMENTS
    unsigned char *input_issuance_amount = input->issuance_amount;
    size_t input_issuance_amount_len = input->issuance_amount_len;
    unsigned char *input_inflation_keys = input->inflation_keys;
    size_t input_inflation_keys_len = input->inflation_keys_len;
    unsigned char *input_issuance_amount_rangeproof = input->issuance_amount_rangeproof;
    size_t input_issuance_amount_rangeproof_len = input->issuance_amount_rangeproof_len;
    unsigned char *input_inflation_keys_rangeproof = input->inflation_keys_rangeproof;
    size_t input_inflation_keys_rangeproof_len = input->inflation_keys_rangeproof_len;
#endif /* BUILD_ELEMENTS */
    int ret = tx_elements_input_issuance_init(input,
                                              nonce,
                                              nonce_len,
                                              entropy,
                                              entropy_len,
                                              issuance_amount,
                                              issuance_amount_len,
                                              inflation_keys,
                                              inflation_keys_len,
                                              issuance_amount_rangeproof,
                                              issuance_amount_rangeproof_len,
                                              inflation_keys_rangeproof,
                                              inflation_keys_rangeproof_len,
                                              true);
#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK) {
        clear_and_free(input_issuance_amount, input_issuance_amount_len);
        clear_and_free(input_inflation_keys, input_inflation_keys_len);
        clear_and_free(input_issuance_amount_rangeproof, input_issuance_amount_rangeproof_len);
        clear_and_free(input_inflation_keys_rangeproof, input_inflation_keys_rangeproof_len);
    }
#endif /* BUILD_ELEMENTS */
    return ret;
}

int wally_tx_elements_input_issuance_free(
    struct wally_tx_input *input)
{
    (void) input;
#ifdef BUILD_ELEMENTS
    if (input) {
        input->features &= ~(WALLY_TX_IS_ELEMENTS | WALLY_TX_IS_ISSUANCE);
        wally_clear(input->blinding_nonce, sizeof(input->blinding_nonce));
        wally_clear(input->entropy, sizeof(input->entropy));

#define FREE_PTR_AND_LEN(name) clear_and_free(input->name, input->name ## _len); \
    input->name = NULL; input->name ## _len = 0

        FREE_PTR_AND_LEN(issuance_amount);
        FREE_PTR_AND_LEN(inflation_keys);
        FREE_PTR_AND_LEN(issuance_amount_rangeproof);
        FREE_PTR_AND_LEN(inflation_keys_rangeproof);
#undef FREE_PTR_AND_LEN

        tx_witness_stack_free(input->pegin_witness, true);
        input->pegin_witness = NULL;
    }
#endif /* BUILD_ELEMENTS */
    return WALLY_OK;
}

static int tx_elements_input_init(
    const unsigned char *txhash, size_t txhash_len,
    uint32_t utxo_index, uint32_t sequence,
    const unsigned char *script, size_t script_len,
    const struct wally_tx_witness_stack *witness,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *entropy, size_t entropy_len,
    const unsigned char *issuance_amount, size_t issuance_amount_len,
    const unsigned char *inflation_keys, size_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len,
    const struct wally_tx_witness_stack *pegin_witness,
    struct wally_tx_input *output, bool is_elements)
{
    struct wally_tx_witness_stack *new_witness = NULL;
    struct wally_tx_witness_stack *new_pegin_witness = NULL;
    unsigned char *new_script = NULL;
    int ret = WALLY_OK, old_features;

    if (!txhash || txhash_len != WALLY_TXHASH_LEN ||
        BYTES_INVALID(script, script_len) || !output)
        return WALLY_EINVAL;

    old_features = output->features;

    if (witness)
        ret = wally_tx_witness_stack_clone_alloc(witness, &new_witness);
    if (ret == WALLY_OK && pegin_witness)
        ret = wally_tx_witness_stack_clone_alloc(pegin_witness, &new_pegin_witness);
    if (ret == WALLY_OK && !clone_bytes(&new_script, script, script_len))
        ret = WALLY_ENOMEM;
    if (ret == WALLY_OK) {
        output->features = 0;
        ret = tx_elements_input_issuance_init(output,
                                              nonce,
                                              nonce_len,
                                              entropy,
                                              entropy_len,
                                              issuance_amount,
                                              issuance_amount_len,
                                              inflation_keys,
                                              inflation_keys_len,
                                              issuance_amount_rangeproof,
                                              issuance_amount_rangeproof_len,
                                              inflation_keys_rangeproof,
                                              inflation_keys_rangeproof_len,
                                              is_elements);
    }

    if (ret != WALLY_OK) {
        wally_tx_witness_stack_free(new_witness);
        wally_tx_witness_stack_free(new_pegin_witness);
        clear_and_free(new_script, script_len);
        output->features = old_features;
    } else {
        const bool is_coinbase = is_coinbase_bytes(txhash, WALLY_TXHASH_LEN, utxo_index);
        memcpy(output->txhash, txhash, WALLY_TXHASH_LEN);
        if (is_elements && !is_coinbase)
            output->index = utxo_index & WALLY_TX_INDEX_MASK;
        else
            output->index = utxo_index;
        if (is_elements && !is_coinbase && (utxo_index & WALLY_TX_PEGIN_FLAG))
            output->features |= WALLY_TX_IS_PEGIN;
        if (is_coinbase)
            output->features |= WALLY_TX_IS_COINBASE;
        output->sequence = sequence;
        output->script = new_script;
        output->script_len = script_len;
        output->witness = new_witness;
#ifdef BUILD_ELEMENTS
        output->pegin_witness = new_pegin_witness;
#endif /* BUILD_ELEMENTS */
    }
    return ret;
}

int wally_tx_elements_input_init(
    const unsigned char *txhash, size_t txhash_len,
    uint32_t utxo_index, uint32_t sequence,
    const unsigned char *script, size_t script_len,
    const struct wally_tx_witness_stack *witness,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *entropy, size_t entropy_len,
    const unsigned char *issuance_amount, size_t issuance_amount_len,
    const unsigned char *inflation_keys, uint64_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len,
    const struct wally_tx_witness_stack *pegin_witness,
    struct wally_tx_input *output)
{
    return tx_elements_input_init(
        txhash, txhash_len,
        utxo_index, sequence,
        script, script_len,
        witness, nonce, nonce_len,
        entropy, entropy_len,
        issuance_amount, issuance_amount_len,
        inflation_keys, inflation_keys_len,
        issuance_amount_rangeproof, issuance_amount_rangeproof_len,
        inflation_keys_rangeproof, inflation_keys_rangeproof_len,
        pegin_witness, output, true);
}

int wally_tx_input_init(const unsigned char *txhash, size_t txhash_len,
                        uint32_t utxo_index, uint32_t sequence,
                        const unsigned char *script, size_t script_len,
                        const struct wally_tx_witness_stack *witness,
                        struct wally_tx_input *output)
{
    return tx_elements_input_init(txhash, txhash_len,
                                  utxo_index, sequence,
                                  script, script_len,
                                  witness, NULL, 0, NULL, 0,
                                  NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL,
                                  output, false);
}

int wally_tx_elements_input_init_alloc(
    const unsigned char *txhash, size_t txhash_len,
    uint32_t utxo_index, uint32_t sequence,
    const unsigned char *script, size_t script_len,
    const struct wally_tx_witness_stack *witness,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *entropy, size_t entropy_len,
    const unsigned char *issuance_amount, size_t issuance_amount_len,
    const unsigned char *inflation_keys, size_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len,
    const struct wally_tx_witness_stack *pegin_witness,
    struct wally_tx_input **output)
{
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_tx_input);

    ret = tx_elements_input_init(txhash, txhash_len, utxo_index, sequence,
                                 script, script_len, witness,
                                 nonce, nonce_len, entropy, entropy_len,
                                 issuance_amount, issuance_amount_len,
                                 inflation_keys, inflation_keys_len,
                                 issuance_amount_rangeproof,
                                 issuance_amount_rangeproof_len,
                                 inflation_keys_rangeproof,
                                 inflation_keys_rangeproof_len, pegin_witness,
                                 *output, true);

    if (ret != WALLY_OK) {
        clear_and_free(*output, sizeof(struct wally_tx_input));
        *output = NULL;
    }
    return ret;
}

int wally_tx_input_init_alloc(const unsigned char *txhash, size_t txhash_len,
                              uint32_t utxo_index, uint32_t sequence,
                              const unsigned char *script, size_t script_len,
                              const struct wally_tx_witness_stack *witness,
                              struct wally_tx_input **output)
{
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_tx_input);

    ret = wally_tx_input_init(txhash, txhash_len, utxo_index, sequence,
                              script, script_len, witness, *output);

    if (ret != WALLY_OK) {
        clear_and_free(*output, sizeof(struct wally_tx_output));
        *output = NULL;
    }
    return ret;
}

static int tx_input_free(struct wally_tx_input *input, bool free_parent)
{
    if (input) {
        clear_and_free(input->script, input->script_len);
        tx_witness_stack_free(input->witness, true);
        wally_tx_elements_input_issuance_free(input);
        wally_clear(input, sizeof(*input));
        if (free_parent)
            wally_free(input);
    }
    return WALLY_OK;
}

int wally_tx_input_free(struct wally_tx_input *input)
{
    return tx_input_free(input, true);
}

int wally_tx_output_clone(const struct wally_tx_output *src,
                          struct wally_tx_output *output)
{
    unsigned char *new_script = NULL;
#ifdef BUILD_ELEMENTS
    unsigned char *new_asset = NULL, *new_value = NULL, *new_nonce = NULL,
                  *new_surjectionproof = NULL, *new_rangeproof = NULL;
#endif
    if (!src || !output)
        return WALLY_EINVAL;

#ifdef BUILD_ELEMENTS
    if (!clone_bytes(&new_asset, src->asset, src->asset_len) ||
        !clone_bytes(&new_value, src->value, src->value_len) ||
        !clone_bytes(&new_nonce, src->nonce, src->nonce_len) ||
        !clone_bytes(&new_surjectionproof, src->surjectionproof, src->surjectionproof_len) ||
        !clone_bytes(&new_rangeproof, src->rangeproof, src->rangeproof_len) ||
        !clone_bytes(&new_script, src->script, src->script_len)) {
#else
    if (!clone_bytes(&new_script, src->script, src->script_len)) {
#endif
        clear_and_free(new_script, src->script_len);
#ifdef BUILD_ELEMENTS
        clear_and_free(new_asset, src->asset_len);
        clear_and_free(new_value, src->value_len);
        clear_and_free(new_nonce, src->nonce_len);
        clear_and_free(new_surjectionproof,  src->surjectionproof_len);
        clear_and_free(new_rangeproof, src->rangeproof_len);
#endif
        return WALLY_ENOMEM;
    }

    memcpy(output, src, sizeof(*src));
    output->script = new_script;
#ifdef BUILD_ELEMENTS
    output->asset = new_asset;
    output->value = new_value;
    output->nonce = new_nonce;
    output->surjectionproof = new_surjectionproof;
    output->rangeproof = new_rangeproof;
#endif
    return WALLY_OK;
}

int wally_tx_output_clone_alloc(const struct wally_tx_output *src,
                                struct wally_tx_output **output)
{
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_tx_output);

    ret = wally_tx_output_clone(src, *output);
    if (ret != WALLY_OK) {
        wally_free(*output);
        *output = NULL;
    }
    return ret;
}

static int tx_elements_output_proof_init(
    struct wally_tx_output *output,
    const unsigned char *surjectionproof,
    size_t surjectionproof_len,
    const unsigned char *rangeproof,
    size_t rangeproof_len)
{
#ifdef BUILD_ELEMENTS
    unsigned char *new_surjectionproof = NULL, *new_rangeproof = NULL;
#endif
    (void) output;

    if (BYTES_INVALID(surjectionproof, surjectionproof_len) ||
        BYTES_INVALID(rangeproof, rangeproof_len))
        return WALLY_EINVAL;

#ifdef BUILD_ELEMENTS
    if (!clone_bytes(&new_surjectionproof, surjectionproof, surjectionproof_len) ||
        !clone_bytes(&new_rangeproof, rangeproof, rangeproof_len)) {
        clear_and_free(new_surjectionproof,  surjectionproof_len);
        clear_and_free(new_rangeproof, rangeproof_len);
        return WALLY_ENOMEM;
    }

    output->surjectionproof = new_surjectionproof;
    output->surjectionproof_len = surjectionproof_len;
    output->rangeproof = new_rangeproof;
    output->rangeproof_len = rangeproof_len;
#endif
    return WALLY_OK;
}

static int tx_elements_output_commitment_init(
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
    size_t rangeproof_len,
    bool is_elements)
{
#ifdef BUILD_ELEMENTS
    int ret;
    unsigned char *new_asset = NULL, *new_value = NULL, *new_nonce = NULL;
#endif

    if (!output ||
        BYTES_INVALID_N(asset, asset_len, WALLY_TX_ASSET_CT_ASSET_LEN) ||
        ((value != NULL) != (value_len == WALLY_TX_ASSET_CT_VALUE_LEN ||
                             value_len == WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN)) ||
        BYTES_INVALID_N(nonce, nonce_len, WALLY_TX_ASSET_CT_NONCE_LEN) ||
        BYTES_INVALID(surjectionproof, surjectionproof_len) ||
        BYTES_INVALID(rangeproof, rangeproof_len))
        return WALLY_EINVAL;

#ifdef BUILD_ELEMENTS
    if (!clone_bytes(&new_asset, asset, asset_len) ||
        !clone_bytes(&new_value, value, value_len) ||
        !clone_bytes(&new_nonce, nonce, nonce_len))
        ret = WALLY_ENOMEM;
    else
        ret = tx_elements_output_proof_init(output,
                                            surjectionproof,
                                            surjectionproof_len,
                                            rangeproof,
                                            rangeproof_len);
    if (ret != WALLY_OK) {
        clear_and_free(new_asset, asset_len);
        clear_and_free(new_value, value_len);
        clear_and_free(new_nonce, nonce_len);
        return ret;
    }

    output->asset = new_asset;
    output->asset_len = asset_len;
    output->value = new_value;
    output->value_len = value_len;
    output->nonce = new_nonce;
    output->nonce_len = nonce_len;
#endif /* BUILD_ELEMENTS */

    if (is_elements)
        output->features |= WALLY_TX_IS_ELEMENTS;

    return WALLY_OK;
}

int wally_tx_elements_output_commitment_set(
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
    size_t rangeproof_len)
{
#ifdef BUILD_ELEMENTS
    unsigned char *output_asset = output->asset;
    size_t output_asset_len = output->asset_len;
    unsigned char *output_value = output->value;
    size_t output_value_len = output->value_len;
    unsigned char *output_nonce = output->nonce;
    size_t output_nonce_len = output->nonce_len;
    unsigned char *output_surjectionproof = output->surjectionproof;
    size_t output_surjectionproof_len = output->surjectionproof_len;
    unsigned char *output_rangeproof = output->rangeproof;
    size_t output_rangeproof_len = output->rangeproof_len;
#endif /* BUILD_ELEMENTS */
    int ret = tx_elements_output_commitment_init(output, asset, asset_len,
                                                 value, value_len,
                                                 nonce, nonce_len,
                                                 surjectionproof, surjectionproof_len,
                                                 rangeproof, rangeproof_len, true);
    if (ret == WALLY_OK) {
#ifdef BUILD_ELEMENTS
        clear_and_free(output_asset, output_asset_len);
        clear_and_free(output_value, output_value_len);
        clear_and_free(output_nonce, output_nonce_len);
        clear_and_free(output_surjectionproof, output_surjectionproof_len);
        clear_and_free(output_rangeproof, output_rangeproof_len);
#endif /* BUILD_ELEMENTS */
    }
    return ret;
}

int wally_tx_elements_output_commitment_free(
    struct wally_tx_output *output)
{
    (void) output;
#ifdef BUILD_ELEMENTS
    if (output) {
        output->features &= ~WALLY_TX_IS_ELEMENTS;
        clear_and_free(output->asset, output->asset_len);
        clear_and_free(output->value, output->value_len);
        clear_and_free(output->nonce, output->nonce_len);
        clear_and_free(output->surjectionproof, output->surjectionproof_len);
        clear_and_free(output->rangeproof, output->rangeproof_len);
    }
#endif /* BUILD_ELEMENTS */
    return WALLY_OK;
}

static int tx_elements_output_init(
    uint64_t satoshi,
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
    struct wally_tx_output *output,
    bool is_elements)
{
    int ret, old_features;
    unsigned char *new_script = NULL;

    if (BYTES_INVALID(script, script_len) || !output ||
        (satoshi > WALLY_SATOSHI_MAX && !is_elements))
        return WALLY_EINVAL;

    if (!clone_bytes(&new_script, script, script_len))
        return WALLY_ENOMEM;

    old_features = output->features;
    output->features = 0;
    if ((ret = tx_elements_output_commitment_init(output, asset, asset_len,
                                                  value, value_len,
                                                  nonce, nonce_len,
                                                  surjectionproof, surjectionproof_len,
                                                  rangeproof, rangeproof_len,
                                                  is_elements)) != WALLY_OK) {
        output->features = old_features;
        clear_and_free(new_script, script_len);
        return ret;
    }

    output->script = new_script;
    output->script_len = script_len;
    output->satoshi = satoshi;
    return WALLY_OK;
}

int wally_tx_elements_output_init(
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
    struct wally_tx_output *output)
{
    return tx_elements_output_init(MAX_INVALID_SATOSHI, script, script_len,
                                   asset, asset_len, value, value_len,
                                   nonce, nonce_len,
                                   surjectionproof, surjectionproof_len,
                                   rangeproof, rangeproof_len, output, true);
}

int wally_tx_elements_output_init_alloc(
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
    struct wally_tx_output **output)
{
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_tx_output);

    ret = tx_elements_output_init(MAX_INVALID_SATOSHI, script, script_len,
                                  asset, asset_len,
                                  value, value_len,
                                  nonce, nonce_len,
                                  surjectionproof,
                                  surjectionproof_len,
                                  rangeproof, rangeproof_len,
                                  *output, true);
    if (ret != WALLY_OK) {
        clear_and_free(*output, sizeof(struct wally_tx_output));
        *output = NULL;
    }
    return ret;
}

int wally_tx_output_init(uint64_t satoshi,
                         const unsigned char *script, size_t script_len,
                         struct wally_tx_output *output)
{
    return tx_elements_output_init(satoshi, script, script_len,
                                   NULL, 0, NULL, 0, NULL, 0,
                                   NULL, 0, NULL, 0, output, false);
}

int wally_tx_output_init_alloc(uint64_t satoshi,
                               const unsigned char *script, size_t script_len,
                               struct wally_tx_output **output)
{
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_tx_output);

    ret = wally_tx_output_init(satoshi, script, script_len, *output);

    if (ret != WALLY_OK) {
        clear_and_free(*output, sizeof(struct wally_tx_output));
        *output = NULL;
    }
    return ret;
}

static int tx_output_free(struct wally_tx_output *output, bool free_parent)
{
    if (output) {
        clear_and_free(output->script, output->script_len);
        wally_tx_elements_output_commitment_free(output);
        wally_clear(output, sizeof(*output));
        if (free_parent)
            wally_free(output);
    }
    return WALLY_OK;
}

int wally_tx_output_free(struct wally_tx_output *output)
{
    return tx_output_free(output, true);
}

static int tx_init_alloc(uint32_t version, uint32_t locktime,
                         size_t inputs_allocation_len,
                         size_t outputs_allocation_len,
                         size_t max_inputs_allocation_len,
                         size_t max_outputs_allocation_len,
                         struct wally_tx **output)
{
    struct wally_tx_input *new_inputs = NULL;
    struct wally_tx_output *new_outputs = NULL;

    OUTPUT_CHECK;
    if (inputs_allocation_len > TX_MAX_INPUTS ||
        outputs_allocation_len > TX_MAX_OUTPUTS)
        return WALLY_EINVAL; /* Tx cannot fit in a block: invalid */
    OUTPUT_ALLOC(struct wally_tx);

    if (inputs_allocation_len) {
        if (inputs_allocation_len > max_inputs_allocation_len)
            inputs_allocation_len = max_inputs_allocation_len;
        new_inputs = wally_calloc(inputs_allocation_len * sizeof(struct wally_tx_input));
    }
    if (outputs_allocation_len) {
        if (outputs_allocation_len > max_outputs_allocation_len)
            outputs_allocation_len = max_outputs_allocation_len;
        new_outputs = wally_calloc(outputs_allocation_len * sizeof(struct wally_tx_output));
    }
    if ((inputs_allocation_len && !new_inputs) ||
        (outputs_allocation_len && !new_outputs)) {
        wally_free(new_inputs);
        wally_free(new_outputs);
        wally_free(*output);
        *output = NULL;
        return WALLY_ENOMEM;
    }

    (*output)->version = version;
    (*output)->locktime = locktime;
    (*output)->inputs = new_inputs;
    (*output)->num_inputs = 0;
    (*output)->inputs_allocation_len = inputs_allocation_len;
    (*output)->outputs = new_outputs;
    (*output)->num_outputs = 0;
    (*output)->outputs_allocation_len = outputs_allocation_len;
    return WALLY_OK;
}

int wally_tx_init_alloc(uint32_t version, uint32_t locktime,
                        size_t inputs_allocation_len,
                        size_t outputs_allocation_len,
                        struct wally_tx **output)
{
    return tx_init_alloc(version, locktime,
                         inputs_allocation_len, outputs_allocation_len,
                         TX_MAX_INPUTS_ALLOC, TX_MAX_OUTPUTS_ALLOC, output);
}

static int tx_free(struct wally_tx *tx, bool free_parent)
{
    size_t i;
    if (tx) {
        for (i = 0; i < tx->num_inputs; ++i)
            tx_input_free(&tx->inputs[i], false);
        clear_and_free(tx->inputs, tx->inputs_allocation_len * sizeof(*tx->inputs));
        for (i = 0; i < tx->num_outputs; ++i)
            tx_output_free(&tx->outputs[i], false);
        clear_and_free(tx->outputs, tx->outputs_allocation_len * sizeof(*tx->outputs));
        wally_clear(tx, sizeof(*tx));
        if (free_parent)
            wally_free(tx);
    }
    return WALLY_OK;
}

int wally_tx_free(struct wally_tx *tx)
{
    return tx_free(tx, true);
}

int wally_tx_add_input_at(struct wally_tx *tx, uint32_t index,
                          const struct wally_tx_input *input)
{
    if (!is_valid_tx(tx) || index > tx->num_inputs || !is_valid_tx_input(input))
        return WALLY_EINVAL;

    if (tx->num_inputs >= tx->inputs_allocation_len) {
        /* Expand the inputs array */
        struct wally_tx_input *p;
        p = array_realloc(tx->inputs, tx->inputs_allocation_len,
                          tx->num_inputs + 1, sizeof(*tx->inputs));
        if (!p)
            return WALLY_ENOMEM;

        clear_and_free(tx->inputs, tx->num_inputs * sizeof(*tx->inputs));
        tx->inputs = p;
        tx->inputs_allocation_len += 1;
    }

    memmove(tx->inputs + index + 1, tx->inputs + index,
            (tx->num_inputs - index) * sizeof(*input));

    if (!clone_input_to(tx->inputs + index, input)) {
        memmove(tx->inputs + index, tx->inputs + index + 1,
                (tx->num_inputs - index) * sizeof(*input)); /* Undo */
        return WALLY_ENOMEM;
    }

    tx->num_inputs += 1;
    return WALLY_OK;
}

int wally_tx_add_input(struct wally_tx *tx, const struct wally_tx_input *input)
{
    return tx ? wally_tx_add_input_at(tx, tx->num_inputs, input) : WALLY_EINVAL;
}

static int tx_add_elements_raw_input_at(
    struct wally_tx *tx, uint32_t index,
    const unsigned char *txhash, size_t txhash_len,
    uint32_t utxo_index, uint32_t sequence,
    const unsigned char *script, size_t script_len,
    const struct wally_tx_witness_stack *witness,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *entropy, size_t entropy_len,
    const unsigned char *issuance_amount, size_t issuance_amount_len,
    const unsigned char *inflation_keys, size_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len,
    const struct wally_tx_witness_stack *pegin_witness,
    uint32_t flags, bool is_elements)
{
    /* Add an input without allocating a temporary wally_tx_input */
    struct wally_tx_input input = {
        { 0 }, utxo_index, sequence,
        (unsigned char *)script, script_len,
        (struct wally_tx_witness_stack *) witness,
        is_elements ? WALLY_TX_IS_ELEMENTS : 0,
#ifdef BUILD_ELEMENTS
        { 0 }, { 0 }, (unsigned char *) issuance_amount,
        issuance_amount_len,
        (unsigned char *) inflation_keys,
        inflation_keys_len,
        (unsigned char *) issuance_amount_rangeproof,
        issuance_amount_rangeproof_len,
        (unsigned char *) inflation_keys_rangeproof,
        inflation_keys_rangeproof_len,
        (struct wally_tx_witness_stack *) pegin_witness
#endif /* BUILD_ELEMENTS */
    };
    bool is_coinbase;
    int ret;
#ifndef BUILD_ELEMENTS
    (void)pegin_witness;
#endif

    if (flags)
        return WALLY_EINVAL; /* TODO: Allow creation of p2pkh/p2sh using flags */

    if (!txhash || txhash_len != WALLY_TXHASH_LEN ||
        BYTES_INVALID_N(nonce, nonce_len, WALLY_TX_ASSET_TAG_LEN) ||
        BYTES_INVALID_N(entropy, entropy_len, WALLY_TX_ASSET_TAG_LEN) ||
        BYTES_INVALID(issuance_amount, issuance_amount_len) ||
        BYTES_INVALID(inflation_keys, inflation_keys_len) ||
        BYTES_INVALID(issuance_amount_rangeproof, issuance_amount_rangeproof_len) ||
        BYTES_INVALID(inflation_keys_rangeproof, inflation_keys_rangeproof_len))
        return WALLY_EINVAL;

    is_coinbase = is_coinbase_bytes(txhash, txhash_len, utxo_index);
    if (is_elements && !is_coinbase)
        input.index = utxo_index & WALLY_TX_INDEX_MASK;
    else
        input.index = utxo_index;
    if (is_coinbase)
        input.features |= WALLY_TX_IS_COINBASE;
    else if (is_elements) {
        if (utxo_index & WALLY_TX_ISSUANCE_FLAG)
            input.features |= WALLY_TX_IS_ISSUANCE;
        if (utxo_index & WALLY_TX_PEGIN_FLAG)
            input.features |= WALLY_TX_IS_PEGIN;
    }

    memcpy(input.txhash, txhash, WALLY_TXHASH_LEN);
#ifdef BUILD_ELEMENTS
    if (nonce)
        memcpy(input.blinding_nonce, nonce, WALLY_TX_ASSET_TAG_LEN);
    if (entropy)
        memcpy(input.entropy, entropy, WALLY_TX_ASSET_TAG_LEN);
#endif /* BUILD_ELEMENTS */
    ret = wally_tx_add_input_at(tx, index, &input);
    wally_clear(&input, sizeof(input));
    return ret;
}

int wally_tx_add_elements_raw_input(
    struct wally_tx *tx,
    const unsigned char *txhash, size_t txhash_len,
    uint32_t utxo_index, uint32_t sequence,
    const unsigned char *script, size_t script_len,
    const struct wally_tx_witness_stack *witness,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *entropy, size_t entropy_len,
    const unsigned char *issuance_amount, size_t issuance_amount_len,
    const unsigned char *inflation_keys, size_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len,
    const struct wally_tx_witness_stack *pegin_witness, uint32_t flags)
{
    if (!tx)
        return WALLY_EINVAL;
    return tx_add_elements_raw_input_at(
        tx, tx->num_inputs, txhash, txhash_len,
        utxo_index, sequence, script,
        script_len, witness,
        nonce, nonce_len, entropy, entropy_len,
        issuance_amount, issuance_amount_len,
        inflation_keys, inflation_keys_len,
        issuance_amount_rangeproof, issuance_amount_rangeproof_len,
        inflation_keys_rangeproof, inflation_keys_rangeproof_len,
        pegin_witness, flags, true);
}

int wally_tx_add_elements_raw_input_at(
    struct wally_tx *tx, uint32_t index,
    const unsigned char *txhash, size_t txhash_len,
    uint32_t utxo_index, uint32_t sequence,
    const unsigned char *script, size_t script_len,
    const struct wally_tx_witness_stack *witness,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *entropy, size_t entropy_len,
    const unsigned char *issuance_amount, size_t issuance_amount_len,
    const unsigned char *inflation_keys, size_t inflation_keys_len,
    const unsigned char *issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len,
    const unsigned char *inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len,
    const struct wally_tx_witness_stack *pegin_witness, uint32_t flags)
{
    return tx_add_elements_raw_input_at(
        tx, index, txhash, txhash_len,
        utxo_index, sequence, script,
        script_len, witness,
        nonce, nonce_len, entropy, entropy_len,
        issuance_amount, issuance_amount_len,
        inflation_keys, inflation_keys_len,
        issuance_amount_rangeproof, issuance_amount_rangeproof_len,
        inflation_keys_rangeproof, inflation_keys_rangeproof_len,
        pegin_witness, flags, true);
}


int wally_tx_add_raw_input(struct wally_tx *tx,
                           const unsigned char *txhash, size_t txhash_len,
                           uint32_t utxo_index, uint32_t sequence,
                           const unsigned char *script, size_t script_len,
                           const struct wally_tx_witness_stack *witness,
                           uint32_t flags)
{
    if (!tx)
        return WALLY_EINVAL;
    return tx_add_elements_raw_input_at(tx, tx->num_inputs, txhash, txhash_len,
                                        utxo_index, sequence, script,
                                        script_len, witness,
                                        NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                                        NULL, 0, NULL, 0, NULL, flags, false);
}

int wally_tx_add_raw_input_at(struct wally_tx *tx, uint32_t index,
                              const unsigned char *txhash, size_t txhash_len,
                              uint32_t utxo_index, uint32_t sequence,
                              const unsigned char *script, size_t script_len,
                              const struct wally_tx_witness_stack *witness,
                              uint32_t flags)
{
    return tx_add_elements_raw_input_at(tx, index, txhash, txhash_len,
                                        utxo_index, sequence, script,
                                        script_len, witness,
                                        NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                                        NULL, 0, NULL, 0, NULL, flags, false);
}

int wally_tx_remove_input(struct wally_tx *tx, size_t index)
{
    struct wally_tx_input *input;

    if (!is_valid_tx(tx) || index >= tx->num_inputs)
        return WALLY_EINVAL;

    input = tx->inputs + index;
    tx_input_free(input, false);
    if (index != tx->num_inputs - 1)
        memmove(input, input + 1,
                (tx->num_inputs - index - 1) * sizeof(*input));
    wally_clear(tx->inputs + tx->num_inputs - 1, sizeof(*input));

    tx->num_inputs -= 1;
    return WALLY_OK;
}

int wally_tx_add_output_at(struct wally_tx *tx, uint32_t index,
                           const struct wally_tx_output *output)
{
    uint64_t total;
    int ret;
    const bool is_elements = output->features & WALLY_TX_IS_ELEMENTS;

    if (!is_valid_tx(tx) || index > tx->num_outputs)
        return WALLY_EINVAL;

    if (!is_elements) {
        if (!is_valid_tx_output(output) ||
            wally_tx_get_total_output_satoshi(tx, &total) != WALLY_OK ||
            total + output->satoshi < total || total + output->satoshi > WALLY_SATOSHI_MAX)
            return WALLY_EINVAL;
    } else if (!is_valid_elements_tx_output(output))
        return WALLY_EINVAL;

    if (tx->num_outputs >= tx->outputs_allocation_len) {
        /* Expand the outputs array */
        struct wally_tx_output *p;
        p = array_realloc(tx->outputs, tx->outputs_allocation_len,
                          tx->num_outputs + 1, sizeof(*tx->outputs));
        if (!p)
            return WALLY_ENOMEM;

        clear_and_free(tx->outputs, tx->num_outputs * sizeof(*tx->outputs));
        tx->outputs = p;
        tx->outputs_allocation_len += 1;
    }

    memmove(tx->outputs + index + 1, tx->outputs + index,
            (tx->num_outputs - index) * sizeof(*output));

    if ((ret = wally_tx_output_clone(output, tx->outputs + index)) != WALLY_OK) {
        memmove(tx->outputs + index, tx->outputs + index + 1,
                (tx->num_outputs - index) * sizeof(*output)); /* Undo */
        return ret;
    }

    tx->num_outputs += 1;
    return WALLY_OK;
}

int wally_tx_add_output(struct wally_tx *tx, const struct wally_tx_output *output)
{
    return tx ? wally_tx_add_output_at(tx, tx->num_outputs, output) : WALLY_EINVAL;
}

static int tx_add_elements_raw_output_at(
    struct wally_tx *tx, uint32_t index, uint64_t satoshi,
    const unsigned char *script, size_t script_len,
    const unsigned char *asset, size_t asset_len,
    const unsigned char *value, size_t value_len,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *surjectionproof, size_t surjectionproof_len,
    const unsigned char *rangeproof, size_t rangeproof_len,
    uint32_t flags, bool is_elements)
{
    /* Add an output without allocating a temporary wally_tx_output */
    struct wally_tx_output output = {
        satoshi, (unsigned char *)script, script_len,
        is_elements ? WALLY_TX_IS_ELEMENTS : 0,
#ifdef BUILD_ELEMENTS
        (unsigned char *)asset, asset_len, (unsigned char *)value, value_len,
        (unsigned char *)nonce, nonce_len, (unsigned char *)surjectionproof, surjectionproof_len,
        (unsigned char *)rangeproof, rangeproof_len,
#endif /* BUILD_ELEMENTS */
    };
    int ret;

    if (flags)
        return WALLY_EINVAL;

    if (BYTES_INVALID_N(asset, asset_len, WALLY_TX_ASSET_CT_ASSET_LEN) ||
        ((value != NULL) != (value_len == WALLY_TX_ASSET_CT_VALUE_LEN ||
                             value_len == WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN)) ||
        BYTES_INVALID_N(nonce, nonce_len, WALLY_TX_ASSET_CT_NONCE_LEN) ||
        BYTES_INVALID(surjectionproof, surjectionproof_len) ||
        BYTES_INVALID(rangeproof, rangeproof_len))
        return WALLY_EINVAL;

    ret = wally_tx_add_output_at(tx, index, &output);
    wally_clear(&output, sizeof(output));
    return ret;
}

int wally_tx_add_elements_raw_output(
    struct wally_tx *tx,
    const unsigned char *script, size_t script_len,
    const unsigned char *asset, size_t asset_len,
    const unsigned char *value, size_t value_len,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *surjectionproof, size_t surjectionproof_len,
    const unsigned char *rangeproof, size_t rangeproof_len,
    uint32_t flags)
{
    if (!tx)
        return WALLY_EINVAL;
    return tx_add_elements_raw_output_at(tx, tx->num_outputs,
                                         MAX_INVALID_SATOSHI,
                                         script, script_len,
                                         asset, asset_len,
                                         value, value_len,
                                         nonce, nonce_len,
                                         surjectionproof, surjectionproof_len,
                                         rangeproof, rangeproof_len,
                                         flags, true);
}

int wally_tx_add_elements_raw_output_at(
    struct wally_tx *tx, uint32_t index,
    const unsigned char *script, size_t script_len,
    const unsigned char *asset, size_t asset_len,
    const unsigned char *value, size_t value_len,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *surjectionproof, size_t surjectionproof_len,
    const unsigned char *rangeproof, size_t rangeproof_len,
    uint32_t flags)
{
    return tx_add_elements_raw_output_at(tx, index,
                                         MAX_INVALID_SATOSHI,
                                         script, script_len,
                                         asset, asset_len,
                                         value, value_len,
                                         nonce, nonce_len,
                                         surjectionproof, surjectionproof_len,
                                         rangeproof, rangeproof_len,
                                         flags, true);
}

int wally_tx_add_raw_output(struct wally_tx *tx, uint64_t satoshi,
                            const unsigned char *script, size_t script_len,
                            uint32_t flags)
{
    if (!tx)
        return WALLY_EINVAL;
    return tx_add_elements_raw_output_at(tx, tx->num_outputs, satoshi,
                                         script, script_len,
                                         NULL, 0, NULL, 0, NULL, 0,
                                         NULL, 0, NULL, 0, flags, false);
}

int wally_tx_add_raw_output_at(struct wally_tx *tx, uint32_t index,
                               uint64_t satoshi,
                               const unsigned char *script, size_t script_len,
                               uint32_t flags)
{
    return tx_add_elements_raw_output_at(tx, index, satoshi,
                                         script, script_len,
                                         NULL, 0, NULL, 0, NULL, 0,
                                         NULL, 0, NULL, 0, flags, false);
}

int wally_tx_remove_output(struct wally_tx *tx, size_t index)
{
    struct wally_tx_output *output;

    if (!is_valid_tx(tx) || index >= tx->num_outputs)
        return WALLY_EINVAL;

    output = tx->outputs + index;
    tx_output_free(output, false);
    if (index != tx->num_outputs - 1)
        memmove(output, output + 1,
                (tx->num_outputs - index - 1) * sizeof(*output));
    wally_clear(tx->outputs + tx->num_outputs - 1, sizeof(*output));

    tx->num_outputs -= 1;
    return WALLY_OK;
}

int wally_tx_get_witness_count(const struct wally_tx *tx, size_t *written)
{
    size_t i;

    if (written)
        *written = 0;

    if (!is_valid_tx(tx) || !written)
        return WALLY_EINVAL;

    for (i = 0; i < tx->num_inputs; ++i) {
        if (tx->inputs[i].witness)
            *written += 1;
#ifdef BUILD_ELEMENTS
        /* TODO: check the count in the presence of a mix of NULL and non-NULL witnesses */
        if (tx->inputs[i].issuance_amount_rangeproof_len)
            *written += 1;
        if (tx->inputs[i].inflation_keys_rangeproof_len)
            *written += 1;
        if (tx->inputs[i].pegin_witness)
            *written += 1;
#endif
    }

#ifdef BUILD_ELEMENTS
    /* TODO: check the count in the presence of a mix of NULL and non-NULL witnesses */
    for (i = 0; i < tx->num_outputs; ++i) {
        if (tx->outputs[i].surjectionproof_len)
            *written += 1;
        if (tx->outputs[i].rangeproof_len)
            *written += 1;
    }
#endif

    return WALLY_OK;
}

static int get_txout_commitments_size(const struct wally_tx_output *output,
                                      size_t *written)
{
#ifdef BUILD_ELEMENTS
    size_t c_n;

    if (!(*written = confidential_asset_length_from_bytes(output->asset)))
        return WALLY_EINVAL;
    if (!(c_n = confidential_value_length_from_bytes(output->value)))
        return WALLY_EINVAL;
    *written += c_n;
    if (!(c_n = confidential_nonce_length_from_bytes(output->nonce)))
        return WALLY_EINVAL;
    *written += c_n;
#else
    (void)output;
    *written = 0;
#endif
    return WALLY_OK;
}

static int get_txin_issuance_size(const struct wally_tx_input *input,
                                  size_t *written)
{
    *written = 0;
#ifdef BUILD_ELEMENTS
    if (input->features & WALLY_TX_IS_ISSUANCE) {
        size_t c_n;

        if (!(*written = confidential_value_length_from_bytes(input->issuance_amount)))
            return WALLY_EINVAL;
        if (!(c_n = confidential_value_length_from_bytes(input->inflation_keys)))
            return WALLY_EINVAL;
        *written = *written + c_n + sizeof(input->blinding_nonce) + sizeof(input->entropy);
    }
#else
    (void)input;
#endif
    return WALLY_OK;
}

static size_t get_bip341_size(uint32_t sighash, bool have_annex, unsigned char ext_flag)
{
    const bool sh_anyonecanpay = sighash & WALLY_SIGHASH_ANYONECANPAY;
    const bool sh_none = (sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_NONE;
    /* See BIP341/342/118. Note the leading 1 for the sighash epoc byte */
    return 1 + 174 - sh_anyonecanpay * 49 - sh_none * 32 +
           have_annex * 32 + (ext_flag == EXT_FLAG_BIP342 ? 37 : 0);
}

/* We compute the size of the witness separately so we can compute vsize
 * without iterating the transaction twice with different flags.
 */
static int tx_get_lengths(const struct wally_tx *tx,
                          const struct tx_serialize_opts *opts, uint32_t flags,
                          size_t *base_size, size_t *witness_size,
                          size_t *witness_count, bool is_elements)
{
    size_t n, i, j;
    const unsigned char sighash = opts ? opts->sighash : 0;
    const bool sh_anyonecanpay = sighash & WALLY_SIGHASH_ANYONECANPAY;
    const bool sh_rangeproof = sighash & WALLY_SIGHASH_RANGEPROOF;
    const bool sh_none = (sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_NONE;
    const bool sh_single = (sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_SINGLE;

    *base_size = 0;
    *witness_size = 0;
    *witness_count = 0;

    if (!is_valid_tx(tx))
        return WALLY_EINVAL;

    if (opts) {
        if (flags & WALLY_TX_FLAG_USE_WITNESS)
            return WALLY_ERROR; /* Segwit tx hashing uses bip143 opts member */

        if (opts->bip341) {
            *base_size = get_bip341_size(opts->tx_sighash, opts->annex_len != 0,
                                         opts->ext_flag);
            *witness_size = 0;
            return WALLY_OK;
        }

        if (opts->bip143) {
            size_t issuance_size, amount_size = sizeof(uint64_t);

            *base_size = sizeof(uint32_t) + /* version */
                         SHA256_LEN + /* hash prevouts */
                         SHA256_LEN + /* hash sequence */
                         WALLY_TXHASH_LEN + sizeof(uint32_t) + /* outpoint + index */
                         varbuff_get_length(opts->script_len) + /* script */
                         sizeof(uint32_t) + /* input sequence */
                         SHA256_LEN + /* hash outputs */
                         ((is_elements && sh_rangeproof) ? SHA256_LEN : 0) + /* rangeproof */
                         sizeof(uint32_t) + /* nlocktime */
                         sizeof(uint32_t); /* tx sighash */

            if (is_elements) {
                /* Amount, possibly blinded */
                if (!(amount_size = confidential_value_length_from_bytes(opts->value)))
                    return WALLY_EINVAL;
                amount_size += SHA256_LEN; /* TODO: Comment what this represents */
            }
            *base_size += amount_size;

            if (get_txin_issuance_size(tx->inputs + opts->index, &issuance_size) != WALLY_OK)
                return WALLY_EINVAL;
            *base_size += issuance_size;
            *witness_size = 0;
            return WALLY_OK;
        }
    }

    if ((flags & ~WALLY_TX_ALL_FLAGS) ||
        ((flags & WALLY_TX_FLAG_USE_WITNESS) &&
         wally_tx_get_witness_count(tx, witness_count) != WALLY_OK))
        return WALLY_EINVAL;

    if (!*witness_count)
        flags &= ~WALLY_TX_FLAG_USE_WITNESS;

    n = sizeof(tx->version) +
        varint_get_length(sh_anyonecanpay ? 1 : tx->num_inputs) +
        (sh_none ? 1 : varint_get_length(sh_single ? opts->index + 1 : tx->num_outputs)) +
        sizeof(tx->locktime) +
        (opts ? sizeof(leint32_t) : 0); /* Include trailing tx_sighash */

    if (!opts && is_elements)
        n += sizeof(uint8_t); /* witness flag */
    for (i = 0; i < tx->num_inputs; ++i) {
        const struct wally_tx_input *input = tx->inputs + i;
        size_t issuance_size = 0;

        if (sh_anyonecanpay && i != opts->index)
            continue; /* sh_anyonecanpay only signs the given index */

        n += sizeof(input->txhash) +
             sizeof(input->index) +
             sizeof(input->sequence);

        if (get_txin_issuance_size(input, &issuance_size) != WALLY_OK)
            return WALLY_EINVAL;
        n += issuance_size;

        if (opts) {
            if (i == opts->index)
                n += varbuff_get_length(opts->script_len);
            else
                ++n;
        } else
            n += varbuff_get_length(input->script_len);

    }

    if (!sh_none) {
        size_t num_outputs = sh_single ? opts->index + 1 : tx->num_outputs;

        for (i = 0; i < num_outputs; ++i) {
            const struct wally_tx_output *output = tx->outputs + i;
            if (sh_single && i != opts->index)
                n += sizeof(EMPTY_OUTPUT);
            else {
                if (is_elements && (output->features & WALLY_TX_IS_ELEMENTS)) {
                    size_t commit_size;
                    if (get_txout_commitments_size(output, &commit_size) != WALLY_OK)
                        return WALLY_EINVAL;
                    n += commit_size;
                } else
                    n += sizeof(output->satoshi);
                n += varbuff_get_length(output->script_len);

#ifdef BUILD_ELEMENTS
                if (is_elements && sh_rangeproof) {
                    n += varbuff_get_length(output->rangeproof_len) +
                         varbuff_get_length(output->surjectionproof_len);
                }
#endif /* BUILD_ELEMENTS */
            }
        }
    }

    *base_size = n;

    n = 0;
    if (flags & WALLY_TX_FLAG_USE_WITNESS) {
        if (is_elements) {
#ifdef BUILD_ELEMENTS
            for (i = 0; i < tx->num_inputs; ++i) {
                const struct wally_tx_input *input = tx->inputs + i;
                size_t num_items;
                n += varbuff_get_length(input->issuance_amount_rangeproof_len);
                n += varbuff_get_length(input->inflation_keys_rangeproof_len);
                num_items = input->witness ? input->witness->num_items : 0;
                n += varint_get_length(num_items);
                for (j = 0; j < num_items; ++j) {
                    const struct wally_tx_witness_item *stack;
                    stack = input->witness->items + j;
                    n += varbuff_get_length(stack->witness_len);
                }
                num_items = input->pegin_witness ? input->pegin_witness->num_items : 0;
                n += varint_get_length(num_items);
                for (j = 0; j < num_items; ++j) {
                    const struct wally_tx_witness_item *stack;
                    stack = input->pegin_witness->items + j;
                    n += varbuff_get_length(stack->witness_len);
                }
            }

            for (i = 0; i < tx->num_outputs; ++i) {
                const struct wally_tx_output *output = tx->outputs + i;
                n += varbuff_get_length(output->surjectionproof_len);
                n += varbuff_get_length(output->rangeproof_len);
            }
#endif /* BUILD_ELEMENTS */
        } else {
            n = 2; /* For marker and flag bytes 0x00 0x01 */

            for (i = 0; i < tx->num_inputs; ++i) {
                const struct wally_tx_input *input = tx->inputs + i;
                size_t num_items = input->witness ? input->witness->num_items : 0;
                n += varint_get_length(num_items);
                for (j = 0; j < num_items; ++j) {
                    const struct wally_tx_witness_item *stack;
                    stack = input->witness->items + j;
                    n += varbuff_get_length(stack->witness_len);
                }
            }
        }
    }

    *witness_size = n;
    return WALLY_OK;
}

static int tx_get_length(const struct wally_tx *tx,
                         const struct tx_serialize_opts *opts, uint32_t flags,
                         size_t *written, bool is_elements)
{
    size_t base_size, witness_size, witness_count;
    int ret;

    if (written)
        *written = 0;
    if (!written)
        return WALLY_EINVAL;
    ret = tx_get_lengths(tx, opts, flags, &base_size, &witness_size,
                         &witness_count, is_elements);
    if (ret == WALLY_OK) {
        if (witness_count && (flags & WALLY_TX_FLAG_USE_WITNESS))
            *written = base_size + witness_size;
        else
            *written = base_size;
    }
    return ret;
}

int wally_tx_get_length(const struct wally_tx *tx, uint32_t flags,
                        size_t *written)
{
    size_t is_elements = 0;
#ifdef BUILD_ELEMENTS
    if (wally_tx_is_elements(tx, &is_elements) != WALLY_OK)
        return WALLY_EINVAL;
#endif

    return tx_get_length(tx, NULL, flags, written, is_elements != 0);
}

int wally_tx_get_weight(const struct wally_tx *tx, size_t *written)
{
    size_t base_size, witness_size, witness_count;
    size_t is_elements = 0;

    if (written)
        *written = 0;

#ifdef BUILD_ELEMENTS
    if (wally_tx_is_elements(tx, &is_elements) != WALLY_OK)
        return WALLY_EINVAL;
#endif

    if (!written ||
        tx_get_lengths(tx, NULL, WALLY_TX_FLAG_USE_WITNESS, &base_size,
                       &witness_size, &witness_count, is_elements != 0) != WALLY_OK)
        return WALLY_EINVAL;

    if (witness_count)
        *written = base_size * 4 + witness_size;
    else
        *written = base_size * 4;

    return WALLY_OK;
}

int wally_tx_vsize_from_weight(size_t weight, size_t *written)
{
    *written = (weight + 3) / 4; /* ceil(weight/4) */
    return WALLY_OK;
}

int wally_tx_get_vsize(const struct wally_tx *tx, size_t *written)
{
    int ret = wally_tx_get_weight(tx, written);
    if (ret == WALLY_OK)
        ret = wally_tx_vsize_from_weight(*written, written);
    return ret;
}

static int hash_prevouts(unsigned char *prevouts, size_t inputs_size,
                         unsigned char *bytes_out, size_t len, bool do_free)
{
    int ret = wally_sha256d(prevouts, inputs_size, bytes_out, len);
    wally_clear(prevouts, inputs_size);
    if (do_free)
        wally_free(prevouts);
    return ret;
}

int wally_get_hash_prevouts(const unsigned char *txhashes, size_t txhashes_len,
                            const uint32_t *utxo_indices, size_t num_utxo_indices,
                            unsigned char *bytes_out, size_t len)
{
    unsigned char *buff_p;
    size_t inputs_size, i;

    if (!txhashes || !txhashes_len || txhashes_len % WALLY_TXHASH_LEN ||
        !utxo_indices || num_utxo_indices * WALLY_TXHASH_LEN != txhashes_len ||
        !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    inputs_size = txhashes_len + (num_utxo_indices * sizeof(uint32_t));
    if (!(buff_p = wally_malloc(inputs_size)))
        return WALLY_ENOMEM;

    for (i = 0; i < num_utxo_indices; ++i) {
        unsigned char *tmp_p = buff_p + i * (WALLY_TXHASH_LEN + sizeof(uint32_t));
        memcpy(tmp_p, txhashes + i * WALLY_TXHASH_LEN, WALLY_TXHASH_LEN);
        uint32_to_le_bytes(utxo_indices[i], tmp_p + WALLY_TXHASH_LEN);
    }
    return hash_prevouts(buff_p, inputs_size, bytes_out, len, true);
}

int wally_tx_get_hash_prevouts(const struct wally_tx *tx,
                               size_t index, size_t num_inputs,
                               unsigned char *bytes_out, size_t len)
{
    unsigned char buff[TX_STACK_SIZE / 2], *buff_p = buff;
    size_t inputs_size, i;

    if (tx && num_inputs == 0xffffffff) {
        if (index)
            return WALLY_EINVAL; /* 0xffffffff is only valid with index == 0 */
       num_inputs = tx->num_inputs;
    }
    if (!tx || index >= tx->num_inputs || !num_inputs ||
        num_inputs > tx->num_inputs || index + num_inputs > tx->num_inputs ||
        !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    inputs_size = num_inputs * (SHA256_LEN + sizeof(uint32_t));
    if (inputs_size > sizeof(buff) && !(buff_p = wally_malloc(inputs_size)))
        return WALLY_ENOMEM;

    for (i = 0; i < num_inputs; ++i) {
        const size_t tx_i = index + i;
        unsigned char *tmp_p = buff_p + i * (WALLY_TXHASH_LEN + sizeof(uint32_t));
        memcpy(tmp_p, tx->inputs[tx_i].txhash, WALLY_TXHASH_LEN);
        uint32_to_le_bytes(tx->inputs[tx_i].index, tmp_p + WALLY_TXHASH_LEN);
    }
    return hash_prevouts(buff_p, inputs_size, bytes_out, len, inputs_size > sizeof(buff));
}

static inline int tx_to_bip143_bytes(const struct wally_tx *tx,
                                     const struct tx_serialize_opts *opts,
                                     uint32_t flags,
                                     unsigned char *bytes_out, size_t len,
                                     size_t *written)
{
    unsigned char buff[TX_STACK_SIZE / 2], *buff_p = buff;
    size_t i, inputs_size, outputs_size, rangeproof_size = 0, issuances_size = 0, buff_len = sizeof(buff);
    size_t is_elements = 0;
    const unsigned char sighash = opts->sighash;
    const bool sh_anyonecanpay = sighash & WALLY_SIGHASH_ANYONECANPAY;
    const bool sh_rangeproof = sighash & WALLY_SIGHASH_RANGEPROOF;
    const bool sh_none = (sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_NONE;
    const bool sh_single = (sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_SINGLE;
    unsigned char *p = bytes_out, *output_p;
    int ret = WALLY_OK;

    (void)flags;
    (void)len;
    (void)sh_rangeproof;

#ifdef BUILD_ELEMENTS
    if ((ret = wally_tx_is_elements(tx, &is_elements)) != WALLY_OK)
        return ret;
#endif

    /* Note we assume tx_to_bytes has already validated all inputs */
    p += uint32_to_le_bytes(tx->version, p);

    inputs_size = tx->num_inputs * (WALLY_TXHASH_LEN + sizeof(uint32_t));
    if (sh_none || (sh_single && opts->index >= tx->num_outputs))
        outputs_size = 0;
    else if (sh_single) {
        const struct wally_tx_output *output = tx->outputs + opts->index;
        if (!is_elements)
            outputs_size = sizeof(uint64_t) +
                           varbuff_get_length(output->script_len);
#ifdef BUILD_ELEMENTS
        else {
            if ((ret = get_txout_commitments_size(output, &outputs_size)) != WALLY_OK)
                goto error;
            outputs_size += varbuff_get_length(output->script_len);

            if (sh_rangeproof) {
                rangeproof_size = varbuff_get_length(output->rangeproof_len) +
                                  varbuff_get_length(output->surjectionproof_len);
            }
        }
#else
        else
            return WALLY_EINVAL;
#endif
    } else {
        outputs_size = 0;
        for (i = 0; i < tx->num_outputs; ++i) {
            const struct wally_tx_output *output = tx->outputs + i;
            if (!is_elements)
                outputs_size += sizeof(uint64_t);
#ifdef BUILD_ELEMENTS
            else {
                size_t commit_size;
                if ((ret = get_txout_commitments_size(output, &commit_size)) != WALLY_OK)
                    goto error;
                outputs_size += commit_size;

                if (sh_rangeproof) {
                    rangeproof_size += varbuff_get_length(output->rangeproof_len) +
                                       varbuff_get_length(output->surjectionproof_len);
                }
            }
#else
            else
                return WALLY_EINVAL;
#endif
            outputs_size += varbuff_get_length(output->script_len);
        }
    }

#ifdef BUILD_ELEMENTS
    if (is_elements && !sh_anyonecanpay) {
        for (i = 0; i < tx->num_inputs; ++i) {
            if (tx->inputs[i].features & WALLY_TX_IS_ISSUANCE) {
                size_t issuance_size;
                if (get_txin_issuance_size(tx->inputs + i, &issuance_size) != WALLY_OK)
                    return WALLY_EINVAL;
                issuances_size += issuance_size;
            } else
                issuances_size += 1;
        }
    }
#endif

    if (inputs_size > buff_len || outputs_size > buff_len ||
        rangeproof_size > buff_len || issuances_size > buff_len) {
        buff_len = inputs_size > outputs_size ? inputs_size : outputs_size;
        buff_len = buff_len > rangeproof_size ? buff_len : rangeproof_size;
        buff_len = buff_len > issuances_size ? buff_len : issuances_size;
        buff_p = wally_malloc(buff_len);
        if (buff_p == NULL)
            return WALLY_ENOMEM;
    }

    /* Inputs */
    if (sh_anyonecanpay)
        memset(p, 0, SHA256_LEN);
    else {
        for (i = 0; i < tx->num_inputs; ++i) {
            unsigned char *tmp_p = buff_p + i * (WALLY_TXHASH_LEN + sizeof(uint32_t));
            memcpy(tmp_p, tx->inputs[i].txhash, WALLY_TXHASH_LEN);
            uint32_to_le_bytes(tx->inputs[i].index, tmp_p + WALLY_TXHASH_LEN);
        }

        if ((ret = wally_sha256d(buff_p, inputs_size, p, SHA256_LEN)) != WALLY_OK)
            goto error;
    }
    p += SHA256_LEN;

    /* Sequences */
    if (sh_anyonecanpay || sh_single || sh_none)
        memset(p, 0, SHA256_LEN);
    else {
        for (i = 0; i < tx->num_inputs; ++i)
            uint32_to_le_bytes(tx->inputs[i].sequence, buff_p + i * sizeof(uint32_t));

        ret = wally_sha256d(buff_p, tx->num_inputs * sizeof(uint32_t), p, SHA256_LEN);
        if (ret != WALLY_OK)
            goto error;
    }
    p += SHA256_LEN;

#ifdef BUILD_ELEMENTS
    if (is_elements) {
        /* Issuance */
        if (sh_anyonecanpay)
            memset(p, 0, SHA256_LEN);
        else {
            unsigned char *tmp_p = buff_p;
            for (i = 0; i < tx->num_inputs; ++i) {
                if (tx->inputs[i].features & WALLY_TX_IS_ISSUANCE) {
                    memcpy(tmp_p, tx->inputs[i].blinding_nonce, WALLY_TX_ASSET_TAG_LEN);
                    tmp_p += WALLY_TX_ASSET_TAG_LEN;
                    memcpy(tmp_p, tx->inputs[i].entropy, WALLY_TX_ASSET_TAG_LEN);
                    tmp_p += WALLY_TX_ASSET_TAG_LEN;
                    tmp_p += confidential_value_to_bytes(tx->inputs[i].issuance_amount,
                                                         tx->inputs[i].issuance_amount_len, tmp_p);
                    tmp_p += confidential_value_to_bytes(tx->inputs[i].inflation_keys,
                                                         tx->inputs[i].inflation_keys_len, tmp_p);
                }
                else
                    *tmp_p++ = 0;
            }

            if ((ret = wally_sha256d(buff_p, issuances_size, p, SHA256_LEN)) != WALLY_OK)
                goto error;
        }
        p += SHA256_LEN;
    }
#endif /* BUILD_ELEMENTS */

    /* Input details */
    memcpy(p, tx->inputs[opts->index].txhash, WALLY_TXHASH_LEN);
    p += WALLY_TXHASH_LEN;
    p += uint32_to_le_bytes(tx->inputs[opts->index].index, p);
    p += varbuff_to_bytes(opts->script, opts->script_len, p);
    if (!is_elements)
        p += uint64_to_le_bytes(opts->satoshi, p);
#ifdef BUILD_ELEMENTS
    else
        p += confidential_value_to_bytes(opts->value, opts->value_len, p);
#endif
    p += uint32_to_le_bytes(tx->inputs[opts->index].sequence, p);

#ifdef BUILD_ELEMENTS
    if (is_elements && (tx->inputs[opts->index].features & WALLY_TX_IS_ISSUANCE)) {
        memcpy(p, tx->inputs[opts->index].blinding_nonce, WALLY_TX_ASSET_TAG_LEN);
        p += WALLY_TX_ASSET_TAG_LEN;
        memcpy(p, tx->inputs[opts->index].entropy, WALLY_TX_ASSET_TAG_LEN);
        p += WALLY_TX_ASSET_TAG_LEN;
        p += confidential_value_to_bytes(tx->inputs[opts->index].issuance_amount,
                                         tx->inputs[opts->index].issuance_amount_len, p);
        p += confidential_value_to_bytes(tx->inputs[opts->index].inflation_keys,
                                         tx->inputs[opts->index].inflation_keys_len, p);
    }
#endif

    /* Outputs */
    if (sh_none || (sh_single && opts->index >= tx->num_outputs))
        memset(p, 0, SHA256_LEN);
    else {
        output_p = buff_p;
        for (i = 0; i < tx->num_outputs; ++i) {
            if (sh_single && i != opts->index)
                continue;
            if (!is_elements)
                output_p += uint64_to_le_bytes(tx->outputs[i].satoshi, output_p);
#ifdef BUILD_ELEMENTS
            else {
                output_p += confidential_value_to_bytes(tx->outputs[i].asset, tx->outputs[i].asset_len,
                                                        output_p);
                output_p += confidential_value_to_bytes(tx->outputs[i].value, tx->outputs[i].value_len,
                                                        output_p);
                output_p += confidential_value_to_bytes(tx->outputs[i].nonce, tx->outputs[i].nonce_len,
                                                        output_p);
            }
#endif
            output_p += varbuff_to_bytes(tx->outputs[i].script,
                                         tx->outputs[i].script_len, output_p);
        }

        ret = wally_sha256d(buff_p, outputs_size, p, SHA256_LEN);
        if (ret != WALLY_OK)
            goto error;
    }
    p += SHA256_LEN;

    /* rangeproof */
#ifdef BUILD_ELEMENTS
    if (is_elements && sh_rangeproof) {
        if (sh_none || (sh_single && opts->index >= tx->num_outputs))
            memset(p, 0, SHA256_LEN);
        else {
            output_p = buff_p;
            for (i = 0; i < tx->num_outputs; ++i) {
                if (sh_single && i != opts->index)
                    continue;
                output_p += varbuff_to_bytes(tx->outputs[i].rangeproof,
                                             tx->outputs[i].rangeproof_len, output_p);
                output_p += varbuff_to_bytes(tx->outputs[i].surjectionproof,
                                             tx->outputs[i].surjectionproof_len, output_p);
            }
            ret = wally_sha256d(buff_p, rangeproof_size, p, SHA256_LEN);
            if (ret != WALLY_OK)
                goto error;
        }
        p += SHA256_LEN;
    }
#endif

    /* nlocktime and sighash*/
    p += uint32_to_le_bytes(tx->locktime, p);
    p += uint32_to_le_bytes(opts->tx_sighash, p);

    *written = p - bytes_out;

error:
    if (buff_p != buff)
        clear_and_free(buff_p, buff_len);
    else
        wally_clear(buff, sizeof(buff));
    return ret;
}

static bool tr_is_input_hash_type(uint32_t sighash, uint32_t hash_type)
{
    return (sighash & WALLY_SIGHASH_TR_IN_MASK) == hash_type;
}

static inline int tx_to_bip341_bytes(const struct wally_tx *tx,
                                     const struct tx_serialize_opts *opts,
                                     uint32_t flags,
                                     unsigned char *bytes_out, size_t len,
                                     size_t *written)
{
    unsigned char buff[TX_STACK_SIZE / 2], *buff_p = buff;
    size_t i, is_elements, sub_size, buff_len = sizeof(buff);
    const bool has_annex = opts->annex != NULL;
    const bool sh_none = (opts->sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_NONE;
    const bool sh_single = (opts->sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_SINGLE;
    const bool sh_anyonecanpay = tr_is_input_hash_type(opts->sighash, WALLY_SIGHASH_ANYONECANPAY);
    const bool sh_anyprevout = tr_is_input_hash_type(opts->sighash, WALLY_SIGHASH_ANYPREVOUT);
    const bool sh_anyprevout_anyscript = tr_is_input_hash_type(opts->sighash, WALLY_SIGHASH_ANYPREVOUTANYSCRIPT);
    unsigned char *p = bytes_out, *tmp_p;
    int ret = WALLY_OK;

    /* Note we assume tx_to_bytes has already validated all inputs */
    (void)flags;
    (void)len;
    (void)is_elements;

#ifdef BUILD_ELEMENTS
    if ((ret = wally_tx_is_elements(tx, &is_elements)) != WALLY_OK || is_elements)
        return WALLY_EINVAL;
#endif

    if (opts->key_version > 0x1)
        return WALLY_EINVAL; /* Non-BIP341/342/118 key version */

    switch (opts->sighash) {
        case WALLY_SIGHASH_DEFAULT:
        case WALLY_SIGHASH_ALL:
        case WALLY_SIGHASH_NONE:
        case WALLY_SIGHASH_SINGLE:
        case WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYONECANPAY:
        case WALLY_SIGHASH_NONE | WALLY_SIGHASH_ANYONECANPAY:
        case WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY:
            break; /* Always valid */
        case WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYPREVOUT:
        case WALLY_SIGHASH_NONE | WALLY_SIGHASH_ANYPREVOUT:
        case WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYPREVOUT:
        case WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYPREVOUT | WALLY_SIGHASH_ANYONECANPAY:
        case WALLY_SIGHASH_NONE | WALLY_SIGHASH_ANYPREVOUT | WALLY_SIGHASH_ANYONECANPAY:
        case WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYPREVOUT | WALLY_SIGHASH_ANYONECANPAY:
            if (opts->key_version != 1)
                return WALLY_EINVAL; /* Only valid for key_version 1 */
            break;
        default:
            return WALLY_EINVAL; /* Unknown sighash type */
    }

    if (sh_single && opts->index >= tx->num_outputs)
        return WALLY_EINVAL; /* no corresponding output for SIGHASH_SINGLE */

    p += uint8_to_le_bytes(0, p);             /* sighash epoch: 0x00 */
    p += uint8_to_le_bytes(opts->sighash, p); /* hash_type (1) */
    p += uint32_to_le_bytes(tx->version, p);  /* nVersion (4) */
    p += uint32_to_le_bytes(tx->locktime, p); /* nLockTime (4) */

    /* Compute the sizes needed for prevouts/scripts/output sub-hashes */
    sub_size = tx->num_inputs * (WALLY_TXHASH_LEN + sizeof(uint32_t));
    buff_len = sub_size > buff_len ? sub_size : buff_len;

    sub_size = 0;
    for (i = 0; i < tx->num_inputs; ++i) {
        const struct wally_map_item *script = wally_map_get_integer(opts->scripts, i);
        if (!script || !script->value || !script->value_len) {
            ret = WALLY_EINVAL; /* Missing script */
            goto error;
        }
        sub_size += varbuff_get_length(script->value_len);
    }
    buff_len = sub_size > buff_len ? sub_size  : buff_len;

    if (sh_none)
        sub_size = 0;
    else if (sh_single) {
        sub_size = sizeof(uint64_t);
        sub_size += varbuff_get_length(tx->outputs[opts->index].script_len);
    } else {
        sub_size = 0;
        for (i = 0; i < tx->num_outputs; ++i) {
            sub_size += sizeof(uint64_t);
            sub_size += varbuff_get_length(tx->outputs[i].script_len);
        }
    }
    buff_len = sub_size > buff_len ? sub_size : buff_len;

    buff_len = opts->tapleaf_script_len > buff_len ? opts->tapleaf_script_len : buff_len;

    /* Allocate a larger buffer if needed to hold our sub-hashes data */
    if (buff_len > sizeof(buff) && !(buff_p = wally_malloc(buff_len)))
        return WALLY_ENOMEM;

    if (!sh_anyonecanpay && !sh_anyprevout) {
        /* sha_prevouts */
        tmp_p = buff_p;
        for (i = 0; i < tx->num_inputs; ++i) {
            memcpy(tmp_p, tx->inputs[i].txhash, WALLY_TXHASH_LEN);
            uint32_to_le_bytes(tx->inputs[i].index, tmp_p + WALLY_TXHASH_LEN);
            tmp_p += WALLY_TXHASH_LEN + sizeof(uint32_t);
        }
        if ((ret = wally_sha256(buff_p, tmp_p - buff_p, p, SHA256_LEN)) != WALLY_OK)
            goto error;
        p += SHA256_LEN;

        /* sha_amounts */
        tmp_p = buff_p;
        for (i = 0; i < tx->num_inputs; ++i)
            tmp_p += uint64_to_le_bytes(opts->prev_satoshis[i], tmp_p);
        if ((ret = wally_sha256(buff_p, tmp_p - buff_p, p, SHA256_LEN)) != WALLY_OK)
            goto error;
        p += SHA256_LEN;

        /* sha_scriptpubkeys */
        tmp_p = buff_p;
        for (i = 0; i < tx->num_inputs; ++i) {
            const struct wally_map_item *script = wally_map_get_integer(opts->scripts, i);
            tmp_p += varbuff_to_bytes(script->value, script->value_len, tmp_p);
        }
        if ((ret = wally_sha256(buff_p, tmp_p - buff_p, p, SHA256_LEN)) != WALLY_OK)
            goto error;
        p += SHA256_LEN;

        /* sha_sequences */
        tmp_p = buff_p;
        for (i = 0; i < tx->num_inputs; ++i)
            tmp_p += uint32_to_le_bytes(tx->inputs[i].sequence, tmp_p);

        if ((ret = wally_sha256(buff_p, tmp_p - buff_p, p, SHA256_LEN)) != WALLY_OK)
            goto error;
        p += SHA256_LEN;
    }

    if (!sh_none && !sh_single) {
        /* sha_outputs */
        tmp_p = buff_p;
        for (i = 0; i < tx->num_outputs; ++i) {
            tmp_p += uint64_to_le_bytes(tx->outputs[i].satoshi, tmp_p);
            tmp_p += varbuff_to_bytes(tx->outputs[i].script,
                                      tx->outputs[i].script_len, tmp_p);
        }
        if ((ret = wally_sha256(buff_p, tmp_p - buff_p, p, SHA256_LEN)) != WALLY_OK)
            goto error;
        p += SHA256_LEN;
    }

    /* Data about this input: */
    p += uint8_to_le_bytes(opts->ext_flag * 2 + has_annex, p); /* spend_type (1) */

    if (sh_anyonecanpay || sh_anyprevout) {
       const struct wally_map_item *script = wally_map_get_integer(opts->scripts, opts->index);
        if (!script || !script->value || script->value_len != WALLY_SCRIPTPUBKEY_P2TR_LEN ||
            script->value[0] != OP_1 || script->value[1] != 32u) {
            ret = WALLY_EINVAL; /* Not a v1 segwit taproot script */
            goto error;
        }
        if (sh_anyonecanpay) {
            /* outpoint (36) */
            memcpy(p, tx->inputs[opts->index].txhash, WALLY_TXHASH_LEN);
            p += WALLY_TXHASH_LEN;
            p += uint32_to_le_bytes(tx->inputs[opts->index].index, p);
        }
        p += uint64_to_le_bytes(opts->satoshi, p);                    /* amount (8) */
        p += varbuff_to_bytes(script->value, script->value_len, p);   /* scriptPubKey (35) */
        p += uint32_to_le_bytes(tx->inputs[opts->index].sequence, p); /* nSequence (4) */
    } else if (sh_anyprevout_anyscript) {
        p += uint32_to_le_bytes(tx->inputs[opts->index].sequence, p); /* nSequence (4) */
    } else {
        p += uint32_to_le_bytes(opts->index, p); /* input_index (4) */
    }

    if (has_annex) {
        /* sha_annex */
        tmp_p = buff_p + varbuff_to_bytes(opts->annex, opts->annex_len, buff_p);
        if ((ret = wally_sha256(buff_p, tmp_p - buff_p, p, SHA256_LEN)) != WALLY_OK)
            goto error;
        p += SHA256_LEN;
    }

    /* Data about this output: */
    if (sh_single) {
        /* sha_single_output */
        const struct wally_tx_output *txout = &tx->outputs[opts->index];
        tmp_p = buff_p + uint64_to_le_bytes(txout->satoshi, buff_p);
        tmp_p += varbuff_to_bytes(txout->script, txout->script_len, tmp_p);
        if ((ret = wally_sha256(buff_p, tmp_p - buff_p, p, SHA256_LEN)) != WALLY_OK)
            goto error;
        p += SHA256_LEN;
    }

    /* Tapscript Extensions: */
    if (opts->ext_flag == EXT_FLAG_BIP342) {
        if (!sh_anyprevout_anyscript) {
            /* tapleaf_hash (32): hash_TapLeaf(v || compact_size(size of s) || s) */
            buff_p[0] = 0xC0; /* leaf_version */
            tmp_p = buff_p + 1;
            tmp_p += varbuff_to_bytes(opts->tapleaf_script, opts->tapleaf_script_len, tmp_p);
            ret = wally_bip340_tagged_hash(buff_p, tmp_p - buff_p, "TapLeaf", p, SHA256_LEN);
            if (ret != WALLY_OK)
                goto error;
            p += SHA256_LEN;
        }

        p += uint8_to_le_bytes(opts->key_version & 0xff, p); /* key_version (1) */
        p += uint32_to_le_bytes(opts->codesep_position, p);  /* codesep_pos (4) */
    } else if (opts->ext_flag) {
        ret = WALLY_ERROR; /* Unknown extension flag */
        goto error;
    }

    *written = p - bytes_out;

error:
    if (buff_p != buff)
        clear_and_free(buff_p, buff_len);
    else
        wally_clear(buff, sizeof(buff));
    return ret;
}

static int tx_to_bytes(const struct wally_tx *tx,
                       const struct tx_serialize_opts *opts,
                       uint32_t flags,
                       unsigned char *bytes_out, size_t len,
                       size_t *written,
                       bool is_elements)
{
    size_t n, i, j, witness_count;
    const unsigned char sighash = opts ? opts->sighash : 0;
    const bool sh_anyonecanpay = sighash & WALLY_SIGHASH_ANYONECANPAY;
    const bool sh_rangeproof = sighash & WALLY_SIGHASH_RANGEPROOF;
    const bool sh_none = (sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_NONE;
    const bool sh_single = (sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_SINGLE;
    unsigned char *p = bytes_out;

    (void)sh_rangeproof;

    if (written)
        *written = 0;

    if (!is_valid_tx(tx) ||
        (flags & ~WALLY_TX_ALL_FLAGS) || !bytes_out || !written ||
        tx_get_length(tx, opts, flags, &n, is_elements) != WALLY_OK)
        return WALLY_EINVAL;

    if (opts && (flags & WALLY_TX_FLAG_USE_WITNESS))
        return WALLY_ERROR; /* Segwit tx hashing is handled elsewhere */

    if (!(flags & WALLY_TX_FLAG_ALLOW_PARTIAL)) {
        /* 0-input/output txs can be only be written with this flag */
        if (!tx->num_inputs || !tx->num_outputs)
            return WALLY_EINVAL;
    }

    if (!tx->num_inputs) {
        /* 0-input txs can only be written in the pre-BIP144 format,
         * since otherwise the resulting tx is ambiguous.
         * Used in PSBTs while building the tx for example.
         */
        if (!(flags & WALLY_TX_FLAG_PRE_BIP144))
            return WALLY_EINVAL;
        flags &= ~WALLY_TX_FLAG_USE_WITNESS;
    }

    if (n > len) {
        *written = n;
        return WALLY_OK;
    }

    if (opts && opts->bip143)
        return tx_to_bip143_bytes(tx, opts, flags, bytes_out, len, written);

    if (opts && opts->bip341)
        return tx_to_bip341_bytes(tx, opts, flags, bytes_out, len, written);

    if (flags & WALLY_TX_FLAG_USE_WITNESS) {
        if (wally_tx_get_witness_count(tx, &witness_count) != WALLY_OK)
            return WALLY_EINVAL;
        if (!witness_count)
            flags &= ~WALLY_TX_FLAG_USE_WITNESS;
    }

    p += uint32_to_le_bytes(tx->version, p);
    if (is_elements) {
        if (!opts)
            *p++ = flags & WALLY_TX_FLAG_USE_WITNESS ? 1 : 0;
    } else {
        if (flags & WALLY_TX_FLAG_USE_WITNESS) {
            *p++ = 0; /* Write BIP 144 marker */
            *p++ = 1; /* Write BIP 144 flag */
        }
    }
    if (sh_anyonecanpay)
        *p++ = 1;
    else
        p += varint_to_bytes(tx->num_inputs, p);

    for (i = 0; i < tx->num_inputs; ++i) {
        const struct wally_tx_input *input = tx->inputs + i;
        if (sh_anyonecanpay && i != opts->index)
            continue; /* sh_anyonecanpay only signs the given index */

        memcpy(p, input->txhash, sizeof(input->txhash));
        p += sizeof(input->txhash);
        if (!opts && (input->features & WALLY_TX_IS_ISSUANCE))
            p += uint32_to_le_bytes(input->index | WALLY_TX_ISSUANCE_FLAG, p);
        else if (!opts && (input->features & WALLY_TX_IS_PEGIN))
            p += uint32_to_le_bytes(input->index | WALLY_TX_PEGIN_FLAG, p);
        else
            p += uint32_to_le_bytes(input->index, p);
        if (opts) {
            if (i == opts->index)
                p += varbuff_to_bytes(opts->script, opts->script_len, p);
            else
                *p++ = 0; /* Blank scripts for non-signing inputs */
        } else
            p += varbuff_to_bytes(input->script, input->script_len, p);

        if ((sh_none || sh_single) && i != opts->index)
            p += uint32_to_le_bytes(0, p);
        else
            p += uint32_to_le_bytes(input->sequence, p);
        if (input->features & WALLY_TX_IS_ISSUANCE) {
            if (!is_elements)
                return WALLY_EINVAL;
#ifdef BUILD_ELEMENTS
            memcpy(p, input->blinding_nonce, WALLY_TX_ASSET_TAG_LEN);
            p += WALLY_TX_ASSET_TAG_LEN;
            memcpy(p, input->entropy, WALLY_TX_ASSET_TAG_LEN);
            p += WALLY_TX_ASSET_TAG_LEN;
            p += confidential_value_to_bytes(input->issuance_amount, input->issuance_amount_len, p);
            p += confidential_value_to_bytes(input->inflation_keys, input->inflation_keys_len, p);
#endif
        }
    }

    if (sh_none)
        *p++ = 0;
    else {
        size_t num_outputs = sh_single ? opts->index + 1 : tx->num_outputs;
        p += varint_to_bytes(num_outputs, p);

        for (i = 0; i < num_outputs; ++i) {
            const struct wally_tx_output *output = tx->outputs + i;
            if (sh_single && i != opts->index) {
                memcpy(p, EMPTY_OUTPUT, sizeof(EMPTY_OUTPUT));
                p += sizeof(EMPTY_OUTPUT);
            } else {
                if (output->features & WALLY_TX_IS_ELEMENTS) {
                    if (!is_elements)
                        return WALLY_EINVAL;
#ifdef BUILD_ELEMENTS
                    p += confidential_value_to_bytes(output->asset, output->asset_len, p);
                    p += confidential_value_to_bytes(output->value, output->value_len, p);
                    p += confidential_value_to_bytes(output->nonce, output->nonce_len, p);
#endif
                } else {
                    p += uint64_to_le_bytes(output->satoshi, p);
                }
                p += varbuff_to_bytes(output->script, output->script_len, p);

#ifdef BUILD_ELEMENTS
                if (is_elements && sh_rangeproof) {
                    p += varbuff_to_bytes(output->rangeproof,
                                          output->rangeproof_len, p);
                    p += varbuff_to_bytes(output->surjectionproof,
                                          output->surjectionproof_len, p);
                }
#endif
            }
        }
    }

    if (!is_elements && (flags & WALLY_TX_FLAG_USE_WITNESS)) {
        for (i = 0; i < tx->num_inputs; ++i) {
            const struct wally_tx_input *input = tx->inputs + i;
            size_t num_items = input->witness ? input->witness->num_items : 0;
            p += varint_to_bytes(num_items, p);
            for (j = 0; j < num_items; ++j) {
                const struct wally_tx_witness_item *stack;
                stack = input->witness->items + j;
                p += varbuff_to_bytes(stack->witness, stack->witness_len, p);
            }
        }
    }

    p += uint32_to_le_bytes(tx->locktime, p);
    if (opts)
        uint32_to_le_bytes(opts->tx_sighash, p);

#ifdef BUILD_ELEMENTS
    if (is_elements && (flags & WALLY_TX_FLAG_USE_WITNESS)) {
        for (i = 0; i < tx->num_inputs; ++i) {
            const struct wally_tx_input *input = tx->inputs + i;
            size_t num_items;
            p += varbuff_to_bytes(input->issuance_amount_rangeproof, input->issuance_amount_rangeproof_len, p);
            p += varbuff_to_bytes(input->inflation_keys_rangeproof, input->inflation_keys_rangeproof_len, p);
            num_items = input->witness ? input->witness->num_items : 0;
            p += varint_to_bytes(num_items, p);
            for (j = 0; j < num_items; ++j) {
                const struct wally_tx_witness_item *stack;
                stack = input->witness->items + j;
                p += varbuff_to_bytes(stack->witness, stack->witness_len, p);
            }
            num_items = input->pegin_witness ? input->pegin_witness->num_items : 0;
            p += varint_to_bytes(num_items, p);
            for (j = 0; j < num_items; ++j) {
                const struct wally_tx_witness_item *stack;
                stack = input->pegin_witness->items + j;
                p += varbuff_to_bytes(stack->witness, stack->witness_len, p);
            }
        }
        for (i = 0; i < tx->num_outputs; ++i) {
            const struct wally_tx_output *output = tx->outputs + i;
            p += varbuff_to_bytes(output->surjectionproof, output->surjectionproof_len, p);
            p += varbuff_to_bytes(output->rangeproof, output->rangeproof_len, p);
        }
    }
#endif
    *written = n;
    return WALLY_OK;
}

int wally_tx_to_bytes(const struct wally_tx *tx, uint32_t flags,
                      unsigned char *bytes_out, size_t len,
                      size_t *written)
{
    size_t is_elements = 0;

#ifdef BUILD_ELEMENTS
    if (wally_tx_is_elements(tx, &is_elements) != WALLY_OK)
        return WALLY_EINVAL;
#endif
    return tx_to_bytes(tx, NULL, flags, bytes_out, len, written, is_elements);
}

/* Common implementation for hex conversion and txid calculation */
static int tx_to_hex_or_txid(const struct wally_tx *tx, uint32_t flags,
                             char **output,
                             unsigned char *bytes_out, size_t len,
                             bool is_elements)
{
    unsigned char buff[TX_STACK_SIZE], *buff_p = buff;
    size_t n, written;
    int ret;

    if (output)
        *output = NULL;

    if ((output && (bytes_out || len)) ||
        (!output && (!bytes_out || len != WALLY_TXHASH_LEN)))
        return WALLY_EINVAL;

    ret = tx_to_bytes(tx, NULL, flags, buff_p, sizeof(buff), &n, is_elements);
    if (ret == WALLY_OK) {
        if (n > sizeof(buff)) {
            if ((buff_p = wally_malloc(n)) == NULL)
                return WALLY_ENOMEM;
            ret = tx_to_bytes(tx, NULL, flags, buff_p, n, &written, is_elements);
            if (n != written)
                ret = WALLY_ERROR; /* Length calculated incorrectly */
        }
        if (ret == WALLY_OK) {
            if (output)
                ret = wally_hex_from_bytes(buff_p, n, output);
            else
                ret = wally_sha256d(buff_p, n, bytes_out, len);
        }
        wally_clear(buff_p, n);
        if (buff_p != buff)
            wally_free(buff_p);
    }
    return ret;
}

int wally_tx_to_hex(const struct wally_tx *tx, uint32_t flags,
                    char **output)
{
    size_t is_elements = 0;

#ifdef BUILD_ELEMENTS
    if (wally_tx_is_elements(tx, &is_elements) != WALLY_OK)
        return WALLY_EINVAL;
#endif
    return tx_to_hex_or_txid(tx, flags, output, NULL, 0, is_elements);
}

int wally_tx_get_txid(const struct wally_tx *tx, unsigned char *bytes_out, size_t len)
{
    uint32_t flags = WALLY_TX_FLAG_ALLOW_PARTIAL;
    size_t is_elements = 0;

#ifdef BUILD_ELEMENTS
    if (wally_tx_is_elements(tx, &is_elements) != WALLY_OK)
        return WALLY_EINVAL;
#endif
    if (!is_elements)
        flags |= WALLY_TX_FLAG_PRE_BIP144;
    return tx_to_hex_or_txid(tx, flags, NULL, bytes_out, len, is_elements);
}

static int analyze_tx(const unsigned char *bytes, size_t bytes_len,
                      uint32_t flags, size_t *num_inputs, size_t *num_outputs,
                      bool *expect_witnesses)
{
    const unsigned char *p = bytes, *end = bytes + bytes_len;
    uint64_t v, num_witnesses;
    size_t i, j;
    struct wally_tx tmp_tx;
    const bool is_elements = flags & WALLY_TX_FLAG_USE_ELEMENTS;

    if (num_inputs)
        *num_inputs = 0;
    if (num_outputs)
        *num_outputs = 0;
    if (expect_witnesses)
        *expect_witnesses = false;

    if (!bytes || bytes_len < sizeof(uint32_t) + 2 || (flags & ~WALLY_TX_ALL_FLAGS) ||
        !num_inputs || !num_outputs || !expect_witnesses)
        return WALLY_EINVAL;

    p += uint32_from_le_bytes(p, &tmp_tx.version);

    if (is_elements) {
        if (flags & WALLY_TX_FLAG_PRE_BIP144)
            return WALLY_EINVAL; /* No pre-BIP 144 serialisation for elements */
        *expect_witnesses = *p++ != 0;
    } else {
        if (!(flags & WALLY_TX_FLAG_PRE_BIP144) && *p == 0) {
            /* BIP 144 extended serialization */
            if (p[1] != 0x1)
                return WALLY_EINVAL; /* Invalid witness flag */
            p += 2;
            *expect_witnesses = true;
        }
    }

#define ensure_n(n) if (p > end || p + (n) > end) return WALLY_EINVAL

#define ensure_varint(dst) ensure_n(varint_length_from_bytes(p)); \
    p += varint_from_bytes(p, (dst))

#define ensure_varbuff(dst) ensure_varint((dst)); \
    ensure_n(*dst)

#define ensure_commitment(dst, explicit_siz, prefix_a, prefix_b) \
    switch (*dst) { \
    case WALLY_TX_ASSET_CT_EMPTY_PREFIX: \
        ensure_n(sizeof(uint8_t)); \
        p++; \
        break; \
    case WALLY_TX_ASSET_CT_EXPLICIT_PREFIX: \
        ensure_n(explicit_siz); \
        p += explicit_siz; \
        break; \
    case prefix_a: \
    case prefix_b: \
        ensure_n(WALLY_TX_ASSET_CT_LEN); \
        p += WALLY_TX_ASSET_CT_LEN; \
        break; \
    default: \
        return WALLY_EINVAL; \
    }

#define ensure_committed_value(dst) \
    ensure_commitment(dst, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN, WALLY_TX_ASSET_CT_VALUE_PREFIX_A, WALLY_TX_ASSET_CT_VALUE_PREFIX_B)

#define ensure_committed_asset(dst) \
    ensure_commitment(dst, WALLY_TX_ASSET_CT_ASSET_LEN, WALLY_TX_ASSET_CT_ASSET_PREFIX_A, WALLY_TX_ASSET_CT_ASSET_PREFIX_B)

#define ensure_committed_nonce(dst) \
    ensure_commitment(dst, WALLY_TX_ASSET_CT_NONCE_LEN, WALLY_TX_ASSET_CT_NONCE_PREFIX_A, WALLY_TX_ASSET_CT_NONCE_PREFIX_B)

    ensure_varint(&v);
    *num_inputs = v;

    for (i = 0; i < *num_inputs; ++i) {
        bool expect_issuance = false;
        uint32_t utxo_index;
        ensure_n(WALLY_TXHASH_LEN + sizeof(uint32_t));
        uint32_from_le_bytes(p + WALLY_TXHASH_LEN, &utxo_index);
        if (is_elements && (utxo_index & WALLY_TX_ISSUANCE_FLAG) &&
            !is_coinbase_bytes(p, WALLY_TXHASH_LEN, utxo_index))
            expect_issuance = true;
        p += WALLY_TXHASH_LEN + sizeof(uint32_t);
        ensure_varbuff(&v);
        /* FIXME: Analyze script types if required */
        p += v;
        ensure_n(sizeof(uint32_t));
        p += sizeof(uint32_t);
        if (expect_issuance) {
            ensure_n(2 * WALLY_TX_ASSET_TAG_LEN);
            p += 2 * WALLY_TX_ASSET_TAG_LEN;
            ensure_committed_value(p); /* issuance amount */
            ensure_committed_value(p); /* inflation keys */
        }
    }

    ensure_varint(&v);
    *num_outputs = v;

    for (i = 0; i < *num_outputs; ++i) {
        if (is_elements) {
            ensure_committed_asset(p);
            ensure_committed_value(p);
            ensure_committed_nonce(p);
        } else {
            ensure_n(sizeof(uint64_t));
            p += sizeof(uint64_t);
        }
        ensure_varbuff(&v);
        /* FIXME: Analyze script types if required */
        p += v;
    }

    if (*expect_witnesses && !is_elements) {
        for (i = 0; i < *num_inputs; ++i) {
            ensure_varint(&num_witnesses);
            for (j = 0; j < num_witnesses; ++j) {
                ensure_varbuff(&v);
                p += v;
            }
        }
    }

    ensure_n(sizeof(uint32_t)); /* Locktime */

    if (*expect_witnesses && is_elements) {
        p += sizeof(uint32_t);
        for (i = 0; i < *num_inputs; ++i) {
            ensure_varbuff(&v); /* issuance amount rangeproof */
            p += v;
            ensure_varbuff(&v); /* inflation keys rangeproof */
            p += v;
            ensure_varint(&num_witnesses); /* scriptWitness */
            for (j = 0; j < num_witnesses; ++j) {
                ensure_varbuff(&v);
                p += v;
            }
            ensure_varint(&num_witnesses); /* peginWitness */
            for (j = 0; j < num_witnesses; ++j) {
                ensure_varbuff(&v);
                p += v;
            }
        }

        for (i = 0; i < *num_outputs; ++i) {
            ensure_varbuff(&v); /* surjection proof */
            p += v;
            ensure_varbuff(&v); /* range proof */
            p += v;
        }
    }

#undef ensure_n
#undef ensure_varint
#undef ensure_varbuff
#undef ensure_commitment
#undef ensure_committed_value
#undef ensure_committed_asset
#undef ensure_committed_nonce
    return WALLY_OK;
}

static int witness_stack_from_bytes(const unsigned char *bytes, struct wally_tx_witness_stack **witness, uint64_t *offset)
{
    int ret = WALLY_OK;
    size_t i;
    uint64_t num_witnesses;
    const unsigned char *p = bytes;
    p += varint_from_bytes(p, &num_witnesses);
    if (num_witnesses) {
        ret = wally_tx_witness_stack_init_alloc(num_witnesses, witness);
        if (ret != WALLY_OK)
            goto cleanup;

        for (i = 0; i < num_witnesses; ++i) {
            uint64_t witness_len;
            p += varint_from_bytes(p, &witness_len);
            ret = wally_tx_witness_stack_set(*witness, i, p, witness_len);
            if (ret != WALLY_OK)
                goto cleanup;
            p += witness_len;
        }
    }

    *offset = p - bytes;

cleanup:
    return ret;
}

static int tx_from_bytes(const unsigned char *bytes, size_t bytes_len,
                         uint32_t flags, struct wally_tx **output)
{
    const unsigned char *p = bytes;
    const bool is_elements = flags & WALLY_TX_FLAG_USE_ELEMENTS;
    bool expect_witnesses;
    size_t i, j, num_inputs, num_outputs;
    uint64_t tmp, num_witnesses;
    int ret;

    OUTPUT_CHECK;

    if (analyze_tx(bytes, bytes_len, flags, &num_inputs, &num_outputs,
                   &expect_witnesses) != WALLY_OK)
        return WALLY_EINVAL;

    /* Allow pre-allocating all inputs as we have already analyzed the tx */
    ret = tx_init_alloc(0, 0, num_inputs, num_outputs,
                        num_inputs, num_outputs, output);
    if (ret != WALLY_OK)
        return ret;

    p += uint32_from_le_bytes(p, &(*output)->version);
    if (is_elements)
        p++; /* Skip witness flag */
    else if (expect_witnesses)
        p += 2; /* Skip flag bytes */
    p += varint_from_bytes(p, &tmp);

    for (i = 0; i < num_inputs; ++i) {
        const unsigned char *txhash = p, *script, *nonce = NULL, *entropy = NULL;
        const unsigned char *issuance_amount = NULL, *inflation_keys = NULL;
        uint32_t index, sequence;
        uint64_t script_len, issuance_amount_len = 0, inflation_keys_len = 0;
        p += WALLY_TXHASH_LEN;
        p += uint32_from_le_bytes(p, &index);
        p += varint_from_bytes(p, &script_len);
        script = p;
        p += script_len;
        p += uint32_from_le_bytes(p, &sequence);
        if (is_elements && !!(index & WALLY_TX_ISSUANCE_FLAG) && !is_coinbase_bytes(txhash, WALLY_TXHASH_LEN, index)) {
            nonce = p;
            p += WALLY_TX_ASSET_TAG_LEN;
            entropy = p;
            p += WALLY_TX_ASSET_TAG_LEN;
            issuance_amount = p;
            p += confidential_value_varint_from_bytes(p, &issuance_amount_len);
            inflation_keys = p;
            p += confidential_value_varint_from_bytes(p, &inflation_keys_len);
        }
        ret = tx_elements_input_init(txhash, WALLY_TXHASH_LEN, index, sequence,
                                     script_len ? script : NULL, script_len, NULL,
                                     nonce, nonce ? WALLY_TX_ASSET_TAG_LEN : 0,
                                     entropy, entropy ? WALLY_TX_ASSET_TAG_LEN : 0,
                                     issuance_amount_len ? issuance_amount : NULL, issuance_amount_len,
                                     inflation_keys_len ? inflation_keys : NULL, inflation_keys_len,
                                     NULL, 0, NULL, 0, NULL, &(*output)->inputs[i], is_elements);
        if (ret != WALLY_OK)
            goto fail;
        (*output)->num_inputs += 1;
    }

    p += varint_from_bytes(p, &tmp);
    for (i = 0; i < num_outputs; ++i) {
        const unsigned char *script, *asset = NULL, *value = NULL, *nonce = NULL;
        uint64_t satoshi = MAX_INVALID_SATOSHI, script_len, asset_len = 0, value_len = 0, nonce_len = 0;
        if (is_elements) {
            asset = p;
            p += confidential_asset_varint_from_bytes(p, &asset_len);
            value = p;
            p += confidential_value_varint_from_bytes(p, &value_len);
            nonce = p;
            p += confidential_nonce_varint_from_bytes(p, &nonce_len);
        } else
            p += uint64_from_le_bytes(p, &satoshi);
        p += varint_from_bytes(p, &script_len);
        script = p;
        p += script_len;
        ret = tx_elements_output_init(satoshi, script_len ? script : NULL, script_len,
                                      asset_len ? asset : NULL, asset_len,
                                      value_len ? value : NULL, value_len,
                                      nonce_len ? nonce : NULL, nonce_len,
                                      NULL, 0, NULL, 0,
                                      &(*output)->outputs[i], is_elements);
        if (ret != WALLY_OK)
            goto fail;
        (*output)->num_outputs += 1;
    }

    if (expect_witnesses && !is_elements) {
        for (i = 0; i < num_inputs; ++i) {
            p += varint_from_bytes(p, &num_witnesses);
            if (!num_witnesses)
                continue;
            ret = wally_tx_witness_stack_init_alloc(num_witnesses,
                                                    &(*output)->inputs[i].witness);
            if (ret != WALLY_OK)
                goto fail;

            for (j = 0; j < num_witnesses; ++j) {
                uint64_t witness_len;
                p += varint_from_bytes(p, &witness_len);
                ret = wally_tx_witness_stack_set((*output)->inputs[i].witness, j,
                                                 p, witness_len);
                if (ret != WALLY_OK)
                    goto fail;
                p += witness_len;
            }
        }
    }

    uint32_from_le_bytes(p, &(*output)->locktime);

#ifdef BUILD_ELEMENTS

#define proof_from_bytes(dst, len) \
    p += varint_from_bytes(p, (len)); \
    (dst) = p; \
    p += *(len)

    if (expect_witnesses && is_elements) {
        p += sizeof(uint32_t);
        for (i = 0; i < num_inputs; ++i) {
            const unsigned char *issuance_amount_rangeproof, *inflation_keys_rangeproof;
            uint64_t issuance_amount_rangeproof_len, inflation_keys_rangeproof_len, offset;
            proof_from_bytes(issuance_amount_rangeproof, &issuance_amount_rangeproof_len);
            proof_from_bytes(inflation_keys_rangeproof, &inflation_keys_rangeproof_len);
            ret = tx_elements_input_issuance_proof_init((*output)->inputs + i,
                                                        issuance_amount_rangeproof_len ? issuance_amount_rangeproof : NULL,
                                                        issuance_amount_rangeproof_len,
                                                        inflation_keys_rangeproof_len ? inflation_keys_rangeproof : NULL,
                                                        inflation_keys_rangeproof_len);
            if (ret != WALLY_OK)
                goto fail;
            ret = witness_stack_from_bytes(p, &(*output)->inputs[i].witness, &offset);
            if (ret != WALLY_OK)
                goto fail;
            p += offset;
            ret = witness_stack_from_bytes(p, &(*output)->inputs[i].pegin_witness, &offset);
            if (ret != WALLY_OK)
                goto fail;
            p += offset;
        }

        for (i = 0; i < num_outputs; ++i) {
            const unsigned char *surjectionproof, *rangeproof;
            uint64_t surjectionproof_len, rangeproof_len;
            proof_from_bytes(surjectionproof, &surjectionproof_len);
            proof_from_bytes(rangeproof, &rangeproof_len);
            ret = tx_elements_output_proof_init((*output)->outputs + i,
                                                surjectionproof_len ? surjectionproof : NULL,
                                                surjectionproof_len,
                                                rangeproof_len ? rangeproof : NULL,
                                                rangeproof_len);
            if (ret != WALLY_OK)
                goto fail;
        }
    }

#undef proof_from_bytes

#endif /* BUILD_ELEMENTS */
    return WALLY_OK;
fail:
    tx_free(*output, true);
    *output = NULL;
    return ret;
}

int wally_tx_from_bytes(const unsigned char *bytes, size_t bytes_len,
                        uint32_t flags, struct wally_tx **output)
{
    return tx_from_bytes(bytes, bytes_len, flags, output);
}

int wally_tx_from_hex(const char *hex, uint32_t flags,
                      struct wally_tx **output)
{
    unsigned char buff[TX_STACK_SIZE], *buff_p = buff;
    size_t hex_len = hex ? strlen(hex) : 0, bin_len;
    size_t written;
    int ret;

    if (!hex || hex_len & 0x1 || !output)
        return WALLY_EINVAL;

    bin_len = hex_len / 2;

    if (bin_len > sizeof(buff)) {
        if ((buff_p = wally_malloc(bin_len)) == NULL)
            return WALLY_ENOMEM;
    }
    ret = wally_hex_to_bytes(hex, buff_p, bin_len, &written);
    if (ret == WALLY_OK)
        ret = tx_from_bytes(buff_p, bin_len, flags, output);

    if (buff_p != buff)
        clear_and_free(buff_p, bin_len);
    else
        wally_clear(buff, bin_len);

    return ret;
}

int wally_tx_is_elements(const struct wally_tx *tx, size_t *written)
{
    if (!tx || !written)
        return WALLY_EINVAL;

    *written = is_valid_elements_tx(tx);

    return WALLY_OK;
}

int wally_tx_elements_input_is_pegin(const struct wally_tx_input *input,
                                     size_t *written)
{
    if (!input || !written)
        return WALLY_EINVAL;

    *written = is_valid_elements_tx_input_pegin(input);

    return WALLY_OK;
}

int wally_tx_is_coinbase(const struct wally_tx *tx, size_t *written)
{
    if (!tx || !written)
        return WALLY_EINVAL;

    *written = tx->num_inputs == 1 && is_valid_coinbase_input(tx->inputs);

    return WALLY_OK;
}

static int tx_get_signature_hash(const struct wally_tx *tx,
                                 size_t index,
                                 const unsigned char *script, size_t script_len,
                                 const unsigned char *extra, size_t extra_len,
                                 uint32_t extra_offset, uint64_t satoshi,
                                 const unsigned char *value,
                                 size_t value_len,
                                 uint32_t sighash, uint32_t tx_sighash, uint32_t flags,
                                 unsigned char *bytes_out, size_t len)
{
    unsigned char buff[TX_STACK_SIZE], *buff_p = buff, ext_flag = 0;
    size_t n, n2;
    size_t is_elements = 0;
    const bool is_bip143 = (flags & WALLY_TX_FLAG_USE_WITNESS) ? true : false;
    const bool is_bip341 = false;
    int ret;
    const struct tx_serialize_opts opts = {
        sighash, tx_sighash, index, script, script_len, satoshi,
        is_bip143, value, value_len, is_bip341, ext_flag, NULL, 0, NULL,
        NULL, 0, 0, 0, NULL, 0
    };

    if (!is_valid_tx(tx) || BYTES_INVALID(script, script_len) ||
        BYTES_INVALID(extra, extra_len) ||
        satoshi > WALLY_SATOSHI_MAX || (sighash & 0xffffff00) ||
        (flags & ~WALLY_TX_ALL_FLAGS) || !bytes_out || len < SHA256_LEN)
        return WALLY_EINVAL;

    if (extra || extra_len || extra_offset)
        return WALLY_ERROR; /* FIXME: Not implemented yet */

    if (index >= tx->num_inputs ||
        (index >= tx->num_outputs && (sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_SINGLE)) {
        if (!(flags & WALLY_TX_FLAG_USE_WITNESS)) {
            memset(bytes_out, 0, SHA256_LEN);
            bytes_out[0] = 0x1;
            return WALLY_OK;
        }
    }

#ifdef BUILD_ELEMENTS
    if ((ret = wally_tx_is_elements(tx, &is_elements)) != WALLY_OK)
        goto fail;
#endif

    if ((ret = tx_get_length(tx, &opts, 0, &n, is_elements != 0)) != WALLY_OK)
        goto fail;

    if (n > sizeof(buff) && (buff_p = wally_malloc(n)) == NULL) {
        ret = WALLY_ENOMEM;
        goto fail;
    }

    if ((ret = tx_to_bytes(tx, &opts, 0, buff_p, n, &n2, is_elements != 0)) != WALLY_OK)
        goto fail;

    if (n != n2)
        ret = WALLY_ERROR; /* tx_get_length/tx_to_bytes mismatch, should not happen! */
    else
        ret = wally_sha256d(buff_p, n2, bytes_out, len);

fail:
    if (buff_p != buff)
        clear_and_free(buff_p, n);
    else
        wally_clear(buff, sizeof(buff));
    return ret;
}

int wally_tx_get_signature_hash(const struct wally_tx *tx,
                                size_t index,
                                const unsigned char *script, size_t script_len,
                                const unsigned char *extra, size_t extra_len,
                                uint32_t extra_offset, uint64_t satoshi,
                                uint32_t sighash, uint32_t tx_sighash, uint32_t flags,
                                unsigned char *bytes_out, size_t len)
{
    return tx_get_signature_hash(tx, index, script, script_len,
                                 extra, extra_len, extra_offset, satoshi,
                                 NULL, 0, sighash, tx_sighash, flags, bytes_out, len);
}

int wally_tx_get_btc_signature_hash(const struct wally_tx *tx, size_t index,
                                    const unsigned char *script, size_t script_len,
                                    uint64_t satoshi, uint32_t sighash, uint32_t flags,
                                    unsigned char *bytes_out, size_t len)
{
    return wally_tx_get_signature_hash(tx, index, script, script_len,
                                       NULL, 0, 0, satoshi, sighash, sighash,
                                       flags, bytes_out, len);
}

int wally_tx_get_btc_taproot_signature_hash(
    const struct wally_tx *tx, size_t index, const struct wally_map *scripts,
    const uint64_t *values, size_t num_values,
    const unsigned char *tapleaf_script, size_t tapleaf_script_len,
    uint32_t key_version, uint32_t codesep_position,
    const unsigned char *annex, size_t annex_len,
    uint32_t sighash, uint32_t flags,
    unsigned char *bytes_out, size_t len)
{
    unsigned char buff[256]; /* Largest possible hash preimage is 244 bytes */
    const bool is_bip143 = false, is_bip341 = true;
    const struct tx_serialize_opts opts = {
        sighash, sighash, index, NULL, 0,
        values && index < num_values ? values[index] : 0,
        is_bip143, NULL, 0, is_bip341, tapleaf_script ? EXT_FLAG_BIP342 : 0,
        values, num_values, scripts, tapleaf_script, tapleaf_script_len,
        key_version, codesep_position, annex, annex_len
    };
    size_t is_elements, n, n2;
    int ret;
    (void)is_elements;

    if (!values || !num_values || index >= num_values ||
        BYTES_INVALID(tapleaf_script, tapleaf_script_len) ||
        BYTES_INVALID(annex, annex_len) || (annex && *annex != 0x50) ||
        flags || !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

#ifdef BUILD_ELEMENTS
    if (wally_tx_is_elements(tx, &is_elements) != WALLY_OK || is_elements)
        return WALLY_EINVAL;
#endif

    if ((ret = tx_get_length(tx, &opts, 0, &n, false)) != WALLY_OK)
        return ret;

    if (n > sizeof(buff))
        return WALLY_ERROR; /* Will never happen unless buff size is reduced */

    ret = tx_to_bytes(tx, &opts, 0, buff, sizeof(buff), &n2, false);
    if (ret == WALLY_OK) {
        if (n != n2)
            ret = WALLY_ERROR; /* tx_get_length/tx_to_bytes mismatch, should not happen! */
        else
            ret = wally_bip340_tagged_hash(buff, n, "TapSighash", bytes_out, len);
    }
    wally_clear(buff, n);
    return ret;
}

int wally_tx_get_elements_signature_hash(const struct wally_tx *tx,
                                         size_t index,
                                         const unsigned char *script, size_t script_len,
                                         const unsigned char *value, size_t value_len,
                                         uint32_t sighash, uint32_t flags,
                                         unsigned char *bytes_out, size_t len)
{
    return tx_get_signature_hash(tx, index, script, script_len,
                                 NULL, 0, 0, 0, value, value_len,
                                 sighash, sighash, flags, bytes_out, len);
}

int wally_tx_confidential_value_from_satoshi(uint64_t satoshi,
                                             unsigned char *bytes_out,
                                             size_t len)
{
    if (!bytes_out || len != WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN)
        return WALLY_EINVAL;

    *bytes_out = 0x1;
    uint64_to_be_bytes(satoshi, &bytes_out[1]);

    return WALLY_OK;
}

int wally_tx_confidential_value_to_satoshi(const unsigned char *value,
                                           size_t value_len,
                                           uint64_t *value_out)
{
    if (!value || value_len != WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN || !value_out || value[0] != 0x1)
        return WALLY_EINVAL;

    uint64_from_be_bytes(&value[1], value_out);

    return WALLY_OK;
}

int wally_tx_elements_issuance_generate_entropy(const unsigned char *txhash,
                                                size_t txhash_len,
                                                uint32_t index,
                                                const unsigned char *contract_hash,
                                                size_t contract_hash_len,
                                                unsigned char *bytes_out,
                                                size_t len)
{
    unsigned char buff[2 * SHA256_LEN];
    unsigned char buff_2[WALLY_TXHASH_LEN + sizeof(uint32_t)];
    int ret;

    if (!txhash || txhash_len != WALLY_TXHASH_LEN ||
        !contract_hash || contract_hash_len != SHA256_LEN ||
        !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    memcpy(buff_2, txhash, txhash_len);
    uint32_to_le_bytes(index, buff_2 + txhash_len);

    ret = wally_sha256d(buff_2, sizeof(buff_2), buff, SHA256_LEN);
    if (ret == WALLY_OK) {
        memcpy(buff + SHA256_LEN, contract_hash, contract_hash_len);
        ret = wally_sha256_midstate(buff, sizeof(buff), bytes_out, len);
    }

    wally_clear_2(buff, sizeof(buff), buff_2, sizeof(buff_2));
    return ret;
}

static int tx_elements_token_from_bytes(const unsigned char *entropy,
                                        size_t entropy_len,
                                        const unsigned char *bytes,
                                        size_t bytes_len,
                                        unsigned char *bytes_out,
                                        size_t len)
{
    unsigned char buff[2 * SHA256_LEN];
    int ret;

    if (!entropy || entropy_len != SHA256_LEN ||
        !bytes_len || bytes_len != SHA256_LEN ||
        !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    memcpy(buff, entropy, entropy_len);
    memcpy(buff + SHA256_LEN, bytes, bytes_len);

    ret = wally_sha256_midstate(buff, sizeof(buff), bytes_out, len);
    wally_clear(buff, sizeof(buff));

    return ret;
}

int wally_tx_elements_issuance_calculate_asset(const unsigned char *entropy,
                                               size_t entropy_len,
                                               unsigned char *bytes_out,
                                               size_t len)
{
    unsigned char buff[SHA256_LEN] = { 0 };
    return tx_elements_token_from_bytes(entropy, entropy_len,
                                        buff, sizeof(buff),
                                        bytes_out, len);
}

int wally_tx_elements_issuance_calculate_reissuance_token(const unsigned char *entropy,
                                                          size_t entropy_len,
                                                          uint32_t flags,
                                                          unsigned char *bytes_out,
                                                          size_t len)
{
    unsigned char buff[SHA256_LEN] = { 0 };

    if ((flags & ~WALLY_TX_FLAG_BLINDED_INITIAL_ISSUANCE))
        return WALLY_EINVAL;

    /* 32-byte '1' constant for unblinded and '2' for confidential */
    buff[0] = flags + 1;
    return tx_elements_token_from_bytes(entropy, entropy_len,
                                        buff, sizeof(buff),
                                        bytes_out, len);
}

int wally_tx_get_total_output_satoshi(const struct wally_tx *tx, uint64_t *value_out)
{
    size_t i;
    if (value_out)
        *value_out = 0;

    if (!is_valid_tx(tx) || !value_out)
        return WALLY_EINVAL;

    for (i = 0; i < tx->num_outputs; ++i) {
        uint64_t v = *value_out + tx->outputs[i].satoshi;

        if (tx->outputs[i].satoshi > WALLY_SATOSHI_MAX ||
            v < *value_out || v > WALLY_SATOSHI_MAX) {
            /* Overflow or too many satoshi in outputs */
            *value_out = 0;
            return WALLY_EINVAL;
        }
        *value_out = v;
    }

    return WALLY_OK;
}

static struct wally_tx_input *tx_get_input(const struct wally_tx *tx, size_t index)
{
    return is_valid_tx(tx) && index < tx->num_inputs ? &tx->inputs[index] : NULL;
}

#define TX_SET_B(typ, name) \
    int wally_tx_set_ ## typ ## _ ## name(const struct wally_tx *tx, size_t index, \
                                          const unsigned char *name, size_t name ## _len) { \
        return wally_tx_ ## typ ## _set_ ## name(tx_get_ ## typ(tx, index), name, name ## _len); \
    }

#if defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined (SWIG_JAVASCRIPT_BUILD) || defined(WASM_BUILD)

/* Getters for wally_tx_input/wally_tx_output/wally_tx values */

static int tx_getb_impl(const void *input,
                        const unsigned char *src, size_t src_len,
                        unsigned char *bytes_out, size_t len, size_t *written)
{
    if (written)
        *written = 0;
    if (!input || !bytes_out || len < src_len || !written)
        return WALLY_EINVAL;
    if (src_len)
        memcpy(bytes_out, src, src_len);
    *written = src_len;
    return WALLY_OK;
}

#define GET_TX_B_FIXED(typ, name, siz, n) \
    int wally_ ## typ ## _get_ ## name(const struct wally_ ## typ *input, \
                                       unsigned char *bytes_out, size_t len) { \
        size_t written; \
        if (!input || len != n) \
            return WALLY_EINVAL; \
        return tx_getb_impl(input, input->name, siz, bytes_out, len, &written); \
    }


GET_TX_B_FIXED(tx_input, txhash, WALLY_TXHASH_LEN, WALLY_TXHASH_LEN)
#ifdef BUILD_ELEMENTS
GET_TX_B_FIXED(tx_input, blinding_nonce, SHA256_LEN, SHA256_LEN)
GET_TX_B_FIXED(tx_input, entropy, SHA256_LEN, SHA256_LEN)
#endif /* BUILD_ELEMENTS */


#define GET_TX_B(typ, name, siz) \
    int wally_ ## typ ## _get_ ## name(const struct wally_ ## typ *input, \
                                       unsigned char *bytes_out, size_t len, size_t * written) { \
        if (!input) \
            return WALLY_EINVAL; \
        return tx_getb_impl(input, input->name, siz, bytes_out, len, written); \
    }

#define GET_TX_I(typ, name, outtyp) \
    int wally_ ## typ ## _get_ ## name(const struct wally_ ## typ *input, outtyp * written) { \
        if (written) *written = 0; \
        if (!input || !written) return WALLY_EINVAL; \
        *written = input->name; \
        return WALLY_OK; \
    }


GET_TX_B(tx_input, script, input->script_len)
static const struct wally_tx_witness_item *get_witness_preamble(
    const struct wally_tx_input *input, size_t index, size_t *written)
{
    if (written)
        *written = 0;
    if (!is_valid_tx_input(input) || !written ||
        !is_valid_witness_stack(input->witness) ||
        index >= input->witness->num_items)
        return NULL;
    return &input->witness->items[index];
}

int wally_tx_input_get_witness(const struct wally_tx_input *input, size_t index,
                               unsigned char *bytes_out, size_t len, size_t *written)
{
    const struct wally_tx_witness_item *item;
    if (!bytes_out || !(item = get_witness_preamble(input, index, written)) ||
        len < item->witness_len)
        return WALLY_EINVAL;
    if (item->witness_len)
        memcpy(bytes_out, item->witness, item->witness_len);
    *written = item->witness_len;
    return WALLY_OK;
}

GET_TX_I(tx_input, index, size_t)
GET_TX_I(tx_input, sequence, size_t)
GET_TX_I(tx_input, script_len, size_t)

int wally_tx_input_get_witness_len(const struct wally_tx_input *input,
                                   size_t index, size_t *written)
{
    const struct wally_tx_witness_item *item;
    if (!(item = get_witness_preamble(input, index, written)))
        return WALLY_EINVAL;
    *written = item->witness_len;
    return WALLY_OK;
}
#ifdef BUILD_ELEMENTS
GET_TX_B(tx_input, issuance_amount, input->issuance_amount_len)
GET_TX_I(tx_input, issuance_amount_len, size_t)
GET_TX_B(tx_input, inflation_keys, input->inflation_keys_len)
GET_TX_I(tx_input, inflation_keys_len, size_t)
GET_TX_B(tx_input, issuance_amount_rangeproof, input->issuance_amount_rangeproof_len)
GET_TX_I(tx_input, issuance_amount_rangeproof_len, size_t)
GET_TX_B(tx_input, inflation_keys_rangeproof, input->inflation_keys_rangeproof_len)
GET_TX_I(tx_input, inflation_keys_rangeproof_len, size_t)
#endif /* BUILD_ELEMENTS */

GET_TX_B(tx_output, script, input->script_len)
GET_TX_I(tx_output, satoshi, uint64_t)
GET_TX_I(tx_output, script_len, size_t)

#ifdef BUILD_ELEMENTS
GET_TX_B_FIXED(tx_output, asset, input->asset_len, WALLY_TX_ASSET_CT_ASSET_LEN)
GET_TX_I(tx_output, asset_len, size_t)
GET_TX_B(tx_output, value, input->value_len)
GET_TX_I(tx_output, value_len, size_t)
GET_TX_B_FIXED(tx_output, nonce, input->nonce_len, WALLY_TX_ASSET_CT_NONCE_LEN)
GET_TX_I(tx_output, nonce_len, size_t)
GET_TX_B(tx_output, surjectionproof, input->surjectionproof_len)
GET_TX_I(tx_output, surjectionproof_len, size_t)
GET_TX_B(tx_output, rangeproof, input->rangeproof_len)
GET_TX_I(tx_output, rangeproof_len, size_t)
#endif /* BUILD_ELEMENTS */

GET_TX_I(tx, version, size_t)
GET_TX_I(tx, locktime, size_t)
GET_TX_I(tx, num_inputs, size_t)
GET_TX_I(tx, num_outputs, size_t)

#ifdef BUILD_ELEMENTS
static int tx_setb_impl(const unsigned char *bytes, size_t bytes_len,
                        unsigned char **bytes_out, size_t *bytes_out_len)
{
    /* TODO: Avoid reallocation if smaller than the existing one */
    unsigned char *new_bytes = NULL;
    if (!clone_bytes(&new_bytes, bytes, bytes_len))
        return WALLY_ENOMEM;

    clear_and_free(*bytes_out, *bytes_out_len);
    *bytes_out = new_bytes;
    *bytes_out_len = bytes_len;
    return WALLY_OK;
}

#define SET_TX_B(typ, name, siz) \
    int wally_ ## typ ## _set_ ## name(struct wally_ ## typ *output, \
                                       const unsigned char *bytes, size_t siz) { \
        if (!is_valid_elements_ ## typ(output) || BYTES_INVALID(bytes, siz)) \
            return WALLY_EINVAL; \
        return tx_setb_impl(bytes, siz, &output->name, &output->name ## _len); \
    }

#define SET_TX_B_FIXED(typ, name, siz, n) \
    int wally_ ## typ ## _set_ ## name(struct wally_ ## typ *output, \
                                       const unsigned char *bytes, size_t siz) { \
        if (!is_valid_elements_ ## typ(output) || (siz && siz != n) || BYTES_INVALID(bytes, siz)) \
            return WALLY_EINVAL; \
        return tx_setb_impl(bytes, siz, &output->name, &output->name ## _len); \
    }
#endif /* BUILD_ELEMENTS */

int wally_tx_input_set_index(struct wally_tx_input *input, uint32_t index)
{
    if (!is_valid_tx_input(input))
        return WALLY_EINVAL;
    input->index = index;
    return WALLY_OK;
}

int wally_tx_input_set_sequence(struct wally_tx_input *input, uint32_t sequence)
{
    if (!is_valid_tx_input(input))
        return WALLY_EINVAL;
    input->sequence = sequence;
    return WALLY_OK;
}

int wally_tx_input_set_txhash(struct wally_tx_input *input,
                              const unsigned char *txhash, size_t txhash_len)
{
    if (!is_valid_tx_input(input) || !txhash || (txhash_len != WALLY_TXHASH_LEN))
        return WALLY_EINVAL;
    memcpy(input->txhash, txhash, txhash_len);
    return WALLY_OK;
}

int wally_tx_output_set_script(struct wally_tx_output *output,
                               const unsigned char *script, size_t script_len)
{
    if (!is_valid_tx_output(output))
        return WALLY_EINVAL;
    return replace_bytes(script, script_len, &output->script, &output->script_len);
}

int wally_tx_output_set_satoshi(struct wally_tx_output *output, uint64_t satoshi)
{
    if (!is_valid_tx_output(output) || satoshi > WALLY_SATOSHI_MAX)
        return WALLY_EINVAL;
    output->satoshi = satoshi;
    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
#define SET_TX_ARRAY(typ, name, siz) \
    int wally_ ## typ ## _set_ ## name(struct wally_ ## typ *input, \
                                       const unsigned char *name, size_t name ## _len) { \
        if (!is_valid_elements_ ## typ(input) || !name || name ## _len != siz) \
            return WALLY_EINVAL; \
        memcpy(input->name, name, siz); \
        return WALLY_OK; \
    }

SET_TX_ARRAY(tx_input, blinding_nonce, SHA256_LEN)
SET_TX_ARRAY(tx_input, entropy, SHA256_LEN)
SET_TX_B(tx_input, inflation_keys, siz)
SET_TX_B(tx_input, inflation_keys_rangeproof, siz)
SET_TX_B(tx_input, issuance_amount, siz)
SET_TX_B(tx_input, issuance_amount_rangeproof, siz)

SET_TX_B_FIXED(tx_output, asset, siz, WALLY_TX_ASSET_CT_ASSET_LEN)
int wally_tx_output_set_value(struct wally_tx_output *output, const unsigned char *value, size_t value_len)
{
    if (!is_valid_elements_tx_output(output) ||
        ((value != NULL) != (value_len == WALLY_TX_ASSET_CT_VALUE_LEN ||
                             value_len == WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN)))
        return WALLY_EINVAL;
    return tx_setb_impl(value, value_len, &output->value, &output->value_len);
}
SET_TX_B_FIXED(tx_output, nonce, siz, WALLY_TX_ASSET_CT_NONCE_LEN)
SET_TX_B(tx_output, surjectionproof, siz)
SET_TX_B(tx_output, rangeproof, siz)
#endif

static struct wally_tx_output *tx_get_output(const struct wally_tx *tx, size_t index)
{
    return is_valid_tx(tx) && index < tx->num_outputs ? &tx->outputs[index] : NULL;
}

#define TX_GET_B(typ, name) \
    int wally_tx_get_ ## typ ## _ ## name(const struct wally_tx *tx, size_t index, unsigned char *bytes_out, size_t len, size_t *written) { \
        return wally_tx_ ## typ ## _get_ ## name(tx_get_ ## typ(tx, index), bytes_out, len, written); \
    }

#define TX_GET_B_FIXED(typ, name) \
    int wally_tx_get_ ## typ ## _ ## name(const struct wally_tx *tx, size_t index, unsigned char *bytes_out, size_t len) { \
        return wally_tx_ ## typ ## _get_ ## name(tx_get_ ## typ(tx, index), bytes_out, len); \
    }

#define TX_GET_I(typ, name) \
    int wally_tx_get_ ## typ ## _ ## name(const struct wally_tx *tx, size_t index, size_t *written) { \
        return wally_tx_ ## typ ## _get_ ## name(tx_get_ ## typ(tx, index), written); \
    }

TX_GET_B(input, script)
TX_GET_I(input, script_len)
TX_GET_B_FIXED(input, txhash)
TX_GET_I(input, index)
TX_GET_I(input, sequence)

int wally_tx_get_input_witness(const struct wally_tx *tx, size_t index, size_t wit_index, unsigned char *bytes_out, size_t len, size_t *written)
{
    return wally_tx_input_get_witness(tx_get_input(tx, index), wit_index, bytes_out, len, written);
}

int wally_tx_get_input_witness_len(const struct wally_tx *tx, size_t index, size_t wit_index, size_t *written)
{
    return wally_tx_input_get_witness_len(tx_get_input(tx, index), wit_index, written);
}

#ifdef BUILD_ELEMENTS
TX_GET_B_FIXED(input, blinding_nonce)
TX_GET_B_FIXED(input, entropy)
TX_GET_B(input, inflation_keys)
TX_GET_B(input, inflation_keys_rangeproof)
TX_GET_B(input, issuance_amount)
TX_GET_B(input, issuance_amount_rangeproof)
TX_GET_I(input, inflation_keys_len)
TX_GET_I(input, inflation_keys_rangeproof_len)
TX_GET_I(input, issuance_amount_len)
TX_GET_I(input, issuance_amount_rangeproof_len)
#endif /* BUILD_ELEMENTS */
TX_GET_B(output, script)
TX_GET_I(output, script_len)

int wally_tx_get_output_satoshi(const struct wally_tx *tx, size_t index, uint64_t *value_out)
{
    return wally_tx_output_get_satoshi(tx_get_output(tx, index), value_out);
}

#ifdef BUILD_ELEMENTS
TX_GET_B_FIXED(output, asset)
TX_GET_B(output, value)
TX_GET_B_FIXED(output, nonce)
TX_GET_B(output, surjectionproof)
TX_GET_B(output, rangeproof)
TX_GET_I(output, asset_len)
TX_GET_I(output, value_len)
TX_GET_I(output, nonce_len)
TX_GET_I(output, surjectionproof_len)
TX_GET_I(output, rangeproof_len)
#endif /* BUILD_ELEMENTS */

TX_SET_B(input, txhash)

int wally_tx_set_input_index(const struct wally_tx *tx, size_t index, uint32_t index_in)
{
    return wally_tx_input_set_index(tx_get_input(tx, index), index_in);
}

int wally_tx_set_input_sequence(const struct wally_tx *tx, size_t index, uint32_t sequence)
{
    return wally_tx_input_set_sequence(tx_get_input(tx, index), sequence);
}

TX_SET_B(output, script)

int wally_tx_set_output_satoshi(const struct wally_tx *tx, size_t index, uint64_t satoshi)
{
    uint64_t current, total;

    if (wally_tx_get_output_satoshi(tx, index, &current) != WALLY_OK ||
        wally_tx_get_total_output_satoshi(tx, &total) != WALLY_OK)
        return WALLY_EINVAL;
    total -= current;
    if (total + satoshi < total || total + satoshi > WALLY_SATOSHI_MAX)
        return WALLY_EINVAL;
    return wally_tx_output_set_satoshi(tx_get_output(tx, index), satoshi);
}

#ifdef BUILD_ELEMENTS
TX_SET_B(input, blinding_nonce)
TX_SET_B(input, entropy)
TX_SET_B(input, inflation_keys)
TX_SET_B(input, inflation_keys_rangeproof)
TX_SET_B(input, issuance_amount)
TX_SET_B(input, issuance_amount_rangeproof)

TX_SET_B(output, asset)
TX_SET_B(output, value)
TX_SET_B(output, nonce)
TX_SET_B(output, surjectionproof)
TX_SET_B(output, rangeproof)
#endif
#endif /* SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD/SWIG_JAVASCRIPT_BUILD/WASM_BUILD */

int wally_tx_input_set_witness(struct wally_tx_input *input,
                               const struct wally_tx_witness_stack *stack)
{
    struct wally_tx_witness_stack *new_witness = NULL;

    if (!is_valid_tx_input(input) || (stack && !is_valid_witness_stack(stack)))
        return WALLY_EINVAL;

    if (stack &&
        wally_tx_witness_stack_clone_alloc(stack, &new_witness) != WALLY_OK)
        return WALLY_ENOMEM;

    tx_witness_stack_free(input->witness, true);
    input->witness = new_witness;
    return WALLY_OK;
}

int wally_tx_set_input_witness(const struct wally_tx *tx, size_t index,
                               const struct wally_tx_witness_stack *stack)
{
    return wally_tx_input_set_witness(tx_get_input(tx, index), stack);
}


int wally_tx_input_set_script(struct wally_tx_input *input,
                              const unsigned char *script, size_t script_len)
{
    if (!is_valid_tx_input(input))
        return WALLY_EINVAL;
    return replace_bytes(script, script_len, &input->script, &input->script_len);
}

TX_SET_B(input, script)

int wally_tx_clone_alloc(const struct wally_tx *tx, uint32_t flags, struct wally_tx **output)
{
    size_t i;
    int ret;

    OUTPUT_CHECK;

    if (!is_valid_tx(tx) || flags & ~WALLY_TX_CLONE_FLAG_NON_FINAL)
        return WALLY_EINVAL;

    ret = wally_tx_init_alloc(tx->version, tx->locktime, tx->num_inputs, tx->num_outputs, output);

    for (i = 0; ret == WALLY_OK && i < tx->num_inputs; ++i) {
        struct wally_tx_input tmp;
        memcpy(&tmp, &tx->inputs[i], sizeof(tmp));
        if (flags & WALLY_TX_CLONE_FLAG_NON_FINAL) {
            tmp.script = NULL;
            tmp.script_len = 0;
            tmp.witness = NULL;
        }
        ret = wally_tx_add_input(*output, &tmp);
    }

    for (i = 0; ret == WALLY_OK && i < tx->num_outputs; ++i)
        ret = wally_tx_add_output(*output, &tx->outputs[i]);

    if (ret != WALLY_OK) {
        wally_tx_free(*output);
        *output = NULL;
    }

    return ret;
}
#undef MAX_INVALID_SATOSHI
