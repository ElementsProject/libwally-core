#include "internal.h"

#include "ccan/ccan/base64/base64.h"
#include "ccan/ccan/build_assert/build_assert.h"

#include <include/wally_crypto.h>
#include <include/wally_script.h>
#include <include/wally_transaction.h>
#include <include/wally_psbt.h>

#include <limits.h>
#include <stdbool.h>
#include "transaction_shared.h"
#include "script_int.h"
#include "script.h"

const uint8_t WALLY_PSBT_MAGIC[5] = {'p', 's', 'b', 't', 0xff};


static bool pubkey_is_compressed(unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN]) {
    return pubkey[0] == 0x02 || pubkey[0] == 0x03;
}


int wally_keypath_map_init_alloc(size_t alloc_len, struct wally_keypath_map **output)
{
    struct wally_keypath_map *result;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_keypath_map);

    if (alloc_len) {
        result->items = wally_malloc(alloc_len * sizeof(*result->items));
        if (!result->items) {
            wally_free(result);
            *output = NULL;
            return WALLY_ENOMEM;
        }
        wally_clear(result->items, alloc_len * sizeof(*result->items));
    }
    result->items_allocation_len = alloc_len;
    result->num_items = 0;
    return WALLY_OK;
}

int wally_keypath_map_free(struct wally_keypath_map *keypaths)
{
    size_t i;

    if (keypaths) {
        for (i = 0; i < keypaths->num_items; ++i) {
            clear_and_free(keypaths->items[i].origin.path, keypaths->items[i].origin.path_len * sizeof(*keypaths->items[i].origin.path));
        }
        clear_and_free(keypaths->items, keypaths->items_allocation_len * sizeof(*keypaths->items));
        clear_and_free(keypaths, sizeof(*keypaths));
    }
    return WALLY_OK;
}

static struct wally_keypath_map *clone_keypath_map(const struct wally_keypath_map *keypaths)
{
    struct wally_keypath_map *result;
    size_t i;

    if (wally_keypath_map_init_alloc(keypaths->items_allocation_len, &result) != WALLY_OK) {
        return NULL;
    }

    for (i = 0; i < keypaths->num_items; ++i) {
        memcpy(&result->items[i].pubkey, keypaths->items[i].pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
        memcpy(&result->items[i].origin.fingerprint, keypaths->items[i].origin.fingerprint, 4);
        if (keypaths->items[i].origin.path) {
            if (!clone_bytes((unsigned char **)&result->items[i].origin.path, (unsigned char *)keypaths->items[i].origin.path, keypaths->items[i].origin.path_len * sizeof(*keypaths->items[i].origin.path))) {
                goto fail;
            }
            result->items[i].origin.path_len = keypaths->items[i].origin.path_len;
        }
    }
    result->num_items = keypaths->num_items;

    return result;

fail:
    wally_keypath_map_free(result);
    return NULL;
}

int wally_add_new_keypath(struct wally_keypath_map *keypaths,
                          unsigned char *pubkey,
                          size_t pubkey_len,
                          unsigned char *fingerprint,
                          size_t fingerprint_len,
                          uint32_t *path,
                          size_t path_len)
{
    size_t latest;

    if (fingerprint_len != FINGERPRINT_LEN || (pubkey_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN && pubkey_len != EC_PUBLIC_KEY_LEN)) {
        return WALLY_EINVAL;
    }

    if (keypaths->num_items == keypaths->items_allocation_len) {
        size_t new_alloc_len = 1;
        size_t orig_num_items = keypaths->num_items;
        if (keypaths->items_allocation_len != 0) {
            new_alloc_len = keypaths->items_allocation_len * 2;
        }
        struct wally_keypath_item *new_items = wally_malloc(new_alloc_len * sizeof(struct wally_keypath_item));
        if (!new_items) {
            return WALLY_ENOMEM;
        }
        wally_bzero(new_items, new_alloc_len * sizeof(*new_items));
        memcpy(new_items, keypaths->items, keypaths->items_allocation_len * sizeof(*keypaths->items));

        clear_and_free(keypaths->items, keypaths->items_allocation_len * sizeof(*keypaths->items));
        keypaths->items = new_items;
        keypaths->num_items = orig_num_items;
        keypaths->items_allocation_len = new_alloc_len;
    }

    latest = keypaths->num_items;

    memcpy(&keypaths->items[latest].pubkey, pubkey, pubkey_len);
    memcpy(&keypaths->items[latest].origin.fingerprint, fingerprint, fingerprint_len);
    if (path) {
        if (!clone_bytes((unsigned char **)&keypaths->items[latest].origin.path, (unsigned char *)path, path_len * sizeof(*path))) {
            return WALLY_ENOMEM;
        }
        keypaths->items[latest].origin.path_len = path_len;
    }
    keypaths->num_items++;

    return WALLY_OK;
}

static int add_keypath_item(struct wally_keypath_map *keypaths, struct wally_keypath_item *item)
{
    return wally_add_new_keypath(keypaths, item->pubkey,
                                 EC_PUBLIC_KEY_UNCOMPRESSED_LEN,
                                 item->origin.fingerprint,
                                 FINGERPRINT_LEN,
                                 item->origin.path,
                                 item->origin.path_len);
}

int wally_partial_sigs_map_init_alloc(size_t alloc_len, struct wally_partial_sigs_map **output)
{
    struct wally_partial_sigs_map *result;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_partial_sigs_map);

    if (alloc_len) {
        result->items = wally_malloc(alloc_len * sizeof(*result->items));
        if (!result->items) {
            wally_free(result);
            *output = NULL;
            return WALLY_ENOMEM;
        }
        wally_clear(result->items, alloc_len * sizeof(*result->items));
    }
    result->items_allocation_len = alloc_len;
    result->num_items = 0;
    return WALLY_OK;
}

int wally_partial_sigs_map_free(struct wally_partial_sigs_map *sigs)
{
    size_t i;

    if (sigs) {
        for (i = 0; i < sigs->num_items; ++i) {
            if (sigs->items[i].sig) {
                clear_and_free(sigs->items[i].sig, sigs->items[i].sig_len);
            }
        }
        clear_and_free(sigs->items, sigs->items_allocation_len * sizeof(*sigs->items));
        clear_and_free(sigs, sizeof(*sigs));
    }
    return WALLY_OK;
}

static struct wally_partial_sigs_map *clone_partial_sigs_map(const struct wally_partial_sigs_map *sigs)
{
    struct wally_partial_sigs_map *result;
    size_t i;

    if (wally_partial_sigs_map_init_alloc(sigs->items_allocation_len, &result) != WALLY_OK) {
        return NULL;
    }

    for (i = 0; i < sigs->num_items; ++i) {
        memcpy(&result->items[i].pubkey, sigs->items[i].pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
        if (sigs->items[i].sig) {
            if (!clone_bytes(&result->items[i].sig, sigs->items[i].sig, sigs->items[i].sig_len)) {
                goto fail;
            }
            result->items[i].sig_len = sigs->items[i].sig_len;
        }
    }
    result->num_items = sigs->num_items;
    return result;

fail:
    wally_partial_sigs_map_free(result);
    return NULL;
}

int wally_add_new_partial_sig(struct wally_partial_sigs_map *sigs,
                              unsigned char *pubkey,
                              size_t pubkey_len,
                              unsigned char *sig,
                              size_t sig_len)
{
    size_t latest;
    if (pubkey_len != EC_PUBLIC_KEY_LEN && pubkey_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN) {
        return WALLY_EINVAL;
    }

    if (sigs->num_items == sigs->items_allocation_len) {
        size_t new_alloc_len = 1;
        size_t orig_num_items = sigs->num_items;
        if (sigs->items_allocation_len != 0) {
            new_alloc_len = sigs->items_allocation_len * 2;
        }
        struct wally_partial_sigs_item *new_items = wally_malloc(new_alloc_len * sizeof(struct wally_partial_sigs_item));
        if (!new_items) {
            return WALLY_ENOMEM;
        }
        wally_bzero(new_items, new_alloc_len * sizeof(*new_items));
        memcpy(new_items, sigs->items, sigs->items_allocation_len * sizeof(*sigs->items));

        clear_and_free(sigs->items, sigs->items_allocation_len * sizeof(*sigs->items));
        sigs->items = new_items;
        sigs->num_items = orig_num_items;
        sigs->items_allocation_len = new_alloc_len;
    }

    latest = sigs->num_items;

    memcpy(&sigs->items[latest].pubkey, pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
    if (sig) {
        if (!clone_bytes(&sigs->items[latest].sig, sig, sig_len)) {
            return WALLY_ENOMEM;
        }
        sigs->items[latest].sig_len = sig_len;
    }
    sigs->num_items++;

    return WALLY_OK;
}

static int add_partial_sig_item(struct wally_partial_sigs_map *sigs, struct wally_partial_sigs_item *item)
{
    return wally_add_new_partial_sig(sigs, item->pubkey,
                                     EC_PUBLIC_KEY_UNCOMPRESSED_LEN,
                                     item->sig,
                                     item->sig_len);
}

int wally_unknowns_map_init_alloc(size_t alloc_len, struct wally_unknowns_map **output)
{
    struct wally_unknowns_map *result;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_unknowns_map);

    if (alloc_len) {
        result->items = wally_malloc(alloc_len * sizeof(*result->items));
        if (!result->items) {
            wally_free(result);
            *output = NULL;
            return WALLY_ENOMEM;
        }
        wally_clear(result->items, alloc_len * sizeof(*result->items));
    }
    result->items_allocation_len = alloc_len;
    result->num_items = 0;
    return WALLY_OK;
}

int wally_unknowns_map_free(struct wally_unknowns_map *unknowns)
{
    size_t i;

    if (unknowns) {
        for (i = 0; i < unknowns->num_items; ++i) {
            if (unknowns->items[i].key) {
                wally_clear(unknowns->items[i].key, unknowns->items[i].key_len);
            }
            if (unknowns->items[i].value) {
                wally_clear(unknowns->items[i].value, unknowns->items[i].value_len);
            }
        }
        clear_and_free(unknowns->items, unknowns->num_items * sizeof(*unknowns->items));
        clear_and_free(unknowns, sizeof(*unknowns));
    }
    return WALLY_OK;
}

static struct wally_unknowns_map *clone_unknowns_map(const struct wally_unknowns_map *unknowns)
{
    struct wally_unknowns_map *result;
    size_t i;

    if (wally_unknowns_map_init_alloc(unknowns->items_allocation_len, &result) != WALLY_OK) {
        return NULL;
    }

    for (i = 0; i < unknowns->num_items; ++i) {
        if (unknowns->items[i].key) {
            if (!clone_bytes(&result->items[i].key, unknowns->items[i].key, unknowns->items[i].key_len)) {
                goto fail;
            }
            result->items[i].key_len = unknowns->items[i].key_len;
        }
        if (unknowns->items[i].value) {
            if (!clone_bytes(&result->items[i].value, unknowns->items[i].value, unknowns->items[i].value_len)) {
                goto fail;
            }
            result->items[i].value_len = unknowns->items[i].value_len;
        }
    }
    result->num_items = unknowns->num_items;
    return result;
fail:
    wally_unknowns_map_free(result);
    return NULL;
}

int wally_add_new_unknown(struct wally_unknowns_map *unknowns,
                          unsigned char *key,
                          size_t key_len,
                          unsigned char *value,
                          size_t value_len)
{
    size_t latest;

    if (unknowns->num_items == unknowns->items_allocation_len) {
        size_t new_alloc_len = 1;
        size_t orig_num_items = unknowns->num_items;
        if (unknowns->items_allocation_len != 0) {
            new_alloc_len = unknowns->items_allocation_len * 2;
        }
        struct wally_unknowns_item *new_items = wally_malloc(new_alloc_len * sizeof(struct wally_unknowns_item));
        if (!new_items) {
            return WALLY_ENOMEM;
        }
        wally_bzero(new_items, new_alloc_len * sizeof(*new_items));
        memcpy(new_items, unknowns->items, unknowns->items_allocation_len * sizeof(*unknowns->items));

        clear_and_free(unknowns->items, unknowns->items_allocation_len * sizeof(*unknowns->items));
        unknowns->items = new_items;
        unknowns->num_items = orig_num_items;
        unknowns->items_allocation_len = new_alloc_len;
    }

    latest = unknowns->num_items;

    if (key) {
        if (!clone_bytes(&unknowns->items[latest].key, key, key_len)) {
            return WALLY_ENOMEM;
        }
        unknowns->items[latest].key_len = key_len;
    }
    if (value) {
        if (!clone_bytes(&unknowns->items[latest].value, value, value_len)) {
            return WALLY_ENOMEM;
        }
        unknowns->items[latest].value_len = value_len;
    }
    unknowns->num_items++;

    return WALLY_OK;
}

static int add_unknowns_item(struct wally_unknowns_map *unknowns, struct wally_unknowns_item *item)
{
    return wally_add_new_unknown(unknowns, item->key, item->key_len, item->value, item->value_len);
}

int wally_psbt_input_init_alloc(
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
    struct wally_psbt_input **output)
{
    struct wally_psbt_input *result;
    int ret = WALLY_OK;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_psbt_input);

    if (non_witness_utxo && (ret = wally_psbt_input_set_non_witness_utxo(result, non_witness_utxo)) != WALLY_OK) {
        goto fail;
    }
    if (witness_utxo && (ret = wally_psbt_input_set_witness_utxo(result, witness_utxo)) != WALLY_OK) {
        goto fail;
    }
    if (redeem_script && (ret = wally_psbt_input_set_redeem_script(result, redeem_script, redeem_script_len)) != WALLY_OK) {
        goto fail;
    }
    if (witness_script && (ret = wally_psbt_input_set_witness_script(result, witness_script, witness_script_len)) != WALLY_OK) {
        goto fail;
    }
    if (final_script_sig && (ret = wally_psbt_input_set_final_script_sig(result, final_script_sig, final_script_sig_len)) != WALLY_OK) {
        goto fail;
    }
    if (final_witness && (ret = wally_psbt_input_set_final_witness(result, final_witness)) != WALLY_OK) {
        goto fail;
    }
    if (keypaths && (ret = wally_psbt_input_set_keypaths(result, keypaths)) != WALLY_OK) {
        goto fail;
    }
    if (partial_sigs && (ret = wally_psbt_input_set_partial_sigs(result, partial_sigs)) != WALLY_OK) {
        goto fail;
    }
    if (unknowns && (ret = wally_psbt_input_set_unknowns(result, unknowns)) != WALLY_OK) {
        goto fail;
    }
    ret = wally_psbt_input_set_sighash_type(result, sighash_type);

    return ret;

fail:
    wally_psbt_input_free(result);
    *output = NULL;
    return ret;
}

int wally_psbt_input_set_non_witness_utxo(
    struct wally_psbt_input *input,
    struct wally_tx *non_witness_utxo)
{
    int ret = WALLY_OK;
    struct wally_tx *result_non_witness_utxo;

    if ((ret = clone_tx(non_witness_utxo, &result_non_witness_utxo)) != WALLY_OK) {
        return ret;
    }
    wally_tx_free(input->non_witness_utxo);
    input->non_witness_utxo = result_non_witness_utxo;
    return ret;
}

int wally_psbt_input_set_witness_utxo(
    struct wally_psbt_input *input,
    struct wally_tx_output *witness_utxo)
{
    int ret = WALLY_OK;
    struct wally_tx_output *result_witness_utxo;

    if ((ret = wally_tx_output_init_alloc(witness_utxo->satoshi, witness_utxo->script, witness_utxo->script_len, &result_witness_utxo)) != WALLY_OK) {
        return ret;
    }
    wally_tx_output_free(input->witness_utxo);
    input->witness_utxo = result_witness_utxo;
    return ret;
}

int wally_psbt_input_set_redeem_script(
    struct wally_psbt_input *input,
    unsigned char *redeem_script,
    size_t redeem_script_len)
{
    unsigned char *result_redeem_script;

    if (!clone_bytes(&result_redeem_script, redeem_script, redeem_script_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(input->redeem_script);
    input->redeem_script = result_redeem_script;
    input->redeem_script_len = redeem_script_len;
    return WALLY_OK;
}

int wally_psbt_input_set_witness_script(
    struct wally_psbt_input *input,
    unsigned char *witness_script,
    size_t witness_script_len)
{
    unsigned char *result_witness_script;

    if (!clone_bytes(&result_witness_script, witness_script, witness_script_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(input->witness_script);
    input->witness_script = result_witness_script;
    input->witness_script_len = witness_script_len;
    return WALLY_OK;
}

int wally_psbt_input_set_final_script_sig(
    struct wally_psbt_input *input,
    unsigned char *final_script_sig,
    size_t final_script_sig_len)
{
    unsigned char *result_final_script_sig;

    if (!clone_bytes(&result_final_script_sig, final_script_sig, final_script_sig_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(input->final_script_sig);
    input->final_script_sig = result_final_script_sig;
    input->final_script_sig_len = final_script_sig_len;
    return WALLY_OK;
}

int wally_psbt_input_set_final_witness(
    struct wally_psbt_input *input,
    struct wally_tx_witness_stack *final_witness)
{
    struct wally_tx_witness_stack *result_final_witness;

    if (!(result_final_witness = clone_witness(final_witness))) {
        return WALLY_ENOMEM;
    }
    wally_tx_witness_stack_free(input->final_witness);
    input->final_witness = result_final_witness;
    return WALLY_OK;
}

int wally_psbt_input_set_keypaths(
    struct wally_psbt_input *input,
    struct wally_keypath_map *keypaths)
{
    struct wally_keypath_map *result_keypaths;

    if (!(result_keypaths = clone_keypath_map(keypaths))) {
        return WALLY_ENOMEM;
    }
    wally_keypath_map_free(input->keypaths);
    input->keypaths = result_keypaths;
    return WALLY_OK;
}

int wally_psbt_input_set_partial_sigs(
    struct wally_psbt_input *input,
    struct wally_partial_sigs_map *partial_sigs)
{
    struct wally_partial_sigs_map *result_partial_sigs;

    if (!(result_partial_sigs = clone_partial_sigs_map(partial_sigs))) {
        return WALLY_ENOMEM;
    }
    wally_partial_sigs_map_free(input->partial_sigs);
    input->partial_sigs = result_partial_sigs;
    return WALLY_OK;
}

int wally_psbt_input_set_unknowns(
    struct wally_psbt_input *input,
    struct wally_unknowns_map *unknowns)
{
    struct wally_unknowns_map *result_unknowns;

    if (!(result_unknowns = clone_unknowns_map(unknowns))) {
        return WALLY_ENOMEM;
    }
    wally_unknowns_map_free(input->unknowns);
    input->unknowns = result_unknowns;
    return WALLY_OK;
}

int wally_psbt_input_set_sighash_type(
    struct wally_psbt_input *input,
    uint32_t sighash_type)
{
    input->sighash_type = sighash_type;
    return WALLY_OK;
}

int wally_psbt_input_free(struct wally_psbt_input *input)
{
    if (input) {
        wally_tx_free(input->non_witness_utxo);
        wally_tx_output_free(input->witness_utxo);
        clear_and_free(input->redeem_script, input->redeem_script_len);
        clear_and_free(input->witness_script, input->witness_script_len);
        clear_and_free(input->final_script_sig, input->final_script_sig_len);
        wally_tx_witness_stack_free(input->final_witness);
        wally_keypath_map_free(input->keypaths);
        wally_partial_sigs_map_free(input->partial_sigs);
        wally_unknowns_map_free(input->unknowns);
    }
    return WALLY_OK;
}

int wally_psbt_output_init_alloc(
    unsigned char *redeem_script,
    size_t redeem_script_len,
    unsigned char *witness_script,
    size_t witness_script_len,
    struct wally_keypath_map *keypaths,
    struct wally_unknowns_map *unknowns,
    struct wally_psbt_output **output)
{
    struct wally_psbt_output *result;
    int ret = WALLY_OK;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_psbt_output);

    if (redeem_script && (ret = wally_psbt_output_set_redeem_script(result, redeem_script, redeem_script_len)) != WALLY_OK) {
        goto fail;
    }
    if (witness_script && (ret = wally_psbt_output_set_witness_script(result, witness_script, witness_script_len)) != WALLY_OK) {
        goto fail;
    }
    if (keypaths && (ret = wally_psbt_output_set_keypaths(result, keypaths)) != WALLY_OK) {
        goto fail;
    }
    if (unknowns && (ret = wally_psbt_output_set_unknowns(result, unknowns)) != WALLY_OK) {
        goto fail;
    }

    return ret;

fail:
    wally_psbt_output_free(result);
    *output = NULL;
    return ret;
}

int wally_psbt_output_set_redeem_script(
    struct wally_psbt_output *output,
    unsigned char *redeem_script,
    size_t redeem_script_len)
{
    unsigned char *result_redeem_script;

    if (!clone_bytes(&result_redeem_script, redeem_script, redeem_script_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(output->redeem_script);
    output->redeem_script = result_redeem_script;
    output->redeem_script_len = redeem_script_len;
    return WALLY_OK;
}

int wally_psbt_output_set_witness_script(
    struct wally_psbt_output *output,
    unsigned char *witness_script,
    size_t witness_script_len)
{
    unsigned char *result_witness_script;

    if (!clone_bytes(&result_witness_script, witness_script, witness_script_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(output->witness_script);
    output->witness_script = result_witness_script;
    output->witness_script_len = witness_script_len;
    return WALLY_OK;
}

int wally_psbt_output_set_keypaths(
    struct wally_psbt_output *output,
    struct wally_keypath_map *keypaths)
{
    struct wally_keypath_map *result_keypaths;

    if (!(result_keypaths = clone_keypath_map(keypaths))) {
        return WALLY_ENOMEM;
    }
    wally_keypath_map_free(output->keypaths);
    output->keypaths = result_keypaths;
    return WALLY_OK;
}

int wally_psbt_output_set_unknowns(
    struct wally_psbt_output *output,
    struct wally_unknowns_map *unknowns)
{
    struct wally_unknowns_map *result_unknowns;

    if (!(result_unknowns = clone_unknowns_map(unknowns))) {
        return WALLY_ENOMEM;
    }
    wally_unknowns_map_free(output->unknowns);
    output->unknowns = result_unknowns;
    return WALLY_OK;
}

int wally_psbt_output_free(struct wally_psbt_output *output)
{
    if (output) {
        clear_and_free(output->redeem_script, output->redeem_script_len);
        clear_and_free(output->witness_script, output->witness_script_len);
        wally_keypath_map_free(output->keypaths);
        wally_unknowns_map_free(output->unknowns);
    }
    return WALLY_OK;
}

int wally_psbt_init_alloc(
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    struct wally_psbt **output)
{
    struct wally_psbt_input *new_inputs = NULL;
    struct wally_psbt_output *new_outputs = NULL;
    struct wally_psbt *result;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_psbt);

    if (inputs_allocation_len) {
        new_inputs = wally_malloc(inputs_allocation_len * sizeof(struct wally_psbt_input));
        wally_bzero(new_inputs, inputs_allocation_len * sizeof(*new_inputs));
    }
    if (outputs_allocation_len) {
        new_outputs = wally_malloc(outputs_allocation_len * sizeof(struct wally_psbt_output));
        wally_bzero(new_outputs, outputs_allocation_len * sizeof(*new_outputs));
    }
    wally_unknowns_map_init_alloc(global_unknowns_allocation_len, &result->unknowns);
    if ((inputs_allocation_len && !new_inputs) ||
        (outputs_allocation_len && !new_outputs) ||
        (global_unknowns_allocation_len && !result->unknowns)) {
        wally_free(new_inputs);
        wally_free(new_outputs);
        wally_free(result->unknowns);
        wally_free(result);
        *output = NULL;
        return WALLY_ENOMEM;
    }

    result->inputs = new_inputs;
    result->num_inputs = 0;
    result->inputs_allocation_len = inputs_allocation_len;
    result->outputs = new_outputs;
    result->num_outputs = 0;
    result->outputs_allocation_len = outputs_allocation_len;
    result->tx = NULL;
    return WALLY_OK;
}

int wally_psbt_free(struct wally_psbt *psbt)
{
    size_t i;
    if (psbt) {
        wally_tx_free(psbt->tx);
        for (i = 0; i < psbt->num_inputs; ++i) {
            wally_psbt_input_free(&psbt->inputs[i]);
        }
        wally_free(psbt->inputs);
        for (i = 0; i < psbt->num_outputs; ++i) {
            wally_psbt_output_free(&psbt->outputs[i]);
        }
        wally_free(psbt->outputs);
        wally_unknowns_map_free(psbt->unknowns);
        wally_free(psbt);
    }
    return WALLY_OK;
}

int wally_psbt_set_global_tx(
    struct wally_psbt *psbt,
    struct wally_tx *tx)
{
    size_t i;
    int ret = WALLY_OK;

    // Needs a psbt that is completely empty, i.e. no tx, no inputs, and no outputs.
    if (!tx || !psbt || psbt->tx || psbt->num_inputs != 0 || psbt->num_outputs != 0) {
        return WALLY_EINVAL;
    }

    // tx cannot have any scriptSigs or witnesses
    for (i = 0; i < tx->num_inputs; ++i) {
        if (tx->inputs[i].script || tx->inputs[i].witness) {
            return WALLY_EINVAL;
        }
    }

    if ((ret = clone_tx(tx, &psbt->tx)) != WALLY_OK) {
        goto fail;
    }

    if (psbt->inputs_allocation_len < tx->num_inputs) {
        if (psbt->inputs) {
            wally_free(psbt->inputs);
        }
        psbt->inputs_allocation_len = 0;
        psbt->inputs = wally_malloc(tx->num_inputs * sizeof(struct wally_psbt_input));
        if (!psbt->inputs) {
            ret = WALLY_ENOMEM;
            goto fail;
        }
        psbt->inputs_allocation_len = tx->num_inputs;
    }
    wally_bzero(psbt->inputs, psbt->inputs_allocation_len * sizeof(*psbt->inputs));
    psbt->num_inputs = tx->num_inputs;

    if (psbt->outputs_allocation_len < tx->num_outputs) {
        if (psbt->outputs) {
            wally_free(psbt->outputs);
        }
        psbt->outputs_allocation_len = 0;
        psbt->outputs = wally_malloc(tx->num_outputs * sizeof(struct wally_psbt_output));
        psbt->outputs_allocation_len = tx->num_outputs;
        if (!psbt->outputs) {
            ret = WALLY_ENOMEM;
            goto fail;
        }
    }
    wally_bzero(psbt->outputs, psbt->outputs_allocation_len * sizeof(*psbt->outputs));
    psbt->num_outputs = tx->num_outputs;

    return ret;

fail:
    if (psbt->tx) {
        wally_tx_free(psbt->tx);
        psbt->tx = NULL;
    }
    return ret;
}

struct psbt_input_counts {
    size_t num_unknowns;
    size_t num_keypaths;
    size_t num_partial_sigs;
};

struct psbt_output_counts {
    size_t num_unknowns;
    size_t num_keypaths;
};

struct psbt_counts {
    size_t num_global_unknowns;
    struct psbt_input_counts *input_counts;
    size_t num_inputs;
    struct psbt_output_counts *output_counts;
    size_t num_outputs;
};

static void free_psbt_count(struct psbt_counts *counts)
{
    if (counts) {
        clear_and_free(counts->input_counts, counts->num_inputs * sizeof(*counts->input_counts));
        clear_and_free(counts->output_counts, counts->num_outputs * sizeof(*counts->output_counts));
        clear_and_free(counts, sizeof(*counts));
    }
}

// Check that the bytes already read + bytes to be read < total len
#define CHECK_BUF_BOUNDS(p, i, begin, tl) if ((p - begin) + i > tl) { \
        ret = WALLY_EINVAL; \
        goto fail; \
}

static int count_psbt_parts(
    const unsigned char *bytes,
    size_t bytes_len,
    struct psbt_counts **output)
{
    struct psbt_counts *result;
    size_t i, vl;
    const unsigned char *key;
    uint64_t key_len, value_len;
    uint8_t type;
    int ret = WALLY_OK;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct psbt_counts);

    const unsigned char *p = bytes, *end = bytes + bytes_len;

    result->num_global_unknowns = 0;
    result->num_inputs = 0;
    result->num_outputs = 0;

    // Skip the magic
    CHECK_BUF_BOUNDS(p, (size_t)5, bytes, bytes_len)
    p += 5;

    // Go through globals and count
    while (p < end) {
        // Read the key length
        vl = varint_from_bytes(p, &key_len);
        CHECK_BUF_BOUNDS(p, key_len + vl, bytes, bytes_len)
        p += vl;

        if (key_len == 0) {
            break;
        }

        // Read the key itself
        key = p;
        type = key[0];
        p += key_len;

        // Read value length
        vl = varint_from_bytes(p, &value_len);
        CHECK_BUF_BOUNDS(p, value_len + vl, bytes, bytes_len)
        p += vl;

        // Process based on type
        switch (type) {
        case WALLY_PSBT_GLOBAL_UNSIGNED_TX: {
            bool expect_wit;
            if (analyze_tx(p, value_len, 0, &result->num_inputs, &result->num_outputs, &expect_wit) != WALLY_OK) {
                ret = WALLY_EINVAL;
                goto fail;
            }
            if ((result->input_counts = wally_malloc(result->num_inputs * sizeof(struct psbt_input_counts))) == NULL ||
                (result->output_counts = wally_malloc(result->num_outputs * sizeof(struct psbt_output_counts))) == NULL) {
                ret = WALLY_ENOMEM;
                goto fail;
            }
            break;
        }
        // Unknowns
        default:
            result->num_global_unknowns++;
        }

        // Increment past value length
        p += value_len;
    }

    // Go through each input
    for (i = 0; i < result->num_inputs && p < end; ++i) {
        struct psbt_input_counts *input = &result->input_counts[i];
        input->num_keypaths = 0;
        input->num_partial_sigs = 0;
        input->num_unknowns = 0;
        while (p < end) {
            // Read the key length
            vl = varint_from_bytes(p, &key_len);
            CHECK_BUF_BOUNDS(p, key_len + vl, bytes, bytes_len)
            p += vl;

            if (key_len == 0) {
                break;
            }

            // Read the key itself
            key = p;
            type = key[0];
            p += key_len;

            // Read value length
            vl = varint_from_bytes(p, &value_len);
            CHECK_BUF_BOUNDS(p, value_len + vl, bytes, bytes_len)
            p += vl;

            // Process based on type
            switch (type) {
            case WALLY_PSBT_IN_NON_WITNESS_UTXO:
            case WALLY_PSBT_IN_WITNESS_UTXO:
            case WALLY_PSBT_IN_SIGHASH_TYPE:
            case WALLY_PSBT_IN_REDEEM_SCRIPT:
            case WALLY_PSBT_IN_WITNESS_SCRIPT:
            case WALLY_PSBT_IN_FINAL_SCRIPTSIG:
            case WALLY_PSBT_IN_FINAL_SCRIPTWITNESS:
                break;
            case WALLY_PSBT_IN_PARTIAL_SIG:
                input->num_partial_sigs++;
                break;
            case WALLY_PSBT_IN_BIP32_DERIVATION:
                input->num_keypaths++;
                break;
            // Unknowns
            default:
                input->num_unknowns++;
            }

            // Increment past value length
            p += value_len;
        }
    }

    // Go through each output
    for (i = 0; i < result->num_outputs && p < end; ++i) {
        struct psbt_output_counts *psbt_output = &result->output_counts[i];
        psbt_output->num_keypaths = 0;
        psbt_output->num_unknowns = 0;
        while (p < end) {
            // Read the key length
            vl = varint_from_bytes(p, &key_len);
            CHECK_BUF_BOUNDS(p, key_len + vl, bytes, bytes_len)
            p += vl;

            if (key_len == 0) {
                break;
            }

            // Read the key itself
            key = p;
            type = key[0];
            p += key_len;

            // Read value length
            vl = varint_from_bytes(p, &value_len);
            CHECK_BUF_BOUNDS(p, value_len + vl, bytes, bytes_len)
            p += vl;

            // Process based on type
            switch (type) {
            case WALLY_PSBT_OUT_REDEEM_SCRIPT:
            case WALLY_PSBT_OUT_WITNESS_SCRIPT:
                break;
            case WALLY_PSBT_OUT_BIP32_DERIVATION:
                psbt_output->num_keypaths++;
                break;
            // Unknowns
            default:
                psbt_output->num_unknowns++;
            }

            // Increment past value length
            p += value_len;
        }
    }

    if (p != end) {
        ret = WALLY_EINVAL;
        goto fail;
    }

    return WALLY_OK;

fail:
    free_psbt_count(result);
    *output = NULL;
    return ret;
}

static int psbt_input_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    struct psbt_input_counts counts,
    size_t *bytes_read,
    struct wally_psbt_input *result)
{
    const unsigned char *p = bytes, *end = bytes + bytes_len, *key, *value;
    uint64_t key_len, value_len;
    uint8_t type;
    int ret = WALLY_OK;
    size_t i, vl;
    bool found_sep = false;

    // Init and alloc the maps
    if (counts.num_keypaths > 0) {
        if ((ret = wally_keypath_map_init_alloc(counts.num_keypaths, &result->keypaths)) != WALLY_OK) {
            return ret;
        }
    }
    if (counts.num_partial_sigs > 0) {
        if ((ret = wally_partial_sigs_map_init_alloc(counts.num_partial_sigs, &result->partial_sigs)) != WALLY_OK) {
            return ret;
        }
    }
    if (counts.num_unknowns > 0) {
        if ((ret = wally_unknowns_map_init_alloc(counts.num_unknowns, &result->unknowns)) != WALLY_OK) {
            return ret;
        }
    }

    // Read key value pairs
    while (p < end) {
        // Read the key length
        vl = varint_from_bytes(p, &key_len);
        CHECK_BUF_BOUNDS(p, key_len + vl, bytes, bytes_len)
        p += vl;

        if (key_len == 0) {
            found_sep = true;
            break;
        }

        // Read the key itself
        key = p;
        type = key[0];
        p += key_len;

        // Pre-read the value length but don't increment for a sanity check
        vl = varint_from_bytes(p, &value_len);
        CHECK_BUF_BOUNDS(p, value_len + vl, bytes, bytes_len)

        // Process based on type
        switch (type) {
        case WALLY_PSBT_IN_NON_WITNESS_UTXO: {
            if (result->non_witness_utxo) {
                return WALLY_EINVAL;     // We already have a non witness utxo
            } else if (key_len != 1) {
                return WALLY_EINVAL;     // Global tx key is one byte type
            }
            p += varint_from_bytes(p, &value_len);
            value = p;
            wally_tx_from_bytes(value, value_len, 0, &result->non_witness_utxo);
            p += value_len;
            break;
        }
        case WALLY_PSBT_IN_WITNESS_UTXO: {
            uint64_t amount = -1, script_len;
            size_t script_len_len;
            if (result->witness_utxo) {
                return WALLY_EINVAL;     // We already have a witness utxo
            } else if (key_len != 1) {
                return WALLY_EINVAL;     // Global tx key is one byte type
            }
            p += varint_from_bytes(p, &value_len);
            p += uint64_from_le_bytes(p, &amount);
            script_len_len = varint_from_bytes(p, &script_len);
            p += script_len_len;
            ret = wally_tx_output_init_alloc(amount, p, script_len, &result->witness_utxo);
            if (ret != WALLY_OK) {
                return ret;
            }
            p += script_len;
            // amount length (8 bytes) + script CSUint + script length = value length
            if (8 + script_len_len + script_len != value_len) {
                return WALLY_EINVAL;
            }
            break;
        }
        case WALLY_PSBT_IN_PARTIAL_SIG: {
            struct wally_partial_sigs_map *partial_sigs = result->partial_sigs;
            if (key_len != 66 && key_len != 34) {
                return WALLY_EINVAL;     // Size of key is unexpected
            }
            // Check for duplicates
            for (i = 0; i < partial_sigs->num_items; ++i) {
                if (memcmp(partial_sigs->items[i].pubkey, &key[1], key_len - 1) == 0) {
                    return WALLY_EINVAL;     // Duplicate key
                }
            }

            memcpy(partial_sigs->items[partial_sigs->num_items].pubkey, &key[1], key_len - 1);

            // Read the signature
            p += varint_from_bytes(p, &value_len);
            clone_bytes(&partial_sigs->items[partial_sigs->num_items].sig, p, value_len);
            partial_sigs->items[partial_sigs->num_items].sig_len = value_len;

            partial_sigs->num_items++;
            p += value_len;
            break;
        }
        case WALLY_PSBT_IN_SIGHASH_TYPE: {
            if (result->sighash_type > 0) {
                return WALLY_EINVAL;     // Sighash already provided
            } else if (key_len != 1) {
                return WALLY_EINVAL;     // Type is more than one byte
            }
            p += varint_from_bytes(p, &value_len);
            p += uint32_from_le_bytes(p, &result->sighash_type);
            break;
        }
        case WALLY_PSBT_IN_REDEEM_SCRIPT: {
            if (result->redeem_script_len != 0) {
                return WALLY_EINVAL;     // Already have a redeem script
            } else if (key_len != 1) {
                return WALLY_EINVAL;     // Type is more than one byte
            }
            p += varint_from_bytes(p, &value_len);
            clone_bytes(&result->redeem_script, p, value_len);
            result->redeem_script_len = value_len;

            p += value_len;
            break;
        }
        case WALLY_PSBT_IN_WITNESS_SCRIPT: {
            if (result->witness_script_len != 0) {
                return WALLY_EINVAL;     // Already have a witness script
            } else if (key_len != 1) {
                return WALLY_EINVAL;     // Type is more than one byte
            }
            p += varint_from_bytes(p, &value_len);
            clone_bytes(&result->witness_script, p, value_len);
            result->witness_script_len = value_len;

            p += value_len;
            break;
        }
        case WALLY_PSBT_IN_BIP32_DERIVATION: {
            struct wally_keypath_map *keypaths = result->keypaths;
            size_t path_len;
            if (key_len != 66 && key_len != 34) {
                return WALLY_EINVAL;     // Size of key is unexpected
            }
            // Check for duplicates
            for (i = 0; i < keypaths->num_items; ++i) {
                if (memcmp(keypaths->items[i].pubkey, &key[1], key_len - 1) == 0) {
                    return WALLY_EINVAL;     // Duplicate key
                }
            }

            memcpy(keypaths->items[keypaths->num_items].pubkey, &key[1], key_len - 1);

            // Read the path length
            p += varint_from_bytes(p, &value_len);
            if (value_len % 4 != 0 || value_len == 0) {
                return WALLY_EINVAL;     // Invalid length for keypaths
            }
            path_len = (value_len / 4) - 1;

            // Read the fingerprint
            memcpy(keypaths->items[keypaths->num_items].origin.fingerprint, p, 4);
            p += 4;

            // Read the path itself
            keypaths->items[keypaths->num_items].origin.path = wally_malloc(path_len * sizeof(uint32_t));
            for (i = 0; i < path_len; ++i) {
                p += uint32_from_le_bytes(p, &keypaths->items[keypaths->num_items].origin.path[i]);
            }
            keypaths->items[keypaths->num_items].origin.path_len = path_len;

            keypaths->num_items++;
            break;
        }
        case WALLY_PSBT_IN_FINAL_SCRIPTSIG: {
            if (result->final_script_sig_len != 0) {
                return WALLY_EINVAL;     // Already have a scriptSig
            } else if (key_len != 1) {
                return WALLY_EINVAL;     // Type is more than one byte
            }
            p += varint_from_bytes(p, &value_len);
            clone_bytes(&result->final_script_sig, p, value_len);
            result->final_script_sig_len = value_len;

            p += value_len;
            break;
        }
        case WALLY_PSBT_IN_FINAL_SCRIPTWITNESS: {
            uint64_t num_witnesses;
            if (result->final_witness) {
                return WALLY_EINVAL;     // Already have a scriptWitness
            } else if (key_len != 1) {
                return WALLY_EINVAL;     // Type is more than one byte
            }
            p += varint_from_bytes(p, &value_len);
            p += varint_from_bytes(p, &num_witnesses);
            ret = wally_tx_witness_stack_init_alloc(num_witnesses, &result->final_witness);
            if (ret != WALLY_OK) {
                return ret;
            }

            for (i = 0; i < num_witnesses; ++i) {
                uint64_t witness_len;
                p += varint_from_bytes(p, &witness_len);
                ret = wally_tx_witness_stack_set(result->final_witness, i, p, witness_len);
                if (ret != WALLY_OK)
                    return ret;
                p += witness_len;
            }
            break;
        }
        // Unknowns
        default: {
            struct wally_unknowns_map *unknowns = result->unknowns;
            clone_bytes(&unknowns->items[unknowns->num_items].key, key, key_len);
            unknowns->items[unknowns->num_items].key_len = key_len;

            p += varint_from_bytes(p, &value_len);
            value = p;
            clone_bytes(&unknowns->items[unknowns->num_items].value, value, value_len);
            unknowns->items[unknowns->num_items].value_len = value_len;

            unknowns->num_items++;
            p += value_len;
            break;
        }
        }
    }

    if (!found_sep) {
        return WALLY_EINVAL;
    }

    *bytes_read = p - bytes;
fail:
    return ret;
}

static int psbt_output_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    struct psbt_output_counts counts,
    size_t *bytes_read,
    struct wally_psbt_output *result)
{
    const unsigned char *p = bytes, *end = bytes + bytes_len, *key, *value;
    uint64_t key_len, value_len;
    uint8_t type;
    size_t i, vl;
    bool found_sep = false;
    int ret = WALLY_OK;

    // Init and alloc the maps
    if (counts.num_keypaths > 0) {
        wally_keypath_map_init_alloc(counts.num_keypaths, &result->keypaths);
    }
    if (counts.num_unknowns > 0) {
        wally_unknowns_map_init_alloc(counts.num_unknowns, &result->unknowns);
    }

    // Read key value pairs
    while (p < end) {
        // Read the key length
        vl = varint_from_bytes(p, &key_len);
        CHECK_BUF_BOUNDS(p, key_len + vl, bytes, bytes_len)
        p += vl;

        if (key_len == 0) {
            found_sep = true;
            break;
        }

        // Read the key itself
        key = p;
        type = key[0];
        p += key_len;

        // Pre-read the value length but don't increment for a sanity check
        vl = varint_from_bytes(p, &value_len);
        CHECK_BUF_BOUNDS(p, value_len + vl, bytes, bytes_len)

        // Process based on type
        switch (type) {
        case WALLY_PSBT_OUT_REDEEM_SCRIPT: {
            if (result->redeem_script_len != 0) {
                return WALLY_EINVAL;     // Already have a redeem script
            } else if (key_len != 1) {
                return WALLY_EINVAL;     // Type is more than one byte
            }
            p += varint_from_bytes(p, &value_len);
            clone_bytes(&result->redeem_script, p, value_len);
            result->redeem_script_len = value_len;

            p += value_len;
            break;
        }
        case WALLY_PSBT_OUT_WITNESS_SCRIPT: {
            if (result->witness_script_len != 0) {
                return WALLY_EINVAL;     // Already have a witness script
            } else if (key_len != 1) {
                return WALLY_EINVAL;     // Type is more than one byte
            }
            p += varint_from_bytes(p, &value_len);
            clone_bytes(&result->witness_script, p, value_len);
            result->witness_script_len = value_len;

            p += value_len;
            break;
        }
        case WALLY_PSBT_OUT_BIP32_DERIVATION: {
            struct wally_keypath_map *keypaths = result->keypaths;
            size_t path_len;
            if (key_len != 66 && key_len != 34) {
                return WALLY_EINVAL;     // Size of key is unexpected
            }
            // Check for duplicates
            for (i = 0; i < keypaths->num_items; ++i) {
                if (memcmp(keypaths->items[i].pubkey, &key[1], key_len - 1) == 0) {
                    return WALLY_EINVAL;     // Duplicate key
                }
            }

            memcpy(keypaths->items[keypaths->num_items].pubkey, &key[1], key_len - 1);

            // Read the path length
            p += varint_from_bytes(p, &value_len);
            if (value_len % 4 != 0 || value_len == 0) {
                return WALLY_EINVAL;     // Invalid length for keypaths
            }
            path_len = (value_len / 4) - 1;

            // Read the fingerprint
            memcpy(keypaths->items[keypaths->num_items].origin.fingerprint, p, 4);
            p += 4;

            // Read the path itself
            keypaths->items[keypaths->num_items].origin.path = wally_malloc(path_len * sizeof(uint32_t));
            for (i = 0; i < path_len; ++i) {
                p += uint32_from_le_bytes(p, &keypaths->items[keypaths->num_items].origin.path[i]);
            }
            keypaths->items[keypaths->num_items].origin.path_len = path_len;

            keypaths->num_items++;
            break;
        }
        // Unknowns
        default: {
            struct wally_unknowns_map *unknowns = result->unknowns;
            clone_bytes(&unknowns->items[unknowns->num_items].key, key, key_len);
            unknowns->items[unknowns->num_items].key_len = key_len;

            p += varint_from_bytes(p, &value_len);
            value = p;
            clone_bytes(&unknowns->items[unknowns->num_items].value, value, value_len);
            unknowns->items[unknowns->num_items].value_len = value_len;

            unknowns->num_items++;
            p += value_len;
            break;
        }
        }
    }

    if (!found_sep) {
        return WALLY_EINVAL;
    }

    *bytes_read = p - bytes;
fail:
    return ret;
}

int wally_psbt_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_psbt **output)
{
    const unsigned char *p = bytes, *end = bytes + bytes_len, *key, *value;
    uint64_t key_len, value_len;
    uint8_t type;
    size_t i, vl;
    int ret = WALLY_OK;
    struct psbt_counts *counts = NULL;
    struct wally_psbt *result = NULL;

    TX_CHECK_OUTPUT;

    // Check the magic
    if (bytes_len <= 5) {
        ret = WALLY_EINVAL;  // Not enough bytes
        goto fail;
    }
    if (memcmp(p, WALLY_PSBT_MAGIC, 5) != 0 ) {
        ret = WALLY_EINVAL;  // Invalid Magic
        goto fail;
    }
    p += 5;

    // Get a count of the psbt parts
    if (count_psbt_parts(bytes, bytes_len, &counts) != WALLY_OK) {
        ret = WALLY_EINVAL;
        goto fail;
    }

    // Make the wally_psbt
    ret = wally_psbt_init_alloc(counts->num_inputs, counts->num_outputs, counts->num_global_unknowns, &result);
    if (ret != WALLY_OK) {
        goto fail;
    }
    *output = result;

    // Read globals first
    bool found_sep = false;
    while (p < end) {
        // Read the key length
        vl = varint_from_bytes(p, &key_len);
        CHECK_BUF_BOUNDS(p, key_len + vl, bytes, bytes_len)
        p += vl;

        if (key_len == 0) {
            found_sep = true;
            break;
        }

        // Read the key itself
        key = p;
        type = key[0];
        p += key_len;

        // Pre-read the value length but don't increment for a sanity check
        vl = varint_from_bytes(p, &value_len);
        CHECK_BUF_BOUNDS(p, value_len + vl, bytes, bytes_len)

        // Process based on type
        switch (type) {
        case WALLY_PSBT_GLOBAL_UNSIGNED_TX: {
            size_t j;
            if (result->tx) {
                ret = WALLY_EINVAL;     // We already have a global tx
                goto fail;
            } else if (key_len != 1) {
                ret = WALLY_EINVAL;     // Global tx key is one byte type
                goto fail;
            }
            p += varint_from_bytes(p, &value_len);
            value = p;
            if ((ret = wally_tx_from_bytes(value, value_len, 0, &result->tx)) != WALLY_OK) {
                goto fail;
            }
            p += value_len;
            // Make sure there are no scriptSigs and scriptWitnesses
            for (j = 0; j < result->tx->num_inputs; ++j) {
                if (result->tx->inputs[j].script_len != 0 || (result->tx->inputs[j].witness && result->tx->inputs[j].witness->num_items != 0)) {
                    ret = WALLY_EINVAL;     // Unsigned tx needs empty scriptSigs and scriptWtinesses
                    goto fail;
                }
            }
            break;
        }
        // Unknowns
        default: {
            struct wally_unknowns_map *unknowns = result->unknowns;
            clone_bytes(&unknowns->items[unknowns->num_items].key, key, key_len);
            unknowns->items[unknowns->num_items].key_len = key_len;

            p += varint_from_bytes(p, &value_len);
            value = p;
            clone_bytes(&unknowns->items[unknowns->num_items].value, value, value_len);
            unknowns->items[unknowns->num_items].value_len = value_len;

            unknowns->num_items++;
            p += value_len;
            break;
        }
        }
    }

    if (!found_sep) {
        ret = WALLY_EINVAL; // Missing global separator
        goto fail;
    }

    if (!result->tx) {
        ret = WALLY_EINVAL; // No global tx
        goto fail;
    }

    // Read inputs
    for (i = 0; i < counts->num_inputs && p < end; ++i) {
        size_t bytes_read;

        ret = psbt_input_from_bytes(p, end - p, counts->input_counts[i], &bytes_read, &result->inputs[i]);
        if (ret != WALLY_OK) {
            goto fail;
        }
        p += bytes_read;
        result->num_inputs++;
    }

    // Make sure that the number of inputs matches the number of inputs in the transaction
    if (result->num_inputs != result->tx->num_inputs) {
        ret = WALLY_EINVAL;
        goto fail;
    }

    // Read outputs
    for (i = 0; i < counts->num_outputs && p < end; ++i) {
        size_t bytes_read;

        ret = psbt_output_from_bytes(p, end - p, counts->output_counts[i], &bytes_read, &result->outputs[i]);
        if (ret != WALLY_OK) {
            goto fail;
        }
        p += bytes_read;
        result->num_outputs++;
    }

    // Make sure that the number of outputs matches the number ot outputs in the transaction
    if (result->num_outputs != result->tx->num_outputs) {
        ret = WALLY_EINVAL;
        goto fail;
    }

    free_psbt_count(counts);
    return WALLY_OK;

fail:
    free_psbt_count(counts);
    wally_psbt_free(result);
    *output = NULL;
    return ret;
}

static int psbt_input_get_length(
    const struct wally_psbt_input *input,
    size_t *len)
{
    int ret;
    size_t out, tx_len, i;
    if (!len) {
        return WALLY_EINVAL;
    }

    *len = 0;
    out = 0;

    // Non witness utxo
    if (input->non_witness_utxo) {
        out += 2; // Key len and one byte type
        ret = wally_tx_get_length(input->non_witness_utxo, WALLY_TX_FLAG_USE_WITNESS, &tx_len);
        if (ret != WALLY_OK) {
            return ret;
        }
        out += varbuff_get_length(tx_len);
    }
    // Witness utxo
    if (input->witness_utxo) {
        size_t wit_size = 0;
        out += 2; // Key len and one byte type
        wit_size += sizeof(input->witness_utxo->satoshi);
        wit_size += varbuff_get_length(input->witness_utxo->script_len);
        out += varbuff_get_length(wit_size);
    }
    // Partial sigs
    if (input->partial_sigs) {
        struct wally_partial_sigs_map *partial_sigs = input->partial_sigs;
        for (i = 0; i < partial_sigs->num_items; ++i) {
            struct wally_partial_sigs_item *item = &partial_sigs->items[i];
            if (pubkey_is_compressed(item->pubkey)) {
                out += varint_get_length(34);
                out += 34; // Compressed pubkey + 1 byte type
            } else {
                out += varint_get_length(66);
                out += 66; // Uncompressed pubkey + 1 byte type
            }
            out += varbuff_get_length(item->sig_len);
        }
    }
    // Sighash type
    if (input->sighash_type > 0) {
        out += 2; // Key len and one byte type
        out += varbuff_get_length(sizeof(input->sighash_type));
    }
    // Redeem script
    if (input->redeem_script) {
        out += 2; // Key len and one byte type
        out += varbuff_get_length(input->redeem_script_len);
    }
    // Witness script
    if (input->witness_script) {
        out += 2; // Key len and one byte type
        out += varbuff_get_length(input->witness_script_len);
    }
    // Keypaths
    if (input->keypaths) {
        struct wally_keypath_map *keypaths = input->keypaths;
        for (i = 0; i < keypaths->num_items; ++i) {
            size_t origin_len;
            struct wally_keypath_item *item = &keypaths->items[i];
            if (pubkey_is_compressed(item->pubkey)) {
                out += varint_get_length(34);
                out += 34; // Compressed pubkey + 1 byte type
            } else {
                out += varint_get_length(66);
                out += 66; // Uncompressed pubkey + 1 byte type
            }

            origin_len = 4; // Start with 4 bytes for fingerprint
            origin_len += item->origin.path_len * sizeof(uint32_t);
            out += varint_get_length(origin_len);
            out += origin_len;
        }
    }
    // Final scriptSig
    if (input->final_script_sig) {
        out += 2; // Key len and one byte type
        out += varbuff_get_length(input->final_script_sig_len);
    }
    // Final scriptWitness
    if (input->final_witness) {
        out += 2; // Key len and one byte type
        struct wally_tx_witness_stack *witness = input->final_witness;
        size_t wit_len = varint_get_length(witness->num_items);
        out += varint_get_length(witness->num_items);
        for (i = 0; i < witness->num_items; ++i) {
            out += varbuff_get_length(witness->items[i].witness_len);
            wit_len += varbuff_get_length(witness->items[i].witness_len);
        }
        out += varint_get_length(wit_len);
    }
    // Unknowns
    if (input->unknowns) {
        for (i = 0; i < input->unknowns->num_items; ++i) {
            struct wally_unknowns_item *unknown = &input->unknowns->items[i];
            out += varbuff_get_length(unknown->key_len);
            out += varbuff_get_length(unknown->value_len);
        }
    }

    // Separator
    out += 1;

    *len = out;
    return WALLY_OK;
}

static int psbt_output_get_length(
    const struct wally_psbt_output *output,
    size_t *len)
{
    size_t out, i;
    if (!len) {
        return WALLY_EINVAL;
    }

    *len = 0;
    out = 0;

    // Redeem script
    if (output->redeem_script) {
        out += 2; // Key len and one byte type
        out += varbuff_get_length(output->redeem_script_len);
    }
    // Witness script
    if (output->witness_script) {
        out += 2; // Key len and one byte type
        out += varbuff_get_length(output->witness_script_len);
    }
    // Keypaths
    if (output->keypaths) {
        struct wally_keypath_map *keypaths = output->keypaths;
        for (i = 0; i < keypaths->num_items; ++i) {
            size_t origin_len;
            struct wally_keypath_item *item = &keypaths->items[i];
            if (pubkey_is_compressed(item->pubkey)) {
                out += varint_get_length(34);
                out += 34; // Compressed pubkey + 1 byte type
            } else {
                out += varint_get_length(66);
                out += 66; // Uncompressed pubkey + 1 byte type
            }

            origin_len = 4; // Start with 4 bytes for fingerprint
            origin_len += item->origin.path_len * sizeof(uint32_t);
            out += varint_get_length(origin_len);
            out += origin_len;
        }
    }
    // Unknowns
    if (output->unknowns) {
        for (i = 0; i < output->unknowns->num_items; ++i) {
            struct wally_unknowns_item *unknown = &output->unknowns->items[i];
            out += varbuff_get_length(unknown->key_len);
            out += varbuff_get_length(unknown->value_len);
        }
    }

    // Separator
    out += 1;

    *len = out;
    return WALLY_OK;
}

int wally_psbt_get_length(
    const struct wally_psbt *psbt,
    size_t *len)
{
    int ret;
    size_t out, tx_len, i;
    if (!len) {
        return WALLY_EINVAL;
    }

    *len = 0;
    out = 5; // Start with 5 byte magic

    // Global tx
    out += 2;
    ret = wally_tx_get_length(psbt->tx, 0, &tx_len);
    if (ret != WALLY_OK) {
        return ret;
    }
    out += varbuff_get_length(tx_len);

    // Global unknowns
    if (psbt->unknowns) {
        for (i = 0; i < psbt->unknowns->num_items; ++i) {
            struct wally_unknowns_item *unknown = &psbt->unknowns->items[i];
            out += varbuff_get_length(unknown->key_len);
            out += varbuff_get_length(unknown->value_len);
        }
    }

    // Separator
    out += 1;

    // Get lengths of each input and output
    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        size_t input_len;
        psbt_input_get_length(input, &input_len);
        out += input_len;
    }
    for (i = 0; i < psbt->num_outputs; ++i) {
        struct wally_psbt_output *output = &psbt->outputs[i];
        size_t output_len;
        psbt_output_get_length(output, &output_len);
        out += output_len;
    }

    *len = out;
    return WALLY_OK;
}

static int psbt_input_to_bytes(
    const struct wally_psbt_input *input,
    unsigned char *bytes_out, size_t len,
    size_t *bytes_written)
{
    unsigned char type, *p = bytes_out, *end = bytes_out + len;
    int ret;
    size_t i, tx_len;

    // Non witness utxo
    if (input->non_witness_utxo) {
        type = WALLY_PSBT_IN_NON_WITNESS_UTXO;
        p += varbuff_to_bytes(&type, 1, p);
        ret = wally_tx_get_length(input->non_witness_utxo, WALLY_TX_FLAG_USE_WITNESS, &tx_len);
        if (ret != WALLY_OK) {
            return ret;
        }
        p += varint_to_bytes(tx_len, p);
        ret = wally_tx_to_bytes(input->non_witness_utxo, WALLY_TX_FLAG_USE_WITNESS, p, end - p, &tx_len);
        if (ret != WALLY_OK) {
            return ret;
        }
        p += tx_len;
    }
    // Witness utxo
    if (input->witness_utxo) {
        unsigned char wit_bytes[50], *w = wit_bytes; // Witness outputs can be no larger than 50 bytes as specified in BIP 141
        size_t wit_len;
        type = WALLY_PSBT_IN_WITNESS_UTXO;
        p += varbuff_to_bytes(&type, 1, p);

        // Serialize the output to the temp buffer;
        w += uint64_to_le_bytes(input->witness_utxo->satoshi, w);
        w += varbuff_to_bytes(input->witness_utxo->script, input->witness_utxo->script_len, w);
        wit_len = w - wit_bytes;

        p += varint_to_bytes(wit_len, p);
        memcpy(p, wit_bytes, wit_len);
        p += wit_len;
    }
    // Partial sigs
    if (input->partial_sigs) {
        struct wally_partial_sigs_map *partial_sigs = input->partial_sigs;
        for (i = 0; i < partial_sigs->num_items; ++i) {
            struct wally_partial_sigs_item *item = &partial_sigs->items[i];
            if (pubkey_is_compressed(item->pubkey)) {
                p += varint_to_bytes(34, p);
                *p = WALLY_PSBT_IN_PARTIAL_SIG;
                p++;
                memcpy(p, item->pubkey, EC_PUBLIC_KEY_LEN);
                p += EC_PUBLIC_KEY_LEN;
            } else {
                p += varint_to_bytes(66, p);
                *p = WALLY_PSBT_IN_PARTIAL_SIG;
                p++;
                memcpy(p, item->pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
                p += EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
            }
            p += varbuff_to_bytes(item->sig, item->sig_len, p);
        }
    }
    // Sighash type
    if (input->sighash_type > 0) {
        type = WALLY_PSBT_IN_SIGHASH_TYPE;
        p += varbuff_to_bytes(&type, 1, p);
        p += varint_to_bytes(sizeof(uint32_t), p);
        p += uint32_to_le_bytes(input->sighash_type, p);
    }
    // Redeem script
    if (input->redeem_script) {
        type = WALLY_PSBT_IN_REDEEM_SCRIPT;
        p += varbuff_to_bytes(&type, 1, p);
        p += varbuff_to_bytes(input->redeem_script, input->redeem_script_len, p);
    }
    // Witness script
    if (input->witness_script) {
        type = WALLY_PSBT_IN_WITNESS_SCRIPT;
        p += varbuff_to_bytes(&type, 1, p);
        p += varbuff_to_bytes(input->witness_script, input->witness_script_len, p);
    }
    // Keypaths
    if (input->keypaths) {
        struct wally_keypath_map *keypaths = input->keypaths;
        for (i = 0; i < keypaths->num_items; ++i) {
            size_t origin_len, j;
            struct wally_keypath_item *item = &keypaths->items[i];
            if (pubkey_is_compressed(item->pubkey)) {
                p += varint_to_bytes(34, p);
                *p = WALLY_PSBT_IN_BIP32_DERIVATION;
                p++;
                memcpy(p, item->pubkey, EC_PUBLIC_KEY_LEN);
                p += EC_PUBLIC_KEY_LEN;
            } else {
                p += varint_to_bytes(66, p);
                *p = WALLY_PSBT_IN_BIP32_DERIVATION;
                p++;
                memcpy(p, item->pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
                p += EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
            }

            origin_len = 4; // Start with 4 bytes for fingerprint
            origin_len += item->origin.path_len * sizeof(uint32_t);
            p += varint_to_bytes(origin_len, p);

            memcpy(p, item->origin.fingerprint, 4);
            p += 4;
            for (j = 0; j < item->origin.path_len; ++j) {
                memcpy(p, &item->origin.path[j], sizeof(uint32_t));
                p += 4;
            }
        }
    }
    // Final scriptSig
    if (input->final_script_sig) {
        type = WALLY_PSBT_IN_FINAL_SCRIPTSIG;
        p += varbuff_to_bytes(&type, 1, p);
        p += varbuff_to_bytes(input->final_script_sig, input->final_script_sig_len, p);
    }
    // Final scriptWitness
    if (input->final_witness) {
        type = WALLY_PSBT_IN_FINAL_SCRIPTWITNESS;
        p += varbuff_to_bytes(&type, 1, p);
        struct wally_tx_witness_stack *witness = input->final_witness;
        size_t wit_len = varint_get_length(witness->num_items);
        for (i = 0; i < witness->num_items; ++i) {
            const struct wally_tx_witness_item *stack;
            stack = witness->items + i;
            wit_len += varint_get_length(stack->witness_len);
            wit_len += stack->witness_len;
        }

        p += varint_to_bytes(wit_len, p);
        p += varint_to_bytes(witness->num_items, p);
        for (i = 0; i < witness->num_items; ++i) {
            const struct wally_tx_witness_item *stack;
            stack = witness->items + i;
            p += varbuff_to_bytes(stack->witness, stack->witness_len, p);
        }
    }
    // Unknowns
    if (input->unknowns) {
        for (i = 0; i < input->unknowns->num_items; ++i) {
            struct wally_unknowns_item *unknown = &input->unknowns->items[i];
            p += varint_to_bytes(unknown->key_len, p);
            memcpy(p, unknown->key, unknown->key_len);
            p += unknown->key_len;
            p += varint_to_bytes(unknown->value_len, p);
            memcpy(p, unknown->value, unknown->value_len);
            p += unknown->value_len;
        }
    }

    // Separator
    *p = WALLY_PSBT_SEPARATOR;
    p++;

    *bytes_written = p - bytes_out;

    return WALLY_OK;
}

static int psbt_output_to_bytes(
    const struct wally_psbt_output *output,
    unsigned char *bytes_out,
    size_t *bytes_written)
{
    unsigned char type, *p = bytes_out;
    size_t i;

    // Redeem script
    if (output->redeem_script) {
        type = WALLY_PSBT_OUT_REDEEM_SCRIPT;
        p += varbuff_to_bytes(&type, 1, p);
        p += varbuff_to_bytes(output->redeem_script, output->redeem_script_len, p);
    }
    // Witness script
    if (output->witness_script) {
        type = WALLY_PSBT_OUT_WITNESS_SCRIPT;
        p += varbuff_to_bytes(&type, 1, p);
        p += varbuff_to_bytes(output->witness_script, output->witness_script_len, p);
    }
    // Keypaths
    if (output->keypaths) {
        struct wally_keypath_map *keypaths = output->keypaths;
        for (i = 0; i < keypaths->num_items; ++i) {
            size_t origin_len, j;
            struct wally_keypath_item *item = &keypaths->items[i];
            if (pubkey_is_compressed(item->pubkey)) {
                p += varint_to_bytes(34, p);
                *p = WALLY_PSBT_OUT_BIP32_DERIVATION;
                p++;
                memcpy(p, item->pubkey, EC_PUBLIC_KEY_LEN);
                p += EC_PUBLIC_KEY_LEN;
            } else {
                p += varint_to_bytes(66, p);
                *p = WALLY_PSBT_OUT_BIP32_DERIVATION;
                p++;
                memcpy(p, item->pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
                p += EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
            }

            origin_len = 4; // Start with 4 bytes for fingerprint
            origin_len += item->origin.path_len * sizeof(uint32_t);
            p += varint_to_bytes(origin_len, p);

            memcpy(p, item->origin.fingerprint, 4);
            p += 4;
            for (j = 0; j < item->origin.path_len; ++j) {
                memcpy(p, &item->origin.path[j], sizeof(uint32_t));
                p += 4;
            }
        }
    }
    // Unknowns
    if (output->unknowns) {
        for (i = 0; i < output->unknowns->num_items; ++i) {
            struct wally_unknowns_item *unknown = &output->unknowns->items[i];
            p += varint_to_bytes(unknown->key_len, p);
            memcpy(p, unknown->key, unknown->key_len);
            p += unknown->key_len;
            p += varint_to_bytes(unknown->value_len, p);
            memcpy(p, unknown->value, unknown->value_len);
            p += unknown->value_len;
        }
    }

    // Separator
    *p = WALLY_PSBT_SEPARATOR;
    p++;

    *bytes_written = p - bytes_out;

    return WALLY_OK;
}

int wally_psbt_to_bytes(
    const struct wally_psbt *psbt,
    unsigned char *bytes_out, size_t len,
    size_t *bytes_written)
{
    unsigned char type, *p = bytes_out, *end = bytes_out + len;
    size_t calc_len, tx_len, i;
    int ret;

    if (bytes_written) {
        *bytes_written = 0;
    }

    ret = wally_psbt_get_length(psbt, &calc_len);
    if (ret != WALLY_OK) {
        return ret;
    }
    if (calc_len > len) {
        return WALLY_EINVAL; // Buffer is not big enough
    }

    // Magic
    memcpy(p, WALLY_PSBT_MAGIC, 5);
    p += 5;

    // Global tx
    type = WALLY_PSBT_GLOBAL_UNSIGNED_TX;
    p += varbuff_to_bytes(&type, 1, p);
    ret = wally_tx_get_length(psbt->tx, 0, &tx_len);
    if (ret != WALLY_OK) {
        return ret;
    }
    p += varint_to_bytes(tx_len, p);
    ret = wally_tx_to_bytes(psbt->tx, 0, p, end - p, &tx_len);
    if (ret != WALLY_OK) {
        return ret;
    }
    p += tx_len;

    // Unknowns
    if (psbt->unknowns) {
        for (i = 0; i < psbt->unknowns->num_items; ++i) {
            struct wally_unknowns_item *unknown = &psbt->unknowns->items[i];
            p += varint_to_bytes(unknown->key_len, p);
            memcpy(p, unknown->key, unknown->key_len);
            p += unknown->key_len;
            p += varint_to_bytes(unknown->value_len, p);
            memcpy(p, unknown->value, unknown->value_len);
            p += unknown->value_len;
        }
    }

    // Separator
    *p = WALLY_PSBT_SEPARATOR;
    p++;

    // Get lengths of each input and output
    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        size_t input_len;
        ret = psbt_input_to_bytes(input, p, end - p, &input_len);
        if (ret != WALLY_OK) {
            return ret;
        }
        p += input_len;
    }
    for (i = 0; i < psbt->num_outputs; ++i) {
        struct wally_psbt_output *output = &psbt->outputs[i];
        size_t output_len;
        ret = psbt_output_to_bytes(output, p, &output_len);
        if (ret != WALLY_OK) {
            return ret;
        }
        p += output_len;
    }
    *bytes_written = p - bytes_out;
    return WALLY_OK;
}

int wally_psbt_from_base64(
    const char *string,
    struct wally_psbt **output)
{
    char *decoded;
    size_t safe_len, string_len;
    ssize_t decoded_len;
    int ret;

    if (!string) {
        return WALLY_EINVAL;
    }

    string_len = strlen(string);
    // Allocate the decoded buffer
    safe_len = base64_decoded_length(string_len);
    if ((decoded = wally_malloc(safe_len)) == NULL) {
        ret = WALLY_ENOMEM;
        goto done;
    }

    // Decode the base64 psbt
    decoded_len = base64_decode(decoded, safe_len, string, string_len);
    if (decoded_len <= 5) { // Make sure we also have enough bytes for the magic
        ret = WALLY_EINVAL;
        goto done;
    }

    // Now decode the psbt
    ret = wally_psbt_from_bytes((unsigned char *)decoded, decoded_len, output);

done:
    if (decoded) {
        wally_free(decoded);
    }
    return ret;
}

int wally_psbt_to_base64(
    struct wally_psbt *psbt,
    char **output)
{
    unsigned char *buff;
    char *result = NULL;
    size_t len, written, b64_safe_len;
    ssize_t b64_len;
    int ret = WALLY_OK;

    if (!output || !psbt) {
        return WALLY_EINVAL;
    }

    if ((ret = wally_psbt_get_length(psbt, &len)) != WALLY_OK) {
        return ret;
    }
    if ((buff = wally_malloc(len)) == NULL) {
        return WALLY_ENOMEM;
    }

    // Get psbt bytes
    if ((ret = wally_psbt_to_bytes(psbt, buff, len, &written)) != WALLY_OK) {
        goto done;
    }

    // Base64 encode
    b64_safe_len = base64_encoded_length(written) + 1; // + 1 for null termination
    if ((result = wally_malloc(b64_safe_len)) == NULL) {
        ret = WALLY_ENOMEM;
        goto done;
    }
    if ((b64_len = base64_encode(result, b64_safe_len, (char *)buff, written)) <= 0) {
        ret = WALLY_EINVAL;
        goto done;
    }
    *output = result;
    result = NULL;

done:
    if (result) {
        clear_and_free(result, b64_safe_len);
    }
    if (buff) {
        clear_and_free(buff, len);
    }
    return ret;
}

static int get_txid(
    struct wally_tx *tx,
    unsigned char *txid,
    size_t txid_len)
{
    unsigned char *bytes = NULL;
    size_t calc, written;
    int ret = WALLY_OK;

    if (!tx || !txid || txid_len != SHA256_LEN) {
        return WALLY_EINVAL;
    }

    if ((ret = wally_tx_get_length(tx, 0, &calc)) != WALLY_OK) {
        return ret;
    }
    if ((bytes = wally_malloc(calc)) == NULL) {
        return WALLY_ENOMEM;
    }
    if ((ret = wally_tx_to_bytes(tx, 0, bytes, calc, &written)) == WALLY_OK) {
        ret = wally_sha256d(bytes, written, txid, SHA256_LEN);
    }

    wally_free(bytes);
    return ret;
}

static int merge_unknowns_into(
    struct wally_unknowns_map *dst,
    const struct wally_unknowns_map *src)
{
    int ret = WALLY_OK;
    size_t i, j;

    if (!src || !dst) {
        return WALLY_EINVAL;
    }

    for (i = 0; i < src->num_items; ++i) {
        bool found = false;
        for (j = 0; j < dst->num_items; ++j) {
            if (src->items[i].key_len == dst->items[j].key_len &&
                memcmp((char *)dst->items[j].key, (char *)src->items[i].key, src->items[i].key_len) == 0) {
                found = true;
                break;
            }
        }
        if (found) {
            continue;
        }
        if ((ret = add_unknowns_item(dst, &src->items[i])) != WALLY_OK) {
            return ret;
        }
    }
    return ret;
}

static int merge_keypaths_into(
    struct wally_keypath_map *dst,
    const struct wally_keypath_map *src)
{
    int ret = WALLY_OK;
    size_t i, j;

    if (!src || !dst) {
        return WALLY_EINVAL;
    }

    for (i = 0; i < src->num_items; ++i) {
        bool found = false;
        for (j = 0; j < dst->num_items; ++j) {
            if (memcmp((char *)dst->items[j].pubkey, (char *)src->items[i].pubkey, 65) == 0) {
                found = true;
                break;
            }
        }
        if (found) {
            continue;
        }
        if ((ret = add_keypath_item(dst, &src->items[i])) != WALLY_OK) {
            return ret;
        }
    }
    return ret;
}

static int merge_input_into(
    struct wally_psbt_input *dst,
    const struct wally_psbt_input *src)
{
    int ret = WALLY_OK;
    size_t i, j;

    if (!dst->non_witness_utxo && src->non_witness_utxo && (ret = clone_tx(src->non_witness_utxo, &dst->non_witness_utxo)) != WALLY_OK) {
        return ret;
    }
    if (!dst->witness_utxo && src->witness_utxo && (ret = wally_tx_output_init_alloc(src->witness_utxo->satoshi, src->witness_utxo->script, src->witness_utxo->script_len, &dst->witness_utxo)) != WALLY_OK) {
        return ret;
    }

    if (src->partial_sigs) {
        if (!dst->partial_sigs) {
            if ((ret = wally_partial_sigs_map_init_alloc(src->partial_sigs->items_allocation_len, &dst->partial_sigs)) != WALLY_OK) {
                return ret;
            }
        }

        for (i = 0; i < src->partial_sigs->num_items; ++i) {
            bool found = false;
            for (j = 0; j < dst->partial_sigs->num_items; ++j) {
                if (memcmp((char *)dst->partial_sigs->items[j].pubkey, (char *)src->partial_sigs->items[i].pubkey, 65) == 0) {
                    found = true;
                    break;
                }
            }
            if (found) {
                continue;
            }
            if ((ret = add_partial_sig_item(dst->partial_sigs, &src->partial_sigs->items[i])) != WALLY_OK) {
                return ret;
            }
        }
    }

    if (src->keypaths) {
        if (!dst->keypaths) {
            if ((ret = wally_keypath_map_init_alloc(src->keypaths->items_allocation_len, &dst->keypaths)) != WALLY_OK) {
                return ret;
            }
        }

        if ((ret = merge_keypaths_into(dst->keypaths, src->keypaths)) != WALLY_OK) {
            return ret;
        }
    }

    if (src->unknowns) {
        if (!dst->unknowns) {
            if ((ret = wally_unknowns_map_init_alloc(src->unknowns->items_allocation_len, &dst->unknowns)) != WALLY_OK) {
                return ret;
            }
        }

        if ((ret = merge_unknowns_into(dst->unknowns, src->unknowns)) != WALLY_OK) {
            return ret;
        }
    }

    if (dst->redeem_script_len == 0 && src->redeem_script_len > 0) {
        if (!clone_bytes(&dst->redeem_script, src->redeem_script, src->redeem_script_len)) {
            return WALLY_ENOMEM;
        }
        dst->redeem_script_len = src->redeem_script_len;
    }

    if (dst->witness_script_len == 0 && src->witness_script_len > 0) {
        if (!clone_bytes(&dst->witness_script, src->witness_script, src->witness_script_len)) {
            return WALLY_ENOMEM;
        }
        dst->witness_script_len = src->witness_script_len;
    }

    if (dst->final_script_sig_len == 0 && src->final_script_sig_len > 0) {
        if (!clone_bytes(&dst->final_script_sig, src->final_script_sig, src->final_script_sig_len)) {
            return WALLY_ENOMEM;
        }
        dst->final_script_sig_len = src->final_script_sig_len;
    }

    if (!dst->final_witness && src->final_witness) {
        dst->final_witness = clone_witness(src->final_witness);
        if (!dst->final_witness) {
            return WALLY_ENOMEM;
        }
    }

    if (src->sighash_type > dst->sighash_type) {
        dst->sighash_type = src->sighash_type;
    }

    return WALLY_OK;
}

static int merge_output_into(
    struct wally_psbt_output *dst,
    const struct wally_psbt_output *src)
{
    int ret = WALLY_OK;

    if (src->keypaths) {
        if (!dst->keypaths) {
            if ((ret = wally_keypath_map_init_alloc(src->keypaths->items_allocation_len, &dst->keypaths)) != WALLY_OK) {
                return ret;
            }
        }

        if ((ret = merge_keypaths_into(dst->keypaths, src->keypaths)) != WALLY_OK) {
            return ret;
        }
    }

    if (src->unknowns) {
        if (!dst->unknowns) {
            if ((ret = wally_unknowns_map_init_alloc(src->unknowns->items_allocation_len, &dst->unknowns)) != WALLY_OK) {
                return ret;
            }
        }

        if ((ret = merge_unknowns_into(dst->unknowns, src->unknowns)) != WALLY_OK) {
            return ret;
        }
    }

    if (dst->redeem_script_len == 0 && src->redeem_script_len > 0) {
        if (!clone_bytes(&dst->redeem_script, src->redeem_script, src->redeem_script_len)) {
            return WALLY_ENOMEM;
        }
        dst->redeem_script_len = src->redeem_script_len;
    }

    if (dst->witness_script_len == 0 && src->witness_script_len > 0) {
        if (!clone_bytes(&dst->witness_script, src->witness_script, src->witness_script_len)) {
            return WALLY_ENOMEM;
        }
        dst->witness_script_len = src->witness_script_len;
    }

    return WALLY_OK;
}

int wally_combine_psbts(
    const struct wally_psbt *psbts,
    size_t psbts_len,
    struct wally_psbt **output)
{
    struct wally_psbt *result;
    unsigned char global_txid[SHA256_LEN];
    size_t i, j;
    int ret = WALLY_OK;

    TX_CHECK_OUTPUT;

    if (!psbts) {
        return WALLY_EINVAL;
    }

    // Get info from the first psbt and use it as the template
    if ((ret = get_txid(psbts->tx, global_txid, SHA256_LEN)) != WALLY_OK) {
        return ret;
    }

    if ((ret = wally_psbt_init_alloc(psbts[0].inputs_allocation_len, psbts[0].outputs_allocation_len, psbts[0].unknowns->items_allocation_len, &result)) != WALLY_OK) {
        return ret;
    }

    if ((ret = clone_tx(psbts[0].tx, &result->tx)) != WALLY_OK) {
        goto fail;
    }
    result->num_inputs = psbts[0].num_inputs;
    result->num_outputs = psbts[0].num_outputs;

    for (i = 0; i < psbts_len; ++i) {
        unsigned char txid[SHA256_LEN];

        // Compare the txids
        if ((ret = get_txid(psbts[i].tx, txid, SHA256_LEN)) != WALLY_OK) {
            goto fail;
        }
        if (memcmp(global_txid, txid, SHA256_LEN) != 0) {
            ret = WALLY_EINVAL;
            goto fail;
        }

        // Now start merging
        for (j = 0; j < result->num_inputs; ++j) {
            if ((ret = merge_input_into(&result->inputs[j], &psbts[i].inputs[j])) != WALLY_OK) {
                goto fail;
            }
        }
        for (j = 0; j < result->num_outputs; ++j) {
            if ((ret = merge_output_into(&result->outputs[j], &psbts[i].outputs[j])) != WALLY_OK) {
                goto fail;
            }
        }

        if (psbts[i].unknowns) {
            if (!result->unknowns) {
                if ((ret = wally_unknowns_map_init_alloc(psbts[i].unknowns->items_allocation_len, &result->unknowns)) != WALLY_OK) {
                    goto fail;
                }
            }

            if ((ret = merge_unknowns_into(result->unknowns, psbts[i].unknowns)) != WALLY_OK) {
                return ret;
            }
        }
    }

    *output = result;
    return WALLY_OK;

fail:
    wally_psbt_free(result);
    return ret;
}

int wally_sign_psbt(
    struct wally_psbt *psbt,
    const unsigned char *key,
    size_t key_len)
{
    unsigned char pubkey[EC_PUBLIC_KEY_LEN], uncomp_pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN], sig[EC_SIGNATURE_LEN], der_sig[EC_SIGNATURE_DER_MAX_LEN + 1];
    size_t i, j, der_sig_len;
    int ret;

    if (!psbt || !psbt->tx || !key || key_len != EC_PRIVATE_KEY_LEN) {
        return WALLY_EINVAL;
    }

    // Get the pubkey
    if ((ret = wally_ec_public_key_from_private_key(key, key_len, pubkey, EC_PUBLIC_KEY_LEN)) != WALLY_OK) {
        return ret;
    }
    if ((ret = wally_ec_public_key_decompress(pubkey, EC_PUBLIC_KEY_LEN, uncomp_pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN)) != WALLY_OK) {
        return ret;
    }

    // Go through each of the inputs
    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        struct wally_tx_input *txin = &psbt->tx->inputs[i];
        unsigned char sighash[SHA256_LEN], *scriptcode, wpkh_sc[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
        size_t scriptcode_len;
        bool match = false, comp = false;
        uint32_t sighash_type = WALLY_SIGHASH_ALL;

        if (!input->keypaths) {
            // Can't do anything without the keypaths
            continue;
        }

        // Go through each listed pubkey and see if it matches.
        for (j = 0; j < input->keypaths->num_items; ++j) {
            struct wally_keypath_item *item = &input->keypaths->items[j];
            if (item->pubkey[0] == 0x04 && memcmp((char *)item->pubkey, (char *)uncomp_pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN) == 0) {
                match = true;
                break;
            } else if (memcmp((char *)item->pubkey, (char *)pubkey, EC_PUBLIC_KEY_LEN) == 0) {
                match = true;
                comp = true;
                break;
            }
        }

        // Did not find pubkey, skip
        if (!match) {
            continue;
        }

        // Sighash type
        if (input->sighash_type > 0) {
            sighash_type = input->sighash_type;
        }

        // Get scriptcode and sighash
        if (input->redeem_script) {
            unsigned char sh[WALLY_SCRIPTPUBKEY_P2SH_LEN];
            size_t written;

            if ((ret = wally_scriptpubkey_p2sh_from_bytes(input->redeem_script, input->redeem_script_len, WALLY_SCRIPT_HASH160, sh, WALLY_SCRIPTPUBKEY_P2SH_LEN, &written)) != WALLY_OK) {
                return ret;
            }
            if (input->non_witness_utxo) {
                if (input->non_witness_utxo->outputs[txin->index].script_len != WALLY_SCRIPTPUBKEY_P2SH_LEN ||
                    memcmp(sh, input->non_witness_utxo->outputs[txin->index].script, WALLY_SCRIPTPUBKEY_P2SH_LEN) != 0) {
                    return WALLY_EINVAL;
                }
            } else if (input->witness_utxo) {
                if (input->witness_utxo->script_len != WALLY_SCRIPTPUBKEY_P2SH_LEN ||
                    memcmp(sh, input->witness_utxo->script, WALLY_SCRIPTPUBKEY_P2SH_LEN) != 0) {
                    return WALLY_EINVAL;
                }
            } else {
                continue;
            }
            scriptcode = input->redeem_script;
            scriptcode_len = input->redeem_script_len;
        } else {
            if (input->non_witness_utxo) {
                scriptcode = input->non_witness_utxo->outputs[txin->index].script;
                scriptcode_len = input->non_witness_utxo->outputs[txin->index].script_len;
            } else if (input->witness_utxo) {
                scriptcode = input->witness_utxo->script;
                scriptcode_len = input->witness_utxo->script_len;
            } else {
                continue;
            }
        }

        if (input->non_witness_utxo) {
            unsigned char txid[SHA256_LEN];

            if ((ret = get_txid(input->non_witness_utxo, txid, SHA256_LEN)) != WALLY_OK) {
                return ret;
            }
            if (memcmp((char *)txid, (char *)txin->txhash, SHA256_LEN) != 0) {
                return WALLY_EINVAL;
            }

            if ((ret = wally_tx_get_btc_signature_hash(psbt->tx, i, scriptcode, scriptcode_len, 0, sighash_type, 0, sighash, SHA256_LEN)) != WALLY_OK) {
                return ret;
            }
        } else if (input->witness_utxo) {
            size_t type;
            if ((ret = wally_scriptpubkey_get_type(scriptcode, scriptcode_len, &type)) != WALLY_OK) {
                return ret;
            }
            if (type == WALLY_SCRIPT_TYPE_P2WPKH) {
                size_t written;
                if ((ret = wally_scriptpubkey_p2pkh_from_bytes(&scriptcode[2], HASH160_LEN, 0, wpkh_sc, WALLY_SCRIPTPUBKEY_P2PKH_LEN, &written)) != WALLY_OK) {
                    return ret;
                }
                scriptcode = wpkh_sc;
                scriptcode_len = WALLY_SCRIPTPUBKEY_P2PKH_LEN;
            } else if (type == WALLY_SCRIPT_TYPE_P2WSH && input->witness_script) {
                unsigned char wsh[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
                size_t written;

                if ((ret = wally_witness_program_from_bytes(input->witness_script, input->witness_script_len, WALLY_SCRIPT_SHA256, wsh, WALLY_SCRIPTPUBKEY_P2WSH_LEN, &written)) != WALLY_OK) {
                    return ret;
                }
                if (scriptcode_len != WALLY_SCRIPTPUBKEY_P2WSH_LEN ||
                    memcmp((char *)wsh, (char *)scriptcode, WALLY_SCRIPTPUBKEY_P2WSH_LEN) != 0) {
                    return WALLY_EINVAL;
                }
                scriptcode = input->witness_script;
                scriptcode_len = input->witness_script_len;
            } else {
                // Not a recognized scriptPubKey type or not enough information
                continue;
            }

            if ((ret = wally_tx_get_btc_signature_hash(psbt->tx, i, scriptcode, scriptcode_len, input->witness_utxo->satoshi, sighash_type, WALLY_TX_FLAG_USE_WITNESS, sighash, SHA256_LEN)) != WALLY_OK) {
                return ret;
            }
        }

        // Sign the sighash
        if ((ret = wally_ec_sig_from_bytes(key, key_len, sighash, SHA256_LEN, EC_FLAG_ECDSA | EC_FLAG_GRIND_R, sig, EC_SIGNATURE_LEN)) != WALLY_OK) {
            return ret;
        }
        if ((ret = wally_ec_sig_normalize(sig, EC_SIGNATURE_LEN, sig, EC_SIGNATURE_LEN)) != WALLY_OK) {
            return ret;
        }
        if ((ret = wally_ec_sig_to_der(sig, EC_SIGNATURE_LEN, der_sig, EC_SIGNATURE_DER_MAX_LEN, &der_sig_len)) != WALLY_OK) {
            return ret;
        }

        // Add the sighash type to the end of the sig
        der_sig[der_sig_len] = (unsigned char)sighash_type;
        der_sig_len++;

        // Copy the DER sig into the psbt
        if (!input->partial_sigs) {
            if ((ret = wally_partial_sigs_map_init_alloc(1, &input->partial_sigs)) != WALLY_OK) {
                return ret;
            }
        }
        if ((ret = wally_add_new_partial_sig(input->partial_sigs, comp ? pubkey : uncomp_pubkey, comp ? EC_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_UNCOMPRESSED_LEN, der_sig, der_sig_len)) != WALLY_OK) {
            return ret;
        }
    }

    return WALLY_OK;
}

int wally_finalize_psbt(struct wally_psbt *psbt)
{
    size_t i;
    int ret;

    if (!psbt) {
        return WALLY_EINVAL;
    }

    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        struct wally_tx_input *txin = &psbt->tx->inputs[i];
        unsigned char *out_script; // Script that determines how we should finalize this input, typically output script
        size_t out_script_len;
        bool witness = false, p2sh = false;;

        if (input->final_script_sig || input->final_witness) {
            // Already finalized
            continue;
        }

        if (input->redeem_script) {
            out_script = input->redeem_script;
            out_script_len = input->redeem_script_len;
            p2sh = true;
        } else {
            out_script = psbt->tx->outputs[txin->index].script;
            out_script_len = psbt->tx->outputs[txin->index].script_len;
        }
        if (input->witness_script) {
            out_script = input->witness_script;
            out_script_len = input->witness_script_len;
            witness = true;
        }

        size_t type;
        if ((ret = wally_scriptpubkey_get_type(out_script, out_script_len, &type)) != WALLY_OK) {
            return ret;
        }

        switch(type) {
        case WALLY_SCRIPT_TYPE_P2PKH:
        case WALLY_SCRIPT_TYPE_P2WPKH: {
            struct wally_partial_sigs_item *partial_sig;
            unsigned char script_sig[WALLY_SCRIPTSIG_P2PKH_MAX_LEN];
            size_t script_sig_len, pubkey_len = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;

            if (!input->partial_sigs || input->partial_sigs->num_items != 1) {
                // Must be single key, single sig
                continue;
            }
            partial_sig = &input->partial_sigs->items[0];
            if (pubkey_is_compressed(partial_sig->pubkey)) {
                pubkey_len = EC_PUBLIC_KEY_LEN;
            }

            if (type == WALLY_SCRIPT_TYPE_P2PKH) {
                if ((ret = wally_scriptsig_p2pkh_from_der(partial_sig->pubkey, pubkey_len, partial_sig->sig, partial_sig->sig_len, script_sig, WALLY_SCRIPTSIG_P2PKH_MAX_LEN, &script_sig_len)) != WALLY_OK) {
                    return ret;
                }
                if (!clone_bytes(&input->final_script_sig, script_sig, script_sig_len)) {
                    return WALLY_ENOMEM;
                }
            } else {
                if ((ret = wally_witness_p2wpkh_from_der(partial_sig->pubkey, pubkey_len, partial_sig->sig, partial_sig->sig_len, &input->final_witness)) != WALLY_OK) {
                    return ret;
                }
            }
            break;
        }
        case WALLY_SCRIPT_TYPE_MULTISIG: {
            unsigned char *script_sig, *sigs, *p = out_script, *end = p + out_script_len;
            uint32_t *sighashes;
            size_t n_sigs, n_pks, sig_i = 0, j, k, sigs_len, script_sig_len, written;

            if (!script_is_op_n(out_script[0], false, &n_sigs)) {
                // How did this happen?
                return WALLY_ERROR;
            }

            if (!input->partial_sigs || input->partial_sigs->num_items < n_sigs) {
                continue;
            }

            if (!script_is_op_n(out_script[out_script_len - 2], false, &n_pks)) {
                // How did this happen?
                return WALLY_ERROR;
            }

            sigs_len = EC_SIGNATURE_LEN * n_sigs;
            if (!(sigs = wally_malloc(sigs_len)) || !(sighashes = wally_malloc(n_sigs * sizeof(uint32_t)))) {
                return WALLY_ENOMEM;
            }

            // Go through the multisig script and figure out the order of pubkeys
            p++; // Skip the n_sig item
            for (j = 0; j < n_pks && p < end; ++j) {
                size_t push_size, push_opcode_size, sig_len;
                unsigned char *pubkey, *sig, compact_sig[EC_SIGNATURE_LEN];
                bool found = false;

                if ((ret = script_get_push_size_from_bytes(p, end - p, &push_size)) != WALLY_OK) {
                    wally_free(sigs);
                    wally_free(sighashes);
                    return ret;
                }
                if ((ret = script_get_push_opcode_size_from_bytes(p, end - p, &push_opcode_size)) != WALLY_OK) {
                    wally_free(sigs);
                    wally_free(sighashes);
                    return ret;
                }
                p += push_opcode_size;

                pubkey = p;
                p += push_size;

                for (k = 0; k < input->partial_sigs->num_items; ++k) {
                    if (memcmp(input->partial_sigs->items[k].pubkey, pubkey, push_size) == 0) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    continue;
                }

                // Get the signature and sighash separately
                sig = input->partial_sigs->items[k].sig;
                sig_len = input->partial_sigs->items[k].sig_len; // Has sighash byte at end
                if ((ret = wally_ec_sig_from_der(sig, sig_len - 1, compact_sig, EC_SIGNATURE_LEN)) != WALLY_OK) {
                    wally_free(sigs);
                    wally_free(sighashes);
                    return ret;
                }
                memcpy(sigs + sig_i * EC_SIGNATURE_LEN, compact_sig, EC_SIGNATURE_LEN);
                sighashes[sig_i] = (uint32_t)sig[sig_len - 1];
                sig_i++;
            }

            if (witness) {
                if ((ret = wally_witness_multisig_from_bytes(out_script, out_script_len, sigs, sigs_len, sighashes, n_sigs, 0, &input->final_witness)) != WALLY_OK) {
                    wally_free(sigs);
                    wally_free(sighashes);
                    return ret;
                }
            } else {
                script_sig_len = n_sigs * (EC_SIGNATURE_DER_MAX_LEN + 2) + out_script_len;
                if (!(script_sig = wally_malloc(script_sig_len))) {
                    wally_free(sigs);
                    wally_free(sighashes);
                    return WALLY_ENOMEM;
                }

                if ((ret = wally_scriptsig_multisig_from_bytes(out_script, out_script_len, sigs, sigs_len, sighashes, n_sigs, 0, script_sig, script_sig_len, &written)) != WALLY_OK) {
                    wally_free(sigs);
                    wally_free(sighashes);
                    wally_free(script_sig);
                    return ret;
                }
                input->final_script_sig = script_sig;
                input->final_script_sig_len = written;
            }

            wally_free(sigs);
            wally_free(sighashes);

            if (witness && p2sh) {
                // P2SH wrapped witness requires final scriptsig of pushing the redeemScript
                script_sig_len = varint_get_length(input->redeem_script_len) + input->redeem_script_len;
                input->final_script_sig = wally_malloc(script_sig_len);
                if ((ret = wally_script_push_from_bytes(input->redeem_script, input->redeem_script_len, 0, input->final_script_sig, script_sig_len, &written)) != WALLY_OK) {
                    wally_free(input->final_script_sig);
                    return ret;
                }
                input->final_script_sig_len = written;
            }

            break;
        }
        default: {
            // Skip this because we can't finalize it
            continue;
        }
        }

        // Clear non-final things
        wally_free(input->redeem_script);
        input->redeem_script_len = 0;
        input->redeem_script = NULL;
        wally_free(input->witness_script);
        input->witness_script_len = 0;
        input->witness_script = NULL;
        wally_keypath_map_free(input->keypaths);
        input->keypaths = NULL;
        wally_partial_sigs_map_free(input->partial_sigs);
        input->partial_sigs = NULL;
        input->sighash_type = 0;
    }
    return WALLY_OK;
}

int wally_extract_psbt(
    struct wally_psbt *psbt,
    struct wally_tx **output)
{
    struct wally_tx *result = NULL;
    size_t i;
    int ret = WALLY_OK;

    TX_CHECK_OUTPUT;

    if (!psbt || !psbt->tx || psbt->num_inputs == 0 || psbt->num_outputs == 0) {
        return WALLY_EINVAL;
    }

    clone_tx(psbt->tx, &result);

    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        struct wally_tx_input *vin = &result->inputs[i];
        if (!input->final_script_sig && !input->final_witness) {
            ret = WALLY_EINVAL;
            goto fail;
        }

        if (input->final_script_sig) {
            if (vin->script) {
                // Our global tx shouldn't have a scriptSig
                ret = WALLY_EINVAL;
                goto fail;
            }
            if (!clone_bytes(&vin->script, input->final_script_sig, input->final_script_sig_len)) {
                ret = WALLY_ENOMEM;
                goto fail;
            }
            vin->script_len = input->final_script_sig_len;
        }
        if (input->final_witness) {
            if (vin->witness) {
                // Our global tx shouldn't have a witness
                ret = WALLY_EINVAL;
                goto fail;
            }
            if (!(vin->witness = clone_witness(input->final_witness))) {
                ret = WALLY_ENOMEM;
                goto fail;
            }
        }
    }

    *output = result;
    return ret;

fail:
    if (result) {
        wally_tx_free(result);
    }
    return ret;
}
