#include "internal.h"

#include "ccan/ccan/base64/base64.h"
#include "ccan/ccan/build_assert/build_assert.h"

#include <include/wally_crypto.h>
#include <include/wally_elements.h>
#include <include/wally_script.h>
#include <include/wally_transaction.h>
#include <include/wally_psbt.h>

#include <limits.h>
#include <assert.h>
#include "transaction_shared.h"
#include "script_int.h"
#include "script.h"
#include "pullpush.h"

const uint8_t WALLY_PSBT_MAGIC[5] = {'p', 's', 'b', 't', 0xff};

#ifdef BUILD_ELEMENTS
const uint8_t WALLY_ELEMENTS_PSBT_MAGIC[5] = {'p', 's', 'e', 't', 0xff};
const uint8_t WALLY_ELEMENTS_ID[8] = {'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
const size_t WALLY_ELEMENTS_ID_LEN = 8;
#endif /* BUILD_ELEMENTS */

static bool pubkey_is_compressed(const unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN]) {
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
        struct wally_keypath_item *new_items;
        size_t new_alloc_len = 1;
        size_t orig_num_items = keypaths->num_items;
        if (keypaths->items_allocation_len != 0) {
            new_alloc_len = keypaths->items_allocation_len * 2;
        }
        new_items = wally_malloc(new_alloc_len * sizeof(struct wally_keypath_item));
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
        struct wally_partial_sigs_item *new_items;
        size_t new_alloc_len = 1;
        size_t orig_num_items = sigs->num_items;
        if (sigs->items_allocation_len != 0) {
            new_alloc_len = sigs->items_allocation_len * 2;
        }
        new_items = wally_malloc(new_alloc_len * sizeof(struct wally_partial_sigs_item));
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
                clear_and_free(unknowns->items[i].key, unknowns->items[i].key_len);
            }
            if (unknowns->items[i].value) {
                clear_and_free(unknowns->items[i].value, unknowns->items[i].value_len);
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
        struct wally_unknowns_item *new_items;
        size_t new_alloc_len = 1;
        size_t orig_num_items = unknowns->num_items;
        if (unknowns->items_allocation_len != 0) {
            new_alloc_len = unknowns->items_allocation_len * 2;
        }
        new_items = wally_malloc(new_alloc_len * sizeof(struct wally_unknowns_item));
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

#ifdef BUILD_ELEMENTS
int wally_psbt_elements_input_init_alloc(
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
    uint64_t value,
    bool has_value,
    unsigned char *value_blinder,
    size_t value_blinder_len,
    unsigned char *asset,
    size_t asset_len,
    unsigned char *asset_blinder,
    size_t asset_blinder_len,
    struct wally_tx *peg_in_tx,
    unsigned char *txout_proof,
    size_t txout_proof_len,
    unsigned char *genesis_hash,
    size_t genesis_hash_len,
    unsigned char *claim_script,
    size_t claim_script_len,
    struct wally_psbt_input **output)
{
    struct wally_psbt_input *result;
    int ret = wally_psbt_input_init_alloc(non_witness_utxo,
                                          witness_utxo,
                                          redeem_script,
                                          redeem_script_len,
                                          witness_script,
                                          witness_script_len,
                                          final_script_sig,
                                          final_script_sig_len,
                                          final_witness,
                                          keypaths,
                                          partial_sigs,
                                          unknowns,
                                          sighash_type,
                                          output);
    if (ret != WALLY_OK) {
        return ret;
    }

    /* wally_psbt_input_init_alloc will allocate and initialize the input */
    result = *output;

    if (has_value && (ret = wally_psbt_elements_input_set_value(result, value)) != WALLY_OK) {
        goto fail;
    }
    if (value_blinder && (ret = wally_psbt_elements_input_set_value_blinder(result, value_blinder, value_blinder_len)) != WALLY_OK) {
        goto fail;
    }
    if (asset && (ret = wally_psbt_elements_input_set_asset(result, asset, asset_len)) != WALLY_OK) {
        goto fail;
    }
    if (asset_blinder && (ret = wally_psbt_elements_input_set_asset_blinder(result, asset_blinder, asset_blinder_len)) != WALLY_OK) {
        goto fail;
    }
    if (peg_in_tx && (ret = wally_psbt_elements_input_set_peg_in_tx(result, peg_in_tx)) != WALLY_OK) {
        goto fail;
    }
    if (txout_proof && (ret = wally_psbt_elements_input_set_txout_proof(result, txout_proof, txout_proof_len)) != WALLY_OK) {
        goto fail;
    }
    if (genesis_hash && (ret = wally_psbt_elements_input_set_genesis_hash(result, genesis_hash, genesis_hash_len)) != WALLY_OK) {
        goto fail;
    }
    if (claim_script && (ret = wally_psbt_elements_input_set_claim_script(result, claim_script, claim_script_len)) != WALLY_OK) {
        goto fail;
    }

    return ret;

fail:
    wally_psbt_input_free(result);
    *output = NULL;
    return ret;
}
#endif /* BUILD_ELEMENTS */

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
    int res = WALLY_OK;
    struct wally_tx_output *output;

    output = wally_malloc(sizeof(struct wally_tx_output));
    if (!output) return WALLY_ENOMEM;
    wally_clear((void *)output, sizeof(struct wally_tx_output));

    /* Since Elements has a different setup,
     * we just clone the passed in output */
    if ((res = wally_clone_output_to(output, witness_utxo)) != WALLY_OK) {
        return res;
    }
    wally_tx_output_free(input->witness_utxo);
    input->witness_utxo = output;
    return res;
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

#ifdef BUILD_ELEMENTS
int wally_psbt_elements_input_set_value(
    struct wally_psbt_input *input,
    uint64_t value)
{
    input->value = value;
    input->has_value = true;
    return WALLY_OK;
}

int wally_psbt_elements_input_set_value_blinder(
    struct wally_psbt_input *input,
    unsigned char *value_blinder,
    size_t value_blinder_len)
{
    unsigned char *result_value_blinder;

    if (!clone_bytes(&result_value_blinder, value_blinder, value_blinder_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(input->value_blinder);
    input->value_blinder = result_value_blinder;
    input->value_blinder_len = value_blinder_len;
    return WALLY_OK;
}

int wally_psbt_elements_input_set_asset(
    struct wally_psbt_input *input,
    unsigned char *asset,
    size_t asset_len)
{
    unsigned char *result_asset;

    if (!clone_bytes(&result_asset, asset, asset_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(input->asset);
    input->asset = result_asset;
    input->asset_len = asset_len;
    return WALLY_OK;
}

int wally_psbt_elements_input_set_asset_blinder(
    struct wally_psbt_input *input,
    unsigned char *asset_blinder,
    size_t asset_blinder_len)
{
    unsigned char *result_asset_blinder;

    if (!clone_bytes(&result_asset_blinder, asset_blinder, asset_blinder_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(input->asset_blinder);
    input->asset_blinder = result_asset_blinder;
    input->asset_blinder_len = asset_blinder_len;
    return WALLY_OK;
}

int wally_psbt_elements_input_set_peg_in_tx(
    struct wally_psbt_input *input,
    struct wally_tx *peg_in_tx)
{
    int ret = WALLY_OK;
    struct wally_tx *result_peg_in_tx;

    if ((ret = clone_tx(peg_in_tx, &result_peg_in_tx)) != WALLY_OK) {
        return ret;
    }
    wally_tx_free(input->peg_in_tx);
    input->peg_in_tx = result_peg_in_tx;
    return ret;
}


int wally_psbt_elements_input_set_txout_proof(
    struct wally_psbt_input *input,
    unsigned char *txout_proof,
    size_t txout_proof_len)
{
    unsigned char *result_txout_proof;

    if (!clone_bytes(&result_txout_proof, txout_proof, txout_proof_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(input->txout_proof);
    input->txout_proof = result_txout_proof;
    input->txout_proof_len = txout_proof_len;
    return WALLY_OK;
}

int wally_psbt_elements_input_set_genesis_hash(
    struct wally_psbt_input *input,
    unsigned char *genesis_hash,
    size_t genesis_hash_len)
{
    unsigned char *result_genesis_hash;

    if (!clone_bytes(&result_genesis_hash, genesis_hash, genesis_hash_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(input->genesis_hash);
    input->genesis_hash = result_genesis_hash;
    input->genesis_hash_len = genesis_hash_len;
    return WALLY_OK;
}

int wally_psbt_elements_input_set_claim_script(
    struct wally_psbt_input *input,
    unsigned char *claim_script,
    size_t claim_script_len)
{
    unsigned char *result_claim_script;

    if (!clone_bytes(&result_claim_script, claim_script, claim_script_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(input->claim_script);
    input->claim_script = result_claim_script;
    input->claim_script_len = claim_script_len;
    return WALLY_OK;
}
#endif /* BUILD_ELEMENTS */

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
#ifdef BUILD_ELEMENTS
        clear_and_free(input->value_blinder, input->value_blinder_len);
        clear_and_free(input->asset, input->asset_len);
        clear_and_free(input->asset_blinder, input->asset_blinder_len);
        wally_tx_free(input->peg_in_tx);
        clear_and_free(input->txout_proof, input->txout_proof_len);
        clear_and_free(input->genesis_hash, input->genesis_hash_len);
        clear_and_free(input->claim_script, input->claim_script_len);
#endif /* BUILD_ELEMENTS */
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

#ifdef BUILD_ELEMENTS
int wally_psbt_elements_output_init_alloc(
    unsigned char *redeem_script,
    size_t redeem_script_len,
    unsigned char *witness_script,
    size_t witness_script_len,
    struct wally_keypath_map *keypaths,
    struct wally_unknowns_map *unknowns,
    unsigned char blinding_pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN],
    bool has_blinding_pubkey,
    unsigned char *value_commitment,
    size_t value_commitment_len,
    unsigned char *value_blinder,
    size_t value_blinder_len,
    unsigned char *asset_commitment,
    size_t asset_commitment_len,
    unsigned char *asset_blinder,
    size_t asset_blinder_len,
    unsigned char *nonce_commitment,
    size_t nonce_commitment_len,
    unsigned char *range_proof,
    size_t range_proof_len,
    unsigned char *surjection_proof,
    size_t surjection_proof_len,
    struct wally_psbt_output **output)
{
    struct wally_psbt_output *result;
    int ret = wally_psbt_output_init_alloc(redeem_script,
                                           redeem_script_len,
                                           witness_script,
                                           witness_script_len,
                                           keypaths,
                                           unknowns,
                                           output);
    if (ret != WALLY_OK) {
        return ret;
    }

    /* wally_psbt_output_init_alloc allocates for us */
    result = *output;

    if (has_blinding_pubkey && (ret = wally_psbt_elements_output_set_blinding_pubkey(result, blinding_pubkey)) != WALLY_OK) {
        goto fail;
    }
    if (value_commitment && (ret = wally_psbt_elements_output_set_value_commitment(result, value_commitment, value_commitment_len)) != WALLY_OK) {
        goto fail;
    }
    if (value_blinder && (ret = wally_psbt_elements_output_set_value_blinder(result, value_blinder, value_blinder_len)) != WALLY_OK) {
        goto fail;
    }
    if (asset_commitment && (ret = wally_psbt_elements_output_set_asset_commitment(result, asset_commitment, asset_commitment_len)) != WALLY_OK) {
        goto fail;
    }
    if (asset_blinder && (ret = wally_psbt_elements_output_set_asset_blinder(result, asset_blinder, asset_blinder_len)) != WALLY_OK) {
        goto fail;
    }
    if (nonce_commitment && (ret = wally_psbt_elements_output_set_nonce_commitment(result, nonce_commitment, nonce_commitment_len)) != WALLY_OK) {
        goto fail;
    }
    if (range_proof && (ret = wally_psbt_elements_output_set_range_proof(result, range_proof, range_proof_len)) != WALLY_OK) {
        goto fail;
    }
    if (surjection_proof && (ret = wally_psbt_elements_output_set_surjection_proof(result, surjection_proof, surjection_proof_len)) != WALLY_OK) {
        goto fail;
    }

    return ret;

fail:
    wally_psbt_output_free(result);
    *output = NULL;
    return ret;
}
#endif /* BUILD_ELEMENTS */

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

#ifdef BUILD_ELEMENTS
int wally_psbt_elements_output_set_blinding_pubkey(
    struct wally_psbt_output *output,
    unsigned char blinding_pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN])
{
    memcpy(output->blinding_pubkey, blinding_pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
    output->has_blinding_pubkey = true;
    return WALLY_OK;
}

int wally_psbt_elements_output_set_value_commitment(
    struct wally_psbt_output *output,
    unsigned char *value_commitment,
    size_t value_commitment_len)
{
    unsigned char *result_value_commitment;

    if (!clone_bytes(&result_value_commitment, value_commitment, value_commitment_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(output->value_commitment);
    output->value_commitment = value_commitment;
    output->value_commitment_len = value_commitment_len;
    return WALLY_OK;
}

int wally_psbt_elements_output_set_value_blinder(
    struct wally_psbt_output *output,
    unsigned char *value_blinder,
    size_t value_blinder_len)
{
    unsigned char *result_value_blinder;

    if (!clone_bytes(&result_value_blinder, value_blinder, value_blinder_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(output->value_blinder);
    output->value_blinder = value_blinder;
    output->value_blinder_len = value_blinder_len;
    return WALLY_OK;
}

int wally_psbt_elements_output_set_asset_commitment(
    struct wally_psbt_output *output,
    unsigned char *asset_commitment,
    size_t asset_commitment_len)
{
    unsigned char *result_asset_commitment;

    if (!clone_bytes(&result_asset_commitment, asset_commitment, asset_commitment_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(output->asset_commitment);
    output->asset_commitment = asset_commitment;
    output->asset_commitment_len = asset_commitment_len;
    return WALLY_OK;
}

int wally_psbt_elements_output_set_asset_blinder(
    struct wally_psbt_output *output,
    unsigned char *asset_blinder,
    size_t asset_blinder_len)
{
    unsigned char *result_asset_blinder;

    if (!clone_bytes(&result_asset_blinder, asset_blinder, asset_blinder_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(output->asset_blinder);
    output->asset_blinder = asset_blinder;
    output->asset_blinder_len = asset_blinder_len;
    return WALLY_OK;
}

int wally_psbt_elements_output_set_nonce_commitment(
    struct wally_psbt_output *output,
    unsigned char *nonce_commitment,
    size_t nonce_commitment_len)
{
    unsigned char *result_nonce_commitment;

    if (!clone_bytes(&result_nonce_commitment, nonce_commitment, nonce_commitment_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(output->nonce_commitment);
    output->nonce_commitment = nonce_commitment;
    output->nonce_commitment_len = nonce_commitment_len;
    return WALLY_OK;
}

int wally_psbt_elements_output_set_range_proof(
    struct wally_psbt_output *output,
    unsigned char *range_proof,
    size_t range_proof_len)
{
    unsigned char *result_range_proof;

    if (!clone_bytes(&result_range_proof, range_proof, range_proof_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(output->range_proof);
    output->range_proof = range_proof;
    output->range_proof_len = range_proof_len;
    return WALLY_OK;
}

int wally_psbt_elements_output_set_surjection_proof(
    struct wally_psbt_output *output,
    unsigned char *surjection_proof,
    size_t surjection_proof_len)
{
    unsigned char *result_surjection_proof;

    if (!clone_bytes(&result_surjection_proof, surjection_proof, surjection_proof_len)) {
        return WALLY_ENOMEM;
    }
    wally_free(output->surjection_proof);
    output->surjection_proof = surjection_proof;
    output->surjection_proof_len = surjection_proof_len;
    return WALLY_OK;
}
#endif/* BUILD_ELEMENTS */

int wally_psbt_output_free(struct wally_psbt_output *output)
{
    if (output) {
        clear_and_free(output->redeem_script, output->redeem_script_len);
        clear_and_free(output->witness_script, output->witness_script_len);
        wally_keypath_map_free(output->keypaths);
        wally_unknowns_map_free(output->unknowns);
#ifdef BUILD_ELEMENTS
        clear_and_free(output->value_commitment, output->value_commitment_len);
        clear_and_free(output->value_blinder, output->value_blinder_len);
        clear_and_free(output->asset_commitment, output->asset_commitment_len);
        clear_and_free(output->asset_blinder, output->asset_blinder_len);
        clear_and_free(output->nonce_commitment, output->nonce_commitment_len);
        clear_and_free(output->range_proof, output->range_proof_len);
        clear_and_free(output->surjection_proof, output->surjection_proof_len);
#endif /* BUILD_ELEMENTS */
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

    /* Version is always 0 */
    result->version = 0;

    memcpy(result->magic, WALLY_PSBT_MAGIC, 5);

    result->inputs = new_inputs;
    result->num_inputs = 0;
    result->inputs_allocation_len = inputs_allocation_len;
    result->outputs = new_outputs;
    result->num_outputs = 0;
    result->outputs_allocation_len = outputs_allocation_len;
    result->tx = NULL;
    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
int wally_psbt_elements_init_alloc(
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    struct wally_psbt **output)
{
    int ret;

    ret = wally_psbt_init_alloc(inputs_allocation_len, outputs_allocation_len, global_unknowns_allocation_len, output);
    memcpy((*output)->magic, WALLY_ELEMENTS_PSBT_MAGIC, 5);

    return ret;
}
#endif /* BUILD_ELEMENTS */

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

    /* Needs a psbt that is completely empty, i.e. no tx, no inputs, and no outputs. */
    if (!tx || !psbt || psbt->tx || psbt->num_inputs != 0 || psbt->num_outputs != 0) {
        return WALLY_EINVAL;
    }

    /* tx cannot have any scriptSigs or witnesses */
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

/* Returns false if it hits a zero length "key" (i.e. separator) or EOF.
 *
 * Otherwise, starts the subfield (extra, extra_len), so caller should
 * call pull_subfield_end(cursor, max, extra, extra_len) if this
 * returns true.
 */
static bool pull_psbt_key_start(
    const unsigned char **cursor, size_t *max,
    uint64_t *type,
    const unsigned char **extra, size_t *extra_len)
{
    size_t key_len;

    key_len = pull_varlength(cursor, max);
    /* This incidentally covers the case where *cursor is NULL */
    if (key_len == 0) {
        return false;
    }
    pull_subfield_start(cursor, max, key_len, extra, extra_len);
    *type = pull_varint(cursor, max);
    return true;
}

/* clones varlength field entirely. */
static bool clone_varlength(unsigned char **dst,
                            size_t *len,
                            const unsigned char **cursor, size_t *max)
{
    *len = pull_varlength(cursor, max);
    return clone_bytes(dst, pull_skip(cursor, max, *len), *len);
}

/* Stricter version of pull_subfield_end which insists there's nothing left. */
static void subfield_nomore_end(const unsigned char **cursor, size_t *max,
                                const unsigned char *subcursor,
                                const size_t submax)
{
    if (submax) {
        pull_failed(cursor, max);
    } else {
        pull_subfield_end(cursor, max, subcursor, submax);
    }
}

/* The remainder of the key is a public key, the value is a keypath */
static int pull_keypath(const unsigned char **cursor, size_t *max,
                        const unsigned char *key, size_t key_len,
                        struct wally_keypath_map *keypaths)
{
    const unsigned char *val;
    size_t i, val_max;
    struct wally_keypath_item *kpitem;

    if (key_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN
        && key_len != EC_PUBLIC_KEY_LEN) {
        return WALLY_EINVAL;     /* Size of key is unexpected */
    }

    /* Check for duplicates */
    for (i = 0; i < keypaths->num_items; ++i) {
        if (memcmp(keypaths->items[i].pubkey, key, key_len) == 0) {
            return WALLY_EINVAL;     /* Duplicate key */
        }
    }

    assert(keypaths->num_items < keypaths->items_allocation_len);
    kpitem = &keypaths->items[keypaths->num_items++];

    memcpy(kpitem->pubkey, key, key_len);
    pull_subfield_end(cursor, max, key, key_len);

    /* Start parsing the value field. */
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

    /* Read the fingerprint */
    pull_bytes(kpitem->origin.fingerprint, sizeof(kpitem->origin.fingerprint),
               &val, &val_max);

    /* Remainder is the path */
    kpitem->origin.path_len = val_max / sizeof(uint32_t);
    kpitem->origin.path = wally_malloc(val_max);
    if (kpitem->origin.path == NULL) {
        return WALLY_ENOMEM;
    }
    for (i = 0; val_max >= sizeof(uint32_t); ++i) {
        kpitem->origin.path[i] = pull_le32(&val, &val_max);
    }
    subfield_nomore_end(cursor, max, val, val_max);
    return WALLY_OK;
}

/* Rewind cursor to prekey, and append unknown key/value to unknowns */
static int pull_unknown_key_value(const unsigned char **cursor,
                                  size_t *max,
                                  const unsigned char *pre_key,
                                  struct wally_unknowns_map *unknowns)
{
    struct wally_unknowns_item *item;

    /* If we've already failed, it's invalid */
    if (!*cursor) {
        return WALLY_EINVAL;
    }

    /* We have to unwind a bit, to get entire key again. */
    *max += (*cursor - pre_key);
    *cursor = pre_key;

    assert(unknowns->num_items < unknowns->items_allocation_len);
    item = &unknowns->items[unknowns->num_items++];

    if (!clone_varlength(&item->key, &item->key_len, cursor, max)) {
        return WALLY_ENOMEM;
    }
    if (!clone_varlength(&item->value, &item->value_len, cursor, max)) {
        return WALLY_ENOMEM;
    }
    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
static size_t push_elements_bytes_size(const struct wally_tx_output *out)
{
    size_t size = 0;
    size += out->asset_len == 0 ? 1 : out->asset_len;
    size += out->value_len == 0 ? 1 : out->value_len;
    size += out->nonce_len == 0 ? 1 : out->nonce_len;
    size += out->script_len == 0 ? 1 : out->script_len + 1;
    return size;
}
static void push_elements_bytes(unsigned char **cursor,
                                size_t *max,
                                unsigned char *value,
                                size_t val_len)
{
    if (value == NULL) {
        unsigned char empty[1] = { 0x00 };
        push_bytes(cursor, max, empty, sizeof(empty));
    } else {
        push_bytes(cursor, max,
                   value, val_len);
    }
}

static int pull_elements_confidential(const unsigned char **cursor,
                                      size_t *max,
                                      unsigned char **value,
                                      size_t *val_len,
                                      size_t prefixA, size_t prefixB,
                                      size_t prefixedSize, size_t explicitSize)
{
    uint8_t type = peek_u8(cursor, max);
    /*The first byte is always the 'version'
     * which tells you what the value is */
    switch (type) {
    /* Empty */
    case 0:
        /* Pop off the type */
        pull_u8(cursor, max);
        *value = NULL;
        *val_len = 0;
        return WALLY_OK;
    /* Explicit size */
    case 1:
        *value = wally_malloc(explicitSize);
        pull_bytes(*value, explicitSize, cursor, max);
        if (!*cursor)
            return WALLY_EINVAL;
        *val_len = explicitSize;
        return WALLY_OK;
    }
    if (type == prefixA || type == prefixB) {
        *value = wally_malloc(prefixedSize);
        pull_bytes(*value, prefixedSize, cursor, max);
        if (!*cursor)
            return WALLY_EINVAL;
        *val_len = prefixedSize;
        return WALLY_OK;
    }
    return WALLY_EINVAL;
}

/* Either returns a 33-byte commitment to a confidential value, or
 * a 64-bit explicit value. */
static int pull_confidential_value(const unsigned char **cursor,
                                   size_t *max,
                                   unsigned char **value,
                                   size_t *val_len)

{
    return pull_elements_confidential(cursor, max, value, val_len,
                                      WALLY_TX_ASSET_CT_VALUE_PREFIX_A, WALLY_TX_ASSET_CT_VALUE_PREFIX_B,
                                      WALLY_TX_ASSET_CT_VALUE_LEN, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
}

static int pull_confidential_asset(const unsigned char **cursor,
                                   size_t *max,
                                   unsigned char **asset,
                                   size_t *asset_len)

{
    return pull_elements_confidential(cursor, max, asset, asset_len,
                                      WALLY_TX_ASSET_CT_ASSET_PREFIX_A, WALLY_TX_ASSET_CT_ASSET_PREFIX_B,
                                      WALLY_TX_ASSET_CT_ASSET_LEN, WALLY_TX_ASSET_CT_ASSET_LEN);
}

static int pull_nonce(const unsigned char **cursor,
                      size_t *max,
                      unsigned char **nonce,
                      size_t *nonce_len)

{
    return pull_elements_confidential(cursor, max, nonce, nonce_len,
                                      WALLY_TX_ASSET_CT_NONCE_PREFIX_A, WALLY_TX_ASSET_CT_NONCE_PREFIX_B,
                                      WALLY_TX_ASSET_CT_NONCE_LEN, WALLY_TX_ASSET_CT_NONCE_LEN);
}

#endif /* BUILD_ELEMENTS */

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

static int count_psbt_parts(
    const unsigned char *bytes,
    size_t bytes_len,
    bool is_elements,
    struct psbt_counts **output)
{
    int ret;
    size_t i, key_len;
    struct psbt_counts *result;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct psbt_counts);

    result->num_global_unknowns = 0;
    result->num_inputs = 0;
    result->num_outputs = 0;

    /* Go through globals and count */
    while ((key_len = pull_varlength(&bytes, &bytes_len)) != 0) {
        const unsigned char *key;

        /* Start parsing key */
        pull_subfield_start(&bytes, &bytes_len, key_len, &key, &key_len);

        /* Process based on type */
        switch (pull_varint(&key, &key_len)) {
        case WALLY_PSBT_GLOBAL_UNSIGNED_TX: {
            bool expect_wit;
            const unsigned char *val;
            size_t val_max;
            int flags = 0;
            subfield_nomore_end(&bytes, &bytes_len, key, key_len);

            /* Value should be a tx */
            val_max = pull_varint(&bytes, &bytes_len);
            val = pull_skip(&bytes, &bytes_len, val_max);
            if (!val) {
                ret = WALLY_EINVAL;
                goto fail;
            }
            if (is_elements) {
                flags |= WALLY_TX_FLAG_USE_ELEMENTS;
            }
            ret = analyze_tx(val, val_max, flags, &result->num_inputs, &result->num_outputs, &expect_wit);
            if (ret != WALLY_OK) {
                goto fail;
            }
            if ((result->input_counts = wally_malloc(result->num_inputs * sizeof(struct psbt_input_counts))) == NULL ||
                (result->output_counts = wally_malloc(result->num_outputs * sizeof(struct psbt_output_counts))) == NULL) {
                ret = WALLY_ENOMEM;
                goto fail;
            }
            break;
        }
        case WALLY_PSBT_GLOBAL_VERSION:
            pull_subfield_end(&bytes, &bytes_len, key, key_len);
            /* Skip over value */
            pull_skip(&bytes, &bytes_len, pull_varint(&bytes, &bytes_len));
            break;
        /* Unknowns */
        default:
            result->num_global_unknowns++;
            pull_subfield_end(&bytes, &bytes_len, key, key_len);
            /* Skip over value */
            pull_skip(&bytes, &bytes_len, pull_varint(&bytes, &bytes_len));
        }
    }

    /* Go through each input */
    for (i = 0; i < result->num_inputs; ++i) {
        struct psbt_input_counts *input = &result->input_counts[i];
        input->num_keypaths = 0;
        input->num_partial_sigs = 0;
        input->num_unknowns = 0;

        while ((key_len = pull_varlength(&bytes, &bytes_len)) != 0) {
            const unsigned char *key;

            /* Start parsing key */
            pull_subfield_start(&bytes, &bytes_len, key_len, &key, &key_len);

            /* Process based on type */
            switch (pull_varint(&key, &key_len)) {
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
            case WALLY_PSBT_PROPRIETARY_TYPE: {
#ifdef BUILD_ELEMENTS
                uint64_t id_len;
                bool valid_type = false;

                id_len = pull_varlength(&key, &key_len);
                if (id_len == WALLY_ELEMENTS_ID_LEN && memcmp(key, WALLY_ELEMENTS_ID, id_len) == 0) {
                    pull_skip(&key, &key_len, id_len);

                    switch (pull_varint(&key, &key_len)) {
                    case WALLY_PSBT_IN_ELEMENTS_VALUE:
                    case WALLY_PSBT_IN_ELEMENTS_VALUE_BLINDER:
                    case WALLY_PSBT_IN_ELEMENTS_ASSET:
                    case WALLY_PSBT_IN_ELEMENTS_ASSET_BLINDER:
                    case WALLY_PSBT_IN_ELEMENTS_PEG_IN_TX:
                    case WALLY_PSBT_IN_ELEMENTS_TXOUT_PROOF:
                    case WALLY_PSBT_IN_ELEMENTS_GENESIS_HASH:
                    case WALLY_PSBT_IN_ELEMENTS_CLAIM_SCRIPT:
                        valid_type = true;
                        break;
                    default:
                        valid_type = false;
                    }
                }
                if (valid_type) {
                    break;
                }
#endif /* BUILD_ELEMENTS */
            }
            /* For unknown case without elements or for unknown proprietary types */
            /* fall through */
            /* Unknowns */
            default:
                input->num_unknowns++;
            }
            pull_subfield_end(&bytes, &bytes_len, key, key_len);
            /* Skip over value */
            pull_skip(&bytes, &bytes_len, pull_varint(&bytes, &bytes_len));
        }
    }

    /* Go through each output */
    for (i = 0; i < result->num_outputs; ++i) {
        struct psbt_output_counts *psbt_output = &result->output_counts[i];
        psbt_output->num_keypaths = 0;
        psbt_output->num_unknowns = 0;

        while ((key_len = pull_varlength(&bytes, &bytes_len)) != 0) {
            const unsigned char *key;

            /* Start parsing key */
            pull_subfield_start(&bytes, &bytes_len, key_len, &key, &key_len);

            /* Process based on type */
            switch (pull_varint(&key, &key_len)) {
            case WALLY_PSBT_OUT_REDEEM_SCRIPT:
            case WALLY_PSBT_OUT_WITNESS_SCRIPT:
                break;
            case WALLY_PSBT_OUT_BIP32_DERIVATION:
                psbt_output->num_keypaths++;
                break;
            case WALLY_PSBT_PROPRIETARY_TYPE: {
#ifdef BUILD_ELEMENTS
                uint64_t id_len;
                bool valid_type = false;

                id_len = pull_varlength(&key, &key_len);
                if (id_len == WALLY_ELEMENTS_ID_LEN && memcmp(key, WALLY_ELEMENTS_ID, id_len) == 0) {
                    pull_skip(&key, &key_len, id_len);

                    switch (pull_varint(&key, &key_len)) {
                    case WALLY_PSBT_OUT_ELEMENTS_VALUE_COMMITMENT:
                    case WALLY_PSBT_OUT_ELEMENTS_VALUE_BLINDER:
                    case WALLY_PSBT_OUT_ELEMENTS_ASSET_COMMITMENT:
                    case WALLY_PSBT_OUT_ELEMENTS_ASSET_BLINDER:
                    case WALLY_PSBT_OUT_ELEMENTS_RANGE_PROOF:
                    case WALLY_PSBT_OUT_ELEMENTS_SURJECTION_PROOF:
                    case WALLY_PSBT_OUT_ELEMENTS_BLINDING_PUBKEY:
                    case WALLY_PSBT_OUT_ELEMENTS_NONCE_COMMITMENT:
                        valid_type = true;
                        break;
                    default:
                        valid_type = false;
                    }
                }
                if (valid_type) {
                    break;
                }
#endif /* BUILD_ELEMENTS */
            }
            /* For unknown case without elements or for unknown proprietary types */
            /* fall through */
            /* Unknowns */
            default:
                psbt_output->num_unknowns++;
            }

            pull_subfield_end(&bytes, &bytes_len, key, key_len);
            /* Skip over value */
            pull_skip(&bytes, &bytes_len, pull_varint(&bytes, &bytes_len));
        }
    }

    /* Either we ran short, or had too much? */
    if (bytes == NULL || bytes_len != 0) {
        ret = WALLY_EINVAL;
        goto fail;
    }

    return WALLY_OK;

fail:
    free_psbt_count(result);
    *output = NULL;
    return ret;
}

static int pull_psbt_input(
    const unsigned char **cursor,
    size_t *max,
    struct psbt_input_counts counts,
    bool is_elements,
    struct wally_psbt_input *result)
{
    int ret;
    size_t key_len;
    const unsigned char *pre_key;

    /* Init and alloc the maps */
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

    /* Read key value pairs */
    pre_key = *cursor;
    while ((key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key, *val;
        size_t val_max;

        /* Start parsing key */
        pull_subfield_start(cursor, max, key_len, &key, &key_len);

        /* Process based on type */
        switch (pull_varint(&key, &key_len)) {
        case WALLY_PSBT_IN_NON_WITNESS_UTXO: {
            int flags = 0;
            if (result->non_witness_utxo) {
                return WALLY_EINVAL;     /* We already have a non witness utxo */
            }
            subfield_nomore_end(cursor, max, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(cursor, max,
                                pull_varint(cursor, max),
                                &val, &val_max);
            if (is_elements) {
                flags |= WALLY_TX_FLAG_USE_ELEMENTS;
            }
            ret = wally_tx_from_bytes(val, val_max, flags,
                                      &result->non_witness_utxo);
            if (ret != WALLY_OK) {
                return ret;
            }
            pull_subfield_end(cursor, max, val, val_max);
            break;
        }
        case WALLY_PSBT_IN_WITNESS_UTXO: {
            uint64_t amount, script_len;
            const unsigned char *script;
            if (result->witness_utxo) {
                return WALLY_EINVAL;     /* We already have a witness utxo */
            }
            subfield_nomore_end(cursor, max, key, key_len);
            /* Start parsing the value field. */
            pull_subfield_start(cursor, max,
                                pull_varint(cursor, max),
                                &val, &val_max);
#ifdef BUILD_ELEMENTS
            if (is_elements) {
                unsigned char *asset, *value, *nonce;
                size_t asset_len, value_len, nonce_len;
                if ((ret = pull_confidential_asset(&val, &val_max, &asset, &asset_len)) != WALLY_OK) {
                    return ret;
                }
                if ((ret = pull_confidential_value(&val, &val_max, &value, &value_len)) != WALLY_OK) {
                    return ret;
                }
                if ((ret = pull_nonce(&val, &val_max, &nonce, &nonce_len)) != WALLY_OK) {
                    return ret;
                }
                script_len = pull_varint(&val, &val_max);
                script = pull_skip(&val, &val_max, script_len);
                if (!script) {
                    return WALLY_EINVAL;
                }
                ret = wally_tx_elements_output_init_alloc(script, script_len,
                                                          asset, asset_len,
                                                          value, value_len,
                                                          nonce, nonce_len,
                                                          NULL, 0, NULL, 0,
                                                          &result->witness_utxo);
                if (ret != WALLY_OK) {
                    return ret;
                }
                subfield_nomore_end(cursor, max, val, val_max);
                break;
            }
#endif /* BUILD_ELEMENTS */

            amount = pull_le64(&val, &val_max);
            script_len = pull_varint(&val, &val_max);
            script = pull_skip(&val, &val_max, script_len);
            if (!script) {
                return WALLY_EINVAL;
            }
            ret = wally_tx_output_init_alloc(amount, script, script_len,
                                             &result->witness_utxo);
            if (ret != WALLY_OK) {
                return ret;
            }
            subfield_nomore_end(cursor, max, val, val_max);
            break;
        }
        case WALLY_PSBT_IN_PARTIAL_SIG: {
            size_t i;
            struct wally_partial_sigs_item *sigitem;
            struct wally_partial_sigs_map *partial_sigs = result->partial_sigs;
            if (key_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN
                && key_len != EC_PUBLIC_KEY_LEN) {
                return WALLY_EINVAL;     /* Size of key is unexpected */
            }
            /* Check for duplicates */
            for (i = 0; i < partial_sigs->num_items; ++i) {
                if (memcmp(partial_sigs->items[i].pubkey, key, key_len) == 0) {
                    return WALLY_EINVAL;     /* Duplicate key */
                }
            }

            sigitem = &partial_sigs->items[partial_sigs->num_items];
            memcpy(sigitem->pubkey, key, key_len);
            pull_subfield_end(cursor, max, key, key_len);

            if (!clone_varlength(&sigitem->sig, &sigitem->sig_len,
                                 cursor, max)) {
                return WALLY_ENOMEM;
            }
            partial_sigs->num_items++;
            break;
        }
        case WALLY_PSBT_IN_SIGHASH_TYPE: {
            if (result->sighash_type > 0) {
                return WALLY_EINVAL;     /* Sighash already provided */
            }
            subfield_nomore_end(cursor, max, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(cursor, max,
                                pull_varint(cursor, max),
                                &val, &val_max);
            result->sighash_type = pull_le32(&val, &val_max);
            subfield_nomore_end(cursor, max, val, val_max);
            break;
        }
        case WALLY_PSBT_IN_REDEEM_SCRIPT: {
            if (result->redeem_script) {
                return WALLY_EINVAL;     /* Already have a redeem script */
            }
            subfield_nomore_end(cursor, max, key, key_len);

            if (!clone_varlength(&result->redeem_script,
                                 &result->redeem_script_len,
                                 cursor, max)) {
                return WALLY_ENOMEM;
            }
            if (result->redeem_script_len == 0) {
                result->redeem_script = wally_malloc(1);
            }
            break;
        }
        case WALLY_PSBT_IN_WITNESS_SCRIPT: {
            if (result->witness_script) {
                return WALLY_EINVAL;     /* Already have a witness script */
            }
            subfield_nomore_end(cursor, max, key, key_len);

            if (!clone_varlength(&result->witness_script,
                                 &result->witness_script_len,
                                 cursor, max)) {
                return WALLY_ENOMEM;
            }
            if (result->witness_script_len == 0) {
                result->witness_script = wally_malloc(1);
            }
            break;
        }
        case WALLY_PSBT_IN_BIP32_DERIVATION: {
            ret = pull_keypath(cursor, max, key, key_len, result->keypaths);
            if (ret != WALLY_OK) {
                return ret;
            }
            break;
        }
        case WALLY_PSBT_IN_FINAL_SCRIPTSIG: {
            if (result->final_script_sig) {
                return WALLY_EINVAL;     /* Already have a scriptSig */
            }
            subfield_nomore_end(cursor, max, key, key_len);

            if (!clone_varlength(&result->final_script_sig,
                                 &result->final_script_sig_len,
                                 cursor, max)) {
                return WALLY_ENOMEM;
            }
            if (result->final_script_sig_len == 0) {
                result->final_script_sig = wally_malloc(1);
            }
            break;
        }
        case WALLY_PSBT_IN_FINAL_SCRIPTWITNESS: {
            uint64_t num_witnesses;
            size_t i;
            if (result->final_witness) {
                return WALLY_EINVAL;     /* Already have a scriptWitness */
            }
            subfield_nomore_end(cursor, max, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(cursor, max,
                                pull_varint(cursor, max),
                                &val, &val_max);
            num_witnesses = pull_varint(&val, &val_max);
            ret = wally_tx_witness_stack_init_alloc(num_witnesses, &result->final_witness);
            if (ret != WALLY_OK) {
                return ret;
            }

            for (i = 0; i < num_witnesses; ++i) {
                uint64_t witness_len = pull_varint(&val, &val_max);
                ret = wally_tx_witness_stack_set(result->final_witness, i,
                                                 pull_skip(&val, &val_max, witness_len),
                                                 witness_len);
                if (ret != WALLY_OK) {
                    return ret;
                }
            }
            subfield_nomore_end(cursor, max, val, val_max);
            break;
        }
        case WALLY_PSBT_PROPRIETARY_TYPE: {
#ifdef BUILD_ELEMENTS
            uint64_t id_len;
            bool valid_type = false;

            id_len = pull_varlength(&key, &key_len);
            if (id_len == WALLY_ELEMENTS_ID_LEN && memcmp(key, WALLY_ELEMENTS_ID, id_len) == 0) {
                /* Skip the elements_id prefix */
                pull_skip(&key, &key_len, WALLY_ELEMENTS_ID_LEN);

                switch (pull_varint(&key, &key_len)) {
                case WALLY_PSBT_IN_ELEMENTS_VALUE: {
                    valid_type = true;
                    if (result->has_value) {
                        return WALLY_EINVAL;    /* Already have value */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    /* Start parsing the value field. */
                    pull_subfield_start(cursor, max,
                                        pull_varint(cursor, max),
                                        &val, &val_max);
                    result->value = pull_le64(&val, &val_max);
                    subfield_nomore_end(cursor, max, val, val_max);
                    result->has_value = true;
                    break;
                }
                case WALLY_PSBT_IN_ELEMENTS_VALUE_BLINDER: {
                    valid_type = true;
                    if (result->value_blinder) {
                        return WALLY_EINVAL;    /* Already have value blinding factor */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->value_blinder,
                                         &result->value_blinder_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->value_blinder_len == 0) {
                        result->value_blinder = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_IN_ELEMENTS_ASSET: {
                    valid_type = true;
                    if (result->asset) {
                        return WALLY_EINVAL;    /* Already have asset */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->asset,
                                         &result->asset_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->asset_len == 0) {
                        result->asset = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_IN_ELEMENTS_ASSET_BLINDER: {
                    valid_type = true;
                    if (result->asset_blinder) {
                        return WALLY_EINVAL;    /* Already have asset blinding factor */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->asset_blinder,
                                         &result->asset_blinder_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->asset_blinder_len == 0) {
                        result->asset_blinder = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_IN_ELEMENTS_PEG_IN_TX: {
                    valid_type = true;
                    if (result->peg_in_tx) {
                        return WALLY_EINVAL;    /* Already have asset */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    /* Start parsing the value field. */
                    pull_subfield_start(cursor, max,
                                        pull_varint(cursor, max),
                                        &val, &val_max);

                    ret = wally_tx_from_bytes(val, val_max, WALLY_TX_FLAG_USE_ELEMENTS,
                                              &result->peg_in_tx);
                    if (ret != WALLY_OK) {
                        return ret;
                    }
                    pull_subfield_end(cursor, max, val, val_max);
                    break;
                }
                case WALLY_PSBT_IN_ELEMENTS_TXOUT_PROOF: {
                    valid_type = true;
                    if (result->txout_proof) {
                        return WALLY_EINVAL;    /* Already have txout proof */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->txout_proof,
                                         &result->txout_proof_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->txout_proof_len == 0) {
                        result->txout_proof = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_IN_ELEMENTS_GENESIS_HASH: {
                    valid_type = true;
                    if (result->genesis_hash) {
                        return WALLY_EINVAL;    /* Already have genesis hash */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->genesis_hash,
                                         &result->genesis_hash_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->genesis_hash_len == 0) {
                        result->genesis_hash = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_IN_ELEMENTS_CLAIM_SCRIPT: {
                    valid_type = true;
                    if (result->claim_script) {
                        return WALLY_EINVAL;    /* Already have asset */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->claim_script,
                                         &result->claim_script_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->claim_script_len == 0) {
                        result->claim_script = wally_malloc(1);
                    }
                    break;
                }
                default:
                    valid_type = false;
                }
            }
            if (valid_type) {
                break;
            }
#endif /* BUILD_ELEMENTS */
        }
        /* For unknown case without elements or for unknown proprietary types */
        /* fall through */
        /* Unknowns */
        default: {
            ret = pull_unknown_key_value(cursor, max, pre_key, result->unknowns);
            if (ret != WALLY_OK) {
                return ret;
            }
            break;
        }
        }
        pre_key = *cursor;

    }

    return WALLY_OK;
}

static int pull_psbt_output(
    const unsigned char **cursor,
    size_t *max,
    struct psbt_output_counts counts,
    struct wally_psbt_output *result)
{
    int ret;
    size_t key_len;
    const unsigned char *pre_key;

    /* Init and alloc the maps */
    if (counts.num_keypaths > 0) {
        wally_keypath_map_init_alloc(counts.num_keypaths, &result->keypaths);
    }
    if (counts.num_unknowns > 0) {
        wally_unknowns_map_init_alloc(counts.num_unknowns, &result->unknowns);
    }

    /* Read key value */
    pre_key = *cursor;
    while ((key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key;

        /* Start parsing key */
        pull_subfield_start(cursor, max, key_len, &key, &key_len);

        /* Process based on type */
        switch (pull_varint(&key, &key_len)) {
        case WALLY_PSBT_OUT_REDEEM_SCRIPT: {
            if (result->redeem_script) {
                return WALLY_EINVAL;     /* Already have a redeem script */
            }
            subfield_nomore_end(cursor, max, key, key_len);

            if (!clone_varlength(&result->redeem_script,
                                 &result->redeem_script_len,
                                 cursor, max)) {
                return WALLY_ENOMEM;
            }
            if (result->redeem_script_len == 0) {
                result->redeem_script = wally_malloc(1);
            }
            break;
        }
        case WALLY_PSBT_OUT_WITNESS_SCRIPT: {
            if (result->witness_script) {
                return WALLY_EINVAL;     /* Already have a witness script */
            }
            subfield_nomore_end(cursor, max, key, key_len);

            if (!clone_varlength(&result->witness_script,
                                 &result->witness_script_len,
                                 cursor, max)) {
                return WALLY_ENOMEM;
            }
            if (result->witness_script_len == 0) {
                result->witness_script = wally_malloc(1);
            }
            break;
        }
        case WALLY_PSBT_OUT_BIP32_DERIVATION: {
            ret = pull_keypath(cursor, max, key, key_len, result->keypaths);
            if (ret != WALLY_OK) {
                return ret;
            }
            break;
        }
        case WALLY_PSBT_PROPRIETARY_TYPE: {
#ifdef BUILD_ELEMENTS
            uint64_t id_len;
            bool valid_type = false;

            id_len = pull_varlength(&key, &key_len);
            if (id_len == WALLY_ELEMENTS_ID_LEN && memcmp(key, WALLY_ELEMENTS_ID, id_len) == 0) {
                /* Skip the elements_id prefix */
                pull_skip(&key, &key_len, WALLY_ELEMENTS_ID_LEN);

                switch (pull_varint(&key, &key_len)) {
                case WALLY_PSBT_OUT_ELEMENTS_VALUE_COMMITMENT: {
                    valid_type = true;
                    if (result->value_commitment) {
                        return WALLY_EINVAL;    /* Already have value commitment */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->value_commitment,
                                         &result->value_commitment_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->value_commitment_len == 0) {
                        result->value_commitment = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_OUT_ELEMENTS_VALUE_BLINDER: {
                    valid_type = true;
                    if (result->value_blinder) {
                        return WALLY_EINVAL;    /* Already have value blinder */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->value_blinder,
                                         &result->value_blinder_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->value_blinder_len == 0) {
                        result->value_blinder = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_OUT_ELEMENTS_ASSET_COMMITMENT: {
                    valid_type = true;
                    if (result->asset_commitment) {
                        return WALLY_EINVAL;    /* Already have asset commitment */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->asset_commitment,
                                         &result->asset_commitment_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->asset_commitment_len == 0) {
                        result->asset_commitment = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_OUT_ELEMENTS_ASSET_BLINDER: {
                    valid_type = true;
                    if (result->asset_blinder) {
                        return WALLY_EINVAL;    /* Already have asset blinder */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->asset_blinder,
                                         &result->asset_blinder_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->asset_blinder_len == 0) {
                        result->asset_blinder = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_OUT_ELEMENTS_RANGE_PROOF: {
                    valid_type = true;
                    if (result->range_proof) {
                        return WALLY_EINVAL;    /* Already have range proof */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->range_proof,
                                         &result->range_proof_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->range_proof_len == 0) {
                        result->range_proof = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_OUT_ELEMENTS_SURJECTION_PROOF: {
                    valid_type = true;
                    if (result->surjection_proof) {
                        return WALLY_EINVAL;    /* Already have surjection proof */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->surjection_proof,
                                         &result->surjection_proof_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->surjection_proof_len == 0) {
                        result->surjection_proof = wally_malloc(1);
                    }
                    break;
                }
                case WALLY_PSBT_OUT_ELEMENTS_BLINDING_PUBKEY: {
                    const unsigned char *val;
                    size_t val_max;
                    valid_type = true;
                    if (result->has_blinding_pubkey) {
                        return WALLY_EINVAL;    /* Already have blinding pubkey */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    /* Start parsing the value field. */
                    pull_subfield_start(cursor, max,
                                        pull_varint(cursor, max),
                                        &val, &val_max);
                    if (val_max != EC_PUBLIC_KEY_UNCOMPRESSED_LEN && val_max != EC_PUBLIC_KEY_LEN) {
                        return WALLY_EINVAL;    /* Size of key is unexpected */
                    }
                    memcpy(result->blinding_pubkey, val, val_max);
                    result->has_blinding_pubkey = true;

                    pull_subfield_end(cursor, max, val, val_max);
                    break;
                }
                case WALLY_PSBT_OUT_ELEMENTS_NONCE_COMMITMENT: {
                    valid_type = true;
                    if (result->nonce_commitment) {
                        return WALLY_EINVAL;    /* Already have nonce commitment */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->nonce_commitment,
                                         &result->nonce_commitment_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (result->nonce_commitment_len == 0) {
                        result->nonce_commitment = wally_malloc(1);
                    }
                    break;
                }
                default:
                    valid_type = false;
                }
            }
            if (valid_type) {
                break;
            }
#endif /* BUILD_ELEMENTS */
        }
        /* For unknown case without elements or for unknown proprietary types */
        /* fall through */
        /* Unknowns */
        default: {
            ret = pull_unknown_key_value(cursor, max, pre_key, result->unknowns);
            if (ret != WALLY_OK) {
                return ret;
            }
            break;
        }
        }
        pre_key = *cursor;
    }

    return WALLY_OK;
}

int wally_psbt_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_psbt **output)
{
    const unsigned char *magic, *pre_key;
    int ret;
    size_t i, key_len;
    struct psbt_counts *counts = NULL;
    struct wally_psbt *result = NULL;
    bool is_elements = false;

    TX_CHECK_OUTPUT;

    magic = pull_skip(&bytes, &bytes_len, sizeof(WALLY_PSBT_MAGIC));
    if (!magic) {
        ret = WALLY_EINVAL;  /* Not enough bytes */
        goto fail;
    }
    if (memcmp(magic, WALLY_PSBT_MAGIC, sizeof(WALLY_PSBT_MAGIC)) != 0 ) {
#ifdef BUILD_ELEMENTS
        if (memcmp(magic, WALLY_ELEMENTS_PSBT_MAGIC, sizeof(WALLY_ELEMENTS_PSBT_MAGIC)) != 0) {
            ret = WALLY_EINVAL;  /* Invalid Magic */
            goto fail;
        }
        is_elements = true;
#else
        ret = WALLY_EINVAL;  /* Invalid Magic */
        goto fail;
#endif /* BUILD_ELEMENTS */
    }

    /* Get a count of the psbt parts */
    if (count_psbt_parts(bytes, bytes_len, is_elements, &counts) != WALLY_OK) {
        ret = WALLY_EINVAL;
        goto fail;
    }

    /* Make the wally_psbt */
    ret = wally_psbt_init_alloc(counts->num_inputs, counts->num_outputs, counts->num_global_unknowns, &result);
    if (ret != WALLY_OK) {
        goto fail;
    }
    *output = result;

    /* Set the magic */
    memcpy(result->magic, magic, 5);

    /* Read globals first */
    pre_key = bytes;
    while ((key_len = pull_varlength(&bytes, &bytes_len)) != 0) {
        const unsigned char *key, *val;
        size_t val_max;

        /* Start parsing key */
        pull_subfield_start(&bytes, &bytes_len, key_len, &key, &key_len);

        /* Process based on type */
        switch (pull_varint(&key, &key_len)) {
        case WALLY_PSBT_GLOBAL_UNSIGNED_TX: {
            int flags = 0;
            if (result->tx) {
                ret = WALLY_EINVAL;     /* We already have a global tx */
                goto fail;
            }
            subfield_nomore_end(&bytes, &bytes_len, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(&bytes, &bytes_len,
                                pull_varint(&bytes, &bytes_len),
                                &val, &val_max);
            if (is_elements) {
                flags |= WALLY_TX_FLAG_USE_ELEMENTS;
            }
            ret = wally_tx_from_bytes(val, val_max, flags, &result->tx);
            if (ret != WALLY_OK) {
                goto fail;
            }
            pull_subfield_end(&bytes, &bytes_len, val, val_max);

            /* Make sure there are no scriptSigs and scriptWitnesses */
            for (i = 0; i < result->tx->num_inputs; ++i) {
                if (result->tx->inputs[i].script_len != 0 || (result->tx->inputs[i].witness && result->tx->inputs[i].witness->num_items != 0)) {
                    ret = WALLY_EINVAL;     /* Unsigned tx needs empty scriptSigs and scriptWtinesses */
                    goto fail;
                }
            }
            break;
        }
        case WALLY_PSBT_GLOBAL_VERSION: {
            if (result->version > 0) {
                ret = WALLY_EINVAL;    /* Version already provided */
                goto fail;
            }
            subfield_nomore_end(&bytes, &bytes_len, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(&bytes, &bytes_len,
                                pull_varint(&bytes, &bytes_len),
                                &val, &val_max);
            result->version = pull_le32(&val, &val_max);
            subfield_nomore_end(&bytes, &bytes_len, val, val_max);
            if (result->version > WALLY_PSBT_HIGHEST_VERSION) {
                ret = WALLY_EINVAL;    /* Unsupported version number */
                goto fail;
            }
            break;
        }
        /* Unknowns */
        default: {
            ret = pull_unknown_key_value(&bytes, &bytes_len, pre_key,
                                         result->unknowns);
            if (ret != WALLY_OK) {
                return ret;
            }
            break;
        }
        }
        pre_key = bytes;
    }

    /* We don't technically need to test here, but it's a minor optimization */
    if (!bytes) {
        ret = WALLY_EINVAL; /* Missing global separator */
        goto fail;
    }

    if (!result->tx) {
        ret = WALLY_EINVAL; /* No global tx */
        goto fail;
    }

    /* Read inputs */
    for (i = 0; i < counts->num_inputs; ++i) {
        ret = pull_psbt_input(&bytes, &bytes_len, counts->input_counts[i], is_elements,
                              &result->inputs[i]);
        /* Increment this now, might be partially initialized! */
        result->num_inputs++;
        if (ret != WALLY_OK) {
            goto fail;
        }
    }

    /* Make sure that the number of inputs matches the number of inputs in the transaction */
    if (result->num_inputs != result->tx->num_inputs) {
        ret = WALLY_EINVAL;
        goto fail;
    }

    /* Read outputs */
    for (i = 0; i < counts->num_outputs; ++i) {
        ret = pull_psbt_output(&bytes, &bytes_len, counts->output_counts[i],
                               &result->outputs[i]);
        result->num_outputs++;
        if (ret != WALLY_OK) {
            goto fail;
        }
    }

    /* If we ran out of data anywhere, fail. */
    if (bytes == NULL) {
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

int wally_psbt_get_length(
    const struct wally_psbt *psbt,
    size_t *len)
{
    int ret;

    ret = wally_psbt_to_bytes(psbt, NULL, 0, len);
    if (ret == WALLY_EINVAL && *len != 0) {
        return WALLY_OK;
    }
    return ret;
}

/* Literally a varbuff containing only type as a varint, then optional data */
static void push_psbt_key(
    unsigned char **cursor, size_t *max,
    uint64_t type, const void *extra, size_t extra_len)
{
    push_varint(cursor, max, varint_get_length(type) + extra_len);
    push_varint(cursor, max, type);
    push_bytes(cursor, max, extra, extra_len);
}

/* Common case of pushing a type whose key is a pubkey */
static void push_psbt_key_with_pubkey(
    unsigned char **cursor, size_t *max,
    uint64_t type,
    const unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN])
{
    if (pubkey_is_compressed(pubkey)) {
        push_psbt_key(cursor, max, type, pubkey, EC_PUBLIC_KEY_LEN);
    } else {
        push_psbt_key(cursor, max, type, pubkey,
                      EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
    }
}

#ifdef BUILD_ELEMENTS
/* Common case of pushing elements proprietary type keys */
static void push_psbt_elements_key(
    unsigned char **cursor, size_t *max,
    uint64_t type, const void *extra, size_t extra_len)
{
    push_varint(cursor, max, varint_get_length(WALLY_PSBT_PROPRIETARY_TYPE)
                + varint_get_length(WALLY_ELEMENTS_ID_LEN)
                + WALLY_ELEMENTS_ID_LEN + varint_get_length(type) + extra_len);
    push_varint(cursor, max, WALLY_PSBT_PROPRIETARY_TYPE);
    push_varbuff(cursor, max, WALLY_ELEMENTS_ID, WALLY_ELEMENTS_ID_LEN);
    push_varint(cursor, max, type);
    push_bytes(cursor, max, extra, extra_len);
}
#endif /* BUILD_ELEMENTS */

static int push_length_and_tx(
    unsigned char **cursor, size_t *max,
    const struct wally_tx *tx, uint32_t flags,
    bool partial_ok)
{
    int ret;
    size_t txlen;
    unsigned char *p;

    ret = wally_tx_get_length(tx, flags, &txlen);
    if (ret != WALLY_OK) {
        return ret;
    }

    push_varint(cursor, max, txlen);

    /* FIXME: convert wally_tx to use push  */
    p = push_bytes(cursor, max, NULL, txlen);
    if (!p) {
        /* We catch this in caller. */
        return WALLY_OK;
    }

    return wally_partial_tx_to_bytes(tx, flags, p, txlen, partial_ok, &txlen);
}

static void push_witness_stack(
    unsigned char **cursor, size_t *max,
    const struct wally_tx_witness_stack *witness)
{
    size_t i;

    push_varint(cursor, max, witness->num_items);
    for (i = 0; i < witness->num_items; ++i) {
        push_varbuff(cursor, max, witness->items[i].witness,
                     witness->items[i].witness_len);
    }
}

static void push_keypath_item(
    unsigned char **cursor, size_t *max,
    uint64_t type,
    const struct wally_keypath_item *item)
{
    size_t origin_len, i;

    push_psbt_key_with_pubkey(cursor, max, type,  item->pubkey);

    origin_len = 4;     /* Start with 4 bytes for fingerprint */
    origin_len += item->origin.path_len * sizeof(uint32_t);
    push_varint(cursor, max, origin_len);

    push_bytes(cursor, max, item->origin.fingerprint, 4);
    for (i = 0; i < item->origin.path_len; ++i) {
        push_bytes(cursor, max,
                   &item->origin.path[i], sizeof(uint32_t));
    }
}

static int push_psbt_input(
    unsigned char **cursor, size_t *max,
    bool is_elements,
    const struct wally_psbt_input *input)
{
    int ret;
    size_t i;

    /* Non witness utxo */
    if (input->non_witness_utxo) {
        push_psbt_key(cursor, max, WALLY_PSBT_IN_NON_WITNESS_UTXO, NULL, 0);
        ret = push_length_and_tx(cursor, max,
                                 input->non_witness_utxo,
                                 WALLY_TX_FLAG_USE_WITNESS, false);
        if (ret != WALLY_OK) {
            return ret;
        }
    }

    /* Witness utxo */
#ifdef BUILD_ELEMENTS
    if (is_elements && input->witness_utxo) {
        struct wally_tx_output *utxo = input->witness_utxo;
        size_t buf_len = push_elements_bytes_size(utxo);
        unsigned char buf[buf_len], *ptr = buf;
        /* Push the asset, value, nonce, then scriptpubkey */
        push_psbt_key(cursor, max, WALLY_PSBT_IN_WITNESS_UTXO, NULL, 0);

        push_elements_bytes(&ptr, &buf_len,
                            utxo->asset,
                            utxo->asset_len);
        push_elements_bytes(&ptr, &buf_len,
                            utxo->value,
                            utxo->value_len);
        push_elements_bytes(&ptr, &buf_len,
                            utxo->nonce,
                            utxo->nonce_len);
        push_varbuff(&ptr, &buf_len,
                     utxo->script,
                     utxo->script_len);

        assert(buf_len == 0);
        push_varbuff(cursor, max, buf, sizeof(buf));
    } else
#else
    if (is_elements) {
        return WALLY_ERROR;
    }
#endif /* BUILD_ELEMENTS */
    if (input->witness_utxo) {
        unsigned char wit_bytes[50], *w = wit_bytes; /* Witness outputs can be no larger than 50 bytes as specified in BIP 141 */
        size_t wit_max = sizeof(wit_bytes);

        push_psbt_key(cursor, max, WALLY_PSBT_IN_WITNESS_UTXO, NULL, 0);

        push_le64(&w, &wit_max, input->witness_utxo->satoshi);
        push_varbuff(&w, &wit_max,
                     input->witness_utxo->script,
                     input->witness_utxo->script_len);

        if (!w) {
            return WALLY_EINVAL;
        }
        push_varbuff(cursor, max, wit_bytes, w - wit_bytes);
    }
    /* Partial sigs */
    if (input->partial_sigs) {
        struct wally_partial_sigs_map *partial_sigs = input->partial_sigs;
        for (i = 0; i < partial_sigs->num_items; ++i) {
            struct wally_partial_sigs_item *item = &partial_sigs->items[i];
            push_psbt_key_with_pubkey(cursor, max, WALLY_PSBT_IN_PARTIAL_SIG,
                                      item->pubkey);
            push_varbuff(cursor, max, item->sig, item->sig_len);
        }
    }
    /* Sighash type */
    if (input->sighash_type > 0) {
        push_psbt_key(cursor, max, WALLY_PSBT_IN_SIGHASH_TYPE, NULL, 0);
        push_varint(cursor, max, sizeof(uint32_t));
        push_le32(cursor, max, input->sighash_type);
    }
    /* Redeem script */
    if (input->redeem_script) {
        push_psbt_key(cursor, max, WALLY_PSBT_IN_REDEEM_SCRIPT, NULL, 0);
        push_varbuff(cursor, max,
                     input->redeem_script, input->redeem_script_len);
    }
    /* Witness script */
    if (input->witness_script) {
        push_psbt_key(cursor, max, WALLY_PSBT_IN_WITNESS_SCRIPT, NULL, 0);
        push_varbuff(cursor, max,
                     input->witness_script, input->witness_script_len);
    }
    /* Keypaths */
    if (input->keypaths) {
        struct wally_keypath_map *keypaths = input->keypaths;
        for (i = 0; i < keypaths->num_items; ++i) {
            push_keypath_item(cursor, max,
                              WALLY_PSBT_IN_BIP32_DERIVATION,
                              &keypaths->items[i]);
        }
    }
    /* Final scriptSig */
    if (input->final_script_sig) {
        push_psbt_key(cursor, max, WALLY_PSBT_IN_FINAL_SCRIPTSIG, NULL, 0);
        push_varbuff(cursor, max,
                     input->final_script_sig, input->final_script_sig_len);
    }
    /* Final scriptWitness */
    if (input->final_witness) {
        size_t wit_len;

        push_psbt_key(cursor, max, WALLY_PSBT_IN_FINAL_SCRIPTWITNESS, NULL, 0);

        /* First pass simply calculates length */
        wit_len = 0;
        push_witness_stack(NULL, &wit_len, input->final_witness);

        push_varint(cursor, max, wit_len);
        push_witness_stack(cursor, max, input->final_witness);
    }
#ifdef BUILD_ELEMENTS
    /* Confidential Assets blinding data */
    if (input->has_value) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_IN_ELEMENTS_VALUE, NULL, 0);
        push_varint(cursor, max, sizeof(leint64_t));
        push_le64(cursor, max, input->value);
    }
    if (input->value_blinder) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_IN_ELEMENTS_VALUE_BLINDER, NULL, 0);
        push_varbuff(cursor, max, input->value_blinder, input->value_blinder_len);
    }
    if (input->asset) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_IN_ELEMENTS_ASSET, NULL, 0);
        push_varbuff(cursor, max, input->asset, input->asset_len);
    }
    if (input->asset_blinder) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_IN_ELEMENTS_ASSET_BLINDER, NULL, 0);
        push_varbuff(cursor, max, input->asset_blinder, input->asset_blinder_len);
    }
    /* Peg ins */
    if (input->peg_in_tx) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_IN_ELEMENTS_PEG_IN_TX, NULL, 0);
        ret = push_length_and_tx(cursor, max,
                                 input->peg_in_tx,
                                 WALLY_TX_FLAG_USE_WITNESS, false);
        if (ret != WALLY_OK) {
            return ret;
        }
    }
    if (input->txout_proof) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_IN_ELEMENTS_TXOUT_PROOF, NULL, 0);
        push_varbuff(cursor, max, input->txout_proof, input->txout_proof_len);
    }
    if (input->genesis_hash) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_IN_ELEMENTS_GENESIS_HASH, NULL, 0);
        push_varbuff(cursor, max, input->genesis_hash, input->genesis_hash_len);
    }
    if (input->claim_script) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_IN_ELEMENTS_CLAIM_SCRIPT, NULL, 0);
        push_varbuff(cursor, max, input->claim_script, input->claim_script_len);
    }
#endif /* BUILD_ELEMENTS */
    /* Unknowns */
    if (input->unknowns) {
        for (i = 0; i < input->unknowns->num_items; ++i) {
            struct wally_unknowns_item *unknown = &input->unknowns->items[i];
            push_varbuff(cursor, max, unknown->key, unknown->key_len);
            push_varbuff(cursor, max, unknown->value, unknown->value_len);
        }
    }

    /* Separator */
    push_u8(cursor, max, WALLY_PSBT_SEPARATOR);
    return WALLY_OK;
}

static int push_psbt_output(
    unsigned char **cursor, size_t *max,
    const struct wally_psbt_output *output)
{
    size_t i;

    /* Redeem script */
    if (output->redeem_script) {
        push_psbt_key(cursor, max, WALLY_PSBT_OUT_REDEEM_SCRIPT, NULL, 0);
        push_varbuff(cursor, max,
                     output->redeem_script, output->redeem_script_len);
    }
    /* Witness script */
    if (output->witness_script) {
        push_psbt_key(cursor, max, WALLY_PSBT_OUT_WITNESS_SCRIPT, NULL, 0);
        push_varbuff(cursor, max,
                     output->witness_script, output->witness_script_len);
    }
    /* Keypaths */
    if (output->keypaths) {
        struct wally_keypath_map *keypaths = output->keypaths;
        for (i = 0; i < keypaths->num_items; ++i) {
            push_keypath_item(cursor, max,
                              WALLY_PSBT_OUT_BIP32_DERIVATION,
                              &keypaths->items[i]);
        }
    }
#ifdef BUILD_ELEMENTS
    if (output->value_commitment) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_OUT_ELEMENTS_VALUE_COMMITMENT, NULL, 0);
        push_varbuff(cursor, max, output->value_commitment, output->value_commitment_len);
    }
    if (output->value_blinder) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_OUT_ELEMENTS_VALUE_BLINDER, NULL, 0);
        push_varbuff(cursor, max, output->value_blinder, output->value_blinder_len);
    }
    if (output->asset_commitment) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_OUT_ELEMENTS_ASSET_COMMITMENT, NULL, 0);
        push_varbuff(cursor, max, output->asset_commitment, output->asset_commitment_len);
    }
    if (output->asset_blinder) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_OUT_ELEMENTS_ASSET_BLINDER, NULL, 0);
        push_varbuff(cursor, max, output->asset_blinder, output->asset_blinder_len);
    }
    if (output->range_proof) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_OUT_ELEMENTS_RANGE_PROOF, NULL, 0);
        push_varbuff(cursor, max, output->range_proof, output->range_proof_len);
    }
    if (output->surjection_proof) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_OUT_ELEMENTS_SURJECTION_PROOF, NULL, 0);
        push_varbuff(cursor, max, output->surjection_proof, output->surjection_proof_len);
    }
    if (output->has_blinding_pubkey) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_OUT_ELEMENTS_BLINDING_PUBKEY, NULL, 0);
        if (pubkey_is_compressed(output->blinding_pubkey)) {
            push_varbuff(cursor, max, output->blinding_pubkey, EC_PUBLIC_KEY_LEN);
        }
        else {
            push_varbuff(cursor, max, output->blinding_pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
        }
    }
    if (output->nonce_commitment) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_OUT_ELEMENTS_NONCE_COMMITMENT, NULL, 0);
        push_varbuff(cursor, max, output->nonce_commitment, output->nonce_commitment_len);
    }
#endif /* BUILD_ELEMENTS */
    /* Unknowns */
    if (output->unknowns) {
        for (i = 0; i < output->unknowns->num_items; ++i) {
            struct wally_unknowns_item *unknown = &output->unknowns->items[i];
            push_varbuff(cursor, max, unknown->key, unknown->key_len);
            push_varbuff(cursor, max, unknown->value, unknown->value_len);
        }
    }

    /* Separator */
    push_u8(cursor, max, WALLY_PSBT_SEPARATOR);
    return WALLY_OK;
}

int wally_psbt_to_bytes(
    const struct wally_psbt *psbt,
    unsigned char *bytes_out, size_t len,
    size_t *bytes_written)
{
    unsigned char *cursor = bytes_out;
    size_t max = len, i;
    int ret;

    *bytes_written = 0;

    push_bytes(&cursor, &max, psbt->magic, sizeof(psbt->magic));

    /* Global tx */
    push_psbt_key(&cursor, &max, WALLY_PSBT_GLOBAL_UNSIGNED_TX, NULL, 0);
    push_length_and_tx(&cursor, &max, psbt->tx, 0, true);

    /* version */
    if (psbt->version > 0) {
        push_psbt_key(&cursor, &max, WALLY_PSBT_GLOBAL_VERSION, NULL, 0);
        push_varint(&cursor, &max, sizeof(uint32_t));
        push_le32(&cursor, &max, psbt->version);
    }

    /* Unknowns */
    if (psbt->unknowns) {
        for (i = 0; i < psbt->unknowns->num_items; ++i) {
            struct wally_unknowns_item *unknown = &psbt->unknowns->items[i];
            push_varbuff(&cursor, &max, unknown->key, unknown->key_len);
            push_varbuff(&cursor, &max, unknown->value, unknown->value_len);
        }
    }

    /* Separator */
    push_u8(&cursor, &max, WALLY_PSBT_SEPARATOR);

    /* Push each input and output */
    size_t is_elements;
    if ((ret = wally_psbt_is_elements(psbt, &is_elements)) != WALLY_OK) {
        return ret;
    }
    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        ret = push_psbt_input(&cursor, &max, is_elements == 1, input);
        if (ret != WALLY_OK) {
            return ret;
        }
    }
    for (i = 0; i < psbt->num_outputs; ++i) {
        struct wally_psbt_output *output = &psbt->outputs[i];
        ret = push_psbt_output(&cursor, &max, output);
        if (ret != WALLY_OK) {
            return ret;
        }
    }

    if (cursor == NULL) {
        /* Once cursor was NULL, max accumulates hm bytes we needed */
        *bytes_written = len + max;
        return WALLY_EINVAL;
    } else {
        *bytes_written = len - max;
    }

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
    /* Allocate the decoded buffer */
    safe_len = base64_decoded_length(string_len);
    if ((decoded = wally_malloc(safe_len)) == NULL) {
        ret = WALLY_ENOMEM;
        goto done;
    }

    /* Decode the base64 psbt */
    decoded_len = base64_decode(decoded, safe_len, string, string_len);
    if (decoded_len <= 5) { /* Make sure we also have enough bytes for the magic */
        ret = WALLY_EINVAL;
        goto done;
    }

    /* Now decode the psbt */
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

    /* Get psbt bytes */
    if ((ret = wally_psbt_to_bytes(psbt, buff, len, &written)) != WALLY_OK) {
        goto done;
    }

    /* Base64 encode */
    b64_safe_len = base64_encoded_length(written) + 1; /* + 1 for null termination */
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

    /* Get info from the first psbt and use it as the template */
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

        /* Compare the txids */
        if ((ret = get_txid(psbts[i].tx, txid, SHA256_LEN)) != WALLY_OK) {
            goto fail;
        }
        if (memcmp(global_txid, txid, SHA256_LEN) != 0) {
            ret = WALLY_EINVAL;
            goto fail;
        }

        /* Now start merging */
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
    bool is_elements;

    if (!psbt || !psbt->tx || !key || key_len != EC_PRIVATE_KEY_LEN) {
        return WALLY_EINVAL;
    }

    if ((ret = wally_psbt_is_elements(psbt, &i)) != WALLY_OK) {
        return ret;
    }
    is_elements = i == 1;

    /* Get the pubkey */
    if ((ret = wally_ec_public_key_from_private_key(key, key_len, pubkey, EC_PUBLIC_KEY_LEN)) != WALLY_OK) {
        return ret;
    }
    if ((ret = wally_ec_public_key_decompress(pubkey, EC_PUBLIC_KEY_LEN, uncomp_pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN)) != WALLY_OK) {
        return ret;
    }

    /* Go through each of the inputs */
    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        struct wally_tx_input *txin = &psbt->tx->inputs[i];
        unsigned char sighash[SHA256_LEN], *scriptcode, wpkh_sc[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
        size_t scriptcode_len;
        bool match = false, comp = false, already_signed = false;
        uint32_t sighash_type = WALLY_SIGHASH_ALL;

        if (!input->keypaths) {
            /* Can't do anything without the keypaths */
            continue;
        }

        /* Go through each listed pubkey and see if it matches. */
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

        /* Did not find pubkey, skip */
        if (!match) {
            continue;
        }

        /* Make sure we don't already have a sig for this input ?! */
        if (input->partial_sigs) {
            for (j = 0; j < input->partial_sigs->num_items; j++) {
                struct wally_partial_sigs_item *item = &input->partial_sigs->items[j];
                if (memcmp((char *)item->pubkey, (char *)uncomp_pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN) == 0
                    || memcmp((char *)item->pubkey, (char *)pubkey, EC_PUBLIC_KEY_LEN) == 0) {
                    already_signed = true;
                    break;
                }
            }
        }

        /* We've already got a partial sig for this pubkey on this input */
        if (already_signed) {
            continue;
        }

        /* Sighash type */
        if (input->sighash_type > 0) {
            sighash_type = input->sighash_type;
        }

        /* Get scriptcode and sighash */
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
                /* Not a recognized scriptPubKey type or not enough information */
                continue;
            }

	    if (is_elements) {
#ifdef BUILD_ELEMENTS
		if ((ret = wally_tx_get_elements_signature_hash(psbt->tx, i, scriptcode, scriptcode_len, input->witness_utxo->value, input->witness_utxo->value_len, sighash_type, WALLY_TX_FLAG_USE_WITNESS, sighash, SHA256_LEN)) != WALLY_OK) {
		    return ret;
		}
#else
		return WALLY_ERROR;
#endif /* BUILD_ELEMENTS */
	    } else if ((ret = wally_tx_get_btc_signature_hash(psbt->tx, i, scriptcode, scriptcode_len, input->witness_utxo->satoshi, sighash_type, WALLY_TX_FLAG_USE_WITNESS, sighash, SHA256_LEN)) != WALLY_OK) {
                return ret;
            }
        }

        /* Sign the sighash */
        if ((ret = wally_ec_sig_from_bytes(key, key_len, sighash, SHA256_LEN, EC_FLAG_ECDSA | EC_FLAG_GRIND_R, sig, EC_SIGNATURE_LEN)) != WALLY_OK) {
            return ret;
        }
        if ((ret = wally_ec_sig_normalize(sig, EC_SIGNATURE_LEN, sig, EC_SIGNATURE_LEN)) != WALLY_OK) {
            return ret;
        }
        if ((ret = wally_ec_sig_to_der(sig, EC_SIGNATURE_LEN, der_sig, EC_SIGNATURE_DER_MAX_LEN, &der_sig_len)) != WALLY_OK) {
            return ret;
        }

        /* Add the sighash type to the end of the sig */
        der_sig[der_sig_len] = (unsigned char)sighash_type;
        der_sig_len++;

        /* Copy the DER sig into the psbt */
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
        /* Script for this input. originally set to the input's scriptPubKey, but in the case of a p2sh/p2wsh
         * input, it will be eventually be set to the unhashed script, if known */
        unsigned char *out_script = NULL;
        size_t out_script_len, type;
        bool witness = false, p2sh = false;;

        if (input->final_script_sig || input->final_witness) {
            /* Already finalized */
            continue;
        }

        /* Note that if we patch libwally to supply the non-witness utxo tx field (tx) for
        * witness inputs also, we'll need a different way to signal p2sh-p2wpkh scripts */
        if (input->witness_utxo && input->witness_utxo->script_len > 0) {
            out_script = input->witness_utxo->script;
            out_script_len = input->witness_utxo->script_len;
            witness = true;
        } else if (input->non_witness_utxo && input->non_witness_utxo->num_outputs > txin->index) {
            struct wally_tx_output out = input->non_witness_utxo->outputs[txin->index];
            out_script = out.script;
            out_script_len = out.script_len;
        }
        if (input->redeem_script) {
            out_script = input->redeem_script;
            out_script_len = input->redeem_script_len;
            p2sh = true;
        }
        if (input->witness_script) {
            out_script = input->witness_script;
            out_script_len = input->witness_script_len;
            witness = true;
        }

        /* We need an outscript to do anything */
        if (!out_script) {
            continue;
        }

        if ((ret = wally_scriptpubkey_get_type(out_script, out_script_len, &type)) != WALLY_OK) {
            return ret;
        }

        switch(type) {
        case WALLY_SCRIPT_TYPE_P2PKH:
        case WALLY_SCRIPT_TYPE_P2WPKH: {
            struct wally_partial_sigs_item *partial_sig;
            unsigned char script_sig[WALLY_SCRIPTSIG_P2PKH_MAX_LEN];
            size_t written, script_sig_len, pubkey_len = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;

            if (!input->partial_sigs || input->partial_sigs->num_items != 1) {
                /* Must be single key, single sig */
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
                if (input->redeem_script) {
                    /* P2SH wrapped witness requires final scriptsig of pushing the redeemScript */
                    script_sig_len = varint_get_length(input->redeem_script_len) + input->redeem_script_len;
                    input->final_script_sig = wally_malloc(script_sig_len);
                    if ((ret = wally_script_push_from_bytes(input->redeem_script, input->redeem_script_len, 0, input->final_script_sig, script_sig_len, &written)) != WALLY_OK) {
                        wally_free(input->final_script_sig);
                        return ret;
                    }
                    input->final_script_sig_len = written;
                }
            }
            break;
        }
        case WALLY_SCRIPT_TYPE_MULTISIG: {
            unsigned char *script_sig, *sigs, *p = out_script, *end = p + out_script_len;
            uint32_t *sighashes;
            size_t n_sigs, n_pks, sig_i = 0, j, k, sigs_len, script_sig_len, written;

            if (!script_is_op_n(out_script[0], false, &n_sigs)) {
                /* How did this happen? */
                return WALLY_ERROR;
            }

            if (!input->partial_sigs || input->partial_sigs->num_items < n_sigs) {
                continue;
            }

            if (!script_is_op_n(out_script[out_script_len - 2], false, &n_pks)) {
                /* How did this happen? */
                return WALLY_ERROR;
            }

            sigs_len = EC_SIGNATURE_LEN * n_sigs;
            if (!(sigs = wally_malloc(sigs_len)) || !(sighashes = wally_malloc(n_sigs * sizeof(uint32_t)))) {
                return WALLY_ENOMEM;
            }

            /* Go through the multisig script and figure out the order of pubkeys */
            p++; /* Skip the n_sig item */
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

                /* Get the signature and sighash separately */
                sig = input->partial_sigs->items[k].sig;
                sig_len = input->partial_sigs->items[k].sig_len; /* Has sighash byte at end */
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
                /* P2SH wrapped witness requires final scriptsig of pushing the redeemScript */
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
            /* Skip this because we can't finalize it */
            continue;
        }
        }

        /* Clear non-final things */
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
                /* Our global tx shouldn't have a scriptSig */
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
                /* Our global tx shouldn't have a witness */
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

int wally_psbt_is_elements(
    const struct wally_psbt *psbt,
    size_t *written)
{
    if (!psbt || !written)
        return WALLY_EINVAL;

    *written = 0;
#ifdef BUILD_ELEMENTS
    if (memcmp(psbt->magic, WALLY_ELEMENTS_PSBT_MAGIC, 5) == 0) {
        *written = 1;
    }
#endif /* BUILD_ELEMENTS */
    return WALLY_OK;
}
