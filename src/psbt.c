#include "internal.h"

#include "ccan/ccan/base64/base64.h"

#include <include/wally_elements.h>
#include <include/wally_script.h>
#include <include/wally_psbt.h>

#include <limits.h>
#include <stdbool.h>
#include "transaction_shared.h"
#include "psbt_int.h"
#include "script_int.h"
#include "script.h"
#include "pullpush.h"

static const uint8_t WALLY_PSBT_MAGIC[5] = {'p', 's', 'b', 't', 0xff};
static const uint8_t WALLY_ELEMENTS_PSBT_MAGIC[5] = {'p', 's', 'e', 't', 0xff};

#ifdef BUILD_ELEMENTS
static const uint8_t WALLY_ELEMENTS_ID[8] = {'e', 'l', 'e', 'm', 'e', 'n', 't', 's'};
static const size_t WALLY_ELEMENTS_ID_LEN = 8;
#endif /* BUILD_ELEMENTS */

static bool pubkey_is_compressed(const unsigned char pub_key[EC_PUBLIC_KEY_UNCOMPRESSED_LEN]) {
    return pub_key[0] == 0x02 || pub_key[0] == 0x03;
}

static size_t get_pubkey_len(const unsigned char *pub_key, size_t pub_key_len)
{
    if (!pub_key_len)
        return 0;
    return pubkey_is_compressed(pub_key) ? EC_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
}

static bool is_valid_pubkey_len(size_t len)
{
    return len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN || len == EC_PUBLIC_KEY_LEN;
}

static bool is_valid_optional_pubkey_len(size_t len)
{
    return !len || is_valid_pubkey_len(len);
}

static bool is_equal_pubkey(const unsigned char *l, size_t l_len, const unsigned char *r, size_t r_len)
{
    if (!l || !r)
        return l == r; /* Equal if both NULL only */

    return l_len == r_len && memcmp(l, r, l_len) == 0;
}

int wally_keypath_map_init_alloc(size_t allocation_len, struct wally_keypath_map **output)
{
    struct wally_keypath_map *result;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_keypath_map);

    if (allocation_len) {
        result->items = wally_calloc(allocation_len * sizeof(*result->items));
        if (!result->items) {
            wally_free(result);
            *output = NULL;
            return WALLY_ENOMEM;
        }
    }
    result->items_allocation_len = allocation_len;
    result->num_items = 0;
    return WALLY_OK;
}

int wally_keypath_map_free(struct wally_keypath_map *keypaths)
{
    size_t i;

    if (keypaths) {
        for (i = 0; i < keypaths->num_items; ++i) {
            clear_and_free(keypaths->items[i].path, keypaths->items[i].path_len * sizeof(*keypaths->items[i].path));
        }
        clear_and_free(keypaths->items, keypaths->items_allocation_len * sizeof(*keypaths->items));
        clear_and_free(keypaths, sizeof(*keypaths));
    }
    return WALLY_OK;
}

int wally_keypath_map_find(const struct wally_keypath_map *keypaths,
                           const unsigned char *pub_key, size_t pub_key_len,
                           size_t *written)
{
    size_t i;

    if (written)
        *written = 0;

    if (!keypaths || !pub_key || !is_valid_pubkey_len(pub_key_len) || !written)
        return WALLY_EINVAL;

    for (i = 0; i < keypaths->num_items; ++i) {
        const struct wally_keypath_item *item = &keypaths->items[i];

        if (is_equal_pubkey(pub_key, pub_key_len,
                            item->pubkey, get_pubkey_len(item->pubkey, sizeof(item->pubkey)))) {
            *written = i + 1; /* Found */
            break;
        }
    }
    return WALLY_OK;
}

static int add_keypath_item(struct wally_keypath_map *keypaths, const struct wally_keypath_item *item)
{
    const size_t pub_key_len = get_pubkey_len(item->pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
    return wally_keypath_map_add(keypaths, item->pubkey, pub_key_len,
                                 item->fingerprint, BIP32_KEY_FINGERPRINT_LEN,
                                 item->path, item->path_len);
}

static int replace_keypaths(const struct wally_keypath_map *src,
                            struct wally_keypath_map **dst)
{
    struct wally_keypath_map *result = NULL;
    size_t i;
    int ret = WALLY_OK;

    if (src) {
        ret = wally_keypath_map_init_alloc(src->items_allocation_len, &result);

        for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
            ret = add_keypath_item(result, src->items + i);
    }

    if (ret != WALLY_OK) {
        wally_keypath_map_free(result);
    } else {
        wally_keypath_map_free(*dst);
        *dst = result;
    }
    return ret;
}

static int array_grow(void **src, size_t num_items, size_t *allocation_len, size_t item_size)
{
    if (num_items == *allocation_len) {
        /* Array is full, allocate more space */
        const size_t n = (*allocation_len == 0 ? 1 : *allocation_len) * 2;
        void *p = realloc_array(*src, *allocation_len, n, item_size);
        if (!p)
            return WALLY_ENOMEM;
        /* Free and replace the old array with the new enlarged copy */
        clear_and_free(*src, num_items * item_size);
        *src = p;
        *allocation_len = n;
    }
    return WALLY_OK;
}

int wally_keypath_map_add(struct wally_keypath_map *keypaths,
                          const unsigned char *pub_key, size_t pub_key_len,
                          const unsigned char *fingerprint, size_t fingerprint_len,
                          const uint32_t *path, size_t path_len)
{
    size_t is_found;
    int ret;

    if (!keypaths || !pub_key || !is_valid_pubkey_len(pub_key_len) ||
        !fingerprint || fingerprint_len != BIP32_KEY_FINGERPRINT_LEN ||
        BYTES_INVALID(path, path_len))
        return WALLY_EINVAL;

    ret = wally_keypath_map_find(keypaths, pub_key, pub_key_len, &is_found);
    if (ret != WALLY_OK || is_found)
        return ret; /* Return WALLY_OK and do nothing if already present */

    ret = array_grow((void *)&keypaths->items, keypaths->num_items,
                     &keypaths->items_allocation_len, sizeof(struct wally_keypath_item));
    if (ret == WALLY_OK) {
        struct wally_keypath_item *new_item = keypaths->items + keypaths->num_items;

        if (path) {
            if (!clone_bytes((unsigned char **)&new_item->path, (unsigned char *)path, path_len * sizeof(*path)))
                return WALLY_ENOMEM;
            new_item->path_len = path_len;
        }
        memcpy(new_item->pubkey, pub_key, pub_key_len);
        memcpy(new_item->fingerprint, fingerprint, fingerprint_len);
        keypaths->num_items++;
    }
    return ret;
}

int wally_partial_sigs_map_init_alloc(size_t allocation_len, struct wally_partial_sigs_map **output)
{
    struct wally_partial_sigs_map *result;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_partial_sigs_map);

    if (allocation_len) {
        result->items = wally_calloc(allocation_len * sizeof(*result->items));
        if (!result->items) {
            wally_free(result);
            *output = NULL;
            return WALLY_ENOMEM;
        }
    }
    result->items_allocation_len = allocation_len;
    result->num_items = 0;
    return WALLY_OK;
}

int wally_partial_sigs_map_free(struct wally_partial_sigs_map *sigs)
{
    size_t i;

    if (sigs) {
        for (i = 0; i < sigs->num_items; ++i)
            clear_and_free(sigs->items[i].sig, sigs->items[i].sig_len);
        clear_and_free(sigs->items, sigs->items_allocation_len * sizeof(*sigs->items));
        clear_and_free(sigs, sizeof(*sigs));
    }
    return WALLY_OK;
}

int wally_partial_sigs_map_find(const struct wally_partial_sigs_map *partial_sigs,
                                const unsigned char *pub_key, size_t pub_key_len,
                                size_t *written)
{
    size_t i;

    if (written)
        *written = 0;

    if (!partial_sigs || !pub_key || !is_valid_pubkey_len(pub_key_len) || !written)
        return WALLY_EINVAL;

    for (i = 0; i < partial_sigs->num_items; ++i) {
        const struct wally_partial_sigs_item *item = &partial_sigs->items[i];

        if (is_equal_pubkey(pub_key, pub_key_len,
                            item->pubkey, get_pubkey_len(item->pubkey, sizeof(item->pubkey)))) {
            *written = i + 1; /* Found */
            break;
        }
    }
    return WALLY_OK;
}

static int add_partial_sig_item(struct wally_partial_sigs_map *sigs, const struct wally_partial_sigs_item *item)
{
    const size_t pub_key_len = get_pubkey_len(item->pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
    return wally_partial_sigs_map_add(sigs, item->pubkey, pub_key_len,
                                      item->sig, item->sig_len);
}

static int replace_partial_sigs(const struct wally_partial_sigs_map *src,
                                struct wally_partial_sigs_map **dst)
{
    struct wally_partial_sigs_map *result = NULL;
    size_t i;
    int ret = WALLY_OK;

    if (src) {
        ret = wally_partial_sigs_map_init_alloc(src->items_allocation_len, &result);

        for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
            ret = add_partial_sig_item(result, src->items + i);
    }

    if (ret != WALLY_OK) {
        wally_partial_sigs_map_free(result);
    } else {
        wally_partial_sigs_map_free(*dst);
        *dst = result;
    }
    return ret;
}

int wally_partial_sigs_map_add(struct wally_partial_sigs_map *sigs,
                               const unsigned char *pub_key, size_t pub_key_len,
                               const unsigned char *sig, size_t sig_len)
{
    size_t is_found;
    int ret;

    if (!sigs || !pub_key || !is_valid_pubkey_len(pub_key_len) ||
        BYTES_INVALID(sig, sig_len))
        return WALLY_EINVAL;

    ret = wally_partial_sigs_map_find(sigs, pub_key, pub_key_len, &is_found);
    if (ret != WALLY_OK || is_found)
        return ret; /* Return WALLY_OK and do nothing if already present */

    ret = array_grow((void *)&sigs->items, sigs->num_items,
                     &sigs->items_allocation_len, sizeof(struct wally_partial_sigs_item));
    if (ret == WALLY_OK) {
        struct wally_partial_sigs_item *new_item = sigs->items + sigs->num_items;

        if (sig && !clone_bytes(&new_item->sig, sig, sig_len))
            return WALLY_ENOMEM;
        new_item->sig_len = sig_len;
        memcpy(&new_item->pubkey, pub_key, pub_key_len);
        sigs->num_items++;
    }
    return ret;
}

int wally_unknowns_map_init_alloc(size_t allocation_len, struct wally_unknowns_map **output)
{
    struct wally_unknowns_map *result;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_unknowns_map);

    if (allocation_len) {
        result->items = wally_calloc(allocation_len * sizeof(*result->items));
        if (!result->items) {
            wally_free(result);
            *output = NULL;
            return WALLY_ENOMEM;
        }
    }
    result->items_allocation_len = allocation_len;
    result->num_items = 0;
    return WALLY_OK;
}

int wally_unknowns_map_free(struct wally_unknowns_map *unknowns)
{
    size_t i;

    if (unknowns) {
        for (i = 0; i < unknowns->num_items; ++i) {
            clear_and_free(unknowns->items[i].key, unknowns->items[i].key_len);
            clear_and_free(unknowns->items[i].value, unknowns->items[i].value_len);
        }
        clear_and_free(unknowns->items, unknowns->num_items * sizeof(*unknowns->items));
        clear_and_free(unknowns, sizeof(*unknowns));
    }
    return WALLY_OK;
}

int wally_unknowns_map_find(const struct wally_unknowns_map *unknowns,
                            const unsigned char *key, size_t key_len,
                            size_t *written)
{
    size_t i;

    if (written)
        *written = 0;

    if (!unknowns || !key || BYTES_INVALID(key, key_len) || !written)
        return WALLY_EINVAL;

    for (i = 0; i < unknowns->num_items; ++i) {
        const struct wally_unknowns_item *item = &unknowns->items[i];

        if (key_len == item->key_len && memcmp(key, item->key, key_len) == 0) {
            *written = i + 1; /* Found */
            break;
        }
    }
    return WALLY_OK;
}

static int add_unknowns_item(struct wally_unknowns_map *unknowns, const struct wally_unknowns_item *item)
{
    return wally_unknowns_map_add(unknowns, item->key, item->key_len, item->value, item->value_len);
}

static int replace_unknowns(const struct wally_unknowns_map *src,
                            struct wally_unknowns_map **dst)
{
    struct wally_unknowns_map *result = NULL;
    size_t i;
    int ret = WALLY_OK;

    if (src) {
        ret = wally_unknowns_map_init_alloc(src->items_allocation_len, &result);

        for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
            ret = add_unknowns_item(result, src->items + i);
    }

    if (ret != WALLY_OK) {
        wally_unknowns_map_free(result);
    } else {
        wally_unknowns_map_free(*dst);
        *dst = result;
    }
    return ret;
}

int wally_unknowns_map_add(struct wally_unknowns_map *unknowns,
                           const unsigned char *key, size_t key_len,
                           const unsigned char *value, size_t value_len)
{
    size_t is_found;
    int ret;

    if (!unknowns || !key || BYTES_INVALID(key, key_len) || BYTES_INVALID(value, value_len))
        return WALLY_EINVAL;

    ret = wally_unknowns_map_find(unknowns, key, key_len, &is_found);
    if (ret != WALLY_OK || is_found)
        return ret; /* Return WALLY_OK and do nothing if already present */

    ret = array_grow((void *)&unknowns->items, unknowns->num_items,
                     &unknowns->items_allocation_len, sizeof(struct wally_unknowns_item));
    if (ret == WALLY_OK) {
        struct wally_unknowns_item *new_item = unknowns->items + unknowns->num_items;

        if (!clone_bytes(&new_item->key, key, key_len))
            return WALLY_ENOMEM;
        if (value && !clone_bytes(&new_item->value, value, value_len)) {
            clear_and_free(new_item->key, key_len);
            new_item->key = NULL;
            return WALLY_ENOMEM;
        }
        new_item->key_len = key_len;
        new_item->value_len = value_len;
        unknowns->num_items++;
    }
    return ret;
}

int wally_psbt_input_set_non_witness_utxo(struct wally_psbt_input *input,
                                          const struct wally_tx *non_witness_utxo)
{
    int ret = WALLY_OK;
    struct wally_tx *new_tx = NULL;

    if (!input)
        return WALLY_EINVAL;

    if (non_witness_utxo &&
        (ret = wally_tx_clone(non_witness_utxo, 0, &new_tx)) != WALLY_OK)
        return ret;

    wally_tx_free(input->non_witness_utxo);
    input->non_witness_utxo = new_tx;
    return ret;
}

int wally_psbt_input_set_witness_utxo(struct wally_psbt_input *input,
                                      const struct wally_tx_output *witness_utxo)
{
    int ret = WALLY_OK;
    struct wally_tx_output *new_output = NULL;

    if (!input)
        return WALLY_EINVAL;

    if (witness_utxo &&
        (ret = wally_tx_output_clone_alloc(witness_utxo, &new_output) != WALLY_OK))
        return ret;

    wally_tx_output_free(input->witness_utxo);
    input->witness_utxo = new_output;
    return ret;
}

int wally_psbt_input_set_redeem_script(struct wally_psbt_input *input,
                                       const unsigned char *redeem_script,
                                       size_t redeem_script_len)
{
    if (!input)
        return WALLY_EINVAL;
    return replace_bytes(redeem_script, redeem_script_len,
                         &input->redeem_script, &input->redeem_script_len);
}

int wally_psbt_input_set_witness_script(struct wally_psbt_input *input,
                                        const unsigned char *witness_script,
                                        size_t witness_script_len)
{
    if (!input)
        return WALLY_EINVAL;
    return replace_bytes(witness_script, witness_script_len,
                         &input->witness_script, &input->witness_script_len);
}

int wally_psbt_input_set_final_script_sig(struct wally_psbt_input *input,
                                          const unsigned char *final_script_sig,
                                          size_t final_script_sig_len)
{
    if (!input)
        return WALLY_EINVAL;
    return replace_bytes(final_script_sig, final_script_sig_len,
                         &input->final_script_sig, &input->final_script_sig_len);
}

int wally_psbt_input_set_final_witness(struct wally_psbt_input *input,
                                       const struct wally_tx_witness_stack *final_witness)
{
    struct wally_tx_witness_stack *new_witness = NULL;

    if (!input)
        return WALLY_EINVAL;

    if (final_witness &&
        (wally_tx_witness_stack_clone_alloc(final_witness, &new_witness) != WALLY_OK))
        return WALLY_ENOMEM;

    wally_tx_witness_stack_free(input->final_witness);
    input->final_witness = new_witness;
    return WALLY_OK;
}

int wally_psbt_input_set_keypaths(struct wally_psbt_input *input,
                                  const struct wally_keypath_map *keypaths)
{
    return input ? replace_keypaths(keypaths, &input->keypaths) : WALLY_EINVAL;
}

int wally_psbt_input_set_partial_sigs(struct wally_psbt_input *input,
                                      const struct wally_partial_sigs_map *partial_sigs)
{
    return input ? replace_partial_sigs(partial_sigs, &input->partial_sigs) : WALLY_EINVAL;
}

int wally_psbt_input_set_unknowns(struct wally_psbt_input *input,
                                  const struct wally_unknowns_map *unknowns)
{
    return input ? replace_unknowns(unknowns, &input->unknowns) : WALLY_EINVAL;
}

int wally_psbt_input_set_sighash_type(struct wally_psbt_input *input, uint32_t sighash_type)
{
    if (!input)
        return WALLY_EINVAL;
    input->sighash_type = sighash_type;
    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
int wally_psbt_elements_input_set_value(struct wally_psbt_input *input, uint64_t value)
{
    input->value = value;
    input->has_value = 1u;
    return WALLY_OK;
}

int wally_psbt_elements_input_clear_value(struct wally_psbt_input *input)
{
    input->value = 0;
    input->has_value = 0;
    return WALLY_OK;
}

int wally_psbt_elements_input_set_value_blinder(struct wally_psbt_input *input,
                                                const unsigned char *value_blinder,
                                                size_t value_blinder_len)
{
    if (!input)
        return WALLY_EINVAL;
    return replace_bytes(value_blinder, value_blinder_len,
                         &input->value_blinder, &input->value_blinder_len);
}

int wally_psbt_elements_input_set_asset(struct wally_psbt_input *input,
                                        const unsigned char *asset, size_t asset_len)
{
    if (!input)
        return WALLY_EINVAL;
    return replace_bytes(asset, asset_len, &input->asset, &input->asset_len);
}

int wally_psbt_elements_input_set_asset_blinder(struct wally_psbt_input *input,
                                                const unsigned char *asset_blinder,
                                                size_t asset_blinder_len)
{
    if (!input)
        return WALLY_EINVAL;
    return replace_bytes(asset_blinder, asset_blinder_len,
                         &input->asset_blinder, &input->asset_blinder_len);
}

int wally_psbt_elements_input_set_peg_in_tx(struct wally_psbt_input *input,
                                            const struct wally_tx *peg_in_tx)
{
    int ret = WALLY_OK;
    struct wally_tx *new_tx = NULL;

    if (!input)
        return WALLY_EINVAL;

    if (peg_in_tx &&
        (ret = wally_tx_clone(peg_in_tx, 0, &new_tx)) != WALLY_OK)
        return ret;

    wally_tx_free(input->peg_in_tx);
    input->peg_in_tx = new_tx;
    return ret;
}

int wally_psbt_elements_input_set_txout_proof(struct wally_psbt_input *input,
                                              const unsigned char *txout_proof,
                                              size_t txout_proof_len)
{
    if (!input)
        return WALLY_EINVAL;
    return replace_bytes(txout_proof, txout_proof_len,
                         &input->txout_proof, &input->txout_proof_len);
}

int wally_psbt_elements_input_set_genesis_hash(struct wally_psbt_input *input,
                                               const unsigned char *genesis_hash,
                                               size_t genesis_hash_len)
{
    if (!input)
        return WALLY_EINVAL;
    return replace_bytes(genesis_hash, genesis_hash_len,
                         &input->genesis_hash, &input->genesis_hash_len);
}

int wally_psbt_elements_input_set_claim_script(struct wally_psbt_input *input,
                                               const unsigned char *claim_script,
                                               size_t claim_script_len)
{
    if (!input)
        return WALLY_EINVAL;
    return replace_bytes(claim_script, claim_script_len,
                         &input->claim_script, &input->claim_script_len);
}
#endif /* BUILD_ELEMENTS */

static int psbt_input_free(struct wally_psbt_input *input, bool free_parent)
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

        wally_clear(input, sizeof(*input));
        if (free_parent)
            wally_free(input);
    }
    return WALLY_OK;
}

int wally_psbt_output_set_redeem_script(struct wally_psbt_output *output,
                                        const unsigned char *redeem_script,
                                        size_t redeem_script_len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(redeem_script, redeem_script_len,
                         &output->redeem_script, &output->redeem_script_len);
}

int wally_psbt_output_set_witness_script(struct wally_psbt_output *output,
                                         const unsigned char *witness_script,
                                         size_t witness_script_len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(witness_script, witness_script_len,
                         &output->witness_script, &output->witness_script_len);
}

int wally_psbt_output_set_keypaths(struct wally_psbt_output *output,
                                   const struct wally_keypath_map *keypaths)
{
    return output ? replace_keypaths(keypaths, &output->keypaths) : WALLY_EINVAL;
}

int wally_psbt_output_set_unknowns(struct wally_psbt_output *output,
                                   const struct wally_unknowns_map *unknowns)
{
    return output ? replace_unknowns(unknowns, &output->unknowns) : WALLY_EINVAL;
}

#ifdef BUILD_ELEMENTS
int wally_psbt_elements_output_set_blinding_pubkey(struct wally_psbt_output *output,
                                                   const unsigned char *blinding_pubkey,
                                                   size_t blinding_pubkey_len)
{
    if (!output || !is_valid_optional_pubkey_len(blinding_pubkey_len))
        return WALLY_EINVAL;
    return replace_bytes(blinding_pubkey, blinding_pubkey_len,
                         &output->blinding_pubkey, &output->blinding_pubkey_len);
}

int wally_psbt_elements_output_set_value_commitment(struct wally_psbt_output *output,
                                                    const unsigned char *value_commitment,
                                                    size_t value_commitment_len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(value_commitment, value_commitment_len,
                         &output->value_commitment, &output->value_commitment_len);
}

int wally_psbt_elements_output_set_value_blinder(struct wally_psbt_output *output,
                                                 const unsigned char *value_blinder,
                                                 size_t value_blinder_len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(value_blinder, value_blinder_len,
                         &output->value_blinder, &output->value_blinder_len);
}

int wally_psbt_elements_output_set_asset_commitment(struct wally_psbt_output *output,
                                                    const unsigned char *asset_commitment,
                                                    size_t asset_commitment_len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(asset_commitment, asset_commitment_len,
                         &output->asset_commitment, &output->asset_commitment_len);
}

int wally_psbt_elements_output_set_asset_blinder(struct wally_psbt_output *output,
                                                 const unsigned char *asset_blinder,
                                                 size_t asset_blinder_len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(asset_blinder, asset_blinder_len,
                         &output->asset_blinder, &output->asset_blinder_len);
}

int wally_psbt_elements_output_set_nonce_commitment(struct wally_psbt_output *output,
                                                    const unsigned char *nonce_commitment,
                                                    size_t nonce_commitment_len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(nonce_commitment, nonce_commitment_len,
                         &output->nonce_commitment, &output->nonce_commitment_len);
}

int wally_psbt_elements_output_set_range_proof(struct wally_psbt_output *output,
                                               const unsigned char *range_proof,
                                               size_t range_proof_len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(range_proof, range_proof_len,
                         &output->range_proof, &output->range_proof_len);
}

int wally_psbt_elements_output_set_surjection_proof(struct wally_psbt_output *output,
                                                    const unsigned char *surjection_proof,
                                                    size_t surjection_proof_len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(surjection_proof, surjection_proof_len,
                         &output->surjection_proof, &output->surjection_proof_len);
}
#endif/* BUILD_ELEMENTS */

static int psbt_output_free(struct wally_psbt_output *output, bool free_parent)
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

        wally_clear(output, sizeof(*output));
        if (free_parent)
            wally_free(output);
    }
    return WALLY_OK;
}

int wally_psbt_init_alloc(
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    struct wally_psbt **output)
{
    struct wally_psbt *result;
    int ret;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_psbt);

    if (inputs_allocation_len)
        result->inputs = wally_calloc(inputs_allocation_len * sizeof(struct wally_psbt_input));
    if (outputs_allocation_len)
        result->outputs = wally_calloc(outputs_allocation_len * sizeof(struct wally_psbt_output));

    ret = wally_unknowns_map_init_alloc(global_unknowns_allocation_len, &result->unknowns);

    if (ret != WALLY_OK ||
        (inputs_allocation_len && !result->inputs) || (outputs_allocation_len && !result->outputs)) {
        wally_psbt_free(result);
        return ret != WALLY_OK ? ret : WALLY_ENOMEM;
    }

    /* Version is always 0 */
    result->version = 0;
    memcpy(result->magic, WALLY_PSBT_MAGIC, sizeof(WALLY_PSBT_MAGIC));
    result->inputs_allocation_len = inputs_allocation_len;
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
    int ret = wally_psbt_init_alloc(inputs_allocation_len,
                                    outputs_allocation_len,
                                    global_unknowns_allocation_len, output);
    if (ret == WALLY_OK)
        memcpy((*output)->magic, WALLY_ELEMENTS_PSBT_MAGIC, sizeof(WALLY_ELEMENTS_PSBT_MAGIC));

    return ret;
}
#endif /* BUILD_ELEMENTS */

int wally_psbt_free(struct wally_psbt *psbt)
{
    size_t i;
    if (psbt) {
        wally_tx_free(psbt->tx);
        for (i = 0; i < psbt->num_inputs; ++i)
            psbt_input_free(&psbt->inputs[i], false);

        wally_free(psbt->inputs);
        for (i = 0; i < psbt->num_outputs; ++i)
            psbt_output_free(&psbt->outputs[i], false);

        wally_free(psbt->outputs);
        wally_unknowns_map_free(psbt->unknowns);
        clear_and_free(psbt, sizeof(*psbt));
    }
    return WALLY_OK;
}

int wally_psbt_get_global_tx_alloc(const struct wally_psbt *psbt, struct wally_tx **output)
{
    TX_CHECK_OUTPUT;
    if (!psbt)
        return WALLY_EINVAL;
    if (!psbt->tx)
        return WALLY_OK; /* Return a NULL tx if not present */
    return wally_tx_clone(psbt->tx, 0, output);
}

#define PSBT_GET(name) \
    int wally_psbt_get_ ## name(const struct wally_psbt *psbt, size_t *written) { \
        if (written) \
            *written = 0; \
        if (!psbt || !written) \
            return WALLY_EINVAL; \
        *written = psbt->name; \
        return WALLY_OK; \
    }

PSBT_GET(version)
PSBT_GET(num_inputs)
PSBT_GET(num_outputs)

static int psbt_set_global_tx(struct wally_psbt *psbt, struct wally_tx *tx, bool do_clone)
{
    struct wally_tx *new_tx = NULL;
    struct wally_psbt_input *new_inputs = NULL;
    struct wally_psbt_output *new_outputs = NULL;
    size_t i;
    int ret;

    if (!psbt || psbt->tx || psbt->num_inputs || psbt->num_outputs || !tx)
        return WALLY_EINVAL; /* PSBT must be completely empty */

    for (i = 0; i < tx->num_inputs; ++i)
        if (tx->inputs[i].script || tx->inputs[i].witness)
            return WALLY_EINVAL; /* tx mustn't have scriptSigs or witnesses */

    if (do_clone && (ret = wally_tx_clone(tx, 0, &new_tx)) != WALLY_OK)
        return ret;

    if (psbt->inputs_allocation_len < tx->num_inputs)
        new_inputs = wally_calloc(tx->num_inputs * sizeof(struct wally_psbt_input));

    if (psbt->outputs_allocation_len < tx->num_outputs)
        new_outputs = wally_calloc(tx->num_outputs * sizeof(struct wally_psbt_output));

    if ((psbt->inputs_allocation_len < tx->num_inputs && !new_inputs) ||
        (psbt->outputs_allocation_len < tx->num_outputs && !new_outputs)) {
        wally_free(new_inputs);
        wally_free(new_outputs);
        wally_tx_free(new_tx);
        return WALLY_ENOMEM;
    }

    if (new_inputs) {
        wally_free(psbt->inputs);
        psbt->inputs = new_inputs;
        psbt->inputs_allocation_len = tx->num_inputs;
    }
    if (new_outputs) {
        wally_free(psbt->outputs);
        psbt->outputs = new_outputs;
        psbt->outputs_allocation_len = tx->num_outputs;
    }
    psbt->num_inputs = tx->num_inputs;
    psbt->num_outputs = tx->num_outputs;
    psbt->tx = do_clone ? new_tx : tx;
    return WALLY_OK;
}

int wally_psbt_set_global_tx(struct wally_psbt *psbt, const struct wally_tx *tx)
{
    return psbt_set_global_tx(psbt, (struct wally_tx *)tx, true);
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
                        struct wally_keypath_map **keypaths)
{
    const unsigned char *val;
    size_t i, val_max, is_found;
    const unsigned char *fingerprint;
    int ret;

    if (!is_valid_pubkey_len(key_len))
        return WALLY_EINVAL;

    if (!*keypaths && (ret = wally_keypath_map_init_alloc(1, keypaths)) != WALLY_OK)
        return ret;

    ret = wally_keypath_map_find(*keypaths, key, key_len, &is_found);
    if (ret == WALLY_OK && is_found)
        ret = WALLY_EINVAL; /* Duplicates are invalid */
    if (ret != WALLY_OK)
        return ret;

    pull_subfield_end(cursor, max, key, key_len);

    /* Start parsing the value field. */
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

    /* Read the fingerprint */
    fingerprint = pull_skip(&val, &val_max, sizeof(BIP32_KEY_FINGERPRINT_LEN));

    ret = wally_keypath_map_add(*keypaths, key, key_len,
                                fingerprint, BIP32_KEY_FINGERPRINT_LEN, NULL, 0);
    if (ret == WALLY_OK) {
        /* Remainder is the path */
        struct wally_keypath_item *kpitem;
        kpitem = (*keypaths)->items + (*keypaths)->num_items - 1;
        if ((kpitem->path = wally_malloc(val_max)) == NULL)
            return WALLY_ENOMEM;

        kpitem->path_len = val_max / sizeof(uint32_t);
        for (i = 0; val_max >= sizeof(uint32_t); ++i) {
            kpitem->path[i] = pull_le32(&val, &val_max);
        }
        subfield_nomore_end(cursor, max, val, val_max);
    }
    return ret;
}

/* The remainder of the key is a public key, the value is a signature */
static int pull_partial_sig(const unsigned char **cursor, size_t *max,
                            const unsigned char *key, size_t key_len,
                            struct wally_partial_sigs_map **partial_sigs)
{
    const unsigned char *val;
    size_t val_len, is_found;
    int ret;

    if (!is_valid_pubkey_len(key_len))
        return WALLY_EINVAL;

    if (!*partial_sigs && wally_partial_sigs_map_init_alloc(1, partial_sigs) != WALLY_OK)
        return WALLY_ENOMEM;

    ret = wally_partial_sigs_map_find(*partial_sigs, key, key_len, &is_found);
    if (ret == WALLY_OK && is_found)
        ret = WALLY_EINVAL; /* Duplicates are invalid */
    if (ret != WALLY_OK)
        return ret;

    pull_subfield_end(cursor, max, key, key_len);

    val_len = pull_varlength(cursor, max);
    val = pull_skip(cursor, max, val_len);

    return wally_partial_sigs_map_add(*partial_sigs, key, key_len, val, val_len);
}

/* Rewind cursor to prekey, and append unknown key/value to unknowns */
static int pull_unknown_key_value(const unsigned char **cursor,
                                  size_t *max,
                                  const unsigned char *pre_key,
                                  struct wally_unknowns_map **unknowns)
{
    const unsigned char *key, *val;
    size_t key_len, val_len, is_found;
    int ret;

    /* If we've already failed, it's invalid */
    if (!*cursor)
        return WALLY_EINVAL;

    if (!*unknowns && wally_unknowns_map_init_alloc(1, unknowns) != WALLY_OK)
        return WALLY_ENOMEM;

    /* We have to unwind a bit, to get entire key again. */
    *max += (*cursor - pre_key);
    *cursor = pre_key;

    key_len = pull_varlength(cursor, max);
    key = pull_skip(cursor, max, key_len);
    val_len = pull_varlength(cursor, max);
    val = pull_skip(cursor, max, val_len);

    ret = wally_unknowns_map_find(*unknowns, key, key_len, &is_found);
    if (ret == WALLY_OK && is_found)
        ret = WALLY_EINVAL; /* Duplicates are invalid */
    if (ret != WALLY_OK)
        return ret;

    return wally_unknowns_map_add(*unknowns, key, key_len, val, val_len);
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
    unsigned char empty = 0;
    push_bytes(cursor, max, value ? value : &empty, value ? val_len : sizeof(empty));
}

static int pull_elements_confidential(const unsigned char **cursor,
                                      size_t *max,
                                      const unsigned char **value,
                                      size_t *val_len,
                                      size_t prefixA, size_t prefixB,
                                      size_t prefixed_size, size_t explicit_size)
{
    /* First byte is always the 'version' which tells you what the value is */
    const uint8_t type = peek_u8(cursor, max);
    size_t size;

    if (type == 0) {
        /* Empty, Pop off the type */
        pull_u8(cursor, max);
        *value = NULL;
        *val_len = 0;
        return WALLY_OK;
    }

    if (type == 1)
        size = explicit_size;
    else if (type == prefixA || type == prefixB)
        size = prefixed_size;
    else
        return WALLY_EINVAL;

    *value = pull_skip(cursor, max, size);
    if (!*cursor)
        return WALLY_EINVAL;
    *val_len = size;
    return WALLY_OK;
}

/* Either returns a 33-byte commitment to a confidential value, or
 * a 64-bit explicit value. */
static int pull_confidential_value(const unsigned char **cursor,
                                   size_t *max,
                                   const unsigned char **value,
                                   size_t *val_len)

{
    return pull_elements_confidential(cursor, max, value, val_len,
                                      WALLY_TX_ASSET_CT_VALUE_PREFIX_A, WALLY_TX_ASSET_CT_VALUE_PREFIX_B,
                                      WALLY_TX_ASSET_CT_VALUE_LEN, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
}

static int pull_confidential_asset(const unsigned char **cursor,
                                   size_t *max,
                                   const unsigned char **asset,
                                   size_t *asset_len)

{
    return pull_elements_confidential(cursor, max, asset, asset_len,
                                      WALLY_TX_ASSET_CT_ASSET_PREFIX_A, WALLY_TX_ASSET_CT_ASSET_PREFIX_B,
                                      WALLY_TX_ASSET_CT_ASSET_LEN, WALLY_TX_ASSET_CT_ASSET_LEN);
}

static int pull_nonce(const unsigned char **cursor,
                      size_t *max,
                      const unsigned char **nonce,
                      size_t *nonce_len)

{
    return pull_elements_confidential(cursor, max, nonce, nonce_len,
                                      WALLY_TX_ASSET_CT_NONCE_PREFIX_A, WALLY_TX_ASSET_CT_NONCE_PREFIX_B,
                                      WALLY_TX_ASSET_CT_NONCE_LEN, WALLY_TX_ASSET_CT_NONCE_LEN);
}

#endif /* BUILD_ELEMENTS */

static int pull_psbt_input(
    const unsigned char **cursor,
    size_t *max,
    uint32_t flags,
    struct wally_psbt_input *result)
{
    int ret;
    size_t key_len;
    const unsigned char *pre_key;

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
            if (result->non_witness_utxo) {
                return WALLY_EINVAL;     /* We already have a non witness utxo */
            }
            subfield_nomore_end(cursor, max, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(cursor, max,
                                pull_varint(cursor, max),
                                &val, &val_max);
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
            if (flags & WALLY_TX_FLAG_USE_ELEMENTS) {
                const unsigned char *asset, *value, *nonce;
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
                if (!script || !script_len) {
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
            if (!script || !script_len) {
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
            ret = pull_partial_sig(cursor, max, key, key_len, &result->partial_sigs);
            if (ret != WALLY_OK)
                return ret;
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
            ret = pull_keypath(cursor, max, key, key_len, &result->keypaths);
            if (ret != WALLY_OK)
                return ret;
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

                    ret = wally_tx_from_bytes(val, val_max, flags, &result->peg_in_tx);
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
            ret = pull_unknown_key_value(cursor, max, pre_key, &result->unknowns);
            if (ret != WALLY_OK)
                return ret;
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
    struct wally_psbt_output *result)
{
    int ret;
    size_t key_len;
    const unsigned char *pre_key;

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
            ret = pull_keypath(cursor, max, key, key_len, &result->keypaths);
            if (ret != WALLY_OK)
                return ret;
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
                    valid_type = true;
                    if (result->blinding_pubkey) {
                        return WALLY_EINVAL;    /* Already have blinding pubkey */
                    }
                    subfield_nomore_end(cursor, max, key, key_len);

                    if (!clone_varlength(&result->blinding_pubkey,
                                         &result->blinding_pubkey_len,
                                         cursor, max)) {
                        return WALLY_ENOMEM;
                    }
                    if (!is_valid_optional_pubkey_len(result->blinding_pubkey_len))
                        return WALLY_EINVAL;
                    if (result->blinding_pubkey_len == 0)
                        result->blinding_pubkey = wally_malloc(1);
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
            ret = pull_unknown_key_value(cursor, max, pre_key, &result->unknowns);
            if (ret != WALLY_OK)
                return ret;
            break;
        }
        }
        pre_key = *cursor;
    }

    return WALLY_OK;
}

int wally_psbt_from_bytes(const unsigned char *bytes, size_t len,
                          struct wally_psbt **output)
{
    const unsigned char *magic, *pre_key;
    int ret;
    size_t i, key_len;
    struct wally_psbt *result = NULL;
    uint32_t flags = 0;

    TX_CHECK_OUTPUT;

    magic = pull_skip(&bytes, &len, sizeof(WALLY_PSBT_MAGIC));
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
        flags |= WALLY_TX_FLAG_USE_ELEMENTS;
#else
        ret = WALLY_EINVAL;  /* Invalid Magic */
        goto fail;
#endif /* BUILD_ELEMENTS */
    }

    /* Make the wally_psbt */
    ret = wally_psbt_init_alloc(0, 0, 8, &result);
    if (ret != WALLY_OK)
        goto fail;

    /* Set the magic */
    memcpy(result->magic, magic, sizeof(WALLY_PSBT_MAGIC));

    /* Read globals first */
    pre_key = bytes;
    while ((key_len = pull_varlength(&bytes, &len)) != 0) {
        const unsigned char *key, *val;
        size_t val_max;

        /* Start parsing key */
        pull_subfield_start(&bytes, &len, key_len, &key, &key_len);

        /* Process based on type */
        switch (pull_varint(&key, &key_len)) {
        case WALLY_PSBT_GLOBAL_UNSIGNED_TX: {
            struct wally_tx *tx;

            subfield_nomore_end(&bytes, &len, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(&bytes, &len,
                                pull_varint(&bytes, &len),
                                &val, &val_max);
            ret = wally_tx_from_bytes(val, val_max, flags, &tx);
            if (ret == WALLY_OK) {
                ret = psbt_set_global_tx(result, tx, false);
                if (ret != WALLY_OK)
                    wally_tx_free(tx);
            }
            if (ret != WALLY_OK)
                goto fail;
            pull_subfield_end(&bytes, &len, val, val_max);
            break;
        }
        case WALLY_PSBT_GLOBAL_VERSION: {
            if (result->version > 0) {
                ret = WALLY_EINVAL;    /* Version already provided */
                goto fail;
            }
            subfield_nomore_end(&bytes, &len, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(&bytes, &len,
                                pull_varint(&bytes, &len),
                                &val, &val_max);
            result->version = pull_le32(&val, &val_max);
            subfield_nomore_end(&bytes, &len, val, val_max);
            if (result->version > WALLY_PSBT_HIGHEST_VERSION) {
                ret = WALLY_EINVAL;    /* Unsupported version number */
                goto fail;
            }
            break;
        }
        /* Unknowns */
        default: {
            ret = pull_unknown_key_value(&bytes, &len, pre_key, &result->unknowns);
            if (ret != WALLY_OK)
                goto fail;
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
    for (i = 0; i < result->tx->num_inputs; ++i) {
        ret = pull_psbt_input(&bytes, &len, flags, &result->inputs[i]);
        if (ret != WALLY_OK)
            goto fail;
    }

    /* Read outputs */
    for (i = 0; i < result->tx->num_outputs; ++i) {
        ret = pull_psbt_output(&bytes, &len, &result->outputs[i]);
        if (ret != WALLY_OK)
            goto fail;
    }

    /* If we ran out of data anywhere, fail. */
    if (!bytes) {
        ret = WALLY_EINVAL;
        goto fail;
    }

    *output = result;
    return WALLY_OK;

fail:
    wally_psbt_free(result);
    return ret;
}

int wally_psbt_get_length(const struct wally_psbt *psbt, uint32_t flags, size_t *written)
{
    return wally_psbt_to_bytes(psbt, flags, NULL, 0, written);
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
    const struct wally_tx *tx, uint32_t flags)
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

    return wally_tx_to_bytes(tx, flags, p, txlen, &txlen);
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

    push_psbt_key(cursor, max, type, item->pubkey,
                  get_pubkey_len(item->pubkey, sizeof(item->pubkey)));

    origin_len = 4;     /* Start with 4 bytes for fingerprint */
    origin_len += item->path_len * sizeof(uint32_t);
    push_varint(cursor, max, origin_len);

    push_bytes(cursor, max, item->fingerprint, 4);
    for (i = 0; i < item->path_len; ++i) {
        push_bytes(cursor, max, &item->path[i], sizeof(uint32_t));
    }
}

static int push_psbt_input(
    unsigned char **cursor, size_t *max,
    uint32_t flags,
    const struct wally_psbt_input *input)
{
    int ret;
    size_t i;

    (void)flags;

    /* Non witness utxo */
    if (input->non_witness_utxo) {
        push_psbt_key(cursor, max, WALLY_PSBT_IN_NON_WITNESS_UTXO, NULL, 0);
        ret = push_length_and_tx(cursor, max,
                                 input->non_witness_utxo,
                                 WALLY_TX_FLAG_USE_WITNESS);
        if (ret != WALLY_OK) {
            return ret;
        }
    }

    /* Witness utxo */
#ifdef BUILD_ELEMENTS
    if ((flags & WALLY_TX_FLAG_USE_ELEMENTS) && input->witness_utxo) {
        struct wally_tx_output *utxo = input->witness_utxo;
        const size_t buff_len = push_elements_bytes_size(utxo);
        size_t remaining = buff_len;
        unsigned char buff[1024], *buff_p = buff, *ptr;

        if (buff_len > sizeof(buff) && !(buff_p = wally_malloc(buff_len)))
            return WALLY_ENOMEM;
        ptr = buff_p;

        /* Push the asset, value, nonce, then scriptpubkey */
        push_psbt_key(cursor, max, WALLY_PSBT_IN_WITNESS_UTXO, NULL, 0);

        push_elements_bytes(&ptr, &remaining, utxo->asset, utxo->asset_len);
        push_elements_bytes(&ptr, &remaining, utxo->value, utxo->value_len);
        push_elements_bytes(&ptr, &remaining, utxo->nonce, utxo->nonce_len);
        push_varbuff(&ptr, &remaining, utxo->script, utxo->script_len);

        if (!remaining)
            push_varbuff(cursor, max, buff_p, buff_len);
        if (buff_p != buff)
            clear_and_free(buff_p, buff_len);
        if (remaining)
            return WALLY_ERROR; /* Should not happen! */
    } else
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
            const struct wally_partial_sigs_item *p = &partial_sigs->items[i];

            push_psbt_key(cursor, max, WALLY_PSBT_IN_PARTIAL_SIG,
                          p->pubkey, get_pubkey_len(p->pubkey, sizeof(p->pubkey)));
            push_varbuff(cursor, max, p->sig, p->sig_len);
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
        for (i = 0; i < input->keypaths->num_items; ++i) {
            push_keypath_item(cursor, max,
                              WALLY_PSBT_IN_BIP32_DERIVATION,
                              &input->keypaths->items[i]);
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
                                 WALLY_TX_FLAG_USE_WITNESS);
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
        for (i = 0; i < output->keypaths->num_items; ++i) {
            push_keypath_item(cursor, max,
                              WALLY_PSBT_OUT_BIP32_DERIVATION,
                              &output->keypaths->items[i]);
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
    if (output->blinding_pubkey) {
        push_psbt_elements_key(cursor, max, WALLY_PSBT_OUT_ELEMENTS_BLINDING_PUBKEY, NULL, 0);
        push_varbuff(cursor, max, output->blinding_pubkey, output->blinding_pubkey_len);
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

int wally_psbt_to_bytes(const struct wally_psbt *psbt, uint32_t flags,
                        unsigned char *bytes_out, size_t len,
                        size_t *written)
{
    unsigned char *cursor = bytes_out;
    size_t max = len, i, is_elements;
    uint32_t tx_flags;
    int ret;

    if (written)
        *written = 0;

    if (flags != 0 || !written)
        return WALLY_EINVAL;

    if ((ret = wally_psbt_is_elements(psbt, &is_elements)) != WALLY_OK)
        return ret;

    tx_flags = is_elements ? WALLY_TX_FLAG_USE_ELEMENTS : 0;
    push_bytes(&cursor, &max, psbt->magic, sizeof(psbt->magic));

    /* Global tx */
    push_psbt_key(&cursor, &max, WALLY_PSBT_GLOBAL_UNSIGNED_TX, NULL, 0);
    push_length_and_tx(&cursor, &max, psbt->tx, WALLY_TX_FLAG_ALLOW_PARTIAL);

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
    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        ret = push_psbt_input(&cursor, &max, tx_flags, input);
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
        *written = len + max;
    } else {
        *written = len - max;
    }

    return WALLY_OK;
}

int wally_psbt_from_base64(const char *base64, struct wally_psbt **output)
{
    char *decoded;
    size_t safe_len, base64_len;
    ssize_t decoded_len;
    int ret;

    TX_CHECK_OUTPUT;
    if (!base64)
        return WALLY_EINVAL;

    base64_len = strlen(base64);
    /* Allocate the decoded buffer */
    safe_len = base64_decoded_length(base64_len);
    if ((decoded = wally_malloc(safe_len)) == NULL) {
        ret = WALLY_ENOMEM;
        goto done;
    }

    /* Decode the base64 psbt */
    decoded_len = base64_decode(decoded, safe_len, base64, base64_len);
    if (decoded_len <= (ssize_t)sizeof(WALLY_PSBT_MAGIC)) {
        ret = WALLY_EINVAL; /* Not enough bytes for the magic */
        goto done;
    }

    /* Now decode the psbt */
    ret = wally_psbt_from_bytes((unsigned char *)decoded, decoded_len, output);

done:
    clear_and_free(decoded, safe_len);
    return ret;
}

int wally_psbt_to_base64(const struct wally_psbt *psbt, uint32_t flags, char **output)
{
    unsigned char *buff;
    char *result = NULL;
    size_t len, written, b64_safe_len = 0;
    int ret = WALLY_OK;

    TX_CHECK_OUTPUT;
    if (!psbt)
        return WALLY_EINVAL;

    if ((ret = wally_psbt_get_length(psbt, flags, &len)) != WALLY_OK)
        return ret;

    if ((buff = wally_malloc(len)) == NULL)
        return WALLY_ENOMEM;

    /* Get psbt bytes */
    if ((ret = wally_psbt_to_bytes(psbt, flags, buff, len, &written)) != WALLY_OK)
        goto done;

    if (written != len) {
        ret = WALLY_ERROR; /* Length calculated incorrectly */
        goto done;
    }

    /* Base64 encode */
    b64_safe_len = base64_encoded_length(written) + 1; /* + 1 for null termination */
    if ((result = wally_malloc(b64_safe_len)) == NULL) {
        ret = WALLY_ENOMEM;
        goto done;
    }
    if (base64_encode(result, b64_safe_len, (char *)buff, written) <= 0) {
        ret = WALLY_EINVAL;
        goto done;
    }
    *output = result;
    result = NULL;

done:
    clear_and_free(result, b64_safe_len);
    clear_and_free(buff, len);
    return ret;
}

static int combine_unknowns(struct wally_unknowns_map **dst,
                            const struct wally_unknowns_map *src)
{
    int ret = WALLY_OK;
    size_t i;

    if (!dst)
        return WALLY_EINVAL;

    if (!src)
        return WALLY_OK; /* No-op */

    if (!*dst)
        ret = wally_unknowns_map_init_alloc(src->items_allocation_len, dst);

    for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
        ret = add_unknowns_item(*dst, &src->items[i]);

    return ret;
}

static int combine_keypath(struct wally_keypath_map **dst,
                           const struct wally_keypath_map *src)
{
    int ret = WALLY_OK;
    size_t i;

    if (!dst)
        return WALLY_EINVAL;

    if (!src)
        return WALLY_OK; /* No-op */

    if (!*dst)
        ret = wally_keypath_map_init_alloc(src->items_allocation_len, dst);

    for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
        ret = add_keypath_item(*dst, &src->items[i]);

    return ret;
}

static int combine_partial_sigs(struct wally_partial_sigs_map **dst,
                                const struct wally_partial_sigs_map *src)
{
    int ret = WALLY_OK;
    size_t i;

    if (!dst)
        return WALLY_EINVAL;

    if (!src)
        return WALLY_OK; /* No-op */

    if (!*dst)
        ret = wally_partial_sigs_map_init_alloc(src->items_allocation_len, dst);

    for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
        ret = add_partial_sig_item(*dst, &src->items[i]);

    return ret;
}

#define COMBINE_BYTES(typ, member) \
    if (!dst->member && src->member && \
        (ret = wally_psbt_ ## typ ## _set_ ## member(dst, src->member, src->member ## _len)) != WALLY_OK) \
        return ret

#define COMBINE_ELEMENTS_BYTES(typ, member) \
    if (!dst->member && src->member && \
        (ret = wally_psbt_elements_ ## typ ## _set_ ## member(dst, src->member, src->member ## _len)) != WALLY_OK) \
        return ret

static int combine_txs(struct wally_tx **dst, struct wally_tx *src)
{
    if (!dst)
        return WALLY_EINVAL;

    if (!*dst && src)
        return wally_tx_clone(src, 0, dst);

    return WALLY_OK;
}

static int combine_inputs(struct wally_psbt_input *dst,
                          const struct wally_psbt_input *src)
{
    int ret;

    if ((ret = combine_txs(&dst->non_witness_utxo, src->non_witness_utxo)) != WALLY_OK)
        return ret;

    if (!dst->witness_utxo && src->witness_utxo) {
        const struct wally_tx_output *src_utxo = src->witness_utxo;
#ifdef BUILD_ELEMENTS
        ret = wally_tx_elements_output_init_alloc(
            src_utxo->script, src_utxo->script_len,
            src_utxo->asset, src_utxo->asset_len,
            src_utxo->value, src_utxo->value_len,
            src_utxo->nonce, src_utxo->nonce_len,
            src_utxo->surjectionproof, src_utxo->surjectionproof_len,
            src_utxo->rangeproof, src_utxo->rangeproof_len,
#else
        ret = wally_tx_output_init_alloc(
            src_utxo->satoshi,
            src_utxo->script,
            src_utxo->script_len,
#endif
            &dst->witness_utxo);
        if (ret != WALLY_OK)
            return ret;
    }

    COMBINE_BYTES(input, redeem_script);
    COMBINE_BYTES(input, witness_script);
    COMBINE_BYTES(input, final_script_sig);

    if (!dst->final_witness && src->final_witness &&
        (ret = wally_psbt_input_set_final_witness(dst, src->final_witness)) != WALLY_OK)
        return ret;
    if ((ret = combine_keypath(&dst->keypaths, src->keypaths)) != WALLY_OK)
        return ret;
    if ((ret = combine_partial_sigs(&dst->partial_sigs, src->partial_sigs)) != WALLY_OK)
        return ret;
    if ((ret = combine_unknowns(&dst->unknowns, src->unknowns)) != WALLY_OK)
        return ret;
    if (!dst->sighash_type && src->sighash_type)
        dst->sighash_type = src->sighash_type;

#ifdef BUILD_ELEMENTS
    if (!dst->has_value && src->has_value) {
        dst->value = src->value;
        dst->has_value = true;
    }
    COMBINE_ELEMENTS_BYTES(input, value_blinder);
    COMBINE_ELEMENTS_BYTES(input, asset);
    COMBINE_ELEMENTS_BYTES(input, asset_blinder);
    if ((ret = combine_txs(&dst->peg_in_tx, src->peg_in_tx)) != WALLY_OK)
        return ret;
    COMBINE_ELEMENTS_BYTES(input, txout_proof);
    COMBINE_ELEMENTS_BYTES(input, genesis_hash);
    COMBINE_ELEMENTS_BYTES(input, claim_script);
#endif
    return WALLY_OK;
}

static int combine_outputs(struct wally_psbt_output *dst,
                           const struct wally_psbt_output *src)
{
    int ret;

    if ((ret = combine_keypath(&dst->keypaths, src->keypaths)) != WALLY_OK)
        return ret;
    if ((ret = combine_unknowns(&dst->unknowns, src->unknowns)) != WALLY_OK)
        return ret;

    COMBINE_BYTES(output, redeem_script);
    COMBINE_BYTES(output, witness_script);

#ifdef BUILD_ELEMENTS
    COMBINE_ELEMENTS_BYTES(output, blinding_pubkey);
    COMBINE_ELEMENTS_BYTES(output, value_commitment);
    COMBINE_ELEMENTS_BYTES(output, value_blinder);
    COMBINE_ELEMENTS_BYTES(output, asset_commitment);
    COMBINE_ELEMENTS_BYTES(output, asset_blinder);
    COMBINE_ELEMENTS_BYTES(output, nonce_commitment);
    COMBINE_ELEMENTS_BYTES(output, range_proof);
    COMBINE_ELEMENTS_BYTES(output, surjection_proof);
#endif
    return WALLY_OK;
}
#undef COMBINE_BYTES
#undef COMBINE_ELEMENTS_BYTES

int wally_psbt_combine(struct wally_psbt *psbt, const struct wally_psbt *src)
{
    unsigned char txid[WALLY_TXHASH_LEN], src_txid[WALLY_TXHASH_LEN];
    size_t i;
    int ret;

    if (!psbt || !psbt->tx || !src || !src->tx)
        return WALLY_EINVAL;

    ret = wally_tx_get_txid(psbt->tx, txid, sizeof(txid));
    if (ret == WALLY_OK)
        ret = wally_tx_get_txid(src->tx, src_txid, sizeof(src_txid));

    if (ret == WALLY_OK && memcmp(txid, src_txid, sizeof(txid)) != 0)
        ret = WALLY_EINVAL; /* Transactions don't match */

    for (i = 0; ret == WALLY_OK && i < psbt->num_inputs; ++i)
        ret = combine_inputs(&psbt->inputs[i], &src->inputs[i]);

    for (i = 0; ret == WALLY_OK && i < psbt->num_outputs; ++i)
        ret = combine_outputs(&psbt->outputs[i], &src->outputs[i]);

    if (ret == WALLY_OK)
        ret = combine_unknowns(&psbt->unknowns, src->unknowns);

    return ret;
}

int wally_psbt_sign(struct wally_psbt *psbt,
                    const unsigned char *key, size_t key_len)
{
    unsigned char pubkey[EC_PUBLIC_KEY_LEN], full_pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    unsigned char sig[EC_SIGNATURE_LEN], der_sig[EC_SIGNATURE_DER_MAX_LEN + 1];
    const size_t pubkey_len = sizeof(pubkey), full_pubkey_len = sizeof(full_pubkey);
    size_t i, der_sig_len, is_elements;
    int ret;

    if (!psbt || !psbt->tx || !key || key_len != EC_PRIVATE_KEY_LEN) {
        return WALLY_EINVAL;
    }

    if ((ret = wally_psbt_is_elements(psbt, &is_elements)) != WALLY_OK)
        return ret;

    /* Get the pubkey */
    if ((ret = wally_ec_public_key_from_private_key(key, key_len, pubkey, pubkey_len)) != WALLY_OK) {
        return ret;
    }
    if ((ret = wally_ec_public_key_decompress(pubkey, pubkey_len, full_pubkey, full_pubkey_len)) != WALLY_OK) {
        return ret;
    }

    /* Go through each of the inputs */
    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        struct wally_tx_input *txin = &psbt->tx->inputs[i];
        unsigned char sighash[SHA256_LEN], *scriptcode, wpkh_sc[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
        size_t keypath_index = 0, scriptcode_len;
        bool is_compressed;
        uint32_t sighash_type;

        /* See if this input has a keypath matching the pubkey of the private key supplied */
        if (input->keypaths) {
            ret = wally_keypath_map_find(input->keypaths, full_pubkey, full_pubkey_len, &keypath_index);
            if (ret == WALLY_OK && !keypath_index)
                ret = wally_keypath_map_find(input->keypaths, pubkey, pubkey_len, &keypath_index);
            if (ret != WALLY_OK)
                return ret;
        }

        if (!keypath_index)
            continue; /* Didn't find a keypath matching this pubkey: skip it */

        is_compressed = pubkey_is_compressed(input->keypaths->items[keypath_index - 1].pubkey);

        /* Make sure we don't already have a sig for this input ?! */
        if (input->partial_sigs) {
            size_t is_found;
            ret = wally_partial_sigs_map_find(input->partial_sigs, full_pubkey, full_pubkey_len, &is_found);
            if (ret == WALLY_OK && !is_found)
                ret = wally_partial_sigs_map_find(input->partial_sigs, pubkey, pubkey_len, &is_found);
            if (ret != WALLY_OK)
                return ret;

            if (is_found)
                continue; /* Already got a partial sig for this pubkey on this input */
        }

        sighash_type = input->sighash_type ? input->sighash_type : WALLY_SIGHASH_ALL;

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
            unsigned char txid[WALLY_TXHASH_LEN];

            if ((ret = wally_tx_get_txid(input->non_witness_utxo, txid, sizeof(txid))) != WALLY_OK) {
                return ret;
            }
            if (memcmp(txid, txin->txhash, sizeof(txid)) != 0) {
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
                    memcmp(wsh, scriptcode, WALLY_SCRIPTPUBKEY_P2WSH_LEN) != 0) {
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
        if (!input->partial_sigs &&
            (ret = wally_partial_sigs_map_init_alloc(1, &input->partial_sigs)) != WALLY_OK)
            return ret;

        ret = wally_partial_sigs_map_add(input->partial_sigs,
                                         is_compressed ? pubkey : full_pubkey,
                                         is_compressed ? pubkey_len : full_pubkey_len,
                                         der_sig, der_sig_len);
        if (ret != WALLY_OK)
            return ret;
    }

    return WALLY_OK;
}

int wally_psbt_finalize(struct wally_psbt *psbt)
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
                    if (!input->final_script_sig) {
                        return WALLY_ENOMEM;
                    }
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
                if (!input->final_script_sig) {
                    return WALLY_ENOMEM;
                }
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

int wally_psbt_extract(
    const struct wally_psbt *psbt,
    struct wally_tx **output)
{
    struct wally_tx *result = NULL;
    size_t i;
    int ret;

    TX_CHECK_OUTPUT;

    if (!psbt || !psbt->tx || !psbt->num_inputs || !psbt->num_outputs ||
        psbt->tx->num_inputs < psbt->num_inputs || psbt->tx->num_outputs < psbt->num_outputs)
        return WALLY_EINVAL;

    if ((ret = wally_tx_clone(psbt->tx, 0, &result)) != WALLY_OK)
        return ret;

    for (i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input *input = &psbt->inputs[i];
        struct wally_tx_input *vin = &result->inputs[i];

        if (!input->final_script_sig && !input->final_witness) {
            ret = WALLY_EINVAL;
            break;
        }

        if (input->final_script_sig) {
            if (vin->script) {
                /* Our global tx shouldn't have a scriptSig */
                ret = WALLY_EINVAL;
                break;
            }
            if (!clone_bytes(&vin->script, input->final_script_sig, input->final_script_sig_len)) {
                ret = WALLY_ENOMEM;
                break;
            }
            vin->script_len = input->final_script_sig_len;
        }
        if (input->final_witness) {
            if (vin->witness) {
                /* Our global tx shouldn't have a witness */
                ret = WALLY_EINVAL;
                break;
            }
            ret = wally_tx_witness_stack_clone_alloc(input->final_witness, &vin->witness);
            if (ret != WALLY_OK)
                break;
        }
    }

    if (ret == WALLY_OK)
        *output = result;
    else
        wally_tx_free(result);
    return ret;
}

int wally_psbt_is_elements(const struct wally_psbt *psbt, size_t *written)
{
    if (!psbt || !written)
        return WALLY_EINVAL;

    *written = memcmp(psbt->magic, WALLY_ELEMENTS_PSBT_MAGIC, sizeof(psbt->magic)) ? 0 : 1;
    return WALLY_OK;
}

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined (SWIG_JAVASCRIPT_BUILD)

static struct wally_psbt_input *psbt_get_input(const struct wally_psbt *psbt, size_t index)
{
    return psbt && index < psbt->num_inputs ? &psbt->inputs[index] : NULL;
}

static struct wally_psbt_output *psbt_get_output(const struct wally_psbt *psbt, size_t index)
{
    return psbt && index < psbt->num_outputs ? &psbt->outputs[index] : NULL;
}

/* Set a binary buffer value on an input/output */
#define PSBT_SET_B(typ, name) \
    int wally_psbt_set_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index, \
                                            const unsigned char *name, size_t name ## _len) { \
        return wally_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), name, name ## _len); \
    }

/* Set an integer value on an input/output */
#define PSBT_SET_I(typ, name, inttyp) \
    int wally_psbt_set_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index, \
                                            inttyp v) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (!p) \
            return WALLY_EINVAL; \
        p->name = v; \
        return WALLY_OK; \
    }

/* Set a struct on an input/output */
#define PSBT_SET_S(typ, name, structtyp) \
    int wally_psbt_set_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index, \
                                            const struct structtyp *p) { \
        return wally_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), p); \
    }


PSBT_SET_S(input, non_witness_utxo, wally_tx)
PSBT_SET_S(input, witness_utxo, wally_tx_output)
PSBT_SET_B(input, redeem_script)
PSBT_SET_B(input, witness_script)
PSBT_SET_B(input, final_script_sig)
PSBT_SET_S(input, final_witness, wally_tx_witness_stack)
PSBT_SET_S(input, keypaths, wally_keypath_map)
PSBT_SET_S(input, partial_sigs, wally_partial_sigs_map)
PSBT_SET_S(input, unknowns, wally_unknowns_map)
PSBT_SET_I(input, sighash_type, uint32_t)

PSBT_SET_B(output, redeem_script)
PSBT_SET_B(output, witness_script)
PSBT_SET_S(output, keypaths, wally_keypath_map)
PSBT_SET_S(output, unknowns, wally_unknowns_map)

#endif /* SWIG/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD/SWIG_JAVASCRIPT_BUILD */
