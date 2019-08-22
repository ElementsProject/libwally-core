#include "internal.h"

#include "ccan/ccan/build_assert/build_assert.h"

#include <include/wally_crypto.h>
#include <include/wally_transaction.h>
#include <include/wally_psbt.h>

#include <limits.h>
#include <stdbool.h>
#include "transaction_shared.h"
#include "script_int.h"

const uint8_t WALLY_PSBT_MAGIC[5] = {'p', 's', 'b', 't', 0xff};

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
