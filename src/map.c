#include "internal.h"

#include <include/wally_bip32.h>
#include <include/wally_crypto.h>
#include <include/wally_map.h>

#include <ccan/endian/endian.h>

int wally_map_init(size_t allocation_len, wally_map_verify_fn_t verify_fn, struct wally_map *output)
{
    if (!output)
        return WALLY_EINVAL;

    wally_clear(output, sizeof(*output));
    if (allocation_len) {
        output->items = wally_calloc(allocation_len * sizeof(*output->items));
        if (!output->items)
            return WALLY_ENOMEM;
    }
    output->items_allocation_len = allocation_len;
    output->verify_fn = verify_fn;
    return WALLY_OK;
}

int wally_map_init_alloc(size_t allocation_len, wally_map_verify_fn_t verify_fn, struct wally_map **output)
{
    struct wally_map *result;
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_map);

    ret = wally_map_init(allocation_len, verify_fn, result);
    if (ret != WALLY_OK) {
        wally_free(result);
        *output = NULL;
    }
    return ret;
}

int wally_map_clear(struct wally_map *map_in)
{
    size_t i;

    if (!map_in)
        return WALLY_EINVAL;
    for (i = 0; i < map_in->num_items; ++i) {
        clear_and_free(map_in->items[i].key, map_in->items[i].key_len);
        clear_and_free(map_in->items[i].value, map_in->items[i].value_len);
    }
    clear_and_free(map_in->items, map_in->num_items * sizeof(*map_in->items));
    wally_clear(map_in, sizeof(*map_in));
    return WALLY_OK;
}

int wally_map_free(struct wally_map *map_in)
{
    if (map_in) {
        wally_map_clear(map_in);
        wally_free(map_in);
    }
    return WALLY_OK;
}

int wally_map_find(const struct wally_map *map_in,
                   const unsigned char *key, size_t key_len,
                   size_t *written)
{
    size_t i;

    if (written)
        *written = 0;

    if (!map_in || !key || BYTES_INVALID(key, key_len) || !written)
        return WALLY_EINVAL;

    for (i = 0; i < map_in->num_items; ++i) {
        const struct wally_map_item *item = &map_in->items[i];

        if (key_len == item->key_len && memcmp(key, item->key, key_len) == 0) {
            *written = i + 1; /* Found */
            break;
        }
    }
    return WALLY_OK;
}

/* Note: If take_value is true and this errors, the caller must
 * free `value`. By design this only happens with calls internal
 * to this source file. */
int map_add(struct wally_map *map_in,
            const unsigned char *key, size_t key_len,
            const unsigned char *value, size_t value_len,
            bool take_value,
            int (*key_fn)(const unsigned char *key, size_t key_len),
            int (*val_fn)(const unsigned char *val, size_t val_len),
            bool ignore_dups)
{
    size_t is_found;
    int ret;

    if (!map_in || !key || BYTES_INVALID(key, key_len) ||
        (key_fn && key_fn(key, key_len) != WALLY_OK) ||
        (val_fn && val_fn(value, value_len) != WALLY_OK) ||
        BYTES_INVALID(value, value_len))
        return WALLY_EINVAL;

    if ((ret = wally_map_find(map_in, key, key_len, &is_found)) != WALLY_OK)
        return ret;

    if (is_found) {
        if (ignore_dups && take_value)
            clear_and_free((unsigned char *)value, value_len);
        return ignore_dups ? WALLY_OK : WALLY_EINVAL;
    }

    ret = array_grow((void *)&map_in->items, map_in->num_items,
                     &map_in->items_allocation_len, sizeof(struct wally_map_item));
    if (ret == WALLY_OK) {
        struct wally_map_item *new_item = map_in->items + map_in->num_items;

        if (!clone_bytes(&new_item->key, key, key_len))
            return WALLY_ENOMEM;
        new_item->key_len = key_len;

        if (value) {
            if (take_value)
                new_item->value = (unsigned char *)value;
            else if (!clone_bytes(&new_item->value, value, value_len)) {
                clear_and_free_bytes(&new_item->key, &new_item->key_len);
                return WALLY_ENOMEM;
            }
        }
        new_item->value_len = value_len;
        map_in->num_items++;
    }
    return ret;
}

int wally_map_add(struct wally_map *map_in,
                  const unsigned char *key, size_t key_len,
                  const unsigned char *value, size_t value_len)
{
    return map_add(map_in, key, key_len, value, value_len, false, NULL, NULL, true);
}

static int map_item_compare(const void *lhs, const void *rhs)
{
    const struct wally_map_item *l = lhs, *r = rhs;
    const size_t min_len = l->key_len < r->key_len ? l->key_len : r->key_len;
    int cmp;

    cmp = memcmp(l->key, r->key, min_len);
    if (cmp == 0) {
        /* Equal up to the min length, longest key is greater. If we have
         * duplicate keys somehow, the resulting order is undefined */
        cmp = l->key_len < r->key_len ? -1 : 1;
    }
    return cmp;
}

int wally_map_sort(struct wally_map *map_in, uint32_t flags)
{
    if (!map_in || flags)
        return WALLY_EINVAL;

    qsort(map_in->items, map_in->num_items, sizeof(struct wally_map_item), map_item_compare);
    return WALLY_OK;
}

int map_extend(struct wally_map *dst, const struct wally_map *src,
               int (*key_fn)(const unsigned char *key, size_t key_len),
               int (*val_fn)(const unsigned char *val, size_t val_len))
{
    int ret = WALLY_OK;
    size_t i;

    if (src) {
        for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
            ret = map_add(dst, src->items[i].key, src->items[i].key_len,
                          src->items[i].value, src->items[i].value_len,
                          false, key_fn, val_fn, true);
    }
    return ret;
}

int map_assign(const struct wally_map *src, struct wally_map *dst,
               int (*key_fn)(const unsigned char *key, size_t key_len),
               int (*val_fn)(const unsigned char *val, size_t val_len))
{
    struct wally_map result;
    size_t i;
    int ret = WALLY_OK;

    if (!src)
        ret = wally_map_init(0, dst->verify_fn, &result);
    else {
        ret = wally_map_init(src->items_allocation_len, src->verify_fn, &result);
        for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
            ret = map_add(&result, src->items[i].key, src->items[i].key_len,
                          src->items[i].value, src->items[i].value_len,
                          false, key_fn, val_fn, true);
    }

    if (ret != WALLY_OK)
        wally_map_clear(&result);
    else {
        wally_map_clear(dst);
        memcpy(dst, &result, sizeof(result));
    }
    return ret;
}

/*
 * PSBT keypath support.
 * - Global XPubs are keyed by bip32 extended keys.
 * - Input/Output keypaths are keyed by raw pubkeys.
 */

static int keypath_key_verify(const unsigned char *key, size_t key_len, struct ext_key *key_out)
{
    int ret = WALLY_EINVAL;

    key_out->version = 0; /* If non-0 on return, we have a bip32 key */

    /* Allow pubkeys, compressed pubkeys, or bip32 extended pubkeys */
    if (key_len == EC_PUBLIC_KEY_LEN || key_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
        ret = wally_ec_public_key_verify(key, key_len);
    else if (key_len == BIP32_SERIALIZED_LEN) {
        ret = bip32_key_unserialize(key, key_len, key_out);
        if (ret == WALLY_OK &&
            (key_out->version == BIP32_VER_MAIN_PRIVATE ||
             key_out->version == BIP32_VER_TEST_PRIVATE))
            ret = WALLY_EINVAL; /* Must be a public key, not private */
    }
    return ret;
}

static int keypath_path_verify(const unsigned char *val, size_t val_len,
                               const struct ext_key *extkey)
{
    size_t path_depth = (val_len - BIP32_KEY_FINGERPRINT_LEN) / sizeof(uint32_t);

    if (!val || val_len < BIP32_KEY_FINGERPRINT_LEN || val_len % sizeof(uint32_t) ||
        (extkey->version && extkey->depth != path_depth))
        return WALLY_EINVAL;
    return WALLY_OK;
}

int wally_keypath_bip32_verify(const unsigned char *key, size_t key_len,
                               const unsigned char *val, size_t val_len)
{
    struct ext_key extkey;

    if (keypath_key_verify(key, key_len, &extkey) != WALLY_OK ||
        !extkey.version ||
        keypath_path_verify(val, val_len, &extkey) != WALLY_OK)
        return WALLY_EINVAL;
    return WALLY_OK;
}

int wally_keypath_public_key_verify(const unsigned char *key, size_t key_len,
                                    const unsigned char *val, size_t val_len)
{
    struct ext_key extkey;

    if (keypath_key_verify(key, key_len, &extkey) != WALLY_OK ||
        extkey.version ||
        keypath_path_verify(val, val_len, &extkey) != WALLY_OK)
        return WALLY_EINVAL;
    return WALLY_OK;
}

int wally_map_keypath_bip32_init_alloc(size_t allocation_len, struct wally_map **output)
{
    return wally_map_init_alloc(allocation_len, wally_keypath_bip32_verify, output);
}

int wally_map_keypath_public_key_init_alloc(size_t allocation_len, struct wally_map **output)
{
    return wally_map_init_alloc(allocation_len, wally_keypath_public_key_verify, output);
}

int wally_map_add_keypath_item(struct wally_map *map_in,
                               const unsigned char *pub_key, size_t pub_key_len,
                               const unsigned char *fingerprint, size_t fingerprint_len,
                               const uint32_t *path, size_t path_len)
{
    struct ext_key extkey;
    unsigned char *value;
    size_t value_len, i;
    int ret;

    if (!map_in || keypath_key_verify(pub_key, pub_key_len, &extkey) != WALLY_OK ||
        !fingerprint || fingerprint_len != BIP32_KEY_FINGERPRINT_LEN ||
        BYTES_INVALID(path, path_len))
        return WALLY_EINVAL;

    if (extkey.version && extkey.depth != path_len)
        return WALLY_EINVAL;

    value_len = fingerprint_len + path_len * sizeof(uint32_t);
    if (!(value = wally_malloc(value_len)))
        return WALLY_ENOMEM;

    memcpy(value, fingerprint, fingerprint_len);
    for (i = 0; i < path_len; ++i) {
        leint32_t tmp = cpu_to_le32(path[i]);
        memcpy(value + fingerprint_len + i * sizeof(uint32_t),
               &tmp, sizeof(tmp));
    }

    ret = map_add(map_in, pub_key, pub_key_len, value, value_len, true, NULL, NULL, true);
    if (ret != WALLY_OK)
        clear_and_free(value, value_len);
    wally_clear(&extkey, sizeof(extkey));
    return ret;
}
