#include "internal.h"

#include <include/wally_bip32.h>
#include <include/wally_crypto.h>
#include <include/wally_map.h>
#include "psbt_io.h"

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
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_map);

    ret = wally_map_init(allocation_len, verify_fn, *output);
    if (ret != WALLY_OK) {
        wally_free(*output);
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
        if (map_in->items[i].key)
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

static int map_find(const struct wally_map *map_in, size_t index,
                    const unsigned char *key, size_t key_len,
                    size_t *written)
{
    size_t i;

    if (written)
        *written = 0;

    if (!map_in || (key && !key_len) || !written)
        return WALLY_EINVAL;

    for (i = index; i < map_in->num_items; ++i) {
        const struct wally_map_item *item = &map_in->items[i];

        if (key_len != item->key_len || !key != !item->key) {
            /* A byte or integer key that doesn't match, or
             * mismatched byte vs integer key
             */
            continue;
        }
        if (!key || !memcmp(key, item->key, key_len)) {
            *written = i + 1; /* Matching byte or integer key */
            break;
        }
    }
    return WALLY_OK;
}

int wally_map_find_from(const struct wally_map *map_in, size_t index,
                        const unsigned char *key, size_t key_len, size_t *written)
{
    return key ? map_find(map_in, index, key, key_len, written) : WALLY_EINVAL;
}

int wally_map_find(const struct wally_map *map_in,
                   const unsigned char *key, size_t key_len, size_t *written)
{
    return wally_map_find_from(map_in, 0, key, key_len, written);
}

int wally_map_find_integer(const struct wally_map *map_in,
                           uint32_t key, size_t *written)
{
    return map_find(map_in, 0, NULL, key, written);
}

static const struct wally_map_item *map_get(const struct wally_map *map_in,
                                            const unsigned char *key, size_t key_len)
{
    size_t index;
    if (map_find(map_in, 0, key, key_len, &index) == WALLY_OK && index)
        return &map_in->items[index - 1];
    return NULL; /* Not found/Invalid */
}

const struct wally_map_item *wally_map_get(const struct wally_map *map_in,
                                           const unsigned char *key, size_t key_len)
{
    return key ? map_get(map_in, key, key_len) : NULL;
}

const struct wally_map_item *wally_map_get_integer(const struct wally_map *map_in,
                                                   uint32_t key)
{
    return map_get(map_in, NULL, key);
}

int wally_map_get_num_items(const struct wally_map *map_in,
                            size_t *written)
{
    if (written)
        *written = 0;
    if (!map_in || !written)
        return WALLY_EINVAL;
    *written = map_in->num_items;
    return WALLY_OK;
}

int wally_map_get_item_key_length(const struct wally_map *map_in,
                                  size_t index, size_t *written)
{
    if (written)
        *written = 0;
    if (!map_in || index >= map_in->num_items || !written)
        return WALLY_EINVAL;
    *written = map_in->items[index].key ? map_in->items[index].key_len : 0;
    return WALLY_OK;
}

int wally_map_get_item_key(const struct wally_map *map_in,
                           size_t index,
                           unsigned char *bytes_out, size_t len, size_t *written)
{
    int ret = wally_map_get_item_key_length(map_in, index, written);
    if (ret == WALLY_OK) {
        const struct wally_map_item *item = &map_in->items[index];
        if (!bytes_out || !len || !*written) {
            /* Either no output buffer supplied, or the key is an integer */
            *written = 0;
            return !bytes_out || !len ? WALLY_EINVAL : WALLY_ERROR;
        }
        if (len >= *written)
            memcpy(bytes_out, item->key, *written);
    }
    return ret;
}

int wally_map_get_item_integer_key(const struct wally_map *map_in,
                                   size_t index, size_t *written)
{
    int ret = wally_map_get_item_key_length(map_in, index, written);
    if (ret == WALLY_OK && *written) {
        *written = 0;
        return WALLY_ERROR; /* Key is not an integer */
    } else if (ret == WALLY_OK) {
        *written = map_in->items[index].key_len;
    }
    return ret;
}

int wally_map_get_item_length(const struct wally_map *map_in,
                              size_t index, size_t *written)
{
    if (written)
        *written = 0;
    if (!map_in || index >= map_in->num_items || !written)
        return WALLY_EINVAL;
    *written = map_in->items[index].value_len;
    return WALLY_OK;
}

int wally_map_get_item(const struct wally_map *map_in,
                       size_t index, unsigned char *bytes_out, size_t len,
                       size_t *written)
{
    if (written)
        *written = 0;
    if (!map_in || index >= map_in->num_items || !bytes_out || !len ||
        !written || !map_in->items[index].value)
        return WALLY_EINVAL;
    *written = map_in->items[index].value_len;
    if (*written <= len)
        memcpy(bytes_out, map_in->items[index].value, *written);
    return WALLY_OK;
}

/* Returns LHS item if key is present in both maps and value is the same */
const struct wally_map_item *map_find_equal_integer(const struct wally_map *lhs,
                                                    const struct wally_map *rhs,
                                                    uint32_t key)
{
    const struct wally_map_item *l = wally_map_get_integer(lhs, key);
    const struct wally_map_item *r = wally_map_get_integer(rhs, key);
    if (l && r && l->value_len == r->value_len && !memcmp(l->value, r->value, r->value_len))
        return l;
    return NULL;
}

/* Note: If take_value is true and this errors, the caller must
 * free `value`. By design this only happens with calls internal
 * to the library. */
int map_add(struct wally_map *map_in,
            const unsigned char *key, size_t key_len,
            const unsigned char *val, size_t val_len,
            bool take_value, bool ignore_dups)
{
    size_t is_found;
    int ret;

    if (!map_in || (key && !key_len) || BYTES_INVALID(val, val_len) ||
        (map_in->verify_fn && map_in->verify_fn(key, key_len, val, val_len) != WALLY_OK))
        return WALLY_EINVAL;

    if ((ret = map_find(map_in, 0, key, key_len, &is_found)) != WALLY_OK)
        return ret;

    if (is_found) {
        if (ignore_dups && take_value)
            clear_and_free((unsigned char *)val, val_len);
        return ignore_dups ? WALLY_OK : WALLY_EINVAL;
    }

    ret = array_grow((void *)&map_in->items, map_in->num_items,
                     &map_in->items_allocation_len, sizeof(struct wally_map_item));
    if (ret == WALLY_OK) {
        struct wally_map_item *new_item = map_in->items + map_in->num_items;

        if (!key) {
            /* Integer key */
            if (new_item->key)
                clear_and_free_bytes(&new_item->key, &new_item->key_len);
        } else if (!clone_bytes(&new_item->key, key, key_len))
            return WALLY_ENOMEM; /* Failed to allocate byte key */
        new_item->key_len = key_len;

        if (val) {
            if (take_value)
                new_item->value = (unsigned char *)val;
            else if (!clone_bytes(&new_item->value, val, val_len)) {
                clear_and_free_bytes(&new_item->key, &new_item->key_len);
                return WALLY_ENOMEM;
            }
        }
        new_item->value_len = val_len;
        map_in->num_items++;
    }
    return ret;
}

int wally_map_add(struct wally_map *map_in,
                  const unsigned char *key, size_t key_len,
                  const unsigned char *value, size_t value_len)
{
    if (!key)
        return WALLY_EINVAL;
    return map_add(map_in, key, key_len, value, value_len, false, true);
}

int wally_map_add_integer(struct wally_map *map_in, uint32_t key,
                          const unsigned char *value, size_t value_len)
{
    return map_add(map_in, NULL, key, value, value_len, false, true);
}

static int map_remove(struct wally_map *map_in, const unsigned char *key, size_t key_len)
{
    size_t index;
    int ret = map_find(map_in, 0, key, key_len, &index);
    if (ret == WALLY_OK && index) {
        struct wally_map_item *to_remove = map_in->items + index - 1;
        if (to_remove->key)
            clear_and_free_bytes(&to_remove->key, &to_remove->key_len);
        clear_and_free_bytes(&to_remove->value, &to_remove->value_len);
        memmove(to_remove, to_remove + 1,
                (map_in->num_items - index) * sizeof(*to_remove));
        map_in->num_items -= 1;
    }
    return ret;
}

int wally_map_remove(struct wally_map *map_in,
                     const unsigned char *key, size_t key_len)
{
    if (!key)
        return WALLY_EINVAL;
    return map_remove(map_in, key, key_len);
}

int wally_map_remove_integer(struct wally_map *map_in, uint32_t key)
{
    return map_remove(map_in, NULL, key);
}

static int map_replace(struct wally_map *map_in,
                       const unsigned char *key, size_t key_len,
                       const unsigned char *value, size_t value_len)
{
    size_t index;
    int ret = map_find(map_in, 0, key, key_len, &index);
    if (ret == WALLY_OK) {
        if (index) {
            struct wally_map_item *to_replace = map_in->items + index - 1;
            ret = replace_bytes(value, value_len, &to_replace->value, &to_replace->value_len);
        } else
            ret = map_add(map_in, key, key_len, value, value_len, false, true);
    }
    return ret;
}

int wally_map_replace(struct wally_map *map_in,
                      const unsigned char *key, size_t key_len,
                      const unsigned char *value, size_t value_len)
{
    if (!key)
        return WALLY_EINVAL;
    return map_replace(map_in, key, key_len, value, value_len);
}

int wally_map_replace_integer(struct wally_map *map_in, uint32_t key,
                              const unsigned char *value, size_t value_len)
{
    return map_replace(map_in, NULL, key, value, value_len);
}

static int map_item_compare(const void *lhs, const void *rhs)
{
    const struct wally_map_item *l = lhs, *r = rhs;
    const size_t min_len = l->key_len < r->key_len ? l->key_len : r->key_len;
    int cmp;

    if (!l->key != !r->key)
        return !l->key ? -1 : 1; /* Integer vs byte key: ints sort first */

    if (!l->key)
        return (l->key_len > r->key_len) - (l->key_len < r->key_len); /* Integers */

    /* Byte keys */
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

int wally_map_combine(struct wally_map *map_in,
                      const struct wally_map *src)
{
    int ret = WALLY_OK;
    size_t i;

    if (!map_in)
        return WALLY_EINVAL;
    if (map_in == src)
        return WALLY_OK;
    if (src) {
        for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
            ret = map_add(map_in, src->items[i].key, src->items[i].key_len,
                          src->items[i].value, src->items[i].value_len,
                          false, true);
    }
    return ret;
}

int wally_map_assign(struct wally_map *map_in,
                     const struct wally_map *src)
{
    struct wally_map result;
    size_t allocation_len = src ? src->items_allocation_len : 0;
    int ret;

    if (!map_in || !src)
        return WALLY_EINVAL;
    if (map_in == src)
        return WALLY_OK;
    ret = wally_map_init(allocation_len, map_in->verify_fn, &result);
    if (ret == WALLY_OK && (ret = wally_map_combine(&result, src)) == WALLY_OK) {
        wally_map_clear(map_in);
        memcpy(map_in, &result, sizeof(result));
    } else
        wally_map_clear(&result);
    return ret;
}

static bool map_contains_key_length(const struct wally_map *map_in,
                                    size_t index, size_t key_len)
{
    size_t i;
    for (i = index; i < map_in->num_items; ++i) {
        if (map_in->items[i].key_len == key_len)
            return true;
    }
    return false;
}

/*
 * BIP32 keypath helpers.
 */
int wally_map_find_bip32_public_key_from(const struct wally_map *map_in, size_t index,
                                         const struct ext_key *hdkey, size_t *written)
{
    int ret;

    if (written)
        *written = 0;

    if (!map_in || !hdkey || !written)
        return WALLY_EINVAL;

    /* Try the compressed pubkey */
    ret = wally_map_find_from(map_in, index, hdkey->pub_key, EC_PUBLIC_KEY_LEN, written);
    if (ret == WALLY_OK && *written)
        return ret;
    /* Try the X-only pubkey */
    ret = wally_map_find_from(map_in, index, hdkey->pub_key + 1, EC_XONLY_PUBLIC_KEY_LEN, written);
    if (ret == WALLY_OK && *written)
        return ret;
    if (map_contains_key_length(map_in, index, EC_PUBLIC_KEY_UNCOMPRESSED_LEN)) {
        /* Uncompressed keys present: try the uncompressed pubkey */
        unsigned char full_pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
        ret = wally_ec_public_key_decompress(hdkey->pub_key, EC_PUBLIC_KEY_LEN,
                                             full_pubkey, sizeof(full_pubkey));
        if (ret == WALLY_OK)
            ret = wally_map_find_from(map_in, index, full_pubkey, sizeof(full_pubkey), written);
        wally_clear(full_pubkey, sizeof(full_pubkey));
    }
    return ret;
}

int wally_map_keypath_get_bip32_key_from_alloc(const struct wally_map *map_in,
                                               size_t index, const struct ext_key *hdkey,
                                               struct ext_key **output)
{
    uint32_t path[BIP32_PATH_MAX_LEN];
    struct ext_key derived;
    size_t i, path_len, idx = 0;
    int ret = WALLY_OK;

    OUTPUT_CHECK;
    if (!map_in || !hdkey)
        return WALLY_EINVAL;

    if (mem_is_zero(hdkey->chain_code, sizeof(hdkey->chain_code))) {
        /* Partial key: Just check if its pubkey is present */
        ret = wally_map_find_bip32_public_key_from(map_in, index, hdkey, &idx);
    } else {
        /* Full key. Iterate the keypaths looking for a derivable match */
        for (i = index; i < map_in->num_items; ++i) {
            const struct wally_map_item *item = map_in->items + i;

            if (item->value_len >= BIP32_KEY_FINGERPRINT_LEN &&
                memcmp(item->value, hdkey->hash160, BIP32_KEY_FINGERPRINT_LEN))
                continue; /* fingerprint mismatch: cannot be our key */

            ret = wally_map_keypath_get_item_path(map_in, i,
                                                  path, BIP32_PATH_MAX_LEN, &path_len);
            if (ret != WALLY_OK)
                break;
            if (path_len + hdkey->depth > BIP32_PATH_MAX_LEN)
               continue; /* Path too long, cannot be this key */
            if (!path_len)
                memcpy(&derived, hdkey, sizeof(derived)); /* Use directly */
            else {
                /* Derive the key to use */
                ret = bip32_key_from_parent_path(hdkey, path, path_len,
                                                 BIP32_FLAG_KEY_PRIVATE, &derived);
            }
            if (ret == WALLY_OK) {
                /* Check the derived public key belongs to this item */
                ret = wally_map_find_bip32_public_key_from(map_in, index, &derived, &idx);
            }
            if (ret != WALLY_OK)
                break;
            if (idx != i + 1)
                idx = 0; /* Not found/pubkey doesn't match, keep looking */
            else {
                hdkey = &derived; /* Pubkey matches, return it */
                break;
            }
        }
    }
    if (ret == WALLY_OK && idx) {
        /* Found, return the matching key */
        *output = wally_calloc(sizeof(struct ext_key));
        if (!*output)
            ret = WALLY_ENOMEM;
        else
            memcpy(*output, hdkey, sizeof(*hdkey));
    }
    wally_clear(&derived, sizeof(derived));
    return ret;
}

/*
 * PSBT keypath support.
 * - Global XPubs are keyed by bip32 extended keys.
 * - Input/Output keypaths are keyed by raw pubkeys.
 * - Taproot keypaths are keyed by x-only pubkeys.
 */
static int keypath_key_verify(const unsigned char *key, size_t key_len, struct ext_key *key_out)
{
    int ret = WALLY_EINVAL;

    key_out->version = 0; /* If non-0 on return, we have a bip32 key */

    if (!key)
        return ret;

    if (key_len == EC_XONLY_PUBLIC_KEY_LEN) {
        /* X-only pubkey */
        ret = wally_ec_xonly_public_key_verify(key, key_len);
    } else if (key_len == EC_PUBLIC_KEY_LEN ||
               key_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN) {
        /* Compressed or uncompressed pubkey */
        ret = wally_ec_public_key_verify(key, key_len);
    } else if (key_len == BIP32_SERIALIZED_LEN) {
        /* BIP32 extended pubkey */
        ret = bip32_key_unserialize(key, key_len, key_out);
        if (ret == WALLY_OK &&
            (key_out->version == BIP32_VER_MAIN_PRIVATE ||
             key_out->version == BIP32_VER_TEST_PRIVATE)) {
            wally_clear(key_out, sizeof(*key_out));
            ret = WALLY_EINVAL; /* Must be a public key, not private */
        }
    }
    return ret;
}

static bool kp_is_valid(const unsigned char *val, size_t val_len)
{
    return val && val_len >= BIP32_KEY_FINGERPRINT_LEN &&
        (val_len - BIP32_KEY_FINGERPRINT_LEN) % sizeof(uint32_t) == 0;
}

static size_t kp_path_len(size_t val_len)
{
    if (val_len == BIP32_KEY_FINGERPRINT_LEN)
        return 0;
    return (val_len - BIP32_KEY_FINGERPRINT_LEN) / sizeof(uint32_t);
}

static int keypath_path_verify(const unsigned char *val, size_t val_len,
                               const struct ext_key *extkey)
{
    if (!kp_is_valid(val, val_len) ||
        (extkey->version && extkey->depth != kp_path_len(val_len)))
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

    if (key_len == EC_XONLY_PUBLIC_KEY_LEN ||
        keypath_key_verify(key, key_len, &extkey) != WALLY_OK ||
        extkey.version ||
        keypath_path_verify(val, val_len, &extkey) != WALLY_OK)
        return WALLY_EINVAL;
    return WALLY_OK;
}

int wally_keypath_xonly_public_key_verify(const unsigned char *key, size_t key_len,
                                          const unsigned char *val, size_t val_len)
{
    struct ext_key extkey;

    if (key_len != EC_XONLY_PUBLIC_KEY_LEN ||
        keypath_key_verify(key, key_len, &extkey) != WALLY_OK ||
        extkey.version ||
        keypath_path_verify(val, val_len, &extkey) != WALLY_OK)
        return WALLY_EINVAL;
    return WALLY_OK;
}

int wally_merkle_path_xonly_public_key_verify(const unsigned char *key, size_t key_len,
                                              const unsigned char *val, size_t val_len)
{
    struct ext_key extkey;

    if (key_len != EC_XONLY_PUBLIC_KEY_LEN ||
        keypath_key_verify(key, key_len, &extkey) != WALLY_OK ||
        extkey.version || BYTES_INVALID(val, val_len) || val_len % SHA256_LEN != 0)
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

int wally_map_keypath_add(struct wally_map *map_in,
                          const unsigned char *pub_key, size_t pub_key_len,
                          const unsigned char *fingerprint, size_t fingerprint_len,
                          const uint32_t *path, size_t path_len)
{
    unsigned char *value;
    size_t value_len, i;
    int ret;

    if (!map_in || !fingerprint || fingerprint_len != BIP32_KEY_FINGERPRINT_LEN ||
        BYTES_INVALID(path, path_len))
        return WALLY_EINVAL;

    if (map_in->verify_fn != wally_keypath_public_key_verify &&
        map_in->verify_fn != wally_keypath_xonly_public_key_verify &&
        map_in->verify_fn != wally_keypath_bip32_verify)
        return WALLY_EINVAL; /* Not a keypath map */

    value_len = fingerprint_len + path_len * sizeof(uint32_t);
    if (!(value = wally_malloc(value_len)))
        return WALLY_ENOMEM;

    memcpy(value, fingerprint, fingerprint_len);
    for (i = 0; i < path_len; ++i) {
        leint32_t tmp = cpu_to_le32(path[i]);
        memcpy(value + fingerprint_len + i * sizeof(uint32_t),
               &tmp, sizeof(tmp));
    }

    ret = map_add(map_in, pub_key, pub_key_len, value, value_len, true, true);
    if (ret != WALLY_OK)
        clear_and_free(value, value_len);
    return ret;
}

int wally_map_merkle_path_add(struct wally_map *map_in,
                              const unsigned char *pub_key, size_t pub_key_len,
                              const unsigned char *merkle_hashes, size_t merkle_hashes_len)
{
    if (!map_in || pub_key_len != EC_XONLY_PUBLIC_KEY_LEN ||
        BYTES_INVALID(merkle_hashes, merkle_hashes_len))
        return WALLY_EINVAL;

    /* Add map for tap leaves */
    return map_add(map_in, pub_key, pub_key_len,
                   merkle_hashes, merkle_hashes_len, false, false);
}

int wally_keypath_get_fingerprint(const unsigned char *val, size_t val_len,
                                  unsigned char *bytes_out, size_t len)
{
    if (!val || val_len < len || !bytes_out || len != BIP32_KEY_FINGERPRINT_LEN)
        return WALLY_EINVAL;
    memcpy(bytes_out, val, len); /* First 4 bytes are the fingerprint */
    return WALLY_OK;
}

int wally_map_keypath_get_item_fingerprint(const struct wally_map *map_in, size_t index,
                                           unsigned char *bytes_out, size_t len)
{
    const struct wally_map_item *item;
    item = map_in && index < map_in->num_items ? &map_in->items[index] : NULL;
    if (!item)
        return WALLY_EINVAL;
    return wally_keypath_get_fingerprint(item->value, item->value_len, bytes_out, len);
}

int wally_keypath_get_path_len(const unsigned char *val, size_t val_len,
                               size_t *written)
{
    if (written)
        *written = 0;
    if (!kp_is_valid(val, val_len) || !written)
        return WALLY_EINVAL;
    *written = kp_path_len(val_len);
    return WALLY_OK;
}

int wally_map_keypath_get_item_path_len(const struct wally_map *map_in, size_t index,
                                        size_t *written)
{
    const struct wally_map_item *item;
    item = map_in && index < map_in->num_items ? &map_in->items[index] : NULL;
    if (written)
        *written = 0;
    if (!item)
        return WALLY_EINVAL;
    return wally_keypath_get_path_len(item->value, item->value_len, written);
}

int wally_keypath_get_path(const unsigned char *val, size_t val_len,
                           uint32_t *child_path_out, size_t child_path_out_len,
                           size_t *written)
{
    int ret = wally_keypath_get_path_len(val, val_len, written);
    if (ret == WALLY_OK) {
        size_t i;

        if (!child_path_out) {
            *written = 0;
            return WALLY_EINVAL;
        } else if (child_path_out_len < *written)
            return WALLY_OK; /* Return required length to caller */

        val += BIP32_KEY_FINGERPRINT_LEN; /* Skip fingerprint */
        for (i = 0; i < *written; ++i) {
            leint32_t tmp;
            memcpy(&tmp, val + i * sizeof(uint32_t), sizeof(tmp));
            child_path_out[i] = le32_to_cpu(tmp);
        }
    }
    return ret;
}

int wally_map_keypath_get_item_path(const struct wally_map *map_in, size_t index,
                                    uint32_t *child_path_out, size_t child_path_out_len,
                                    size_t *written)
{
    const struct wally_map_item *item;
    item = map_in && index < map_in->num_items ? &map_in->items[index] : NULL;
    if (written)
        *written = 0;
    if (!item || !child_path_out)
        return WALLY_EINVAL;
    return wally_keypath_get_path(item->value, item->value_len,
                                  child_path_out, child_path_out_len, written);
}

/*
 * PSBT preimage support.
 * Preimages are stored keyed by the preimage type + hash, with
 * the preimage as the data. This allows us to iterate the map keys
 * in order when serializing, to match the output ordering from core.
 */
typedef int (*psbt_hash_fn_t)(const unsigned char *, size_t, unsigned char *, size_t);

static int hash_verify(const unsigned char *key, size_t key_len,
                       const unsigned char *val, size_t val_len,
                       psbt_hash_fn_t hash_fn, size_t hash_len)
{
    unsigned char buff[SHA256_LEN];

    if (key_len == hash_len &&
        hash_fn(val, val_len, buff, hash_len) == WALLY_OK &&
        !memcmp(key, buff, hash_len))
        return WALLY_OK; /* Provided key is the correct hash of the preimage */
    return WALLY_EINVAL; /* Invalid key */
}

int wally_map_hash_preimage_verify(const unsigned char *key, size_t key_len,
                                   const unsigned char *val, size_t val_len)
{
    if (key && key_len) {
        switch (key[0]) {
        case PSBT_IN_RIPEMD160:
            return hash_verify(key + 1, key_len - 1, val, val_len, wally_ripemd160, RIPEMD160_LEN);
        case PSBT_IN_SHA256:
            return hash_verify(key + 1, key_len - 1, val, val_len, wally_sha256, SHA256_LEN);
        case PSBT_IN_HASH160:
            return hash_verify(key + 1, key_len - 1, val, val_len, wally_hash160, HASH160_LEN);
        case PSBT_IN_HASH256:
            return hash_verify(key + 1, key_len - 1, val, val_len, wally_sha256d, SHA256_LEN);
        default:
            break;
        }
    }
    return WALLY_EINVAL;
}

int wally_map_preimage_init_alloc(size_t allocation_len, struct wally_map **output)
{
    return wally_map_init_alloc(allocation_len, wally_map_hash_preimage_verify, output);
}

int map_add_preimage_and_hash(struct wally_map *map_in,
                              const unsigned char *key, size_t key_len,
                              const unsigned char *val, size_t val_len,
                              size_t type, bool skip_verify)
{
    unsigned char tmp[SHA256_LEN + 1];
    wally_map_verify_fn_t verify_fn;
    int ret;

    if (!map_in || !key || !val || !val_len)
        return WALLY_EINVAL;

    if (type == PSBT_IN_RIPEMD160 || type == PSBT_IN_HASH160) {
        if (key_len != RIPEMD160_LEN)
            return WALLY_EINVAL;
    } else if (type == PSBT_IN_SHA256 || type == PSBT_IN_HASH256) {
        if (key_len != SHA256_LEN)
            return WALLY_EINVAL;
    } else
        return WALLY_EINVAL;

    /* Make a copy of the key, prefixed by the type */
    tmp[0] = type & 0xff;
    memcpy(tmp + 1, key, key_len);
    verify_fn = map_in->verify_fn;

    if (skip_verify)
        map_in->verify_fn = NULL; /* Don't recalculate known-good hashes */

    ret = map_add(map_in, tmp, key_len + 1, val, val_len, false, false);

    if (skip_verify)
        map_in->verify_fn = verify_fn;

    return ret;
}

static int preimage_add(struct wally_map *map_in,
                        const unsigned char *val, size_t val_len,
                        size_t type, psbt_hash_fn_t hash_fn, size_t len)
{
    unsigned char tmp[SHA256_LEN];

    if (!map_in || !val || !val_len)
        return WALLY_EINVAL;
    if (hash_fn(val, val_len, tmp, len) != WALLY_OK)
        return WALLY_EINVAL;
    return map_add_preimage_and_hash(map_in, tmp, len, val, val_len, type, true);
}

int wally_map_preimage_ripemd160_add(struct wally_map *map_in,
                                     const unsigned char *val, size_t val_len)
{
    return preimage_add(map_in, val, val_len, PSBT_IN_RIPEMD160,
                        wally_ripemd160, RIPEMD160_LEN);
}

int wally_map_preimage_sha256_add(struct wally_map *map_in,
                                  const unsigned char *val, size_t val_len)
{
    return preimage_add(map_in, val, val_len, PSBT_IN_SHA256,
                        wally_sha256, SHA256_LEN);
}

int wally_map_preimage_hash160_add(struct wally_map *map_in,
                                   const unsigned char *val, size_t val_len)
{
    return preimage_add(map_in, val, val_len, PSBT_IN_HASH160,
                        wally_hash160, HASH160_LEN);
}

int wally_map_preimage_sha256d_add(struct wally_map *map_in,
                                   const unsigned char *val, size_t val_len)
{
    return preimage_add(map_in, val, val_len, PSBT_IN_HASH256,
                        wally_sha256d, SHA256_LEN);
}
