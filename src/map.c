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

static int map_find(const struct wally_map *map_in,
                    const unsigned char *key, size_t key_len,
                    size_t *written)
{
    size_t i;

    if (written)
        *written = 0;

    if (!map_in || (key && !key_len) || !written)
        return WALLY_EINVAL;

    for (i = 0; i < map_in->num_items; ++i) {
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

int wally_map_find(const struct wally_map *map_in,
                   const unsigned char *key, size_t key_len,
                   size_t *written)
{
    if (!key)
        return WALLY_EINVAL;
    return map_find(map_in, key, key_len, written);
}

int wally_map_find_integer(const struct wally_map *map_in,
                           uint32_t key, size_t *written)
{
    return map_find(map_in, NULL, key, written);
}

static const struct wally_map_item *map_get(const struct wally_map *map_in,
                                            const unsigned char *key, size_t key_len)
{
    size_t index;
    if (map_find(map_in, key, key_len, &index) == WALLY_OK && index)
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

    if ((ret = map_find(map_in, key, key_len, &is_found)) != WALLY_OK)
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
    int ret = map_find(map_in, key, key_len, &index);
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
    int ret = map_find(map_in, key, key_len, &index);
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
    /* Preimages are stored keyed by the preimage type + hash, with
     * the preimage as the data. This allows us to iterate the map keys
     * in order when serializing, to match the output ordering from core.
     */
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
