#ifndef LIBWALLY_CORE_MAP_H
#define LIBWALLY_CORE_MAP_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SWIG
struct wally_map;
typedef void *wally_map_verify_fn_t;
#else

/** A function to validate a map item */
typedef int (*wally_map_verify_fn_t)(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *value,
    size_t value_len);

/** A map item */
struct wally_map_item {
    unsigned char *key;
    size_t key_len;
    unsigned char *value;
    size_t value_len;
};

/** A map of key,value pairs */
struct wally_map {
    struct wally_map_item *items;
    size_t num_items;
    size_t items_allocation_len;
    wally_map_verify_fn_t verify_fn;
};
#endif /* SWIG */

#ifndef SWIG
/**
 * Initialize a new map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param output: Map to initialize.
 */
WALLY_CORE_API int wally_map_init(
    size_t allocation_len,
    wally_map_verify_fn_t verify_fn,
    struct wally_map *output);
#endif /* SWIG_PYTHON */

/**
 * Allocate and initialize a new map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param output: Destination for the new map.
 */
WALLY_CORE_API int wally_map_init_alloc(
    size_t allocation_len,
    wally_map_verify_fn_t verify_fn,
    struct wally_map **output);

#ifndef SWIG_PYTHON
/**
 * Free a map allocated by `wally_map_init_alloc`.
 *
 * :param map_in: The map to free.
 */
WALLY_CORE_API int wally_map_free(
    struct wally_map *map_in);
#endif /* SWIG_PYTHON */

/**
 * Remove all entries from a map.
 *
 * :param map_in: The map to clear.
 *
 * .. note:: This function frees all pre-allocated memory, and thus can
 *|    be used to free a map initialised with `wally_map_init` without
 *|    freeing the map struct itself.
 */
WALLY_CORE_API int wally_map_clear(
    struct wally_map *map_in);

/**
 * Add an item to a map.
 *
 * :param map_in: The map to add to.
 * :param key: The key to add.
 * :param key_len: Length of ``key`` in bytes.
 * :param value: The value to add.
 * :param value_len: Length of ``value`` in bytes.
 *
 * .. note:: If the key given is already in the map, this call succeeds
 *|    without altering the map.
 */
WALLY_CORE_API int wally_map_add(
    struct wally_map *map_in,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *value,
    size_t value_len);

/**
 * Add an item to a map keyed by an integer.
 *
 * As per `wally_map_add`, using an integer key.
 */
WALLY_CORE_API int wally_map_add_integer(
    struct wally_map *map_in,
    uint32_t key,
    const unsigned char *value,
    size_t value_len);

/**
 * Add an item to a map, replacing it if already present.
 *
 * See `wally_map_add`.
 */
WALLY_CORE_API int wally_map_replace(
    struct wally_map *map_in,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *value,
    size_t value_len);

/**
 * Add an item to a map keyed by an integer, replacing it if already present.
 *
 * See `wally_map_add_integer`.
 */
WALLY_CORE_API int wally_map_replace_integer(
    struct wally_map *map_in,
    uint32_t key,
    const unsigned char *value,
    size_t value_len);

/**
 * Remove an item from a map.
 *
 * :param map_in: The map to remove from.
 * :param key: The key to add.
 * :param key_len: Length of ``key`` in bytes.
 */
WALLY_CORE_API int wally_map_remove(
    struct wally_map *map_in,
    const unsigned char *key,
    size_t key_len);

/**
 * Remove an item from a map keyed by an integer.
 *
 * See `wally_map_remove_integer`.
 */
WALLY_CORE_API int wally_map_remove_integer(
    struct wally_map *map_in,
    uint32_t key);

/**
 * Find an item in a map.
 *
 * :param map_in: The map to find ``key`` in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_map_find(
    const struct wally_map *map_in,
    const unsigned char *key,
    size_t key_len,
    size_t *written);

/**
 * Find an item in a map keyed by an integer.
 *
 * As per `wally_map_find`, using an integer key.
 */
WALLY_CORE_API int wally_map_find_integer(
    const struct wally_map *map_in,
    uint32_t key,
    size_t *written);

#ifndef SWIG
/**
 * Find an item in a map.
 *
 * :param map_in: The map to find ``key`` in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 *
 * .. note:: This is a non-standard call for low-level use. It returns the
 *|    map item directly without copying, or NULL if not found/an error occurs.
 */
WALLY_CORE_API const struct wally_map_item *wally_map_get(
    const struct wally_map *map_in,
    const unsigned char *key,
    size_t key_len);

/**
 * Find an item in a map keyed by an integer.
 *
 * As per `wally_map_get`, using an integer key.
 */
WALLY_CORE_API const struct wally_map_item *wally_map_get_integer(
    const struct wally_map *map_in,
    uint32_t key);
#endif

/**
 * Sort the items in a map.
 *
 * :param map_in: The map to sort.
 * :param flags: Flags controlling sorting. Must be 0.
 */
WALLY_CORE_API int wally_map_sort(
    struct wally_map *map_in,
    uint32_t flags);

/**
 * Combine the items from a source map into another map.
 *
 * :param map_in: the destination to combine into.
 * :param source: the source to copy items from.
 *
 * .. note:: If this call fails, ``map_in`` may be left partially updated.
 */
WALLY_CORE_API int wally_map_combine(
    struct wally_map *map_in,
    const struct wally_map *source);

/**
 * Replace a maps contents with another map.
 *
 * :param map_in: the destination to combine into.
 * :param source: the source to copy items from.
 *
 * .. note:: If this call fails, ``map_in`` is left untouched.
 */
WALLY_CORE_API int wally_map_assign(
    struct wally_map *map_in,
    const struct wally_map *source);

#ifndef SWIG
/**
 * Verify a PSBT keypath keyed by a serialized bip32 extended public key.
 *
 * :param key: An extended public key in bip32 format.
 * :param key_len: Length of ``key`` in bytes. Must be ``BIP32_SERIALIZED_LEN``.
 * :param val: The 4 byte PSBT serialized master key fingerprint followed by the serialized path.
 * :param val_len: Length of ``val`` in bytes.
 */
WALLY_CORE_API int wally_keypath_bip32_verify(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *val,
    size_t val_len);

/**
 * Verify a PSBT keypath keyed by a compressed or uncompressed public key.
 *
 * :param key: Public key bytes.
 * :param key_len: Length of ``key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``BIP32_SERIALIZED_LEN``.
 * :param val: The 4 byte PSBT serialized master key fingerprint followed by the serialized path.
 * :param val_len: Length of ``val`` in bytes.
 */
WALLY_CORE_API int wally_keypath_public_key_verify(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *val,
    size_t val_len);

/**
 * Verify a PSBT keypath keyed by an x-only public key.
 *
 * :param key: Public key bytes.
 * :param key_len: Length of ``key`` in bytes. Must be ``EC_XONLY_PUBLIC_KEY_LEN``,
 * :param val: The 4 byte PSBT serialized master key fingerprint followed by the serialized path.
 * :param val_len: Length of ``val`` in bytes.
 */
WALLY_CORE_API int wally_keypath_xonly_public_key_verify(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *val,
    size_t val_len);
#endif /* SWIG */

/**
 * Allocate and initialize a new BIP32 keypath map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param output: Destination for the new map.
 */
WALLY_CORE_API int wally_map_keypath_bip32_init_alloc(
    size_t allocation_len,
    struct wally_map **output);

/**
 * Allocate and initialize a new public key keypath map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param output: Destination for the new map.
 */
WALLY_CORE_API int wally_map_keypath_public_key_init_alloc(
    size_t allocation_len,
    struct wally_map **output);

/**
 * Convert and add a public key and path to a keypath map.
 *
 * :param map_in: The keypath map to add to.
 * :param pub_key: The public key or extended public key to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``BIP32_SERIALIZED_LEN``
 *|    for an extended bip32 public key, or ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN``
 *|    or ``EC_PUBLIC_KEY_LEN`` for a public key.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be ``BIP32_KEY_FINGERPRINT_LEN``.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_map_keypath_add(
    struct wally_map *map_in,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);


/**
 * Verify a preimage map key and value pair.
 *
 * :param key: The preimage hash, prefixed by a hash type byte.
 * :param key_len: Length of ``key`` in bytes.
 * :param val: The preimage data hashed to produce ``key``.
 * :param val_len: Length of ``val`` in bytes.
 *
 * .. note:: Multiple preimage types are stored in the same map, prefixed by
 *|    a leading byte. The exact format of storage is implementation dependent
 *|    and may change in the future.
 */
WALLY_CORE_API int wally_map_hash_preimage_verify(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *val,
    size_t val_len);

/**
 * Allocate and initialize a new preimage map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param output: Destination for the new map.
 */
WALLY_CORE_API int wally_map_preimage_init_alloc(
    size_t allocation_len,
    struct wally_map **output);

/**
 * Add a ripemd160 preimage to a preimage map.
 *
 * :param map_in: The preimage map to add to.
 * :param value: The data to store.
 * :param value_len: Length of ``value`` in bytes.
 */
WALLY_CORE_API int wally_map_preimage_ripemd160_add(
    struct wally_map *map_in,
    const unsigned char *value,
    size_t value_len);

/**
 * Add a sha256 preimage to a preimage map.
 *
 * :param map_in: The preimage map to add to.
 * :param value: The data to store.
 * :param value_len: Length of ``value`` in bytes.
 */
WALLY_CORE_API int wally_map_preimage_sha256_add(
    struct wally_map *map_in,
    const unsigned char *value,
    size_t value_len);

/**
 * Add a hash160 preimage to a preimage map.
 *
 * :param map_in: The preimage map to add to.
 * :param value: The data to store.
 * :param value_len: Length of ``value`` in bytes.
 */
WALLY_CORE_API int wally_map_preimage_hash160_add(
    struct wally_map *map_in,
    const unsigned char *value,
    size_t value_len);

/**
 * Add a sha256d preimage to a preimage map.
 *
 * :param map_in: The preimage map to add to.
 * :param value: The data to store.
 * :param value_len: Length of ``value`` in bytes.
 */
WALLY_CORE_API int wally_map_preimage_sha256d_add(
    struct wally_map *map_in,
    const unsigned char *value,
    size_t value_len);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_MAP_H */
