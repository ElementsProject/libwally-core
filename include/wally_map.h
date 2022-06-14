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
 */
WALLY_CORE_API int wally_map_add(
    struct wally_map *map_in,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *value,
    size_t value_len);

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
 * Sort the items in a map.
 *
 * :param map_in: The map to sort.
 * :param flags: Flags controlling sorting. Must be 0.
 */
WALLY_CORE_API int wally_map_sort(
    struct wally_map *map_in,
    uint32_t flags);

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
#endif /* SWIG */

/**
 * Convert and add a pubkey/keypath to a map.
 *
 * :param map_in: The map to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be ``BIP32_KEY_FINGERPRINT_LEN``.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_map_add_keypath_item(
    struct wally_map *map_in,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

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

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_MAP_H */