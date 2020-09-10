#ifndef LIBWALLY_CORE_DESCRIPTOR_H
#define LIBWALLY_CORE_DESCRIPTOR_H

#include "wally_core.h"
#include "wally_address.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WALLY_NETWORK_BITCOIN_REGTEST 0xff  /** Bitcoin regtest */

#ifdef SWIG
struct wally_descriptor_address_item;
struct wally_descriptor_addresses;
#else
/** A descriptor address */
struct wally_descriptor_address_item {
    uint32_t child_num;
    char *address;
    size_t address_len;
};

/** A descriptor addresses */
struct wally_descriptor_addresses {
    struct wally_descriptor_address_item *items;
    size_t num_items;
};
#endif

#ifndef SWIG_PYTHON
/**
 * Free addresses allocated by `wally_descriptor_to_addresses`.
 *
 * :param addresses: addresses to free.
 */
WALLY_CORE_API int wally_free_descriptor_addresses(
    struct wally_descriptor_addresses *addresses);
#endif /* SWIG_PYTHON */

/**
 * Create a script corresponding to a miniscript string.
 *
 * :param miniscript: Miniscript string.
 * :param key_name_array: Array of key policy name string.
 * :param key_value_array: Array of key mapped value string.
 * :param array_len: Length of the array of key policy name.
 * :param derive_child_num: Number of the derive path.
 * :param flags: For future use. Must be 0.
 * :param script: Destination for the resulting scriptpubkey.
 * :param script_len: Length of the script array.
 * :param written: Destination for the using scriptpubkey length.
 */
WALLY_CORE_API int wally_descriptor_parse_miniscript(
    const char *miniscript,
    const char **key_name_array,
    const char **key_value_array,
    size_t array_len,
    uint32_t derive_child_num,
    uint32_t flags,
    unsigned char *script,
    size_t script_len,
    size_t *written);

/**
 * Create a scriptpubkey corresponding to a output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param key_name_array: Array of key policy name string.
 * :param key_value_array: Array of key mapped value string.
 * :param array_len: Length of the array of key policy name.
 * :param derive_child_num: Number of the derive path.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param target_depth: Number of the descriptor depth. Default is 0.
 * :param target_index: Number of the descriptor index. Default is 0.
 * :param flags: For future use. Must be 0.
 * :param script: Destination for the resulting scriptpubkey.
 * :param script_len: Length of the script array.
 * :param written: Destination for the using scriptpubkey length.
 */
WALLY_CORE_API int wally_descriptor_to_scriptpubkey(
    const char *descriptor,
    const char **key_name_array,
    const char **key_value_array,
    size_t array_len,
    uint32_t derive_child_num,
    uint32_t network,
    uint32_t target_depth,
    uint32_t target_index,
    uint32_t flags,
    unsigned char *script,
    size_t script_len,
    size_t *written);

/**
 * Create an address corresponding to a output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param key_name_array: Array of key policy name string.
 * :param key_value_array: Array of key mapped value string.
 * :param array_len: Length of the array of key policy name.
 * :param derive_child_num: Number of the derive path.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_to_address(
    const char *descriptor,
    const char **key_name_array,
    const char **key_value_array,
    size_t array_len,
    uint32_t derive_child_num,
    uint32_t network,
    uint32_t flags,
    char **output);

/**
 * Create addresses that corresponds to the derived range of a output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param key_name_array: Array of key policy name string.
 * :param key_value_array: Array of key mapped value string.
 * :param array_len: Length of the array of key policy name.
 * :param start_child_num: Number of the derive start path.
 * :param end_child_num: Number of the derive end path.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param flags: For future use. Must be 0.
 * :param addresses: Destination for the resulting addresses.
 *|    The string returned should be freed using `wally_free_descriptor_addresses`.
 */
WALLY_CORE_API int wally_descriptor_to_addresses(
    const char *descriptor,
    const char **key_name_array,
    const char **key_value_array,
    size_t array_len,
    uint32_t start_child_num,
    uint32_t end_child_num,
    uint32_t network,
    uint32_t flags,
    struct wally_descriptor_addresses *addresses);

/**
 * Create an output descriptor checksum.
 *
 * :param descriptor: Output descriptor.
 * :param key_name_array: Array of key policy name string.
 * :param key_value_array: Array of key mapped value string.
 * :param array_len: Length of the array of key policy name.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting descriptor string.
 */
WALLY_CORE_API int wally_descriptor_create_checksum(
    const char *descriptor,
    const char **key_name_array,
    const char **key_value_array,
    size_t array_len,
    uint32_t flags,
    char **output);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_DESCRIPTOR_H */
