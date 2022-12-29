#ifndef LIBWALLY_CORE_DESCRIPTOR_H
#define LIBWALLY_CORE_DESCRIPTOR_H

#include "wally_core.h"
#include "wally_address.h"
#include "wally_map.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WALLY_NETWORK_BITCOIN_REGTEST 0xff  /** Bitcoin regtest */

/* miniscript type flag */
#define WALLY_MINISCRIPT_WITNESS_SCRIPT  0x00
#define WALLY_MINISCRIPT_TAPSCRIPT       0x01

/**
 * Create a script corresponding to a miniscript string.
 *
 * :param miniscript: Miniscript string.
 * :param key_value_map: key map of input label name.
 * :param derive_child_num: Number of the derive path.
 * :param flags: For analyze type.
 *|    see WALLY_MINISCRIPT_WITNESS_SCRIPT, WALLY_MINISCRIPT_TAPSCRIPT.
 * :param script_out: Destination for the resulting scriptpubkey.
 * :param script_len: Length of the script array.
 * :param written: Destination for the using scriptpubkey length.
 */
WALLY_CORE_API int wally_descriptor_parse_miniscript(
    const char *miniscript,
    const struct wally_map *key_value_map,
    uint32_t derive_child_num,
    uint32_t flags,
    unsigned char *script_out,
    size_t script_len,
    size_t *written);

/**
 * Create a script corresponding to a miniscript string.
 *
 * :param miniscript: Miniscript string.
 * :param key_value_map: key map of input label name.
 * :param derive_child_num: Number of the derive path.
 * :param flags: For analyze type.
 *|    see WALLY_MINISCRIPT_WITNESS_SCRIPT, WALLY_MINISCRIPT_TAPSCRIPT.
 * :param written: Destination for the using scriptpubkey length.
 */
WALLY_CORE_API int wally_descriptor_parse_miniscript_len(
    const char *miniscript,
    const struct wally_map *key_value_map,
    uint32_t derive_child_num,
    uint32_t flags,
    size_t *written);

/**
 * Create a scriptpubkey corresponding to a output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param key_value_map: key map of input label name.
 * :param derive_child_num: Number of the derive path.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param target_depth: Number of the descriptor depth. Default is 0.
 * :param target_index: Number of the descriptor index. Default is 0.
 * :param flags: For future use. Must be 0.
 * :param script_out: Destination for the resulting scriptpubkey.
 * :param script_len: Length of the script array.
 * :param written: Destination for the using scriptpubkey length.
 */
WALLY_CORE_API int wally_descriptor_to_scriptpubkey(
    const char *descriptor,
    const struct wally_map *key_value_map,
    uint32_t derive_child_num,
    uint32_t network,
    uint32_t target_depth,
    uint32_t target_index,
    uint32_t flags,
    unsigned char *script_out,
    size_t script_len,
    size_t *written);

/**
 * Create a scriptpubkey corresponding to a output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param key_value_map: key map of input label name.
 * :param derive_child_num: Number of the derive path.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param target_depth: Number of the descriptor depth. Default is 0.
 * :param target_index: Number of the descriptor index. Default is 0.
 * :param flags: For future use. Must be 0.
 * :param written: Destination for the using scriptpubkey length.
 */
WALLY_CORE_API int wally_descriptor_to_scriptpubkey_len(
    const char *descriptor,
    const struct wally_map *key_value_map,
    uint32_t derive_child_num,
    uint32_t network,
    uint32_t target_depth,
    uint32_t target_index,
    uint32_t flags,
    size_t *written);

/**
 * Create an address corresponding to a output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param key_value_map: key map of input label name.
 * :param derive_child_num: Number of the derive path.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_to_address(
    const char *descriptor,
    const struct wally_map *key_value_map,
    uint32_t derive_child_num,
    uint32_t network,
    uint32_t flags,
    char **output);

/**
 * Create addresses that corresponds to the derived range of a output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param key_value_map: key map of input label name.
 * :param start_child_num: Number of the derive start path.
 * :param end_child_num: Number of the derive end path.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param flags: For future use. Must be 0.
 * :param addresses: Destination for the resulting addresses.
 *|    The string returned should be freed using `wally_map_free`.
 */
WALLY_CORE_API int wally_descriptor_to_addresses_alloc(
    const char *descriptor,
    const struct wally_map *key_value_map,
    uint32_t start_child_num,
    uint32_t end_child_num,
    uint32_t network,
    uint32_t flags,
    struct wally_map **addresses);

/**
 * Create an output descriptor checksum.
 *
 * :param descriptor: Output descriptor.
 * :param key_value_map: key map of input label name.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting descriptor string.
 */
WALLY_CORE_API int wally_descriptor_create_checksum(
    const char *descriptor,
    const struct wally_map *key_value_map,
    uint32_t flags,
    char **output);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_DESCRIPTOR_H */
