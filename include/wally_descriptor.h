#ifndef LIBWALLY_CORE_DESCRIPTOR_H
#define LIBWALLY_CORE_DESCRIPTOR_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wally_map;

/* Miniscript type flag */
#define WALLY_MINISCRIPT_WITNESS_SCRIPT 0x00 /** Witness script */
#define WALLY_MINISCRIPT_TAPSCRIPT      0x01 /** Tapscript */

/**
 * Canonicalize a descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting canonical descriptor.
 *|    The string returned should be freed using `wally_free_string`.
 *
 * Replaces any variables from ``vars_in`` with their mapped values,
 * and adds a checksum if required. Key names for ``vars_in`` must be 16
 * characters or less and start with a letter.
 *
 * .. note:: Other canonicalization (hardened derivation indicator
 * mapping, and private to public key mapping) is not yet implemented.
 */
WALLY_CORE_API int wally_descriptor_canonicalize(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t flags,
    char **output);

/**
 * Get the length of a script corresponding to a miniscript string.
 *
 * :param miniscript: Miniscript string.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param child_num: The BIP32 child number to derive.
 * :param flags: Flags controlling the type of script to create. Use one of
 *|    ``WALLY_MINISCRIPT_WITNESS_SCRIPT`` or ``WALLY_MINISCRIPT_TAPSCRIPT``.
 * :param written: Destination for the resulting script length.
 *
 * .. note:: Computing this length is expensive. Prefer to pass a large
 *| buffer to `wally_miniscript_to_script` and retry only if the
 *| buffer is too small.
 */
WALLY_CORE_API int wally_miniscript_to_script_len(
    const char *miniscript,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t flags,
    size_t *written);

/**
 * Create a script corresponding to a miniscript string.
 *
 * :param miniscript: Miniscript string.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param child_num: The BIP32 child number to derive.
 * :param flags: Flags controlling the type of script to create. Use one of
 *|    ``WALLY_MINISCRIPT_WITNESS_SCRIPT`` or ``WALLY_MINISCRIPT_TAPSCRIPT``.
 * :param bytes_out: Destination for the resulting scriptPubKey.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_miniscript_to_script(
    const char *miniscript,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of a scriptPubKey corresponding to an output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param child_num: The BIP32 child number to derive.
 * :param network: ``WALLY_NETWORK_`` constant descripting the network to generate for.
 * :param depth: Number of the descriptor depth. Default is 0.
 * :param index: Number of the descriptor index. Default is 0.
 * :param flags: For future use. Must be 0.
 * :param written: Destination for the resulting scriptPubKey length.
 *
 * .. note:: Computing this length is expensive. Prefer to pass a large
 *| buffer to `wally_descriptor_to_scriptpubkey` and retry only if the
 *| buffer is too small.
 */
WALLY_CORE_API int wally_descriptor_to_scriptpubkey_len(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t network,
    uint32_t depth,
    uint32_t index,
    uint32_t flags,
    size_t *written);

/**
 * Create a scriptPubKey corresponding to an output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param child_num: The BIP32 child number to derive.
 * :param network: ``WALLY_NETWORK_`` constant descripting the network to generate for.
 * :param depth: Number of the descriptor depth. Default is 0.
 * :param index: Number of the descriptor index. Default is 0.
 * :param flags: For future use. Must be 0.
 * :param bytes_out: Destination for the resulting scriptPubKey.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_descriptor_to_scriptpubkey(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t network,
    uint32_t depth,
    uint32_t index,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create an address corresponding to an output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param child_num: The BIP32 child number to derive.
 * :param network: ``WALLY_NETWORK_`` constant descripting the network to generate for.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting addresss.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_to_address(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t network,
    uint32_t flags,
    char **output);

/**
 * Create addresses that correspond to the derived range of an output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param child_num: The first BIP32 child number to derive.
 * :param network: ``WALLY_NETWORK_`` constant descripting the network to generate for.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting addresses.
 * :param num_outputs: The number of items in ``output``. Addresses will be
 *|    generated into this array starting from child_num, incrementing by 1.
 *|    The addresses returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_to_addresses(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t network,
    uint32_t flags,
    char **output,
    size_t num_outputs);

/**
 * Create an output descriptor checksum.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting descriptor checksum.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_get_checksum(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t flags,
    char **output);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_DESCRIPTOR_H */
