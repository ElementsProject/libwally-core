#ifndef LIBWALLY_CORE_DESCRIPTOR_H
#define LIBWALLY_CORE_DESCRIPTOR_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wally_map;
/** An opaque type holding a parsed minscript/descriptor expression */
struct wally_descriptor;

/* Miniscript type flag */
#define WALLY_MINISCRIPT_WITNESS_SCRIPT 0x00 /** Witness script */
#define WALLY_MINISCRIPT_TAPSCRIPT      0x01 /** Tapscript */
#define WALLY_MINISCRIPT_ONLY           0x02 /** Only allow miniscript (not descriptor) expressions */

/**
 * Parse an output descriptor or miniscript expression.
 *
 * :param descriptor: Output descriptor or miniscript expression to parse.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param network: ``WALLY_NETWORK_`` constant descripting the network the
 *|    descriptor belongs to, or WALLY_NETWORK_NONE for miniscript-only expressions.
 * :param flags: ``WALLY_MINISCRIPT_ONLY`` to disallow descriptor expressions, or 0.
 * :param output: Destination for the resulting parsed descriptor.
 *|    The descriptor returned should be freed using `wally_descriptor_free`.
 *
 * Variable names can be used in the descriptor string and will be substituted
 * with the contents of ``vars_in`` during parsing. Key names for ``vars_in``
 * must be 16 characters or less in length and start with a letter.
 */
WALLY_CORE_API int wally_descriptor_parse(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t network,
    uint32_t flags,
    struct wally_descriptor **output);

/**
 * Free a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression to free.
 */
WALLY_CORE_API int wally_descriptor_free(
    struct wally_descriptor *descriptor);

/**
 * Canonicalize a descriptor.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting canonical descriptor.
 *|    The string returned should be freed using `wally_free_string`.
 *
 * .. note:: Other canonicalization (hardened derivation indicator
 * mapping, and private to public key mapping) is not yet implemented.
 */
WALLY_CORE_API int wally_descriptor_canonicalize(
    const struct wally_descriptor *descriptor,
    uint32_t flags,
    char **output);

/**
 * Create an output descriptor checksum.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting descriptor checksum.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_get_checksum(
    const struct wally_descriptor *descriptor,
    uint32_t flags,
    char **output);


/**
 * Get the length of a script corresponding to a miniscript string.
 *
 * :param miniscript: Miniscript string.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param child_num: The BIP32 child number to derive, or zero for static scripts.
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
 * :param child_num: The BIP32 child number to derive, or zero for static scripts.
 * :param flags: Flags controlling the type of script to create. Use one of
 *|    ``WALLY_MINISCRIPT_WITNESS_SCRIPT`` or ``WALLY_MINISCRIPT_TAPSCRIPT``.
 * :param bytes_out: Destination for the resulting script.
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
 * Get the maximum length of a scriptPubKey corresponding to an output descriptor.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param flags: For future use. Must be 0.
 * :param written: Destination for the resulting maximum scriptPubKey length.
 *
 * .. note:: This function overestimates the script size required, but is
 *|    cheap to compute (does not require script generation).
 */
WALLY_CORE_API int wally_descriptor_to_scriptpubkey_maximum_length(
    const struct wally_descriptor *descriptor,
    uint32_t flags,
    size_t *written);

/**
 * Get the length of a scriptPubKey corresponding to an output descriptor.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param depth: Depth of the expression tree to generate from. Pass 0 to generate from the root.
 * :param index: The zero-based index of the child at depth ``depth`` to generate from.
 * :param variant: The variant of descriptor to generate. Pass 0 for the default.
 * :param child_num: The BIP32 child number to derive, or 0 for static descriptors.
 * :param flags: For future use. Must be 0.
 * :param written: Destination for the resulting scriptPubKey length.
 *
 * .. note:: Computing the script length using this function is expensive, as
 *|    it must generate the script. Prefer to use `wally_descriptor_to_scriptpubkey_maximum_length`
 *|    or pass a large buffer to `wally_descriptor_to_scriptpubkey` and retry
 *|    the call with a larger buffer if the it was too small.
 */
WALLY_CORE_API int wally_descriptor_to_scriptpubkey_len(
    struct wally_descriptor *descriptor,
    uint32_t depth,
    uint32_t index,
    uint32_t variant,
    uint32_t child_num,
    uint32_t flags,
    size_t *written);

/**
 * Create a scriptPubKey corresponding to an output descriptor.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param depth: Depth of the expression tree to generate from. Pass 0 to generate from the root.
 * :param index: The zero-based index of the child at depth ``depth`` to generate from.
 * :param variant: The variant of descriptor to generate. Pass 0 for the default.
 * :param child_num: The BIP32 child number to derive, or 0 for static descriptors.
 * :param flags: For future use. Must be 0.
 * :param bytes_out: Destination for the resulting scriptPubKey.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_descriptor_to_scriptpubkey(
    struct wally_descriptor *descriptor,
    uint32_t depth,
    uint32_t index,
    uint32_t variant,
    uint32_t child_num,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create an address corresponding to an output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param child_num: The BIP32 child number to derive, or zero for static descriptors.
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
 * :param child_num: The BIP32 child number to derive, or zero for static descriptors.
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

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_DESCRIPTOR_H */
