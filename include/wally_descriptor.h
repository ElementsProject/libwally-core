#ifndef LIBWALLY_CORE_DESCRIPTOR_H
#define LIBWALLY_CORE_DESCRIPTOR_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wally_map;
/** An opaque type holding a parsed minscript/descriptor expression */
struct wally_descriptor;

/*** miniscript-flags Miniscript/Descriptor parsing flags */
#define WALLY_MINISCRIPT_TAPSCRIPT        0x01 /** Tapscript, use x-only pubkeys */
#define WALLY_MINISCRIPT_ONLY             0x02 /** Only allow miniscript (not descriptor) expressions */
#define WALLY_MINISCRIPT_REQUIRE_CHECKSUM 0x04 /** Require a checksum to be present */
#define WALLY_MINISCRIPT_POLICY_TEMPLATE  0x08 /** Only allow policy templates with @n BIP32 keys */
#define WALLY_MINISCRIPT_UNIQUE_KEYPATHS  0x10 /** For policy templates, ensure BIP32 derivation paths differ for identical keys */
#define WALLY_MINISCRIPT_DEPTH_MASK       0xffff0000 /** Mask for limiting maximum depth */
#define WALLY_MINISCRIPT_DEPTH_SHIFT      16 /** Shift to convert maximum depth to flags */

/*** miniscript-features Miniscript/Descriptor feature flags */
#define WALLY_MS_IS_RANGED       0x01 /** Allows key ranges via ``*`` */
#define WALLY_MS_IS_MULTIPATH    0x02 /** Allows multiple paths via ``<a;b;c>`` */
#define WALLY_MS_IS_PRIVATE      0x04 /** Contains at least one private key */
#define WALLY_MS_IS_UNCOMPRESSED 0x08 /** Contains at least one uncompressed key */
#define WALLY_MS_IS_RAW          0x10 /** Contains at least one raw key */
#define WALLY_MS_IS_DESCRIPTOR   0x20 /** Contains only descriptor expressions (no miniscript) */
#define WALLY_MS_IS_X_ONLY       0x40 /** Contains at least one x-only key */
#define WALLY_MS_IS_PARENTED     0x80 /** Contains at least one key key with a parent key origin */

/*** ms-canonicalization-flags Miniscript/Descriptor canonicalization flags */
#define WALLY_MS_CANONICAL_NO_CHECKSUM 0x01 /** Do not include a checksum */

/**
 * Parse an output descriptor or miniscript expression.
 *
 * :param descriptor: Output descriptor or miniscript expression to parse.
 * :param vars_in: Map of variable names to values, or NULL.
 * :param network: Network the descriptor belongs to. Pass `WALLY_NETWORK_NONE`
 *|    for miniscript-only expressions or to infer the network. Must
 *|    be one of the :ref:`address-networks`.
 * :param flags: :ref:`miniscript-flags`. The maximum depth of the descriptor
 *|    can be limited by passing the depth in the upper 16 bits of the flags.
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
 * :param flags: :ref:`ms-canonicalization-flags` controlling canonicalization.
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
 * Get the network used in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param value_out: Destination for the resulting network, returned as one
 *|    of the :ref:`address-networks`.
 *
 * A descriptor parsed with `WALLY_NETWORK_NONE` will infer its network from
 * the contained key expressions. If the descriptor does not contain network
 * information (e.g. its keys are raw keys), then this function will
 * return `WALLY_NETWORK_NONE`, and `wally_descriptor_set_network` must be
 * called to set a network for the descriptor before addresses can be
 * generated from it.
 */
WALLY_CORE_API int wally_descriptor_get_network(
    const struct wally_descriptor *descriptor,
    uint32_t *value_out);

/**
 * set the network for a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param network: Network the descriptor should belong to. One of the :ref:`address-networks`.
 *
 * .. note:: The network can only be set if it is currently `WALLY_NETWORK_NONE`.
 */
WALLY_CORE_API int wally_descriptor_set_network(
    struct wally_descriptor *descriptor,
    uint32_t network);

/**
 * Get the features used in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param value_out: Destination for the resulting :ref:`miniscript-features`.
 */
WALLY_CORE_API int wally_descriptor_get_features(
    const struct wally_descriptor *descriptor,
    uint32_t *value_out);

/**
 * Get the number of variants in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param value_out: Destination for the number of available variants.
 *
 * Expressions such as ``combo()`` can return more than one script/address for
 * a given key or key path. Each available type is represented as a variant
 * numbered from zero. The variant is passed to `wally_descriptor_to_script`
 * or `wally_descriptor_to_addresses` to generate a script/address
 * corresponding to that variant type.
 *
 * For ``combo()``, the variants are ``p2pk``, ``p2pkh``, ``p2wpkh``,
 * and ``p2sh-p2wpkh`` in order from 0-3. If the expression's key is
 * uncompressed, only the first two variants are available.
 */
WALLY_CORE_API int wally_descriptor_get_num_variants(
    const struct wally_descriptor *descriptor,
    uint32_t *value_out);

/**
 * Get the number of multi-path items in a descriptors path expression(s).
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param value_out: Destination for the number of ranges.
 *
 * Paths in descriptor key expressions can contain multiple paths in the
 * format ``<x;y;z>``, where each item corresponds to a new path with the
 * given path elements being one of ``x``, ``y``, or ``z`` respectively. The
 * index of the multi-path is passed to `wally_descriptor_to_script`
 * or `wally_descriptor_to_addresses` to generate a script/address
 * corresponding to the corresponding key path.
 */
WALLY_CORE_API int wally_descriptor_get_num_paths(
    const struct wally_descriptor *descriptor,
    uint32_t *value_out);

/**
 * Get the maximum depth of a descriptors parse tree.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param value_out: Destination for the descriptor depth.
 *
 * This function is intended for use by callers that need to limit the size
 * of descriptors they process (for example, to limit stack usage).
 */
WALLY_CORE_API int wally_descriptor_get_depth(
    const struct wally_descriptor *descriptor,
    uint32_t *value_out);

/**
 * Get the number of keys in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param value_out: Destination for the number of keys.
 *
 * .. note:: Repeated keys are counted once for each time they appear.
 */
WALLY_CORE_API int wally_descriptor_get_num_keys(
    const struct wally_descriptor *descriptor,
    uint32_t *value_out);

/**
 * Get the string representation of a key in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param index: The zero-based index of the key to get.
 * :param output: Destination for the resulting string representation.
 *|    The string returned should be freed using `wally_free_string`.
 *
 * .. note:: Keys may be BIP32 xpub/xpriv, WIF or hex pubkeys, and may be
 *|    x-only. The caller can use `wally_descriptor_get_key_features` to
 *|    determine the type of a given key.
 */
WALLY_CORE_API int wally_descriptor_get_key(
    const struct wally_descriptor *descriptor,
    size_t index,
    char **output);

/**
 * Get the features of a key in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param index: The zero-based index of the key to get.
 * :param value_out: Destination for the resulting :ref:`miniscript-features`.
 */
WALLY_CORE_API int wally_descriptor_get_key_features(
    const struct wally_descriptor *descriptor,
    size_t index,
    uint32_t *value_out);

/**
 * Get the length of a keys child path string in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param index: The zero-based index of the key whose child path to get.
 * :param written: Destination for the length of the keys child path string,
 *|    excluding the NUL terminator (zero if not present).
 */
WALLY_CORE_API int wally_descriptor_get_key_child_path_str_len(
    const struct wally_descriptor *descriptor,
    size_t index,
    size_t *written);

/**
 * Get the keys child path string in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param index: The zero-based index of the key whose child path to get.
 * :param output: Destination for the resulting path string (empty if not present).
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_get_key_child_path_str(
    const struct wally_descriptor *descriptor,
    size_t index,
    char **output);

/**
 * Get the keys parent BIP32 fingerprint in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param index: The zero-based index of the key whose parent fingerprint to get.
 * :param bytes_out: Destination for the fingerprint.
 * FIXED_SIZED_OUTPUT(len, bytes_out, BIP32_KEY_FINGERPRINT_LEN)
 *
 * If the key does not contain key origin information then `WALLY_EINVAL` is returned.
 */
WALLY_CORE_API int wally_descriptor_get_key_origin_fingerprint(
    const struct wally_descriptor *descriptor,
    size_t index,
    unsigned char *bytes_out,
    size_t len);

/**
 * Get the length of a keys parent path string in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param index: The zero-based index of the key whose parent path to get.
 * :param written: Destination for the length of the keys parent path string,
 *|    excluding the NUL terminator (zero if not present).
 */
WALLY_CORE_API int wally_descriptor_get_key_origin_path_str_len(
    const struct wally_descriptor *descriptor,
    size_t index,
    size_t *written);

/**
 * Get the keys parent path string in a parsed output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param index: The zero-based index of the key whose parent path to get.
 * :param output: Destination for the resulting path string (empty if not present).
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_get_key_origin_path_str(
    const struct wally_descriptor *descriptor,
    size_t index,
    char **output);

/**
 * Get the maximum length of a script corresponding to an output descriptor.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param depth: Depth of the expression tree to generate from. Pass 0 to generate from the root.
 * :param index: The zero-based index of the child at depth ``depth`` to generate from.
 * :param variant: The variant of descriptor to generate. See `wally_descriptor_get_num_variants`.
 * :param multi_index: The multi-path item to generate. See `wally_descriptor_get_num_paths`.
 * :param child_num: The BIP32 child number to derive, or 0 for static descriptors.
 * :param flags: For future use. Must be 0.
 * :param written: Destination for the resulting maximum script length.
 *
 * .. note:: This function overestimates the script size required, but is
 *|    cheap to compute (does not require script generation).
 */
WALLY_CORE_API int wally_descriptor_to_script_get_maximum_length(
    const struct wally_descriptor *descriptor,
    uint32_t depth,
    uint32_t index,
    uint32_t variant,
    uint32_t multi_index,
    uint32_t child_num,
    uint32_t flags,
    size_t *written);

/**
 * Create a script corresponding to an output descriptor or miniscript expression.
 *
 * :param descriptor: Parsed output descriptor or miniscript expression.
 * :param depth: Depth of the expression tree to generate from. Pass 0 to generate from the root.
 * :param index: The zero-based index of the child at depth ``depth`` to generate from.
 * :param variant: The variant of descriptor to generate. See `wally_descriptor_get_num_variants`.
 * :param multi_index: The multi-path item to generate. See `wally_descriptor_get_num_paths`.
 * :param child_num: The BIP32 child number to derive, or 0 for static descriptors.
 * :param flags: For future use. Must be 0.
 * :param bytes_out: Destination for the resulting scriptPubKey or script.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 *
 * .. note:: For miniscript expressions, the script generated is untyped
 *|    bitcoin script. For descriptors, a scriptPubKey is generated.
 *
 * .. note:: ``depth`` and ``index`` can be used to generate sub-scripts from
 *|    the expression tree. These are expected to be useful once introspection
 *|    of the expression is improved, e.g. to allow generating the nested
 *|    script inside sh() or wsh() expressions.
 */
WALLY_CORE_API int wally_descriptor_to_script(
    const struct wally_descriptor *descriptor,
    uint32_t depth,
    uint32_t index,
    uint32_t variant,
    uint32_t multi_index,
    uint32_t child_num,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create an address corresponding to an output descriptor.
 *
 * :param descriptor: Parsed output descriptor.
 * :param variant: The variant of descriptor to generate. See `wally_descriptor_get_num_variants`.
 * :param multi_index: The multi-path item to generate. See `wally_descriptor_get_num_paths`.
 * :param child_num: The BIP32 child number to derive, or zero for static descriptors.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting address.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_to_address(
    const struct wally_descriptor *descriptor,
    uint32_t variant,
    uint32_t multi_index,
    uint32_t child_num,
    uint32_t flags,
    char **output);

/**
 * Create addresses that correspond to the derived range of an output descriptor.
 *
 * :param descriptor: Parsed output descriptor.
 * :param variant: The variant of descriptor to generate. See `wally_descriptor_get_num_variants`.
 * :param multi_index: The multi-path item to generate. See `wally_descriptor_get_num_paths`.
 * :param child_num: The BIP32 child number to derive, or zero for static descriptors.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting addresses.
 * :param num_outputs: The number of items in ``output``. Addresses will be
 *|    generated into this array starting from child_num, incrementing by 1.
 *|    The addresses returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_to_addresses(
    const struct wally_descriptor *descriptor,
    uint32_t variant,
    uint32_t multi_index,
    uint32_t child_num,
    uint32_t flags,
    char **output,
    size_t num_outputs);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_DESCRIPTOR_H */
