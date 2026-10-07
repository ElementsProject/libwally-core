#ifndef LIBWALLY_CORE_MINISCRIPT_DECODE_H
#define LIBWALLY_CORE_MINISCRIPT_DECODE_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct wally_descriptor;
struct wally_map;

/* Maximum script lengths accepted by the decoder, matching Bitcoin Core's
 * MaxScriptSize(). Callers pass attacker-controlled PSBT scripts here, so
 * anything larger is rejected before decoding.
 *
 * Segwit v0: the P2WSH standardness limit (MAX_STANDARD_P2WSH_SCRIPT_SIZE).
 *
 * Tapscript: leaf scripts have no explicit limit, so Core bounds them by what
 * a maximum-standard-weight transaction can still spend with a maximum-sized
 * witness, i.e. MAX_STANDARD_TX_WEIGHT (400000)
 *   - TX_BODY_LEEWAY_WEIGHT (378: version, locktime, 1 input, 1 P2WSH output,
 *     compact sizes, segwit marker, all x4, plus 2)
 *   - MAX_TAPSCRIPT_SAT_SIZE (70135: 1000 stack elements of 65 bytes with
 *     their compact sizes, plus a maximum 4129-byte control block)
 *   = 329487, less the 5-byte compact size of that length. */
#define MS_DECODE_MAX_SCRIPT_LEN_SEGWIT_V0 3600
#define MS_DECODE_MAX_SCRIPT_LEN_TAPSCRIPT 329482

/* Maximum nesting depth of a decoded expression, as limited by passing
 * it to wally_descriptor_parse() (see WALLY_MINISCRIPT_DEPTH_SHIFT) */
#define MS_DECODE_MAX_DEPTH 128

/*
 * Decode a script into miniscript expression text.
 *
 * :param script: The segwit v0 witness script or tapscript leaf script.
 * :param script_len: Length of ``script`` in bytes.
 * :param keys: Public keys to resolve the key hashes of ``pk_h`` fragments
 *|    from, as the keys of a map, or NULL. Only keys of the size used by
 *|    the script context (33 bytes for segwit v0, 32 for tapscript) are used.
 * :param flags: WALLY_MINISCRIPT_TAPSCRIPT to decode a tapscript, or 0.
 * :param output: Destination for the resulting expression text.
 *|    The string returned should be freed using `wally_free_string`.
 *
 * The script is decoded as Bitcoin Core's miniscript DecodeScript() does,
 * and printed as its ToString() would print the result. The expression is
 * not type checked: use `ms_descriptor_from_script` to obtain a validated
 * expression.
 */
int ms_script_to_miniscript(const unsigned char *script, size_t script_len,
                            const struct wally_map *keys, uint32_t flags,
                            char **output);

/*
 * Decode a script into a parsed miniscript expression.
 *
 * :param script: The segwit v0 witness script or tapscript leaf script.
 * :param script_len: Length of ``script`` in bytes.
 * :param keys: As for `ms_script_to_miniscript`.
 * :param flags: As for `ms_script_to_miniscript`.
 * :param output: Destination for the resulting parsed expression.
 *|    The descriptor returned should be freed using `wally_descriptor_free`.
 *
 * In addition to decoding the script, checks that the expression is a valid
 * top level miniscript expression (i.e. of type B) and that it generates
 * the given script.
 */
int ms_descriptor_from_script(const unsigned char *script, size_t script_len,
                              const struct wally_map *keys, uint32_t flags,
                              struct wally_descriptor **output);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_MINISCRIPT_DECODE_H */
