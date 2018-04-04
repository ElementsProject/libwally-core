#ifndef LIBWALLY_CORE_ADDRESS_H
#define LIBWALLY_CORE_ADDRESS_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Create a segwit native address from a v0 witness program.
 *
 * :param bytes: Witness program bytes, including the version and data push opcode.
 * :param bytes_len: Length of ``bytes`` in bytes. Must be 20 or 32 if script_version is 0.
 * :param addr_family: Address family to generate, e.g. "bc" or "tb".
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting segwit native address string.
 */
WALLY_CORE_API int wally_addr_segwit_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    const char *addr_family,
    uint32_t flags,
    char **output);

/**
 * Get a witness program from a segwit native address.
 *
 * :param addr: Address to fetch the witness program from.
 * :param addr_family: Address family to generate, e.g. "bc" or "tb".
 * :param flags: For future use. Must be 0.
 * :param bytes_out: Destination for the resulting witness program bytes.
 * :param len: Length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_addr_segwit_to_bytes(
    const char *addr,
    const char *addr_family,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_ADDRESS_H */
