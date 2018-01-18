#ifndef LIBWALLY_CORE_ADDRESS_H
#define LIBWALLY_CORE_ADDRESS_H

#include "wally_core.h"

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Create a segwit native address from a v0 witness program.
 *
 * @bytes_in: Witness program bytes, including the version and data push opcode.
 * @len_in: Length of @bytes_in in bytes. Must be 20 or 32 if script_version is 0.
 * @addr_family: Address family to generate, e.g. "bc" or "tb".
 * @flags: For future use. Must be 0.
 * @output: Destination for the resulting segwit native address string.
 */
WALLY_CORE_API int wally_addr_segwit_from_bytes(
    const unsigned char *bytes_in,
    size_t len_in,
    const char *addr_family,
    uint32_t flags,
    char **output);

/**
 * Get a witness program from a segwit native address.
 *
 * @addr: Address to fetch the witness program from.
 * @addr_family: Address family to generate, e.g. "bc" or "tb".
 * @flags: For future use. Must be 0.
 * @bytes_out: Destination for the resulting witness program bytes.
 * @len: Length of @bytes_out in bytes.
 * @written: Destination for the number of bytes written to @bytes_out.
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
