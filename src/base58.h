#ifndef LIBWALLY_BASE58_H
#define LIBWALLY_BASE58_H

#include <ccan/compiler/compiler.h>

/**
 * Calculate the base58 checksum of a block of binary data.
 *
 * @bytes: Binary data to calculate the checksum for.
 * @len: The length of @bytes in bytes.
 * @checksum: Destination for the checksum.
 *
 * Returns WALLY_OK, or WALLY_ERROR if hashing failed.
 */
int base58_get_checksum(
    const unsigned char *bytes,
    size_t len,
    uint32_t *checksum) WARN_UNUSED_RESULT;

#endif /* LIBWALLY_BASE58_H */
