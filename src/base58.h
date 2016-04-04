#ifndef LIBWALLY_BASE58_H
#define LIBWALLY_BASE58_H

#include <stdint.h>
#include <stdlib.h>

/**
 * Create a base 58 encoded string representing binary data.
 *
 * @bytes_in: Binary data to convert.
 * @len: The length of @bytes_in in bytes.
 * @output Destination for the base 58 encoded string representing @bytes_in.
 */
WALLY_CORE_API void base58_string_from_bytes(
    const unsigned char *bytes_in,
    size_t len,
    char **output);

/**
 * Decode a base 58 encoded string back into into binary data.
 *
 * @str_in: Base 58 encoded string to decode.
 * @bytes_out: Destination for converted binary data.
 * @len: The length of @bytes_out in bytes.
 *
 * Returns the number of bytes written to @bytes_out or 0 on error.
 */
WALLY_CORE_API size_t base58_string_to_bytes(
    const char *str_in,
    unsigned char *bytes_out,
    size_t len);

#endif /* LIBWALLY_BASE58_H */
