#ifndef LIBWALLY_BASE58_H
#define LIBWALLY_BASE58_H

#include <stdint.h>
#include <stdlib.h>

/** The number of extra bytes required to hold a base58 checksum */
#define BASE58_CHECKSUM_LEN 4u

/** For @base58_string_from_bytes, indicates that a checksum should
 * be generated.
 **/
#define BASE58_FLAG_CHECKSUM_GENERATE 0x1

/** For @base58_string_from_bytes, indicates that 'bytes_in_out' contains
 * @BASE58_CHECKSUM_LEN extra bytes for a checksum to be added into.
 */
#define BASE58_FLAG_CHECKSUM_RESERVED 0x2

/**
 * Create a base 58 encoded string representing binary data.
 *
 * @bytes_in_out: Binary data to convert.
 * @len: The length of @bytes_in_out in bytes.
 * @flags: Pass @BASE58_FLAG_CHECKSUM_GENERATE if @bytes_in_out should have a
 *         checksum calculated and appended before converting to base 58. Pass
 *         @BASE58_FLAG_CHECKSUM_RESERVED if @bytes_in_out contains an
 *         extra @BASE58_CHECKSUM_LEN bytes to calculate the checksum into. @len
 *         should be the full length including any extra bytes passed.
 * @output Destination for the base 58 encoded string representing @bytes_in_out.
 */
void base58_string_from_bytes(
    unsigned char *bytes_in_out,
    size_t len,
    uint32_t flags,
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
size_t base58_string_to_bytes(
    const char *str_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

#endif /* LIBWALLY_BASE58_H */
