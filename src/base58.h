#ifndef LIBWALLY_BASE58_H
#define LIBWALLY_BASE58_H

#include <stdint.h>
#include <stdlib.h>

/** The number of extra bytes required to hold a base58 checksum */
#define BASE58_CHECKSUM_LEN 4u

/** For @base58_from_bytes, indicates that a checksum should
 * be generated. For @base58_to_bytes, indicates that the
 * embedded checksum should be validated and stripped off the returned
 * bytes.
 **/
#define BASE58_FLAG_CHECKSUM 0x1

/**
 * Create a base 58 encoded string representing binary data.
 *
 * @bytes_in_out: Binary data to convert.
 * @len: The length of @bytes_in_out in bytes.
 * @flags: Pass @BASE58_FLAG_CHECKSUM if @bytes_in_out should have a
 *         checksum calculated and appended before converting to base 58.
 * @output Destination for the base 58 encoded string representing @bytes_in_out.
 *         This should be freed using @wally_free_string().
 */
int base58_from_bytes(
    unsigned char *bytes_in_out,
    size_t len,
    uint32_t flags,
    char **output);

/**
 * Calculate the base58 checksum of a block of binary data.
 *
 * @bytes_in_out: Binary data to calculate the checksum for.
 * @len: The length of @bytes_in_out in bytes.
 */
uint32_t base58_get_checksum(
    const unsigned char *bytes_in,
    size_t len);

/**
 * Return the length of a base58 encoded string once decoded into bytes.
 *
 * @str_in: Base 58 encoded string to find the length of.
 * @written: Destination for the length of the decoded bytes.
 *
 * Returns the exact number of bytes that would be required to store @str_in
 * as decoded binary, including any embedded checksum. If the string contains
 * invalid characters then WALLY_EINVAL is returned. Note that no checksum
 * validation takes place.
 *
 * In the worst case (an all zero buffer, represented by a string of '1'
 * characters), this function will return strlen(@str_in). You can therefore
 * safely use the length of @str_in as a buffer size to avoid calling this
 * function in most cases.
 */
int base58_get_length(
    const char *str_in,
    size_t *written);

/**
 * Decode a base 58 encoded string back into into binary data.
 *
 * @str_in: Base 58 encoded string to decode.
 * @flags: Pass @BASE58_FLAG_CHECKSUM if @bytes_out should have a
 *         checksum validated and removed before returning. In this case, @len
 *         must contain an extra @BASE58_CHECKSUM_LEN bytes to calculate the
 *         checksum into. The returned length will not include the checksum.
 * @bytes_out: Destination for converted binary data.
 * @len: The length of @bytes_out in bytes.
 * @written: Destination for the length of the decoded bytes.
 *
 * If the function succeeds, you must check @written. If it is greater
 * than @len then no data has been written and the function should be retried
 * with a buffer of at least @written bytes in size.
 */
int base58_to_bytes(
    const char *str_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#endif /* LIBWALLY_BASE58_H */
