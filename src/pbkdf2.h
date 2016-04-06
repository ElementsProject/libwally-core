#ifndef LIBWALLY_PBKDF2_H
#define LIBWALLY_PBKDF2_H

#include <stdlib.h>

/** Number of extra bytes required at the end of 'salt' for pbkdf2 functions */
#define PBKDF2_SALT_BYTES 4u

/** Output length for @pbkdf2_hmac_sha256 */
#define PBKDF2_HMAC_SHA256_LEN 32

/** Output length for @pbkdf2_hmac_sha512 */
#define PBKDF2_HMAC_SHA512_LEN 64

/**
 * Derive a pseudorandom key from inputs using HMAC SHA512.
 *
 * @pass: Password to derive from.
 * @pass_len: Length of @pass in bytes.
 * @salt: Salt to derive from.
 * @salt_len: Length of @salt in bytes.
 * @cost: The cost of the function. The larger this number, the
 *        longer the key will take to derive.
 * @bytes_out: Destination for the derived pseudorandom key.
 * @len: The length of @bytes_out in bytes. This must be a multiple
 *       of @PBKDF2_HMAC_SHA512_LEN.
 *
 * Returns 0 on success or non-zero if any paramter is invalid.
 */
int pbkdf2_hmac_sha512(const unsigned char *pass, size_t pass_len,
                       unsigned char *salt, size_t salt_len,
                       size_t cost,
                       unsigned char *bytes_out, size_t len);

#endif /* LIBWALLY_PBKDF2_H */
