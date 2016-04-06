#ifndef LIBWALLY_PBKDF2_H
#define LIBWALLY_PBKDF2_H

#include <stdlib.h>

/** Number of extra bytes required at the end of 'salt' for pbkdf2 functions */
#define PBKDF2_SALT_BYTES 4u

/** Output length for @pbkdf2_hmac_sha512 */
#define PBKDF2_HMAC_SHA512_LEN 64

/* Note we only support a single output block at present - len must
 * be @PBKDF2_HMAC_SHA512_LEN
 */
int pbkdf2_hmac_sha512(const unsigned char *pass, size_t pass_len,
                       unsigned char *salt, size_t salt_len,
                       unsigned char *bytes_out, size_t len);

#endif /* LIBWALLY_PBKDF2_H */
