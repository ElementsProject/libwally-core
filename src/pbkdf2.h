#ifndef LIBWALLY_PBKDF2_H
#define LIBWALLY_PBKDF2_H

#include <stdlib.h>

/** This number of extra bytes are required at the end of 'salt' */
#define PBKDF2_SALT_BYTES 4u

int pbkdf2_hmac_sha512(const unsigned char *pass, size_t pass_len,
                       unsigned char *salt, size_t salt_len,
                       unsigned char *bytes_out, size_t len);

#endif /* LIBWALLY_PBKDF2_H */
