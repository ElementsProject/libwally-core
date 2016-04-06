#ifndef LIBWALLY_PBKDF2_H
#define LIBWALLY_PBKDF2_H

#include <stdlib.h>

/** This number of extra bytes are required at the end of 'salt' */
#define PBKDF2_SALT_BYTES 4u

void pbkdf2_hmac_sha256(unsigned char *bytes_out,
                        const unsigned char *pass, size_t pass_len,
                        unsigned char *salt, size_t salt_len);

void pbkdf2_hmac_sha512(unsigned char *bytes_out,
                        const unsigned char *pass, size_t pass_len,
                        unsigned char *salt, size_t salt_len);

#endif /* LIBWALLY_PBKDF2_H */
