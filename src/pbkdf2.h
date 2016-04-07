#ifndef LIBWALLY_PBKDF2_H
#define LIBWALLY_PBKDF2_H

#include <stdlib.h>


/** Extra bytes required at the end of 'salt_in_out' for pbkdf2 functions */
#define PBKDF2_HMAC_EXTRA_LEN 4u

/** Output length for @pbkdf2_hmac_sha256 */
#define PBKDF2_HMAC_SHA256_LEN 32

/** Output length for @pbkdf2_hmac_sha512 */
#define PBKDF2_HMAC_SHA512_LEN 64

/** For hmac functions, indicates that 'salt_in_out' contains
 * @PBKDF2_HMAC_EXTRA_LEN extra bytes for a the block number to be added into.
 */
#define PBKDF2_HMAC_FLAG_BLOCK_RESERVED 0x1


/**
 * Derive a pseudorandom key from inputs using HMAC SHA256.
 *
 * @pass: Password to derive from.
 * @pass_len: Length of @pass in bytes.
 * @salt_in_out: Salt to derive from. If @flags contains the value
 *        @PBKDF2_HMAC_FLAG_BLOCK_RESERVED then this memory must
 *        have @PBKDF2_HMAC_EXTRA_LEN of spare room at the end of the salt itself.
 * @salt_len: Length of @salt_in_out in bytes, including any extra spare bytes.
 * @flags: PBKDF2_HMAC_FLAG_ flags values indicating desired behaviour.
 * @cost: The cost of the function. The larger this number, the
 *        longer the key will take to derive.
 * @bytes_out: Destination for the derived pseudorandom key.
 * @len: The length of @bytes_out in bytes. This must be a multiple
 *       of @PBKDF2_HMAC_SHA256_LEN.
 *
 * Returns 0 on success or non-zero if any paramter is invalid.
 */
int pbkdf2_hmac_sha256(
    const unsigned char *pass,
    size_t pass_len,
    unsigned char *salt_in_out,
    size_t salt_len,
    uint32_t flags,
    size_t cost,
    unsigned char *bytes_out,
    size_t len);

/** @see pbkdf2_hmac_sha512.  */
int pbkdf2_hmac_sha512(
    const unsigned char *pass,
    size_t pass_len,
    unsigned char *salt_in_out,
    size_t salt_len,
    uint32_t flags,
    size_t cost,
    unsigned char *bytes_out,
    size_t len);


#endif /* LIBWALLY_PBKDF2_H */
