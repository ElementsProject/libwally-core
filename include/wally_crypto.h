#ifndef LIBWALLY_CORE_CRYPTO_H
#define LIBWALLY_CORE_CRYPTO_H

#include "wally_core.h"

#include <stdint.h>
#include <stdlib.h>

/**
 * Derive a pseudorandom key from inputs using an expensive application
 * of HMAC SHA256.
 *
 * @pass: Password to derive from.
 * @pass_len: Length of @pass in bytes.
 * @salt: Salt to derive from.
 * @salt_len: Length of @salt in bytes.
 * @cost: The cost of the function. The larger this number, the
 *        longer the key will take to derive.
 * @block_size: The size of memory blocks required.
 * @parallelism: Parallelism factor.
 * @bytes_out: Destination for the derived pseudorandom key.
 * @len: The length of @bytes_out in bytes.
 */
WALLY_CORE_API int wally_scrypt(
    const unsigned char *pass,
    size_t pass_len,
    const unsigned char *salt,
    size_t salt_len,
    uint32_t cost,
    uint32_t block_size,
    uint32_t parallelism,
    unsigned char *bytes_out,
    size_t len);


/** Extra bytes required at the end of 'salt_in_out' for pbkdf2 functions */
#define PBKDF2_HMAC_EXTRA_LEN 4

/** Output length for @wally_pbkdf2_hmac_sha256 */
#define PBKDF2_HMAC_SHA256_LEN 32

/** Output length for @wally_pbkdf2_hmac_sha512 */
#define PBKDF2_HMAC_SHA512_LEN 64

/** For hmac functions, indicates that 'salt_in_out' contains
 * @PBKDF2_HMAC_EXTRA_LEN extra bytes for the block number to be added into.
 */
#define PBKDF2_HMAC_FLAG_BLOCK_RESERVED 1


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
 * Returns 0 on success or non-zero if any parameter is invalid.
 */
WALLY_CORE_API int wally_pbkdf2_hmac_sha256(
    const unsigned char *pass,
    size_t pass_len,
    unsigned char *salt_in_out,
    size_t salt_len,
    uint32_t flags,
    uint32_t cost,
    unsigned char *bytes_out,
    size_t len);

/** @see wally_pbkdf2_hmac_sha512. */
WALLY_CORE_API int wally_pbkdf2_hmac_sha512 (
    const unsigned char *pass,
    size_t pass_len,
    unsigned char *salt_in_out,
    size_t salt_len,
    uint32_t flags,
    uint32_t cost,
    unsigned char *bytes_out,
    size_t len);

#endif /* LIBWALLY_CORE_CRYPTO_H */
