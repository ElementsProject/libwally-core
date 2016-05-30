#ifndef LIBWALLY_CORE_CRYPTO_H
#define LIBWALLY_CORE_CRYPTO_H

#include "wally_core.h"

#include <stdint.h>
#include <stdlib.h>

/**
 * Derive a pseudorandom key from inputs using an expensive application
 * of HMAC SHA-256.
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


#define AES_BLOCK_LEN   16 /** Length of AES encrypted blocks */

#define AES_KEY_LEN_128 16 /** AES-128 Key length */
#define AES_KEY_LEN_192 24 /** AES-192 Key length */
#define AES_KEY_LEN_256 32 /** AES-256 Key length */

#define AES_FLAG_ENCRYPT  1 /** Encrypt */
#define AES_FLAG_DECRYPT  2 /** Decrypt */

/**
 * Encrypt/decrypt data using AES (ECB mode, no padding).
 *
 * @key: Key material for initialisation.
 * @key_len: Length of @key in bytes. Must be an AES_KEY_LEN_ constant.
 * @bytes_in: Bytes to encrypt/decrypt.
 * @len_in: Length of @bytes_in in bytes. Must be a multiple of @AES_BLOCK_LEN.
 * @flags: AES_FLAG_ constants indicating the desired behaviour.
 * @bytes_out: Destination for the encrypted/decrypted data.
 * @len: The length of @bytes_out in bytes. Must be a multiple of @AES_BLOCK_LEN.
 */
WALLY_CORE_API int wally_aes(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Encrypt/decrypt data using AES (CBC mode).
 *
 * @key: Key material for initialisation.
 * @key_len: Length of @key in bytes. Must be an AES_KEY_LEN_ constant.
 * @iv: Initialisation vector.
 * @iv_len: Length of @iv in bytes. Must be @AES_BLOCK_LEN.
 * @bytes_in: Bytes to encrypt/decrypt.
 * @len_in: Length of @bytes_in in bytes. Must be a multiple of @AES_BLOCK_LEN.
 * @flags: AES_FLAG_ constants indicating the desired behaviour.
 * @bytes_out: Destination for the encrypted/decrypted data.
 * @len: The length of @bytes_out in bytes. Must be a multiple of @AES_BLOCK_LEN.
 * @written: Destination for the number of bytes written to @bytes_out.
 *
 * Defaults to PKCS#7 padding.
 */
WALLY_CORE_API int wally_aes_cbc(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *iv,
    size_t iv_len,
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);


/** Output length for @wally_sha256 */
#define SHA256_LEN 32

/** Output length for @wally_sha512 */
#define SHA512_LEN 64

/**
 * SHA-256
 *
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting hash.
 * @len: The length of @bytes_out in bytes. Must be @SHA256_LEN.
 */
WALLY_CORE_API int wally_sha256(
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);

/**
 * SHA-256d (double SHA-256)
 *
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting hash.
 * @len: The length of @bytes_out in bytes. Must be @SHA256_LEN.
 */
WALLY_CORE_API int wally_sha256d(
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);

/**
 * SHA-512
 *
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting hash.
 * @len: The length of @bytes_out in bytes. Must be @SHA512_LEN.
 */
WALLY_CORE_API int wally_sha512(
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);


/** Output length for @wally_hmac_sha256 */
#define HMAC_SHA256_LEN 32

/** Output length for @wally_hmac_sha512 */
#define HMAC_SHA512_LEN 64

/**
 * Compute an HMAC using SHA-256
 *
 * @key: The key for the hash
 * @key_len: The length of @key in bytes.
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting HMAC.
 * @len: The length of @bytes_out in bytes. Must be @HMAC_SHA256_LEN.
 */
WALLY_CORE_API int wally_hmac_sha256(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);

/**
 * Compute an HMAC using SHA-512
 *
 * @key: The key for the hash
 * @key_len: The length of @key in bytes.
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting HMAC.
 * @len: The length of @bytes_out in bytes. Must be @HMAC_SHA512_LEN.
 */
WALLY_CORE_API int wally_hmac_sha512(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *bytes_in,
    size_t len_in,
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
 * Derive a pseudorandom key from inputs using HMAC SHA-256.
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
