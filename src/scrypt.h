#ifndef LIBWALLY_SCRYPT_H
#define LIBWALLY_SCRYPT_H

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
 *
 * @bytes_in must be an even multiple of the number of bits in the wordlist used.
 */
int scrypt(const unsigned char *pass, size_t pass_len,
           const unsigned char *salt, size_t salt_len,
           uint32_t cost, uint32_t block_size, uint32_t parallelism,
           unsigned char *bytes_out, size_t len);

#endif /* LIBWALLY_SCRYPT_H */
