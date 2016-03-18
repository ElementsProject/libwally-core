#ifndef LIBWALLY_MNEMONIC_H
#define LIBWALLY_MNEMONIC_H

#include <stdint.h>
#include <stdlib.h>

struct words;

/**
 * mnemonic_from_bytes - Return a mnemonic representation of a block of bytes.
 * @w: List of words.
 * @bytes: Bytes to convert to a mnemonic pass phrase.
 * @len: The length of @bytes in bytes.
 *
 * @bytes must be an even multiple of the number of bits in the wordlist used.
 */
char* mnemonic_from_bytes(const struct words *w, const uint8_t *bytes, size_t len);

/**
 * mnemonic_to_bytes - Convert a mnemonic representation into a block of bytes.
 * @w: List of words.
 * @mnemonic: Mnemonic pass phrase to store.
 * @bytes: Where to store the converted representation.
 * @len: The length of @bytes in bytes.
 *
 * Returns the length of the written mnemonic in bytes, zero on error.
 */
size_t mnemonic_to_bytes(const struct words *w, const char* mnemonic, uint8_t *bytes, size_t len);

#endif /* LIBWALLY_MNEMONIC_H */
