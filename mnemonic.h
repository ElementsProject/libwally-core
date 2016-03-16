#ifndef LIBWALLY_MNEMONIC_H
#define LIBWALLY_MNEMONIC_H

#include <stdint.h>
#include <stdlib.h>

struct words;

/**
 * mnemonic_from_bytes - Return a mnemonic representation of a block of bytes.
 * @w: List of words.
 * @bytes: Bytes to covert to a mnemonic pass phrase.
 * @len: The length of @bytes in bytes.
 *
 * @bytes must be an even multiple of the number of bits in the wordlist used.
 */
char* mnemonic_from_bytes(const struct words *w, const uint8_t *bytes, size_t len);

#endif /* LIBWALLY_MNEMONIC_H */
