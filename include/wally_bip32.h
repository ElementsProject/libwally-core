#ifndef LIBWALLY_CORE_BIP32_H
#define LIBWALLY_CORE_BIP32_H

#include "wally-core.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define BIP32_ENTROPY_LEN_256 32u


/* Extended key */
struct ext_key {
    unsigned char chain_code[32];
    unsigned char key[32];

};

WALLY_CORE_API int bip32_ext_key_from_bytes(
    const unsigned char *bytes,
    size_t len,
    struct ext_key *dest);

#endif /* LIBWALLY_CORE_BIP32_H */
