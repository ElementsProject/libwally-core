#ifndef LIBWALLY_CORE_BIP38_H
#define LIBWALLY_CORE_BIP38_H

#include "wally_core.h"

#include <stdint.h>
#include <stdbool.h>

/* Flags for BIP38 conversion. The first 8 bits are reserved for the network */
#define BIP38_KEY_MAINNET    0   /* Address is for main network */
#define BIP38_KEY_TESTNET    7   /* Address is for test network */
#define BIP38_KEY_COMPRESSED 256 /* Public key is compressed */
#define BIP38_KEY_EC_MULT    512 /* EC-Multiplied key (FIXME: Not implemented) */


WALLY_CORE_API int bip38_from_private_key(
    const unsigned char *priv_key,
    size_t len,
    const unsigned char *password,
    size_t password_len,
    uint32_t flags,
    char **output);

WALLY_CORE_API int bip38_to_private_key(
    const char *bip38,
    const unsigned char *password,
    size_t password_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

#endif /* LIBWALLY_CORE_BIP38_H */
