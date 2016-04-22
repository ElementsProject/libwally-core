#ifndef LIBWALLY_CORE_BIP38_H
#define LIBWALLY_CORE_BIP38_H

#include "wally_core.h"

#include <stdint.h>

/* Flags for BIP38 conversion. The first 8 bits are reserved for the network */
#define BIP38_KEY_MAINNET       0  /* Address is for main network */
#define BIP38_KEY_TESTNET       7  /* Address is for test network */
#define BIP38_KEY_COMPRESSED   256 /* Public key is compressed */
#define BIP38_KEY_EC_MULT      512 /* EC-Multiplied key (FIXME: Not implemented) */
#define BIP38_KEY_RAW_MODE    1024 /* Treat bytes in as raw data */
#define BIP38_KEY_SWAP_ORDER  2048 /* Hash comes after encrypted key */

#define BIP38_RAW_LEN 39 /* Length of a raw BIP38 key in bytes */

WALLY_CORE_API int bip38_raw_from_private_key(
    const unsigned char *bytes_in,
    size_t len_in,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

WALLY_CORE_API int bip38_from_private_key(
    const unsigned char *bytes_in,
    size_t len_in,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    char **output);

WALLY_CORE_API int bip38_raw_to_private_key(
    const unsigned char *bytes_in,
    size_t len_in,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

WALLY_CORE_API int bip38_to_private_key(
    const char *bip38,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

#endif /* LIBWALLY_CORE_BIP38_H */
