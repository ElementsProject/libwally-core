#ifndef LIBWALLY_CORE_BIP38_H
#define LIBWALLY_CORE_BIP38_H

#include "wally_core.h"

#include <stdint.h>
#include <stdbool.h>

WALLY_CORE_API int bip38_from_private_key(
    const unsigned char *priv_key,
    size_t len,
    const unsigned char *password,
    size_t password_len,
    unsigned char network,
    bool compressed,
    char **output);

WALLY_CORE_API int bip38_to_private_key(
    const char *bip38,
    const unsigned char *password,
    size_t password_len,
    unsigned char network,
    unsigned char *bytes_out,
    size_t len);

#endif /* LIBWALLY_CORE_BIP38_H */
