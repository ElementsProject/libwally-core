#ifndef LIBWALLY_CORE_BIP38_H
#define LIBWALLY_CORE_BIP38_H

#include "wally-core.h"

#include <stdint.h>
#include <stdbool.h>

WALLY_CORE_API int bip38_from_private_key(
    const unsigned char *priv_key,
    size_t len,
    const unsigned char *pass,
    size_t pass_len,
    unsigned char network,
    bool compressed,
    char **output);

#endif /* LIBWALLY_CORE_BIP38_H */
