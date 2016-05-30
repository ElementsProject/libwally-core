#include <include/wally_core.h>
#include "internal.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "ccan/ccan/str/hex/hex.h"

int wally_bytes_to_hex(const unsigned char *bytes_in, size_t len_in,
                       char **output)
{
    (void)bytes_in;
    (void)len_in;
    (void)output;
    return 0;
}

int wally_hex_to_bytes(const char *hex,
                       unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t len_in;

    if (written)
        *written = 0;

    if (!hex || !bytes_out || !len || !(len_in = strlen(hex)) || len_in & 0x1)
        return WALLY_EINVAL;

    if (len < len_in / 2) {
        *written = len_in / 2;
        return WALLY_OK; /* Not enough room in bytes_out */
    }

    len = len_in / 2; /* hex_decode expects exact length */
    if (!hex_decode(hex, len_in, bytes_out, len))
        return WALLY_EINVAL;

    if (written)
        *written = len;

    return WALLY_OK;
}
