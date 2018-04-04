#include "internal.h"
#include "ccan/ccan/str/hex/hex.h"

int wally_hex_from_bytes(const unsigned char *bytes, size_t bytes_len,
                         char **output)
{
    if (output)
        *output = NULL;

    if (!bytes || !output)
        return WALLY_EINVAL;

    *output = wally_malloc(hex_str_size(bytes_len));
    if (!*output)
        return WALLY_ENOMEM;

    /* Note we ignore the return value as this call cannot fail */
    hex_encode(bytes, bytes_len, *output, hex_str_size(bytes_len));
    return WALLY_OK;
}

int wally_hex_to_bytes(const char *hex,
                       unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t bytes_len = hex ? strlen(hex) : 0;

    if (written)
        *written = 0;

    if (!hex || !bytes_out || !len || bytes_len & 0x1)
        return WALLY_EINVAL;

    if (len < bytes_len / 2) {
        if (written)
            *written = bytes_len / 2;
        return WALLY_OK; /* Not enough room in bytes_out, or empty string */
    }

    len = bytes_len / 2; /* hex_decode expects exact length */
    if (!hex_decode(hex, bytes_len, bytes_out, len))
        return WALLY_EINVAL;

    if (written)
        *written = len;

    return WALLY_OK;
}
