#include "internal.h"
#include "ccan/ccan/crypto/sha256/sha256.h"

#include "libbase58/base58.c"


void base58_string_from_bytes(const unsigned char *bytes_in, size_t len,
                              uint32_t flags, char **output)
{
    size_t out_len = 0;

    *output = NULL;

    /* FIXME: Handle flags */
    b58enc(NULL, &out_len, bytes_in, len); /* Find required size */

    if (out_len && (*output = malloc(out_len)))
        b58enc(*output, &out_len, bytes_in, len); /* Perform conversion */
}

size_t base58_string_to_bytes(const char *str_in,
                              unsigned char *bytes_out, size_t len)
{
    size_t out_len = len;

    if (!b58tobin(bytes_out, &out_len, str_in, 0))
        return 0;

    return out_len;
}
