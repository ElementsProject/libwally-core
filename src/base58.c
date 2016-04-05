#include "base58.h"
#include "internal.h"
#include "ccan/ccan/crypto/sha256/sha256.h"

#include "libbase58/base58.c"


static uint32_t base58_checksum(const unsigned char *bytes_in, size_t len)
{
    struct sha256 sha_1, sha_2;
    uint32_t checksum;

    sha256(&sha_1, bytes_in, len);
    sha256(&sha_2, &sha_1, sizeof(sha_1));
    checksum = sha_2.u.u32[0];
    clear_n(2, &sha_1, sizeof(sha_1), &sha_2, sizeof(sha_2));
    return checksum;
}


void base58_string_from_bytes(unsigned char *bytes_in_out, size_t len,
                              uint32_t flags, char **output)
{
    unsigned char *copy = NULL;
    size_t out_len = 0;

    *output = NULL;

    if (flags & (BASE58_FLAG_CHECKSUM_GENERATE | BASE58_FLAG_CHECKSUM_RESERVED)) {
        /* Caller wants a checksum generated and included in the returned string */
        uint32_t checksum;

        if (!(flags & BASE58_FLAG_CHECKSUM_RESERVED)) {
            /* No reserved space, use a temporary buffer */
            if (!(copy = malloc(len + BASE58_CHECKSUM_LEN)))
                return;
            memcpy(copy, bytes_in_out, len);
            bytes_in_out = copy;
            len += BASE58_CHECKSUM_LEN;
        } else if (len < BASE58_CHECKSUM_LEN)
            return;

        checksum = base58_checksum(bytes_in_out, len - BASE58_CHECKSUM_LEN);
        memcpy(bytes_in_out + len - BASE58_CHECKSUM_LEN,
               &checksum, sizeof(checksum));
    }

    b58enc(NULL, &out_len, bytes_in_out, len); /* Find required size */

    if (out_len && (*output = malloc(out_len)))
        b58enc(*output, &out_len, bytes_in_out, len); /* Perform conversion */

    if (copy) {
        clear(copy, len);
        free(copy);
    }
}

size_t base58_string_to_bytes(const char *str_in, uint32_t flags,
                              unsigned char *bytes_out, size_t len)
{
    unsigned char *actual_out;
    size_t out_len = len;

    /* FIXME: Flags */

    if (!b58tobin(bytes_out, &out_len, str_in, 0))
        return 0;

    /* b58tobin leaves the result at the end of bytes_out, so we have to
     * shuffle the data to the start and wipe anything following it.
     * FIXME: This sucks, and won't be fixed upstream, rewrite?
     **/
    actual_out = bytes_out + len - out_len;
    if (actual_out != bytes_out) {
        memmove(bytes_out, actual_out, out_len);
        clear(bytes_out + out_len, len - out_len);
    }
    return out_len;
}
