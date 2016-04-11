#include "base58.h"
#include "internal.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/endian/endian.h"
#include <string.h>

/* Temporary stack buffer sizes */
#define BIGNUM_WORDS 128u
#define BIGNUM_BYTES (BIGNUM_WORDS * sizeof(uint32_t))

static const unsigned char base58_to_byte[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* .1234567 */
    0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 89...... */

    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, /* .ABCDEFG */
    0x11, 0x00, 0x12, 0x13, 0x14, 0x15, 0x16, 0x00, /* H.JKLMN. */
    0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, /* PQRSTUVW */
    0x1F, 0x20, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, /* XYZ..... */

    0x00, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, /* .abcdefg */
    0x29, 0x2A, 0x2B, 0x2C, 0x00, 0x2D, 0x2E, 0x2F, /* hijk.mno */
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* pqrstuvx */
    0x38, 0x39, 0x3A, 0x00, 0x00, 0x00, 0x00, 0x00, /* xyz..... */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
};

static const char byte_to_base58[58] = {
    '1', '2', '3', '4', '5', '6', '7', '8',
    '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
    'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y','z'
};

/* Returns -1 on error. If 0 is returned then:
 * *len <= input value - OK, bytes_out contains data.
 * *len > input value - Failed and bytes_out untouched.
 */
static int base58_decode(const char *base58, size_t base58_len,
                         unsigned char *bytes_out, size_t *len)
{
    uint32_t bn_buf[BIGNUM_WORDS];
    uint32_t *bn = bn_buf, *top_word, *bn_p;
    size_t bn_words, ones, cp_len, i;
    unsigned char *cp;

    /* Process leading '1's */
    for (ones = 0; ones < base58_len && base58[ones] == '1'; ++ones)
        ; /* no-op*/

    if (!(base58_len -= ones)) {
        if (bytes_out && ones <= *len)
            memset(bytes_out, 0, ones);
        *len = ones;
        return 0; /* String of all '1's */
    }
    base58 += ones; /* Skip over leading '1's */

    /* Take 6 bits to store each 58 bit number, rounded up to the next byte,
     * then round that up to a uint32_t word boundary. */
    bn_words = ((base58_len * 6 + 7) / 8 + 3) / 4;

    /* Allocate our bignum buffer if it won't fit on the stack */
    if (bn_words > BIGNUM_WORDS)
        if (!(bn = malloc(bn_words * sizeof(*bn))))
            return -1;

    /* Iterate through the characters adding them to our bignum. We keep
     * track of the current top word to avoid iterating over words that
     * we know are zero. */
    top_word = bn + bn_words - 1;
    *top_word = 0;

    for (i = 0; i < base58_len; ++i) {
        unsigned char byte = base58_to_byte[((unsigned char *)base58)[i]];
        if (!byte--) {
            if (bn != bn_buf)
                free(bn);
            return -1; /* Invalid char */
        }

        for (bn_p = bn + bn_words - 1; bn_p >= top_word; --bn_p) {
            uint64_t mult = *bn_p * 58ull + byte;
            *bn_p = mult & 0xffffffff;
            byte = (mult >> 32) & 0xff;
            if (byte && bn_p == top_word) {
                *--top_word = byte; /* Increase bignum size */
                break;
            }
        }
    }

    /* We have our bignum stored from top_word to bn + bn_words - 1. Convert
     * its words to big-endian so we can simply memcpy it to bytes_out. */
    for (bn_p = top_word; bn_p < bn + bn_words; ++bn_p)
        *bn_p = cpu_to_be32(*bn_p); /* No-op on big-endian machines */

    for (cp = (unsigned char *)top_word; !*cp; ++cp)
        ; /* Skip leading zero bytes in our bignum */

    /* Copy the result if it fits, cleanup and return */
    cp_len = (unsigned char *)(bn + bn_words) - cp;

    if (bytes_out && ones + cp_len <= *len) {
        memset(bytes_out, 0, ones);
        memcpy(bytes_out + ones, cp, cp_len);
    }

    clear(cp, cp_len);
    if (bn != bn_buf)
        free(bn);

    *len = ones + cp_len;
    return 0;
}

uint32_t base58_get_checksum(const unsigned char *bytes_in, size_t len)
{
    struct sha256 sha_1, sha_2;
    uint32_t checksum;

    sha256(&sha_1, bytes_in, len);
    sha256(&sha_2, &sha_1, sizeof(sha_1));
    checksum = sha_2.u.u32[0];
    clear_n(2, &sha_1, sizeof(sha_1), &sha_2, sizeof(sha_2));
    return checksum;
}


int base58_from_bytes(unsigned char *bytes_in, size_t len,
                      uint32_t flags, char **output)
{
    uint32_t checksum, *cs_p = NULL;
    unsigned char bn_buf[BIGNUM_BYTES];
    unsigned char *bn = bn_buf, *top_byte, *bn_p;
    size_t bn_bytes, zeros, i, orig_len = len;

    *output = NULL;

    if (flags & ~BASE58_FLAG_CHECKSUM || !len)
        return -1; /* Invalid flags or no input */

    if (flags & BASE58_FLAG_CHECKSUM) {
        checksum = base58_get_checksum(bytes_in, len);
        cs_p = &checksum;
        len += 4;
    }

#define b(n) (n < orig_len ? bytes_in[n] : ((unsigned char *)cs_p)[n - orig_len])

    /* Process leading zeros */
    for (zeros = 0; zeros < len && !b(zeros); ++zeros)
        ; /* no-op*/

    if (zeros == len) {
        *output = malloc(zeros + 1);
        if (!*output)
            return -1;
        memset(*output, '1', zeros);
        (*output)[zeros] = '\0';
        return 0; /* All 0's */
    }

    bn_bytes = (len - zeros) * 138 / 100 + 1; /* log(256)/log(58) rounded up */

    /* Allocate our bignum buffer if it won't fit on the stack */
    if (bn_bytes > BIGNUM_BYTES)
        if (!(bn = malloc(bn_bytes)))
            return -1;

    top_byte = bn + bn_bytes - 1;
    *top_byte = 0;

    for (i = zeros; i < len; ++i)
    {
        uint32_t carry = b(i);
        for (bn_p = bn + bn_bytes - 1; bn_p >= top_byte; --bn_p) {
            carry = *bn_p * 256 + carry;
            *bn_p = carry % 58;
            carry = carry / 58;
            if (carry && bn_p == top_byte)
                *--top_byte = 0; /* Increase bignum size */
        }
    }

    while (!*top_byte)
        ++top_byte; /* Skip leading zero bytes in our bignum */

    /* Copy the result */
    bn_bytes = bn + bn_bytes - top_byte;

    *output = malloc(zeros + bn_bytes + 1);
    if (!*output)
        return -1;
    memset(*output, '1', zeros);
    for (i = 0; i < bn_bytes; ++i)
        (*output)[zeros + i] = byte_to_base58[top_byte[i]];
    (*output)[zeros + bn_bytes] = '\0';

    clear(bn, bn_bytes);
    if (bn != bn_buf)
        free(bn);
    return 0;
}


/* FIXME: return int, take len as pointer */
size_t base58_get_length(const char *str_in)
{
    size_t len = 0;
    if (base58_decode(str_in, strlen(str_in), NULL, &len))
        len = 0;
    return len;
}

/* FIXME: return int, take len as pointer */
size_t base58_to_bytes(const char *str_in, uint32_t flags,
                       unsigned char *bytes_out, size_t len)
{
    size_t out_len = len;

    if (flags & ~BASE58_FLAG_CHECKSUM)
        return 0; /* Invalid flags */

    if (flags & BASE58_FLAG_CHECKSUM && len < BASE58_CHECKSUM_LEN)
        return 0; /* No room for checksum */

    if (base58_decode(str_in, strlen(str_in), bytes_out, &out_len) ||
        out_len > len)
        return 0; /* Invalid chars or not enough space */

    if (flags & BASE58_FLAG_CHECKSUM) {
        size_t offset = out_len - BASE58_CHECKSUM_LEN;
        uint32_t checksum = base58_get_checksum(bytes_out, offset);

        if (memcmp(bytes_out + offset, &checksum, sizeof(checksum))) {
            clear(bytes_out, len);
            return 0; /* Checksum mismatch */
        }

        clear(bytes_out + offset, BASE58_CHECKSUM_LEN);
        out_len -= BASE58_CHECKSUM_LEN;
    }
    return out_len;
}
