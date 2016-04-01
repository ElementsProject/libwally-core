#include "mnemonic.h"
#include "internal.h"
#include "wordlist.h"
#include <string.h>

#define U8_AT(bytes, pos) (bytes)[(pos) / 8u]
#define U8_MASK(pos) (1u << (7u - (pos) % 8u))

/* Get n'th value (of w->bits length) from bytes */
static size_t extract_index(size_t bits, const unsigned char *bytes_in, size_t n)
{
    size_t pos, end, value;
    for (pos = n * bits, end = pos + bits, value = 0; pos < end; ++pos)
        value = (value << 1u) | !!(U8_AT(bytes_in, pos) & U8_MASK(pos));
    return value;
}

/* Store n'th value (of w->bits length) to bytes
 * Assumes: 1) the bits we are writing to are zero
 *          2) value fits within w->bits
 */
static void store_index(size_t bits, unsigned char *bytes_out, size_t n, size_t value)
{
    size_t i, pos;
    for (pos = n * bits, i = 0; i < bits; ++i, ++pos)
        if (value & (1u << (bits - i - 1u)))
            U8_AT(bytes_out, pos) |= U8_MASK(pos);
}

char *mnemonic_from_bytes(const struct words *w, const unsigned char *bytes_in, size_t len)
{
    size_t total_bits = len * 8u; /* bits in 'bytes' */
    size_t total_mnemonics = total_bits / w->bits; /* Mnemonics in 'bytes' */
    size_t i, str_len = 0;
    char *str;

    /* Compute length of result */
    for (i = 0; i < total_mnemonics; ++i) {
        size_t index = extract_index(w->bits, bytes_in, i);
        size_t mnemonic_len = strlen(w->indices[index]);

        str_len += mnemonic_len + 1; /* +1 for following separator or NUL */
    }

    /* Allocate and fill result */
    if ((str = malloc(str_len))) {
        char *out = str;

        for (i = 0; i < total_mnemonics; ++i) {
            size_t index = extract_index(w->bits, bytes_in, i);
            size_t mnemonic_len = strlen(w->indices[index]);

            memcpy(out, w->indices[index], mnemonic_len);
            out[mnemonic_len] = ' '; /* separator */
            out += mnemonic_len + 1;
        }
        str[str_len - 1] = '\0'; /* Overwrite the last separator with NUL */
    }

    return str;
}

size_t mnemonic_to_bytes(const struct words *w, const char *mnemonic, unsigned char *bytes_out, size_t len)
{
    struct words *mnemonic_w = wordlist_init(mnemonic);
    size_t i;

    if (!mnemonic_w)
        return 0;

    /* FIXME: Check output size */
    memset(bytes_out, 0, len);

    for (i = 0; i < mnemonic_w->len; ++i) {
        size_t index = wordlist_lookup_word(w, mnemonic_w->indices[i]);
        if (!index) {
            wordlist_free(mnemonic_w);
            clear(bytes_out, len);
            return -1;
        }
        store_index(w->bits, bytes_out, i, index - 1);
    }

    wordlist_free(mnemonic_w);
    return (i * w->bits + 7u) / 8u;
}

void mnemonic_free(char *mnemonic)
{
    if (mnemonic) {
        clear(mnemonic, strlen(mnemonic));
        free(mnemonic);
    }
}
