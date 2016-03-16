#include "mnemonic.h"
#include "wordlist.h"
#include <string.h>

/* Get n'th value (of w->bits length) from bytes */
static size_t extract_index(const struct words *w, const uint8_t *bytes, size_t n)
{
    (void)w;
    (void)bytes;
    (void)n;
    return 0u;
}

char* mnemonic_from_bytes(const struct words *w, const uint8_t *bytes, size_t len)
{
    size_t total_bits = len * 8u; /* bits in 'bytes' */
    size_t total_mnemonics = total_bits / w->bits; /* Mnemonics in 'bytes' */
    size_t i, str_len = 0;
    char *str;

    if (total_bits % w->bits)
        return NULL; /* Not an even number of mnemonics */

    /* Compute length of result */
    for (i = 0; i < total_mnemonics; ++i) {
        size_t index = extract_index(w, bytes, i);
        size_t mnemonic_len = strlen(w->indices[index]);

        str_len += mnemonic_len + 1; /* +1 for following separator or NUL */
    }

    /* Allocate and fill result */
    if ((str = malloc(str_len))) {
        char* out = str;

        for (i = 0; i < total_mnemonics; ++i) {
            size_t index = extract_index(w, bytes, i);
            size_t mnemonic_len = strlen(w->indices[index]);

            memcpy(out, w->indices[index], mnemonic_len);
            out[mnemonic_len] = ' '; /* separator */
            out += mnemonic_len + 1;
        }
        str[str_len - 1] = '\0'; /* Overwrite the last separator with NUL */
    }

    return str;
}
