#include "bip39.h"
#include "mnemonic.h"
#include "wordlist.h"
#include <string.h>

#include "data/wordlists/english.c"

const struct words *bip39_default_wordlist(void)
{
    return &en_words;
}

const struct words *bip39_get_wordlist(const char* lang)
{
    if (!strcmp(lang, "en"))
        return &en_words;

    return 0;
}

char* bip39_mnemonic_from_bytes(const struct words *w, const uint8_t *bytes, size_t len)
{
    switch (len) {
    case BIP39_ENTROPY_LEN_128:
    case BIP39_ENTROPY_LEN_160:
    case BIP39_ENTROPY_LEN_192:
    case BIP39_ENTROPY_LEN_224:
    case BIP39_ENTROPY_LEN_256:
        break;
    default:
        return 0;
    }

    /* FIXME */
    (void)w;
    (void)bytes;
    return 0;
}
