#include "bip39.h"
#include "mnemonic.h"
#include "wordlist.h"
#include <ccan/crypto/sha256/sha256.h>
#include <string.h>

#include "data/wordlists/chinese_simplified.c"
#include "data/wordlists/chinese_traditional.c"
#include "data/wordlists/english.c"
#include "data/wordlists/french.c"
#include "data/wordlists/italian.c"
#include "data/wordlists/spanish.c"
#include "data/wordlists/japanese.c"


static const struct {
    const char name[4];
    const struct words* words;
} lookup[] = {
    { "en", &en_words}, { "es", &es_words}, { "fr", &fr_words},
    { "it", &it_words}, { "jp", &jp_words}, { "zhs", &zhs_words},
    { "zht", &zht_words},
    /* FIXME: Should 'zh' map to traditional or simplified? */
};

const struct words *bip39_get_wordlist(const char* lang)
{
    if (lang) {
        size_t i;
        for (i = 0; i < sizeof(lookup) / sizeof(lookup[0]); ++i)
            if (!strcmp(lang, lookup[i].name))
                return lookup[i].words;
    }
    return &en_words; /* Fallback to English if not found */
}

char* bip39_mnemonic_from_bytes(const struct words *w, const uint8_t *bytes, size_t len)
{
    /* 128 to 256 bits of entropy require 4-8 bits of checksum */
    uint8_t checksummed_bytes[BIP39_ENTROPY_LEN_256 + sizeof(uint8_t)];
    uint8_t checksum;

    switch (len) {
    case BIP39_ENTROPY_LEN_128:
    case BIP39_ENTROPY_LEN_160:
    case BIP39_ENTROPY_LEN_192:
    case BIP39_ENTROPY_LEN_224:
    case BIP39_ENTROPY_LEN_256:
        break;
    default:
        return NULL;
    }

    {
        struct sha256 tmp;
        sha256(&tmp, bytes, len); /* FIXME: Allow user to provide a SHA256 impl */
        checksum = tmp.u.u8[0];
    }

    memcpy(checksummed_bytes, bytes, len);
    checksummed_bytes[len] = checksum;
    return mnemonic_from_bytes(w, checksummed_bytes, len + 1);
}
