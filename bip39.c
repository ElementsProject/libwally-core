#include "bip39.h"
#include "mnemonic.h"
#include "wordlist.h"
#include <ccan/crypto/sha256/sha256.h>
#include <string.h>

#include "data/wordlists/english.c"
#include "data/wordlists/french.c"
#include "data/wordlists/italian.c"
#include "data/wordlists/spanish.c"
#include "data/wordlists/japanese.c"


const struct words *bip39_default_wordlist(void)
{
    return &en_words;
}

const struct words *bip39_get_wordlist(const char* lang)
{
    if (!strcmp(lang, "en"))
        return &en_words;
    if (!strcmp(lang, "es"))
        return &es_words;
    if (!strcmp(lang, "fr"))
        return &fr_words;
    if (!strcmp(lang, "it"))
        return &it_words;
    if (!strcmp(lang, "jp"))
        return &jp_words;

    return NULL;
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
