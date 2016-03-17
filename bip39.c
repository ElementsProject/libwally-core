#include "bip39.h"
#include "mnemonic.h"
#include "wordlist.h"
#include <ccan/crypto/sha256/sha256.h>
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
        return 0;
    }

    {
        struct sha256 tmp;
        sha256(&tmp, bytes, len);
        checksum = tmp.u.u8[0];
    }

    memcpy(checksummed_bytes, bytes, len);
    checksummed_bytes[len] = checksum;
    return mnemonic_from_bytes(w, checksummed_bytes, sizeof(checksummed_bytes));
}
