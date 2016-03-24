#include <include/wally_bip39.h>
#include <string.h>
#include "mnemonic.h"
#include "wordlist.h"
#include "hmac.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"

#include "data/wordlists/chinese_simplified.c"
#include "data/wordlists/chinese_traditional.c"
#include "data/wordlists/english.c"
#include "data/wordlists/french.c"
#include "data/wordlists/italian.c"
#include "data/wordlists/spanish.c"
#include "data/wordlists/japanese.c"


static const struct {
    const char name[4];
    const struct words *words;
} lookup[] = {
    { "en", &en_words}, { "es", &es_words}, { "fr", &fr_words},
    { "it", &it_words}, { "jp", &jp_words}, { "zhs", &zhs_words},
    { "zht", &zht_words},
    /* FIXME: Should 'zh' map to traditional or simplified? */
};

const char *bip39_get_languages()
{
    return "en es fr it jp zhs zht";
}

const struct words *bip39_get_wordlist(const char *lang)
{
    if (lang) {
        size_t i;
        for (i = 0; i < sizeof(lookup) / sizeof(lookup[0]); ++i)
            if (!strcmp(lang, lookup[i].name))
                return lookup[i].words;
    }
    return &en_words; /* Fallback to English if not found */
}

/* Convert an input entropy length to a mask for checksum bits. As it
 * returns 0 for bad lengths, it serves as a validation function too.
 */
static size_t entropy_len_to_mask(size_t len)
{
    switch (len) {
    case BIP39_ENTROPY_LEN_128: return 0xf0;
    case BIP39_ENTROPY_LEN_160: return 0xf8;
    case BIP39_ENTROPY_LEN_192: return 0xfc;
    case BIP39_ENTROPY_LEN_224: return 0xfe;
    case BIP39_ENTROPY_LEN_256: return 0xff;
    }
    return 0;
}

static unsigned char bip39_checksum(const unsigned char *bytes, size_t len)
{
    struct sha256 tmp;
    sha256(&tmp, bytes, len); /* FIXME: Allow user to provide a SHA256 impl */
    return tmp.u.u8[0];
}

char *bip39_mnemonic_from_bytes(const struct words *w, const unsigned char *bytes, size_t len)
{
    /* 128 to 256 bits of entropy require 4-8 bits of checksum */
    unsigned char checksummed_bytes[BIP39_ENTROPY_LEN_256 + sizeof(unsigned char)];

    w = w ? w : &en_words;

    if (w->bits != 11u || !entropy_len_to_mask(len))
        return NULL;

    memcpy(checksummed_bytes, bytes, len);
    checksummed_bytes[len] = bip39_checksum(bytes, len);;
    return mnemonic_from_bytes(w, checksummed_bytes, len + 1);
}

size_t bip39_mnemonic_to_bytes(const struct words *w, const char *mnemonic,
                               unsigned char *bytes, size_t len)
{
    unsigned char tmp_bytes[BIP39_ENTROPY_LEN_256 + sizeof(unsigned char)];
    size_t mask, tmp_len;

    /* Ideally we would infer the wordlist here. Unfortunately this cannot
     * work reliably because the default word lists overlap. In combination
     * with being sorted lexographically, this means the default lists
     * were poorly chosen. But we are stuck with them now.
     *
     * If the caller doesn't know which word list to use, they should iterate
     * over the available ones and try any resulting list that the mnemonic
     * validates against.
     */
    w = w ? w : &en_words;

    if (w->bits != 11u)
        return false;

    tmp_len = mnemonic_to_bytes(w, mnemonic, tmp_bytes, sizeof(tmp_bytes));

    if (!tmp_len || len < tmp_len - 1 ||
        !(mask = entropy_len_to_mask(tmp_len - 1)))
        return 0;

    if ((tmp_bytes[tmp_len - 1] & mask) !=
        (bip39_checksum(tmp_bytes, tmp_len - 1) & mask))
        return 0; /* Mismatched checksum */

    memcpy(bytes, tmp_bytes, tmp_len - 1);
    return tmp_len - 1;
}

bool bip39_mnemonic_is_valid(const struct words *w, const char *mnemonic)
{
    unsigned char bytes[BIP39_ENTROPY_LEN_256 + sizeof(unsigned char)];
    return bip39_mnemonic_to_bytes(w, mnemonic, bytes, sizeof(bytes)) != 0;
}

#define SALT_BYTES 4u /* Extra bytes for salt */

/*
 * This is a heavily modified version of openBSDs pkcs5_pbkdf2 from
 * libutil/pkcs5_pbkdf2.c, whose copyright appears here:
 *
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */
static void pbkdf2_hmac_sha512(const unsigned char *pass, size_t pass_len,
                               unsigned char *salt, size_t salt_len,
                               unsigned char *key, size_t key_len)
{
    struct sha512 obuf, d1, d2;
    size_t count, i, j, r;

    for (count = 1; key_len != 0; ++count) {
        salt[salt_len + 0] = (count >> 24) & 0xff;
        salt[salt_len + 1] = (count >> 16) & 0xff;
        salt[salt_len + 2] = (count >> 8) & 0xff;
        salt[salt_len + 3] = count & 0xff;

        hmac_sha512(&d1, pass, pass_len, salt, salt_len + SALT_BYTES);
        obuf = d1;

        for (i = 1; i < 2048u; ++i) {
            hmac_sha512(&d2, pass, pass_len, d1.u.u8, sizeof(d1));
            d1 = d2;
            for (j = 0; j < sizeof(obuf); ++j)
                obuf.u.u8[j] ^= d1.u.u8[j];
        }

        r = key_len < sizeof(obuf) ? key_len : sizeof(obuf);
        memcpy(key, obuf.u.u8, r);
        key += r;
        key_len -= r;
    }
}

int bip39_mnemonic_to_seed(unsigned char *output,
                           const char *mnemonic, const char *password)
{
    const char *prefix = "mnemonic";
    const size_t prefix_len = strlen(prefix);
    const size_t password_len = password ? strlen(password) : 0;
    const size_t salt_len = prefix_len + password_len;
    unsigned char *salt = malloc(salt_len + SALT_BYTES);

    if (!salt)
        return -1;

    memcpy(salt, prefix, prefix_len);
    memcpy(salt + prefix_len, password, password_len);

    pbkdf2_hmac_sha512((unsigned char *)mnemonic, strlen(mnemonic),
                       salt, salt_len, output, BIP39_SEED_LEN_512);
    free(salt);
    return 0;
}
