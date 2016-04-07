#include <include/wally_bip39.h>
#include <string.h>
#include "internal.h"
#include "mnemonic.h"
#include "wordlist.h"
#include "hmac.h"
#include "pbkdf2.h"
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

void bip39_get_languages(char **output)
{
    *output = strdup("en es fr it jp zhs zht");
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
static size_t len_to_mask(size_t len)
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

static unsigned char bip39_checksum(const unsigned char *bytes_in, size_t len)
{
    struct sha256 sha;
    unsigned char ret;
    sha256(&sha, bytes_in, len); /* FIXME: Allow user to provide a SHA256 impl */
    ret = sha.u.u8[0];
    clear(&sha, sizeof(sha));
    return ret;
}

void bip39_mnemonic_from_bytes(const struct words *w,
                               const unsigned char *bytes_in, size_t len,
                               char **output)
{
    /* 128 to 256 bits of entropy require 4-8 bits of checksum */
    unsigned char checksummed_bytes[BIP39_ENTROPY_LEN_256 + sizeof(unsigned char)];

    *output = NULL;

    w = w ? w : &en_words;

    if (w->bits == 11u && len_to_mask(len)) {
        memcpy(checksummed_bytes, bytes_in, len);
        checksummed_bytes[len] = bip39_checksum(bytes_in, len);;
        *output = mnemonic_from_bytes(w, checksummed_bytes, len + 1);
        clear(checksummed_bytes, sizeof(checksummed_bytes));
    }
}

static bool checksum_ok(const unsigned char *bytes, size_t idx, size_t mask)
{
    /* The checksum is stored after the data to sum */
    return (bytes[idx] & mask) == (bip39_checksum(bytes, idx) & mask);
}

size_t bip39_mnemonic_to_bytes(const struct words *w, const char *mnemonic,
                               unsigned char *bytes_out, size_t len)
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
        return 0;

    tmp_len = mnemonic_to_bytes(w, mnemonic, tmp_bytes, sizeof(tmp_bytes));

    if (!tmp_len-- || len < tmp_len || !(mask = len_to_mask(tmp_len)) ||
        !checksum_ok(tmp_bytes, tmp_len, mask)) {
        clear(tmp_bytes, sizeof(tmp_bytes));
        return 0;
    }

    memcpy(bytes_out, tmp_bytes, tmp_len);
    clear(tmp_bytes, sizeof(tmp_bytes));
    return tmp_len;
}

bool bip39_mnemonic_is_valid(const struct words *w, const char *mnemonic)
{
    unsigned char tmp_bytes[BIP39_ENTROPY_LEN_256 + sizeof(unsigned char)];
    size_t len;
    len = bip39_mnemonic_to_bytes(w, mnemonic, tmp_bytes, sizeof(tmp_bytes));
    clear(tmp_bytes, sizeof(tmp_bytes));
    return len != 0;
}

size_t bip39_mnemonic_to_seed(const char *mnemonic, const char *password,
                              unsigned char *bytes_out, size_t len)
{
    const size_t bip9_cost = 2048u;
    const char *prefix = "mnemonic";
    const size_t prefix_len = strlen(prefix);
    const size_t password_len = password ? strlen(password) : 0;
    const size_t salt_len = prefix_len + password_len + PBKDF2_HMAC_EXTRA_LEN;
    size_t written = 0;
    unsigned char *salt = malloc(salt_len);

    if (!salt || len != BIP39_SEED_LEN_512)
        return 0;

    memcpy(salt, prefix, prefix_len);
    memcpy(salt + prefix_len, password, password_len);

    if (!pbkdf2_hmac_sha512((unsigned char *)mnemonic, strlen(mnemonic),
                            salt, salt_len, PBKDF2_HMAC_FLAG_BLOCK_RESERVED,
                            bip9_cost, bytes_out, len))
        written = BIP39_SEED_LEN_512; /* Succeeded */

    clear(salt, salt_len);
    free(salt);

    return written;
}
