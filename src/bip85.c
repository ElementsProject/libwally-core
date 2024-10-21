#include "internal.h"
#include <include/wally_bip32.h>
#include <include/wally_bip39.h>
#include <include/wally_bip85.h>
#include <include/wally_crypto.h>

/* Bip85 path element values */
#define BIP85_PURPOSE  (BIP32_INITIAL_HARDENED_CHILD | 83696968)
#define BIP85_APPLICATION_39 (BIP32_INITIAL_HARDENED_CHILD | 39)
#define BIP85_APPLICATION_RSA (BIP32_INITIAL_HARDENED_CHILD | 828365)

#define BIP85_ENTROPY_HMAC_KEY_LEN 18
static const uint8_t BIP85_ENTROPY_HMAC_KEY[BIP85_ENTROPY_HMAC_KEY_LEN]
    = { 'b', 'i', 'p', '-', 'e', 'n', 't', 'r', 'o', 'p', 'y', '-', 'f', 'r', 'o', 'm', '-', 'k' };

/* Bip85 specifies a language code from 0' to 8' - so order here is important */
static const char *bip85_langs[] = { "en", "jp", "kr", "es", "zhs", "zht", "fr", "it", "cz" };


static size_t get_entropy_len(uint32_t num_words)
{
    switch (num_words) {
    case 12:
        return BIP39_ENTROPY_LEN_128;
    case 18:
        return BIP39_ENTROPY_LEN_192;
    case 24:
        return BIP39_ENTROPY_LEN_256;
    default:
        return 0; /* Only 12, 18 and 24 words supported */
    }
}

int bip85_get_languages(char **output)
{
    if (!output)
        return WALLY_EINVAL;
    *output = wally_strdup("en jp kr es zhs zht fr it cz");
    return *output ? WALLY_OK : WALLY_ENOMEM;
}

int bip85_get_bip39_entropy(const struct ext_key *hdkey,
                            const char *lang, uint32_t num_words, uint32_t index,
                            unsigned char* bytes_out, size_t len,
                            size_t* written)
{
    struct ext_key derived;
    uint32_t path[5]; /* PURPOSE_BIP85 / APP_39 / land_idx / num_words / index */
    uint32_t lang_idx = 0; /* 0=English */
    const size_t entropy_len = get_entropy_len(num_words);
    int ret;

    if (written)
        *written = 0;

    if (!hdkey || !entropy_len || index & BIP32_INITIAL_HARDENED_CHILD ||
        !bytes_out || len != HMAC_SHA512_LEN || !written)
        return WALLY_EINVAL;

    if (lang) {
        /* Lookup the callers language */
        size_t i;
        for (i = 0; i < NUM_ELEMS(bip85_langs); ++i) {
            if (!strcmp(lang, bip85_langs[i])) {
                lang_idx = i;
                break;
            }
        }
        if (i == NUM_ELEMS(bip85_langs))
            return WALLY_EINVAL; /* Language not found */
    }

    /* Derive a private key from the bip85 path for bip39 mnemonic entropy */
    path[0] = BIP85_PURPOSE;
    path[1] = BIP85_APPLICATION_39;
    path[2] = lang_idx | BIP32_INITIAL_HARDENED_CHILD;
    path[3] = num_words | BIP32_INITIAL_HARDENED_CHILD;
    path[4] = index | BIP32_INITIAL_HARDENED_CHILD;
    ret = bip32_key_from_parent_path(hdkey, path, NUM_ELEMS(path),
                                     BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH,
                                     &derived);

    if (ret == WALLY_OK) {
        /* HMAC-SHA512 the derived private key with the fixed bip85 key
         * Write result directly into output buffer - 'written' indicates
         * how much should be used. */
        ret = wally_hmac_sha512(BIP85_ENTROPY_HMAC_KEY, BIP85_ENTROPY_HMAC_KEY_LEN,
                                derived.priv_key + 1, sizeof(derived.priv_key) - 1,
                                bytes_out, len);
        if (ret == WALLY_OK)
            *written = entropy_len;
    }
    wally_clear(&derived, sizeof(derived));
    return ret;
}

int bip85_get_rsa_entropy(const struct ext_key *hdkey, uint32_t key_bits, uint32_t index,
                          unsigned char *bytes_out, size_t len, size_t *written)
{
    struct ext_key derived;
    uint32_t path[4]; /* PURPOSE_BIP85 / APP_RSA / key_bits / index */
    int ret;

    if (written)
        *written = 0;

    if (!hdkey || key_bits & BIP32_INITIAL_HARDENED_CHILD || index & BIP32_INITIAL_HARDENED_CHILD || !bytes_out
        || len != HMAC_SHA512_LEN || !written)
        return WALLY_EINVAL;

    /* Derive a private key from the bip85 path for bip39 mnemonic entropy */
    path[0] = BIP85_PURPOSE;
    path[1] = BIP85_APPLICATION_RSA;
    path[2] = key_bits | BIP32_INITIAL_HARDENED_CHILD;
    path[3] = index | BIP32_INITIAL_HARDENED_CHILD;
    ret = bip32_key_from_parent_path(hdkey, path, NUM_ELEMS(path),
                                     BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH,
                                     &derived);

    if (ret == WALLY_OK) {
        /* HMAC-SHA512 the derived private key with the fixed bip85 key
         * Write result directly into output buffer - 'written' indicates
         * how much should be used. */
        ret = wally_hmac_sha512(BIP85_ENTROPY_HMAC_KEY, BIP85_ENTROPY_HMAC_KEY_LEN, derived.priv_key + 1,
                                sizeof(derived.priv_key) - 1, bytes_out, len);
        if (ret == WALLY_OK)
            *written = len;
    }
    wally_clear(&derived, sizeof(derived));
    return ret;
}
