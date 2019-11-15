#include "config.h"

#include <wally_core.h>
#include <wally_address.h>
#include <wally_crypto.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static const char *elements_bech32 = "ert1qu6ssk77c466kg3x9wd82dqkd9udddykyfykm9k";
static const char *elements_confidential_key = "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800";
static const char *elements_blech32 = "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd";

// OP_HASH160 29b1ec079a9c6a45a4e9ab38c3aa3e0ad3dc61f0 OP_EQUALVERIFY
// 332a30b8b2753e64b1d0ebc951c057f0d9c29992d11118794c0fa1c6d2357ca6
static const char *elements_witness_script = "0020332a30b8b2753e64b1d0ebc951c057f0d9c29992d11118794c0fa1c6d2357ca6";
static const char *elements_script_bech32 = "ert1qxv4rpw9jw5lxfvwsa0y4rszh7rvu9xvj6yg3s72vp7sud5340jnquagp6g";
static const char *elements_script_blech32 = "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqve2xzutyaf7vjcap67f28q90uxec2ve95g3rpu5crapcmfr2l9xl5jzazvcpysz";


static bool check_confidential_addr_from_addr_segwit_pubkey(void)
{
    size_t written = 0;
    unsigned char pub_key[EC_PUBLIC_KEY_LEN];
    char *blech32 = NULL;
    int ret;
    bool is_success = false;

    ret = wally_hex_to_bytes(elements_confidential_key,
                             pub_key, EC_PUBLIC_KEY_LEN, &written);
    if (ret != WALLY_OK)
        return false;

    if (written != EC_PUBLIC_KEY_LEN)
        return false;

    ret = wally_confidential_addr_from_addr_segwit(elements_bech32,
                                                   "ert", "el", pub_key, EC_PUBLIC_KEY_LEN, &blech32);
    if (ret != WALLY_OK)
        return false;

    if (strncmp(blech32, elements_blech32, strlen(elements_blech32) + 1) == 0)
        is_success = true;

    wally_free_string(blech32);
    return is_success;
}

static bool check_confidential_addr_from_addr_segwit_script(void)
{
    size_t written = 0;
    unsigned char pub_key[EC_PUBLIC_KEY_LEN];
    unsigned char witness_script[SHA256_LEN + 2];
    char bech32_address[91];
    char *blech32 = NULL;
    char *bech32 = NULL;
    int ret;
    bool is_success = false;

    ret = wally_hex_to_bytes(elements_confidential_key,
                             pub_key, EC_PUBLIC_KEY_LEN, &written);
    if (ret != WALLY_OK)
        return false;

    if (written != EC_PUBLIC_KEY_LEN)
        return false;

    ret = wally_hex_to_bytes(elements_witness_script,
                             witness_script, SHA256_LEN + 2, &written);
    if (ret != WALLY_OK)
        return false;

    if (written != (SHA256_LEN + 2))
        return false;

    ret = wally_addr_segwit_from_bytes(witness_script, written,
                                       "ert", 0, &bech32);
    if (ret != WALLY_OK)
        return false;

    strcpy(bech32_address, bech32);
    wally_free_string(bech32);

    if (strcmp(bech32_address, elements_script_bech32) != 0)
        return false;

    ret = wally_confidential_addr_from_addr_segwit(bech32_address,
                                                   "ert", "el", pub_key, EC_PUBLIC_KEY_LEN, &blech32);
    if (ret != WALLY_OK)
        return false;

    if (strncmp(blech32, elements_script_blech32, strlen(elements_script_blech32) + 1) == 0)
        is_success = true;

    wally_free_string(blech32);
    return is_success;
}

static bool check_confidential_addr_to_addr_segwit_pubkey(void)
{
    char *bech32 = NULL;
    int ret;
    bool is_success = false;

    ret = wally_confidential_addr_to_addr_segwit(elements_blech32,
                                                 "el", "ert", &bech32);
    if (ret != WALLY_OK)
        return false;

    if (strcmp(bech32, elements_bech32) == 0)
        is_success = true;

    wally_free_string(bech32);
    return is_success;
}

static bool check_confidential_addr_to_addr_segwit_script(void)
{
    char *bech32 = NULL;
    int ret;
    bool is_success = false;

    ret = wally_confidential_addr_to_addr_segwit(elements_script_blech32,
                                                 "el", "ert", &bech32);
    if (ret != WALLY_OK)
        return false;

    if (strcmp(bech32, elements_script_bech32) == 0)
        is_success = true;

    wally_free_string(bech32);
    return is_success;
}

static bool check_confidential_addr_segwit_to_ec_public_key_pubkey(void)
{
    char *pub_key_str = NULL;
    unsigned char pub_key[EC_PUBLIC_KEY_LEN];
    int ret;
    bool is_success = false;

    ret = wally_confidential_addr_segwit_to_ec_public_key(
        elements_blech32, "el", pub_key, EC_PUBLIC_KEY_LEN);
    if (ret != WALLY_OK)
        return false;

    ret = wally_hex_from_bytes(pub_key, EC_PUBLIC_KEY_LEN, &pub_key_str);
    if (ret != WALLY_OK)
        return false;

    if (strcmp(pub_key_str, elements_confidential_key) == 0)
        is_success = true;

    wally_free_string(pub_key_str);
    return is_success;
}

static bool check_confidential_addr_segwit_to_ec_public_key_script(void)
{
    char *pub_key_str = NULL;
    unsigned char pub_key[EC_PUBLIC_KEY_LEN];
    int ret;
    bool is_success = false;

    ret = wally_confidential_addr_segwit_to_ec_public_key(
        elements_script_blech32, "el", pub_key, EC_PUBLIC_KEY_LEN);
    if (ret != WALLY_OK)
        return false;

    ret = wally_hex_from_bytes(pub_key, EC_PUBLIC_KEY_LEN, &pub_key_str);
    if (ret != WALLY_OK)
        return false;

    if (strcmp(pub_key_str, elements_confidential_key) == 0)
        is_success = true;

    wally_free_string(pub_key_str);
    return is_success;
}



int main(void)
{
    bool tests_ok = true;

    if (!check_confidential_addr_from_addr_segwit_pubkey()) {
        printf("check_confidential_addr_from_addr_segwit(pubkey) test failed!\n");
        tests_ok = false;
    }

    if (!check_confidential_addr_from_addr_segwit_script()) {
        printf("check_confidential_addr_from_addr_segwit(script) test failed!\n");
        tests_ok = false;
    }

    if (!check_confidential_addr_to_addr_segwit_pubkey()) {
        printf("check_confidential_addr_to_addr_segwit(pubkey) test failed!\n");
        tests_ok = false;
    }

    if (!check_confidential_addr_to_addr_segwit_script()) {
        printf("check_confidential_addr_to_addr_segwit(script) test failed!\n");
        tests_ok = false;
    }

    if (!check_confidential_addr_segwit_to_ec_public_key_pubkey()) {
        printf("check_confidential_addr_segwit_to_ec_public_key(pubkey) test failed!\n");
        tests_ok = false;
    }

    if (!check_confidential_addr_segwit_to_ec_public_key_script()) {
        printf("check_confidential_addr_segwit_to_ec_public_key(script) test failed!\n");
        tests_ok = false;
    }

    return tests_ok ? 0 : 1;
}
