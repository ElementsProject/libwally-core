#include "config.h"

#include <wally_core.h>
#include <wally_address.h>
#include <wally_crypto.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

struct wally_blech32_test {
    const char *address;
    const char *addr_family;
    const char *confidential_key;
    const char *confidential_address;
    const char *confidential_addr_family;
};

/*
pk=02409b4d18429c6e5cbc0bd59c63b8fe7055f603190c8deed6a644bc95c9772e48
script=OP_HASH160 dc4af3ea14b0592621514e2bd4a0e083c7fac2f2 OP_EQUALVERIFY
  -> a914dc4af3ea14b0592621514e2bd4a0e083c7fac2f288
tr hash=409b4d18429c6e5cbc0bd59c63b8fe7055f603190c8deed6a644bc95c9772e48
*/

static struct wally_blech32_test g_blech32_test_table[] = {
    {   /* p2wpkh testnet */
        "ert1qm39086s5kpvjvg23fc4afg8qs0rl4shjygphsr",
        "ert",
        "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800",
        "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqphz2704pfvzeycs4zn3t6jswpq78ltp0yd23jxpdekpau",
        "el"
    },
    {   /* p2wsh testnet */
        "ert1qgs3lcwxkawtwvmrhrdww65m2vvmkl9367t54xh990dpmc09mehqs89mfu7",
        "ert",
        "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800",
        "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqq3prlsudd6ukuek8wx6ua4fk5cehd7tr4uhf2dw2276rhs7thnwpxqzalk28qxgj",
        "el"
    },
    {   /* p2wpkh liquidv1 */
        "ex1qm39086s5kpvjvg23fc4afg8qs0rl4shj76t00e",
        "ex",
        "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800",
        "lq1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqphz2704pfvzeycs4zn3t6jswpq78ltp0yxz3p90nf3npx",
        "lq"
    },
    {   /* p2wsh liquidv1 */
        "ex1qgs3lcwxkawtwvmrhrdww65m2vvmkl9367t54xh990dpmc09mehqssgyt6f",
        "ex",
        "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800",
        "lq1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqq3prlsudd6ukuek8wx6ua4fk5cehd7tr4uhf2dw2276rhs7thnwp0vuhrqfhrklz",
        "lq"
    },
    {   /* p2tr testnet */
        "ert1pgzd56xzzn3h9e0qt6kwx8w87wp2lvqcepjx7a44xgj7ftjth9eyq0lx3wm",
        "ert",
        "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800",
        "el1pqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqsymf5vy98rwtj7qh4vuvwu0uuz47cp3jrydamt2v39ujhyhwtjgyxxut0a8e8ju",
        "el"
    },
    {   /* p2tr liquidv1 */
        "ex1pgzd56xzzn3h9e0qt6kwx8w87wp2lvqcepjx7a44xgj7ftjth9eyqcjengv",
        "ex",
        "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800",
        "lq1pqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqsymf5vy98rwtj7qh4vuvwu0uuz47cp3jrydamt2v39ujhyhwtjgd2ckhe7h6h9v",
        "lq"
    },
};

static bool check_confidential_addr_from_addr_segwit(
    const char *address,
    const char *addr_family,
    const char *confidential_addr_family,
    const char *confidential_key,
    const char *expect_confidential_address)
{
    size_t written = 0;
    unsigned char pub_key[EC_PUBLIC_KEY_LEN];
    char *blech32 = NULL;
    int ret;
    bool is_success = false;

    ret = wally_hex_to_bytes(confidential_key,
                             pub_key, EC_PUBLIC_KEY_LEN, &written);
    if (ret != WALLY_OK)
        return false;

    if (written != EC_PUBLIC_KEY_LEN)
        return false;

    ret = wally_confidential_addr_from_addr_segwit(
        address, addr_family, confidential_addr_family, pub_key, EC_PUBLIC_KEY_LEN, &blech32);
    if (ret != WALLY_OK)
        return false;

    if (strncmp(blech32, expect_confidential_address, strlen(expect_confidential_address) + 1) == 0)
        is_success = true;

    wally_free_string(blech32);
    return is_success;
}

static bool check_confidential_addr_to_addr_segwit(
    const char *address,
    const char *confidential_addr_family,
    const char *addr_family,
    const char *expect_address)
{
    char *bech32 = NULL;
    int ret;
    bool is_success = false;

    ret = wally_confidential_addr_to_addr_segwit(
        address, confidential_addr_family, addr_family, &bech32);
    if (ret != WALLY_OK)
        return false;

    if (strcmp(bech32, expect_address) == 0)
        is_success = true;

    wally_free_string(bech32);
    return is_success;
}

static bool check_confidential_addr_segwit_to_ec_public_key(
    const char *address,
    const char *confidential_addr_family,
    const char *expect_confidential_key)
{
    char *pub_key_str = NULL;
    unsigned char pub_key[EC_PUBLIC_KEY_LEN];
    int ret;
    bool is_success = false;

    ret = wally_confidential_addr_segwit_to_ec_public_key(
        address, confidential_addr_family, pub_key, EC_PUBLIC_KEY_LEN);
    if (ret != WALLY_OK)
        return false;

    ret = wally_hex_from_bytes(pub_key, EC_PUBLIC_KEY_LEN, &pub_key_str);
    if (ret != WALLY_OK)
        return false;

    if (strcmp(pub_key_str, expect_confidential_key) == 0)
        is_success = true;

    wally_free_string(pub_key_str);
    return is_success;
}

int main(void)
{
    bool tests_ok = true;
    size_t max = sizeof(g_blech32_test_table) / sizeof(struct wally_blech32_test);

    for (size_t idx = 0; idx < max; ++idx) {
        if (!check_confidential_addr_from_addr_segwit(
            g_blech32_test_table[idx].address,
            g_blech32_test_table[idx].addr_family,
            g_blech32_test_table[idx].confidential_addr_family,
            g_blech32_test_table[idx].confidential_key,
            g_blech32_test_table[idx].confidential_address)) {
            printf("check_confidential_addr_from_addr_segwit test failed!(%zu)\n", idx);
            tests_ok = false;
        }

        if (!check_confidential_addr_to_addr_segwit(
            g_blech32_test_table[idx].confidential_address,
            g_blech32_test_table[idx].confidential_addr_family,
            g_blech32_test_table[idx].addr_family,
            g_blech32_test_table[idx].address)) {
            printf("check_confidential_addr_to_addr_segwit test failed!(%zu)\n", idx);
            tests_ok = false;
        }

        if (!check_confidential_addr_segwit_to_ec_public_key(
            g_blech32_test_table[idx].confidential_address,
            g_blech32_test_table[idx].confidential_addr_family,
            g_blech32_test_table[idx].confidential_key)) {
            printf("check_confidential_addr_segwit_to_ec_public_key test failed!(%zu)\n", idx);
            tests_ok = false;
        }
    }

    return tests_ok ? 0 : 1;
}
