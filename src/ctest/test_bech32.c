#include "config.h"

#include <wally_core.h>
#include <wally_address.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static const char *invalid = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefg";

static bool check_segwit_to_bytes(void)
{
    unsigned char *mem = calloc(90, sizeof(unsigned char));
    size_t written;
    int ret;

    if (!mem)
        return false;

    ret = wally_addr_segwit_to_bytes(invalid, "tb", 0, mem, 90, &written);

    if (ret != WALLY_EINVAL)
        return false;

    free(mem);

    return true;
}

static bool check_segwit_addr(void)
{
    unsigned char *mem = calloc(90, sizeof(unsigned char));
    size_t written;
    int ret;
    bool is_success = true;
    char *output = NULL;
    
    if (!mem)
        return false;

    ret = wally_hex_to_bytes("0014751e76e8199196d454941c45d1b3a323f1433bd6", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 43) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "tb", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", 63) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("0014751e76e8199196d454941c45d1b3a323f1433bd6", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 43) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", 75) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("6002751e", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1sw50qgdz25j", 15) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("5210751e76e8199196d454941c45d1b3a323", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", 37) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "tb", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", 63) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "tb", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", 63) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", 63) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    free(mem);

    return is_success;
}

static bool check_addr_segwit(void)
{
    unsigned char *mem;
    unsigned char *mem2;
    size_t written;
    size_t written2;
    int ret;
    bool is_success = true;

    mem = calloc(90, sizeof(unsigned char));
    if (!mem)
        return false;

    mem2 = calloc(90, sizeof(unsigned char));
    if (!mem2) {
        free(mem);
        return false;
    }

    ret = wally_addr_segwit_to_bytes(
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes("0014751e76e8199196d454941c45d1b3a323f1433bd6", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "tb", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "BC1SW50QGDZ25J",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes("6002751e", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes("5210751e76e8199196d454941c45d1b3a323", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "tb", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "tb", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    free(mem);
    free(mem2);

    return is_success;
}

static bool check_bech32m(void)
{
    unsigned char *mem = calloc(90, sizeof(unsigned char));
    size_t written;
    int ret;
    bool is_success = true;
    size_t ver = 0;

    if (!mem)
        return false;

    ret = wally_decode_bech32("A1LQFN3A", "a", 0, mem, 90, &written, &ver);
    if (ret != WALLY_OK || written != 0 || ver == 0)
        is_success = false;

    ret = wally_decode_bech32("a1lqfn3a", "a", 0, mem, 90, &written, &ver);
    if (ret != WALLY_OK || written != 0 || ver == 0)
        is_success = false;

    ret = wally_decode_bech32(
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1",
            0, mem, 90, &written, &ver);
    if (ret != WALLY_OK || written != 0 || ver == 0)
        is_success = false;

    ret = wally_decode_bech32(
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "abcdef",
            0, mem, 90, &written, &ver);
    if (ret != WALLY_OK || written != 32 || ver == 0)
        is_success = false;

    ret = wally_decode_bech32(
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "1",
            0, mem, 90, &written, &ver);
    if (ret != WALLY_OK || written != 82 || ver == 0)
        is_success = false;

    ret = wally_decode_bech32(
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "split",
            0, mem, 90, &written, &ver);
    if (ret != WALLY_OK || written != 48 || ver == 0)
        is_success = false;

    ret = wally_decode_bech32("?1v759aa", "?", 0, mem, 90, &written, &ver);
    if (ret != WALLY_OK || written != 0 || ver == 0)
        is_success = false;

    char message[20];
    char hrp[2] = {0, 0};
    strncpy(message+1, "1xj0phk", sizeof(message)-1);
    hrp[0] = 0x20;
    message[0] = hrp[0];
    ret = wally_decode_bech32(message, hrp, 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    strncpy(message+1, "1g6xzxy", sizeof(message)-1);
    hrp[0] = 0x7f;
    message[0] = hrp[0];
    ret = wally_decode_bech32(message, hrp, 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    strncpy(message+1, "1vctc34", sizeof(message)-1);
    hrp[0] = 0x80;
    message[0] = hrp[0];
    ret = wally_decode_bech32(message, hrp, 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32(
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1",
        0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("qyrz8wqd2c9m", "", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("1qyrz8wqd2c9m", "", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("y1b0jsk6g", "y", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("lt1igcx5c0", "lt", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("in1muywd", "in", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("mm1crxm3i", "mm", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("au1s5cgom", "au", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("M1VUXWEZ", "m", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("16plkw9", "", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    ret = wally_decode_bech32("1p2gdwpf", "", 0, mem, 90, &written, &ver);
    if (ret != WALLY_EINVAL)
        is_success = false;

    free(mem);

    return is_success;
}

int main(void)
{
    bool tests_ok = true;

    if (!check_segwit_to_bytes()) {
        printf("check_segwit_to_bytes test failed!\n");
        tests_ok = false;
    }
    if (!check_segwit_addr()) {
        printf("check_segwit_addr test failed!\n");
        tests_ok = false;
    }
    if (!check_addr_segwit()) {
        printf("check_addr_segwit test failed!\n");
        tests_ok = false;
    }
    if (!check_bech32m()) {
        printf("check_bech32m test failed!\n");
        tests_ok = false;
    }

    return tests_ok ? 0 : 1;
}
