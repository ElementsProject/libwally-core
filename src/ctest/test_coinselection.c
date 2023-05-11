#include "config.h"

#include <wally_coinselection.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define NUM_ELEMS(a) (sizeof(a) / sizeof(a[0]))
#define MAX_TEST_UTXOS 16

#ifdef BUILD_ELEMENTS
static const struct asset_test {
    const char *name;
    uint64_t values[MAX_TEST_UTXOS];
    size_t num_values;
    uint64_t target;
    size_t attempts;
    uint32_t io_ratio;
    uint32_t expected[MAX_TEST_UTXOS];
    size_t num_expected;
} g_asset_tests[] = {
    {
        "Insufficient",
        { 50, 25, 15, 5 }, 4,
        500, 0xffffffff, 5,
        { 0 }, 0 /* 0 length = no solution found */
    }, {
        "Single exact match: first",
        { 50, 25, 15, 5 }, 4,
        50, 0xffffffff, 5,
        { 0 }, 1
    }, {
        "Single exact match: last",
        { 50, 25, 15, 5 }, 4,
        5, 0xffffffff, 5,
        { 3 }, 1
    }, {
        "Require all",
        { 50, 25, 15, 5 }, 4,
        50 + 25 + 15 + 5, 4 + 1, 5, /* Only N+1 attempts are required */
        { 0, 1, 2, 3 }, 4
    }, {
        "All larger than target",
        { 50, 25, 15, 5 }, 4,
        3, 0xffffffff, 5,
        { 0 }, 1 /* Largest single value is returned */
    }, {
        "Cores hard_test_case(12) io_ratio=4",
        /* 6 input exact match beats the first 2 inputs with io_ratio=4 or
         * greater. Solution is found in 314 attempts.
         */
        { 2049, 2048, 1026, 1024, 516, 512, 264, 256, 144, 128, 96, 64 }, 12,
        2048 + 1024 + 512 + 256 + 128 + 64, 0xffffffff, 4,
        { 1, 3, 5, 7, 9, 11 }, 6
    }, {
        "Cores hard_test_case(12) io_ratio=3",
        /* With io_ratio=3, matches beyond length 5 are not searched once we
         * discover the initial 2 input solution, so the best solution is the
         * first 2 inputs, found in 154 attempts.
         */
        { 2049, 2048, 1026, 1024, 516, 512, 264, 256, 144, 128, 96, 64 }, 12,
        2048 + 1024 + 512 + 256 + 128 + 64, 0xffffffff, 3,
        { 0, 1 }, 2
    }, {
        "Middle and last",
        { 2049, 2048, 1026, 1024, 516, 512, 264, 256, 144, 128, 96, 64 }, 12,
        512 + 64, 0xffffffff, 5,
        { 5, 11 }, 2 /* Found in 48 attempts */
    },
};

static bool test_coinselection_assets(void)
{
    size_t i, n, written;
    uint32_t out[WALLY_CS_MAX_ASSETS];
    int ret;

    for (i = 0; i < NUM_ELEMS(g_asset_tests); ++i) {
        const struct asset_test *test = g_asset_tests + i;
        ret = wally_coinselect_assets(test->values, test->num_values,
                                      test->target, test->attempts,
                                      test->io_ratio, out, sizeof(out),
                                      &written);
        if (ret != WALLY_OK) {
            printf("[%s] test failed!\n", test->name);
            return false;
        }
        if (written != test->num_expected) {
            printf("[%s] test unexpected result size!\n", test->name);
            return false;
        }
        for (n = 0; n < test->num_expected; ++n) {
            if (out[n] != test->expected[n]) {
                printf("[%s] test unexpected result %d(%d != %d)!\n",
                        test->name, (int)n, out[n], test->expected[n]);
                return false;
            }
        }
    }
    return true;
}
#endif /* BUILD_ELEMENTS */

int main(void)
{
    bool tests_ok = true;

#define RUN(t) if (!t()) { printf(#t " test_coinselection() test failed!\n"); tests_ok = false; }

#ifdef BUILD_ELEMENTS
    RUN(test_coinselection_assets);
#endif

    return tests_ok ? 0 : 1;
}
