#include "config.h"

#include <wally_core.h>
#include "script_int.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define NUM_ELEMS(a) (sizeof(a) / sizeof(a[0]))

#define B_1(b1)                     { b1,  0,  0,  0,  0,  0 }
#define B_2(b1, b2)                 { b1, b2,  0,  0,  0,  0 }
#define B_3(b1, b2, b3)             { b1, b2, b3,  0,  0,  0 }
#define B_4(b1, b2, b3, b4)         { b1, b2, b3, b4,  0,  0 }
#define B_5(b1, b2, b3, b4, b5)     { b1, b2, b3, b4, b5,  0 }
#define B_6(b1, b2, b3, b4, b5, b6) { b1, b2, b3, b4, b5, b6 }

#ifdef WALLY_EXPORT_ALL
struct scriptint_test {
    int64_t expected;
    unsigned char bytes[6];
    bool is_valid;
    const char* description;
} scriptint_cases[] = {
    /* valid encodings, but rejected by scriptint_from_bytes */
    { 0,           B_1(0x00),                         false, "Must use OP_0 instead" },
    { 1,           B_2(0x01, 0x01),                   false, "Must use OP_1 instead" },
    { 16,          B_2(0x01, 0x10),                   false, "Must use OP_16 instead" },
    { -1,          B_2(0x01, 0x81),                   false, "Negative disallowed (-1)"},
    { -127,        B_2(0x01, 0xff),                   false, "Negative disallowed (-127)" },
    { -128,        B_3(0x02, 0x80, 0x80),             false, "Negative disallowed (-128)" },
    { -255,        B_3(0x02, 0xff, 0x80),             false, "Negative disallowed (-255)" },
    { -32767,      B_3(0x02, 0xff, 0xff),             false, "Negative disallowed (-32767)" },
    { -2147483647, B_5(0x04, 0xff, 0xff, 0xff, 0xff), false, "Negative disallowed (-2147483647)" },
    /* valid */
    { 17,          B_2(0x01, 0x11),                   true,  "Minimum allowed" },
    { 127,         B_2(0x01, 0x7f),                   true,  "Max 1-byte without padding" },
    { 128,         B_3(0x02, 0x80, 0x00),             true,  "Requires trailing 0" },
    { 255,         B_3(0x02, 0xff, 0x00),             true,  "255" },
    { 32767,       B_3(0x02, 0xff, 0x7f),             true,  "Max 2-byte without padding" },
    { 32768,       B_4(0x03, 0x00, 0x80, 0x00),       true,  "Requires trailing 0" },
    { 8388607,     B_4(0x03, 0xff, 0xff, 0x7f),       true,  "Max 3-byte without padding" },
    { 2147483647,  B_5(0x04, 0xff, 0xff, 0xff, 0x7f), true,  "Max allowed value 0xffffffff" },
    /* invalid encodings */
    { 0,           B_2(0x01, 0x00),                   false, "Non-minimal 0" },
    { 0,           B_2(0x01, 0x80),                   false, "Negative 0" },
    { 1,           B_3(0x02, 0x01, 0x00),             false, "Zero padded positive int" },
    { -1,          B_3(0x02, 0x01, 0x80),             false, "Zero padding on negative int" },
    { 127,         B_3(0x02, 0x7f, 0x00),             false, "Trailing 0" },
    { -127,        B_3(0x02, 0x7f, 0x80),             false, "Trailing sign byte" },
    { 0,           B_4(0x03, 0x00, 0x00, 0x00),       false, "Negative Case: Multi-byte redundant zeros" },
    { 0,           B_6(0x05, 0x01, 0x02, 0x03, 0x04,
                       0x05),                         false, ">4 bytes" }
};

static bool test_scriptint_parse(void)
{
    for (size_t i = 0; i < NUM_ELEMS(scriptint_cases); ++i) {
        const struct scriptint_test* test = scriptint_cases + i;
        const size_t len = test->bytes[0] + 1;
        int64_t v;
        int ret = scriptint_from_bytes(test->bytes, len, &v);
        if (!test->is_valid) {
            if (ret != WALLY_EINVAL)
                return false;
        } else {
            if (ret != WALLY_OK || v != test->expected)
                return false;
        }
    }

    return true;
}
#endif

int main(void)
{
    bool tests_ok = true;

#define RUN(t) if (!t()) { printf(#t "() test failed!\n"); tests_ok = false; }

#ifdef WALLY_EXPORT_ALL
    RUN(test_scriptint_parse);
#endif

    return tests_ok ? 0 : 1;
}
