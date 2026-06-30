/* Provides scriptint_from_bytes for test_miniscript_decode.
 * This function is internal to the library (hidden in the DSO) so
 * the test binary needs its own copy when compiling miniscript_decode.c. */
#include "config.h"
#include <string.h>
#include "script_int.h"
#include <include/wally_core.h>

int64_t scriptint_from_bytes(const unsigned char *bytes, size_t len, int64_t *value_out)
{
    int64_t mask = 0x80;
    size_t i;

    if (value_out)
        *value_out = 0;

    if (!bytes || len < 1 || len <= bytes[0] || bytes[0] > 4 || !value_out)
        return WALLY_EINVAL;

    for (i = 0; i < bytes[0]; ++i) {
        *value_out |= (int64_t)(bytes[i + 1]) << (8 * i);
        mask <<= 8;
    }

    if (bytes[i] & 0x80) {
        *value_out ^= (mask >> 8);
        *value_out = -*value_out;
    }
    return WALLY_OK;
}
