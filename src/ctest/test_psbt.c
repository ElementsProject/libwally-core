#include "config.h"

#include <wally_psbt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "psbts.h"

/* Ignore test logging compiler warnings */
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif

static void fail(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);
    va_end(args);
    abort();
}

static void change_version(struct wally_psbt* psbt, uint32_t version, const char* base64_in)
{
    int ret = wally_psbt_set_version(psbt, 0, version);
    if (ret != WALLY_OK)
        fail("psbt set version to %u returned %d for %s", version, ret, base64_in);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(invalid_psbts) / sizeof(invalid_psbts[0]); i++) {
        struct wally_psbt *psbt;

        if (wally_psbt_from_base64(invalid_psbts[i].base64, 0, &psbt) != WALLY_OK)
            continue;
        fail("Should have failed to parse psbt %s", invalid_psbts[i].base64);
    }

    for (i = 0; i < sizeof(valid_psbts) / sizeof(valid_psbts[0]); i++) {
        const char *base64_in = valid_psbts[i].base64;
        struct wally_psbt *psbt, *psbt_clone;
        char *output;
        unsigned char *bytes;
        size_t is_elements, len, written;

#ifndef BUILD_ELEMENTS
        if (valid_psbts[i].is_pset)
            continue;
#endif /* ndef BUILD_ELEMENTS */

        if (wally_psbt_from_base64(base64_in, 0, &psbt) != WALLY_OK)
            fail("Failed to parse psbt %s", base64_in);

        if (wally_psbt_to_base64(psbt, 0, &output) != WALLY_OK)
            fail("Failed to base64 psbt %s", base64_in);

        if (valid_psbts[i].can_round_trip) {
            if (strcmp(output, base64_in) != 0)
                fail("psbt %s turned into %s?", base64_in, output);
        }

        wally_free_string(output);

        if (wally_psbt_get_length(psbt, 0, &len) != WALLY_OK)
            fail("Failed to get psbt %s len", base64_in);

        bytes = malloc(len);
        if (wally_psbt_to_bytes(psbt, 0, bytes, len, &written) != WALLY_OK)
            fail("psbt %s could not to_bytes?", base64_in);

        if (len != written)
            fail("psbt %s to_bytes to %zu not %zu?", base64_in, written, len);

        if (wally_base64_from_bytes(bytes, len, 0, &output) != WALLY_OK)
            fail("Failed to convert psbt bytes to base64");

        if (valid_psbts[i].can_round_trip) {
            if (strcmp(output, base64_in) != 0)
                fail("psbt[%zi] base64 %s not %s", i, output, base64_in);
        }

        wally_free_string(output);
        output = NULL;
        free(bytes);

        /* combining with a copy of ourselves should be a no-op */
        if (wally_psbt_from_base64(base64_in, 0, &psbt_clone) != WALLY_OK)
            fail("Failed to parse psbt clone %s", base64_in);

        if (wally_psbt_is_elements(psbt_clone, &is_elements) != WALLY_OK)
            fail("Failed to check PSET status %s", base64_in);

        if (!is_elements) {
            /* FIXME: combine for elements */
            if (wally_psbt_combine(psbt_clone, psbt) != WALLY_OK)
                fail("Failed to combine psbts %s", base64_in);

            if (wally_psbt_to_base64(psbt_clone, 0, &output) != WALLY_OK)
                fail("Failed to base64 psbt combined %s", base64_in);

            if (valid_psbts[i].can_round_trip) {
                if (strcmp(output, base64_in) != 0)
                    fail("psbt combine %s turned into %s?", base64_in, output);
            }
        }

        wally_free_string(output);
        wally_psbt_free(psbt_clone);

        /* Clone should return an identical copy */
        if (wally_psbt_clone_alloc(psbt, 0, &psbt_clone) != WALLY_OK)
            fail("Failed to clone psbts %s", base64_in);

        if (wally_psbt_to_base64(psbt_clone, 0, &output) != WALLY_OK)
            fail("Failed to base64 psbt clone %s", base64_in);

        if (valid_psbts[i].can_round_trip) {
            if (strcmp(output, base64_in) != 0)
                fail("psbt clone %s turned into %s?", base64_in, output);
        }

        wally_free_string(output);

        /* Round-trip psbts through versions */
        if (is_elements) {
            /* Only PSETv2 is supported, so skip round-tripping */
        } else if (psbt->version == WALLY_PSBT_VERSION_0) {
            /* V0 -> V2 -> V0 */
            /* We have to save and restore the tx version as v1 txs
             * are upgraded to v2 when the PSBT is upgraded */
            uint32_t tx_version = psbt_clone->tx->version;
            change_version(psbt_clone, WALLY_PSBT_VERSION_2, base64_in);
            change_version(psbt_clone, WALLY_PSBT_VERSION_0, base64_in);
            psbt_clone->tx->version = tx_version;
        } else if (psbt->version == WALLY_PSBT_VERSION_2) {
            /* V2 -> V0 -> V2 */
            bool has_per_input_lock = false;
            for (size_t j = 0; !has_per_input_lock && j < psbt->num_inputs; ++j) {
                has_per_input_lock |= psbt->inputs[j].required_locktime != 0;
                has_per_input_lock |= psbt->inputs[j].required_lockheight != 0;
            }
            if (has_per_input_lock) {
                /* Round-tripping loses per-input timelock information, so
                 * skip round-tripping in this case */
            } else {
                change_version(psbt_clone, WALLY_PSBT_VERSION_0, base64_in);
                change_version(psbt_clone, WALLY_PSBT_VERSION_2, base64_in);
                if (psbt->has_fallback_locktime && psbt->fallback_locktime == 0) {
                    /* Its possible to redundantly set the fallback locktime
                     * to its default value of zero. In this case the
                     * roundtripped psbt will not have a fallback locktime,
                     * so set it here to allow the check below to pass */
                    psbt_clone->has_fallback_locktime = true;
                }
                /* Tx modifiable flags are not round-tripped, since v0 has
                 * no concept of non-modifiability */
                psbt_clone->tx_modifiable_flags = psbt->tx_modifiable_flags;
            }
        } else {
            fail("Unknown psbt version %d in %s", psbt->version, base64_in);
        }

        /* Still should match */
        if (wally_psbt_to_base64(psbt_clone, 0, &output) != WALLY_OK)
            fail("Failed to base64 psbt clone %s", base64_in);

        if (valid_psbts[i].can_round_trip) {
            if (strcmp(output, base64_in) != 0)
                fail("psbt clone %s turned into %s?", base64_in, output);
        }

        wally_free_string(output);
        wally_psbt_free(psbt_clone);
        wally_psbt_free(psbt);
    }

    wally_cleanup(0);
    return 0;
}
