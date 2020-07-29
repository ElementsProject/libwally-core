#include "config.h"

#include <wally_psbt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

#include "psbts.h"

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(invalid_psbts) / sizeof(invalid_psbts[0]); i++) {
        struct wally_psbt *psbt;

        if (wally_psbt_from_base64(invalid_psbts[i].base64, &psbt) != WALLY_OK)
            continue;
        errx(1, "Should have failed to parse psbt %s", invalid_psbts[i].base64);
    }

    for (i = 0; i < sizeof(valid_psbts) / sizeof(valid_psbts[0]); i++) {
        const char *base64_in = valid_psbts[i].base64;
        struct wally_psbt *psbt, *psbt_clone;
        char *output;
        unsigned char *bytes;
        size_t len, written;

        if (wally_psbt_from_base64(base64_in, &psbt) != WALLY_OK)
            errx(1, "Failed to parse psbt %s", base64_in);

        if (wally_psbt_to_base64(psbt, 0, &output) != WALLY_OK)
            errx(1, "Failed to base64 psbt %s", base64_in);

        if (strcmp(output, base64_in) != 0)
            errx(1, "psbt %s turned into %s?", base64_in, output);

        wally_free_string(output);

        if (wally_psbt_get_length(psbt, 0, &len) != WALLY_OK)
            errx(1, "Failed to get psbt %s len", base64_in);

        bytes = malloc(len);
        if (wally_psbt_to_bytes(psbt, 0, bytes, len, &written) != WALLY_OK)
            errx(1, "psbt %s could not to_bytes?", base64_in);

        if (len != written) {
            errx(1, "psbt %s to_bytes to %zu not %zu?", base64_in,
                 written, len);
        }

        if (wally_hex_from_bytes(bytes, len, &output) != WALLY_OK)
            errx(1, "Failed to convert psbt bytes to hex");

        if (strcmp(output, valid_psbts[i].hex) != 0)
            errx(1, "psbt[%zi] bytes %s not %s", i, output, valid_psbts[i].hex);

        wally_free_string(output);
        free(bytes);

        /* combining with a copy of ourselves should be a no-op */
        if (wally_psbt_from_base64(base64_in, &psbt_clone) != WALLY_OK)
            errx(1, "Failed to parse psbt clone %s", base64_in);

        if (wally_psbt_combine(psbt_clone, psbt) != WALLY_OK)
            errx(1, "Failed to combine psbts %s", base64_in);

        if (wally_psbt_to_base64(psbt_clone, 0, &output) != WALLY_OK)
            errx(1, "Failed to base64 psbt combined %s", base64_in);

        if (strcmp(output, base64_in) != 0)
            errx(1, "psbt combine %s turned into %s?", base64_in, output);

        wally_free_string(output);
        wally_psbt_free(psbt_clone);

        /* Clone should return an identical copy */
        if (wally_psbt_clone_alloc(psbt, 0, &psbt_clone) != WALLY_OK)
            errx(1, "Failed to clone psbts %s", base64_in);

        if (wally_psbt_to_base64(psbt_clone, 0, &output) != WALLY_OK)
            errx(1, "Failed to base64 psbt clone %s", base64_in);

        if (strcmp(output, base64_in) != 0)
            errx(1, "psbt clone %s turned into %s?", base64_in, output);

        wally_free_string(output);
        wally_psbt_free(psbt_clone);
        wally_psbt_free(psbt);
    }

    wally_cleanup(0);
    return 0;
}
