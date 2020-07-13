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
        const char* base64_in = valid_psbts[i].base64;
        struct wally_psbt *psbt;
        char *output;
        unsigned char *bytes;
        size_t len, written;

        if (wally_psbt_from_base64(base64_in, &psbt) != WALLY_OK)
            errx(1, "Failed to parse psbt %s", base64_in);

        if (wally_psbt_to_base64(psbt, &output) != WALLY_OK)
            errx(1, "Failed to base64 psbt %s", base64_in);

        if (strcmp(output, base64_in) != 0)
            errx(1, "psbt %s turned into %s?", base64_in, output);

        wally_free_string(output);

        if (wally_psbt_get_length(psbt, &len) != WALLY_OK)
            errx(1, "Failed to get psbt %s len", base64_in);

        bytes = malloc(len);
        if (wally_psbt_to_bytes(psbt, bytes, len, &written) != WALLY_OK)
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
        wally_psbt_free(psbt);
    }

    return 0;
}
