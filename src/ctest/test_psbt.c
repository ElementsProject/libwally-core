#include "config.h"

#include <wally_psbt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <err.h>
#include <ccan/str/hex/hex.h>

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
        struct wally_psbt *psbt;
        char *output;
        unsigned char *bytes;
        size_t len, actual_len;

        if (wally_psbt_from_base64(valid_psbts[i].base64, &psbt) != WALLY_OK) {
            errx(1, "Failed to parse psbt %s", valid_psbts[i].base64);
        }
        if (wally_psbt_to_base64(psbt, &output) != WALLY_OK) {
            errx(1, "Failed to base64 psbt %s", valid_psbts[i].base64);
        }
        if (strcmp(output, valid_psbts[i].base64) != 0) {
            errx(1, "psbt %s turned into %s?", valid_psbts[i].base64, output);
        }
        free(output);

        if (wally_psbt_get_length(psbt, &len) != WALLY_OK) {
            errx(1, "Failed to get pbst %s len", valid_psbts[i].base64);
        }
        bytes = malloc(len);
        if (wally_psbt_to_bytes(psbt, bytes, len, &actual_len) != WALLY_OK) {
            errx(1, "psbt %s could not to_bytes?", valid_psbts[i].base64);
        }
        if (len != actual_len) {
            errx(1, "psbt %s to_bytes to %zu not %zu?", valid_psbts[i].base64,
                 actual_len, len);
        }
        output = malloc(hex_str_size(len));
        hex_encode(bytes, len, output, hex_str_size(len));
        if (strcmp(output, valid_psbts[i].hex) != 0) {
            errx(1, "psbt[%zi] bytes %s not %s", i, output, valid_psbts[i].hex);
        }
        free(bytes);
        free(output);
        wally_psbt_free(psbt);
    }

    return 0;
}
