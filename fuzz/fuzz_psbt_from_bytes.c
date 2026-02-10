#include <wally_psbt.h>

static void test_fuzz_psbt_from_bytes(const uint8_t *data, size_t size, uint32_t flags)
{
    struct wally_psbt *psbt = NULL;
    int ret;

    ret = wally_psbt_from_bytes(data, size, flags, &psbt);
    if (psbt) {
        if (ret == WALLY_OK && flags == WALLY_PSBT_PARSE_FLAG_STRICT) {
            /* Parsing succeeded: try to serialize it back to bytes */
            size_t len = 0, written = 0;
            ret = wally_psbt_get_length(psbt, 0, &len);
            if (ret == WALLY_OK && len) {
                unsigned char *bytes = malloc(len);
                if (bytes) {
                    wally_psbt_to_bytes(psbt, 0, bytes, len, &written);
                    free(bytes);
                }
            }
        }
        wally_psbt_free(psbt);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Test strict parsing */
    test_fuzz_psbt_from_bytes(data, size, WALLY_PSBT_PARSE_FLAG_STRICT);
    /* Test loose parsing */
    test_fuzz_psbt_from_bytes(data, size, WALLY_PSBT_PARSE_FLAG_LOOSE);
    /* Test default flags (no flags) */
    test_fuzz_psbt_from_bytes(data, size, 0);

    return 0;
}
