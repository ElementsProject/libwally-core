#include <wally_transaction.h>

static void test_tx_from_bytes(const uint8_t *data, size_t size, uint32_t flags)
{
    struct wally_tx *tx = NULL;
    int ret;

    ret = wally_tx_from_bytes(data, size, flags, &tx);
    if (tx) {
        if (ret == WALLY_OK &&
            (flags == WALLY_TX_FLAG_USE_WITNESS ||
             flags == (WALLY_TX_FLAG_USE_WITNESS|WALLY_TX_FLAG_USE_ELEMENTS))) {
            /* Parsing succeeded: try to serialize it back to bytes */
            size_t len = 0, written = 0;
            ret = wally_tx_get_length(tx, flags, &len);
            if (ret == WALLY_OK && len) {
                unsigned char *bytes = malloc(len);
                if (bytes) {
                    wally_tx_to_bytes(tx, flags, bytes, len, &written);
                    free(bytes);
                }
            }
        }
        wally_tx_free(tx);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint32_t flags[6] = {
        0,
        WALLY_TX_FLAG_USE_WITNESS,
        WALLY_TX_FLAG_USE_ELEMENTS,
        WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_USE_ELEMENTS,
        WALLY_TX_FLAG_ALLOW_PARTIAL,
        WALLY_TX_FLAG_PRE_BIP144
    };

    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
        test_tx_from_bytes(data, size, flags[i]);

    return 0;
}
