#include <wally_descriptor.h>
#include <wally_address.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void test_fuzz_descriptor(const char *str, uint32_t network)
{
    struct wally_descriptor *desc = NULL;
    int ret;

    ret = wally_descriptor_parse(str, NULL, network, 0, &desc);
    if (desc) {
        uint32_t features = 0;
        wally_descriptor_get_features(desc, &features);

        /* Canonicalize — must not crash */
        char *canon = NULL;
        wally_descriptor_canonicalize(desc, 0, &canon);
        wally_free_string(canon);

        /* Checksum — must not crash */
        char *chk = NULL;
        wally_descriptor_get_checksum(desc, 0, &chk);
        wally_free_string(chk);

        /* Address derivation for indices 0 and 1 */
        if (ret == WALLY_OK) {
            char *addr = NULL;
            wally_descriptor_to_address(desc, 0, 0, 0, 0, &addr);
            wally_free_string(addr);
            addr = NULL;
            wally_descriptor_to_address(desc, 0, 0, 1, 0, &addr);
            wally_free_string(addr);
        }

        /* If musig() is present, walk participant keys */
        if (features & WALLY_MS_IS_MUSIG) {
            size_t num_keys = 0;
            wally_descriptor_get_num_keys(desc, &num_keys);
            if (num_keys > 16)
                num_keys = 16;
            for (size_t k = 0; k < num_keys; k++) {
                size_t np = 0;
                if (wally_descriptor_get_musig_num_participants(desc, k, &np) == WALLY_OK) {
                    if (np > 16)
                        np = 16;
                    for (size_t p = 0; p < np; p++) {
                        char *pkey = NULL;
                        wally_descriptor_get_musig_participant_key(desc, k, p, &pkey);
                        wally_free_string(pkey);
                    }
                }
            }
        }

        wally_descriptor_free(desc);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Treat input bytes as a NUL-terminated descriptor string */
    char *str = malloc(size + 1);
    if (!str)
        return 0;
    memcpy(str, data, size);
    str[size] = '\0';

    /* Try all four network variants */
    static const uint32_t networks[] = {
        WALLY_NETWORK_NONE,
        WALLY_NETWORK_BITCOIN_MAINNET,
        WALLY_NETWORK_BITCOIN_TESTNET,
        WALLY_NETWORK_BITCOIN_REGTEST,
    };

    for (size_t i = 0; i < sizeof(networks) / sizeof(networks[0]); i++)
        test_fuzz_descriptor(str, networks[i]);

    free(str);
    return 0;
}
