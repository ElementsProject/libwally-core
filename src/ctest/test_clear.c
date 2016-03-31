#include <wally_bip32.h>

int main(void)
{
    /* Dummy call, just make sure this links OK */
    bip32_key_from_bytes(NULL, 0, BIP32_VER_MAIN_PUBLIC, NULL);
    return 0;
}
