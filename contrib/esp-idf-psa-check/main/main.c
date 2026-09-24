#include <stdio.h>
#include "wally_core.h"
#include "wally_crypto.h"

/* Reference the hashing entry points so that they are linked in */
void app_main(void)
{
    static const unsigned char msg[] = "abc";
    unsigned char h32[32], h64[64];
    int ret = wally_init(0);
    ret |= wally_sha256(msg, 3, h32, sizeof(h32));
    ret |= wally_sha512(msg, 3, h64, sizeof(h64));
    ret |= wally_sha256_midstate(msg, 3, h32, sizeof(h32));
    ret |= wally_hmac_sha512(msg, 3, msg, 3, h64, sizeof(h64));
    ret |= wally_bip340_tagged_hash(msg, 3, "TapLeaf", h32, sizeof(h32));
    ret |= wally_pbkdf2_hmac_sha512(msg, 3, msg, 3, 0, 2, h64, sizeof(h64));
    printf("wally psa check ret=%d %02x%02x\n", ret, h32[0], h32[1]);
}
