#include "internal.h"
#include <include/wally_crypto.h>
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"

int wally_ecdh(const unsigned char *pub_key, size_t pub_key_len,
               const unsigned char *bytes, size_t bytes_len,
               unsigned char *bytes_out, size_t len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_pubkey pub;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN ||
        !pubkey_parse(ctx, &pub, pub_key, pub_key_len) ||
        !bytes || bytes_len != EC_PRIVATE_KEY_LEN ||
        !secp256k1_ec_seckey_verify(ctx, bytes) ||
        !bytes_out || len != SHA256_LEN) {
        wally_clear(&pub, sizeof(pub));
        return WALLY_EINVAL;
    }

    if (!secp256k1_ecdh(ctx, bytes_out, &pub, bytes, NULL, NULL)) {
        wally_clear(&pub, sizeof(pub));
        wally_clear(bytes_out, len);
        return WALLY_ERROR;
    }

    wally_clear(&pub, sizeof(pub));
    return WALLY_OK;
}
