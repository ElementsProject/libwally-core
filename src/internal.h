#ifndef LIBWALLY_INTERNAL_H
#define LIBWALLY_INTERNAL_H

#include <include/wally_core.h>
#include "secp256k1/include/secp256k1.h"
#include <config.h>

/* Fetch an internal secp context */
const secp256k1_context *secp_ctx(void);
#define secp256k1_context_destroy(c) _do_not_destroy_shared_ctx_pointers(c)

#define pubkey_create     secp256k1_ec_pubkey_create
#define pubkey_parse      secp256k1_ec_pubkey_parse
#define pubkey_tweak_add  secp256k1_ec_pubkey_tweak_add
#define pubkey_serialize  secp256k1_ec_pubkey_serialize
#define privkey_tweak_add secp256k1_ec_privkey_tweak_add

#define PUBKEY_COMPRESSED   SECP256K1_EC_COMPRESSED
#define PUBKEY_UNCOMPRESSED SECP256K1_EC_UNCOMPRESSED


inline static void clear(void *p, size_t len)
{
    clear_n(1, p, len);
}

#endif /* LIBWALLY_INTERNAL_H */

