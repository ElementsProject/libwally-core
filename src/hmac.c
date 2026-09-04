#include "internal.h"
#include "hmac.h"
#include <ccan/ccan/crypto/sha256/sha256.h>
#include <ccan/ccan/crypto/sha512/sha512.h>
#include <include/wally_crypto.h>
#include <ccan/ccan/build_assert/build_assert.h>

#ifdef SHA_T
#undef SHA_T
#endif
#define SHA_T sha256
#define SHA_PRE(name) sha256 ## name
#define HMAC_FUNCTION hmac_sha256_impl
#define WALLY_HMAC_FUNCTION wally_hmac_sha256
#define SHA_BLOCK_LEN 64
#include "hmac.inl"

#undef SHA_T
#define SHA_T sha512
#undef SHA_PRE
#define SHA_PRE(name) sha512 ## name
#undef HMAC_FUNCTION
#define HMAC_FUNCTION hmac_sha512_impl
#undef WALLY_HMAC_FUNCTION
#define WALLY_HMAC_FUNCTION wally_hmac_sha512
#undef SHA_BLOCK_LEN
#define SHA_BLOCK_LEN 128
#include "hmac.inl"
