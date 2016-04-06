#include <include/wally_bip39.h>
#include "pbkdf2.h"
#include "internal.h"
#include "hmac.h"
#include <string.h>
#include "ccan/ccan/endian/endian.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
#include "ccan/ccan/build_assert/build_assert.h"
#include <ccan/compiler/compiler.h>

static bool alignment_ok(const void *p UNUSED, size_t n UNUSED)
{
#if HAVE_UNALIGNED_ACCESS
    return true;
#else
    return ((size_t)p % n == 0);
#endif
}

#define SHA_T sha256
#define SHA_ALIGN_T uint32_t
#define SHA_POST(name) name ## sha256
#define PBKDF2_HMAC_SHA_LEN PBKDF2_HMAC_SHA256_LEN
#include "pbkdf2.inl"

#undef SHA_T
#define SHA_T sha512
#undef SHA_ALIGN_T
#define SHA_ALIGN_T uint64_t
#undef SHA_POST
#define SHA_POST(name) name ## sha512
#undef PBKDF2_HMAC_SHA_LEN
#define PBKDF2_HMAC_SHA_LEN PBKDF2_HMAC_SHA512_LEN
#include "pbkdf2.inl"

