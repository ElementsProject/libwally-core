#ifndef WALLY_NO_AMALGAMATION
/*
 * secp2556k1-zkp configuration
 */
#define ENABLE_MODULE_ECDH 1
#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SCHNORRSIG 1
#define ENABLE_MODULE_GENERATOR 1
#define ENABLE_MODULE_ECDSA_S2C 1
#define ENABLE_MODULE_RECOVERY 1
#ifdef BUILD_ELEMENTS
#define ENABLE_MODULE_RANGEPROOF 1
#define ENABLE_MODULE_SURJECTIONPROOF 1
#define ENABLE_MODULE_WHITELIST 1
#endif

#if (defined(__clang__) || defined(__GNUC__)) && (defined(__x86_64__) || defined(__amd64__))
#define USE_ASM_X86_64 1
#endif

#undef PACKAGE
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION
#undef VERSION
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-function"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "src/secp256k1/src/secp256k1.c"
#include "src/secp256k1/src/precomputed_ecmult_gen.c"
#include "src/secp256k1/src/precomputed_ecmult.c"

/* Force the inclusion of our internal header first, so that
 * config.h (which must be provided by the amalgamation user)
 * is included.
 */
#define BUILD_AMALGAMATION 1
#include "src/internal.h"

/* The amalgamation user can provide their own defines and skip
 * providing a ccan_config.h if they define _WALLY_CCAN_CONFIG_H_.
 */
#ifndef _WALLY_CCAN_CONFIG_H_
#include "src/ccan_config.h"
#endif

#include "src/internal.c"
#include "src/address.c"
#include "src/aes.c"
#include "src/anti_exfil.c"
#include "src/base_58.c"
#include "src/base_64.c"
#include "src/bech32.c"
#include "src/blech32.c"
#include "src/bip32.c"
#include "src/bip38.c"
#include "src/bip39.c"
#include "src/bip85.c"
#include "src/coins.c"
#include "src/descriptor.c"
#include "src/ecdh.c"
#include "src/elements.c"
#include "src/hex_.c"
#include "src/hmac.c"
#include "src/map.c"
#include "src/mnemonic.c"
#include "src/pbkdf2.c"
#include "src/pullpush.c"
#include "src/psbt.c"
#include "src/script.c"
#include "src/scrypt.c"
#include "src/sign.c"
#include "src/symmetric.c"
#include "src/transaction.c"
#include "src/tx_io.c"
#include "src/wif.c"
#include "src/wordlist.c"

/* ccan sources */
#include "src/ccan/ccan/crypto/sha256/sha256.c"

/* Redefine internal names so sha-512 can be included without conflicts */
#define Round Round_512
#define Transform Transform_512
#define Maj Maj_512
#define Sigma0 Sigma0_512
#define sigma0 sigma0_512
#define Sigma1 Sigma1_512
#define sigma1 sigma1_512
#define add add_512
#define Ch Ch_512
#include "src/ccan/ccan/crypto/sha512/sha512.c"
#undef Round
#undef Transform
#undef Sigma0
#undef sigma0
#undef sigma1
#undef Sigma1
#undef add
#undef Maj
#undef Ch
#include "src/ccan/ccan/str/hex/hex.c"

/* Redefine internal names so ripemd-160 can be included without conflicts */
#define Transform Transform_ripemd160
#define add add_ripemd160
#define Round Round_ripemd160
#include "src/ccan/ccan/crypto/ripemd160/ripemd160.c"
#undef Transform
#undef add
#undef Round
#include "src/ccan/ccan/base64/base64.c"

void wally_silence_unused_warnings(void)
{
    assert_sign_assumptions();
    assert_bip32_assumptions();
    assert_bip38_assumptions();
    assert_tx_assumptions();
}

/* Undefine our internal macros */
#undef BYTES_VALID
#undef BYTES_INVALID
#undef BYTES_INVALID_N
#undef OUTPUT_CHECK
#undef OUTPUT_ALLOC

#endif /* WALLY_NO_AMALGAMATION */
