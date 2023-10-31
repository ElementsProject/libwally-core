/*
 * secp2556k1-zkp configuration
 */
#define ENABLE_MODULE_ECDH 1
#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SCHNORRSIG 1
#define ENABLE_MODULE_GENERATOR 1
#define ENABLE_MODULE_ECDSA_S2C 1
#ifdef BUILD_ELEMENTS
#define ENABLE_MODULE_RANGEPROOF 1
#define ENABLE_MODULE_RECOVERY 1
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
#include "ccan/ccan/crypto/sha256/sha256.c"

#include "internal.c"
#include "address.c"
#include "aes.c"
#include "anti_exfil.c"
#include "base_58.c"
#include "base_64.c"
#include "bech32.c"
#include "blech32.c"
#include "bip32.c"
#include "bip38.c"
#include "bip39.c"
#include "bip85.c"
#include "coins.c"
#include "descriptor.c"
#include "ecdh.c"
#include "elements.c"
#include "hex_.c"
#include "hmac.c"
#include "map.c"
#include "mnemonic.c"
#include "pbkdf2.c"
#include "pullpush.c"
#include "psbt.c"
#include "script.c"
#include "scrypt.c"
#include "sign.c"
#include "symmetric.c"
#include "transaction.c"
#include "wif.c"
#include "wordlist.c"

void wally_silence_unused_warnings(void)
{
    assert_sign_assumptions();
    assert_bip32_assumptions();
    assert_bip38_assumptions();
    assert_tx_assumptions();
}
