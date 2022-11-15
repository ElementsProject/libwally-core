#ifndef LIBWALLY_CORE_BIP32_INT_H
#define LIBWALLY_CORE_BIP32_INT_H 1

#ifdef __cplusplus
extern "C" {
#endif

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined(SWIG_JAVASCRIPT_BUILD) || defined(WASM_BUILD)

/**
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_BIP32_CHAIN_CODE_LEN)
 */
WALLY_CORE_API int bip32_key_get_chain_code(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);

/**
 * FIXED_SIZED_OUTPUT(len, bytes_out, HASH160_LEN)
 */
WALLY_CORE_API int bip32_key_get_parent160(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);

/**
 * FIXED_SIZED_OUTPUT(len, bytes_out, EC_PRIVATE_KEY_LEN)
 */
WALLY_CORE_API int bip32_key_get_priv_key(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);

/**
 * FIXED_SIZED_OUTPUT(len, bytes_out, HASH160_LEN)
 */
WALLY_CORE_API int bip32_key_get_hash160(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);

/**
 * FIXED_SIZED_OUTPUT(len, bytes_out, EC_PUBLIC_KEY_LEN)
 */
WALLY_CORE_API int bip32_key_get_pub_key(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);

#ifdef BUILD_ELEMENTS

/**
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_BIP32_TWEAK_SUM_LEN)
 */
WALLY_CORE_API int bip32_key_get_pub_key_tweak_sum(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);

#endif /* BUILD_ELEMENTS */

WALLY_CORE_API int bip32_key_get_depth(const struct ext_key *hdkey, size_t *written);
WALLY_CORE_API int bip32_key_get_child_num(const struct ext_key *hdkey, size_t *written);
WALLY_CORE_API int bip32_key_get_version(const struct ext_key *hdkey, size_t *written);

#endif /* SWIG/SWIG_JAVA_BUILD/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD */

#ifdef __cplusplus
}
#endif


#endif /* LIBWALLY_CORE_BIP32_INT_H */
