#ifndef LIBWALLY_CORE_BIP32_INT_H
#define LIBWALLY_CORE_BIP32_INT_H 1

#ifdef __cplusplus
extern "C" {
#endif

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined(SWIG_JAVASCRIPT_BUILD) || defined(WASM_BUILD)
WALLY_CORE_API int bip32_key_get_chain_code(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_parent160(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_priv_key(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_hash160(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_pub_key(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
#ifdef BUILD_ELEMENTS
WALLY_CORE_API int bip32_key_get_pub_key_tweak_sum(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
#endif /* BUILD_ELEMENTS */

WALLY_CORE_API int bip32_key_get_depth(const struct ext_key *hdkey, size_t *written);
WALLY_CORE_API int bip32_key_get_child_num(const struct ext_key *hdkey, size_t *written);
WALLY_CORE_API int bip32_key_get_version(const struct ext_key *hdkey, size_t *written);

#endif /* SWIG/SWIG_JAVA_BUILD/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD */

#if !defined(SWIG) && !defined(WASM_BUILD)
/* Internal: Create a partial bip32 key from a private key (no chaincode, un-derivable) */
int bip32_key_from_private_key(uint32_t version, const unsigned char *priv_key, size_t priv_key_len, struct ext_key *output);
#endif /* SWIG/WASM_BUILD */

#ifdef __cplusplus
}
#endif


#endif /* LIBWALLY_CORE_BIP32_INT_H */
