#ifndef LIBWALLY_CORE_BIP32_INT_H
#define LIBWALLY_CORE_BIP32_INT_H 1

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined(SWIG_JAVASCRIPT_BUILD)

WALLY_CORE_API int bip32_key_get_chain_code(const struct ext_key *key_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_parent160(const struct ext_key *key_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_priv_key(const struct ext_key *key_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_hash160(const struct ext_key *key_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_pub_key(const struct ext_key *key_in, unsigned char *bytes_out, size_t len);

WALLY_CORE_API int bip32_key_get_depth(const struct ext_key *key_in, size_t *written);
WALLY_CORE_API int bip32_key_get_child_num(const struct ext_key *key_in, size_t *written);
WALLY_CORE_API int bip32_key_get_version(const struct ext_key *key_in, size_t *written);

#endif /* SWIG_JAVA_BUILD/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD */

#endif /* LIBWALLY_CORE_BIP32_INT_H */
