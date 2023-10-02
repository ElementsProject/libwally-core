#ifndef LIBWALLY_CORE_ADDRESS_H
#define LIBWALLY_CORE_ADDRESS_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ext_key;

#define WALLY_WIF_FLAG_COMPRESSED 0x0   /** Corresponding public key compressed */
#define WALLY_WIF_FLAG_UNCOMPRESSED 0x1 /** Corresponding public key uncompressed */

#define WALLY_CA_PREFIX_LIQUID 0x0c /** Liquid v1 confidential address prefix */
#define WALLY_CA_PREFIX_LIQUID_REGTEST 0x04 /** Liquid v1 confidential address prefix for regtest */
#define WALLY_CA_PREFIX_LIQUID_TESTNET 0x17 /** Liquid v1 confidential address prefix for testnet */

/*** address-networks Address network constants */
#define WALLY_NETWORK_NONE 0x00 /** Used for miniscript parsing only */
#define WALLY_NETWORK_BITCOIN_MAINNET 0x01 /** Bitcoin mainnet */
#define WALLY_NETWORK_BITCOIN_REGTEST 0xff  /** Bitcoin regtest: Behaves as testnet except for segwit */
#define WALLY_NETWORK_BITCOIN_TESTNET 0x02 /** Bitcoin testnet */
#define WALLY_NETWORK_LIQUID 0x03 /** Liquid v1 */
#define WALLY_NETWORK_LIQUID_REGTEST 0x04 /** Liquid v1 regtest */
#define WALLY_NETWORK_LIQUID_TESTNET 0x05 /** Liquid v1 testnet */

#define WALLY_ADDRESS_TYPE_P2PKH 0x01       /** P2PKH address ("1...") */
#define WALLY_ADDRESS_TYPE_P2SH_P2WPKH 0x02 /** P2SH-P2WPKH wrapped SegWit address ("3...") */
#define WALLY_ADDRESS_TYPE_P2WPKH 0x04      /** P2WPKH native SegWit address ("bc1...)" */

/*** address-versions Address versions */
#define WALLY_ADDRESS_VERSION_P2PKH_MAINNET 0x00 /** P2PKH address on mainnet */
#define WALLY_ADDRESS_VERSION_P2PKH_TESTNET 0x6F /** P2PKH address on testnet */
#define WALLY_ADDRESS_VERSION_P2PKH_LIQUID 0x39 /** P2PKH address on liquid v1 */
#define WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST 0xEB /** P2PKH address on liquid v1 regtest */
#define WALLY_ADDRESS_VERSION_P2PKH_LIQUID_TESTNET 0x24 /** P2PKH address on liquid v1 testnet */
#define WALLY_ADDRESS_VERSION_P2SH_MAINNET 0x05 /** P2SH address on mainnet */
#define WALLY_ADDRESS_VERSION_P2SH_TESTNET 0xC4 /** P2SH address on testnet */
#define WALLY_ADDRESS_VERSION_P2SH_LIQUID 0x27 /** P2SH address on liquid v1 */
#define WALLY_ADDRESS_VERSION_P2SH_LIQUID_REGTEST 0x4B /** P2SH address on liquid v1 regtest */
#define WALLY_ADDRESS_VERSION_P2SH_LIQUID_TESTNET 0x13 /** P2SH address on liquid v1 testnet */
#define WALLY_ADDRESS_VERSION_WIF_MAINNET 0x80 /** Wallet Import Format on mainnet */
#define WALLY_ADDRESS_VERSION_WIF_TESTNET 0xEF /** Wallet Import Format on testnet */

#define WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN 42 /** OP_[0-16] OP_PUSH_N [up-to-40-bytes witprog] */
#define WALLY_ADDRESS_PUBKEY_MAX_LEN 25

#define WALLY_SEGWIT_V0_ADDRESS_PUBKEY_MAX_LEN 34 /** OP_0 OP_PUSH_{20,32} [20 bytes for wpkh, 32 for wsh] */
#define WALLY_SEGWIT_V1_ADDRESS_PUBKEY_LEN 34 /** OP_1 OP_PUSH_32 [32-bytes x-only pubkey] */

/**
 * Create a segwit native address from a v0 or later witness program.
 *
 * :param bytes: Witness program bytes, including the version and data push opcode.
 * :param bytes_len: Length of ``bytes`` in bytes. Must be `HASH160_LEN` + 2
 *|    or `SHA256_LEN` + 2 for v0 witness programs.
 * :param addr_family: Address family to generate, e.g. "bc" or "tb".
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting segwit native address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_addr_segwit_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    const char *addr_family,
    uint32_t flags,
    char **output);

/**
 * Get a scriptPubKey containing the witness program from a segwit native address.
 *
 * :param addr: Address to fetch the witness program from.
 * :param addr_family: Address family to generate, e.g. "bc" or "tb".
 * :param flags: For future use. Must be 0.
 * :param bytes_out: Destination for the resulting scriptPubKey (including the version and data push opcode)
 * MAX_SIZED_OUTPUT(len, bytes_out, WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN)
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_addr_segwit_to_bytes(
    const char *addr,
    const char *addr_family,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get a scriptPubKey containing the witness program from a known-length segwit native address.
 *
 * See `wally_addr_segwit_to_bytes`.
 *
 * MAX_SIZED_OUTPUT(len, bytes_out, WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN)
 */
WALLY_CORE_API int wally_addr_segwit_n_to_bytes(
    const char *addr,
    size_t addr_len,
    const char *addr_family,
    size_t addr_family_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the segwit version of a segwit native address.
 *
 * :param addr: Address to fetch the witness program from.
 * :param addr_family: Address family to generate, e.g. "bc" or "tb".
 * :param flags: For future use. Must be 0.
 * :param written: Destination for the segwit version from 0 to 16 inclusive.
 */
WALLY_CORE_API int wally_addr_segwit_get_version(
    const char *addr,
    const char *addr_family,
    uint32_t flags,
    size_t *written);

/**
 * Get the segwit version of a known-length segwit native address.
 *
 * See `wally_addr_segwit_get_version`.
 */
WALLY_CORE_API int wally_addr_segwit_n_get_version(
    const char *addr,
    size_t addr_len,
    const char *addr_family,
    size_t addr_family_len,
    uint32_t flags,
    size_t *written);

/**
 * Infer a scriptPubKey from an address.
 *
 * :param addr: Base58 encoded address to infer the scriptPubKey from.
 *|    For confidential Liquid addresses first call `wally_confidential_addr_to_addr`.
 * :param network: Network the address is for. One of the :ref:`address-networks`.
 * :param bytes_out: Destination for the resulting scriptPubKey.
 * MAX_SIZED_OUTPUT(len, bytes_out, WALLY_ADDRESS_PUBKEY_MAX_LEN)
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_address_to_scriptpubkey(
    const char *addr,
    uint32_t network,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Infer an address from a scriptPubKey.
 *
 * :param scriptpubkey: scriptPubKey bytes.
 * :param scriptpubkey_len: Length of ``scriptpubkey`` in bytes.
 * :param network: Network to generate the address for. One of the :ref:`address-networks`.
 * :param output: Destination for the resulting Base58 encoded address string.
 *|    The string returned should be freed using `wally_free_string`.
 *
 * For SegWit addresses, use `wally_addr_segwit_from_bytes` instead. To
 * determine if a scriptPubKey is SegWit, use `wally_scriptpubkey_get_type`.
 */
WALLY_CORE_API int wally_scriptpubkey_to_address(
    const unsigned char *scriptpubkey,
    size_t scriptpubkey_len,
    uint32_t network,
    char **output);

/**
 * Convert a private key to Wallet Import Format.
 *
 * :param priv_key: Private key bytes.
 * :param priv_key_len: The length of ``priv_key`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param prefix: Expected prefix byte, e.g. `WALLY_ADDRESS_VERSION_WIF_MAINNET`
 *|     or `WALLY_ADDRESS_VERSION_WIF_TESTNET`.
 * :param flags: Pass `WALLY_WIF_FLAG_COMPRESSED` if the corresponding pubkey is compressed,
 *|    otherwise `WALLY_WIF_FLAG_UNCOMPRESSED`.
 * :param output: Destination for the resulting Wallet Import Format string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_wif_from_bytes(
    const unsigned char *priv_key,
    size_t priv_key_len,
    uint32_t prefix,
    uint32_t flags,
    char **output);

/**
 * Convert a Wallet Import Format string to a private key.
 *
 * :param wif: Private key in Wallet Import Format.
 * :param prefix: Prefix byte to use, e.g. `WALLY_ADDRESS_VERSION_WIF_MAINNET`
 *|     or `WALLY_ADDRESS_VERSION_WIF_TESTNET`.
 * :param flags: Pass `WALLY_WIF_FLAG_COMPRESSED` if the corresponding pubkey is compressed,
 *|    otherwise `WALLY_WIF_FLAG_UNCOMPRESSED`.
 * :param bytes_out: Destination for the private key.
 * FIXED_SIZED_OUTPUT(len, bytes_out, EC_PRIVATE_KEY_LEN)
 */
WALLY_CORE_API int wally_wif_to_bytes(
    const char *wif,
    uint32_t prefix,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Determine if a private key in Wallet Import Format corresponds to an uncompressed public key.
 *
 * :param wif: Private key in Wallet Import Format to check.
 * :param written: 1 if the corresponding public key is uncompressed, 0 if compressed.
 */
WALLY_CORE_API int wally_wif_is_uncompressed(
    const char *wif,
    size_t *written);

/**
 * Create a public key corresponding to a private key in Wallet Import Format.
 *
 * :param wif: Private key in Wallet Import Format.
 * :param prefix: Expected prefix byte, e.g. `WALLY_ADDRESS_VERSION_WIF_MAINNET`
 *|     or `WALLY_ADDRESS_VERSION_WIF_TESTNET`.
 * :param bytes_out: Destination for the resulting public key.
 * :param len: The length of ``bytes_out``.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_wif_to_public_key(
    const char *wif,
    uint32_t prefix,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create a legacy or wrapped SegWit address corresponding to a BIP32 key.
 *
 * :param hdkey: The extended key to use.
 * :param flags: `WALLY_ADDRESS_TYPE_P2PKH` for a legacy address, `WALLY_ADDRESS_TYPE_P2SH_P2WPKH`
 *| for P2SH-wrapped SegWit.
 * :param version: Address version to generate. One of the :ref:`address-versions`.
 * :param output: Destination for the resulting address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_bip32_key_to_address(
    const struct ext_key *hdkey,
    uint32_t flags,
    uint32_t version,
    char **output);

/**
 * Create a native SegWit address corresponding to a BIP32 key.
 *
 * :param hdkey: The extended key to use.
 * :param addr_family: Address family to generate, e.g. "bc" or "tb".
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting segwit native address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_bip32_key_to_addr_segwit(
    const struct ext_key *hdkey,
    const char *addr_family,
    uint32_t flags,
    char **output);

/**
 * Create a P2PKH address corresponding to a private key in Wallet Import Format.
 *
 * :param wif: Private key in Wallet Import Format.
 * :param prefix: Prefix byte to use, e.g. 0x80, 0xef.
 * :param version: Address version to generate. One of the :ref:`address-versions`.
 * :param output: Destination for the resulting address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_wif_to_address(
    const char *wif,
    uint32_t prefix,
    uint32_t version,
    char **output);

#ifndef WALLY_ABI_NO_ELEMENTS
/**
 * Extract the address from a confidential address.
 *
 * :param address: The base58 encoded confidential address to extract the address from.
 * :param prefix: The confidential address prefix byte, e.g. `WALLY_CA_PREFIX_LIQUID`.
 * :param output: Destination for the resulting address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_confidential_addr_to_addr(
    const char *address,
    uint32_t prefix,
    char **output);

/**
 * Extract the blinding public key from a confidential address.
 *
 * :param address: The base58 encoded confidential address to extract the public key from.
 * :param prefix: The confidential address prefix byte, e.g. `WALLY_CA_PREFIX_LIQUID`.
 * :param bytes_out: Destination for the public key.
 * FIXED_SIZED_OUTPUT(len, bytes_out, EC_PUBLIC_KEY_LEN)
 */
WALLY_CORE_API int wally_confidential_addr_to_ec_public_key(
    const char *address,
    uint32_t prefix,
    unsigned char *bytes_out,
    size_t len);

/**
 * Create a confidential address from an address and blinding public key.
 *
 * :param address: The base58 encoded address to make confidential.
 * :param prefix: The confidential address prefix byte, e.g. `WALLY_CA_PREFIX_LIQUID`.
 * :param pub_key: The blinding public key to associate with ``address``.
 * :param pub_key_len: The length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_LEN`.
 * :param output: Destination for the resulting address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_confidential_addr_from_addr(
    const char *address,
    uint32_t prefix,
    const unsigned char *pub_key,
    size_t pub_key_len,
    char **output);

/**
 * Extract the segwit native address from a confidential address.
 *
 * :param address: The blech32 encoded confidential address to extract the address from.
 * :param confidential_addr_family: The confidential address family of ``address``.
 * :param addr_family: The address family to generate.
 * :param output: Destination for the resulting address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_confidential_addr_to_addr_segwit(
    const char *address,
    const char *confidential_addr_family,
    const char *addr_family,
    char **output);

/**
 * Extract the blinding public key from a segwit confidential address.
 *
 * :param address: The blech32 encoded confidential address to extract the public key from.
 * :param confidential_addr_family: The confidential address family of ``address``.
 * :param bytes_out: Destination for the public key.
 * FIXED_SIZED_OUTPUT(len, bytes_out, EC_PUBLIC_KEY_LEN)
 */
WALLY_CORE_API int wally_confidential_addr_segwit_to_ec_public_key(
    const char *address,
    const char *confidential_addr_family,
    unsigned char *bytes_out,
    size_t len);

/**
 * Create a confidential address from a segwit native address and blinding public key.
 *
 * :param address: The bech32 encoded address to make confidential.
 * :param addr_family: The address family to generate.
 * :param confidential_addr_family: The confidential address family to generate.
 * :param pub_key: The blinding public key to associate with ``address``.
 * :param pub_key_len: The length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_LEN`.
 * :param output: Destination for the resulting address string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_confidential_addr_from_addr_segwit(
    const char *address,
    const char *addr_family,
    const char *confidential_addr_family,
    const unsigned char *pub_key,
    size_t pub_key_len,
    char **output);
#endif /* WALLY_ABI_NO_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_ADDRESS_H */
