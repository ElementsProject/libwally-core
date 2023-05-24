#ifndef LIBWALLY_CORE_BIP38_H
#define LIBWALLY_CORE_BIP38_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/*** bip38-flags BIP38 conversion flags */
#define BIP38_KEY_NETWORK_MASK  0xff  /** Mask for the bottom 8 bitflags which hold the network */
#define BIP38_KEY_MAINNET       0  /** Address is for main network */
#define BIP38_KEY_TESTNET      111 /** Address is for test network */
#define BIP38_KEY_COMPRESSED   256 /** Public key is compressed */
#define BIP38_KEY_EC_MULT      512 /** EC-Multiplied key (FIXME: Not implemented) */
#define BIP38_KEY_QUICK_CHECK 1024 /** Check structure only (no password required) */
#define BIP38_KEY_RAW_MODE    2048 /** Treat bytes in as raw data */
#define BIP38_KEY_SWAP_ORDER  4096 /** Hash comes after encrypted key */

#define BIP38_SERIALIZED_LEN 39 /** Length of a raw BIP38 key in bytes */


/**
 * Encode a private key in raw BIP 38 address format.
 *
 * :param bytes: Private key to use.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param pass: Password for the encoded private key.
 * :param pass_len: Length of ``pass`` in bytes.
 * :param flags: :ref:`bip38-flags` indicating desired behavior.
 * :param bytes_out: Destination for the resulting raw BIP38 address.
 * FIXED_SIZED_OUTPUT(len, bytes_out, BIP38_SERIALIZED_LEN)
 */
WALLY_CORE_API int bip38_raw_from_private_key(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Encode a private key in BIP 38 address format.
 *
 * :param bytes: Private key to use.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param pass: Password for the encoded private key.
 * :param pass_len: Length of ``pass`` in bytes.
 * :param flags: :ref:`bip38-flags` indicating desired behavior.
 * :param output: Destination for the resulting BIP38 address.
 */
WALLY_CORE_API int bip38_from_private_key(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    char **output);

/**
 * Decode a raw BIP 38 address to a private key.
 *
 * :param bytes: Raw BIP 38 address to decode.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be `BIP38_SERIALIZED_LEN`.
 * :param pass: Password for the encoded private key.
 * :param pass_len: Length of ``pass`` in bytes.
 * :param flags: :ref:`bip38-flags` indicating desired behavior.
 * :param bytes_out: Destination for the resulting private key.
 * FIXED_SIZED_OUTPUT(len, bytes_out, EC_PRIVATE_KEY_LEN)
 */
WALLY_CORE_API int bip38_raw_to_private_key(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Decode a BIP 38 address to a private key.
 *
 * :param bip38: BIP 38 address to decode.
 * :param pass: Password for the encoded private key.
 * :param pass_len: Length of ``pass`` in bytes.
 * :param flags: :ref:`bip38-flags` indicating desired behavior.
 * :param bytes_out: Destination for the resulting private key.
 * FIXED_SIZED_OUTPUT(len, bytes_out, EC_PRIVATE_KEY_LEN)
 */
WALLY_CORE_API int bip38_to_private_key(
    const char *bip38,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Get compression and/or EC mult flags.
 *
 * :param bytes: Raw BIP 38 address to get the flags from.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be `BIP38_SERIALIZED_LEN`.
 * :param written: :ref:`bip38-flags` indicating behavior.
 */
WALLY_CORE_API int bip38_raw_get_flags(
    const unsigned char *bytes,
    size_t bytes_len,
    size_t *written);

/**
 * Get compression and/or EC mult flags.
 *
 * :param bip38: BIP 38 address to get the flags from.
 * :param written: :ref:`bip38-flags` indicating behavior.
 */
WALLY_CORE_API int bip38_get_flags(
    const char *bip38,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_BIP38_H */
