#ifndef LIBWALLY_CORE_PSBT_H
#define LIBWALLY_CORE_PSBT_H

#include "wally_transaction.h"
#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WALLY_PSBT_SEPARATOR 0x00

#define WALLY_PSBT_GLOBAL_UNSIGNED_TX 0x00

#define WALLY_PSBT_IN_NON_WITNESS_UTXO 0x00
#define WALLY_PSBT_IN_WITNESS_UTXO 0x01
#define WALLY_PSBT_IN_PARTIAL_SIG 0x02
#define WALLY_PSBT_IN_SIGHASH_TYPE 0x03
#define WALLY_PSBT_IN_REDEEM_SCRIPT 0x04
#define WALLY_PSBT_IN_WITNESS_SCRIPT 0x05
#define WALLY_PSBT_IN_BIP32_DERIVATION 0x06
#define WALLY_PSBT_IN_FINAL_SCRIPTSIG 0x07
#define WALLY_PSBT_IN_FINAL_SCRIPTWITNESS 0x08

#define WALLY_PSBT_OUT_REDEEM_SCRIPT 0x00
#define WALLY_PSBT_OUT_WITNESS_SCRIPT 0x01
#define WALLY_PSBT_OUT_BIP32_DERIVATION 0x02

#ifdef SWIG
struct wally_key_origin_info;
struct wally_keypath_map;
struct wally_partial_sigs_map;
struct wally_unknowns_map;
struct wally_psbt_input;
struct wally_psbt_output;
struct wally_psbt;
#else

#define FINGERPRINT_LEN 4

/** Key origin data. Contains a BIP 32 fingerprint and the derivation path */
struct wally_key_origin_info {
    unsigned char fingerprint[FINGERPRINT_LEN];
    uint32_t *path;
    size_t path_len;
};

/** Item in keypath map */
struct wally_keypath_item {
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    struct wally_key_origin_info origin;
};

/** A map of public keys to BIP 32 fingerprint and derivation paths */
struct wally_keypath_map {
    struct wally_keypath_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** Item in partial signatures map */
struct wally_partial_sigs_item {
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    unsigned char *sig;
    size_t sig_len;
};

/** A map of public key's to signatures */
struct wally_partial_sigs_map {
    struct wally_partial_sigs_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** Unknown item */
struct wally_unknowns_item {
    unsigned char *key;
    size_t key_len;
    unsigned char *value;
    size_t value_len;
};

/** Unknown items map */
struct wally_unknowns_map {
    struct wally_unknowns_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** A psbt input map */
struct wally_psbt_input {
    struct wally_tx *non_witness_utxo;
    struct wally_tx_output *witness_utxo;
    unsigned char *redeem_script;
    size_t redeem_script_len;
    unsigned char *witness_script;
    size_t witness_script_len;
    unsigned char *final_script_sig;
    size_t final_script_sig_len;
    struct wally_tx_witness_stack *final_witness;
    struct wally_keypath_map *keypaths;
    struct wally_partial_sigs_map *partial_sigs;
    struct wally_unknowns_map *unknowns;
    uint32_t sighash_type;
};

/** A psbt output map */
struct wally_psbt_output {
    unsigned char *redeem_script;
    size_t redeem_script_len;
    unsigned char *witness_script;
    size_t witness_script_len;
    struct wally_keypath_map *keypaths;
    struct wally_unknowns_map *unknowns;
};

/** A parsed bitcoin transaction */
struct wally_psbt {
    struct wally_tx *tx;
    struct wally_psbt_input *inputs;
    size_t num_inputs;
    size_t inputs_allocation_len;
    struct wally_psbt_output *outputs;
    size_t num_outputs;
    size_t outputs_allocation_len;
    struct wally_unknowns_map *unknowns;
};
#endif /* SWIG */

/**
 * Allocate and initialize a new keypath map.
 *
 * :param alloc_len: The number of items to allocate.
 * :param output: Destination for the new keypath map
 */
WALLY_CORE_API int wally_keypath_map_init_alloc(size_t alloc_len, struct wally_keypath_map **output);

#ifndef SWIG_PYTHON
/**
 * Free a keypath map allocated by `wally_keypath_map_init_alloc`.
 *
 * :param keypaths: The keypath map to free.
 */
WALLY_CORE_API int wally_keypath_map_free(struct wally_keypath_map *keypaths);
#endif /* SWIG_PYTHON */

/**
 * Add an item to a keypath map
 *
 * :param keypaths: The keypath map to add to
 * :param pubkey: The pubkey to add
 * :param pubkey_len: The length of the pubkey. Must be EC_PUBLIC_KEY_UNCOMPRESSED_LEN or EC_PUBLIC_KEY_LEN
 * :param fingerprint: The master key fingerprint for the pubkey
 * :param fingerprint_len: The length of the fingerprint. Must be FINGERPRINT_LEN
 * :param path: The BIP32 derivation path for the pubkey
 * :param path_len: The number of items in path
 */
WALLY_CORE_API int wally_add_new_keypath(struct wally_keypath_map *keypaths,
                                   unsigned char *pubkey,
                                   size_t pubkey_len,
                                   unsigned char *fingerprint,
                                   size_t fingerprint_len,
                                   uint32_t *path,
                                   size_t path_len);

/**
 * Allocate and initialize a new partial sigs map.
 *
 * :param alloc_len: The number of items to allocate.
 * :param output: Destination for the new partial sigs map
 */
WALLY_CORE_API int wally_partial_sigs_map_init_alloc(size_t alloc_len, struct wally_partial_sigs_map **output);

#ifndef SWIG_PYTHON
/**
 * Free a partial sigs map allocated by `wally_partial_sigs_map_init_alloc`.
 *
 * :param sigs: The partial sigs map to free.
 */
WALLY_CORE_API int wally_partial_sigs_map_free(struct wally_partial_sigs_map *sigs);
#endif /* SWIG_PYTHON */

/**
 * Add an item to a partial sigs map
 *
 * :param sigs: The partial sigs map to add to
 * :param pubkey: The pubkey to add
 * :param pubkey_len: Length of the public key. Must be EC_PUBLIC_KEY_LEN or EC_PUBLIC_KEY_UNCOMPRESSED_LEN
 * :param sig: The signature to add
 * :param sig_len: The length of sig
 */
WALLY_CORE_API int wally_add_new_partial_sig(struct wally_partial_sigs_map *sigs,
                                       unsigned char *pubkey,
                                       size_t pubkey_len,
                                       unsigned char *sig,
                                       size_t sig_len);

/**
 * Allocate and initialize a new unknowns map
 *
 * :param alloc_len: The number of items to allocate.
 * :param output: Destination for the new unknowns map
 */
WALLY_CORE_API int wally_unknowns_map_init_alloc(size_t alloc_len, struct wally_unknowns_map **output);

#ifndef SWIG_PYTHON
/**
 * Free an unknowns map allocated by `wally_unknowns_map_init_alloc`.
 *
 * :param unknowns: The unknowns map map to free.
 */
WALLY_CORE_API int wally_unknowns_map_free(struct wally_unknowns_map *unknowns);
#endif /* SWIG_PYTHON */

/**
 * Add an item to an unknowns map
 *
 * :param unknowns: The unknowns map to add to
 * :param key: The key to add
 * :param key_len: The length of the key
 * :param value: The value to add
 * :param value_len: The length of value
 */
WALLY_CORE_API int wally_add_new_unknown(struct wally_unknowns_map *unknowns,
                                   unsigned char *key,
                                   size_t key_len,
                                   unsigned char *value,
                                   size_t value_len);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_PSBT_H */
