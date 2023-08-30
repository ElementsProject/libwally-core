#ifndef LIBWALLY_INTERNAL_H
#define LIBWALLY_INTERNAL_H

#include <include/wally_core.h>
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_recovery.h"
#include "secp256k1/include/secp256k1_extrakeys.h"
#ifndef BUILD_STANDARD_SECP
#include "secp256k1/include/secp256k1_ecdsa_s2c.h"
#endif
#include <config.h>
#if defined(HAVE_MEMSET_S)
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <stdbool.h>
#include <string.h>

/* Fetch an internal secp context */
const secp256k1_context *secp_ctx(void);
#define secp256k1_context_destroy(c) _do_not_destroy_shared_ctx_pointers(c)

/* secp pub/priv key functions */
#define pubkey_create     secp256k1_ec_pubkey_create
#define pubkey_tweak_add  secp256k1_ec_pubkey_tweak_add

int pubkey_combine(secp256k1_pubkey *pubnonce, const secp256k1_pubkey *const *pubnonces, size_t n);
int pubkey_negate(secp256k1_pubkey *pubkey);
int pubkey_parse(secp256k1_pubkey *pubkey, const unsigned char *input, size_t input_len);
int pubkey_serialize(unsigned char *output, size_t *outputlen, const secp256k1_pubkey *pubkey, unsigned int flags);
/* Note xpubkey_parse accepts standard compressed pubkeys as well as x-only */
int xpubkey_parse(secp256k1_xonly_pubkey *pubkey, const unsigned char *input, size_t input_len);
int xpubkey_tweak_add(secp256k1_pubkey *pubkey, const secp256k1_xonly_pubkey *xpubkey, const unsigned char *tweak);
int xpubkey_serialize(unsigned char *output, const secp256k1_xonly_pubkey *xpubkey);
int seckey_verify(const unsigned char *seckey);
int seckey_negate(unsigned char *seckey);
int seckey_tweak_add(unsigned char *seckey, const unsigned char *tweak);
int seckey_tweak_mul(unsigned char *seckey, const unsigned char *tweak);
int keypair_create(secp256k1_keypair *keypair, const unsigned char *priv_key);
int keypair_xonly_pub(secp256k1_xonly_pubkey *xpubkey, const secp256k1_keypair *keypair);
int keypair_sec(unsigned char *output, const secp256k1_keypair *keypair);
int keypair_xonly_tweak_add(secp256k1_keypair *keypair, const unsigned char *tweak);

#define PUBKEY_COMPRESSED   SECP256K1_EC_COMPRESSED
#define PUBKEY_UNCOMPRESSED SECP256K1_EC_UNCOMPRESSED


void wally_clear(void *p, size_t len);
void wally_clear_2(void *p, size_t len, void *p2, size_t len2);
void wally_clear_3(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3);
void wally_clear_4(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3, void *p4, size_t len4);

void clear_and_free(void *p, size_t len);
void clear_and_free_bytes(unsigned char **p, size_t *len);

bool mem_is_zero(const void *mem, size_t len);

/* Fetch our internal operations function pointers */
const struct wally_operations *wally_ops(void);

void *wally_malloc(size_t size);
void *wally_calloc(size_t size);
void wally_free(void *ptr);
char *wally_strdup_n(const char *str, size_t str_len);
char *wally_strdup(const char *str);

#define malloc(size) __use_wally_malloc_internally__
#define calloc(size) __use_wally_calloc_internally__
#define free(ptr) __use_wally_free_internally__
#ifdef strdup
#undef strdup
#endif
#define strdup(ptr) __use_wally_strdup_internally__

/* Validity checking for input parameters */
#define BYTES_VALID(p, len) ((p != NULL) == (len != 0))
#define BYTES_INVALID(p, len) (!BYTES_VALID(p, len))
#define BYTES_INVALID_N(p, len, siz) ((p != NULL) != (len == siz))

/* Check and allocate output parameters */
#define OUTPUT_CHECK if (!output) return WALLY_EINVAL; else *output = NULL
#define OUTPUT_ALLOC(typ) \
    *output = wally_calloc(sizeof(typ)); \
    if (!*output) return WALLY_ENOMEM

/* Helpers for operating on byte buffers */
bool clone_data(void **dst, const void *src, size_t len);
bool clone_bytes(unsigned char **dst, const unsigned char *src, size_t len);
int replace_bytes(const unsigned char *bytes, size_t bytes_len,
                  unsigned char **bytes_out, size_t *bytes_len_out);
void *array_realloc(const void *src, size_t old_n, size_t new_n, size_t size);

int array_grow(void **src, size_t num_items, size_t *allocation_len,
               size_t item_size);

struct ext_key;
/* Internal: Create a partial bip32 key from a private key (no chaincode, un-derivable) */
int bip32_key_from_private_key(uint32_t version, const unsigned char *priv_key,
                               size_t priv_key_len, struct ext_key *output);

struct wally_map;
int map_add(struct wally_map *map_in,
            const unsigned char *key, size_t key_len,
            const unsigned char *value, size_t value_len,
            bool take_value, bool ignore_dups);
int map_add_preimage_and_hash(struct wally_map *map_in,
                              const unsigned char *key, size_t key_len,
                              const unsigned char *val, size_t val_len,
                              size_t type, bool skip_verify);
const struct wally_map_item *map_find_equal_integer(const struct wally_map *lhs,
                                                    const struct wally_map *rhs,
                                                    uint32_t key);

/* Clamp input/output allocation sizing to standard tx sizes for BTC.
 * Liquid numbers are smaller; we use the upper limit */
#define TX_MAX_INPUTS_ALLOC 1738u
#define TX_MAX_OUTPUTS_ALLOC 3224u

/* Clamp initial witness stack allocation sizing */
#define MAX_WITNESS_ITEMS_ALLOC 100u /* Non-Taproot standardness limit */

/* Absolute maximum number of inputs and outputs for BTC.
 * Liquid numbers are smaller; we use the upper limit */
#define TX_MAX_INPUTS (TX_MAX_INPUTS_ALLOC * 10)
#define TX_MAX_OUTPUTS (TX_MAX_OUTPUTS_ALLOC * 10)

#endif /* LIBWALLY_INTERNAL_H */
