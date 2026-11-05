#ifndef LIBWALLY_CORE_MINISCRIPT_SATISFY_H
#define LIBWALLY_CORE_MINISCRIPT_SATISFY_H 1

#include "descriptor_int.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Witness state kinds (maps to Rust Witness<T> enum variants) */
#define MS_WITNESS_IMPOSSIBLE   0u  /* No valid satisfaction exists */
#define MS_WITNESS_UNAVAILABLE  1u  /* Missing data; third party may satisfy */
#define MS_WITNESS_STACK        2u  /* Stack data available */
#define MS_WITNESS_OOM          3u  /* An allocation failed: no result */

typedef struct ms_witness_item_t {
    unsigned char *data;
    size_t         data_len;
} ms_witness_item;

typedef struct ms_witness_t {
    uint32_t         kind;                 /* MS_WITNESS_* constant */
    ms_witness_item *items;
    size_t           num_items;
    size_t           items_allocation_len; /* allocated capacity */
} ms_witness;

typedef struct ms_satisfaction_t {
    ms_witness witness;
    bool       has_sig;           /* true if satisfaction contains a signature */
    uint32_t   absolute_timelock; /* 0 = absent */
    uint32_t   relative_timelock; /* 0 = absent */
} ms_satisfaction;

void ms_satisfaction_free(ms_satisfaction *s);

/* Hash type constants for lookup_preimage */
#define MS_HASH_SHA256    0u
#define MS_HASH_HASH256   1u
#define MS_HASH_RIPEMD160 2u
#define MS_HASH_HASH160   3u

/* Asset provider for ms_satisfy_node. Mirrors rust-miniscript AssetProvider. */
typedef struct ms_satisfier_t {
    /* Write a DER/Schnorr sig into sig_out; set *sig_len_out. Return true if
     * available. sig_out has room for EC_SIGNATURE_DER_MAX_LEN + 1 bytes
     * (max-DER signature plus sighash byte); callbacks MUST NOT write more. */
    bool (*lookup_sig)(const struct ms_satisfier_t *stfr,
                       const unsigned char *pk, size_t pk_len,
                       unsigned char *sig_out, size_t *sig_len_out);
    /* Write the 32-byte preimage of hash into preimage_out. hash_type = MS_HASH_*. */
    bool (*lookup_preimage)(const struct ms_satisfier_t *stfr,
                            const unsigned char *hash, size_t hash_len,
                            uint32_t hash_type,
                            unsigned char preimage_out[32]);
    /* Return true if relative locktime lock is satisfied. */
    bool (*check_older)(const struct ms_satisfier_t *stfr, uint32_t lock);
    /* Return true if absolute locktime lock is satisfied. */
    bool (*check_after)(const struct ms_satisfier_t *stfr, uint32_t lock);
    void *user_data;
} ms_satisfier;

/* Satisfy and dissatisfy a parsed miniscript expression. The keys of the
 * expression must be public keys (as decoded by ms_descriptor_from_script):
 * keys of other kinds are treated as having no signature available. */
void ms_satisfy_node(const ms_node *node, const ms_satisfier *stfr,
                     bool malleable,
                     ms_satisfaction *sat_out, ms_satisfaction *dissat_out);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_MINISCRIPT_SATISFY_H */
