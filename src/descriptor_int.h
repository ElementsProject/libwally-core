#ifndef WALLY_DESCRIPTOR_INT_H
#define WALLY_DESCRIPTOR_INT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ms_node kind base values */
#define KIND_MINISCRIPT 0x01

/* Miniscript terminal/compound node kinds */
#define KIND_MINISCRIPT_PK        (0x00000100 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_PKH       (0x00000200 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_MULTI     (0x00000300 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_PK_K      (0x00001000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_PK_H      (0x00002000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OLDER     (0x00010000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_AFTER     (0x00020000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_SHA256    (0x00030000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_HASH256   (0x00040000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_RIPEMD160 (0x00050000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_HASH160   (0x00060000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_THRESH    (0x00070000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_ANDOR     (0x01000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_AND_V     (0x02000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_AND_B     (0x03000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_AND_N     (0x04000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OR_B      (0x05000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OR_C      (0x06000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OR_D      (0x07000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OR_I      (0x08000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_MULTI_A   (0x09000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_MULTI_A_S (0x0A000000 | KIND_MINISCRIPT)

/* Wrapper node kinds (decoder-only; not used by the string parser) */
#define KIND_MINISCRIPT_ALT            (0x0B000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_SWAP           (0x0C000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_CHECK          (0x0D000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_DUP_IF         (0x0E000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_VERIFY         (0x0F000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_NON_ZERO       (0x10000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_ZERO_NOT_EQUAL (0x11000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_JUST_0         (0x12000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_JUST_1         (0x13000000 | KIND_MINISCRIPT)

/* Witness state kinds (maps to Rust Witness<T> enum variants) */
#define MS_WITNESS_IMPOSSIBLE   0u  /* No valid satisfaction exists */
#define MS_WITNESS_UNAVAILABLE  1u  /* Missing data; third party may satisfy */
#define MS_WITNESS_STACK        2u  /* Stack data available */

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

int  ms_witness_init(ms_witness *w, uint32_t kind);
void ms_witness_free(ms_witness *w);
int  ms_satisfaction_init(ms_satisfaction *s, uint32_t witness_kind);
void ms_satisfaction_free(ms_satisfaction *s);
ms_satisfaction satisfaction_best(ms_satisfaction a, ms_satisfaction b);
void satisfaction_or_b(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                       bool malleable);
void satisfaction_or_c(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                       bool malleable);
void satisfaction_or_d(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                       bool malleable);
void satisfaction_or_i(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                       bool malleable);
void satisfaction_andor(ms_satisfaction sat_x, ms_satisfaction dissat_x,
                        ms_satisfaction sat_y, ms_satisfaction dissat_y,
                        ms_satisfaction sat_z, ms_satisfaction dissat_z,
                        ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                        bool malleable);
void satisfaction_thresh(size_t k, size_t n,
                         ms_satisfaction *sats,
                         ms_satisfaction *dissats,
                         ms_satisfaction *sat_out,
                         ms_satisfaction *dissat_out);
void satisfaction_thresh_mall(size_t k, size_t n,
                              ms_satisfaction *sats,
                              ms_satisfaction *dissats,
                              ms_satisfaction *sat_out,
                              ms_satisfaction *dissat_out);

ms_satisfaction ms_satisfaction_clone(const ms_satisfaction *src);

/* Hash type constants for lookup_preimage */
#define MS_HASH_SHA256    0u
#define MS_HASH_HASH256   1u
#define MS_HASH_RIPEMD160 2u
#define MS_HASH_HASH160   3u

/* Asset provider for satisfy_node. Mirrors rust-miniscript AssetProvider. */
typedef struct ms_satisfier_t {
    /* Write a DER/Schnorr sig into sig_out; set *sig_len_out. Return true if available. */
    bool (*lookup_sig)(const struct ms_satisfier_t *stfr,
                       const unsigned char *pk, size_t pk_len,
                       unsigned char *sig_out, size_t *sig_len_out);
    /* For pk_h fragments: given the 20-byte HASH160, resolve the public key and
     * (when available) a signature. On return: pk_out/pk_len_out are always set
     * when the function returns true; *sig_len_out > 0 only when a signature is
     * also available. Returns false when the public key is unknown, which maps to
     * MS_WITNESS_IMPOSSIBLE for sat and MS_WITNESS_UNAVAILABLE for dissat. May be NULL if no pk_h
     * fragments are expected. */
    bool (*lookup_pkh)(const struct ms_satisfier_t *stfr,
                       const unsigned char *hash20,
                       unsigned char *pk_out,  size_t *pk_len_out,
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
    /* 32-byte taproot leaf hash; NULL for segwit v0. */
    const unsigned char *leaf_hash;
    void *user_data;
} ms_satisfier;

/* A node in a parsed miniscript expression */
typedef struct ms_node_t {
    struct ms_node_t *next;
    struct ms_node_t *child;
    struct ms_node_t *parent;
    uint32_t kind;
    uint32_t type_properties;
    int64_t number;
    const char *child_path;
    const char *data;
    uint32_t data_len;
    uint32_t child_path_len;
    char wrapper_str[12];
    unsigned short flags; /* WALLY_MS_IS_ flags */
    unsigned char builtin;
} ms_node;

typedef struct wally_descriptor ms_ctx;

/* Built-in miniscript expressions */
typedef int (*node_verify_fn_t)(ms_ctx *ctx, ms_node *node);
typedef int (*node_gen_fn_t)(ms_ctx *ctx, ms_node *node,
                             unsigned char *script, size_t script_len, size_t *written);

struct ms_builtin_t {
    const char *name;
    const uint32_t name_len;
    const uint32_t kind;
    const uint32_t type_properties;
    const uint32_t child_count; /* Number of expected children */
    const node_verify_fn_t verify_fn;
    const node_gen_fn_t generate_fn;
};

extern const struct ms_builtin_t g_builtins[];

void satisfy_node(const ms_node *node, const ms_satisfier *stfr,
                  bool malleable,
                  ms_satisfaction *sat_out, ms_satisfaction *dissat_out);

#endif /* WALLY_DESCRIPTOR_INT_H */
