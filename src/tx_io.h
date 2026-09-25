#ifndef LIBWALLY_CORE_TX_IO_H
#define LIBWALLY_CORE_TX_IO_H 1

#include <include/wally_map.h>
#include <include/wally_script.h>
#include "ccan/ccan/crypto/sha256/sha256.h"

/* Suggested initial size of a signing cache to avoid re-allocations */
#define TXIO_CACHE_INITIAL_SIZE 16

/* A cursor for pushing/pulling tx bytes for hashing */
typedef struct cursor_io
{
    struct sha256_ctx ctx;
    struct wally_map *cache;
    unsigned char *cursor;
    size_t max;
    bool hash_failed; /* A sub-hash failed: txio_done() must fail */
} cursor_io;

/* Hash helpers */
void tagged_hash_init(struct sha256_ctx *ctx,
                      const unsigned char *hash, size_t hash_len);

void hash_varbuff(struct sha256_ctx *ctx,
                  const unsigned char *bytes, size_t bytes_len);

int bip341_tapbranch_hash(const unsigned char *lhs, size_t lhs_len,
                          const unsigned char *rhs, size_t rhs_len,
                          bool is_elements, unsigned char *bytes_out, size_t len) WARN_UNUSED_RESULT;

/* The tapscript leaf version: 0xc0 (BIP-342) for BTC, 0xc4 for Elements */
#define TAPSCRIPT_LEAF_VERSION(is_elements) ((is_elements) ? \
    WALLY_LEAF_VERSION_TAPSCRIPT_ELEMENTS : WALLY_LEAF_VERSION_TAPSCRIPT)

int bip341_tapleaf_hash(unsigned char leaf_version,
                        const unsigned char *script, size_t script_len,
                        bool is_elements, unsigned char *bytes_out, size_t len) WARN_UNUSED_RESULT;

#endif /* LIBWALLY_CORE_TX_IO_H */
