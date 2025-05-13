#ifndef LIBWALLY_CORE_TX_IO_H
#define LIBWALLY_CORE_TX_IO_H 1

#include <include/wally_map.h>
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
} cursor_io;

/* Hash helpers */
void tagged_hash_init(struct sha256_ctx *ctx,
                      const unsigned char *hash, size_t hash_len);

void hash_varbuff(struct sha256_ctx *ctx,
                  const unsigned char *bytes, size_t bytes_len);

#endif /* LIBWALLY_CORE_TX_IO_H */
