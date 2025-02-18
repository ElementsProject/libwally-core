#ifndef LIBWALLY_CORE_TX_IO_H
#define LIBWALLY_CORE_TX_IO_H 1

#include <include/wally_transaction.h>
#include <include/wally_map.h>
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "pullpush.h"

/* A cursor for pushing/pulling tx bytes for hashing */
typedef struct cursor_io
{
    unsigned char *cursor;
    size_t max;
    struct wally_map *cache;
    struct sha256_ctx ctx;
} cursor_io;

int txio_get_bip341_signature_hash(
    const struct wally_tx *tx, size_t index,
    const struct wally_map *scripts,
    const struct wally_map *assets,
    const struct wally_map *values,
    const unsigned char *tapleaf_script, size_t tapleaf_script_len,
    uint32_t key_version,
    uint32_t codesep_position,
    const unsigned char *annex, size_t annex_len,
    const unsigned char *genesis_blockhash, size_t genesis_blockhash_len,
    uint32_t sighash,
    uint32_t flags,
    struct wally_map *cache,
    unsigned char *bytes_out, size_t len);

#endif /* LIBWALLY_CORE_TX_IO_H */
