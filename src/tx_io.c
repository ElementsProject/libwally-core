#include "internal.h"
#include <include/wally_transaction.h>
#include "pullpush.h"
#include "script.h"
#include "script_int.h"
#include "tx_io.h"
#include <string.h>

#define WALLY_SATOSHI_MAX ((uint64_t)WALLY_BTC_MAX * WALLY_SATOSHI_PER_BTC)

#define SIGTYPE_ALL (WALLY_SIGTYPE_PRE_SW | WALLY_SIGTYPE_SW_V0 | WALLY_SIGTYPE_SW_V1)

/* Cache keys for data that is constant while signing a given tx.
 * We also cache other data keyed by their binary value directly.
 */
#define TXIO_UNCACHED                 0 /* Signals that data should not be cached */
#define TXIO_SHA_TAPSIGHASH_CTX       1 /* Initial sha256_ctx for taproot bip340 hashing */
#define TXIO_SHA_OUTPOINT_FLAGS       2 /* Taproot cached data ... */
#define TXIO_SHA_PREVOUTS             3
#define TXIO_SHA_AMOUNTS              4
#define TXIO_SHA_ASSET_AMOUNTS        5
#define TXIO_SHA_SCRIPTPUBKEYS        6
#define TXIO_SHA_SEQUENCES            7
#define TXIO_SHA_ISSUANCES            8
#define TXIO_SHA_ISSUANCE_RANGEPROOFS 9
#define TXIO_SHA_OUTPUTS              10
#define TXIO_SHA_OUTPUT_WITNESSES     11 /* ... end of taproot cached data */

/* SHA256(TapSighash) */
static const unsigned char TAPSIGHASH_SHA256[SHA256_LEN] = {
    0xf4, 0x0a, 0x48, 0xdf, 0x4b, 0x2a, 0x70, 0xc8, 0xb4, 0x92, 0x4b, 0xf2, 0x65, 0x46, 0x61, 0xed,
    0x3d, 0x95, 0xfd, 0x66, 0xa3, 0x13, 0xeb, 0x87, 0x23, 0x75, 0x97, 0xc6, 0x28, 0xe4, 0xa0, 0x31
};
/* SHA256(TapLeaf) */
static const unsigned char TAPLEAF_SHA256[SHA256_LEN] = {
    0xae, 0xea, 0x8f, 0xdc, 0x42, 0x08, 0x98, 0x31, 0x05, 0x73, 0x4b, 0x58, 0x08, 0x1d, 0x1e, 0x26,
    0x38, 0xd3, 0x5f, 0x1c, 0xb5, 0x40, 0x08, 0xd4, 0xd3, 0x57, 0xca, 0x03, 0xbe, 0x78, 0xe9, 0xee
};

#ifdef BUILD_ELEMENTS
/* SHA256(TapSighash/elements) */
static const unsigned char TAPSIGHASH_SHA256_ELEMENTS[SHA256_LEN] = {
    0xe3, 0x43, 0x16, 0x49, 0xdc, 0xb6, 0x48, 0x53, 0x3d, 0x8e, 0x36, 0x4a, 0xff, 0xd6, 0x06, 0xcb,
    0x7d, 0xe9, 0x78, 0xd6, 0x0c, 0xd0, 0x12, 0x2d, 0x1e, 0x55, 0x17, 0x48, 0x75, 0xca, 0xba, 0x08
};
/* SHA256(TapLeaf/elements) */
static const unsigned char TAPLEAF_SHA256_ELEMENTS[SHA256_LEN] = {
    0x69, 0xff, 0xb5, 0x5a, 0xb8, 0xc8, 0x1c, 0x21, 0xf5, 0x8b, 0x2a, 0xdc, 0xb0, 0x83, 0x5a, 0x08,
    0x60, 0x8a, 0xf5, 0x9d, 0x04, 0x2f, 0x03, 0x37, 0x64, 0x33, 0x9c, 0xd8, 0xe6, 0xba, 0x33, 0xe7
};
#define TAPSIGHASH_SHA256(is_elements) (is_elements ? TAPSIGHASH_SHA256_ELEMENTS : TAPSIGHASH_SHA256)
#define TAPLEAF_SHA256(is_elements) (is_elements ? TAPLEAF_SHA256_ELEMENTS : TAPLEAF_SHA256)
#else
#define TAPSIGHASH_SHA256(is_elements) TAPSIGHASH_SHA256
#define TAPLEAF_SHA256(is_elements) TAPLEAF_SHA256
#endif /* BUILD_ELEMENTS */

static bool script_len_ok(size_t len) { return len != 0; }
static bool asset_len_ok(size_t len) { return len == WALLY_TX_ASSET_CT_ASSET_LEN; }
static bool satoshi_len_ok(size_t len) { return len == sizeof(uint64_t); }
static bool value_len_ok(size_t len)
{
    return len == WALLY_TX_ASSET_CT_VALUE_LEN ||
           len == WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN;
}

static uint64_t satoshi_from_item(const struct wally_map_item *item)
{
    uint64_t v;
    /* Map values must be in cpu byte order, but may not be aligned */
    memcpy(&v, item->value, item->value_len);
    return v;
}

/* Ensure 'm' is integer-indexed with num_items valid items */
static bool map_has_all(const struct wally_map *m, size_t num_items,
                        bool (*len_fn)(size_t))
{
    if (!m || m->num_items != num_items)
        return false;
    for (size_t i = 0; i < num_items; ++i) {
        const struct wally_map_item *item = m->items + i;
        if (item->key || item->key_len != i ||
            !item->value || !len_fn(item->value_len))
            return false;
    }
    return true;
}

/* Ensure 'm' is integer-indexed containing a valid item for 'index' */
static bool map_has_one(const struct wally_map *m, size_t index,
                        bool (*len_fn)(size_t))
{
    if (!m || !m->num_items)
        return false;
    for (size_t i = 0; i < m->num_items; ++i) {
        const struct wally_map_item *item = m->items + i;
        if (item->key || !item->value || !len_fn(item->value_len))
            return false;
        if (index == item->key_len) {
            if (len_fn == satoshi_len_ok &&
                satoshi_from_item(item) > WALLY_SATOSHI_MAX)
                    return false; /* Invalid BTC amount */
            return true;
        }
    }
    return false;
}

static inline void hash_u8(struct sha256_ctx *ctx, uint8_t v)
{
    sha256_u8(ctx, v);
}

static inline void hash_le32(struct sha256_ctx *ctx, uint32_t v)
{
    sha256_le32(ctx, v);
}

static inline void hash_le64(struct sha256_ctx *ctx, uint64_t v)
{
    sha256_le64(ctx, v);
}

static void hash_map_le64(struct sha256_ctx *ctx,
                          const struct wally_map *m, size_t index)
{
    hash_le64(ctx, satoshi_from_item(wally_map_get_integer(m, index)));
}

static inline void hash_bytes(struct sha256_ctx *ctx,
                              const unsigned char *bytes, size_t bytes_len)
{
    sha256_update(ctx, bytes, bytes_len);
}

static void hash_varbuff(struct sha256_ctx *ctx,
                         const unsigned char *bytes, size_t bytes_len)
{
    unsigned char varbuff_len[9];
    size_t n = varint_to_bytes(bytes_len, varbuff_len);
    sha256_update(ctx, varbuff_len, n);
    sha256_update(ctx, bytes, bytes_len);
}

static void hash_map_varbuff(struct sha256_ctx *ctx,
                             const struct wally_map *m, size_t index)
{
    const struct wally_map_item *item = wally_map_get_integer(m, index);
    hash_varbuff(ctx, item->value, item->value_len);
}

static bool txio_hash_cached_item(cursor_io *io, uint32_t key)
{
    const struct wally_map_item *item;
    item = io->cache ? wally_map_get_integer(io->cache, key) : NULL;
    if (!item)
        return false;
    hash_bytes(&io->ctx, item->value, item->value_len);
    return true;
}

static void txio_hash_sha256_ctx(cursor_io *io, struct sha256_ctx *ctx, int key)
{
    struct sha256 hash;
    sha256_done(ctx, &hash);
    hash_bytes(&io->ctx, hash.u.u8, sizeof(hash));
    if (io->cache && key != TXIO_UNCACHED)
        wally_map_add_integer(io->cache, key, hash.u.u8, sizeof(hash));
}

static void txio_done(cursor_io *io)
{
    struct sha256 hash;
    sha256_done(&io->ctx, &hash);
    push_bytes(&io->cursor, &io->max, hash.u.u8, sizeof(hash));
}

/* Initialize a sha256 context for bip340 tagged hashing.
 * 'hash' must be SHA256(tag), e.g. 'TapSighash', 'TapLeaf' etc.
 */
static void tagged_hash_init(struct sha256_ctx *ctx,
                             const unsigned char *hash, size_t hash_len)
{
    sha256_init(ctx);
    hash_bytes(ctx, hash, hash_len);
    hash_bytes(ctx, hash, hash_len);
}

#ifdef BUILD_ELEMENTS
static void hash_commmitment(struct sha256_ctx *ctx,
                             const unsigned char *bytes, size_t bytes_len)
{
    if (!bytes_len)
        hash_u8(ctx, 0);
    else
        hash_bytes(ctx, bytes, bytes_len);
}

static void hash_map_commmitment(struct sha256_ctx *ctx,
                                 const struct wally_map *m, size_t index)
{
    const struct wally_map_item *item = wally_map_get_integer(m, index);
    hash_commmitment(ctx, item->value, item->value_len);
}

static void hash_issuance_rangeproofs(struct sha256_ctx *ctx,
                                      const struct wally_tx_input *txin)
{
    if (!(txin->features & WALLY_TX_IS_ISSUANCE)) {
        hash_u8(ctx, 0);
        hash_u8(ctx, 0);
        return;
    }
    hash_varbuff(ctx, txin->issuance_amount_rangeproof, txin->issuance_amount_rangeproof_len);
    hash_varbuff(ctx, txin->inflation_keys_rangeproof, txin->inflation_keys_rangeproof_len);
}

static void hash_output_elements(struct sha256_ctx *ctx,
                                 const struct wally_tx_output *txout)
{
    hash_commmitment(ctx, txout->asset, txout->asset_len);
    hash_commmitment(ctx, txout->value, txout->value_len);
    hash_commmitment(ctx, txout->nonce, txout->nonce_len);
    hash_varbuff(ctx, txout->script, txout->script_len);
}

static void hash_output_witness(struct sha256_ctx *ctx,
                                const struct wally_tx_output *txout)
{
    hash_varbuff(ctx, txout->surjectionproof, txout->surjectionproof_len);
    hash_varbuff(ctx, txout->rangeproof, txout->rangeproof_len);
}

static void txio_hash_sha_outpoint_flags(cursor_io *io, const struct wally_tx *tx)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_OUTPOINT_FLAGS)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < tx->num_inputs; ++i) {
            const struct wally_tx_input *txin = tx->inputs + i;
            uint8_t v = 0;
            if (txin->features & WALLY_TX_IS_ISSUANCE)
                v = WALLY_TX_ISSUANCE_FLAG >> 24;
            else if (txin->features & WALLY_TX_IS_PEGIN)
                v = WALLY_TX_PEGIN_FLAG >> 24;
            hash_u8(&ctx, v);
        }
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_OUTPOINT_FLAGS);
    }
}

static void txio_hash_sha_asset_amounts(cursor_io *io,
                                        const struct wally_map *values,
                                        const struct wally_map *assets)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_ASSET_AMOUNTS)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < values->num_items; ++i) {
            hash_commmitment(&ctx, assets->items[i].value, assets->items[i].value_len);
            hash_commmitment(&ctx, values->items[i].value, values->items[i].value_len);
        }
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_ASSET_AMOUNTS);
    }
}

static void txio_hash_sha_issuances(cursor_io *io, const struct wally_tx *tx)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_ISSUANCES)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < tx->num_inputs; ++i) {
            const struct wally_tx_input *txin = tx->inputs + i;
            if (!(txin->features & WALLY_TX_IS_ISSUANCE)) {
                hash_u8(&ctx, 0);
                continue;
            }
            hash_bytes(&ctx, txin->blinding_nonce, sizeof(txin->blinding_nonce));
            hash_bytes(&ctx, txin->entropy, sizeof(txin->entropy));
            hash_commmitment(&ctx, txin->issuance_amount, txin->issuance_amount_len);
            hash_commmitment(&ctx, txin->inflation_keys, txin->inflation_keys_len);
        }
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_ISSUANCES);
    }
}

static void txio_hash_sha_issuance_rangeproofs(cursor_io *io, const struct wally_tx *tx)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_ISSUANCE_RANGEPROOFS)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < tx->num_inputs; ++i)
            hash_issuance_rangeproofs(&ctx, tx->inputs + i);
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_ISSUANCE_RANGEPROOFS);
    }
}

static void txio_hash_sha_outputs_elements(cursor_io *io, const struct wally_tx *tx)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_OUTPUTS)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < tx->num_outputs; ++i)
            hash_output_elements(&ctx, tx->outputs + i);
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_OUTPUTS);
    }
}

static void txio_hash_sha_output_witnesses(cursor_io *io, const struct wally_tx *tx)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_OUTPUT_WITNESSES)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < tx->num_outputs; ++i)
            hash_output_witness(&ctx, tx->outputs + i);
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_OUTPUT_WITNESSES);
    }
}

static void txio_hash_outpoint_flag(cursor_io *io, const struct wally_tx_input *txin)
{
    unsigned char outpoint_flag = 0;
    if (txin->features & WALLY_TX_IS_ISSUANCE)
        outpoint_flag |= WALLY_TX_ISSUANCE_FLAG >> 24;
    if (txin->features & WALLY_TX_IS_PEGIN)
        outpoint_flag |= WALLY_TX_PEGIN_FLAG >> 24;
    hash_u8(&io->ctx, outpoint_flag);
}

static void txio_hash_input_elements(cursor_io *io,
                                     const struct wally_tx *tx, size_t index,
                                     const struct wally_map *scripts,
                                     const struct wally_map *assets,
                                     const struct wally_map *values)
{
    const struct wally_tx_input *txin = tx->inputs + index;

    hash_map_commmitment(&io->ctx, assets, index);
    hash_map_commmitment(&io->ctx, values, index);
    hash_map_varbuff(&io->ctx, scripts, index);
    hash_le32(&io->ctx, txin->sequence);

    if (!(txin->features & WALLY_TX_IS_ISSUANCE))
        hash_u8(&io->ctx, 0);
    else {
        /* asset_issuance */
        hash_bytes(&io->ctx, txin->blinding_nonce, sizeof(txin->blinding_nonce));
        hash_bytes(&io->ctx, txin->entropy, sizeof(txin->entropy));
        hash_commmitment(&io->ctx, txin->issuance_amount, txin->issuance_amount_len);
        hash_commmitment(&io->ctx, txin->inflation_keys, txin->inflation_keys_len);
        {
            /* sha_single_issuance_rangeproofs */
            struct sha256_ctx ctx;
            sha256_init(&ctx);
            hash_issuance_rangeproofs(&ctx, txin);
            txio_hash_sha256_ctx(io, &ctx, TXIO_UNCACHED);
        }
    }
}

static void txio_hash_sha_single_output_elements(cursor_io *io,
                                                 const struct wally_tx_output *txout)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    hash_output_elements(&ctx, txout);
    txio_hash_sha256_ctx(io, &ctx, TXIO_UNCACHED);
}

static void txio_hash_sha_single_output_witness(cursor_io *io,
                                                const struct wally_tx_output *txout)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    hash_output_witness(&ctx, txout);
    txio_hash_sha256_ctx(io, &ctx, TXIO_UNCACHED);
}
#endif /* BUILD_ELEMENTS */

static void txio_hash_sha_prevouts(cursor_io *io, const struct wally_tx *tx)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_PREVOUTS)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < tx->num_inputs; ++i) {
            hash_bytes(&ctx, tx->inputs[i].txhash, WALLY_TXHASH_LEN);
            hash_le32(&ctx, tx->inputs[i].index);
        }
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_PREVOUTS);
    }
}

static void txio_hash_sha_amounts(cursor_io *io, const struct wally_map *values)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_AMOUNTS)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < values->num_items; ++i)
            hash_le64(&ctx, satoshi_from_item(values->items + i));
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_AMOUNTS);
    }
}

static void txio_hash_sha_scriptpubkeys(cursor_io *io, const struct wally_map *scripts)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_SCRIPTPUBKEYS)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < scripts->num_items; ++i)
            hash_varbuff(&ctx, scripts->items[i].value, scripts->items[i].value_len);
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_SCRIPTPUBKEYS);
    }
}

static void txio_hash_sha_sequences(cursor_io *io, const struct wally_tx *tx)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_SEQUENCES)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < tx->num_inputs; ++i)
            hash_le32(&ctx, tx->inputs[i].sequence);
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_SEQUENCES);
    }
}

static void txio_hash_sha_outputs(cursor_io *io, const struct wally_tx *tx)
{
    if (!txio_hash_cached_item(io, TXIO_SHA_OUTPUTS)) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t i = 0; i < tx->num_outputs; ++i) {
            hash_le64(&ctx, tx->outputs[i].satoshi);
            hash_varbuff(&ctx, tx->outputs[i].script, tx->outputs[i].script_len);
        }
        txio_hash_sha256_ctx(io, &ctx, TXIO_SHA_OUTPUTS);
    }
}

static void txio_hash_outpoint(cursor_io *io, const struct wally_tx_input *txin)
{
    hash_bytes(&io->ctx, txin->txhash, sizeof(txin->txhash));
    hash_le32(&io->ctx, txin->index);
}

static void txio_hash_input(cursor_io *io,
                            const struct wally_tx *tx, size_t index,
                            const struct wally_map *scripts,
                            const struct wally_map *values)
{
    hash_map_le64(&io->ctx, values, index);
    hash_map_varbuff(&io->ctx, scripts, index);
    hash_le32(&io->ctx, tx->inputs[index].sequence);
}

static void txio_hash_sha_single_output(cursor_io *io, const struct wally_tx_output *txout)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    hash_le64(&ctx, txout->satoshi);
    hash_varbuff(&ctx, txout->script, txout->script_len);
    txio_hash_sha256_ctx(io, &ctx, TXIO_UNCACHED);
}

static void txio_hash_annex(cursor_io *io,
                            const unsigned char *annex, size_t annex_len)
{
    const struct wally_map_item *item;
    item = io->cache ? wally_map_get(io->cache, annex, annex_len) : NULL;
    if (item)
        hash_bytes(&io->ctx, item->value, item->value_len);
    else {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        hash_varbuff(&ctx, annex, annex_len);
        struct sha256 hash;
        sha256_done(&ctx, &hash);
        hash_bytes(&io->ctx, hash.u.u8, sizeof(hash));
        if (io->cache)
            wally_map_add(io->cache, annex, annex_len, hash.u.u8, sizeof(hash));
    }
}

static void txio_hash_tapleaf_hash(cursor_io *io,
                                   const unsigned char *tapleaf_script, size_t tapleaf_script_len,
                                   bool is_elements)
{
    const struct wally_map_item *item;
    item = io->cache ? wally_map_get(io->cache, tapleaf_script, tapleaf_script_len) : NULL;
    if (item) {
        hash_bytes(&io->ctx, item->value, item->value_len);
    } else {
        struct sha256_ctx ctx;
        struct sha256 hash;
        tagged_hash_init(&ctx, TAPLEAF_SHA256(is_elements), SHA256_LEN);
        hash_u8(&ctx, 0xc0); /* leaf_version */
        hash_varbuff(&ctx, tapleaf_script, tapleaf_script_len);
        sha256_done(&ctx, &hash);
        hash_bytes(&io->ctx, hash.u.u8, sizeof(hash));
        if (io->cache)
            wally_map_add(io->cache, tapleaf_script, tapleaf_script_len, hash.u.u8, sizeof(hash));
    }
}

/* BIP 341 */
static void txio_bip341_init(cursor_io *io,
                             const unsigned char *genesis_blockhash, size_t genesis_blockhash_len)
{
    const struct wally_map_item *item;
    item = io->cache ? wally_map_get_integer(io->cache, TXIO_SHA_TAPSIGHASH_CTX) : NULL;
    if (item) {
        /* Note we hash the intial sha256_ctx itself here and so memcpy it */
        memcpy(&io->ctx, item->value, item->value_len);
        return;
    }

    tagged_hash_init(&io->ctx, TAPSIGHASH_SHA256(genesis_blockhash != NULL), SHA256_LEN);
    if (genesis_blockhash) {
        hash_bytes(&io->ctx, genesis_blockhash, genesis_blockhash_len);
        hash_bytes(&io->ctx, genesis_blockhash, genesis_blockhash_len);
    }
    if (io->cache)
        wally_map_add_integer(io->cache, TXIO_SHA_TAPSIGHASH_CTX,
                              (const unsigned char*)&io->ctx, sizeof(io->ctx));
}

static inline uint32_t tr_get_output_sighash_type(uint32_t sighash)
{
    if (sighash == WALLY_SIGHASH_DEFAULT)
       return WALLY_SIGHASH_ALL;
    return sighash & 0x3;
}

static inline bool bip341_is_input_hash_type(uint32_t sighash, uint32_t hash_type)
{
    return (sighash & WALLY_SIGHASH_TR_IN_MASK) == hash_type;
}

static int bip341_signature_hash(
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
    struct wally_map *cache,
    unsigned char *bytes_out, size_t len)
{
    const struct wally_tx_input *txin = tx ? tx->inputs + index : NULL;
    const struct wally_tx_output *txout = tx ? tx->outputs + index : NULL;
    size_t is_elements = 0;
    const uint32_t output_type = tr_get_output_sighash_type(sighash);
    const bool sh_anyonecanpay = sighash & WALLY_SIGHASH_ANYONECANPAY;
    const bool sh_anyprevout = bip341_is_input_hash_type(sighash, WALLY_SIGHASH_ANYPREVOUT);
    const bool sh_anyprevout_anyscript = bip341_is_input_hash_type(sighash, WALLY_SIGHASH_ANYPREVOUTANYSCRIPT);
    cursor_io io;
    int ret = WALLY_OK;

    if (!tx || index >= tx->num_inputs ||
        !values ||
        BYTES_INVALID(tapleaf_script, tapleaf_script_len) ||
        key_version > 1 ||
        codesep_position != WALLY_NO_CODESEPARATOR || /* TODO: Add support */
        BYTES_INVALID(annex, annex_len) || (annex && *annex != 0x50) ||
        BYTES_INVALID_N(genesis_blockhash, genesis_blockhash_len, SHA256_LEN) ||
        !bytes_out || len != SHA256_LEN)
       return WALLY_EINVAL;

#ifdef BUILD_ELEMENTS
    if ((ret = wally_tx_is_elements(tx, &is_elements)) != WALLY_OK)
        return ret;
#endif
    if (is_elements) {
        if (!genesis_blockhash)
           return WALLY_EINVAL;
    } else {
        genesis_blockhash = NULL;
        genesis_blockhash_len = 0;
    }

    {
        /* Validate input scripts/values/assets:
         * For ACP/APO, we must have the items at 'index', and look them up.
         * Otherwise we need all values, and iterate them.
         */
        const struct wally_map_item *item;
        bool (*value_len_fn)(size_t) = is_elements ? value_len_ok : satoshi_len_ok;
        if (!sh_anyonecanpay && !sh_anyprevout) {
            if (!map_has_all(scripts, tx->num_inputs, script_len_ok) ||
                !map_has_all(values, tx->num_inputs, value_len_fn) ||
                (is_elements && !map_has_all(assets, tx->num_inputs, asset_len_ok)))
                return WALLY_EINVAL;
        } else {
            if (!map_has_one(scripts, index, script_len_ok) ||
                !map_has_one(values, index, value_len_fn) ||
                (is_elements && !map_has_one(assets, index, asset_len_ok)))
                return WALLY_EINVAL;
        }
        item = wally_map_get_integer(scripts, index);
        if (!scriptpubkey_is_p2tr(item->value, item->value_len))
            return WALLY_EINVAL;
    }

    switch (sighash) {
        case WALLY_SIGHASH_DEFAULT:
        case WALLY_SIGHASH_ALL:
        case WALLY_SIGHASH_NONE:
        case WALLY_SIGHASH_SINGLE:
        case WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYONECANPAY:
        case WALLY_SIGHASH_NONE | WALLY_SIGHASH_ANYONECANPAY:
        case WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY:
            break; /* Always valid */
        case WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYPREVOUT:
        case WALLY_SIGHASH_NONE | WALLY_SIGHASH_ANYPREVOUT:
        case WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYPREVOUT:
        case WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYPREVOUT | WALLY_SIGHASH_ANYONECANPAY:
        case WALLY_SIGHASH_NONE | WALLY_SIGHASH_ANYPREVOUT | WALLY_SIGHASH_ANYONECANPAY:
        case WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYPREVOUT | WALLY_SIGHASH_ANYONECANPAY:
            if (key_version != 1)
                return WALLY_EINVAL; /* Only valid for key_version 1 */
            if (is_elements)
                return WALLY_ERROR; /* Elements: unsure of Activation status/no ELIP */
            break;
        default:
            return WALLY_EINVAL; /* Unknown sighash type */
    }

    /* Init */
    io.cache = cache;
    io.cursor = bytes_out;
    io.max = len;
    txio_bip341_init(&io, genesis_blockhash, genesis_blockhash_len);
    if (!is_elements)
        hash_u8(&io.ctx, 0); /* sighash epoch */
    /* Tx data */
    hash_u8(&io.ctx, sighash); /* hash_type */
    hash_le32(&io.ctx, tx->version);
    hash_le32(&io.ctx, tx->locktime);
#ifdef BUILD_ELEMENTS
    if (is_elements & !sh_anyonecanpay)
        txio_hash_sha_outpoint_flags(&io, tx);
#endif
    if (!sh_anyonecanpay && !sh_anyprevout) {
        txio_hash_sha_prevouts(&io, tx);
#ifdef BUILD_ELEMENTS
        if (is_elements)
            txio_hash_sha_asset_amounts(&io, values, assets);
        else
#endif
            txio_hash_sha_amounts(&io, values);
        txio_hash_sha_scriptpubkeys(&io, scripts);
        txio_hash_sha_sequences(&io, tx);
#ifdef BUILD_ELEMENTS
        if (is_elements) {
            txio_hash_sha_issuances(&io, tx);
            txio_hash_sha_issuance_rangeproofs(&io, tx);
        }
#endif
    }
    if (output_type == WALLY_SIGHASH_ALL) {
#ifdef BUILD_ELEMENTS
        if (is_elements) {
            txio_hash_sha_outputs_elements(&io, tx);
            txio_hash_sha_output_witnesses(&io, tx);
        } else
#endif
            txio_hash_sha_outputs(&io, tx);
    }
    /* Input data */
    hash_u8(&io.ctx, (tapleaf_script ? 1 : 0) * 2 + (annex ? 1 : 0)); /* spend_type */
    if (sh_anyonecanpay || sh_anyprevout) {
        if (sh_anyonecanpay) {
#ifdef BUILD_ELEMENTS
            if (is_elements)
                txio_hash_outpoint_flag(&io, txin);
#endif
            txio_hash_outpoint(&io, txin);
        }
#ifdef BUILD_ELEMENTS
        if (is_elements)
            txio_hash_input_elements(&io, tx, index, scripts, assets, values);
        else
#endif
            txio_hash_input(&io, tx, index, scripts, values);
    } else if (sh_anyprevout_anyscript) {
        hash_le32(&io.ctx, tx->inputs[index].sequence); /* nSequence */
    } else {
        hash_le32(&io.ctx, index); /* input_index */
    }
    if (annex) {
        txio_hash_annex(&io, annex, annex_len);
    }
    /* Output data */
    if (output_type == WALLY_SIGHASH_SINGLE) {
#ifdef BUILD_ELEMENTS
        if (is_elements) {
            txio_hash_sha_single_output_elements(&io, txout);
            txio_hash_sha_single_output_witness(&io, txout);
        } else
#endif
            txio_hash_sha_single_output(&io, txout);
    }
    /* Tapscript Extensions */
    if (tapleaf_script) {
        if (!sh_anyprevout_anyscript)
            txio_hash_tapleaf_hash(&io, tapleaf_script, tapleaf_script_len, is_elements);
        hash_u8(&io.ctx, key_version & 0xff);
        hash_le32(&io.ctx, codesep_position);
    }
    txio_done(&io);
    if (io.max)
        ret = WALLY_ERROR; /* Wrote the wrong number of bytes: should not happen! */
    return ret;
}

int wally_tx_get_input_signature_hash(
    const struct wally_tx *tx, size_t index,
    const struct wally_map *scripts,
    const struct wally_map *assets,
    const struct wally_map *values,
    const unsigned char *script, size_t script_len,
    uint32_t key_version,
    uint32_t codesep_position,
    const unsigned char *annex, size_t annex_len,
    const unsigned char *genesis_blockhash, size_t genesis_blockhash_len,
    uint32_t sighash,
    uint32_t flags,
    struct wally_map *cache,
    unsigned char *bytes_out, size_t len)
{
    if (!flags || (flags & ~SIGTYPE_ALL))
        return WALLY_EINVAL;
    if (flags & WALLY_SIGTYPE_SW_V1)
        return bip341_signature_hash(tx, index, scripts, assets, values,
                                     script, script_len,
                                     key_version, codesep_position,
                                     annex, annex_len,
                                     genesis_blockhash, genesis_blockhash_len,
                                     sighash, cache, bytes_out, len);
    return WALLY_ERROR; /* FIXME: Support segwit/pre-segwit hashing */
}
