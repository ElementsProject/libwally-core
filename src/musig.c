#include "internal.h"
#include <include/wally_crypto.h>
#include <include/wally_musig.h>
#include <include/wally_bip32.h>

#ifndef BUILD_STANDARD_SECP
#include <secp256k1_musig.h>

/* Struct bodies kept private to prevent inadvertent copying (nonce-reuse risk) */
struct wally_musig_keyagg_cache { unsigned char data[197]; };
struct wally_musig_secnonce      { unsigned char data[132]; };
struct wally_musig_pubnonce      { unsigned char data[132]; };
struct wally_musig_aggnonce      { unsigned char data[132]; };
struct wally_musig_session       { unsigned char data[133]; };
struct wally_musig_partial_sig   { unsigned char data[36];  };

/* Comparison function for qsort: lexicographic order of 33-byte compressed pubkeys */
static int musig2_keyagg_pubkey_cmp(const void *a, const void *b)
{
    return memcmp(a, b, EC_PUBLIC_KEY_LEN);
}

/* BIP-328 synthetic xpub chain code: SHA256("MuSig2MuSig2MuSig2") */
static const unsigned char MUSIG2_CHAINCODE[WALLY_MUSIG2_CHAINCODE_LEN] = {
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74,
    0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
    0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3,
    0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65
};

/* Compile-time size assertions to catch upstream secp256k1-zkp ABI changes */
typedef char assert_keyagg_cache_size[
    sizeof(secp256k1_musig_keyagg_cache) == sizeof(struct wally_musig_keyagg_cache) ? 1 : -1];
typedef char assert_secnonce_size[
    sizeof(secp256k1_musig_secnonce) == sizeof(struct wally_musig_secnonce) ? 1 : -1];
typedef char assert_pubnonce_size[
    sizeof(secp256k1_musig_pubnonce) == sizeof(struct wally_musig_pubnonce) ? 1 : -1];
typedef char assert_aggnonce_size[
    sizeof(secp256k1_musig_aggnonce) == sizeof(struct wally_musig_aggnonce) ? 1 : -1];
typedef char assert_session_size[
    sizeof(secp256k1_musig_session) == sizeof(struct wally_musig_session) ? 1 : -1];
typedef char assert_partial_sig_size[
    sizeof(secp256k1_musig_partial_sig) == sizeof(struct wally_musig_partial_sig) ? 1 : -1];

/* --- Lifecycle functions (parse/serialize/free) --- */

/* Free an opaque MuSig2 object, zeroing its contents first */
#define MUSIG_FREE(typ) \
    WALLY_CORE_API int wally_musig_ ## typ ## _free( \
        struct wally_musig_ ## typ *p) \
    { \
        if (p) \
            clear_and_free(p, sizeof(*p)); \
        return WALLY_OK; \
    }

/* Serialize an opaque MuSig2 object by copying out its raw bytes */
#define MUSIG_RAW_SERIALIZE(typ, LEN) \
    WALLY_CORE_API int wally_musig_ ## typ ## _serialize( \
        const struct wally_musig_ ## typ *p, \
        unsigned char *bytes_out, \
        size_t len) \
    { \
        if (!p || !bytes_out || len != LEN) \
            return WALLY_EINVAL; \
        memcpy(bytes_out, p->data, LEN); \
        return WALLY_OK; \
    }

/* Parse an opaque MuSig2 object via its secp256k1 parse function */
#define MUSIG_SECP_PARSE(typ, LEN) \
    WALLY_CORE_API int wally_musig_ ## typ ## _parse( \
        const unsigned char *bytes, \
        size_t bytes_len, \
        struct wally_musig_ ## typ **output) \
    { \
        const secp256k1_context *ctx = secp_ctx(); \
        secp256k1_musig_ ## typ *parsed; \
        if (!bytes || bytes_len != LEN || !output) \
            return WALLY_EINVAL; \
        *output = NULL; \
        if (!ctx) \
            return WALLY_ENOMEM; \
        if (!(parsed = wally_calloc(sizeof(*parsed)))) \
            return WALLY_ENOMEM; \
        if (!secp256k1_musig_ ## typ ## _parse(ctx, parsed, bytes)) { \
            clear_and_free(parsed, sizeof(*parsed)); \
            return WALLY_EINVAL; \
        } \
        *output = (struct wally_musig_ ## typ *)parsed; \
        return WALLY_OK; \
    }

/* Serialize an opaque MuSig2 object via its secp256k1 serialize function */
#define MUSIG_SECP_SERIALIZE(typ, LEN) \
    WALLY_CORE_API int wally_musig_ ## typ ## _serialize( \
        const struct wally_musig_ ## typ *p, \
        unsigned char *bytes_out, \
        size_t len) \
    { \
        const secp256k1_context *ctx = secp_ctx(); \
        if (!p || !bytes_out || len != LEN) \
            return WALLY_EINVAL; \
        if (!ctx) \
            return WALLY_ENOMEM; \
        if (!secp256k1_musig_ ## typ ## _serialize( \
                ctx, bytes_out, (const secp256k1_musig_ ## typ *)p)) \
            return WALLY_ERROR; \
        return WALLY_OK; \
    }

MUSIG_FREE(keyagg_cache)
MUSIG_FREE(secnonce)
MUSIG_FREE(pubnonce)
MUSIG_FREE(aggnonce)
MUSIG_FREE(session)
MUSIG_FREE(partial_sig)

MUSIG_RAW_SERIALIZE(keyagg_cache, WALLY_MUSIG_KEYAGG_CACHE_LEN)
MUSIG_RAW_SERIALIZE(session, WALLY_MUSIG_SESSION_LEN)

MUSIG_SECP_PARSE(pubnonce, WALLY_MUSIG_PUBNONCE_LEN)
MUSIG_SECP_SERIALIZE(pubnonce, WALLY_MUSIG_PUBNONCE_LEN)
MUSIG_SECP_PARSE(aggnonce, WALLY_MUSIG_AGGNONCE_LEN)
MUSIG_SECP_SERIALIZE(aggnonce, WALLY_MUSIG_AGGNONCE_LEN)
MUSIG_SECP_PARSE(partial_sig, WALLY_MUSIG_PARTIAL_SIG_LEN)
MUSIG_SECP_SERIALIZE(partial_sig, WALLY_MUSIG_PARTIAL_SIG_LEN)

WALLY_CORE_API int wally_musig_keyagg_cache_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_keyagg_cache **output)
{
    const secp256k1_context *ctx = secp_ctx();
    struct wally_musig_keyagg_cache *cache;
    secp256k1_pubkey agg_pk;

    if (!bytes || bytes_len != WALLY_MUSIG_KEYAGG_CACHE_LEN || !output)
        return WALLY_EINVAL;
    *output = NULL;
    if (!ctx)
        return WALLY_ENOMEM;
    cache = wally_calloc(sizeof(*cache));
    if (!cache)
        return WALLY_ENOMEM;
    memcpy(cache->data, bytes, WALLY_MUSIG_KEYAGG_CACHE_LEN);
    /* Validate by extracting the aggregate key. secp256k1-zkp has no full
     * validator for this struct, but this rejects a corrupted magic or
     * aggregate-key field rather than deferring the failure to signing. */
    if (!secp256k1_musig_pubkey_get(ctx, &agg_pk,
                                    (const secp256k1_musig_keyagg_cache *)cache)) {
        clear_and_free(cache, sizeof(*cache));
        return WALLY_EINVAL;
    }
    *output = cache;
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_session_parse(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_musig_session **output)
{
    struct wally_musig_session *session;

    if (!bytes || bytes_len != WALLY_MUSIG_SESSION_LEN || !output)
        return WALLY_EINVAL;
    *output = NULL;
    session = wally_calloc(sizeof(*session));
    if (!session)
        return WALLY_ENOMEM;
    memcpy(session->data, bytes, WALLY_MUSIG_SESSION_LEN);
    *output = session;
    return WALLY_OK;
}

/* --- Key aggregation functions --- */

WALLY_CORE_API int wally_musig_pubkey_agg(
    const unsigned char *pub_keys,
    size_t pub_keys_len,
    unsigned char *agg_pk_out,
    size_t agg_pk_out_len,
    struct wally_musig_keyagg_cache **cache_out)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_pubkey *pubkeys_parsed = NULL;
    const secp256k1_pubkey **pubkey_ptrs = NULL;
    secp256k1_musig_keyagg_cache *cache = NULL;
    secp256k1_xonly_pubkey xonly;
    size_t n_pubkeys, i;
    int ret = WALLY_EINVAL;

    if (!pub_keys || !pub_keys_len || pub_keys_len % EC_PUBLIC_KEY_LEN != 0)
        return WALLY_EINVAL;
    if (agg_pk_out && agg_pk_out_len != EC_XONLY_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    if (!agg_pk_out && !cache_out)
        return WALLY_EINVAL;
    if (cache_out)
        *cache_out = NULL;
    if (!ctx)
        return WALLY_ENOMEM;

    n_pubkeys = pub_keys_len / EC_PUBLIC_KEY_LEN;
    if (n_pubkeys < 2)
        return WALLY_EINVAL;

    /* Allocate the pointer and element arrays together */
    pubkey_ptrs = wally_calloc(n_pubkeys * (sizeof(*pubkey_ptrs) + sizeof(*pubkeys_parsed)));
    if (!pubkey_ptrs)
        return WALLY_ENOMEM;
    pubkeys_parsed = (secp256k1_pubkey *)(pubkey_ptrs + n_pubkeys);

    for (i = 0; i < n_pubkeys; i++) {
        if (!pubkey_parse(&pubkeys_parsed[i],
                          pub_keys + i * EC_PUBLIC_KEY_LEN,
                          EC_PUBLIC_KEY_LEN))
            goto cleanup;
        pubkey_ptrs[i] = &pubkeys_parsed[i];
    }

    if (cache_out) {
        cache = wally_calloc(sizeof(secp256k1_musig_keyagg_cache));
        if (!cache) {
            ret = WALLY_ENOMEM;
            goto cleanup;
        }
    }

    if (!secp256k1_musig_pubkey_agg(ctx,
                                    agg_pk_out ? &xonly : NULL,
                                    cache, pubkey_ptrs, n_pubkeys))
        goto cleanup;

    if (agg_pk_out)
        xpubkey_serialize(agg_pk_out, &xonly);

    if (cache_out) {
        *cache_out = (struct wally_musig_keyagg_cache *)cache;
        cache = NULL;
    }
    ret = WALLY_OK;

cleanup:
    if (cache)
        wally_free(cache);
    wally_free(pubkey_ptrs);
    return ret;
}

WALLY_CORE_API int wally_musig_pubkey_get(
    const struct wally_musig_keyagg_cache *cache,
    unsigned char *pub_key_out,
    size_t pub_key_out_len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_pubkey agg_pk;
    size_t len = EC_PUBLIC_KEY_LEN;

    if (!cache || !pub_key_out || pub_key_out_len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_pubkey_get(ctx, &agg_pk,
                                    (const secp256k1_musig_keyagg_cache *)cache))
        return WALLY_ERROR;

    pubkey_serialize(pub_key_out, &len, &agg_pk, PUBKEY_COMPRESSED);
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_pubkey_ec_tweak_add(
    struct wally_musig_keyagg_cache *cache,
    const unsigned char *tweak,
    size_t tweak_len,
    unsigned char *pub_key_out,
    size_t pub_key_out_len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_pubkey output_pk;
    size_t len = EC_PUBLIC_KEY_LEN;

    if (!cache || !tweak || tweak_len != EC_SCALAR_LEN)
        return WALLY_EINVAL;
    if (pub_key_out && pub_key_out_len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_pubkey_ec_tweak_add(ctx,
                                             pub_key_out ? &output_pk : NULL,
                                             (secp256k1_musig_keyagg_cache *)cache,
                                             tweak))
        return WALLY_ERROR;

    if (pub_key_out)
        pubkey_serialize(pub_key_out, &len, &output_pk, PUBKEY_COMPRESSED);
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_pubkey_xonly_tweak_add(
    struct wally_musig_keyagg_cache *cache,
    const unsigned char *tweak,
    size_t tweak_len,
    unsigned char *pub_key_out,
    size_t pub_key_out_len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_pubkey output_pk;
    size_t len = EC_PUBLIC_KEY_LEN;

    if (!cache || !tweak || tweak_len != EC_SCALAR_LEN)
        return WALLY_EINVAL;
    if (pub_key_out && pub_key_out_len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx,
                                                pub_key_out ? &output_pk : NULL,
                                                (secp256k1_musig_keyagg_cache *)cache,
                                                tweak))
        return WALLY_ERROR;

    if (pub_key_out)
        pubkey_serialize(pub_key_out, &len, &output_pk, PUBKEY_COMPRESSED);
    return WALLY_OK;
}

/* --- Nonce generation and aggregation functions --- */

WALLY_CORE_API int wally_musig_nonce_gen(
    const unsigned char *session_secrand32,
    size_t session_secrand32_len,
    const unsigned char *seckey,
    size_t seckey_len,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const struct wally_musig_keyagg_cache *keyagg_cache,
    const unsigned char *msg32,
    size_t msg32_len,
    const unsigned char *extra_input32,
    size_t extra_input32_len,
    struct wally_musig_secnonce **secnonce_out,
    struct wally_musig_pubnonce **pubnonce_out)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_musig_secnonce *secnonce = NULL;
    secp256k1_musig_pubnonce *pubnonce = NULL;
    secp256k1_pubkey pubkey;

    if (!session_secrand32 || session_secrand32_len != 32)
        return WALLY_EINVAL;
    if (mem_is_zero(session_secrand32, session_secrand32_len))
        return WALLY_EINVAL; /* All-zero session randomness is never valid: it must be
                              * unique and uniformly random. Reject the most common
                              * uninitialized/predictable input as defense-in-depth.
                              * The caller is still responsible for real entropy and
                              * never reusing a value across signing sessions. */
    if (BYTES_INVALID_N(seckey, seckey_len, EC_PRIVATE_KEY_LEN))
        return WALLY_EINVAL;
    if (seckey && wally_ec_private_key_verify(seckey, seckey_len) != WALLY_OK)
        return WALLY_EINVAL;
    if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    if (BYTES_INVALID_N(msg32, msg32_len, EC_MESSAGE_HASH_LEN))
        return WALLY_EINVAL;
    if (BYTES_INVALID_N(extra_input32, extra_input32_len, 32))
        return WALLY_EINVAL;
    if (!secnonce_out || !pubnonce_out)
        return WALLY_EINVAL;
    *secnonce_out = NULL;
    *pubnonce_out = NULL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (!pubkey_parse(&pubkey, pub_key, pub_key_len))
        return WALLY_EINVAL;

    secnonce = wally_calloc(sizeof(secp256k1_musig_secnonce));
    if (!secnonce)
        return WALLY_ENOMEM;

    pubnonce = wally_calloc(sizeof(secp256k1_musig_pubnonce));
    if (!pubnonce) {
        wally_free(secnonce);
        return WALLY_ENOMEM;
    }

    {
        /* secp256k1 zeroes the session randomness buffer in place to prevent
         * reuse; copy our const input into a mutable local for the call. */
        unsigned char secrand[32];
        int ok;
        wally_memcpy(secrand, session_secrand32, sizeof(secrand));
        ok = secp256k1_musig_nonce_gen(ctx, secnonce, pubnonce,
                                       secrand, seckey, &pubkey,
                                       msg32,
                                       keyagg_cache ? (const secp256k1_musig_keyagg_cache *)keyagg_cache : NULL,
                                       extra_input32);
        wally_clear(secrand, sizeof(secrand));
        if (!ok) {
            clear_and_free(secnonce, sizeof(*secnonce));
            wally_free(pubnonce);
            return WALLY_ERROR;
        }
    }

    *secnonce_out = (struct wally_musig_secnonce *)secnonce;
    *pubnonce_out = (struct wally_musig_pubnonce *)pubnonce;
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_nonce_gen_counter(
    uint64_t counter,
    const unsigned char *seckey,
    size_t seckey_len,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const struct wally_musig_keyagg_cache *keyagg_cache,
    const unsigned char *msg32,
    size_t msg32_len,
    const unsigned char *extra_input32,
    size_t extra_input32_len,
    struct wally_musig_secnonce **secnonce_out,
    struct wally_musig_pubnonce **pubnonce_out)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_musig_secnonce *secnonce = NULL;
    secp256k1_musig_pubnonce *pubnonce = NULL;
    unsigned char derived[EC_PUBLIC_KEY_LEN];
    secp256k1_keypair keypair;
    int ret;

    /* seckey is REQUIRED for counter mode */
    if (!seckey || seckey_len != EC_PRIVATE_KEY_LEN)
        return WALLY_EINVAL;
    if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    if (BYTES_INVALID_N(msg32, msg32_len, EC_MESSAGE_HASH_LEN))
        return WALLY_EINVAL;
    if (BYTES_INVALID_N(extra_input32, extra_input32_len, 32))
        return WALLY_EINVAL;
    if (!secnonce_out || !pubnonce_out)
        return WALLY_EINVAL;
    *secnonce_out = NULL;
    *pubnonce_out = NULL;
    if (!ctx)
        return WALLY_ENOMEM;

    /* Counter mode signs with the keypair derived from seckey; require that
     * the callers public key matches it to catch mismatched arguments. */
    if (wally_ec_public_key_from_private_key(seckey, seckey_len,
                                             derived, sizeof(derived)) != WALLY_OK)
        return WALLY_EINVAL;
    if (memcmp(derived, pub_key, sizeof(derived)))
        return WALLY_EINVAL;

    /* secp256k1's dedicated counter API (a low-entropy session_id would be
     * rejected by nonce_gen). */
    if (!keypair_create(&keypair, seckey))
        return WALLY_EINVAL;

    secnonce = wally_calloc(sizeof(secp256k1_musig_secnonce));
    if (!secnonce) {
        wally_clear(&keypair, sizeof(keypair));
        return WALLY_ENOMEM;
    }

    pubnonce = wally_calloc(sizeof(secp256k1_musig_pubnonce));
    if (!pubnonce) {
        wally_free(secnonce);
        wally_clear(&keypair, sizeof(keypair));
        return WALLY_ENOMEM;
    }

    ret = secp256k1_musig_nonce_gen_counter(ctx, secnonce, pubnonce,
                                            counter, &keypair, msg32,
                                            keyagg_cache ? (const secp256k1_musig_keyagg_cache *)keyagg_cache : NULL,
                                            extra_input32);
    wally_clear(&keypair, sizeof(keypair));

    if (!ret) {
        clear_and_free(secnonce, sizeof(*secnonce));
        wally_free(pubnonce);
        return WALLY_ERROR;
    }

    *secnonce_out = (struct wally_musig_secnonce *)secnonce;
    *pubnonce_out = (struct wally_musig_pubnonce *)pubnonce;
    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_nonce_agg(
    const unsigned char *pubnonces,
    size_t pubnonces_len,
    size_t n_pubnonces,
    struct wally_musig_aggnonce **aggnonce_out)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_musig_pubnonce *parsed = NULL;
    const secp256k1_musig_pubnonce **ptrs = NULL;
    secp256k1_musig_aggnonce *aggnonce = NULL;
    size_t i;
    int ret = WALLY_EINVAL;

    if (!pubnonces || n_pubnonces < 2)
        return WALLY_EINVAL;
    if (pubnonces_len != n_pubnonces * WALLY_MUSIG_PUBNONCE_LEN)
        return WALLY_EINVAL;
    if (!aggnonce_out)
        return WALLY_EINVAL;
    *aggnonce_out = NULL;
    if (!ctx)
        return WALLY_ENOMEM;

    /* Allocate the pointer and element arrays together */
    ptrs = wally_calloc(n_pubnonces * (sizeof(*ptrs) + sizeof(*parsed)));
    if (!ptrs)
        return WALLY_ENOMEM;
    parsed = (secp256k1_musig_pubnonce *)(ptrs + n_pubnonces);

    for (i = 0; i < n_pubnonces; i++) {
        if (!secp256k1_musig_pubnonce_parse(ctx, &parsed[i],
                                            pubnonces + i * WALLY_MUSIG_PUBNONCE_LEN))
            goto cleanup;
        ptrs[i] = &parsed[i];
    }

    aggnonce = wally_calloc(sizeof(secp256k1_musig_aggnonce));
    if (!aggnonce) {
        ret = WALLY_ENOMEM;
        goto cleanup;
    }

    if (!secp256k1_musig_nonce_agg(ctx, aggnonce, ptrs, n_pubnonces)) {
        ret = WALLY_ERROR;
        goto cleanup;
    }

    *aggnonce_out = (struct wally_musig_aggnonce *)aggnonce;
    aggnonce = NULL;
    ret = WALLY_OK;

cleanup:
    if (aggnonce)
        wally_free(aggnonce);
    wally_free(ptrs);
    return ret;
}

WALLY_CORE_API int wally_musig_nonce_process(
    const struct wally_musig_aggnonce *aggnonce,
    const unsigned char *msg32,
    size_t msg32_len,
    const struct wally_musig_keyagg_cache *cache,
    const unsigned char *adaptor,
    size_t adaptor_len,
    struct wally_musig_session **session_out)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_musig_session *session = NULL;
    secp256k1_pubkey adaptor_pk;
    int ret = WALLY_EINVAL;

    if (!aggnonce || !msg32 || msg32_len != 32)
        return WALLY_EINVAL;
    if (!cache || !session_out)
        return WALLY_EINVAL;
    if (adaptor && adaptor_len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    if (!adaptor && adaptor_len)
        return WALLY_EINVAL;
    *session_out = NULL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (adaptor && !pubkey_parse(&adaptor_pk, adaptor, adaptor_len))
        return WALLY_EINVAL;

    session = wally_calloc(sizeof(secp256k1_musig_session));
    if (!session)
        return WALLY_ENOMEM;

    if (!secp256k1_musig_nonce_process(ctx, session,
                                       (const secp256k1_musig_aggnonce *)aggnonce,
                                       msg32,
                                       (const secp256k1_musig_keyagg_cache *)cache,
                                       adaptor ? &adaptor_pk : NULL)) {
        ret = WALLY_ERROR;
        goto cleanup;
    }

    *session_out = (struct wally_musig_session *)session;
    session = NULL;
    ret = WALLY_OK;

cleanup:
    if (session)
        wally_free(session);
    return ret;
}

WALLY_CORE_API int wally_musig_partial_sign(
    struct wally_musig_secnonce *secnonce,
    const unsigned char *seckey,
    size_t seckey_len,
    const struct wally_musig_keyagg_cache *cache,
    const struct wally_musig_session *session,
    struct wally_musig_partial_sig **partial_sig_out)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_keypair keypair;
    secp256k1_musig_partial_sig *partial_sig = NULL;
    int ret = WALLY_EINVAL;

    if (!secnonce || !seckey || seckey_len != EC_PRIVATE_KEY_LEN)
        return WALLY_EINVAL;
    if (!cache || !session || !partial_sig_out)
        return WALLY_EINVAL;
    *partial_sig_out = NULL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (!keypair_create(&keypair, seckey)) {
        ret = WALLY_EINVAL;
        goto cleanup;
    }

    partial_sig = wally_calloc(sizeof(secp256k1_musig_partial_sig));
    if (!partial_sig) {
        ret = WALLY_ENOMEM;
        goto cleanup;
    }

    if (!secp256k1_musig_partial_sign(ctx, partial_sig,
                                      (secp256k1_musig_secnonce *)secnonce,
                                      &keypair,
                                      (const secp256k1_musig_keyagg_cache *)cache,
                                      (const secp256k1_musig_session *)session)) {
        ret = WALLY_ERROR;
        goto cleanup;
    }

    *partial_sig_out = (struct wally_musig_partial_sig *)partial_sig;
    partial_sig = NULL;
    ret = WALLY_OK;

cleanup:
    wally_clear(&keypair, sizeof(keypair));
    if (partial_sig)
        wally_free(partial_sig);
    return ret;
}

WALLY_CORE_API int wally_musig_partial_sig_verify(
    const struct wally_musig_partial_sig *sig,
    const struct wally_musig_pubnonce *pubnonce,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const struct wally_musig_keyagg_cache *cache,
    const struct wally_musig_session *session)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_pubkey pk;

    if (!sig || !pubnonce || !pub_key || pub_key_len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    if (!cache || !session)
        return WALLY_EINVAL;
    if (!ctx)
        return WALLY_ENOMEM;

    if (!pubkey_parse(&pk, pub_key, pub_key_len))
        return WALLY_EINVAL;

    if (!secp256k1_musig_partial_sig_verify(ctx,
                                            (const secp256k1_musig_partial_sig *)sig,
                                            (const secp256k1_musig_pubnonce *)pubnonce,
                                            &pk,
                                            (const secp256k1_musig_keyagg_cache *)cache,
                                            (const secp256k1_musig_session *)session))
        return WALLY_ERROR;

    return WALLY_OK;
}

WALLY_CORE_API int wally_musig_partial_sig_agg(
    const unsigned char *partial_sigs,
    size_t partial_sigs_len,
    size_t n_sigs,
    const struct wally_musig_session *session,
    unsigned char *sig64_out,
    size_t sig64_out_len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_musig_partial_sig *parsed = NULL;
    const secp256k1_musig_partial_sig **ptrs = NULL;
    size_t i;
    int ret = WALLY_EINVAL;

    if (!partial_sigs || n_sigs < 2)
        return WALLY_EINVAL;
    if (partial_sigs_len != n_sigs * WALLY_MUSIG_PARTIAL_SIG_LEN)
        return WALLY_EINVAL;
    if (!session || !sig64_out || sig64_out_len != EC_SIGNATURE_LEN)
        return WALLY_EINVAL;
    if (!ctx)
        return WALLY_ENOMEM;

    /* Allocate the pointer and element arrays together */
    ptrs = wally_calloc(n_sigs * (sizeof(*ptrs) + sizeof(*parsed)));
    if (!ptrs)
        return WALLY_ENOMEM;
    parsed = (secp256k1_musig_partial_sig *)(ptrs + n_sigs);

    for (i = 0; i < n_sigs; i++) {
        if (!secp256k1_musig_partial_sig_parse(ctx, &parsed[i],
                                               partial_sigs + i * WALLY_MUSIG_PARTIAL_SIG_LEN)) {
            ret = WALLY_EINVAL;
            goto cleanup;
        }
        ptrs[i] = &parsed[i];
    }

    if (!secp256k1_musig_partial_sig_agg(ctx, sig64_out,
                                         (const secp256k1_musig_session *)session,
                                         ptrs, n_sigs)) {
        ret = WALLY_ERROR;
        goto cleanup;
    }

    ret = WALLY_OK;

cleanup:
    wally_free(ptrs);
    return ret;
}

WALLY_CORE_API int wally_musig_pubkey_to_xpub(
    const unsigned char *agg_pk,
    size_t agg_pk_len,
    uint32_t version,
    struct ext_key **output)
{
    if (!agg_pk || agg_pk_len != EC_PUBLIC_KEY_LEN || !output)
        return WALLY_EINVAL;
    if (agg_pk[0] != 0x02 && agg_pk[0] != 0x03)
        return WALLY_EINVAL; /* Not a compressed public key */
    if (version != BIP32_VER_MAIN_PUBLIC && version != BIP32_VER_TEST_PUBLIC)
        return WALLY_EINVAL;
    *output = NULL;

    /* Construct ext_key at depth 0 with no parent, using the fixed BIP-328
     * chain code. Note BIP-328 uses the full compressed aggregate key with
     * its real parity byte, not an (implicitly even) x-only interpretation. */
    return bip32_key_init_alloc(
        version,
        0,                                            /* depth */
        0,                                            /* child_num */
        MUSIG2_CHAINCODE, WALLY_MUSIG2_CHAINCODE_LEN,
        agg_pk, EC_PUBLIC_KEY_LEN,
        NULL, 0,                                      /* no private key */
        NULL, 0,                                      /* hash160: computed from pub_key */
        NULL, 0,                                      /* parent160: zeros for root key */
        output);
}

WALLY_CORE_API int wally_musig_pubkeys_derive_then_agg(
    const unsigned char *xpubs,
    size_t xpubs_len,
    uint32_t child_num,
    unsigned char *agg_pk_out,
    size_t agg_pk_out_len,
    struct wally_musig_keyagg_cache **cache_out)
{
    unsigned char *sorted_pubkeys = NULL;
    struct ext_key hdkey, child;
    size_t n_xpubs, i;
    int ret = WALLY_EINVAL;

    if (!xpubs || xpubs_len < 2 * BIP32_SERIALIZED_LEN ||
        xpubs_len % BIP32_SERIALIZED_LEN != 0)
        return WALLY_EINVAL;
    if (child_num >= BIP32_INITIAL_HARDENED_CHILD)
        return WALLY_EINVAL;
    if (agg_pk_out && agg_pk_out_len != EC_XONLY_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    if (!agg_pk_out && !cache_out)
        return WALLY_EINVAL;

    n_xpubs = xpubs_len / BIP32_SERIALIZED_LEN;

    sorted_pubkeys = wally_malloc(n_xpubs * EC_PUBLIC_KEY_LEN);
    if (!sorted_pubkeys)
        return WALLY_ENOMEM;

    for (i = 0; i < n_xpubs; i++) {
        ret = bip32_key_unserialize(xpubs + i * BIP32_SERIALIZED_LEN,
                                    BIP32_SERIALIZED_LEN, &hdkey);
        if (ret != WALLY_OK)
            goto cleanup;

        ret = bip32_key_from_parent(&hdkey, child_num,
                                    BIP32_FLAG_KEY_PUBLIC, &child);
        if (ret != WALLY_OK)
            goto cleanup;

        memcpy(sorted_pubkeys + i * EC_PUBLIC_KEY_LEN,
               child.pub_key, EC_PUBLIC_KEY_LEN);
    }

    qsort(sorted_pubkeys, n_xpubs, EC_PUBLIC_KEY_LEN, musig2_keyagg_pubkey_cmp);

    ret = wally_musig_pubkey_agg(sorted_pubkeys, n_xpubs * EC_PUBLIC_KEY_LEN,
                                 agg_pk_out, agg_pk_out_len, cache_out);

cleanup:
    wally_clear_2(&hdkey, sizeof(hdkey), &child, sizeof(child));
    wally_free(sorted_pubkeys);
    return ret;
}

WALLY_CORE_API int wally_musig_pubkeys_agg_then_derive(
    const unsigned char *pub_keys,
    size_t pub_keys_len,
    uint32_t version,
    uint32_t child_num,
    unsigned char *pub_key_out,
    size_t pub_key_out_len,
    struct ext_key **child_out)
{
    unsigned char agg_pk[EC_PUBLIC_KEY_LEN];
    struct wally_musig_keyagg_cache *cache = NULL;
    struct ext_key *synthetic_xpub = NULL;
    struct ext_key *child = NULL;
    unsigned char *sorted = NULL;
    int ret;

    if (!pub_keys || pub_keys_len < 2 * EC_PUBLIC_KEY_LEN ||
        pub_keys_len % EC_PUBLIC_KEY_LEN != 0)
        return WALLY_EINVAL;
    if (version != BIP32_VER_MAIN_PUBLIC && version != BIP32_VER_TEST_PUBLIC)
        return WALLY_EINVAL;
    if (child_num >= BIP32_INITIAL_HARDENED_CHILD)
        return WALLY_EINVAL;
    if (!pub_key_out && !child_out)
        return WALLY_EINVAL;
    if (pub_key_out && pub_key_out_len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;

    sorted = wally_malloc(pub_keys_len);
    if (!sorted)
        return WALLY_ENOMEM;
    memcpy(sorted, pub_keys, pub_keys_len);
    qsort(sorted, pub_keys_len / EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN, musig2_keyagg_pubkey_cmp);

    ret = wally_musig_pubkey_agg(sorted, pub_keys_len, NULL, 0, &cache);
    if (ret != WALLY_OK)
        goto cleanup;

    /* Fetch the full compressed aggregate key; BIP-328 requires its parity */
    ret = wally_musig_pubkey_get(cache, agg_pk, sizeof(agg_pk));
    if (ret != WALLY_OK)
        goto cleanup;

    ret = wally_musig_pubkey_to_xpub(agg_pk, sizeof(agg_pk), version,
                                     &synthetic_xpub);
    if (ret != WALLY_OK)
        goto cleanup;

    ret = bip32_key_from_parent_alloc(synthetic_xpub, child_num,
                                      BIP32_FLAG_KEY_PUBLIC, &child);
    if (ret != WALLY_OK)
        goto cleanup;

    if (pub_key_out)
        memcpy(pub_key_out, child->pub_key, EC_PUBLIC_KEY_LEN);

    if (child_out) {
        *child_out = child;
        child = NULL;
    }

cleanup:
    if (child)
        bip32_key_free(child);
    if (synthetic_xpub)
        bip32_key_free(synthetic_xpub);
    wally_musig_keyagg_cache_free(cache);
    wally_free(sorted);
    wally_clear(agg_pk, sizeof(agg_pk));
    return ret;
}

#endif /* ndef BUILD_STANDARD_SECP */
