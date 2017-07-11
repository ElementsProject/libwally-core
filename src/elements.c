#include "internal.h"
#include <include/wally_elements.h>
#include <include/wally_crypto.h>
#include "secp256k1/include/secp256k1_generator.h"
#include "secp256k1/include/secp256k1_rangeproof.h"
#include "src/secp256k1/include/secp256k1_surjectionproof.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include <stdbool.h>

static int get_generator(const secp256k1_context *ctx,
                         const unsigned char *generator, size_t generator_len,
                         secp256k1_generator *dest) {
    if (!generator || generator_len != ASSET_GENERATOR_LEN ||
        !secp256k1_generator_parse(ctx, dest, generator))
        return WALLY_EINVAL;
    return WALLY_OK;
}

static int get_commitment(const secp256k1_context *ctx,
                          const unsigned char *commitment, size_t commitment_len,
                          secp256k1_pedersen_commitment *dest) {
    if (!commitment || commitment_len != ASSET_COMMITMENT_LEN ||
        !secp256k1_pedersen_commitment_parse(ctx, dest, commitment))
        return WALLY_EINVAL;
    return WALLY_OK;
}

int wally_asset_generator_from_bytes(const unsigned char *asset, size_t asset_len,
                                     const unsigned char *abf, size_t abf_len,
                                     unsigned char *bytes_out, size_t len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_generator gen;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!asset || asset_len != ASSET_TAG_LEN || !abf || abf_len != ASSET_TAG_LEN ||
        !bytes_out || len != ASSET_GENERATOR_LEN)
        return WALLY_EINVAL;

    if (!secp256k1_generator_generate_blinded(ctx, &gen, asset, abf))
        return WALLY_ERROR; /* Invalid entropy; caller should try again */

    secp256k1_generator_serialize(ctx, bytes_out, &gen); /* Never fails */
    clear(&gen, sizeof(gen));
    return WALLY_OK;
}

int wally_asset_final_vbf(const uint64_t *values, size_t values_len, size_t num_inputs,
                          const unsigned char *abf, size_t abf_len,
                          const unsigned char *vbf, size_t vbf_len,
                          unsigned char *bytes_out, size_t len)
{
    const secp256k1_context *ctx = secp_ctx();
    const unsigned char **abf_p = NULL, **vbf_p = NULL;
    size_t i;
    int ret = WALLY_ERROR;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!values || values_len < 2u ||
        !abf || abf_len != (values_len * ASSET_TAG_LEN) ||
        !vbf || vbf_len != ((values_len - 1) * ASSET_TAG_LEN) ||
        !bytes_out || len != ASSET_TAG_LEN)
        return WALLY_EINVAL;

    abf_p = wally_malloc(values_len * sizeof(unsigned char *));
    vbf_p = wally_malloc(values_len * sizeof(unsigned char *));

    if (!abf_p || !vbf_p) {
        ret = WALLY_ENOMEM;
        goto cleanup;
    }

    for (i = 0; i < values_len; i++) {
        abf_p[i] = abf + i * ASSET_TAG_LEN;
        vbf_p[i] = vbf + i * ASSET_TAG_LEN;
    }
    vbf_p[values_len - 1] = bytes_out;
    clear(bytes_out, len);

    if (secp256k1_pedersen_blind_generator_blind_sum(ctx, values, abf_p,
                                                     (unsigned char *const *)vbf_p,
                                                     values_len, num_inputs))
        ret = WALLY_OK;

cleanup:
    wally_free(abf_p);
    wally_free(vbf_p);
    return ret;
}

int wally_asset_value_commitment(uint64_t value,
                                 const unsigned char *vbf, size_t vbf_len,
                                 const unsigned char *generator, size_t generator_len,
                                 unsigned char *bytes_out, size_t len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_generator gen;
    secp256k1_pedersen_commitment commit;
    bool ok;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!vbf || vbf_len != ASSET_TAG_LEN || !bytes_out || len != ASSET_COMMITMENT_LEN ||
        get_generator(ctx, generator, generator_len, &gen) != WALLY_OK)
        return WALLY_EINVAL;

    ok = secp256k1_pedersen_commit(ctx, &commit, vbf, value, &gen) &&
         secp256k1_pedersen_commitment_serialize(ctx, bytes_out, &commit);

    clear_n(2, &gen, sizeof(gen), &commit, sizeof(commit));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_asset_rangeproof(uint64_t value,
                           const unsigned char *pub_key, size_t pub_key_len,
                           const unsigned char *priv_key, size_t priv_key_len,
                           const unsigned char *asset, size_t asset_len,
                           const unsigned char *abf, size_t abf_len,
                           const unsigned char *vbf, size_t vbf_len,
                           const unsigned char *commitment, size_t commitment_len,
                           const unsigned char *extra_commit, size_t extra_commit_len,
                           const unsigned char *generator, size_t generator_len,
                           uint64_t min_value, unsigned char *bytes_out, size_t len,
                           size_t *written)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_generator gen;
    secp256k1_pubkey pub;
    secp256k1_pedersen_commitment commit;
    unsigned char nonce[32], message[ASSET_TAG_LEN * 2];
    struct sha256 nonce_sha;
    int ret = WALLY_EINVAL;

    if (written)
        *written = 0;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN ||
        !pubkey_parse(ctx, &pub, pub_key, pub_key_len) ||
        !asset || asset_len != ASSET_TAG_LEN ||
        !abf || abf_len != ASSET_TAG_LEN ||
        !vbf || vbf_len != ASSET_TAG_LEN ||
        !bytes_out || len < ASSET_RANGEPROOF_MAX_LEN || !written ||
        wally_ec_private_key_verify(priv_key, priv_key_len) != WALLY_OK ||
        get_commitment(ctx, commitment, commitment_len, &commit) != WALLY_OK ||
        /* FIXME: Is there an upper size limit on the extra commitment? */
        (extra_commit_len && !extra_commit) ||
        min_value > 0x7ffffffffffffffful ||
        get_generator(ctx, generator, generator_len, &gen) != WALLY_OK)
        goto cleanup;

    /* Create the rangeproof nonce */
    if (!secp256k1_ecdh(ctx, nonce, &pub, priv_key)) {
        /* FIXME: Only return WALLY_ERROR if this can fail while priv_key
         * passes wally_ec_private_key_verify(), otherwise return WALLY_EINVAL
         */
        ret = WALLY_ERROR;
        goto cleanup;
    }
    wally_sha256(nonce, sizeof(nonce), nonce_sha.u.u8, sizeof(nonce_sha));

    /* Create the rangeproof message */
    memcpy(message, asset, ASSET_TAG_LEN);
    memcpy(message + ASSET_TAG_LEN, abf, ASSET_TAG_LEN);

    *written = ASSET_RANGEPROOF_MAX_LEN;
    /* FIXME: This only allows 32 bit values. The caller should be able to
     * pass in the maximum value allowed */
    if (secp256k1_rangeproof_sign(ctx, bytes_out, written, min_value, &commit,
                                  vbf, nonce_sha.u.u8, 0, 32, value,
                                  message, sizeof(message),
                                  extra_commit, extra_commit_len,
                                  &gen))
        ret = WALLY_OK;
    else {
        *written = 0;
        ret = WALLY_ERROR; /* Caller must retry with different blinding */
    }

cleanup:
    clear_n(6, &gen, sizeof(gen), &pub, sizeof(pub),
            &commit, sizeof(commit),  nonce, sizeof(nonce),
            &nonce_sha, sizeof(nonce_sha), message, sizeof(message));
    return ret;
}

int wally_asset_unblind(const unsigned char *pub_key, size_t pub_key_len,
                        const unsigned char *priv_key, size_t priv_key_len,
                        const unsigned char *proof, size_t proof_len,
                        const unsigned char *commitment, size_t commitment_len,
                        const unsigned char *extra_commit, size_t extra_commit_len,
                        const unsigned char *generator, size_t generator_len,
                        unsigned char *asset_out, size_t asset_out_len,
                        unsigned char *abf_out, size_t abf_out_len,
                        unsigned char *vbf_out, size_t vbf_out_len,
                        uint64_t *value_out)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_generator gen;
    secp256k1_pubkey pub;
    secp256k1_pedersen_commitment commit;
    unsigned char nonce[32], message[ASSET_TAG_LEN * 2];
    struct sha256 nonce_sha;
    size_t message_len = sizeof(message);
    uint64_t min_value, max_value;
    int ret = WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN ||
        !pubkey_parse(ctx, &pub, pub_key, pub_key_len) ||
        wally_ec_private_key_verify(priv_key, priv_key_len) != WALLY_OK ||
        !proof || !proof_len ||
        get_commitment(ctx, commitment, commitment_len, &commit) != WALLY_OK ||
        (extra_commit_len && !extra_commit) ||
        get_generator(ctx, generator, generator_len, &gen) != WALLY_OK ||
        !asset_out || asset_out_len != ASSET_TAG_LEN ||
        !abf_out || abf_out_len != ASSET_TAG_LEN ||
        !vbf_out || vbf_out_len != ASSET_TAG_LEN || !value_out)
        goto cleanup;

    /* Create the rangeproof nonce */
    if (!secp256k1_ecdh(ctx, nonce, &pub, priv_key))
        goto cleanup;
    wally_sha256(nonce, sizeof(nonce), nonce_sha.u.u8, sizeof(nonce_sha));

    /* Extract the value blinding factor, value and message from the rangeproof */
    if (!secp256k1_rangeproof_rewind(ctx, vbf_out, value_out,
                                     message, &message_len,
                                     nonce_sha.u.u8, &min_value, &max_value,
                                     &commit, proof, proof_len,
                                     extra_commit, extra_commit_len,
                                     &gen))
        goto cleanup;

    /* FIXME: check results per blind.cpp */

    /* Extract the asset id and asset blinding factor from the message */
    memcpy(asset_out, message, ASSET_TAG_LEN);
    memcpy(abf_out, message + ASSET_TAG_LEN, ASSET_TAG_LEN);
    ret = WALLY_OK;

cleanup:
    clear_n(6, &gen, sizeof(gen), &pub, sizeof(pub),
            &commit, sizeof(commit),  nonce, sizeof(nonce),
            &nonce_sha, sizeof(nonce_sha), message, sizeof(message));
    return ret;
}

int wally_asset_surjectionproof_size(size_t num_inputs, size_t *written)
{
    size_t num_used = num_inputs > 3 ? 3 : num_inputs;
    if (written)
        *written = 0;
    if (!num_inputs || !written)
        return WALLY_EINVAL;
    *written = SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(num_inputs, num_used);
    return WALLY_OK;
}

int wally_asset_surjectionproof(const unsigned char *output_asset, size_t output_asset_len,
                                const unsigned char *output_abf, size_t output_abf_len,
                                const unsigned char *output_generator, size_t output_generator_len,
                                const unsigned char *bytes_in, size_t len_in,
                                const unsigned char *asset, size_t asset_len,
                                const unsigned char *abf, size_t abf_len,
                                const unsigned char *generator, size_t generator_len,
                                unsigned char *bytes_out, size_t len,
                                size_t *written)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_generator gen;
    secp256k1_surjectionproof proof;
    secp256k1_generator *generators = NULL;
    const size_t num_inputs = asset_len / ASSET_TAG_LEN;
    size_t num_used = num_inputs > 3 ? 3 : num_inputs;
    size_t actual_index, i;
    int ret = WALLY_EINVAL;

    if (written)
        *written = 0;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!output_asset || output_asset_len != ASSET_TAG_LEN ||
        !output_abf || output_abf_len != ASSET_TAG_LEN ||
        get_generator(ctx, output_generator, output_generator_len, &gen) != WALLY_OK ||
        !bytes_in || len_in != 32u ||
        !asset || !num_inputs || (asset_len % ASSET_TAG_LEN != 0) ||
        !abf || abf_len != num_inputs * ASSET_TAG_LEN ||
        !generator || generator_len != num_inputs * ASSET_GENERATOR_LEN ||
        !bytes_out || len != SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(num_inputs, num_used) ||
        !written)
        goto cleanup;

    /* Build the array of input generator pointers required by secp */
    /* FIXME: This is horribly painful. Since parsed representations dont
     * currently differ from serialised, if this function took a pointer
     * to an array, all this is actually just a very convoluted cast.
     */
    if (!(generators = wally_malloc(num_inputs * ASSET_GENERATOR_LEN))) {
        ret = WALLY_ENOMEM;
        goto cleanup;
    }
    for (i = 0; i < num_inputs; ++i) {
        const unsigned char *src = generator + i * ASSET_GENERATOR_LEN;
        if (get_generator(ctx, src, ASSET_GENERATOR_LEN, &generators[i]) != WALLY_OK)
            goto cleanup;
    }

    if (!secp256k1_surjectionproof_initialize(ctx, &proof, &actual_index,
                                              (const secp256k1_fixed_asset_tag *)asset,
                                              num_inputs, num_used,
                                              (const secp256k1_fixed_asset_tag *)output_asset,
                                              100, bytes_in)) {
        ret = WALLY_ERROR; /* Caller must retry with different entropy/outputs */
        goto cleanup;
    }

    if (!secp256k1_surjectionproof_generate(ctx, &proof, generators, num_inputs,
                                            &gen, actual_index,
                                            abf + actual_index * ASSET_TAG_LEN,
                                            output_abf)) {
        ret = WALLY_ERROR; /* Caller must retry with different entropy/outputs */
        goto cleanup;
    }

    *written = len;
    secp256k1_surjectionproof_serialize(ctx, bytes_out, written, &proof);
    ret = WALLY_OK;

cleanup:
    clear_n(2, &gen, sizeof(gen), &proof, sizeof(proof));
    if (generators)
        clear(generators, generator_len);
    wally_free(generators);
    return ret;
}
