#include "internal.h"
#ifdef BUILD_ELEMENTS
#include "script_int.h"
#include <include/wally_address.h>
#include <include/wally_bip32.h>
#include <include/wally_elements.h>
#include <include/wally_crypto.h>
#include <include/wally_symmetric.h>
#include <include/wally_transaction.h>
#include "secp256k1/include/secp256k1_generator.h"
#include "secp256k1/include/secp256k1_rangeproof.h"
#include "src/secp256k1/include/secp256k1_surjectionproof.h"
#include "src/secp256k1/include/secp256k1_whitelist.h"


static const unsigned char LABEL_STR[] = {
    'S', 'L', 'I', 'P', '-', '0', '0', '7', '7'
};

static int parse_generator(const secp256k1_context *ctx,
                           const unsigned char *generator, size_t generator_len,
                           secp256k1_generator *dest)
{
    if (!generator || generator_len != ASSET_GENERATOR_LEN ||
        !secp256k1_generator_parse(ctx, dest, generator))
        return WALLY_EINVAL;
    return WALLY_OK;
}

static int parse_commitment(const secp256k1_context *ctx,
                            const unsigned char *commitment, size_t commitment_len,
                            secp256k1_pedersen_commitment *dest)
{
    if (!commitment || commitment_len != ASSET_COMMITMENT_LEN ||
        !secp256k1_pedersen_commitment_parse(ctx, dest, commitment))
        return WALLY_EINVAL;
    return WALLY_OK;
}

int wally_ecdh_nonce_hash(const unsigned char *pub_key, size_t pub_key_len,
                          const unsigned char *priv_key, size_t priv_key_len,
                          unsigned char *bytes_out, size_t len)
{
    unsigned char nonce[SHA256_LEN];
    int ret;

    ret = wally_ecdh(pub_key, pub_key_len, priv_key, priv_key_len,
                     nonce, sizeof(nonce));
    if (ret == WALLY_OK)
        ret = wally_sha256(nonce, sizeof(nonce), bytes_out, len);
    wally_clear(nonce, sizeof(nonce));
    return ret;
}

int wally_asset_generator_from_bytes(const unsigned char *asset, size_t asset_len,
                                     const unsigned char *abf, size_t abf_len,
                                     unsigned char *bytes_out, size_t len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_generator gen;
    int secp_ret;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!asset || !bytes_out || len != ASSET_GENERATOR_LEN)
        return WALLY_EINVAL;

    if (asset_len == ASSET_COMMITMENT_LEN) {
        if (abf || abf_len)
            return WALLY_EINVAL;
        if (*asset == 1) {
            /* Explicit asset */
            secp_ret = secp256k1_generator_generate(ctx, &gen, asset + 1);
        } else if (*asset != WALLY_TX_ASSET_CT_ASSET_PREFIX_A &&
                   *asset != WALLY_TX_ASSET_CT_ASSET_PREFIX_B) {
            return WALLY_EINVAL; /* Invalid commitment prefix */
        } else {
            /* Confidential asset commitment */
            secp_ret = secp256k1_generator_parse(ctx, &gen, asset);
        }
    } else {
        if (asset_len != ASSET_TAG_LEN)
            return WALLY_EINVAL; /* Invalid asset id */
        if (abf && abf_len == BLINDING_FACTOR_LEN) {
            /* Asset tag plus blinding factor */
            secp_ret = secp256k1_generator_generate_blinded(ctx, &gen, asset, abf);
        } else if (abf || abf_len)
            return WALLY_EINVAL; /* Invalid blinding factor */
        else {
            /* Asset tag without blinding factor */
            secp_ret = secp256k1_generator_generate(ctx, &gen, asset);
        }
    }

    if (!secp_ret)
        return WALLY_ERROR; /* Invalid asset/entropy; caller should try again */

    secp256k1_generator_serialize(ctx, bytes_out, &gen); /* Never fails */
    wally_clear(&gen, sizeof(gen));
    return WALLY_OK;
}

int wally_asset_final_vbf(const uint64_t *values, size_t num_values, size_t num_inputs,
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

    if (!values || num_values < 2u ||
        num_inputs >= num_values ||
        !abf || abf_len != (num_values * BLINDING_FACTOR_LEN) ||
        !vbf || vbf_len != ((num_values - 1) * BLINDING_FACTOR_LEN) ||
        !bytes_out || len != ASSET_TAG_LEN)
        return WALLY_EINVAL;

    abf_p = wally_malloc(num_values * sizeof(unsigned char *));
    vbf_p = wally_malloc(num_values * sizeof(unsigned char *));

    if (!abf_p || !vbf_p) {
        ret = WALLY_ENOMEM;
        goto cleanup;
    }

    for (i = 0; i < num_values; i++) {
        abf_p[i] = abf + i * BLINDING_FACTOR_LEN;
        vbf_p[i] = vbf + i * BLINDING_FACTOR_LEN;
    }
    vbf_p[num_values - 1] = bytes_out;
    wally_clear(bytes_out, len);

    if (secp256k1_pedersen_blind_generator_blind_sum(ctx, values, abf_p,
                                                     (unsigned char *const *)vbf_p,
                                                     num_values, num_inputs))
        ret = WALLY_OK;

cleanup:
    clear_and_free(abf_p, num_values * sizeof(unsigned char *));
    clear_and_free(vbf_p, num_values * sizeof(unsigned char *));
    return ret;
}

int wally_asset_scalar_offset(uint64_t value,
                              const unsigned char *abf, size_t abf_len,
                              const unsigned char *vbf, size_t vbf_len,
                              unsigned char *bytes_out, size_t len)
{
    beint64_t tweak[4] = { 0, 0, 0, cpu_to_be64(value) };
    unsigned char tmp[EC_SCALAR_LEN];
    int ret;

    if (bytes_out && len)
        wally_clear(bytes_out, len);

    /* Compute value * asset_blinder + value_blinder */
    ret = wally_ec_scalar_multiply((unsigned char *)&tweak[0], sizeof(tweak),
                                   abf, abf_len, tmp, sizeof(tmp));
    if (ret == WALLY_OK)
        ret = wally_ec_scalar_add(tmp, sizeof(tmp), vbf, vbf_len, bytes_out, len);
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

    if (!vbf || vbf_len != BLINDING_FACTOR_LEN || !bytes_out || len != ASSET_COMMITMENT_LEN ||
        parse_generator(ctx, generator, generator_len, &gen) != WALLY_OK)
        return WALLY_EINVAL;

    ok = secp256k1_pedersen_commit(ctx, &commit, vbf, value, &gen) &&
         secp256k1_pedersen_commitment_serialize(ctx, bytes_out, &commit);

    wally_clear_2(&gen, sizeof(gen), &commit, sizeof(commit));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_asset_rangeproof_get_maximum_len(uint64_t value, int min_bits, size_t *written)
{
    const secp256k1_context *ctx = secp_ctx();
    if (!written)
        return WALLY_EINVAL;
    *written = 0;
    if (!ctx)
        return WALLY_ENOMEM;
    *written = secp256k1_rangeproof_max_size(ctx, value, min_bits);
    return WALLY_OK;
}

int wally_asset_rangeproof_with_nonce(uint64_t value,
                                      const unsigned char *nonce_hash, size_t nonce_hash_len,
                                      const unsigned char *asset, size_t asset_len,
                                      const unsigned char *abf, size_t abf_len,
                                      const unsigned char *vbf, size_t vbf_len,
                                      const unsigned char *commitment, size_t commitment_len,
                                      const unsigned char *extra, size_t extra_len,
                                      const unsigned char *generator, size_t generator_len,
                                      uint64_t min_value, int exp, int min_bits,
                                      unsigned char *bytes_out, size_t len,
                                      size_t *written)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_generator gen;
    secp256k1_pedersen_commitment commit;
    unsigned char message[ASSET_TAG_LEN * 2];
    const bool is_explicit = value == min_value && exp == -1 && !min_bits;
    int ret = WALLY_EINVAL;

    if (written)
        *written = 0;

    if (!ctx)
        return WALLY_ENOMEM;

    if (is_explicit) {
        if (asset || asset_len || abf || abf_len || extra || extra_len ||
            len < ASSET_EXPLICIT_RANGEPROOF_MAX_LEN)
            goto cleanup;
    } else {
        /* FIXME: Is there an upper size limit on the extra commitment? */
        if (!asset || asset_len != ASSET_TAG_LEN ||
            !abf || abf_len != BLINDING_FACTOR_LEN ||
            BYTES_INVALID(extra, extra_len) || len < ASSET_RANGEPROOF_MAX_LEN)
            goto cleanup;
    }
    if (!nonce_hash || nonce_hash_len != SHA256_LEN ||
        !vbf || vbf_len != BLINDING_FACTOR_LEN || !bytes_out || !written ||
        parse_commitment(ctx, commitment, commitment_len, &commit) != WALLY_OK ||
        min_value > 0x7ffffffffffffffful ||
        exp < -1 || exp > 18 ||
        min_bits < 0 || min_bits > 64 ||
        parse_generator(ctx, generator, generator_len, &gen) != WALLY_OK)
        goto cleanup;

    /* Create the rangeproof message */
    if (!is_explicit) {
        memcpy(message, asset, ASSET_TAG_LEN);
        memcpy(message + ASSET_TAG_LEN, abf, BLINDING_FACTOR_LEN);
    }

    *written = ASSET_RANGEPROOF_MAX_LEN;
    if (secp256k1_rangeproof_sign(ctx, bytes_out, written, min_value, &commit,
                                  vbf, nonce_hash, exp, min_bits, value,
                                  is_explicit ? NULL : message,
                                  is_explicit ? 0 : sizeof(message),
                                  extra, extra_len,
                                  &gen))
        ret = WALLY_OK;
    else {
        *written = 0;
        ret = WALLY_ERROR; /* Caller must retry with different blinding */
    }

cleanup:
    wally_clear_3(&gen, sizeof(gen), &commit, sizeof(commit),
                  message, sizeof(message));
    return ret;
}

int wally_asset_rangeproof(uint64_t value,
                           const unsigned char *pub_key, size_t pub_key_len,
                           const unsigned char *priv_key, size_t priv_key_len,
                           const unsigned char *asset, size_t asset_len,
                           const unsigned char *abf, size_t abf_len,
                           const unsigned char *vbf, size_t vbf_len,
                           const unsigned char *commitment, size_t commitment_len,
                           const unsigned char *extra, size_t extra_len,
                           const unsigned char *generator, size_t generator_len,
                           uint64_t min_value, int exp, int min_bits,
                           unsigned char *bytes_out, size_t len,
                           size_t *written)
{
    unsigned char nonce_hash[SHA256_LEN];
    int ret;

    ret = wally_ecdh_nonce_hash(pub_key, pub_key_len, priv_key, priv_key_len,
                                nonce_hash, sizeof(nonce_hash));
    if (ret == WALLY_OK)
        ret = wally_asset_rangeproof_with_nonce(value,
                                                nonce_hash, sizeof(nonce_hash),
                                                asset, asset_len,
                                                abf, abf_len,
                                                vbf, vbf_len,
                                                commitment, commitment_len,
                                                extra, extra_len,
                                                generator, generator_len,
                                                min_value, exp, min_bits,
                                                bytes_out, len, written);

    wally_clear(nonce_hash, sizeof(nonce_hash));
    return ret;
}

int wally_explicit_rangeproof(uint64_t value,
                              const unsigned char *nonce, size_t nonce_len,
                              const unsigned char *vbf, size_t vbf_len,
                              const unsigned char *commitment, size_t commitment_len,
                              const unsigned char *generator, size_t generator_len,
                              unsigned char *bytes_out, size_t len, size_t *written)
{
    return wally_asset_rangeproof_with_nonce(value, nonce, nonce_len, NULL, 0, NULL, 0,
                                             vbf, vbf_len, commitment, commitment_len, NULL, 0,
                                             generator, generator_len, value, -1, 0,
                                             bytes_out, len, written);
}

int wally_explicit_rangeproof_verify(const unsigned char *rangeproof, size_t rangeproof_len,
                                     uint64_t value,
                                     const unsigned char *commitment, size_t commitment_len,
                                     const unsigned char *generator, size_t generator_len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_pedersen_commitment commit;
    secp256k1_generator gen;
    uint64_t min_v, max_v;

    if (!rangeproof || rangeproof_len > ASSET_EXPLICIT_RANGEPROOF_MAX_LEN ||
        parse_commitment(ctx, commitment, commitment_len, &commit) != WALLY_OK ||
        parse_generator(ctx, generator, generator_len, &gen) != WALLY_OK)
        return WALLY_EINVAL;

    if (!secp256k1_rangeproof_verify(ctx, &min_v, &max_v, &commit,
                                     rangeproof, rangeproof_len, NULL, 0, &gen))
        return WALLY_EINVAL;
    return value == min_v ? WALLY_OK : WALLY_EINVAL;
}

int wally_asset_unblind_with_nonce(const unsigned char *nonce_hash, size_t nonce_hash_len,
                                   const unsigned char *proof, size_t proof_len,
                                   const unsigned char *commitment, size_t commitment_len,
                                   const unsigned char *extra, size_t extra_len,
                                   const unsigned char *generator, size_t generator_len,
                                   unsigned char *asset_out, size_t asset_out_len,
                                   unsigned char *abf_out, size_t abf_out_len,
                                   unsigned char *vbf_out, size_t vbf_out_len,
                                   uint64_t *value_out)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_generator gen;
    secp256k1_pedersen_commitment commit;
    unsigned char message[ASSET_TAG_LEN * 2];
    size_t message_len = sizeof(message);
    uint64_t min_value, max_value;
    int ret = WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!nonce_hash || nonce_hash_len != SHA256_LEN ||
        !proof || !proof_len ||
        parse_commitment(ctx, commitment, commitment_len, &commit) != WALLY_OK ||
        (extra_len && !extra) ||
        parse_generator(ctx, generator, generator_len, &gen) != WALLY_OK ||
        !asset_out || asset_out_len != ASSET_TAG_LEN ||
        !abf_out || abf_out_len != BLINDING_FACTOR_LEN ||
        !vbf_out || vbf_out_len != BLINDING_FACTOR_LEN || !value_out)
        goto cleanup;

    /* Extract the value blinding factor, value and message from the rangeproof */
    if (!secp256k1_rangeproof_rewind(ctx, vbf_out, value_out,
                                     message, &message_len,
                                     nonce_hash, &min_value, &max_value,
                                     &commit, proof, proof_len,
                                     extra, extra_len,
                                     &gen))
        goto cleanup;

    /* FIXME: check results per blind.cpp */

    /* Extract the asset id and asset blinding factor from the message */
    memcpy(asset_out, message, ASSET_TAG_LEN);
    memcpy(abf_out, message + ASSET_TAG_LEN, ASSET_TAG_LEN);
    ret = WALLY_OK;

cleanup:
    wally_clear_3(&gen, sizeof(gen), &commit, sizeof(commit),
                  message, sizeof(message));
    return ret;
}

int wally_asset_unblind(const unsigned char *pub_key, size_t pub_key_len,
                        const unsigned char *priv_key, size_t priv_key_len,
                        const unsigned char *proof, size_t proof_len,
                        const unsigned char *commitment, size_t commitment_len,
                        const unsigned char *extra, size_t extra_len,
                        const unsigned char *generator, size_t generator_len,
                        unsigned char *asset_out, size_t asset_out_len,
                        unsigned char *abf_out, size_t abf_out_len,
                        unsigned char *vbf_out, size_t vbf_out_len,
                        uint64_t *value_out)
{
    unsigned char nonce_hash[SHA256_LEN];
    int ret;

    ret = wally_ecdh_nonce_hash(pub_key, pub_key_len, priv_key, priv_key_len,
                                nonce_hash, sizeof(nonce_hash));
    if (ret == WALLY_OK)
        ret = wally_asset_unblind_with_nonce(nonce_hash, sizeof(nonce_hash),
                                             proof, proof_len,
                                             commitment, commitment_len,
                                             extra, extra_len,
                                             generator, generator_len,
                                             asset_out, asset_out_len,
                                             abf_out, abf_out_len,
                                             vbf_out, vbf_out_len,
                                             value_out);

    wally_clear(nonce_hash, sizeof(nonce_hash));
    return ret;
}

int wally_asset_surjectionproof_size(size_t num_inputs, size_t *written)
{
    size_t num_used = num_inputs > 3 ? 3 : num_inputs;
    if (written)
        *written = 0;
    if (!num_inputs || num_inputs > SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS || !written)
        return WALLY_EINVAL;
    *written = SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(num_inputs, num_used);
    return WALLY_OK;
}

static int surjproof_impl(const unsigned char *output_asset, size_t output_asset_len,
                          const unsigned char *output_abf, size_t output_abf_len,
                          const unsigned char *output_generator, size_t output_generator_len,
                          const unsigned char *bytes, size_t bytes_len,
                          const unsigned char *asset, size_t asset_len,
                          const unsigned char *abf, size_t abf_len,
                          const unsigned char *generator, size_t generator_len,
                          unsigned char *bytes_out, size_t len,
                          size_t *written, size_t n_attempts)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_generator gen;
    secp256k1_surjectionproof proof;
    secp256k1_generator *generators = NULL;
    const size_t num_inputs = asset_len / ASSET_TAG_LEN;
    const size_t num_used = num_inputs > 3 ? 3 : num_inputs;
    size_t actual_index, i;
    int ret = WALLY_EINVAL;

    if (written)
        *written = 0;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!output_asset || output_asset_len != ASSET_TAG_LEN ||
        !output_abf || output_abf_len != BLINDING_FACTOR_LEN ||
        parse_generator(ctx, output_generator, output_generator_len, &gen) != WALLY_OK ||
        !bytes || bytes_len != 32u || !asset ||
        !num_inputs || num_inputs > SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS ||
        (asset_len % ASSET_TAG_LEN != 0) ||
        !abf || abf_len != num_inputs * BLINDING_FACTOR_LEN ||
        !generator || generator_len != num_inputs * ASSET_GENERATOR_LEN ||
        !bytes_out || !len ||
        !written)
        goto cleanup;

    if (len < SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(num_inputs, num_used)) {
        /* Let the caller know the required length */
        *written = SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(num_inputs, num_used);
        ret = WALLY_OK;
        goto cleanup;
    }

    /* Build the array of input generator pointers required by secp */
    /* FIXME: This is horribly painful. Since parsed representations dont
     * currently differ from serialized, if this function took a pointer
     * to an array, all this is actually just a very convoluted cast.
     */
    if (!(generators = wally_malloc(num_inputs * sizeof(secp256k1_generator)))) {
        ret = WALLY_ENOMEM;
        goto cleanup;
    }
    for (i = 0; i < num_inputs; ++i) {
        const unsigned char *src = generator + i * ASSET_GENERATOR_LEN;
        if (parse_generator(ctx, src, ASSET_GENERATOR_LEN, &generators[i]) != WALLY_OK)
            goto cleanup;
    }

    if (!secp256k1_surjectionproof_initialize(ctx, &proof, &actual_index,
                                              (const secp256k1_fixed_asset_tag *)asset,
                                              num_inputs, num_used,
                                              (const secp256k1_fixed_asset_tag *)output_asset,
                                              n_attempts, bytes)) {
        ret = WALLY_ERROR; /* Caller must retry with different entropy/outputs */
        goto cleanup;
    }

    if (!secp256k1_surjectionproof_generate(ctx, &proof, generators, num_inputs,
                                            &gen, actual_index,
                                            abf + actual_index * BLINDING_FACTOR_LEN,
                                            output_abf)) {
        ret = WALLY_ERROR; /* Caller must retry with different entropy/outputs */
        goto cleanup;
    }

    *written = len;
    secp256k1_surjectionproof_serialize(ctx, bytes_out, written, &proof);
    ret = WALLY_OK;

cleanup:
    wally_clear_2(&gen, sizeof(gen), &proof, sizeof(proof));
    if (generators)
        clear_and_free(generators, num_inputs * sizeof(secp256k1_generator));
    return ret;
}

int wally_asset_surjectionproof_len(const unsigned char *output_asset, size_t output_asset_len,
                                    const unsigned char *output_abf, size_t output_abf_len,
                                    const unsigned char *output_generator, size_t output_generator_len,
                                    const unsigned char *bytes, size_t bytes_len,
                                    const unsigned char *asset, size_t asset_len,
                                    const unsigned char *abf, size_t abf_len,
                                    const unsigned char *generator, size_t generator_len,
                                    size_t *written)
{
    unsigned char buff[1];
    return surjproof_impl(output_asset, output_asset_len, output_abf, output_abf_len,
                          output_generator, output_generator_len, bytes, bytes_len,
                          asset, asset_len, abf, abf_len, generator, generator_len,
                          buff, sizeof(buff), written, 100);
}

int wally_asset_surjectionproof(const unsigned char *output_asset, size_t output_asset_len,
                                const unsigned char *output_abf, size_t output_abf_len,
                                const unsigned char *output_generator, size_t output_generator_len,
                                const unsigned char *bytes, size_t bytes_len,
                                const unsigned char *asset, size_t asset_len,
                                const unsigned char *abf, size_t abf_len,
                                const unsigned char *generator, size_t generator_len,
                                unsigned char *bytes_out, size_t len,
                                size_t *written)
{
    return surjproof_impl(output_asset, output_asset_len, output_abf, output_abf_len,
                          output_generator, output_generator_len, bytes, bytes_len,
                          asset, asset_len, abf, abf_len, generator, generator_len,
                          bytes_out, len, written, 100);
}

int wally_explicit_surjectionproof(const unsigned char *output_asset, size_t output_asset_len,
                                   const unsigned char *output_abf, size_t output_abf_len,
                                   const unsigned char *output_generator, size_t output_generator_len,
                                   unsigned char *bytes_out, size_t len)
{
    const secp256k1_context *ctx = secp_ctx();
    const unsigned char dummy_entropy[32] = { 0 };
    unsigned char asset_generator[ASSET_GENERATOR_LEN];
    size_t written;
    int ret;

    if (!ctx)
        return WALLY_ENOMEM;
    if (output_asset_len != ASSET_TAG_LEN || len != ASSET_EXPLICIT_SURJECTIONPROOF_LEN)
        return WALLY_EINVAL;

    ret = wally_asset_generator_from_bytes(output_asset, output_asset_len, NULL, 0,
                                           asset_generator, sizeof(asset_generator));
    if (ret == WALLY_OK)
        ret = surjproof_impl(output_asset, output_asset_len, output_abf, output_abf_len,
                             output_generator, output_generator_len,
                             dummy_entropy, sizeof(dummy_entropy),
                             output_asset, output_asset_len,
                             dummy_entropy, sizeof(dummy_entropy),
                             asset_generator, sizeof(asset_generator),
                             bytes_out, len, &written, 1);
    if (ret == WALLY_OK && written != ASSET_EXPLICIT_SURJECTIONPROOF_LEN)
        ret = WALLY_ERROR; /* Should never happen */

    wally_clear(asset_generator, sizeof(asset_generator));
    return ret;
}

int wally_explicit_surjectionproof_verify(
    const unsigned char *surjectionproof, size_t surjectionproof_len,
    const unsigned char *output_asset, size_t output_asset_len,
    const unsigned char *output_generator, size_t output_generator_len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_surjectionproof sjp;
    secp256k1_generator asset_gen, blinded_asset_gen;
    int ret = WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;
    if (surjectionproof && surjectionproof_len &&
        secp256k1_surjectionproof_parse(ctx, &sjp, surjectionproof, surjectionproof_len) &&
        output_asset && output_asset_len == ASSET_TAG_LEN &&
        secp256k1_generator_generate(ctx, &asset_gen, output_asset) &&
        parse_generator(ctx, output_generator, output_generator_len, &blinded_asset_gen) == WALLY_OK) {
        ret = secp256k1_surjectionproof_verify(ctx, &sjp, &asset_gen,
                                               1, &blinded_asset_gen) ? WALLY_OK : WALLY_ERROR;
    }
    wally_clear_3(&sjp, sizeof(sjp), &asset_gen, sizeof(asset_gen),
                  &blinded_asset_gen, sizeof(blinded_asset_gen));
    return ret;
}

int wally_confidential_addr_to_addr(
    const char *address,
    uint32_t prefix,
    char **output)
{
    unsigned char buf[2 + EC_PUBLIC_KEY_LEN + HASH160_LEN + BASE58_CHECKSUM_LEN];
    unsigned char *addr_bytes_p = &buf[EC_PUBLIC_KEY_LEN + 1];
    size_t written;
    int ret;

    if (output)
        *output = NULL;

    if (!address || !output)
        return WALLY_EINVAL;

    ret = wally_base58_to_bytes(address, BASE58_FLAG_CHECKSUM, buf, sizeof(buf), &written);
    if (ret == WALLY_OK) {
        if (written != sizeof(buf) - BASE58_CHECKSUM_LEN || buf[0] != prefix)
            ret = WALLY_EINVAL;
        else {
            /* Move the version in front of the address hash and encode it */
            addr_bytes_p[0] = buf[1];
            ret = wally_base58_from_bytes(addr_bytes_p, HASH160_LEN + 1,
                                          BASE58_FLAG_CHECKSUM, output);
        }
    }

    wally_clear(buf, sizeof(buf));
    return ret;
}

int wally_confidential_addr_to_ec_public_key(
    const char *address,
    uint32_t prefix,
    unsigned char *bytes_out,
    size_t len)
{
    unsigned char buf[2 + EC_PUBLIC_KEY_LEN + HASH160_LEN + BASE58_CHECKSUM_LEN];
    size_t written;
    int ret;

    if (!address || !bytes_out || len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;

    ret = wally_base58_to_bytes(address, BASE58_FLAG_CHECKSUM, buf, sizeof(buf), &written);
    if (ret == WALLY_OK) {
        if (written != sizeof(buf) - BASE58_CHECKSUM_LEN || buf[0] != prefix)
            ret = WALLY_EINVAL;
        else {
            /* Return the embedded public key */
            memcpy(bytes_out, buf + 2, EC_PUBLIC_KEY_LEN);
        }
    }

    wally_clear(buf, sizeof(buf));
    return ret;
}

int wally_confidential_addr_from_addr(
    const char *address,
    uint32_t prefix,
    const unsigned char *pub_key,
    size_t pub_key_len,
    char **output)
{
    unsigned char buf[2 + EC_PUBLIC_KEY_LEN + HASH160_LEN + BASE58_CHECKSUM_LEN];
    unsigned char *addr_bytes_p = &buf[EC_PUBLIC_KEY_LEN + 1];
    size_t written;
    int ret;

    if (output)
        *output = NULL;

    if (!address || (prefix & 0xffffff00) || !pub_key || pub_key_len != EC_PUBLIC_KEY_LEN || !output)
        return WALLY_EINVAL;

    /* Decode the passed address */
    ret = wally_base58_to_bytes(address, BASE58_FLAG_CHECKSUM,
                                addr_bytes_p, 1 + HASH160_LEN + BASE58_CHECKSUM_LEN, &written);
    if (ret == WALLY_OK) {
        if (written != HASH160_LEN + 1)
            ret = WALLY_EINVAL;
        else {
            /* Copy the prefix/version/pubkey and encode the address to return */
            buf[0] = prefix & 0xff;
            buf[1] = addr_bytes_p[0];
            memcpy(buf + 2, pub_key, pub_key_len);
            ret = wally_base58_from_bytes(buf, sizeof(buf) - BASE58_CHECKSUM_LEN,
                                          BASE58_FLAG_CHECKSUM, output);
        }
    }

    wally_clear(buf, sizeof(buf));
    return ret;
}

int wally_asset_blinding_key_from_seed(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len)
{
    unsigned char root[HMAC_SHA512_LEN];
    int ret;

    ret = wally_symmetric_key_from_seed(bytes, bytes_len, root, sizeof(root));
    if (ret == WALLY_OK) {
        ret = wally_symmetric_key_from_parent(root, sizeof(root), 0, LABEL_STR, sizeof(LABEL_STR),
                                              bytes_out, len);
        wally_clear(root, sizeof(root));
    }

    return ret;
}

static int asset_blinding_key_hash(
    const unsigned char *bytes, size_t bytes_len,
    const unsigned char *data, size_t data_len,
    unsigned char *bytes_out, size_t len)
{
    if (bytes && bytes_len == HMAC_SHA512_LEN) {
        /* Full blinding key: convert it to the used part (last half) */
        bytes += HMAC_SHA512_LEN / 2;
        bytes_len = HMAC_SHA512_LEN / 2;
    }
    if (!bytes || bytes_len != HMAC_SHA512_LEN / 2 || !data || !data_len ||
        !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;
    return wally_hmac_sha256(bytes, bytes_len, data, data_len, bytes_out, len);
}

int wally_asset_blinding_key_to_ec_private_key(
    const unsigned char *bytes, size_t bytes_len,
    const unsigned char *script, size_t script_len,
    unsigned char *bytes_out, size_t len)
{
    int ret = asset_blinding_key_hash(bytes, bytes_len, script, script_len, bytes_out, len);
    if (ret == WALLY_OK) {
        ret = wally_ec_private_key_verify(bytes_out, len);
        if (ret != WALLY_OK)
            wally_clear(bytes_out, len);
    }
    return ret;
}

#define BK_ABF 0x1
#define BK_VBF 0x2

int bk_to_abf_vbf_impl(
    const unsigned char *bytes, size_t bytes_len,
    const unsigned char *hash_prevouts, size_t hash_prevouts_len,
    uint32_t output_index, unsigned char *bytes_out, size_t len, uint32_t flags)
{
    unsigned char buff[SHA256_LEN];
    unsigned char msg[7] = { 0x00, 'B', 'F', 0x00, 0x00, 0x00, 0x00 };
    size_t i;
    int ret;

    if (!bytes_out || len != SHA256_LEN * (flags == (BK_ABF|BK_VBF) ? 2 : 1))
        return WALLY_EINVAL;
    ret = asset_blinding_key_hash(bytes, bytes_len,
                                  hash_prevouts, hash_prevouts_len,
                                  buff, sizeof(buff));
    if (ret == WALLY_OK) {
        uint32_to_be_bytes(output_index, msg + 3);
        for (i = BK_ABF; ret == WALLY_OK && i <= BK_VBF; ++i) {
            if (flags & i) {
                msg[0] = i == BK_ABF ? 'A' : 'V';
                ret = wally_hmac_sha256(buff, sizeof(buff), msg, sizeof(msg),
                                        bytes_out, SHA256_LEN);
                bytes_out += SHA256_LEN;
            }
        }
    }
    wally_clear(buff, sizeof(buff));
    return ret;
}

int wally_asset_blinding_key_to_abf_vbf(
    const unsigned char *bytes, size_t bytes_len,
    const unsigned char *hash_prevouts, size_t hash_prevouts_len,
    uint32_t output_index, unsigned char *bytes_out, size_t len)
{
    return bk_to_abf_vbf_impl(bytes, bytes_len, hash_prevouts, hash_prevouts_len,
                              output_index, bytes_out, len, BK_ABF | BK_VBF);
}

int wally_asset_blinding_key_to_abf(
    const unsigned char *bytes, size_t bytes_len,
    const unsigned char *hash_prevouts, size_t hash_prevouts_len,
    uint32_t output_index,
    unsigned char *bytes_out, size_t len)
{
    return bk_to_abf_vbf_impl(bytes, bytes_len, hash_prevouts, hash_prevouts_len,
                              output_index, bytes_out, len, BK_ABF);
}

int wally_asset_blinding_key_to_vbf(
    const unsigned char *bytes, size_t bytes_len,
    const unsigned char *hash_prevouts, size_t hash_prevouts_len,
    uint32_t output_index,
    unsigned char *bytes_out, size_t len)
{
    return bk_to_abf_vbf_impl(bytes, bytes_len, hash_prevouts, hash_prevouts_len,
                              output_index, bytes_out, len, BK_VBF);
}

int wally_asset_pak_whitelistproof_size(size_t num_keys, size_t *written)
{
    if (written)
        *written = 0;
    if (!written || num_keys > SECP256K1_WHITELIST_MAX_N_KEYS)
        return WALLY_EINVAL;
    *written = 1 + 32 * (1 + num_keys);
    return WALLY_OK;
}

int wally_asset_pak_whitelistproof(
    const unsigned char *online_keys, size_t online_keys_len,
    const unsigned char *offline_keys, size_t offline_keys_len,
    size_t key_index,
    const unsigned char *sub_pubkey, size_t sub_pubkey_len,
    const unsigned char *online_priv_key, size_t online_priv_key_len,
    const unsigned char *summed_key, size_t summed_key_len,
    unsigned char *bytes_out, size_t len, size_t *written)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_pubkey online_secp_keys[SECP256K1_WHITELIST_MAX_N_KEYS];
    secp256k1_pubkey offline_secp_keys[SECP256K1_WHITELIST_MAX_N_KEYS];
    secp256k1_pubkey pubkey;
    secp256k1_whitelist_signature sig;
    const size_t num_keys = offline_keys_len / EC_PUBLIC_KEY_LEN;
    size_t sig_size = (1 + 32 * (1 + num_keys));
    size_t i;
    int ret;

    if (written)
        *written = 0;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!online_keys || online_keys_len != offline_keys_len ||
        !offline_keys || !offline_keys_len ||
        offline_keys_len % EC_PUBLIC_KEY_LEN || key_index >= num_keys ||
        num_keys > SECP256K1_WHITELIST_MAX_N_KEYS ||
        !sub_pubkey || sub_pubkey_len != EC_PUBLIC_KEY_LEN ||
        !online_priv_key || online_priv_key_len != EC_PRIVATE_KEY_LEN ||
        !summed_key || summed_key_len != EC_PRIVATE_KEY_LEN ||
        !pubkey_parse(&pubkey, sub_pubkey, sub_pubkey_len) ||
        !bytes_out || !len || !written)
        return WALLY_EINVAL;

    if (len < sig_size) {
        *written = sig_size;
        return WALLY_OK; /* Tell the caller the required size */
    }

    for (i = 0; i < num_keys; ++i) {
        if (!pubkey_parse(&online_secp_keys[i], online_keys + i * EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN) ||
            !pubkey_parse(&offline_secp_keys[i], offline_keys + i * EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN)) {
            ret = WALLY_EINVAL;
            goto fail;
        }
    }

    if (secp256k1_whitelist_sign(ctx, &sig, online_secp_keys, offline_secp_keys, num_keys,
                                 &pubkey, online_priv_key, summed_key, key_index) &&
        secp256k1_whitelist_verify(ctx, &sig, online_secp_keys, offline_secp_keys, num_keys, &pubkey) &&
        secp256k1_whitelist_signature_serialize(ctx, bytes_out, &sig_size, &sig)) {
        ret = WALLY_OK;
        *written = sig_size;
    } else
        ret = WALLY_ERROR;

fail:
    wally_clear_3(online_secp_keys, sizeof(online_secp_keys),
                  offline_secp_keys, (sizeof(offline_secp_keys)),
                  &pubkey, sizeof(pubkey));
    return ret;
}

int wally_asset_pak_whitelistproof_len(
    const unsigned char *online_keys, size_t online_keys_len,
    const unsigned char *offline_keys, size_t offline_keys_len,
    size_t key_index,
    const unsigned char *sub_pubkey, size_t sub_pubkey_len,
    const unsigned char *online_priv_key, size_t online_priv_key_len,
    const unsigned char *summed_key, size_t summed_key_len,
    size_t *written)
{
    unsigned char buff[1]; /* Undersized: we only want the length */
    return wally_asset_pak_whitelistproof(online_keys, online_keys_len,
                                          offline_keys, offline_keys_len,
                                          key_index,
                                          sub_pubkey, sub_pubkey_len,
                                          online_priv_key, online_priv_key_len,
                                          summed_key, summed_key_len,
                                          buff, sizeof(buff), written);
}
#endif /* BUILD_ELEMENTS */
