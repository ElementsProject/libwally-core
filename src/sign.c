#include "internal.h"
#include <include/wally_crypto.h>
#include "script_int.h"
#include "secp256k1/include/secp256k1_schnorrsig.h"
#include "ccan/ccan/build_assert/build_assert.h"

#define EC_FLAGS_TYPES (EC_FLAG_ECDSA | EC_FLAG_SCHNORR)

#define MSG_ALL_FLAGS (BITCOIN_MESSAGE_FLAG_HASH)

static const char MSG_PREFIX[] = "\x18" "Bitcoin Signed Message:\n";
static const char TAPTWEAK_BTC[] = "TapTweak";
#ifdef BUILD_ELEMENTS
static const char TAPTWEAK_ELEMENTS[] = "TapTweak/elements";
#define GET_TAPTWEAK(flags) ((flags & EC_FLAG_ELEMENTS)? TAPTWEAK_ELEMENTS : TAPTWEAK_BTC)
#else
#define GET_TAPTWEAK(flags) TAPTWEAK_BTC
#endif


/* LCOV_EXCL_START */
/* Check assumptions we expect to hold true */
static void assert_sign_assumptions(void)
{
    BUILD_ASSERT(sizeof(secp256k1_ecdsa_signature) == EC_SIGNATURE_LEN);
}
/* LCOV_EXCL_STOP */

static bool is_valid_ec_type(uint32_t flags)
{
    return ((flags & EC_FLAGS_TYPES) == EC_FLAG_ECDSA) ||
           ((flags & EC_FLAGS_TYPES) == EC_FLAG_SCHNORR);
}

int wally_ec_private_key_verify(const unsigned char *priv_key, size_t priv_key_len)
{
    const secp256k1_context *ctx = secp_ctx();

    if (!ctx)
        return WALLY_ENOMEM;

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN)
        return WALLY_EINVAL;

    return secp256k1_ec_seckey_verify(ctx, priv_key) ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_public_key_verify(const unsigned char *pub_key, size_t pub_key_len)
{
    secp256k1_pubkey pub;

    if (!pub_key ||
        !(pub_key_len == EC_PUBLIC_KEY_LEN || pub_key_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN) ||
        !pubkey_parse(&pub, pub_key, pub_key_len))
        return WALLY_EINVAL;

    wally_clear(&pub, sizeof(pub));
    return WALLY_OK;
}

int wally_ec_xonly_public_key_verify(const unsigned char *pub_key, size_t pub_key_len)
{
    secp256k1_xonly_pubkey pub;

    if (!pub_key || pub_key_len != EC_XONLY_PUBLIC_KEY_LEN ||
        !xpubkey_parse(&pub, pub_key, pub_key_len))
        return WALLY_EINVAL;

    wally_clear(&pub, sizeof(pub));
    return WALLY_OK;
}

int wally_ec_public_key_from_private_key(const unsigned char *priv_key, size_t priv_key_len,
                                         unsigned char *bytes_out, size_t len)
{
    secp256k1_pubkey pub;
    size_t len_in_out = EC_PUBLIC_KEY_LEN;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = priv_key && priv_key_len == EC_PRIVATE_KEY_LEN &&
         bytes_out && len == EC_PUBLIC_KEY_LEN &&
         pubkey_create(ctx, &pub, priv_key) &&
         pubkey_serialize(bytes_out, &len_in_out, &pub, PUBKEY_COMPRESSED) &&
         len_in_out == EC_PUBLIC_KEY_LEN;

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear(&pub, sizeof(pub));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_public_key_decompress(const unsigned char *pub_key, size_t pub_key_len,
                                   unsigned char *bytes_out, size_t len)
{
    secp256k1_pubkey pub;
    size_t len_in_out = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
    bool ok;

    ok = pub_key && pub_key_len == EC_PUBLIC_KEY_LEN &&
         bytes_out && len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN &&
         pubkey_parse(&pub, pub_key, pub_key_len) &&
         pubkey_serialize(bytes_out, &len_in_out, &pub, PUBKEY_UNCOMPRESSED) &&
         len_in_out == EC_PUBLIC_KEY_UNCOMPRESSED_LEN;

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear(&pub, sizeof(pub));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_public_key_negate(const unsigned char *pub_key, size_t pub_key_len,
                               unsigned char *bytes_out, size_t len)
{
    secp256k1_pubkey pub;
    size_t len_in_out = EC_PUBLIC_KEY_LEN;
    bool ok;

    ok = pub_key && pub_key_len == EC_PUBLIC_KEY_LEN &&
         bytes_out && len == EC_PUBLIC_KEY_LEN &&
         pubkey_parse(&pub, pub_key, pub_key_len) &&
         pubkey_negate(&pub) &&
         pubkey_serialize(bytes_out, &len_in_out, &pub, PUBKEY_COMPRESSED) &&
         len_in_out == EC_PUBLIC_KEY_LEN;

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear(&pub, sizeof(pub));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

static int get_bip341_tweak(const unsigned char *pub_key, size_t pub_key_len,
                            const unsigned char *merkle_root, uint32_t flags,
                            unsigned char *tweak, size_t tweak_len)
{
    unsigned char preimage[EC_XONLY_PUBLIC_KEY_LEN + SHA256_LEN];
    const size_t offset = pub_key_len == EC_PUBLIC_KEY_LEN ? 1 : 0;
    const size_t preimage_len = merkle_root ? sizeof(preimage) : EC_XONLY_PUBLIC_KEY_LEN;
    (void)flags;

    memcpy(preimage, pub_key + offset, EC_XONLY_PUBLIC_KEY_LEN);
    if (merkle_root)
        memcpy(preimage + EC_XONLY_PUBLIC_KEY_LEN, merkle_root, SHA256_LEN);
    return wally_bip340_tagged_hash(preimage, preimage_len,
                                    GET_TAPTWEAK(flags), tweak, tweak_len);
}

int wally_ec_public_key_bip341_tweak(
    const unsigned char *pub_key, size_t pub_key_len,
    const unsigned char *merkle_root, size_t merkle_root_len,
    uint32_t flags, unsigned char *bytes_out, size_t len)
{
    secp256k1_xonly_pubkey xonly;
    int ret;

    if (!pub_key || BYTES_INVALID_N(merkle_root, merkle_root_len, SHA256_LEN) ||
#ifdef BUILD_ELEMENTS
        (flags & ~EC_FLAG_ELEMENTS) ||
#else
        flags ||
#endif
        !bytes_out || len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;

    ret = xpubkey_parse(&xonly, pub_key, pub_key_len) ? WALLY_OK : WALLY_EINVAL;
    if (ret == WALLY_OK) {
        unsigned char tweak[SHA256_LEN];
        secp256k1_pubkey tweaked;
        size_t len_in_out = EC_PUBLIC_KEY_LEN;
        ret = get_bip341_tweak(pub_key, pub_key_len, merkle_root,
                               flags, tweak, sizeof(tweak));
        if (ret == WALLY_OK && !xpubkey_tweak_add(&tweaked, &xonly, tweak))
            ret = WALLY_ERROR;
        if (ret == WALLY_OK)
            pubkey_serialize(bytes_out, &len_in_out,
                             &tweaked, SECP256K1_EC_COMPRESSED);
    }
    return ret;
}

int wally_ec_private_key_bip341_tweak(
    const unsigned char *priv_key, size_t priv_key_len,
    const unsigned char *merkle_root, size_t merkle_root_len,
    uint32_t flags, unsigned char *bytes_out, size_t len)
{
    unsigned char tweak[SHA256_LEN];
    unsigned char pub_key[EC_XONLY_PUBLIC_KEY_LEN];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly;
    int ret;

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        BYTES_INVALID_N(merkle_root, merkle_root_len, SHA256_LEN) ||
#ifdef BUILD_ELEMENTS
        (flags & ~EC_FLAG_ELEMENTS) ||
#else
        flags ||
#endif
        !bytes_out || len != EC_PRIVATE_KEY_LEN)
        return WALLY_EINVAL;

    if (!keypair_create(&keypair, priv_key))
        return WALLY_ERROR; /* Invalid private key */

    if (!keypair_xonly_pub(&xonly, &keypair) ||
        !xpubkey_serialize(pub_key, &xonly))
        ret = WALLY_EINVAL;
    else
        ret = get_bip341_tweak(pub_key, sizeof(pub_key), merkle_root,
                               flags, tweak, sizeof(tweak));
    if (ret == WALLY_OK && (!keypair_xonly_tweak_add(&keypair, tweak) ||
        !keypair_sec(bytes_out, &keypair)))
        ret = WALLY_ERROR;
    wally_clear(&keypair, sizeof(keypair));
    return ret;
}

int wally_ec_sig_normalize(const unsigned char *sig, size_t sig_len,
                           unsigned char *bytes_out, size_t len)
{
    secp256k1_ecdsa_signature sig_secp, sig_low;
    const secp256k1_context *ctx = secp256k1_context_no_precomp;
    bool ok;

    ok = sig && sig_len == EC_SIGNATURE_LEN &&
         bytes_out && len == EC_SIGNATURE_LEN &&
         secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig);

    if (ok) {
        /* Note no error is returned, just whether the sig was changed */
        secp256k1_ecdsa_signature_normalize(ctx, &sig_low, &sig_secp);

        ok = secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out,
                                                         &sig_low);
    }

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear_2(&sig_secp, sizeof(sig_secp), &sig_low, sizeof(sig_low));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_to_der(const unsigned char *sig, size_t sig_len,
                        unsigned char *bytes_out, size_t len, size_t *written)
{
    secp256k1_ecdsa_signature sig_secp;
    size_t len_in_out = len;
    const secp256k1_context *ctx = secp256k1_context_no_precomp;
    bool ok;

    if (written)
        *written = 0;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = sig && sig_len == EC_SIGNATURE_LEN &&
         bytes_out && len >= EC_SIGNATURE_DER_MAX_LEN && written &&
         secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig) &&
         secp256k1_ecdsa_signature_serialize_der(ctx, bytes_out,
                                                 &len_in_out, &sig_secp);

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    if (ok)
        *written = len_in_out;
    wally_clear(&sig_secp, sizeof(sig_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_from_der(const unsigned char *bytes, size_t bytes_len,
                          unsigned char *bytes_out, size_t len)
{
    secp256k1_ecdsa_signature sig_secp;
    const secp256k1_context *ctx = secp256k1_context_no_precomp;
    bool ok;

    ok = bytes && bytes_len && bytes_out && len == EC_SIGNATURE_LEN &&
         secp256k1_ecdsa_signature_parse_der(ctx, &sig_secp, bytes, bytes_len) &&
         secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out, &sig_secp);

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear(&sig_secp, sizeof(sig_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_from_bytes_aux_len(const unsigned char *priv_key, size_t priv_key_len,
                                    const unsigned char *bytes, size_t bytes_len,
                                    const unsigned char *aux_rand, size_t aux_rand_len,
                                    uint32_t flags, size_t *written)
{
    if (written)
        *written = 0;
    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        BYTES_INVALID_N(aux_rand, aux_rand_len, 32) ||
        !is_valid_ec_type(flags) || flags & ~EC_FLAGS_ALL || !written)
        return WALLY_EINVAL;
    if (flags & EC_FLAG_SCHNORR) {
        if (flags & (EC_FLAG_RECOVERABLE | EC_FLAG_GRIND_R))
            return WALLY_EINVAL; /* Only ECDSA supports recoverable/grinding sigs */
    } else if (aux_rand && (flags & EC_FLAG_GRIND_R))
        return WALLY_EINVAL; /* Can't use grinding if aux_rand provided */
    *written = flags & EC_FLAG_RECOVERABLE ? EC_SIGNATURE_RECOVERABLE_LEN : EC_SIGNATURE_LEN;
    return WALLY_OK;
}

int wally_ec_sig_from_bytes_len(const unsigned char *priv_key, size_t priv_key_len,
                                const unsigned char *bytes, size_t bytes_len,
                                uint32_t flags, size_t *written)
{
    return wally_ec_sig_from_bytes_aux_len(priv_key, priv_key_len, bytes, bytes_len,
                                           NULL, 0, flags, written);
}

int wally_ec_sig_from_bytes_aux(const unsigned char *priv_key, size_t priv_key_len,
                                const unsigned char *bytes, size_t bytes_len,
                                const unsigned char *aux_rand, size_t aux_rand_len,
                                uint32_t flags, unsigned char *bytes_out, size_t len)
{
    wally_ec_nonce_t nonce_fn = wally_ops()->ec_nonce_fn;
    const secp256k1_context *ctx = secp_ctx();
    size_t expected_len;

    if (wally_ec_sig_from_bytes_aux_len(priv_key, priv_key_len,
                                        bytes, bytes_len, aux_rand, aux_rand_len,
                                        flags, &expected_len) != WALLY_OK ||
        !bytes_out || len != expected_len)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    if (flags & EC_FLAG_SCHNORR) {
        secp256k1_keypair keypair;
        int ret = WALLY_OK;
        if (!keypair_create(&keypair, priv_key))
            ret = WALLY_EINVAL;
        else if (!secp256k1_schnorrsig_sign32(ctx, bytes_out, bytes, &keypair, aux_rand))
            ret = WALLY_ERROR;
        wally_clear(&keypair, sizeof(&keypair));
        return ret;
    } else {
        unsigned char extra_entropy[32] = {0}, *entropy_p = (unsigned char *)aux_rand;
        unsigned char *bytes_out_p = flags & EC_FLAG_RECOVERABLE ? bytes_out + 1 : bytes_out;
        secp256k1_ecdsa_recoverable_signature sig_secp;
        uint32_t counter = 0;
        int recid;

        while (true) {
            if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig_secp, bytes,
                                                  priv_key, nonce_fn, entropy_p)) {
                wally_clear(&sig_secp, sizeof(sig_secp));
                if (!secp256k1_ec_seckey_verify(ctx, priv_key))
                    return WALLY_EINVAL; /* Invalid priv_key */
                return WALLY_ERROR;     /* Nonce function failed */
            }

            /* Note this function is documented as never failing */
            secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, bytes_out_p, &recid, &sig_secp);

            if (!(flags & EC_FLAG_GRIND_R) || *bytes_out_p < 0x80) {
                wally_clear(&sig_secp, sizeof(sig_secp));
                /* Note the following assumes the key is compressed */
                if (flags & EC_FLAG_RECOVERABLE)
                    bytes_out[0] = 27 + recid + 4;

                return WALLY_OK;
            }
            /* Incremement nonce to grind for low-R */
            entropy_p = extra_entropy;
            ++counter;
            uint32_to_le_bytes(counter, entropy_p);
        }
    }

}

int wally_ec_sig_from_bytes(const unsigned char *priv_key, size_t priv_key_len,
                            const unsigned char *bytes, size_t bytes_len,
                            uint32_t flags, unsigned char *bytes_out, size_t len)
{
    return wally_ec_sig_from_bytes_aux(priv_key, priv_key_len,
                                       bytes, bytes_len, NULL, 0,
                                       flags, bytes_out, len);
}

int wally_ec_sig_verify(const unsigned char *pub_key, size_t pub_key_len,
                        const unsigned char *bytes, size_t bytes_len,
                        uint32_t flags,
                        const unsigned char *sig, size_t sig_len)
{
    secp256k1_ecdsa_signature sig_secp;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!pub_key || !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !is_valid_ec_type(flags) || flags & ~EC_FLAGS_TYPES ||
        !sig || sig_len != EC_SIGNATURE_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    if (flags & EC_FLAG_SCHNORR) {
        secp256k1_xonly_pubkey xonly_pub;
        ok = xpubkey_parse(&xonly_pub, pub_key, pub_key_len);
        ok = ok && secp256k1_schnorrsig_verify(ctx, sig, bytes, bytes_len, &xonly_pub);
        wally_clear(&xonly_pub, sizeof(xonly_pub));
    } else {
        secp256k1_pubkey pub;
        if (pub_key_len != EC_PUBLIC_KEY_LEN)
            return WALLY_EINVAL;
        ok = pubkey_parse(&pub, pub_key, pub_key_len);
        ok = ok && secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig) &&
             secp256k1_ecdsa_verify(ctx, &sig_secp, bytes, &pub);
        wally_clear(&pub, sizeof(pub));
    }

    wally_clear(&sig_secp, sizeof(sig_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_to_public_key(const unsigned char *bytes, size_t bytes_len,
                               const unsigned char *sig, size_t sig_len,
                               unsigned char *bytes_out, size_t len)
{
    secp256k1_pubkey pub;
    secp256k1_ecdsa_recoverable_signature sig_secp;
    const secp256k1_context *ctx = secp_ctx();
    size_t len_in_out = EC_PUBLIC_KEY_LEN;
    int recid;
    bool ok;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !sig || sig_len != EC_SIGNATURE_RECOVERABLE_LEN ||
        !bytes_out || len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;

    recid = (sig[0] - 27) & 3;
    ok = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig_secp, &sig[1], recid) &&
         secp256k1_ecdsa_recover(ctx, &pub, &sig_secp, bytes) &&
         pubkey_serialize(bytes_out, &len_in_out, &pub, PUBKEY_COMPRESSED);

    wally_clear_2(&pub, sizeof(pub), &sig_secp, sizeof(sig_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

#define IS_SCALAR_VALID(s, s_len) (s && s_len == EC_SCALAR_LEN)

int wally_ec_scalar_verify(const unsigned char *scalar, size_t scalar_len)
{
    if (!IS_SCALAR_VALID(scalar, scalar_len))
        return WALLY_EINVAL;
    return mem_is_zero(scalar, scalar_len) || seckey_verify(scalar) ? WALLY_OK : WALLY_EINVAL;
}

static bool check_scalar_op_args(const unsigned char *scalar, size_t scalar_len,
                                 const unsigned char *operand, size_t operand_len,
                                 unsigned char *bytes_out, size_t len)
{
    if (bytes_out && len)
        wally_clear(bytes_out, len);

    return IS_SCALAR_VALID(scalar, scalar_len) &&
           IS_SCALAR_VALID(operand, operand_len) &&
           IS_SCALAR_VALID(bytes_out, len);
}

int wally_ec_scalar_add(const unsigned char *scalar, size_t scalar_len,
                        const unsigned char *operand, size_t operand_len,
                        unsigned char *bytes_out, size_t len)
{
    unsigned char tmp[EC_SCALAR_LEN];

    if (!check_scalar_op_args(scalar, scalar_len, operand, operand_len, bytes_out, len))
        return WALLY_EINVAL;

    if (mem_is_zero(operand, len)) {
        /* X + 0 = X */
        if (!mem_is_zero(scalar, scalar_len) && !seckey_verify(scalar))
            return WALLY_ERROR; /* Outside the group order */
        memcpy(bytes_out, scalar, len);
        return WALLY_OK;
    }

    if (mem_is_zero(scalar, len)) {
        /* 0 + X = X */
        if (!seckey_verify(operand))
            return WALLY_ERROR; /* Outside the group order */
        memcpy(bytes_out, operand, len);
        return WALLY_OK;
    }

    /* Check for addition of the scalars inverse */
    memcpy(tmp, operand, len);
    if (!seckey_negate(tmp))
        return WALLY_ERROR; /* Outside the group order */

    if (!memcmp(scalar, tmp, len)) {
        /* X + -X = 0 */
        return WALLY_OK; /* bytes_out zeroed above */
    }
    memcpy(bytes_out, scalar, len);
    return seckey_tweak_add(bytes_out, operand) ? WALLY_OK : WALLY_ERROR;
}

int wally_ec_scalar_add_to(unsigned char *scalar, size_t scalar_len,
                           const unsigned char *operand, size_t operand_len)
{
    unsigned char tmp[EC_SCALAR_LEN];
    int ret = wally_ec_scalar_add(scalar, scalar_len, operand, operand_len, tmp, sizeof(tmp));
    if (ret == WALLY_OK)
        memcpy(scalar, tmp, scalar_len);
    wally_clear(tmp, sizeof(tmp));
    return ret;
}

int wally_ec_scalar_subtract(const unsigned char *scalar, size_t scalar_len,
                             const unsigned char *operand, size_t operand_len,
                             unsigned char *bytes_out, size_t len)
{
    unsigned char tmp[EC_SCALAR_LEN];

    if (!check_scalar_op_args(scalar, scalar_len, operand, operand_len, bytes_out, len))
        return WALLY_EINVAL;

    if (mem_is_zero(operand, len)) {
        /* X - 0 = X */
        if (!mem_is_zero(scalar, len) && !seckey_verify(scalar))
            return WALLY_ERROR; /* Outside the group order */
        memcpy(bytes_out, scalar, len);
        return WALLY_OK;
    }

    if (mem_is_zero(scalar, len)) {
        /* 0 - X = -X */
        if (!seckey_verify(operand))
            return WALLY_ERROR; /* Outside the group order */
        memcpy(bytes_out, operand, len);
        return seckey_negate(bytes_out) ? WALLY_OK : WALLY_ERROR;
    }

    if (!memcmp(scalar, operand, len)) {
        /* X - X = 0 */
        return WALLY_OK; /* bytes_out zeroed above */
    }

    /* Implement as X + (-Y) */
    memcpy(tmp, operand, len);
    if (!seckey_negate(tmp))
        return WALLY_ERROR; /* Outside the group order */
    memcpy(bytes_out, scalar, len);
    return seckey_tweak_add(bytes_out, tmp) ? WALLY_OK : WALLY_ERROR;
}

int wally_ec_scalar_subtract_from(unsigned char *scalar, size_t scalar_len,
                                  const unsigned char *operand, size_t operand_len)
{
    unsigned char tmp[EC_SCALAR_LEN];
    int ret = wally_ec_scalar_subtract(scalar, scalar_len, operand, operand_len, tmp, sizeof(tmp));
    if (ret == WALLY_OK)
        memcpy(scalar, tmp, scalar_len);
    wally_clear(tmp, sizeof(tmp));
    return ret;
}

int wally_ec_scalar_multiply(const unsigned char *scalar, size_t scalar_len,
                             const unsigned char *operand, size_t operand_len,
                             unsigned char *bytes_out, size_t len)
{
    if (!check_scalar_op_args(scalar, scalar_len, operand, operand_len, bytes_out, len))
        return WALLY_EINVAL;

    if (mem_is_zero(operand, len)) {
        /* X * 0 = 0 */
        if (!mem_is_zero(scalar, scalar_len) && !seckey_verify(scalar))
            return WALLY_ERROR; /* Outside the group order */
        return WALLY_OK; /* bytes_out zeroed above */
    }

    if (mem_is_zero(scalar, len)) {
        /* 0 * X = 0 */
        if (!seckey_verify(operand))
            return WALLY_ERROR; /* Outside the group order */
        return WALLY_OK; /* bytes_out zeroed above */
    }

    memcpy(bytes_out, scalar, len);
    return seckey_tweak_mul(bytes_out, operand) ? WALLY_OK : WALLY_ERROR;
}

int wally_ec_scalar_multiply_by(unsigned char *scalar, size_t scalar_len,
                                const unsigned char *operand, size_t operand_len)
{
    unsigned char tmp[EC_SCALAR_LEN];
    int ret = wally_ec_scalar_multiply(scalar, scalar_len, operand, operand_len, tmp, sizeof(tmp));
    if (ret == WALLY_OK)
        memcpy(scalar, tmp, scalar_len);
    wally_clear(tmp, sizeof(tmp));
    return ret;
}

static inline size_t varint_len(size_t bytes_len) {
    return bytes_len < 0xfd ? 1u : 3u;
}

int wally_format_bitcoin_message(const unsigned char *bytes, size_t bytes_len,
                                 uint32_t flags,
                                 unsigned char *bytes_out, size_t len,
                                 size_t *written)
{
    unsigned char buf[256], *msg_buf = bytes_out, *out;
    const bool do_hash = (flags & BITCOIN_MESSAGE_FLAG_HASH);
    size_t msg_len;

    if (written)
        *written = 0;

    if (!bytes || !bytes_len || bytes_len > BITCOIN_MESSAGE_MAX_LEN ||
        (flags & ~MSG_ALL_FLAGS) || !bytes_out || !written)
        return WALLY_EINVAL;

    msg_len = sizeof(MSG_PREFIX) - 1 + varint_len(bytes_len) + bytes_len;
    *written = do_hash ? SHA256_LEN : msg_len;

    if (len < *written)
        return WALLY_OK; /* Not enough output space, return required size */

    if (do_hash) {
        /* Ensure we have a suitable temporary buffer to serialize into */
        msg_buf = buf;
        if (msg_len > sizeof(buf)) {
            msg_buf = wally_malloc(msg_len);
            if (!msg_buf) {
                *written = 0;
                return WALLY_ENOMEM;
            }
        }
    }

    /* Serialize the message */
    out = msg_buf;
    memcpy(out, MSG_PREFIX, sizeof(MSG_PREFIX) - 1);
    out += sizeof(MSG_PREFIX) - 1;
    if (bytes_len < 0xfd)
        *out++ = bytes_len;
    else {
        *out++ = 0xfd;
        *out++ = bytes_len & 0xff;
        *out++ = bytes_len >> 8;
    }
    memcpy(out, bytes, bytes_len);

    if (do_hash) {
        wally_sha256d(msg_buf, msg_len, bytes_out, SHA256_LEN);
        wally_clear(msg_buf, msg_len);
        if (msg_buf != buf)
            wally_free(msg_buf);
    }
    return WALLY_OK;
}

#ifndef BUILD_STANDARD_SECP
int wally_s2c_sig_from_bytes(const unsigned char *priv_key, size_t priv_key_len,
                             const unsigned char *bytes, size_t bytes_len,
                             const unsigned char *s2c_data, size_t s2c_data_len,
                             uint32_t flags,
                             unsigned char *s2c_opening_out, size_t s2c_opening_out_len,
                             unsigned char *bytes_out, size_t len)
{
    secp256k1_ecdsa_signature sig_secp;
    secp256k1_ecdsa_s2c_opening opening_secp;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !s2c_data || s2c_data_len != WALLY_S2C_DATA_LEN ||
        flags != EC_FLAG_ECDSA ||
        !bytes_out || len != EC_SIGNATURE_LEN ||
        !s2c_opening_out || s2c_opening_out_len != WALLY_S2C_OPENING_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!secp256k1_ecdsa_s2c_sign(ctx, &sig_secp, &opening_secp, bytes, priv_key, s2c_data)) {
        wally_clear_2(&sig_secp, sizeof(sig_secp), &opening_secp, sizeof(opening_secp));
        if (!secp256k1_ec_seckey_verify(ctx, priv_key))
            return WALLY_EINVAL; /* invalid priv_key */
        return WALLY_ERROR;     /* Nonce function failed */
    }

    ok = secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out, &sig_secp) &&
         secp256k1_ecdsa_s2c_opening_serialize(ctx, s2c_opening_out, &opening_secp);

    wally_clear_2(&sig_secp, sizeof(sig_secp), &opening_secp, sizeof(opening_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_s2c_commitment_verify(const unsigned char *sig, size_t sig_len,
                                const unsigned char *s2c_data, size_t s2c_data_len,
                                const unsigned char *s2c_opening, size_t s2c_opening_len,
                                uint32_t flags)
{
    secp256k1_ecdsa_signature sig_secp;
    secp256k1_ecdsa_s2c_opening opening_secp;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!sig || sig_len != EC_SIGNATURE_LEN ||
        !s2c_data || s2c_data_len != WALLY_S2C_DATA_LEN ||
        !s2c_opening || s2c_opening_len != WALLY_S2C_OPENING_LEN ||
        flags != EC_FLAG_ECDSA)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig) &&
         secp256k1_ecdsa_s2c_opening_parse(ctx, &opening_secp, s2c_opening) &&
         secp256k1_ecdsa_s2c_verify_commit(ctx, &sig_secp, s2c_data, &opening_secp);

    wally_clear_2(&sig_secp, sizeof(sig_secp), &opening_secp, sizeof(opening_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}
#endif /* ndef BUILD_STANDARD_SECP */
