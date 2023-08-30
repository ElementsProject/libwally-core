#include "internal.h"

#include <include/wally_elements.h>
#include <include/wally_script.h>
#include <include/wally_psbt.h>
#include <include/wally_psbt_members.h>

#include <limits.h>
#include "psbt_io.h"
#include "script_int.h"
#include "script.h"
#include "pullpush.h"

/* TODO:
 * - When setting utxo in an input via the psbt (in the SWIG
 *   case), check the txid matches the input (see is_matching_txid() call
 *   in the signing code).
 * - When signing, validate the existing signatures and refuse to sign if
 *   any are incorrect. This prevents others pretending to sign and then
 *   gaining our signature without having provided theirs.
 * - Signing of multisig inputs is not implemented.
 * - Change detection is not implemented, something like:
 *   wally_psbt_is_related_output(psbt, index, ext_key, written) could
 *   identify whether the given output pays to an address from ext_key.
 * - (V2) If we support adding/moving PSBT inputs, check lock time consistency
 *   when we do so.
 */

/* All allowed flags for wally_psbt_get_id() */
#define PSBT_ID_ALL_FLAGS (WALLY_PSBT_ID_AS_V2 | WALLY_PSBT_ID_USE_LOCKTIME)

/* All allowed flags for wally_psbt_from_[bytes|base64]() */
#define PSBT_ALL_PARSE_FLAGS (WALLY_PSBT_PARSE_FLAG_STRICT)

static const uint8_t PSBT_MAGIC[5] = {'p', 's', 'b', 't', 0xff};
static const uint8_t PSET_MAGIC[5] = {'p', 's', 'e', 't', 0xff};

#define MAX_INVALID_SATOSHI ((uint64_t) -1)
/* Note we mask given indices regardless of PSBT/PSET, since enormous
 * indices can never be valid on BTC either */
#define MASK_INDEX(index) ((index) & WALLY_TX_INDEX_MASK)

#define TR_MAX_MERKLE_PATH_LEN 128u

#ifdef BUILD_ELEMENTS
/* The PSET key prefix is the same as the first 4 PSET magic bytes */
#define PSET_PREFIX_LEN 4u

static bool is_pset_key(const unsigned char *key, size_t key_len)
{
    return key_len == PSET_PREFIX_LEN && !memcmp(key, PSET_MAGIC, key_len);
}

static int scalar_verify(const unsigned char *key, size_t key_len,
                         const unsigned char *val, size_t val_len)
{
    return !val && !val_len ? wally_ec_scalar_verify(key, key_len) : WALLY_EINVAL;
}
#endif /* BUILD_ELEMENTS */

static int tx_clone_alloc(const struct wally_tx *src, struct wally_tx **dst) {
    return wally_tx_clone_alloc(src, 0, dst);
}

static bool is_matching_txid(const struct wally_tx *tx,
                             const unsigned char *txid, size_t txid_len)
{
    unsigned char src_txid[WALLY_TXHASH_LEN];
    bool ret;

    if (!tx || !txid || txid_len != WALLY_TXHASH_LEN)
        return false;

    if (wally_tx_get_txid(tx, src_txid, sizeof(src_txid)) != WALLY_OK)
        return false;

    ret = memcmp(src_txid, txid, txid_len) == 0;
    wally_clear(src_txid, sizeof(src_txid));
    return ret;
}

static bool psbt_is_valid(const struct wally_psbt *psbt)
{
    if (!psbt)
        return false;
    if (psbt->version == PSBT_0) {
        /* v0 may have a tx; number of PSBT in/outputs must match */
        if ((psbt->tx ? psbt->tx->num_inputs  : 0) != psbt->num_inputs ||
            (psbt->tx ? psbt->tx->num_outputs  : 0) != psbt->num_outputs)
            return false;
    } else {
        /* v2 must not have a tx */
        if (psbt->version != PSBT_2 || psbt->tx)
            return false;
    }
    return true;
}

static bool psbt_can_modify(const struct wally_psbt *psbt, uint32_t flags)
{
    return psbt && (psbt->version == PSBT_0 || ((psbt->tx_modifiable_flags & flags) == flags));
}

#ifdef BUILD_ELEMENTS
static bool utxo_has_explicit_value(const struct wally_tx_output *utxo)
{
    return utxo && utxo->value && utxo->value_len && utxo->value[0] == 1u;
}

static bool utxo_has_explicit_asset(const struct wally_tx_output *utxo)
{
    return utxo && utxo->asset && utxo->asset_len && utxo->asset[0] == 1u;
}
#endif /* BUILD_ELEMENTS */

static struct wally_psbt_input *psbt_get_input(const struct wally_psbt *psbt, size_t index)
{
    if (!psbt || index >= psbt->num_inputs ||
        (psbt->version == PSBT_0 && (!psbt->tx || index >= psbt->tx->num_inputs)))
        return NULL;
    return &psbt->inputs[index];
 }

static struct wally_psbt_output *psbt_get_output(const struct wally_psbt *psbt, size_t index)
{
    if (!psbt || index >= psbt->num_outputs ||
        (psbt->version == PSBT_0 && (!psbt->tx || index >= psbt->tx->num_outputs)))
        return NULL;
    return &psbt->outputs[index];
}

static const struct wally_tx_output *utxo_from_input(const struct wally_psbt *psbt,
                                                     const struct wally_psbt_input *input)
{
    if (psbt && input) {
        if (input->witness_utxo)
            return input->witness_utxo;
        if (input->utxo) {
            if (psbt->version == PSBT_2 && input->index < input->utxo->num_outputs)
                return &input->utxo->outputs[input->index];
            if (psbt->tx && psbt->num_inputs == psbt->tx->num_inputs) {
                /* Get the UTXO output index from the global tx */
                size_t input_index = input - psbt->inputs;
                size_t output_index = psbt->tx->inputs[input_index].index;
                if (output_index < input->utxo->num_outputs)
                    return &input->utxo->outputs[output_index];
            }
        }
    }
    return NULL;
}

/* Try to determine if a PSBT input is taproot.
 * TODO: We could verify that the script and field checks are in sync
 * here, i.e. that an input with taproot fields has a taproot script,
 * and return an error otherwise.
 */
static bool is_taproot_input(const struct wally_psbt *psbt,
                             const struct wally_psbt_input *inp)
{
    if (!inp)
        return false;
    else {
        const struct wally_tx_output *utxo = utxo_from_input(psbt, inp);
        if (utxo) {
            /* Determine from the scriptpubkey if possible */
            size_t script_type;
            int ret = wally_scriptpubkey_get_type(utxo->script, utxo->script_len,
                                                  &script_type);
            if (ret == WALLY_OK)
                return script_type == WALLY_SCRIPT_TYPE_P2TR;
        }
        /* No usable UTXO/script for this input, check for taproot fields */
        return inp->taproot_leaf_hashes.num_items ||
               inp->taproot_leaf_scripts.num_items ||
               inp->taproot_leaf_signatures.num_items ||
               wally_map_get_integer(&inp->psbt_fields, PSBT_IN_TAP_INTERNAL_KEY) ||
               wally_map_get_integer(&inp->psbt_fields, PSBT_IN_TAP_MERKLE_ROOT) ||
               wally_map_get_integer(&inp->psbt_fields, PSBT_IN_TAP_KEY_SIG);
    }
}

/* Set a struct member on a parent struct */
#define SET_STRUCT(PARENT, NAME, STRUCT_TYPE, CLONE_FN, FREE_FN) \
    int PARENT ## _set_ ## NAME(struct PARENT *parent, const struct STRUCT_TYPE *p) { \
        int ret = WALLY_OK; \
        struct STRUCT_TYPE *new_p = NULL; \
        if (!parent) return WALLY_EINVAL; \
        if (p && (ret = CLONE_FN(p, &new_p)) != WALLY_OK) return ret; \
        FREE_FN(parent->NAME); \
        parent->NAME = new_p; \
        return ret; \
    }

/* Set/find in and add a map value member on a parent struct */
#define SET_MAP(PARENT, NAME, ADD_POST) \
    int PARENT ## _set_ ## NAME ## s(struct PARENT *parent, const struct wally_map *map_in) { \
        if (!parent) return WALLY_EINVAL; \
        return wally_map_assign(&parent->NAME ## s, map_in); \
    } \
    int PARENT ## _find_ ## NAME(struct PARENT *parent, \
                                 const unsigned char *key, size_t key_len, \
                                 size_t *written) { \
        if (written) *written = 0; \
        if (!parent) return WALLY_EINVAL; \
        return wally_map_find(&parent->NAME ## s, key, key_len, written); \
    } \
    int PARENT ## _add_ ## NAME ## ADD_POST(struct PARENT *parent, \
                                            const unsigned char *key, size_t key_len, \
                                            const unsigned char *value, size_t value_len) { \
        if (!parent) return WALLY_EINVAL; \
        return wally_map_add(&parent->NAME ## s, key, key_len, value, value_len); \
    }

/* Add a keypath to parent structs keypaths member */
#define ADD_KEYPATH(PARENT) \
    int PARENT ## _keypath_add(struct PARENT *parent, \
                               const unsigned char *pub_key, size_t pub_key_len, \
                               const unsigned char *fingerprint, size_t fingerprint_len, \
                               const uint32_t *child_path, size_t child_path_len) { \
        if (!parent) return WALLY_EINVAL; \
        return wally_map_keypath_add(&parent->keypaths, pub_key, pub_key_len, \
                                     fingerprint, fingerprint_len, \
                                     child_path, child_path_len); \
    }

/* Add a taproot keypath to parent structs keypaths member */
#define ADD_TAP_KEYPATH(PARENT) \
    int PARENT ## _taproot_keypath_add(struct PARENT *parent, \
                                       const unsigned char *pub_key, size_t pub_key_len, \
                                       const unsigned char *tapleaf_hashes, size_t tapleaf_hashes_len, \
                                       const unsigned char *fingerprint, size_t fingerprint_len, \
                                       const uint32_t *child_path, size_t child_path_len) { \
        int ret; \
        if (!parent) return WALLY_EINVAL; \
        ret = wally_merkle_path_xonly_public_key_verify(pub_key, pub_key_len, tapleaf_hashes, tapleaf_hashes_len); \
        if (ret == WALLY_OK) \
            ret = wally_map_keypath_add(&parent->taproot_leaf_paths, \
                                         pub_key, pub_key_len, \
                                         fingerprint, fingerprint_len, \
                                         child_path, child_path_len); \
        if (ret == WALLY_OK) \
            ret = wally_map_merkle_path_add(&parent->taproot_leaf_hashes, \
                                            pub_key, pub_key_len, \
                                            tapleaf_hashes, tapleaf_hashes_len); \
        return ret; \
    }

static int map_field_get_len(const struct wally_map *map_in,
                             uint32_t type, size_t *written)
{
    size_t index;
    int ret;

    if (written)
        *written = 0;
    if (!map_in || !written)
        return WALLY_EINVAL;
    ret = wally_map_find_integer(map_in, type, &index);
    if (ret == WALLY_OK && index)
        *written = map_in->items[index - 1].value_len; /* Found */
    return ret;
}

static int map_field_get(const struct wally_map *map_in, uint32_t type,
                         unsigned char *bytes_out, size_t len,
                         size_t *written)
{
    size_t index;
    int ret;

    if (written)
        *written = 0;
    if (!map_in || !bytes_out || !written)
        return WALLY_EINVAL;
    ret = wally_map_find_integer(map_in, type, &index);
    if (ret == WALLY_OK && index) {
        /* Found */
        const struct wally_map_item *item = map_in->items + index - 1;
        *written = item->value_len;
        if (len >= item->value_len)
            memcpy(bytes_out, item->value, item->value_len);
    }
    return ret;
}

static int map_field_set(struct wally_map *map_in, uint32_t type,
                         const unsigned char *val, size_t val_len)
{
    if (!map_in || BYTES_INVALID(val, val_len))
        return WALLY_EINVAL;

    if (!val)
        return wally_map_remove_integer(map_in, type);
    return wally_map_replace_integer(map_in, type, val, val_len);
}

/* Methods for a binary buffer field from a PSET input/output */
#define MAP_INNER_FIELD(typ, name, FT, mapname) \
    int wally_psbt_ ## typ ## _get_ ## name ## _len(const struct wally_psbt_ ## typ *p, \
                                                    size_t * written) { \
        return map_field_get_len(p ? &p->mapname : NULL, FT, written); \
    } \
    int wally_psbt_ ## typ ## _get_ ## name(const struct wally_psbt_ ## typ *p, \
                                            unsigned char *bytes_out, size_t len, size_t * written) { \
        return map_field_get(p ? &p->mapname : NULL, FT, bytes_out, len, written); \
    } \
    int wally_psbt_ ## typ ## _clear_ ## name(struct wally_psbt_ ## typ *p) { \
        return wally_map_remove_integer(p ? &p->mapname : NULL, FT); \
    } \
    int wally_psbt_ ## typ ## _set_ ## name(struct wally_psbt_ ## typ *p, \
                                            const unsigned char *value, size_t value_len) { \
        return map_field_set(p ? &p->mapname : NULL, FT, value, value_len); \
    }

int wally_psbt_input_is_finalized(const struct wally_psbt_input *input,
                                  size_t *written)
{
    if (written)
        *written = 0;
    if (!input || !written)
        return WALLY_EINVAL;
    if (input->final_witness ||
        wally_map_get_integer(&input->psbt_fields, PSBT_IN_FINAL_SCRIPTSIG))
        *written = 1;
    return WALLY_OK;
}

SET_STRUCT(wally_psbt_input, utxo, wally_tx,
           tx_clone_alloc, wally_tx_free)
int wally_psbt_input_set_witness_utxo(struct wally_psbt_input *input, const struct wally_tx_output *utxo)
{
    int ret = WALLY_OK;
    struct wally_tx_output *new_utxo = NULL;
    if (!input)
        return WALLY_EINVAL;
#ifdef BUILD_ELEMENTS
    if (input->has_amount && utxo_has_explicit_value(utxo))
        return WALLY_EINVAL; /* UTXO value is already explicit */
#endif
    if (utxo && (ret = wally_tx_output_clone_alloc(utxo, &new_utxo)) != WALLY_OK)
        return ret;
    wally_tx_output_free(input->witness_utxo);
    input->witness_utxo = new_utxo;
    return ret;
}

int wally_psbt_input_set_witness_utxo_from_tx(struct wally_psbt_input *input,
                                              const struct wally_tx *utxo, uint32_t index)
{
    if (!utxo || index >= utxo->num_outputs)
        return WALLY_EINVAL;
    return wally_psbt_input_set_witness_utxo(input, utxo->outputs + index);
}
MAP_INNER_FIELD(input, redeem_script, PSBT_IN_REDEEM_SCRIPT, psbt_fields)
MAP_INNER_FIELD(input, witness_script, PSBT_IN_WITNESS_SCRIPT, psbt_fields)
MAP_INNER_FIELD(input, final_scriptsig, PSBT_IN_FINAL_SCRIPTSIG, psbt_fields)
MAP_INNER_FIELD(input, taproot_signature, PSBT_IN_TAP_KEY_SIG, psbt_fields)
SET_STRUCT(wally_psbt_input, final_witness, wally_tx_witness_stack,
           wally_tx_witness_stack_clone_alloc, wally_tx_witness_stack_free)
SET_MAP(wally_psbt_input, keypath,)
ADD_KEYPATH(wally_psbt_input)
ADD_TAP_KEYPATH(wally_psbt_input)
SET_MAP(wally_psbt_input, signature, _internal)
int wally_psbt_input_add_signature(struct wally_psbt_input *input,
                                   const unsigned char *pub_key, size_t pub_key_len,
                                   const unsigned char *sig, size_t sig_len)
{
    if (input && sig && sig_len) {
        const unsigned char sighash = sig[sig_len - 1];
        if (!sighash || (input->sighash && input->sighash != sighash))
            return WALLY_EINVAL; /* Incompatible sighash */
    }
    return wally_psbt_input_add_signature_internal(input, pub_key, pub_key_len,
                                                   sig, sig_len);
}
SET_MAP(wally_psbt_input, unknown,)
int wally_psbt_input_set_previous_txid(struct wally_psbt_input *input,
                                       const unsigned char *txhash, size_t len)
{
    if (!input || BYTES_INVALID_N(txhash, len, WALLY_TXHASH_LEN))
        return WALLY_EINVAL;
    if (txhash)
        memcpy(input->txhash, txhash, WALLY_TXHASH_LEN);
    else
        wally_clear(input->txhash, WALLY_TXHASH_LEN);
    return WALLY_OK;
}

int wally_psbt_input_set_sighash(struct wally_psbt_input *input, uint32_t sighash)
{
    size_t i;

    if (!input)
        return WALLY_EINVAL;
    /* Note we do not skip this check if sighash == input->sighash.
     * This is because we set the loaded value again after reading a PSBT
     * input, in order to ensure the loaded signatures are compatible with
     * it (since they can be read in any order).
     */
    if (sighash) {
        for (i = 0; i < input->signatures.num_items; ++i) {
            const struct wally_map_item *item = &input->signatures.items[i];
            if (!item->value || !item->value_len ||
                sighash != item->value[item->value_len - 1]) {
                /* Cannot set a sighash that is incompatible with existing sigs */
                return WALLY_EINVAL;
            }
        }
    }
    input->sighash = sighash;
    return WALLY_OK;
}

int wally_psbt_input_set_output_index(struct wally_psbt_input *input, uint32_t index)
{
    if (!input)
        return WALLY_EINVAL;
    /* The PSBT index ignores any elements issuance/pegin flags */
    input->index = MASK_INDEX(index);
    return WALLY_OK;
}

int wally_psbt_input_set_sequence(struct wally_psbt_input *input, uint32_t sequence)
{
    if (!input)
        return WALLY_EINVAL;
    input->sequence = sequence;
    return WALLY_OK;
}

int wally_psbt_input_clear_sequence(struct wally_psbt_input *input)
{
    return wally_psbt_input_set_sequence(input, WALLY_TX_SEQUENCE_FINAL);
}

int wally_psbt_input_set_required_locktime(struct wally_psbt_input *input, uint32_t locktime)
{
    if (!input || !locktime || locktime < PSBT_LOCKTIME_MIN_TIMESTAMP)
        return WALLY_EINVAL;
    input->required_locktime = locktime;
    return WALLY_OK;
}

int wally_psbt_input_clear_required_locktime(struct wally_psbt_input *input)
{
    if (!input)
        return WALLY_EINVAL;
    input->required_locktime = 0;
    return WALLY_OK;
}

int wally_psbt_input_set_required_lockheight(struct wally_psbt_input *input, uint32_t lockheight)
{
    if (!input || !lockheight || lockheight >= PSBT_LOCKTIME_MIN_TIMESTAMP)
        return WALLY_EINVAL;
    input->required_lockheight = lockheight;
    return WALLY_OK;
}

int wally_psbt_input_clear_required_lockheight(struct wally_psbt_input *input)
{
    if (!input)
        return WALLY_EINVAL;
    input->required_lockheight = 0;
    return WALLY_OK;
}

/* Verify a DER encoded ECDSA sig plus sighash byte */
static int der_sig_verify(const unsigned char *der, size_t der_len)
{
    unsigned char sig[EC_SIGNATURE_LEN];
    if (der_len)
        return wally_ec_sig_from_der(der, der_len - 1, sig, sizeof(sig));
    return WALLY_EINVAL;
}

static int pubkey_sig_verify(const unsigned char *key, size_t key_len,
                             const unsigned char *val, size_t val_len)
{
    int ret = wally_ec_public_key_verify(key, key_len);
    if (ret == WALLY_OK)
        ret = der_sig_verify(val, val_len);
    return ret;
}

static int map_leaf_hashes_verify(const unsigned char *key, size_t key_len,
                                  const unsigned char *val, size_t val_len)
{
    int ret = wally_ec_xonly_public_key_verify(key, key_len);
    if (ret == WALLY_OK) {
        if (BYTES_INVALID(val, val_len) || (val_len && val_len % SHA256_LEN) ||
            val_len > TR_MAX_MERKLE_PATH_LEN * SHA256_LEN)
            ret = WALLY_EINVAL;
    }
    return ret;
}

static int psbt_input_field_verify(uint32_t field_type,
                                   const unsigned char *val, size_t val_len)
{
    if (val) {
        switch (field_type) {
        case PSBT_IN_REDEEM_SCRIPT:
        case PSBT_IN_WITNESS_SCRIPT:
        case PSBT_IN_FINAL_SCRIPTSIG:
        case PSBT_IN_POR_COMMITMENT:
            /* Scripts, or UTF-8 proof of reserves message */
            return val_len ? WALLY_OK : WALLY_EINVAL;
        case PSBT_IN_TAP_KEY_SIG:
            /* 64 or 65 byte Schnorr signature TODO: Add constants */
            return val_len == 64 || val_len == 65 ? WALLY_OK : WALLY_EINVAL;
        case PSBT_IN_TAP_INTERNAL_KEY:
        case PSBT_IN_TAP_MERKLE_ROOT:
            /* 32 byte x-only pubkey, or 32 byte merkle hash */
            return val_len == SHA256_LEN ? WALLY_OK : WALLY_EINVAL;
        default:
            break;
        }
    }
    return WALLY_EINVAL;
}

static int psbt_map_input_field_verify(const unsigned char *key, size_t key_len,
                                       const unsigned char *val, size_t val_len)
{
    return key ? WALLY_EINVAL : psbt_input_field_verify(key_len, val, val_len);
}

static int psbt_output_field_verify(uint32_t field_type,
                                    const unsigned char *val, size_t val_len)
{
    switch (field_type) {
    case PSBT_OUT_REDEEM_SCRIPT:
    case PSBT_OUT_WITNESS_SCRIPT:
        /* Scripts */
        return val_len ? WALLY_OK : WALLY_EINVAL;
    case PSBT_OUT_TAP_INTERNAL_KEY:
        /* 32 byte x-only pubkey */
        return val && val_len == SHA256_LEN ? WALLY_OK : WALLY_EINVAL;
    case PSBT_OUT_TAP_TREE:
        /* FIXME: validate the tree is in the expected encoded format */
        return val && val_len >= 4 ? WALLY_OK : WALLY_EINVAL;
    default:
        break;
    }
    return WALLY_EINVAL;
}

static int psbt_map_output_field_verify(const unsigned char *key, size_t key_len,
                                        const unsigned char *val, size_t val_len)
{
    return key ? WALLY_EINVAL : psbt_output_field_verify(key_len, val, val_len);
}

#ifdef BUILD_ELEMENTS
static int pset_input_field_verify(uint32_t field_type,
                                   const unsigned char *val, size_t val_len)
{
    if (!val || !val_len)
        return WALLY_EINVAL;
    switch (field_type) {
    case PSET_IN_ISSUANCE_VALUE_COMMITMENT:
    case PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT:
        /* 33 byte commitments */
        if (confidential_value_length_from_bytes(val) != WALLY_TX_ASSET_CT_LEN)
            return WALLY_EINVAL;
        break;
    case PSET_IN_ISSUANCE_VALUE_RANGEPROOF:
    case PSET_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF:
    case PSET_IN_PEG_IN_TXOUT_PROOF:
    case PSET_IN_PEG_IN_CLAIM_SCRIPT:
    case PSET_IN_UTXO_RANGEPROOF:
    case PSET_IN_ISSUANCE_BLIND_VALUE_PROOF:
    case PSET_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF:
    case PSET_IN_VALUE_PROOF:
    case PSET_IN_ASSET_PROOF:
        /* Byte sequences of varying lengths */
        break;
    case PSET_IN_PEG_IN_GENESIS_HASH:
    case PSET_IN_ISSUANCE_BLINDING_NONCE:
    case PSET_IN_ISSUANCE_ASSET_ENTROPY:
    case PSET_IN_EXPLICIT_ASSET:
        /* 32 byte hash, entropy, or asset */
        if (val_len != SHA256_LEN)
            return WALLY_EINVAL;
        break;
    default:
        return WALLY_EINVAL;
    }
    return WALLY_OK;
}

static int pset_map_input_field_verify(const unsigned char *key, size_t key_len,
                                       const unsigned char *val, size_t val_len)
{
    return key ? WALLY_EINVAL : pset_input_field_verify(key_len, val, val_len);
}

static int pset_output_field_verify(uint32_t field_type,
                                    const unsigned char *val, size_t val_len)
{
    size_t len;
    if (!val || !val_len)
        return WALLY_EINVAL;
    switch (field_type) {
    case PSET_OUT_ASSET:
        /* 32 byte asset id */
        if (val_len != ASSET_TAG_LEN)
            return WALLY_EINVAL;
        break;
    case PSET_OUT_VALUE_COMMITMENT:
        len = confidential_value_length_from_bytes(val);
        if (len != WALLY_TX_ASSET_CT_VALUE_LEN && len != WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN)
            return WALLY_EINVAL;
        break;
    case PSET_OUT_ASSET_COMMITMENT:
        /* 33 byte commitments */
        if (confidential_asset_length_from_bytes(val) != WALLY_TX_ASSET_CT_LEN)
            return WALLY_EINVAL;
        break;
    case PSET_OUT_BLINDING_PUBKEY:
    case PSET_OUT_ECDH_PUBKEY:
        /* 33 byte compressed pubkeys */
        if (val_len != EC_PUBLIC_KEY_LEN)
            return WALLY_EINVAL; /* Uncompressed keys are not allowed */
        return wally_ec_public_key_verify(val, val_len);
        break;
    case PSET_OUT_VALUE_RANGEPROOF:
    case PSET_OUT_ASSET_SURJECTION_PROOF:
    case PSET_OUT_BLIND_VALUE_PROOF:
    case PSET_OUT_BLIND_ASSET_PROOF:
        /* Byte sequences of varying lengths */
        break;
    default:
        return WALLY_EINVAL;
    }
    return WALLY_OK;
}

static int pset_map_output_field_verify(const unsigned char *key, size_t key_len,
                                        const unsigned char *val, size_t val_len)
{
    return key ? WALLY_EINVAL : pset_output_field_verify(key_len, val, val_len);
}

int wally_psbt_input_set_amount(struct wally_psbt_input *input, uint64_t amount)
{
    if (!input)
        return WALLY_EINVAL;
    if (utxo_has_explicit_value(input->witness_utxo))
        return WALLY_EINVAL; /* UTXO value is already explicit */
    input->amount = amount;
    input->has_amount = 1u;
    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
int wally_psbt_input_generate_explicit_proofs(
    struct wally_psbt_input *input,
    uint64_t satoshi,
    const unsigned char *asset, size_t asset_len,
    const unsigned char *abf, size_t abf_len,
    const unsigned char *vbf, size_t vbf_len,
    const unsigned char *entropy, size_t entropy_len)
{
    const struct wally_tx_output *utxo = input ? input->witness_utxo : 0;
    unsigned char proof[ASSET_SURJECTIONPROOF_MAX_LEN]; /* > ASSET_EXPLICIT_RANGEPROOF_MAX_LEN */
    size_t proof_len;
    int ret;

    if (!utxo || utxo_has_explicit_value(utxo) || utxo_has_explicit_asset(utxo))
        return WALLY_EINVAL; /* No UTXO, or UTXO value/asset already explicit */

    /* Generate the explicit proofs and set them in the input */
    ret = wally_explicit_rangeproof(satoshi, entropy, entropy_len,
                                    vbf, vbf_len,
                                    utxo->value, utxo->value_len,
                                    utxo->asset, utxo->asset_len,
                                    proof, sizeof(proof), &proof_len);
    if (ret == WALLY_OK) {
        if (proof_len > sizeof(proof))
            ret = WALLY_ERROR; /* Should never happen */
        else
            ret = wally_psbt_input_set_amount_rangeproof(input, proof, proof_len);
        if (ret == WALLY_OK)
            ret = wally_psbt_input_set_amount(input, satoshi);
    }
    if (ret == WALLY_OK) {
        proof_len = ASSET_EXPLICIT_SURJECTIONPROOF_LEN;
        ret = wally_explicit_surjectionproof(asset, asset_len,
                                             abf, abf_len,
                                             utxo->asset, utxo->asset_len,
                                             proof, proof_len);
    }
    if (ret == WALLY_OK) {
        ret = wally_psbt_input_set_asset_surjectionproof(input, proof, proof_len);
        if (ret == WALLY_OK)
            ret = wally_psbt_input_set_asset(input, asset, asset_len);
    }

    if (ret != WALLY_OK) {
        input->amount = 0;
        input->has_amount = 0;
        wally_psbt_input_clear_amount_rangeproof(input);
        wally_psbt_input_clear_asset(input);
        wally_psbt_input_clear_asset_surjectionproof(input);
    }
    wally_clear(proof, sizeof(proof));
    return ret;
}
#endif /* BUILD_ELEMENTS */

int wally_psbt_input_clear_amount(struct wally_psbt_input *input)
{
    if (!input)
        return WALLY_EINVAL;
    input->amount = 0;
    input->has_amount = 0;
    return WALLY_OK;
}

int wally_psbt_input_set_issuance_amount(struct wally_psbt_input *input,
                                         uint64_t amount)
{
    if (!input)
        return WALLY_EINVAL;
    input->issuance_amount = amount;
    return WALLY_OK;
}

int wally_psbt_input_set_inflation_keys(struct wally_psbt_input *input,
                                        uint64_t amount)
{
    if (!input)
        return WALLY_EINVAL;
    input->inflation_keys = amount;
    return WALLY_OK;
}

int wally_psbt_input_set_pegin_amount(struct wally_psbt_input *input, uint64_t amount)
{
    if (!input)
        return WALLY_EINVAL;
    input->pegin_amount = amount;
    return WALLY_OK;
}

SET_STRUCT(wally_psbt_input, pegin_tx, wally_tx, tx_clone_alloc, wally_tx_free)
SET_STRUCT(wally_psbt_input, pegin_witness, wally_tx_witness_stack,
           wally_tx_witness_stack_clone_alloc, wally_tx_witness_stack_free)

MAP_INNER_FIELD(input, issuance_amount_commitment, PSET_IN_ISSUANCE_VALUE_COMMITMENT, pset_fields)
MAP_INNER_FIELD(input, issuance_amount_rangeproof, PSET_IN_ISSUANCE_VALUE_RANGEPROOF, pset_fields)
MAP_INNER_FIELD(input, issuance_blinding_nonce, PSET_IN_ISSUANCE_BLINDING_NONCE, pset_fields)
MAP_INNER_FIELD(input, issuance_asset_entropy, PSET_IN_ISSUANCE_ASSET_ENTROPY, pset_fields)
MAP_INNER_FIELD(input, issuance_amount_blinding_rangeproof, PSET_IN_ISSUANCE_BLIND_VALUE_PROOF, pset_fields)
MAP_INNER_FIELD(input, pegin_claim_script, PSET_IN_PEG_IN_CLAIM_SCRIPT, pset_fields)
MAP_INNER_FIELD(input, pegin_genesis_blockhash, PSET_IN_PEG_IN_GENESIS_HASH, pset_fields)
MAP_INNER_FIELD(input, pegin_txout_proof, PSET_IN_PEG_IN_TXOUT_PROOF, pset_fields)
MAP_INNER_FIELD(input, inflation_keys_commitment, PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT, pset_fields)
MAP_INNER_FIELD(input, inflation_keys_rangeproof, PSET_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF, pset_fields)
MAP_INNER_FIELD(input, inflation_keys_blinding_rangeproof, PSET_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF, pset_fields)
MAP_INNER_FIELD(input, amount_rangeproof, PSET_IN_VALUE_PROOF, pset_fields)
MAP_INNER_FIELD(input, asset, PSET_IN_EXPLICIT_ASSET, pset_fields)
MAP_INNER_FIELD(input, asset_surjectionproof, PSET_IN_ASSET_PROOF, pset_fields)
MAP_INNER_FIELD(input, utxo_rangeproof, PSET_IN_UTXO_RANGEPROOF, pset_fields)
#endif /* BUILD_ELEMENTS */

static void psbt_input_init(struct wally_psbt_input *input)
{
    wally_clear(input, sizeof(*input));
    wally_map_init(0, wally_keypath_public_key_verify, &input->keypaths);
    wally_map_init(0, pubkey_sig_verify, &input->signatures);
    wally_map_init(0, NULL, &input->unknowns);
    wally_map_init(0, wally_map_hash_preimage_verify, &input->preimages);
    wally_map_init(0, psbt_map_input_field_verify, &input->psbt_fields);
    wally_map_init(0, NULL /* FIXME */, &input->taproot_leaf_signatures);
    wally_map_init(0, NULL /* FIXME */, &input->taproot_leaf_scripts);
    wally_map_init(0, map_leaf_hashes_verify, &input->taproot_leaf_hashes);
    wally_map_init(0, wally_keypath_xonly_public_key_verify, &input->taproot_leaf_paths);
#ifdef BUILD_ELEMENTS
    wally_map_init(0, pset_map_input_field_verify, &input->pset_fields);
#endif /* BUILD_ELEMENTS */
}

static int psbt_input_free(struct wally_psbt_input *input, bool free_parent)
{
    if (input) {
        wally_tx_free(input->utxo);
        wally_tx_output_free(input->witness_utxo);
        wally_tx_witness_stack_free(input->final_witness);
        wally_map_clear(&input->keypaths);
        wally_map_clear(&input->signatures);
        wally_map_clear(&input->unknowns);
        wally_map_clear(&input->preimages);
        wally_map_clear(&input->psbt_fields);
        wally_map_clear(&input->taproot_leaf_signatures);
        wally_map_clear(&input->taproot_leaf_scripts);
        wally_map_clear(&input->taproot_leaf_hashes);
        wally_map_clear(&input->taproot_leaf_paths);
#ifdef BUILD_ELEMENTS
        wally_tx_free(input->pegin_tx);
        wally_tx_witness_stack_free(input->pegin_witness);
        wally_map_clear(&input->pset_fields);
#endif /* BUILD_ELEMENTS */
        wally_clear(input, sizeof(*input));
        if (free_parent)
            wally_free(input);
    }
    return WALLY_OK;
}

MAP_INNER_FIELD(output, redeem_script, PSBT_OUT_REDEEM_SCRIPT, psbt_fields)
MAP_INNER_FIELD(output, witness_script, PSBT_OUT_WITNESS_SCRIPT, psbt_fields)
SET_MAP(wally_psbt_output, keypath,)
ADD_KEYPATH(wally_psbt_output)
ADD_TAP_KEYPATH(wally_psbt_output)
SET_MAP(wally_psbt_output, unknown,)

int wally_psbt_output_set_amount(struct wally_psbt_output *output, uint64_t amount)
{
    if (!output)
        return WALLY_EINVAL;
    output->amount = amount;
    output->has_amount = 1u;
    return WALLY_OK;
}

int wally_psbt_output_clear_amount(struct wally_psbt_output *output)
{
    if (!output)
        return WALLY_EINVAL;
    output->amount = 0;
    output->has_amount = 0;
    return WALLY_OK;
}

int wally_psbt_output_set_script(struct wally_psbt_output *output,
                                 const unsigned char *bytes, size_t len)
{
    if (!output)
        return WALLY_EINVAL;
    return replace_bytes(bytes, len, &output->script, &output->script_len);
}


#ifdef BUILD_ELEMENTS
int wally_psbt_output_set_blinder_index(struct wally_psbt_output *output, uint32_t index)
{
    if (!output)
        return WALLY_EINVAL;
    output->blinder_index = index;
    output->has_blinder_index = 1u;
    return WALLY_OK;
}

int wally_psbt_output_clear_blinder_index(struct wally_psbt_output *output)
{
    if (!output)
        return WALLY_EINVAL;
    output->blinder_index = 0;
    output->has_blinder_index = 0;
    return WALLY_OK;
}

MAP_INNER_FIELD(output, value_commitment, PSET_OUT_VALUE_COMMITMENT, pset_fields)
MAP_INNER_FIELD(output, asset, PSET_OUT_ASSET, pset_fields)
MAP_INNER_FIELD(output, asset_commitment, PSET_OUT_ASSET_COMMITMENT, pset_fields)
MAP_INNER_FIELD(output, value_rangeproof, PSET_OUT_VALUE_RANGEPROOF, pset_fields)
MAP_INNER_FIELD(output, asset_surjectionproof, PSET_OUT_ASSET_SURJECTION_PROOF, pset_fields)
MAP_INNER_FIELD(output, blinding_public_key, PSET_OUT_BLINDING_PUBKEY, pset_fields)
MAP_INNER_FIELD(output, ecdh_public_key, PSET_OUT_ECDH_PUBKEY, pset_fields)
MAP_INNER_FIELD(output, value_blinding_rangeproof, PSET_OUT_BLIND_VALUE_PROOF, pset_fields)
MAP_INNER_FIELD(output, asset_blinding_surjectionproof, PSET_OUT_BLIND_ASSET_PROOF, pset_fields)

static int psbt_output_get_blinding_state(const struct wally_psbt_output *output, uint64_t *written)
{
    const struct wally_map_item *p;
    uint32_t ft;

    *written = 0;
    for (ft = PSET_OUT_VALUE_COMMITMENT; ft <= PSET_OUT_ECDH_PUBKEY; ++ft) {
        if (PSET_OUT_BLINDING_FIELDS & PSET_FT(ft)) {
            if ((p = wally_map_get_integer(&output->pset_fields, ft))) {
                *written |= PSET_FT(ft);
                if ((ft == PSET_OUT_BLINDING_PUBKEY || ft == PSET_OUT_ECDH_PUBKEY) &&
                    wally_ec_public_key_verify(p->value, p->value_len) != WALLY_OK)
                    return WALLY_ERROR; /* Invalid */
            }
        }
    }
    return WALLY_OK;
}

int wally_psbt_output_get_blinding_status(const struct wally_psbt_output *output,
                                          uint32_t flags, size_t *written)
{
    uint64_t state;

    if (written)
        *written = WALLY_PSET_BLINDED_NONE;
    if (!output || flags || !written)
        return WALLY_EINVAL;

    if (psbt_output_get_blinding_state(output, &state) != WALLY_OK)
        return WALLY_ERROR;

    if (PSET_BLINDING_STATE_REQUIRED(state)) {
        if (PSET_BLINDING_STATE_FULL(state))
            *written = WALLY_PSET_BLINDED_FULL;
        else if (PSET_BLINDING_STATE_PARTIAL(state))
            *written = WALLY_PSET_BLINDED_PARTIAL;
        else
            *written = WALLY_PSET_BLINDED_REQUIRED;
    }
    return WALLY_OK;
}

/* Verify that unblinded values, their commitment, and commitment proof
 * are provided/elided where required, and proofs are valid if provided.
 */
static bool pset_check_proof(const struct wally_psbt *psbt,
                             const struct wally_psbt_input *in,
                             const struct wally_psbt_output *out,
                             uint64_t value_bit,
                             uint64_t commitment_key, uint64_t proof_key, uint32_t flags)
{
    const bool is_mandatory = !!out; /* Both output commitments/values are mandatory */
    const bool is_utxo_value = in && (value_bit == PSET_FT(PSET_IN_EXPLICIT_VALUE));
    const bool is_utxo_asset = in && (value_bit == PSET_FT(PSET_IN_EXPLICIT_ASSET));
    const struct wally_map *pset_fields = out ? &out->pset_fields : &in->pset_fields;
    const struct wally_map_item *item, *proof;
    struct wally_map_item commitment, asset;
    uint64_t value = 0;
    bool has_value = false, has_explicit = false, do_verify = true;;
    int ret;

    if (!in && !out)
        return false; /* Not possible, but it fixes static analysis */

    wally_clear(&commitment, sizeof(commitment));
    wally_clear(&asset, sizeof(asset));

    /* Get the explicit proof, if any */
    proof = wally_map_get_integer(pset_fields, proof_key);

    /* Get the unblinded asset or value and its commitment, if any.
     * For value rangeproofs, also get the asset commitment: 'asset' is
     * - The unblinded asset value for asset surjection proofs, or
     * - The asset commitment, for value rangeproofs.
     */
    if (is_utxo_value || is_utxo_asset) {
        /* Get explicit value and commitments from the inputs UTXO */
        const struct wally_tx_output *utxo = utxo_from_input(psbt, in);
        has_value = is_utxo_value && in->has_amount;
        value = in->amount;
        if (utxo) {
            if (is_utxo_value) {
                commitment.value = utxo->value;
                commitment.value_len = utxo->value_len;
                asset.value = utxo->asset;
                asset.value_len = utxo->asset_len;
                has_explicit = has_value;
            } else {
                commitment.value = utxo->asset;
                commitment.value_len = utxo->asset_len;
                if ((item = wally_map_get_integer(pset_fields, PSET_IN_EXPLICIT_ASSET)) != NULL) {
                    memcpy(&asset, item, sizeof(asset));
                    has_explicit = true;
                }
            }
        }
    } else {
        /* Get commitment from the PSET fields map */
        if ((item = wally_map_get_integer(pset_fields, commitment_key)) != NULL)
            memcpy(&commitment, item, sizeof(commitment));

        if (in) {
            /* Input issuance/re-issuance proofs */
            if (value_bit == PSET_FT(PSET_IN_ISSUANCE_VALUE))
                value = in->issuance_amount;
            else
                value = in->inflation_keys; /* PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_AMOUNT) */
            has_value = value != 0;
            has_explicit = has_value;
            /* FIXME: Elements doesn't currently ever generate or validate issuance
             *        proofs; its not immediately clear what the asset commitment
             *        should be for the rangeproof either */
            do_verify = false;
        } else {
            /* Output value/asset proofs */
            if (value_bit == PSBT_FT(PSBT_OUT_AMOUNT)) {
                value = out->amount;
                has_value = out->has_amount;
                has_explicit = has_value;
                if ((item = wally_map_get_integer(pset_fields, PSET_OUT_ASSET_COMMITMENT)) != NULL)
                    memcpy(&asset, item, sizeof(asset));
            } else {
                /* PSET_FT(PSET_OUT_ASSET) */
                if ((item = wally_map_get_integer(pset_fields, PSET_OUT_ASSET)) != NULL) {
                    memcpy(&asset, item, sizeof(asset));
                    has_explicit = true;
                }
            }
        }
    }

    if (proof && !commitment.value)
        return false; /* Proof without commitment value */
    if (commitment.value) {
        if (!has_explicit)
            return true; /* Explicit value has been removed, nothing to prove */
        if (!proof && (flags & WALLY_PSBT_PARSE_FLAG_STRICT))
            return false; /* value and commitment without range/surjection proof */
    } else if (!has_explicit && is_mandatory) {
        /* No value, commitment or proof for a mandatory field - invalid */
        return false;
    }

    if (!proof || !commitment.value || !has_explicit)
        return true; /* Nothing to validate */

    /* Validate the proof */
    if (has_value) {
        if (!do_verify) {
            ret = WALLY_OK;
        } else if (!asset.value || !asset.value_len) {
            /* For value rangeproofs, the asset commitment is mandatory
             * to allow verification, although the PSET spec misses this */
            ret = WALLY_EINVAL;
        } else
            ret = wally_explicit_rangeproof_verify(proof->value, proof->value_len, value,
                                                   commitment.value, commitment.value_len,
                                                   asset.value, asset.value_len);
    } else {
        ret = wally_explicit_surjectionproof_verify(proof->value, proof->value_len,
                                                    asset.value, asset.value_len,
                                                    commitment.value, commitment.value_len);
    }
    return ret == WALLY_OK;
}
#endif /* BUILD_ELEMENTS */

static void psbt_output_init(struct wally_psbt_output *output)
{
    wally_clear(output, sizeof(*output));
    wally_map_init(0, wally_keypath_public_key_verify, &output->keypaths);
    wally_map_init(0, NULL, &output->unknowns);
    wally_map_init(0, psbt_map_output_field_verify, &output->psbt_fields);
    wally_map_init(0, NULL, &output->taproot_tree);
    wally_map_init(0, map_leaf_hashes_verify, &output->taproot_leaf_hashes);
    wally_map_init(0, wally_keypath_xonly_public_key_verify, &output->taproot_leaf_paths);
#ifdef BUILD_ELEMENTS
    wally_map_init(0, pset_map_output_field_verify, &output->pset_fields);
#endif /* BUILD_ELEMENTS */
}

static int psbt_output_free(struct wally_psbt_output *output, bool free_parent)
{
    if (output) {
        wally_map_clear(&output->keypaths);
        wally_map_clear(&output->unknowns);
        clear_and_free(output->script, output->script_len);
        wally_map_clear(&output->psbt_fields);
        wally_map_clear(&output->taproot_tree);
        wally_map_clear(&output->taproot_leaf_hashes);
        wally_map_clear(&output->taproot_leaf_paths);
#ifdef BUILD_ELEMENTS
        wally_map_clear(&output->pset_fields);
#endif /* BUILD_ELEMENTS */

        wally_clear(output, sizeof(*output));
        if (free_parent)
            wally_free(output);
    }
    return WALLY_OK;
}

static int psbt_init(uint32_t version, size_t num_inputs, size_t num_outputs,
                     size_t num_unknowns, uint32_t flags,
                     size_t max_num_inputs, size_t max_num_outputs,
                     struct wally_psbt *psbt_out)
{
    int ret;

    if (psbt_out)
        wally_clear(psbt_out, sizeof(*psbt_out));
    if ((version != PSBT_0 && version != PSBT_2) || !psbt_out)
        return WALLY_EINVAL; /* Only v0/v2 are specified/supported */
    if (num_inputs > TX_MAX_INPUTS || num_outputs > TX_MAX_OUTPUTS)
        return WALLY_EINVAL; /* Resulting tx could not fit in a block */
#ifdef BUILD_ELEMENTS
    if (flags & ~WALLY_PSBT_INIT_PSET ||
        (flags & WALLY_PSBT_INIT_PSET && version != PSBT_2))
        return WALLY_EINVAL;
#else
    if (flags)
        return WALLY_EINVAL;
#endif /* BUILD_ELEMENTS */

    if (num_inputs) {
        if (num_inputs > max_num_inputs)
            num_inputs = max_num_inputs;
        psbt_out->inputs = wally_calloc(num_inputs * sizeof(struct wally_psbt_input));
    }
    if (num_outputs) {
        if (num_outputs > max_num_outputs)
            num_outputs = max_num_outputs;
        psbt_out->outputs = wally_calloc(num_outputs * sizeof(struct wally_psbt_output));
    }

    ret = wally_map_init(num_unknowns, NULL, &psbt_out->unknowns);
    if (ret == WALLY_OK)
        ret = wally_map_init(0, wally_keypath_bip32_verify, &psbt_out->global_xpubs);
#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK)
        ret = wally_map_init(0, scalar_verify, &psbt_out->global_scalars);
#endif /* BUILD_ELEMENTS */

    if (ret != WALLY_OK ||
        (num_inputs && !psbt_out->inputs) ||
        (num_outputs && !psbt_out->outputs)) {
        wally_free(psbt_out->inputs);
        wally_free(psbt_out->outputs);
        wally_map_clear(&psbt_out->unknowns);
        wally_clear(psbt_out, sizeof(psbt_out));
        return ret != WALLY_OK ? ret : WALLY_ENOMEM;
    }

    psbt_out->version = version;
    psbt_out->tx_version = 2u; /* Minimum tx version is 2 */
    /* Both inputs and outputs can be added to a newly created PSBT */
    psbt_out->tx_modifiable_flags = WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS;

#ifdef BUILD_ELEMENTS
    if (flags & WALLY_PSBT_INIT_PSET)
        memcpy(psbt_out->magic, PSET_MAGIC, sizeof(PSET_MAGIC));
    else
#endif /* BUILD_ELEMENTS */
    memcpy(psbt_out->magic, PSBT_MAGIC, sizeof(PSBT_MAGIC));
    psbt_out->inputs_allocation_len = num_inputs;
    psbt_out->outputs_allocation_len = num_outputs;
    psbt_out->tx = NULL;
    return WALLY_OK;
}

static int psbt_init_alloc(uint32_t version, size_t num_inputs, size_t num_outputs,
                           size_t num_unknowns, uint32_t flags,
                           size_t max_num_inputs, size_t max_num_outputs,
                           struct wally_psbt **output)
{
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_psbt);
    ret = psbt_init(version, num_inputs, num_outputs, num_unknowns, flags,
                    max_num_inputs, max_num_outputs, *output);
    if (ret != WALLY_OK) {
        wally_free(*output);
        *output = NULL;
    }
    return ret;
}

int wally_psbt_init_alloc(uint32_t version, size_t num_inputs, size_t num_outputs,
                          size_t num_unknowns, uint32_t flags, struct wally_psbt **output)
{
    return psbt_init_alloc(version, num_inputs, num_outputs, num_unknowns,
                           flags, TX_MAX_INPUTS_ALLOC, TX_MAX_OUTPUTS_ALLOC,
                           output);
}

int wally_psbt_from_tx(const struct wally_tx *tx, uint32_t version,
                       uint32_t flags, struct wally_psbt **output)
{
    size_t i;
    int ret;

    if (output)
        *output = NULL;
    if (!tx || !output || (version == WALLY_PSBT_VERSION_2 && tx->version < 2u))
        return WALLY_EINVAL;
    ret = psbt_init_alloc(version, tx->num_inputs, tx->num_outputs, 0, flags,
                          tx->num_inputs, tx->num_outputs, output);
    if (ret == WALLY_OK && version == WALLY_PSBT_VERSION_0)
        ret = wally_psbt_set_global_tx(*output, tx);
    else {
        for (i = 0; ret == WALLY_OK && i < tx->num_inputs; ++i)
            ret = wally_psbt_add_tx_input_at(*output, i, 0, tx->inputs + i);
        for (i = 0; ret == WALLY_OK && i < tx->num_outputs; ++i)
            ret = wally_psbt_add_tx_output_at(*output, i, 0, tx->outputs + i);
        if (ret == WALLY_OK) {
            (*output)->tx_version = tx->version;
            ret = wally_psbt_set_fallback_locktime(*output, tx->locktime);
        }
    }
    if (ret != WALLY_OK) {
        wally_psbt_free(*output);
        *output = NULL;
    }
    return ret;
}

static void psbt_claim_allocated_inputs(struct wally_psbt *psbt, size_t num_inputs, size_t num_outputs)
{
    size_t i;

    /* Requires num_inputs/outputs are <= the allocated lengths */
    psbt->num_inputs = num_inputs;
    for (i = 0; i < num_inputs; i++) {
        psbt_input_init(psbt->inputs + i);
        psbt->inputs[i].sequence = WALLY_TX_SEQUENCE_FINAL;
    }
    psbt->num_outputs = num_outputs;
    for (i = 0; i < num_outputs; i++)
        psbt_output_init(psbt->outputs + i);
}

int wally_psbt_free(struct wally_psbt *psbt)
{
    size_t i;
    if (psbt) {
        wally_tx_free(psbt->tx);
        for (i = 0; i < psbt->num_inputs; ++i)
            psbt_input_free(&psbt->inputs[i], false);

        wally_free(psbt->inputs);
        for (i = 0; i < psbt->num_outputs; ++i)
            psbt_output_free(&psbt->outputs[i], false);

        wally_free(psbt->outputs);
        wally_map_clear(&psbt->unknowns);
        wally_map_clear(&psbt->global_xpubs);
#ifdef BUILD_ELEMENTS
        wally_map_clear(&psbt->global_scalars);
#endif /* BUILD_ELEMENTS */
        clear_and_free(psbt, sizeof(*psbt));
    }
    return WALLY_OK;
}

int wally_psbt_get_global_tx_alloc(const struct wally_psbt *psbt, struct wally_tx **output)
{
    OUTPUT_CHECK;
    if (!psbt || psbt->version != PSBT_0)
        return WALLY_EINVAL;
    if (!psbt->tx)
        return WALLY_OK; /* Return a NULL tx if not present */
    return tx_clone_alloc(psbt->tx, output);
}

#define PSBT_GET(name, v) \
    int wally_psbt_get_ ## name(const struct wally_psbt *psbt, size_t *written) { \
        if (written) \
            *written = 0; \
        if (!psbt || !written || (v == PSBT_2 && psbt->version != v)) \
            return WALLY_EINVAL; \
        *written = psbt->name; \
        return WALLY_OK; \
    }

PSBT_GET(version, PSBT_0)
PSBT_GET(num_inputs, PSBT_0)
PSBT_GET(num_outputs, PSBT_0)
PSBT_GET(fallback_locktime, PSBT_2)
PSBT_GET(tx_version, PSBT_2)
PSBT_GET(tx_modifiable_flags, PSBT_2)

int wally_psbt_has_fallback_locktime(const struct wally_psbt *psbt, size_t *written)
{
    if (written)
        *written = 0;
    if (!psbt || !written || psbt->version != PSBT_2)
        return WALLY_EINVAL;
    *written = psbt->has_fallback_locktime ? 1 : 0;
    return WALLY_OK;
}

int wally_psbt_set_tx_version(struct wally_psbt *psbt, uint32_t tx_version) {
    if (!psbt || psbt->version != PSBT_2 || tx_version < 2u)
        return WALLY_EINVAL;
    psbt->tx_version = tx_version;
    return WALLY_OK;
}

int wally_psbt_set_fallback_locktime(struct wally_psbt *psbt, uint32_t locktime) {
    if (!psbt || psbt->version != PSBT_2)
        return WALLY_EINVAL;
    psbt->fallback_locktime = locktime;
    psbt->has_fallback_locktime = 1u;
    return WALLY_OK;
}

int wally_psbt_clear_fallback_locktime(struct wally_psbt *psbt) {
    if (!psbt || psbt->version != PSBT_2)
        return WALLY_EINVAL;
    psbt->fallback_locktime = 0u;
    psbt->has_fallback_locktime = 0u;
    return WALLY_OK;
}

int wally_psbt_set_tx_modifiable_flags(struct wally_psbt *psbt, uint32_t flags) {
    if (!psbt || psbt->version != PSBT_2 ||
        (flags & ~PSBT_TXMOD_ALL_FLAGS))
        return WALLY_EINVAL;
    psbt->tx_modifiable_flags = flags;
    return WALLY_OK;
}

int wally_psbt_find_input_spending_utxo(const struct wally_psbt *psbt,
                                        const unsigned char *txhash, size_t txhash_len,
                                        uint32_t utxo_index, size_t *written)
{
    size_t i;
    if (written)
        *written = 0;
    if (!psbt_is_valid(psbt) || !txhash || txhash_len != WALLY_TXHASH_LEN ||
        !written)
        return WALLY_EINVAL;
    for (i = 0; i < psbt->num_inputs; ++i) {
        if (psbt->version == PSBT_0) {
            const struct wally_tx_input *input = &psbt->tx->inputs[i];
            if (input->index == utxo_index && !memcmp(input->txhash, txhash, txhash_len)) {
                *written = i + 1;
                return WALLY_OK;
            }
        } else {
            const struct wally_psbt_input *input = &psbt->inputs[i];
            if (input->index == utxo_index && !memcmp(input->txhash, txhash, txhash_len)) {
                *written = i + 1;
                return WALLY_OK;
            }
        }
    }
    return WALLY_OK; /* Not found, return 0 */
}

#ifdef BUILD_ELEMENTS
int wally_psbt_get_global_scalars_size(const struct wally_psbt *psbt, size_t *written)
{
    if (written) *written = 0;
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0 || !written)
        return WALLY_EINVAL;
    *written = psbt->global_scalars.num_items;
    return WALLY_OK;
}

int wally_psbt_find_global_scalar(struct wally_psbt *psbt,
                                  const unsigned char *scalar, size_t scalar_len,
                                  size_t *written)
{
    if (written) *written = 0;
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0)
        return WALLY_EINVAL;
    return wally_map_find(&psbt->global_scalars, scalar, scalar_len, written);
}

int wally_psbt_get_global_scalar(const struct wally_psbt *psbt, size_t index,
                                 unsigned char *bytes_out, size_t len)
{
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0 ||
        index >= psbt->global_scalars.num_items ||
        !bytes_out || len != WALLY_SCALAR_OFFSET_LEN)
        return WALLY_EINVAL;
    memcpy(bytes_out, psbt->global_scalars.items[index].key, len);
    return WALLY_OK;
}

int wally_psbt_add_global_scalar(struct wally_psbt *psbt,
                                 const unsigned char *scalar, size_t scalar_len)
{
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0)
        return WALLY_EINVAL;
    return wally_map_add(&psbt->global_scalars, scalar, scalar_len, NULL, 0);
}

int wally_psbt_set_global_scalars(struct wally_psbt *psbt, const struct wally_map *map_in)
{
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0)
        return WALLY_EINVAL;
    return wally_map_assign(&psbt->global_scalars, map_in);
}

int wally_psbt_set_pset_modifiable_flags(struct wally_psbt *psbt, uint32_t flags)
{
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0 || flags & ~PSET_TXMOD_ALL_FLAGS)
        return WALLY_EINVAL;
    psbt->pset_modifiable_flags = flags & ~WALLY_PSET_TXMOD_RESERVED;
    return WALLY_OK;
}

PSBT_GET(pset_modifiable_flags, PSBT_2)
#endif /* BUILD_ELEMENTS */

int wally_psbt_is_finalized(const struct wally_psbt *psbt,
                            size_t *written)
{
    size_t i;

    if (written)
        *written = 0;
    if (!psbt_is_valid(psbt) || !written)
        return WALLY_EINVAL;

    for (i = 0; i < psbt->num_inputs; ++i) {
        if (!psbt->inputs[i].final_witness &&
            !wally_map_get_integer(&psbt->inputs[i].psbt_fields, PSBT_IN_FINAL_SCRIPTSIG))
            return WALLY_OK; /* Non fully finalized */
    }
    /* We are finalized if we have inputs since they are all finalized */
    *written = psbt->num_inputs ?  1 : 0;
    return WALLY_OK;
}

int wally_psbt_is_input_finalized(const struct wally_psbt *psbt,
                                  size_t index, size_t *written)
{
    return wally_psbt_input_is_finalized(psbt_get_input(psbt, index), written);
}

static int psbt_set_global_tx(struct wally_psbt *psbt, struct wally_tx *tx, bool do_clone)
{
    struct wally_tx *new_tx = NULL;
    struct wally_psbt_input *new_inputs = NULL;
    struct wally_psbt_output *new_outputs = NULL;
    size_t i;
    int ret;

    if (!psbt_is_valid(psbt) || !tx || psbt->tx || psbt->version != PSBT_0)
        return WALLY_EINVAL; /* PSBT must be v0 and completely empty */

    if (do_clone) {
        /* clone without scriptSigs and witnesses */
        const uint32_t clone_flags = WALLY_TX_CLONE_FLAG_NON_FINAL;
        if ((ret = wally_tx_clone_alloc(tx, clone_flags, &new_tx)) != WALLY_OK)
            return ret;
    } else {
        /* tx mustn't have scriptSigs or witnesses */
        for (i = 0; i < tx->num_inputs; ++i)
            if (tx->inputs[i].script || tx->inputs[i].witness)
                return WALLY_EINVAL;
    }

    if (psbt->inputs_allocation_len < tx->num_inputs) {
        new_inputs = wally_malloc(tx->num_inputs * sizeof(struct wally_psbt_input));
        for (i = 0; i < tx->num_inputs; ++i)
            psbt_input_init(&new_inputs[i]);
    }

    if (psbt->outputs_allocation_len < tx->num_outputs) {
        new_outputs = wally_malloc(tx->num_outputs * sizeof(struct wally_psbt_output));
        for (i = 0; i < tx->num_outputs; ++i)
            psbt_output_init(&new_outputs[i]);
    }

    if ((psbt->inputs_allocation_len < tx->num_inputs && !new_inputs) ||
        (psbt->outputs_allocation_len < tx->num_outputs && !new_outputs)) {
        wally_free(new_inputs);
        wally_free(new_outputs);
        wally_tx_free(new_tx);
        return WALLY_ENOMEM;
    }

    if (new_inputs) {
        wally_free(psbt->inputs);
        psbt->inputs = new_inputs;
        psbt->inputs_allocation_len = tx->num_inputs;
    }
    if (new_outputs) {
        wally_free(psbt->outputs);
        psbt->outputs = new_outputs;
        psbt->outputs_allocation_len = tx->num_outputs;
    }
    psbt->num_inputs = tx->num_inputs;
    psbt->num_outputs = tx->num_outputs;
    psbt->tx = do_clone ? new_tx : tx;
    return WALLY_OK;
}

int wally_psbt_set_global_tx(struct wally_psbt *psbt, const struct wally_tx *tx)
{
    return psbt_set_global_tx(psbt, (struct wally_tx *)tx, true);
}

#ifdef BUILD_ELEMENTS
static int add_commitment(const unsigned char *value, size_t value_len,
                          uint32_t ft, uint32_t ft_commitment,
                          struct wally_map *map_in)
{
    if (value_len <= 1)
        return WALLY_OK; /* Empty or null commitment */
    if (*value == 0x1) {
        /* Asset isn't blinded: add it as the non-commitment field */
        return wally_map_add_integer(map_in, ft, value + 1, value_len - 1);
    }
    return wally_map_add_integer(map_in, ft_commitment, value, value_len);
}

static int add_commitment_amount(const unsigned char *value, size_t value_len,
                                 uint32_t ft_commitment,
                                 uint64_t *amount, uint32_t *has_amount,
                                 struct wally_map *map_in)
{
    *amount = 0;
    *has_amount = 0;
    if (value_len <= 1)
        return WALLY_OK; /* Empty or null commitment */
    if (*value == 0x1) {
        /* Asset isn't blinded: add the explicit value and mark it present */
        if (wally_tx_confidential_value_to_satoshi(value, value_len, amount) != WALLY_OK)
            return WALLY_EINVAL;
        *has_amount = *value != 0;
        return WALLY_OK;
    }
    return wally_map_add_integer(map_in, ft_commitment, value, value_len);
}

static int psbt_input_from_tx_input_issuance(const struct wally_tx_input *txin,
                                             struct wally_psbt_input *dst)
{
    uint32_t has_amount;
    int ret = add_commitment_amount(txin->issuance_amount, txin->issuance_amount_len,
                                    PSET_IN_ISSUANCE_VALUE_COMMITMENT,
                                    &dst->issuance_amount, &has_amount,
                                    &dst->pset_fields);
    if (ret == WALLY_OK && txin->issuance_amount_rangeproof)
        ret = wally_map_add_integer(&dst->pset_fields, PSET_IN_ISSUANCE_VALUE_RANGEPROOF,
                                    txin->issuance_amount_rangeproof,
                                    txin->issuance_amount_rangeproof_len);
    if (ret == WALLY_OK)
        ret = add_commitment_amount(txin->inflation_keys, txin->inflation_keys_len,
                                    PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT,
                                    &dst->inflation_keys, &has_amount,
                                    &dst->pset_fields);
    if (ret == WALLY_OK && txin->inflation_keys_rangeproof)
        ret = wally_map_add_integer(&dst->pset_fields, PSET_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF,
                                    txin->inflation_keys_rangeproof,
                                    txin->inflation_keys_rangeproof_len);
    if (ret == WALLY_OK && !mem_is_zero(txin->blinding_nonce, sizeof(txin->blinding_nonce)))
        ret = wally_map_add_integer(&dst->pset_fields, PSET_IN_ISSUANCE_BLINDING_NONCE,
                                    txin->blinding_nonce, sizeof(txin->blinding_nonce));
    if (ret == WALLY_OK && !mem_is_zero(txin->entropy, sizeof(txin->entropy)))
        ret = wally_map_add_integer(&dst->pset_fields, PSET_IN_ISSUANCE_ASSET_ENTROPY,
                                    txin->entropy, sizeof(txin->entropy));
    return ret;
}

static int psbt_input_from_tx_input_pegin(const struct wally_tx_input *txin,
                                          struct wally_psbt_input *dst)
{
    (void)txin;
    (void)dst;
    return WALLY_ERROR; /* FIXME: Implement peg-in fields */
}
#endif /* BUILD_ELEMENTS */

static int psbt_input_from_tx_input(struct wally_psbt *psbt,
                                    const struct wally_tx_input *txin,
                                    bool is_pset, struct wally_psbt_input *dst)
{
    int ret = WALLY_OK;

    psbt_input_init(dst);
    if (psbt->version == PSBT_0)
        return WALLY_OK; /* Nothing to do */

    memcpy(dst->txhash, txin->txhash, WALLY_TXHASH_LEN);
    dst->index = MASK_INDEX(txin->index);
    dst->sequence = txin->sequence;

    if (psbt->version == PSBT_2) {
        if (is_pset) {
#ifdef BUILD_ELEMENTS
            if (txin->features & WALLY_TX_IS_ISSUANCE)
                ret = psbt_input_from_tx_input_issuance(txin, dst);
            if (ret == WALLY_OK && txin->features & WALLY_TX_IS_PEGIN)
                ret = psbt_input_from_tx_input_pegin(txin, dst);
#endif /* BUILD_ELEMENTS */
        }
    }
    if (ret != WALLY_OK)
        psbt_input_free(dst, false);
    return ret;
}

int wally_psbt_add_input_taproot_keypath(
    struct wally_psbt *psbt,
    uint32_t index, uint32_t flags,
    const unsigned char *pub_key, size_t pub_key_len,
    const unsigned char *tapleaf_hashes, size_t tapleaf_hashes_len,
    const unsigned char *fingerprint, size_t fingerprint_len,
    const uint32_t *child_path, size_t child_path_len)
{
    struct wally_psbt_input *inp = psbt_get_input(psbt, index);
    if (!inp || !psbt_is_valid(psbt) || flags ||
        !psbt_can_modify(psbt, WALLY_PSBT_TXMOD_INPUTS))
        return WALLY_EINVAL;

    return wally_psbt_input_taproot_keypath_add(inp, pub_key, pub_key_len,
                                                tapleaf_hashes, tapleaf_hashes_len,
                                                fingerprint, fingerprint_len,
                                                child_path, child_path_len);
}

int wally_psbt_add_tx_input_at(struct wally_psbt *psbt,
                               uint32_t index, uint32_t flags,
                               const struct wally_tx_input *txin)
{
    struct wally_tx_input txin_copy;
    size_t is_pset;
    int ret = WALLY_OK;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx) ||
        (flags & ~WALLY_PSBT_FLAG_NON_FINAL) || index > psbt->num_inputs || !txin)
        return WALLY_EINVAL;

    if (!psbt_can_modify(psbt, WALLY_PSBT_TXMOD_INPUTS))
        return WALLY_EINVAL; /* FIXME: WALLY_PSBT_TXMOD_SINGLE */

    if ((ret = wally_psbt_is_elements(psbt, &is_pset)) != WALLY_OK)
        return ret;

    if (psbt->num_inputs >= psbt->inputs_allocation_len &&
        (ret = array_grow((void *)&psbt->inputs, psbt->num_inputs,
                          &psbt->inputs_allocation_len,
                          sizeof(*psbt->inputs))) != WALLY_OK)
        return ret;

    memcpy(&txin_copy, txin, sizeof(*txin));
    if (flags & WALLY_PSBT_FLAG_NON_FINAL) {
        /* Clear scriptSig and witness before adding */
        txin_copy.script = NULL;
        txin_copy.script_len = 0;
        txin_copy.witness = NULL;
    }

    if (psbt->version == PSBT_0)
        ret = wally_tx_add_input_at(psbt->tx, index, &txin_copy);

    if (ret == WALLY_OK) {
        struct wally_psbt_input tmp, *dst = psbt->inputs + index;

        ret = psbt_input_from_tx_input(psbt, &txin_copy, !!is_pset, &tmp);
        if (ret == WALLY_OK) {
            memmove(dst + 1, dst, (psbt->num_inputs - index) * sizeof(*psbt->inputs));
            memcpy(dst, &tmp, sizeof(tmp));
            wally_clear(&tmp, sizeof(tmp));
            psbt->num_inputs += 1;
        }
    }

    if (ret != WALLY_OK && psbt->version == PSBT_0)
        wally_tx_remove_input(psbt->tx, index);
    wally_clear(&txin_copy, sizeof(txin_copy));
    return ret;
}

int wally_psbt_remove_input(struct wally_psbt *psbt, uint32_t index)
{
    int ret = WALLY_OK;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx) ||
        index >= psbt->num_inputs)
        return WALLY_EINVAL;

    if (!psbt_can_modify(psbt, WALLY_PSBT_TXMOD_INPUTS))
        return WALLY_EINVAL; /* FIXME: WALLY_PSBT_TXMOD_SINGLE */

    if (psbt->version == PSBT_0)
        ret = wally_tx_remove_input(psbt->tx, index);
    if (ret == WALLY_OK) {
        struct wally_psbt_input *to_remove = psbt->inputs + index;
        bool need_single = false;
        size_t i;
        if (psbt->version == PSBT_2 &&
            (to_remove->sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_SINGLE) {
            /* Remove SINGLE from tx modifiable flags if no longer needed */
            for (i = 0; i < psbt->num_inputs && !need_single; ++i) {
                need_single |= i != index &&
                               (psbt->inputs[i].sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_SINGLE;
            }
            if (!need_single)
                psbt->tx_modifiable_flags &= ~WALLY_PSBT_TXMOD_SINGLE;
        }
        psbt_input_free(to_remove, false);
        memmove(to_remove, to_remove + 1,
                (psbt->num_inputs - index - 1) * sizeof(*to_remove));
        psbt->num_inputs -= 1;
    }
    return ret;
}

static int psbt_output_from_tx_output(struct wally_psbt *psbt,
                                      const struct wally_tx_output *txout,
                                      bool is_pset, struct wally_psbt_output *dst)
{
    int ret;

    psbt_output_init(dst);
    if (psbt->version == PSBT_0)
        return WALLY_OK; /* Nothing to do */

    ret = replace_bytes(txout->script, txout->script_len,
                        &dst->script, &dst->script_len);
    if (ret == WALLY_OK) {
        /* Note we check for wallys sentinel indicating no explicit satoshi */
        dst->has_amount = txout->satoshi != MAX_INVALID_SATOSHI;
        dst->amount = dst->has_amount ? txout->satoshi : 0;
        if (is_pset) {
#ifdef BUILD_ELEMENTS
            ret = add_commitment(txout->asset, txout->asset_len,
                                 PSET_OUT_ASSET, PSET_OUT_ASSET_COMMITMENT,
                                 &dst->pset_fields);
            if (ret == WALLY_OK)
                ret = add_commitment_amount(txout->value, txout->value_len,
                                            PSET_OUT_VALUE_COMMITMENT,
                                            &dst->amount, &dst->has_amount,
                                            &dst->pset_fields);
            if (ret == WALLY_OK && txout->nonce_len)
                ret = wally_map_add_integer(&dst->pset_fields, PSET_OUT_ECDH_PUBKEY,
                                            txout->nonce, txout->nonce_len);
            if (ret == WALLY_OK && txout->surjectionproof_len)
                ret = wally_map_add_integer(&dst->pset_fields, PSET_OUT_ASSET_SURJECTION_PROOF,
                                            txout->surjectionproof, txout->surjectionproof_len);
            if (ret == WALLY_OK && txout->rangeproof_len)
                ret = wally_map_add_integer(&dst->pset_fields, PSET_OUT_VALUE_RANGEPROOF,
                                            txout->rangeproof, txout->rangeproof_len);
#endif /* BUILD_ELEMENTS */
        }
    }
    if (ret != WALLY_OK)
        psbt_output_free(dst, false);
    return ret;
}

int wally_psbt_add_output_taproot_keypath(
    struct wally_psbt *psbt,
    uint32_t index, uint32_t flags,
    const unsigned char *pub_key, size_t pub_key_len,
    const unsigned char *tapleaf_hashes, size_t tapleaf_hashes_len,
    const unsigned char *fingerprint, size_t fingerprint_len,
    const uint32_t *child_path, size_t child_path_len)
{
    struct wally_psbt_output *p = psbt_get_output(psbt, index);
    if (!p || !psbt_is_valid(psbt) || flags ||
        !psbt_can_modify(psbt, WALLY_PSBT_TXMOD_OUTPUTS))
        return WALLY_EINVAL;

    return wally_psbt_output_taproot_keypath_add(p, pub_key, pub_key_len,
                                                 tapleaf_hashes, tapleaf_hashes_len,
                                                 fingerprint, fingerprint_len,
                                                 child_path, child_path_len);
}

int wally_psbt_add_tx_output_at(struct wally_psbt *psbt,
                                uint32_t index, uint32_t flags,
                                const struct wally_tx_output *txout)
{
    size_t is_pset;
    int ret = WALLY_OK;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx) ||
        flags || index > psbt->num_outputs || !txout)
        return WALLY_EINVAL;

    if (!psbt_can_modify(psbt, WALLY_PSBT_TXMOD_OUTPUTS))
        return WALLY_EINVAL; /* FIXME: WALLY_PSBT_TXMOD_SINGLE */

    if ((ret = wally_psbt_is_elements(psbt, &is_pset)) != WALLY_OK)
        return ret;

    if (psbt->num_outputs >= psbt->outputs_allocation_len &&
        (ret = array_grow((void *)&psbt->outputs, psbt->num_outputs,
                          &psbt->outputs_allocation_len,
                          sizeof(*psbt->outputs))) != WALLY_OK)
        return ret;

    if (psbt->version == PSBT_0)
        ret = wally_tx_add_output_at(psbt->tx, index, txout);

    if (ret == WALLY_OK) {
        struct wally_psbt_output tmp, *dst = psbt->outputs + index;

        ret = psbt_output_from_tx_output(psbt, txout, !!is_pset, &tmp);
        if (ret == WALLY_OK) {
            memmove(dst + 1, dst, (psbt->num_outputs - index) * sizeof(*psbt->outputs));
            memcpy(dst, &tmp, sizeof(tmp));
            wally_clear(&tmp, sizeof(tmp));
            psbt->num_outputs += 1;
        }
    }

    if (ret != WALLY_OK && psbt->version == PSBT_0)
        wally_tx_remove_output(psbt->tx, index);
    return ret;
}

int wally_psbt_remove_output(struct wally_psbt *psbt, uint32_t index)
{
    int ret = WALLY_OK;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx) ||
        index >= psbt->num_outputs)
        return WALLY_EINVAL;

    if (!psbt_can_modify(psbt, WALLY_PSBT_TXMOD_OUTPUTS))
        return WALLY_EINVAL; /* FIXME: WALLY_PSBT_TXMOD_SINGLE */

    if (psbt->version == PSBT_0)
        ret = wally_tx_remove_output(psbt->tx, index);
    if (ret == WALLY_OK) {
        struct wally_psbt_output *to_remove = psbt->outputs + index;
        psbt_output_free(to_remove, false);
        memmove(to_remove, to_remove + 1,
                (psbt->num_outputs - index - 1) * sizeof(*to_remove));
        psbt->num_outputs -= 1;
    }
    return ret;
}

static uint8_t pull_u8_subfield(const unsigned char **cursor, size_t *max)
{
    const unsigned char *val;
    size_t val_len;
    uint8_t ret;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = pull_u8(&val, &val_len);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

static uint32_t pull_le32_subfield(const unsigned char **cursor, size_t *max)
{
    const unsigned char *val;
    size_t val_len;
    uint32_t ret;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = pull_le32(&val, &val_len);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

static uint64_t pull_le64_subfield(const unsigned char **cursor, size_t *max)
{
    const unsigned char *val;
    size_t val_len;
    uint64_t ret;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = pull_le64(&val, &val_len);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

static uint64_t pull_varint_subfield(const unsigned char **cursor, size_t *max)
{
    const unsigned char *val;
    size_t val_len;
    uint64_t ret;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = pull_varint(&val, &val_len);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

static int pull_output_varbuf(const unsigned char **cursor, size_t *max,
                              struct wally_psbt_output *output,
                              int (*set_fn)(struct wally_psbt_output *, const unsigned char *, size_t))
{
    const unsigned char *val;
    size_t val_len;
    pull_varlength_buff(cursor, max, &val, &val_len);
    return val_len ? set_fn(output, val, val_len) : WALLY_OK;
}

static int pull_map_item(const unsigned char **cursor, size_t *max,
                         const unsigned char *key, size_t key_len,
                         struct wally_map *map_in)
{
    const unsigned char *val;
    size_t val_len;

    pull_varlength_buff(cursor, max, &val, &val_len);
    return map_add(map_in, key, key_len, val_len ? val : NULL, val_len, false, false);
}

static int pull_preimage(const unsigned char **cursor, size_t *max,
                         size_t type, const unsigned char *key, size_t key_len,
                         struct wally_map *map_in)
{
    const unsigned char *val;
    size_t val_len;

    pull_varlength_buff(cursor, max, &val, &val_len);
    return map_add_preimage_and_hash(map_in, key, key_len, val, val_len, type, false);
}

static int pull_tx(const unsigned char **cursor, size_t *max,
                   uint32_t tx_flags, struct wally_tx **tx_out)
{
    const unsigned char *val;
    size_t val_len;
    int ret;

    if (*tx_out)
        return WALLY_EINVAL; /* Duplicate */
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = wally_tx_from_bytes(val, val_len, tx_flags, tx_out);
    pull_subfield_end(cursor, max, val, val_len);
    return ret;
}

#ifdef BUILD_ELEMENTS
typedef size_t (*commitment_len_fn_t)(const unsigned char *);

static bool pull_commitment(const unsigned char **cursor, size_t *max,
                            const unsigned char **dst, size_t *len,
                            commitment_len_fn_t len_fn)
{
    if (!*cursor || !*max)
        return false;

    if (!(*len = len_fn(*cursor)))
        return false; /* Invalid commitment */
    if (!(*dst = pull_skip(cursor, max, *len)))
        return false;
    if (*len == 1u) {
        *dst = NULL; /* NULL commitment */
        *len = 0;
    }
    return true;
}
#endif /* BUILD_ELEMENTS */

static int pull_tx_output(const unsigned char **cursor, size_t *max,
                          bool is_pset, struct wally_tx_output **txout_out)
{
    const unsigned char *val, *script;
    size_t val_len, script_len;
    uint64_t satoshi;
    int ret;

    (void)is_pset;
    if (*txout_out)
        return WALLY_EINVAL; /* Duplicate */
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);

#ifdef BUILD_ELEMENTS
    if (is_pset) {
        const unsigned char *asset, *value, *nonce;
        size_t asset_len, value_len, nonce_len;

        if (!pull_commitment(&val, &val_len, &asset, &asset_len,
                             confidential_asset_length_from_bytes) ||
            !pull_commitment(&val, &val_len, &value, &value_len,
                             confidential_value_length_from_bytes) ||
            !pull_commitment(&val, &val_len, &nonce, &nonce_len,
                             confidential_nonce_length_from_bytes))
            return WALLY_EINVAL;

        /* Note unlike non-Elements, script can be empty for fee outputs */
        pull_varint_buff(&val, &val_len, &script, &script_len);
        ret = wally_tx_elements_output_init_alloc(script, script_len, asset, asset_len,
                                                  value, value_len, nonce, nonce_len,
                                                  NULL, 0, NULL, 0, txout_out);
        subfield_nomore_end(cursor, max, val, val_len);
        return ret;
    }
#endif /* BUILD_ELEMENTS */
    satoshi = pull_le64(&val, &val_len);
    pull_varint_buff(&val, &val_len, &script, &script_len);
    if (!script || !script_len)
        return WALLY_EINVAL;
    ret = wally_tx_output_init_alloc(satoshi, script, script_len, txout_out);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

/* Rewind cursor to prekey, and append unknown key/value to unknowns */
static int pull_unknown_key_value(const unsigned char **cursor, size_t *max,
                                  const unsigned char *pre_key,
                                  struct wally_map *unknowns)
{
    const unsigned char *key, *val;
    size_t key_len, val_len;

    /* If we've already failed, it's invalid */
    if (!*cursor)
        return WALLY_EINVAL;

    /* We have to unwind a bit, to get entire key again. */
    *max += (*cursor - pre_key);
    *cursor = pre_key;

    pull_varlength_buff(cursor, max, &key, &key_len);
    pull_varlength_buff(cursor, max, &val, &val_len);

    return map_add(unknowns, key, key_len, val, val_len, false, false);
}

static uint64_t pull_field_type(const unsigned char **cursor, size_t *max,
                                const unsigned char **key, size_t *key_len,
                                bool is_pset, bool *is_pset_ft)
{
    uint64_t field_type;
    *is_pset_ft = false;
    pull_subfield_start(cursor, max, *key_len, key, key_len);
    field_type = pull_varint(key, key_len);
    if (is_pset && field_type == WALLY_PSBT_PROPRIETARY_TYPE) {
#ifdef BUILD_ELEMENTS
        const size_t pset_key_len = pull_varlength(key, key_len);
        if (is_pset_key(*key, pset_key_len)) {
            pull_skip(key, key_len, PSET_PREFIX_LEN);
            field_type = pull_varint(key, key_len);
            *is_pset_ft = true;
        }
#endif /* BUILD_ELEMENTS */
    }
    return field_type;
}

static int pull_taproot_leaf_signature(const unsigned char **cursor, size_t *max,
                                       const unsigned char **key, size_t *key_len,
                                       struct wally_map *leaf_sigs)
{
    /* TODO: use schnorr/taproot constants here */
    const unsigned char *val, *xonly_hash;
    size_t val_len;

    /* key = x-only pubkey + leaf hash */
    if (*key_len != 64u || !(xonly_hash = pull_skip(key, key_len, *key_len)))
        return WALLY_EINVAL;
    subfield_nomore_end(cursor, max, *key, *key_len);

    pull_varlength_buff(cursor, max, &val, &val_len);
    if (!val || (val_len != 64u && val_len != 65))
        return WALLY_EINVAL; /* Invalid signature length */
    return map_add(leaf_sigs, xonly_hash, 64u, val, val_len, false, false);
}

static bool is_valid_control_block_len(size_t ctrl_len)
{
    return ctrl_len >= 33u && ctrl_len <= 33u + 128u * 32u &&
           ((ctrl_len - 33u) % 32u) == 0;
}

static int pull_taproot_leaf_script(const unsigned char **cursor, size_t *max,
                                    const unsigned char **key, size_t *key_len,
                                    struct wally_map *leaf_scripts)
{
    /* TODO: use taproot constants here */
    const unsigned char *ctrl, *val;
    size_t ctrl_len = *key_len, val_len;

    ctrl = pull_skip(key, key_len, ctrl_len);
    if (!ctrl || !is_valid_control_block_len(ctrl_len))
        return WALLY_EINVAL;
    subfield_nomore_end(cursor, max, *key, *key_len);

    pull_varlength_buff(cursor, max, &val, &val_len);
    if (!val || !val_len)
        return WALLY_EINVAL;

    return map_add(leaf_scripts, ctrl, ctrl_len, val, val_len, false, false);
}

static int pull_taproot_derivation(const unsigned char **cursor, size_t *max,
                                   const unsigned char **key, size_t *key_len,
                                   struct wally_map *leaf_hashes,
                                   struct wally_map *leaf_paths)
{
    const unsigned char *xonly = *key, *hashes, *val;
    size_t xonly_len = *key_len, num_hashes, hashes_len, val_len;
    int ret;

    if (xonly_len != EC_XONLY_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    num_hashes = pull_varint(&val, &val_len);
    hashes_len = num_hashes * SHA256_LEN;
    if (!(hashes = pull_skip(&val, &val_len, hashes_len)))
        return WALLY_EINVAL;

    if (val_len < sizeof(uint32_t) || val_len % sizeof(uint32_t))
        return WALLY_EINVAL; /* Invalid fingerprint + path */

    ret = map_add(leaf_hashes, xonly, xonly_len,
                  hashes_len ? hashes : NULL, hashes_len, false, false);
    if (ret == WALLY_OK) {
        ret = map_add(leaf_paths, xonly, xonly_len, val, val_len, false, false);
        if (ret == WALLY_OK) {
            pull_skip(&val, &val_len, val_len);
            subfield_nomore_end(cursor, max, val, val_len);
        }
    }
    return ret;
}

static struct wally_psbt *pull_psbt(const unsigned char **cursor, size_t *max)
{
    struct wally_psbt *psbt = NULL;
    const unsigned char *magic = pull_skip(cursor, max, sizeof(PSBT_MAGIC));
    int ret = WALLY_EINVAL;

    if (magic && !memcmp(magic, PSBT_MAGIC, sizeof(PSBT_MAGIC)))
        ret = wally_psbt_init_alloc(0, 0, 0, 8, 0, &psbt);
#ifdef BUILD_ELEMENTS
    else if (magic && !memcmp(magic, PSET_MAGIC, sizeof(PSET_MAGIC)))
        ret = wally_psbt_init_alloc(2, 0, 0, 8, WALLY_PSBT_INIT_PSET, &psbt);
#endif /* BUILD_ELEMENTS */
    return ret == WALLY_OK ? psbt : NULL;
}

static int pull_psbt_input(const struct wally_psbt *psbt,
                           const unsigned char **cursor, size_t *max,
                           uint32_t tx_flags, uint32_t flags,
                           struct wally_psbt_input *result)
{
    size_t key_len, val_len;
    const unsigned char *pre_key = *cursor, *val_p;
    const bool is_pset = (tx_flags & WALLY_TX_FLAG_USE_ELEMENTS) != 0;
    uint64_t mandatory = psbt->version == PSBT_0 ? PSBT_IN_MANDATORY_V0 : PSBT_IN_MANDATORY_V2;
    uint64_t disallowed = psbt->version == PSBT_0 ? PSBT_IN_DISALLOWED_V0 : PSBT_IN_DISALLOWED_V2;
    uint64_t keyset = 0;
    int ret = WALLY_OK;

    if (!is_pset) {
        /* PSBT: Remove mandatory/disallowed PSET fields */
        mandatory &= PSBT_FT_MASK;
        disallowed &= PSBT_FT_MASK;
    }

    /* Default any non-zero input values */
    result->sequence = WALLY_TX_SEQUENCE_FINAL;

    /* Read key value pairs */
    while (ret == WALLY_OK && (key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key;
        bool is_pset_ft;
        uint64_t field_type = pull_field_type(cursor, max, &key, &key_len, is_pset, &is_pset_ft);
        const uint64_t raw_field_type = field_type;
        uint64_t field_bit;
        bool is_known;

        if (is_pset_ft) {
            is_known = field_type <= PSET_IN_MAX;
            if (is_known) {
                field_type = PSET_FT(field_type);
                field_bit = field_type;
            }
        } else {
            is_known = field_type <= PSBT_IN_MAX;
            if (is_known)
                field_bit = PSBT_FT(field_type);
        }

        /* Process based on type */
        if (is_known) {
            if (keyset & field_bit && (!(field_bit & PSBT_IN_REPEATABLE))) {
                ret = WALLY_EINVAL; /* Duplicate value */
                break;
            }
            keyset |= field_bit;
            if (field_bit & PSBT_IN_HAVE_KEYDATA)
                pull_subfield_end(cursor, max, key, key_len);
            else
                subfield_nomore_end(cursor, max, key, key_len);

            switch (field_type) {
            case PSBT_IN_NON_WITNESS_UTXO:
                ret = pull_tx(cursor, max, tx_flags, &result->utxo);
                break;
            case PSBT_IN_WITNESS_UTXO:
                ret = pull_tx_output(cursor, max, is_pset, &result->witness_utxo);
                break;
            case PSBT_IN_PARTIAL_SIG:
                ret = pull_map_item(cursor, max, key, key_len, &result->signatures);
                break;
            case PSBT_IN_SIGHASH_TYPE:
                result->sighash = pull_le32_subfield(cursor, max);
                break;
            case PSBT_IN_BIP32_DERIVATION:
                ret = pull_map_item(cursor, max, key, key_len, &result->keypaths);
                break;
            case PSBT_IN_FINAL_SCRIPTWITNESS:
                ret = pull_witness(cursor, max, &result->final_witness, true);
                break;
            case PSBT_IN_RIPEMD160:
            case PSBT_IN_SHA256:
            case PSBT_IN_HASH160:
            case PSBT_IN_HASH256:
                ret = pull_preimage(cursor, max, field_type, key, key_len, &result->preimages);
                break;
            case PSBT_IN_REDEEM_SCRIPT:
            case PSBT_IN_WITNESS_SCRIPT:
            case PSBT_IN_FINAL_SCRIPTSIG:
            case PSBT_IN_POR_COMMITMENT:
            case PSBT_IN_TAP_KEY_SIG:
            case PSBT_IN_TAP_INTERNAL_KEY:
            case PSBT_IN_TAP_MERKLE_ROOT:
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = wally_map_add_integer(&result->psbt_fields, raw_field_type,
                                            val_p, val_len);
                break;
            case PSBT_IN_PREVIOUS_TXID:
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = wally_psbt_input_set_previous_txid(result, val_p, val_len);
                break;
            case PSBT_IN_OUTPUT_INDEX:
                result->index = pull_le32_subfield(cursor, max);
                if (is_pset && (result->index & ~WALLY_TX_INDEX_MASK) &&
                    (flags & WALLY_PSBT_PARSE_FLAG_STRICT))
                    ret = WALLY_EINVAL;
                result->index = MASK_INDEX(result->index);
                break;
            case PSBT_IN_SEQUENCE:
                result->sequence = pull_le32_subfield(cursor, max);
                break;
            case PSBT_IN_REQUIRED_TIME_LOCKTIME:
                ret = wally_psbt_input_set_required_locktime(result, pull_le32_subfield(cursor, max));
                break;
            case PSBT_IN_REQUIRED_HEIGHT_LOCKTIME:
                ret = wally_psbt_input_set_required_lockheight(result, pull_le32_subfield(cursor, max));
                break;
            case PSBT_IN_TAP_SCRIPT_SIG:
                ret = pull_taproot_leaf_signature(cursor, max, &key, &key_len,
                                                  &result->taproot_leaf_signatures);
                break;
            case PSBT_IN_TAP_LEAF_SCRIPT:
                ret = pull_taproot_leaf_script(cursor, max, &key, &key_len,
                                               &result->taproot_leaf_scripts);
                break;
            case PSBT_IN_TAP_BIP32_DERIVATION:
                ret = pull_taproot_derivation(cursor, max, &key, &key_len,
                                              &result->taproot_leaf_hashes,
                                              &result->taproot_leaf_paths);
                break;
#ifdef BUILD_ELEMENTS
            case PSET_FT(PSET_IN_EXPLICIT_VALUE):
                ret = wally_psbt_input_set_amount(result, pull_le64_subfield(cursor, max));
                break;
            case PSET_FT(PSET_IN_ISSUANCE_VALUE):
                ret = wally_psbt_input_set_issuance_amount(result,
                                                           pull_le64_subfield(cursor, max));
                break;
            case PSET_FT(PSET_IN_PEG_IN_VALUE):
                ret = wally_psbt_input_set_pegin_amount(result, pull_le64_subfield(cursor, max));
                break;
            case PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_AMOUNT):
                ret = wally_psbt_input_set_inflation_keys(result,
                                                          pull_le64_subfield(cursor, max));
                break;
            case PSET_FT(PSET_IN_PEG_IN_TX):
                /* Note 0 for tx_flags here as peg-in tx is from the base chain */
                ret = pull_tx(cursor, max, 0, &result->pegin_tx);
                break;
            case PSET_FT(PSET_IN_PEG_IN_WITNESS):
                ret = pull_witness(cursor, max, &result->pegin_witness, true);
                break;
            case PSET_FT(PSET_IN_ISSUANCE_VALUE_COMMITMENT):
            case PSET_FT(PSET_IN_ISSUANCE_VALUE_RANGEPROOF):
            case PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF):
            case PSET_FT(PSET_IN_PEG_IN_TXOUT_PROOF):
            case PSET_FT(PSET_IN_PEG_IN_GENESIS_HASH):
            case PSET_FT(PSET_IN_PEG_IN_CLAIM_SCRIPT):
            case PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT):
            case PSET_FT(PSET_IN_ISSUANCE_BLINDING_NONCE):
            case PSET_FT(PSET_IN_ISSUANCE_ASSET_ENTROPY):
            case PSET_FT(PSET_IN_UTXO_RANGEPROOF):
            case PSET_FT(PSET_IN_ISSUANCE_BLIND_VALUE_PROOF):
            case PSET_FT(PSET_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF):
            case PSET_FT(PSET_IN_VALUE_PROOF):
            case PSET_FT(PSET_IN_EXPLICIT_ASSET):
            case PSET_FT(PSET_IN_ASSET_PROOF):
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = wally_map_add_integer(&result->pset_fields, raw_field_type,
                                            val_p, val_len);
                break;
#endif /* BUILD_ELEMENTS */
            default:
                goto unknown;
            }
        } else {
unknown:
            /* Unknown case without elements or for unknown proprietary types */
            ret = pull_unknown_key_value(cursor, max, pre_key, &result->unknowns);
        }
        pre_key = *cursor;
    }

    if (mandatory && (keyset & mandatory) != mandatory)
        ret = WALLY_EINVAL; /* Mandatory field is missing */
    else if (disallowed && (keyset & disallowed))
        ret = WALLY_EINVAL; /* Disallowed field present */

    if (ret == WALLY_OK && result->sighash) {
        /* Verify that the sighash provided matches any signatures given */
        ret = wally_psbt_input_set_sighash(result, result->sighash);
    }

#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK && is_pset) {
        const uint32_t strict_flags = flags | WALLY_PSBT_PARSE_FLAG_STRICT;
        /* Commitment key isn't used for PSET_IN_EXPLICIT_VALUE/ASSET */
        const uint64_t unused_key = 0xffffffff;

        /* Explicit values are only valid if we have an input UTXO */
#define PSET_UTXO_BITS (PSET_FT(PSBT_IN_NON_WITNESS_UTXO) | PSET_FT(PSBT_IN_WITNESS_UTXO))

        if (!pset_check_proof(psbt, result, NULL, PSET_FT(PSET_IN_ISSUANCE_VALUE),
                              PSET_IN_ISSUANCE_VALUE_COMMITMENT,
                              PSET_IN_ISSUANCE_BLIND_VALUE_PROOF, flags) ||
            !pset_check_proof(psbt, result, NULL, PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_AMOUNT),
                              PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT,
                              PSET_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF, flags) ||
            !pset_check_proof(psbt, result, NULL, PSET_FT(PSET_IN_EXPLICIT_VALUE),
                              unused_key, PSET_IN_VALUE_PROOF, strict_flags) ||
            !pset_check_proof(psbt, result, NULL, PSET_FT(PSET_IN_EXPLICIT_ASSET),
                              unused_key, PSET_IN_ASSET_PROOF, strict_flags))
            ret = WALLY_EINVAL;
    }
#endif /* BUILD_ELEMENTS */
    (void)flags; /* For non-elements builds */
    return ret;
}

static int pull_psbt_output(const struct wally_psbt *psbt,
                            const unsigned char **cursor, size_t *max,
                            uint32_t tx_flags, uint32_t flags,
                            struct wally_psbt_output *result)
{
    size_t key_len, val_len;
    const unsigned char *pre_key = *cursor, *val_p;
    const bool is_pset = (tx_flags & WALLY_TX_FLAG_USE_ELEMENTS) != 0;
    uint64_t mandatory = psbt->version == PSBT_0 ? PSBT_OUT_MANDATORY_V0 : PSBT_OUT_MANDATORY_V2;
    uint64_t disallowed = psbt->version == PSBT_0 ? PSBT_OUT_DISALLOWED_V0 : PSBT_OUT_DISALLOWED_V2;
    uint64_t keyset = 0;
    int ret = WALLY_OK;

    if (!is_pset) {
        /* PSBT: Remove mandatory/disallowed PSET fields */
        mandatory &= PSBT_FT_MASK;
        disallowed &= PSBT_FT_MASK;
    }

    /* Read key value pairs */
    while (ret == WALLY_OK && (key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key;
        bool is_pset_ft;
        uint64_t field_type = pull_field_type(cursor, max, &key, &key_len, is_pset, &is_pset_ft);
        const uint64_t raw_field_type = field_type;
        uint64_t field_bit;
        bool is_known;

        if (is_pset_ft) {
            is_known = field_type <= PSET_OUT_MAX;
            if (is_known) {
                field_type = PSET_FT(field_type);
                field_bit = field_type;
            }
        } else {
            is_known = field_type <= PSBT_OUT_MAX;
            if (is_known)
                field_bit = PSBT_FT(field_type);
        }

        /* Process based on type */
        if (is_known) {
            if (keyset & field_bit && (!(field_bit & PSBT_OUT_REPEATABLE))) {
                ret = WALLY_EINVAL; /* Duplicate value */
                break;
            }
            keyset |= field_bit;
            if (field_bit & PSBT_OUT_HAVE_KEYDATA)
                pull_subfield_end(cursor, max, key, key_len);
            else
                subfield_nomore_end(cursor, max, key, key_len);

            switch (field_type) {
            case PSBT_OUT_BIP32_DERIVATION:
                ret = pull_map_item(cursor, max, key, key_len, &result->keypaths);
                break;
            case PSBT_OUT_AMOUNT:
                ret = wally_psbt_output_set_amount(result, pull_le64_subfield(cursor, max));
                break;
            case PSBT_OUT_SCRIPT:
                ret = pull_output_varbuf(cursor, max, result,
                                         wally_psbt_output_set_script);
                break;
            case PSBT_OUT_REDEEM_SCRIPT:
            case PSBT_OUT_WITNESS_SCRIPT:
            case PSBT_OUT_TAP_INTERNAL_KEY:
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = wally_map_add_integer(&result->psbt_fields, raw_field_type,
                                            val_p, val_len);
                break;
            case PSBT_OUT_TAP_TREE:
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                /* Add the leaf to the map keyed by its (1-based) position */
                ret = wally_map_add_integer(&result->taproot_tree,
                                            result->taproot_tree.num_items + 1,
                                            val_p, val_len);
                break;
            case PSBT_OUT_TAP_BIP32_DERIVATION:
                ret = pull_taproot_derivation(cursor, max, &key, &key_len,
                                              &result->taproot_leaf_hashes,
                                              &result->taproot_leaf_paths);
                break;
#ifdef BUILD_ELEMENTS
            case PSET_FT(PSET_OUT_BLINDER_INDEX):
                result->blinder_index = pull_le32_subfield(cursor, max);
                result->has_blinder_index = 1u;
                break;
            case PSET_FT(PSET_OUT_VALUE_COMMITMENT):
            case PSET_FT(PSET_OUT_ASSET):
            case PSET_FT(PSET_OUT_ASSET_COMMITMENT):
            case PSET_FT(PSET_OUT_VALUE_RANGEPROOF):
            case PSET_FT(PSET_OUT_ASSET_SURJECTION_PROOF):
            case PSET_FT(PSET_OUT_BLINDING_PUBKEY):
            case PSET_FT(PSET_OUT_ECDH_PUBKEY):
            case PSET_FT(PSET_OUT_BLIND_VALUE_PROOF):
            case PSET_FT(PSET_OUT_BLIND_ASSET_PROOF):
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = wally_map_add_integer(&result->pset_fields, raw_field_type,
                                            val_p, val_len);
                break;
#endif /* BUILD_ELEMENTS */
            default:
                goto unknown;
            }
        } else {
unknown:
            ret = pull_unknown_key_value(cursor, max, pre_key, &result->unknowns);
        }
        pre_key = *cursor;
    }
#ifdef BUILD_ELEMENTS
    if (is_pset) {
        /* Amount must be removed if commitments are present; therefore
         * unlike PSBT v2 it is not unconditionally mandatory */
        mandatory &= ~PSBT_FT(PSBT_OUT_AMOUNT);
    }
#endif /* BUILD_ELEMENTS */

    if (mandatory && (keyset & mandatory) != mandatory)
        ret = WALLY_EINVAL; /* Mandatory field is missing*/
    else if (disallowed && (keyset & disallowed))
        ret = WALLY_EINVAL; /* Disallowed field present */

#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK && is_pset) {
        if (!pset_check_proof(psbt, NULL, result, PSBT_FT(PSBT_OUT_AMOUNT),
                              PSET_OUT_VALUE_COMMITMENT,
                              PSET_OUT_BLIND_VALUE_PROOF, flags) ||
            !pset_check_proof(psbt, NULL, result, PSET_FT(PSET_OUT_ASSET),
                              PSET_OUT_ASSET_COMMITMENT,
                              PSET_OUT_BLIND_ASSET_PROOF, flags))
            ret = WALLY_EINVAL;
    }
#endif /* BUILD_ELEMENTS */
    (void)flags; /* For non-elements builds */
    return ret;
}

int wally_psbt_from_bytes(const unsigned char *bytes, size_t len,
                          uint32_t flags, struct wally_psbt **output)
{
    const unsigned char **cursor = &bytes;
    const unsigned char *pre_key;
    size_t *max = &len, i, key_len, input_count = 0, output_count = 0;
    uint32_t tx_flags = 0, pre144flag = WALLY_TX_FLAG_PRE_BIP144;
    uint64_t mandatory, disallowed, keyset = 0;
    bool is_pset = false;
    int ret = WALLY_OK;

    OUTPUT_CHECK;
    if (!bytes || len < sizeof(PSBT_MAGIC) || (flags & ~PSBT_ALL_PARSE_FLAGS) || !output)
        return WALLY_EINVAL;

    if (!(*output = pull_psbt(cursor, max)))
        return WALLY_EINVAL;

    if (memcmp((*output)->magic, PSBT_MAGIC, sizeof(PSBT_MAGIC))) {
        is_pset = true;
        tx_flags |= WALLY_TX_FLAG_USE_ELEMENTS; /* Elements PSET */
        pre144flag = 0;
    }
    /* Reset modifiable flags for loaded PSBTs */
    (*output)->tx_modifiable_flags = 0;
#ifdef BUILD_ELEMENTS
    (*output)->pset_modifiable_flags = 0;
#endif /* BUILD_ELEMENTS */

    /* Read globals first */
    pre_key = *cursor;
    while (ret == WALLY_OK && (key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key;
        bool is_pset_ft;
        uint64_t field_type = pull_field_type(cursor, max, &key, &key_len, is_pset, &is_pset_ft);
        uint64_t field_bit;
        bool is_known;

        if (is_pset_ft) {
            is_known = field_type <= PSET_GLOBAL_MAX;
            if (is_known) {
                field_type = PSET_FT(field_type);
                field_bit = field_type;
            }
        } else {
            is_known = field_type <= PSBT_GLOBAL_MAX || field_type == PSBT_GLOBAL_VERSION;
            if (is_known) {
                if (field_type == PSBT_GLOBAL_VERSION)
                    field_bit = PSBT_GLOBAL_VERSION_BIT;
                else
                    field_bit = PSBT_FT(field_type);
            }
        }

        /* Process based on type */
        if (is_known) {
            struct wally_tx *tx = NULL;

            if (keyset & field_bit && (!(field_bit & PSBT_GLOBAL_REPEATABLE))) {
                ret = WALLY_EINVAL; /* Duplicate value */
                break;
            }
            keyset |= field_bit;
            if (field_bit & PSBT_GLOBAL_HAVE_KEYDATA)
                pull_subfield_end(cursor, max, key, key_len);
            else
                subfield_nomore_end(cursor, max, key, key_len);

            switch (field_type) {
            case PSBT_GLOBAL_UNSIGNED_TX:
                if ((ret = pull_tx(cursor, max, tx_flags | pre144flag, &tx)) == WALLY_OK)
                    ret = psbt_set_global_tx(*output, tx, false);
                if (ret != WALLY_OK)
                    wally_tx_free(tx);
                break;
            case PSBT_GLOBAL_XPUB:
                ret = pull_map_item(cursor, max, key, key_len, &(*output)->global_xpubs);
                break;
            case PSBT_GLOBAL_VERSION:
                (*output)->version = pull_le32_subfield(cursor, max);
                if ((*output)->version != PSBT_0 && (*output)->version != PSBT_2)
                    ret = WALLY_EINVAL; /* Unsupported version number */
                break;
            case PSBT_GLOBAL_INPUT_COUNT:
                input_count = pull_varint_subfield(cursor, max);
                break;
            case PSBT_GLOBAL_OUTPUT_COUNT:
                output_count = pull_varint_subfield(cursor, max);
                break;
            case PSBT_GLOBAL_TX_VERSION:
                (*output)->tx_version = pull_le32_subfield(cursor, max);
                break;
            case PSBT_GLOBAL_FALLBACK_LOCKTIME:
                (*output)->fallback_locktime = pull_le32_subfield(cursor, max);
                (*output)->has_fallback_locktime = 1u;
                break;
            case PSBT_GLOBAL_TX_MODIFIABLE:
                (*output)->tx_modifiable_flags = pull_u8_subfield(cursor, max);
                if ((*output)->tx_modifiable_flags & ~PSBT_TXMOD_ALL_FLAGS)
                    ret = WALLY_EINVAL; /* Invalid flags */
                break;
#ifdef BUILD_ELEMENTS
            case PSET_FT(PSET_GLOBAL_SCALAR): {
                const unsigned char *workaround;
                size_t workaround_len;

                /* Work around an elements bug with scalars */
                pull_varlength_buff(cursor, max, &workaround, &workaround_len);
                ret = map_add(&(*output)->global_scalars, key, key_len, NULL, 0, false, false);
                break;
            }
            case PSET_FT(PSET_GLOBAL_TX_MODIFIABLE):
                (*output)->pset_modifiable_flags = pull_u8_subfield(cursor, max);
                /* Ignore the reserved flag if set */
                (*output)->pset_modifiable_flags &= ~WALLY_PSET_TXMOD_RESERVED;
                if ((*output)->pset_modifiable_flags & ~PSET_TXMOD_ALL_FLAGS)
                    ret = WALLY_EINVAL; /* Invalid flags */
                break;
#endif /* BUILD_ELEMENTS */
            default:
                goto unknown;
            }
        } else {
unknown:
            ret = pull_unknown_key_value(cursor, max, pre_key, &(*output)->unknowns);
        }
        pre_key = *cursor;
    }

    mandatory = (*output)->version == PSBT_0 ? PSBT_GLOBAL_MANDATORY_V0 : PSBT_GLOBAL_MANDATORY_V2;
    disallowed = (*output)->version == PSBT_0 ? PSBT_GLOBAL_DISALLOWED_V0 : PSBT_GLOBAL_DISALLOWED_V2;
    if (!is_pset) {
        /* PSBT: Remove mandatory/disallowed PSET fields */
        mandatory &= PSBT_FT_MASK;
        disallowed &= PSBT_FT_MASK;
    }
    if (mandatory && (keyset & mandatory) != mandatory)
        ret = WALLY_EINVAL; /* Mandatory field is missing*/
    else if (disallowed && (keyset & disallowed))
        ret = WALLY_EINVAL; /* Disallowed field present */

    if (ret == WALLY_OK && (*output)->version == PSBT_2) {
        if ((*output)->tx_version < 2)
            ret = WALLY_EINVAL; /* Tx version must be >= 2 */
        else {
            struct wally_psbt tmp;
            ret = psbt_init((*output)->version, input_count, output_count,
                            0, 0, input_count, output_count, &tmp);
            if (ret == WALLY_OK) {
                /* Steal the allocated input/output arrays */
                (*output)->inputs = tmp.inputs;
                (*output)->inputs_allocation_len = tmp.inputs_allocation_len;
                (*output)->outputs = tmp.outputs;
                (*output)->outputs_allocation_len = tmp.outputs_allocation_len;
                psbt_claim_allocated_inputs(*output, input_count, output_count);
            }
        }
    }

    /* Read inputs */
    for (i = 0; ret == WALLY_OK && i < (*output)->num_inputs; ++i)
        ret = pull_psbt_input(*output, cursor, max, tx_flags,flags,
                              (*output)->inputs + i);

    /* Read outputs */
    for (i = 0; ret == WALLY_OK && i < (*output)->num_outputs; ++i)
        ret = pull_psbt_output(*output, cursor, max, tx_flags, flags,
                               (*output)->outputs + i);

    if (ret == WALLY_OK && !*cursor)
        ret = WALLY_EINVAL; /* Ran out of data */

    if (ret != WALLY_OK) {
        wally_psbt_free(*output);
        *output = NULL;
    }
    return ret;
}

int wally_psbt_get_length(const struct wally_psbt *psbt, uint32_t flags, size_t *written)
{
    return wally_psbt_to_bytes(psbt, flags, NULL, 0, written);
}

static void push_psbt_key(unsigned char **cursor, size_t *max,
                          uint64_t type, const void *extra, size_t extra_len)
{
    push_varint(cursor, max, varint_get_length(type) + extra_len);
    push_varint(cursor, max, type);
    push_bytes(cursor, max, extra, extra_len);
}

#ifdef BUILD_ELEMENTS
static void push_pset_key(unsigned char **cursor, size_t *max,
                          uint64_t type, const void *extra, size_t extra_len)
{
    const size_t prefix_len = 6u; /* PROPRIETARY_TYPE + len("pset") + "pset" */
    push_varint(cursor, max, prefix_len + varint_get_length(type) + extra_len);
    push_varint(cursor, max, WALLY_PSBT_PROPRIETARY_TYPE);
    push_varbuff(cursor, max, PSET_MAGIC, PSET_PREFIX_LEN);
    push_varint(cursor, max, type);
    push_bytes(cursor, max, extra, extra_len);
}
#endif /* BUILD_ELEMENTS */

static void push_key(unsigned char **cursor, size_t *max,
                     uint64_t type, bool is_pset,
                     const void *extra, size_t extra_len)
{
    (void)is_pset;
#ifdef BUILD_ELEMENTS
    if (is_pset)
        push_pset_key(cursor, max, type, extra, extra_len);
    else
#endif
    push_psbt_key(cursor, max, type, extra, extra_len);
}

static int push_length_and_tx(unsigned char **cursor, size_t *max,
                              const struct wally_tx *tx, uint32_t flags)
{
    int ret;
    size_t tx_len;
    unsigned char *p;

    if ((ret = wally_tx_get_length(tx, flags, &tx_len)) != WALLY_OK)
        return ret;

    push_varint(cursor, max, tx_len);

    /* TODO: convert wally_tx to use push  */
    if (!(p = push_bytes(cursor, max, NULL, tx_len)))
        return WALLY_OK; /* We catch this in caller. */

    return wally_tx_to_bytes(tx, flags, p, tx_len, &tx_len);
}

static void push_witness(unsigned char **cursor, size_t *max,
                         uint64_t type, bool is_pset,
                         const struct wally_tx_witness_stack *witness)
{
    size_t wit_len = 0;
    push_witness_stack(NULL, &wit_len, witness); /* calculate length */

    push_key(cursor, max, type, is_pset, NULL, 0);
    push_varint(cursor, max, wit_len);
    push_witness_stack(cursor, max, witness);
}

static void push_psbt_varbuff(unsigned char **cursor, size_t *max,
                              uint64_t type, bool is_pset,
                              const unsigned char *bytes, size_t bytes_len)
{
    if (bytes) {
        push_key(cursor, max, type, is_pset, NULL, 0);
        push_varbuff(cursor, max, bytes, bytes_len);
    }
}

static void push_psbt_le32(unsigned char **cursor, size_t *max,
                           uint64_t type, bool is_pset, uint32_t value)
{
    push_key(cursor, max, type, is_pset, NULL, 0);
    push_varint(cursor, max, sizeof(value));
    push_le32(cursor, max, value);
}

static void push_psbt_le64(unsigned char **cursor, size_t *max,
                           uint64_t type, bool is_pset, uint64_t value)
{
    push_key(cursor, max, type, is_pset, NULL, 0);
    push_varint(cursor, max, sizeof(value));
    push_le64(cursor, max, value);
}

static void push_map(unsigned char **cursor, size_t *max,
                     const struct wally_map *map_in)
{
    size_t i;
    for (i = 0; i < map_in->num_items; ++i) {
        const struct wally_map_item *item = map_in->items + i;
        push_varbuff(cursor, max, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
}

static void push_psbt_map(unsigned char **cursor, size_t *max,
                          uint64_t type, bool is_pset,
                          const struct wally_map *map_in)
{
    size_t i;
    for (i = 0; i < map_in->num_items; ++i) {
        const struct wally_map_item *item = map_in->items + i;
        push_key(cursor, max, type, is_pset, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
}

static int push_preimages(unsigned char **cursor, size_t *max,
                          const struct wally_map *map_in)
{
    size_t i;
    for (i = 0; i < map_in->num_items; ++i) {
        const struct wally_map_item *item = map_in->items + i;
        const uint64_t type = item->key[0];

        push_key(cursor, max, type, false, item->key + 1, item->key_len - 1);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
    return WALLY_OK;
}

static int push_taproot_leaf_signatures(unsigned char **cursor, size_t *max, size_t ft,
                                        const struct wally_map *leaf_sigs)
{
    size_t i;

    for (i = 0; i < leaf_sigs->num_items; ++i) {
        const struct wally_map_item *item = leaf_sigs->items + i;
        push_key(cursor, max, ft, false, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
    return WALLY_OK;
}

static int push_taproot_leaf_scripts(unsigned char **cursor, size_t *max, size_t ft,
                                     const struct wally_map *leaf_scripts)
{
    size_t i;

    for (i = 0; i < leaf_scripts->num_items; ++i) {
        const struct wally_map_item *item = leaf_scripts->items + i;

        if (!is_valid_control_block_len(item->key_len) || !item->value_len)
            return WALLY_EINVAL;

        push_key(cursor, max, ft, false, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
    return WALLY_OK;
}

static size_t get_taproot_derivation_size(size_t num_hashes, size_t path_len)
{
    return varint_get_length(num_hashes) + num_hashes * SHA256_LEN +
           sizeof(uint32_t) + path_len * sizeof(uint32_t);
}

static int push_taproot_derivation(unsigned char **cursor, size_t *max, size_t ft,
                                   const struct wally_map *leaf_hashes,
                                   const struct wally_map *leaf_paths)
{
    size_t i, index, num_hashes, num_children;
    const struct wally_map_item *hashes, *path;
    int ret;

    for (i = 0; i < leaf_paths->num_items; ++i) {
        /* Find the hashes to write with this xonly keys path */
        path = leaf_paths->items + i;
        if (path->value_len < sizeof(uint32_t) || path->value_len % sizeof(uint32_t))
            return WALLY_EINVAL; /* Invalid fingerprint + path */

        ret = wally_map_find(leaf_hashes, path->key, path->key_len, &index);
        if (ret != WALLY_OK || !index)
            return WALLY_EINVAL; /* Corresponding hashes not found */

        hashes = leaf_hashes->items + index - 1;
        num_hashes = hashes->value_len / SHA256_LEN;
        num_children = path->value_len / sizeof(uint32_t) - 1;

        /* Key is the x-only pubkey */
        push_key(cursor, max, ft, false, path->key, path->key_len);
        /* Compute and write the length of the associated data */
        push_varint(cursor, max, get_taproot_derivation_size(num_hashes, num_children));
        /* <hashes len> <leaf hash>* */
        push_varint(cursor, max, num_hashes); /* Not the length as BIP371 suggests */
        push_bytes(cursor, max, hashes->value, hashes->value_len);
        /* <4 byte fingerprint> <32-bit uint>* */
        push_bytes(cursor, max, path->value, path->value_len);
    }
    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
static bool push_commitment(unsigned char **cursor, size_t *max,
                            const unsigned char *commitment, size_t commitment_len)
{
    if (!BYTES_VALID(commitment, commitment_len))
        return false;
    if (!commitment)
        push_u8(cursor, max, 0); /* NULL commitment */
    else
        push_bytes(cursor, max, commitment, commitment_len);
    return true;
}
#endif /* BUILD_ELEMENTS */

static int push_tx_output(unsigned char **cursor, size_t *max,
                          bool is_pset, const struct wally_tx_output *txout)
{
#ifdef BUILD_ELEMENTS
    if (is_pset) {
        if (!push_commitment(cursor, max, txout->asset, txout->asset_len) ||
            !push_commitment(cursor, max, txout->value, txout->value_len) ||
            !push_commitment(cursor, max, txout->nonce, txout->nonce_len))
            return WALLY_EINVAL;
        push_varbuff(cursor, max, txout->script, txout->script_len);
    } else
#endif /* BUILD_ELEMENTS */
    {
        (void)is_pset;
        push_le64(cursor, max, txout->satoshi);
        push_varbuff(cursor, max, txout->script, txout->script_len);
    }
    return WALLY_OK;
}

static int push_varbuff_from_map(unsigned char **cursor, size_t *max,
                                 uint64_t type, uint32_t key, bool is_pset,
                                 const struct wally_map *map_in)
{
    size_t index;
    int ret = wally_map_find_integer(map_in, key, &index);
    if (ret == WALLY_OK && index) {
        const struct wally_map_item *item = map_in->items + index - 1;
        push_psbt_varbuff(cursor, max, type, is_pset,
                          item->value, item->value_len);
    }
    return ret;
}

static int push_psbt_input(const struct wally_psbt *psbt,
                           unsigned char **cursor, size_t *max,
                           uint32_t tx_flags, uint32_t flags,
                           const struct wally_psbt_input *input)
{
    const bool is_pset = (tx_flags & WALLY_TX_FLAG_USE_ELEMENTS) != 0;
    int ret;
    const struct wally_map_item *final_scriptsig;

    /* Non witness utxo */
    if (input->utxo) {
        push_psbt_key(cursor, max, PSBT_IN_NON_WITNESS_UTXO, NULL, 0);
        if ((ret = push_length_and_tx(cursor, max,
                                      input->utxo,
                                      WALLY_TX_FLAG_USE_WITNESS)) != WALLY_OK)
            return ret;
    }

    /* Witness utxo */
    if (input->witness_utxo) {
        size_t txout_len = 0;
        push_psbt_key(cursor, max, PSBT_IN_WITNESS_UTXO, NULL, 0);
        /* Push the txout length then its contents */
        ret = push_tx_output(NULL, &txout_len, is_pset, input->witness_utxo);
        if (ret == WALLY_OK) {
            push_varint(cursor, max, txout_len);
            ret = push_tx_output(cursor, max, is_pset, input->witness_utxo);
        }
        if (ret != WALLY_OK)
            return ret;
    }

    final_scriptsig = wally_map_get_integer(&input->psbt_fields, PSBT_IN_FINAL_SCRIPTSIG);
    if ((!input->final_witness && !final_scriptsig) ||
        (flags & WALLY_PSBT_SERIALIZE_FLAG_REDUNDANT)) {
        /* BIP-0174 is clear that once finalized, these members should be
         * removed from the PSBT and therefore obviously not serialized.
         * If an input is finalized eternally (by setting final_witness/
         * final_scriptsig directly), then these fields may still be present
         * in the PSBT. By default, wally will not serialize them in that case
         * unless WALLY_PSBT_SERIALIZE_FLAG_REDUNDANT is given, since doing so
         * violates the spec and makes the PSBT unnecessarily larger.
         * WALLY_PSBT_SERIALIZE_FLAG_REDUNDANT is supported to allow matching
         * the buggy behaviour of other implementations, since it seems there
         * is already code incorrectly relying on this behaviour in the wild.
         */
        /* Partial sigs */
        push_psbt_map(cursor, max, PSBT_IN_PARTIAL_SIG, false, &input->signatures);
        /* Sighash type */
        if (input->sighash)
            push_psbt_le32(cursor, max, PSBT_IN_SIGHASH_TYPE, false, input->sighash);

        if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_REDEEM_SCRIPT,
                                         PSBT_IN_REDEEM_SCRIPT,
                                         false, &input->psbt_fields)) != WALLY_OK)
            return ret;

        if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_WITNESS_SCRIPT,
                                         PSBT_IN_WITNESS_SCRIPT,
                                         false, &input->psbt_fields)) != WALLY_OK)
            return ret;

        /* Keypaths */
        push_psbt_map(cursor, max, PSBT_IN_BIP32_DERIVATION, false, &input->keypaths);
    }

    if (final_scriptsig)
        push_psbt_varbuff(cursor, max, PSBT_IN_FINAL_SCRIPTSIG, false,
                          final_scriptsig->value, final_scriptsig->value_len);

    /* Final scriptWitness */
    if (input->final_witness)
        push_witness(cursor, max, PSBT_IN_FINAL_SCRIPTWITNESS,
                     false, input->final_witness);

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_POR_COMMITMENT,
                                     PSBT_IN_POR_COMMITMENT,
                                     false, &input->psbt_fields)) != WALLY_OK)
        return ret;

    if ((ret = push_preimages(cursor, max, &input->preimages)) != WALLY_OK)
        return ret;

    if (psbt->version == PSBT_2) {
        if (mem_is_zero(input->txhash, WALLY_TXHASH_LEN))
            return WALLY_EINVAL; /* No previous txid provided */
        push_psbt_varbuff(cursor, max, PSBT_IN_PREVIOUS_TXID, false,
                          input->txhash, sizeof(input->txhash));

        push_psbt_le32(cursor, max, PSBT_IN_OUTPUT_INDEX, false, input->index);

        if (input->sequence != WALLY_TX_SEQUENCE_FINAL)
            push_psbt_le32(cursor, max, PSBT_IN_SEQUENCE, false, input->sequence);

        if (input->required_locktime)
            push_psbt_le32(cursor, max, PSBT_IN_REQUIRED_TIME_LOCKTIME, false, input->required_locktime);

        if (input->required_lockheight)
            push_psbt_le32(cursor, max, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, false, input->required_lockheight);
    }

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_TAP_KEY_SIG,
                                     PSBT_IN_TAP_KEY_SIG,
                                     false, &input->psbt_fields)) != WALLY_OK)
        return ret;

    if ((ret = push_taproot_leaf_signatures(cursor, max, PSBT_IN_TAP_SCRIPT_SIG,
                                            &input->taproot_leaf_signatures)) != WALLY_OK)
        return ret;

    if ((ret = push_taproot_leaf_scripts(cursor, max, PSBT_IN_TAP_LEAF_SCRIPT,
                                         &input->taproot_leaf_scripts)) != WALLY_OK)
        return ret;

    if (input->taproot_leaf_hashes.num_items) {
        ret = push_taproot_derivation(cursor, max, PSBT_IN_TAP_BIP32_DERIVATION,
                                      &input->taproot_leaf_hashes,
                                      &input->taproot_leaf_paths);
        if (ret != WALLY_OK)
            return ret;
    }

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_TAP_INTERNAL_KEY,
                                     PSBT_IN_TAP_INTERNAL_KEY,
                                     false, &input->psbt_fields)) != WALLY_OK)
        return ret;
    if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_TAP_MERKLE_ROOT,
                                     PSBT_IN_TAP_MERKLE_ROOT,
                                     false, &input->psbt_fields)) != WALLY_OK)
        return ret;

#ifdef BUILD_ELEMENTS
    if (is_pset && psbt->version == PSBT_2) {
        uint32_t ft;
        for (ft = PSET_IN_ISSUANCE_VALUE; ft <= PSET_IN_MAX; ++ft) {
            switch (ft) {
            case PSET_IN_EXPLICIT_VALUE:
                /* Note we only output an explicit value if we have its proof */
                if (input->has_amount && wally_map_get_integer(&input->pset_fields, PSET_IN_VALUE_PROOF))
                    push_psbt_le64(cursor, max, ft, true, input->amount);
                break;
            case PSET_IN_ISSUANCE_VALUE:
                if (input->issuance_amount)
                    push_psbt_le64(cursor, max, ft, true, input->issuance_amount);
                break;
            case PSET_IN_PEG_IN_TX:
                if (input->pegin_tx) {
                    push_key(cursor, max, ft, true, NULL, 0);
                    if ((ret = push_length_and_tx(cursor, max, input->pegin_tx,
                                                  WALLY_TX_FLAG_USE_WITNESS)) != WALLY_OK)
                        return ret;
                }
                break;
            case PSET_IN_PEG_IN_VALUE:
                if (input->pegin_amount)
                    push_psbt_le64(cursor, max, ft, true, input->pegin_amount);
                break;
            case PSET_IN_PEG_IN_WITNESS:
                if (input->pegin_witness)
                    push_witness(cursor, max, ft, true, input->pegin_witness);
                break;
            case PSET_IN_ISSUANCE_INFLATION_KEYS_AMOUNT:
                if (input->inflation_keys)
                    push_psbt_le64(cursor, max, ft, true, input->inflation_keys);
                break;
            default:
                ret = push_varbuff_from_map(cursor, max, ft, ft, true,
                                            &input->pset_fields);
                if (ret != WALLY_OK)
                    return ret;
                break;
            }
        }
    }
#endif /* BUILD_ELEMENTS */

    /* Unknowns */
    push_map(cursor, max, &input->unknowns);
    /* Separator */
    push_u8(cursor, max, PSBT_SEPARATOR);
    return WALLY_OK;
}

static int push_psbt_output(const struct wally_psbt *psbt,
                            unsigned char **cursor, size_t *max, bool is_pset,
                            const struct wally_psbt_output *output)
{
    size_t i;
    unsigned char dummy = 0;
    int ret;

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_OUT_REDEEM_SCRIPT,
                                     PSBT_OUT_REDEEM_SCRIPT,
                                     false, &output->psbt_fields)) != WALLY_OK)
        return ret;

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_OUT_WITNESS_SCRIPT,
                                     PSBT_OUT_WITNESS_SCRIPT,
                                     false, &output->psbt_fields)) != WALLY_OK)
        return ret;

    /* Keypaths */
    push_psbt_map(cursor, max, PSBT_OUT_BIP32_DERIVATION, false, &output->keypaths);

    if (psbt->version == PSBT_2) {
        if (!is_pset && (!output->has_amount || !output->script || !output->script_len))
            return WALLY_EINVAL; /* Must be provided */

        if (output->has_amount)
            push_psbt_le64(cursor, max, PSBT_OUT_AMOUNT, false, output->amount);

        /* Core/Elements always write the script; if missing its written as empty */
        push_psbt_varbuff(cursor, max, PSBT_OUT_SCRIPT, false,
                          output->script ? output->script : &dummy,
                          output->script_len);
    }

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_OUT_TAP_INTERNAL_KEY,
                                     PSBT_OUT_TAP_INTERNAL_KEY,
                                     false, &output->psbt_fields)) != WALLY_OK)
        return ret;

    for (i = 0; i < output->taproot_tree.num_items; ++i) {
        ret = push_varbuff_from_map(cursor, max, PSBT_OUT_TAP_TREE, i + 1,
                                    false, &output->taproot_tree);
        if (ret != WALLY_OK)
            return ret;
    }

    if (output->taproot_leaf_hashes.num_items) {
        ret = push_taproot_derivation(cursor, max, PSBT_OUT_TAP_BIP32_DERIVATION,
                                      &output->taproot_leaf_hashes,
                                      &output->taproot_leaf_paths);
        if (ret != WALLY_OK)
            return ret;
    }

#ifdef BUILD_ELEMENTS
    if (is_pset && psbt->version == PSBT_2) {
        uint32_t ft;
        for (ft = PSET_OUT_VALUE_COMMITMENT; ft <= PSET_OUT_MAX; ++ft) {
            switch (ft) {
            case PSET_OUT_BLINDER_INDEX:
                if (output->has_blinder_index)
                    push_psbt_le32(cursor, max, ft, true, output->blinder_index);
                break;
            default:
                ret = push_varbuff_from_map(cursor, max, ft, ft, true,
                                            &output->pset_fields);
                if (ret != WALLY_OK)
                    return ret;
                break;
            }
        }
    }
#endif /* BUILD_ELEMENTS */

    /* Unknowns */
    push_map(cursor, max, &output->unknowns);
    /* Separator */
    push_u8(cursor, max, PSBT_SEPARATOR);
    return WALLY_OK;
}

int wally_psbt_to_bytes(const struct wally_psbt *psbt, uint32_t flags,
                        unsigned char *bytes_out, size_t len,
                        size_t *written)
{
    unsigned char *cursor = bytes_out;
    size_t max = len, i, is_pset;
    uint32_t tx_flags;
    int ret;

    if (written)
        *written = 0;

    if (!psbt_is_valid(psbt) || flags & ~WALLY_PSBT_SERIALIZE_FLAG_REDUNDANT ||
        !written)
        return WALLY_EINVAL;

    if ((ret = wally_psbt_is_elements(psbt, &is_pset)) != WALLY_OK)
        return ret;

    tx_flags = is_pset ? WALLY_TX_FLAG_USE_ELEMENTS : 0;
    push_bytes(&cursor, &max, psbt->magic, sizeof(psbt->magic));

    /* Global tx */
    if (psbt->tx) {
        push_psbt_key(&cursor, &max, PSBT_GLOBAL_UNSIGNED_TX, NULL, 0);
        ret = push_length_and_tx(&cursor, &max, psbt->tx,
                                 WALLY_TX_FLAG_ALLOW_PARTIAL | WALLY_TX_FLAG_PRE_BIP144);
        if (ret != WALLY_OK)
            return ret;
    }
    /* Global XPubs */
    push_psbt_map(&cursor, &max, PSBT_GLOBAL_XPUB, false, &psbt->global_xpubs);

    if (psbt->version == PSBT_2) {
        size_t n;
        unsigned char buf[sizeof(uint8_t) + sizeof(uint64_t)];

        push_psbt_le32(&cursor, &max, PSBT_GLOBAL_TX_VERSION, false, psbt->tx_version);

        if (psbt->has_fallback_locktime)
            push_psbt_le32(&cursor, &max, PSBT_GLOBAL_FALLBACK_LOCKTIME, false, psbt->fallback_locktime);

        push_psbt_key(&cursor, &max, PSBT_GLOBAL_INPUT_COUNT, NULL, 0);
        n = varint_to_bytes(psbt->num_inputs, buf);
        push_varbuff(&cursor, &max, buf, n);

        push_psbt_key(&cursor, &max, PSBT_GLOBAL_OUTPUT_COUNT, NULL, 0);
        n = varint_to_bytes(psbt->num_outputs, buf);
        push_varbuff(&cursor, &max, buf, n);

        if (psbt->tx_modifiable_flags) {
            push_psbt_key(&cursor, &max, PSBT_GLOBAL_TX_MODIFIABLE, NULL, 0);
            push_varint(&cursor, &max, sizeof(uint8_t));
            push_u8(&cursor, &max, psbt->tx_modifiable_flags & 0xff);
        }
#ifdef BUILD_ELEMENTS
        push_psbt_map(&cursor, &max, PSET_GLOBAL_SCALAR, true, &psbt->global_scalars);

        if (psbt->pset_modifiable_flags) {
            push_key(&cursor, &max, PSET_GLOBAL_TX_MODIFIABLE, true, NULL, 0);
            push_varint(&cursor, &max, sizeof(uint8_t));
            push_u8(&cursor, &max, psbt->pset_modifiable_flags);
        }
#endif /* BUILD_ELEMENTS */
    }

    if (psbt->version == PSBT_2)
        push_psbt_le32(&cursor, &max, PSBT_GLOBAL_VERSION, false, psbt->version);

    /* Unknowns */
    push_map(&cursor, &max, &psbt->unknowns);

    /* Separator */
    push_u8(&cursor, &max, PSBT_SEPARATOR);

    /* Push each input and output */
    for (i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input *input = &psbt->inputs[i];
        if ((ret = push_psbt_input(psbt, &cursor, &max, tx_flags, flags, input)) != WALLY_OK)
            return ret;
    }
    for (i = 0; i < psbt->num_outputs; ++i) {
        const struct wally_psbt_output *output = &psbt->outputs[i];
        if ((ret = push_psbt_output(psbt, &cursor, &max, !!is_pset, output)) != WALLY_OK)
            return ret;
    }

    if (cursor == NULL) {
        /* Once cursor is NULL, max holds how many bytes we needed */
        *written = len + max;
    } else {
        *written = len - max;
    }

    return WALLY_OK;
}

int wally_psbt_from_base64(const char *base64, uint32_t flags, struct wally_psbt **output)
{
    unsigned char *decoded;
    size_t max_len, written;
    int ret;

    OUTPUT_CHECK;
    if ((ret = wally_base64_get_maximum_length(base64, 0, &max_len)) != WALLY_OK)
        return ret;

    /* Allocate the buffer to decode into */
    if ((decoded = wally_malloc(max_len)) == NULL)
        return WALLY_ENOMEM;

    /* Decode the base64 psbt into binary */
    if ((ret = wally_base64_to_bytes(base64, 0, decoded, max_len, &written)) != WALLY_OK)
        goto done;

    if (written <= sizeof(PSBT_MAGIC)) {
        ret = WALLY_EINVAL; /* Not enough bytes for the magic + any data */
        goto done;
    }
    if (written > max_len) {
        ret = WALLY_ERROR; /* Max len too small, should never happen! */
        goto done;
    }

    /* decode the psbt */
    ret = wally_psbt_from_bytes(decoded, written, flags, output);

done:
    clear_and_free(decoded, max_len);
    return ret;
}

int wally_psbt_to_base64(const struct wally_psbt *psbt, uint32_t flags, char **output)
{
    unsigned char *buff;
    size_t len, written;
    int ret;

    OUTPUT_CHECK;

    if ((ret = wally_psbt_get_length(psbt, flags, &len)) != WALLY_OK)
        return ret;

    if ((buff = wally_malloc(len)) == NULL)
        return WALLY_ENOMEM;

    /* Get psbt bytes */
    if ((ret = wally_psbt_to_bytes(psbt, flags, buff, len, &written)) != WALLY_OK)
        goto done;

    if (written != len) {
        ret = WALLY_ERROR; /* Length calculated incorrectly */
        goto done;
    }

    /* Base64 encode */
    ret = wally_base64_from_bytes(buff, len, 0, output);

done:
    clear_and_free(buff, len);
    return ret;
}

static int combine_txs(struct wally_tx **dst, struct wally_tx *src)
{
    if (!dst)
        return WALLY_EINVAL;

    if (!*dst && src)
        return tx_clone_alloc(src, dst);

    return WALLY_OK;
}

static int combine_map_if_empty(struct wally_map *dst, const struct wally_map *src)
{
    if (!dst->num_items && src->num_items)
        return wally_map_combine(dst, src);
    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
static int combine_map_item(struct wally_map *dst, const struct wally_map *src, uint32_t ft)
{
    if (!wally_map_get_integer(dst, ft)) {
        const struct wally_map_item *src_item;
        if ((src_item = wally_map_get_integer(src, ft)))
            return wally_map_add_integer(dst, ft, src_item->value, src_item->value_len);
    }
    return WALLY_OK;
}

static int merge_value_commitment(struct wally_map *dst_fields, uint64_t *dst_amount,
                                  const struct wally_map *src_fields, uint64_t src_amount,
                                  uint32_t ft, bool for_clone)
{
    const struct wally_map_item *dst_commitment, *src_commitment;
    bool have_dst_commitment, have_src_commitment;
    int ret;

    dst_commitment = wally_map_get_integer(dst_fields, ft);
    have_dst_commitment = dst_commitment && dst_commitment->value_len != 1u;
    src_commitment = wally_map_get_integer(src_fields, ft);
    have_src_commitment = src_commitment && src_commitment->value_len != 1u;

    if (for_clone || (!*dst_amount && !have_dst_commitment && src_amount)) {
        /* We don't have an amount or a commitment for one, copy source amount */
        *dst_amount = src_amount;
    }
    if (!have_dst_commitment && have_src_commitment) {
        /* Source has an amount commitment, copy it and clear our value */
        ret = wally_map_replace_integer(dst_fields, ft,
                                        src_commitment->value, src_commitment->value_len);
        if (ret != WALLY_OK)
            return ret;
        if (!for_clone) {
            /* Not cloning: clear the amount when we have a committment to it */
            *dst_amount = 0;
        }
    }
    return WALLY_OK;
}
#endif /* BUILD_ELEMENTS */

static int combine_input(struct wally_psbt_input *dst,
                         const struct wally_psbt_input *src,
                         bool is_pset, bool for_clone)
{
    int ret;

    if (for_clone && mem_is_zero(dst->txhash, WALLY_TXHASH_LEN)) {
        memcpy(dst->txhash, src->txhash, WALLY_TXHASH_LEN);
        dst->index = src->index;
    } else if (memcmp(dst->txhash, src->txhash, WALLY_TXHASH_LEN) ||
               dst->index != src->index)
        return WALLY_EINVAL; /* Mismatched inputs */

    if (dst->sequence == WALLY_TX_SEQUENCE_FINAL)
        dst->sequence = src->sequence;

    if ((ret = combine_txs(&dst->utxo, src->utxo)) != WALLY_OK)
        return ret;

    if (!dst->witness_utxo && src->witness_utxo) {
        ret = wally_tx_output_clone_alloc(src->witness_utxo, &dst->witness_utxo);
        if (ret != WALLY_OK)
            return ret;
    }

    if (!dst->final_witness && src->final_witness &&
        (ret = wally_psbt_input_set_final_witness(dst, src->final_witness)) != WALLY_OK)
        return ret;
    if ((ret = wally_map_combine(&dst->keypaths, &src->keypaths)) != WALLY_OK)
        return ret;
    if ((ret = wally_map_combine(&dst->signatures, &src->signatures)) != WALLY_OK)
        return ret;
    if ((ret = wally_map_combine(&dst->unknowns, &src->unknowns)) != WALLY_OK)
        return ret;
    if (!dst->sighash && src->sighash)
        dst->sighash = src->sighash;
    if (!dst->required_locktime && src->required_locktime)
        dst->required_locktime = src->required_locktime;
    if (!dst->required_lockheight && src->required_lockheight)
        dst->required_lockheight = src->required_lockheight;
    if ((ret = wally_map_combine(&dst->preimages, &src->preimages)) != WALLY_OK)
        return ret;
    if ((ret = wally_map_combine(&dst->psbt_fields, &src->psbt_fields)) != WALLY_OK)
        return ret;
    if ((ret = combine_map_if_empty(&dst->taproot_leaf_signatures, &src->taproot_leaf_signatures)) != WALLY_OK)
        return ret;
    if ((ret = combine_map_if_empty(&dst->taproot_leaf_scripts, &src->taproot_leaf_scripts)) != WALLY_OK)
        return ret;
    if (!dst->taproot_leaf_hashes.num_items && !dst->taproot_leaf_paths.num_items &&
        src->taproot_leaf_hashes.num_items && src->taproot_leaf_paths.num_items) {
        ret = wally_map_combine(&dst->taproot_leaf_hashes, &src->taproot_leaf_hashes);
        if (ret == WALLY_OK)
            ret = wally_map_combine(&dst->taproot_leaf_paths, &src->taproot_leaf_paths);
    }
    if (ret == WALLY_OK && is_pset) {
#ifdef BUILD_ELEMENTS
        uint32_t ft;
        if (ret == WALLY_OK && !dst->has_amount && src->has_amount) {
            dst->amount = src->amount;
            dst->has_amount = 1u;
        }

        if (ret == WALLY_OK)
            ret = merge_value_commitment(&dst->pset_fields, &dst->issuance_amount,
                                         &src->pset_fields, src->issuance_amount,
                                         PSET_IN_ISSUANCE_VALUE_COMMITMENT, for_clone);

        if (ret == WALLY_OK)
            ret = merge_value_commitment(&dst->pset_fields, &dst->inflation_keys,
                                         &src->pset_fields, src->inflation_keys,
                                         PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT, for_clone);
        if (ret == WALLY_OK && !dst->pegin_amount && src->pegin_amount)
            dst->pegin_amount = src->pegin_amount;

        if (ret == WALLY_OK)
            ret = combine_txs(&dst->pegin_tx, src->pegin_tx);

        if (ret == WALLY_OK && !dst->pegin_witness && src->pegin_witness)
            ret = wally_psbt_input_set_pegin_witness(dst, src->pegin_witness);

        for (ft = 0; ret == WALLY_OK && ft <= PSET_IN_MAX; ++ft) {
            if (PSET_IN_MERGEABLE & PSET_FT(ft))
                ret = combine_map_item(&dst->pset_fields, &src->pset_fields, ft);
        }
#endif /* BUILD_ELEMENTS */
    }
    return ret;
}

static int combine_output(struct wally_psbt_output *dst,
                          const struct wally_psbt_output *src,
                          bool is_pset, bool for_clone)
{
    int ret = WALLY_OK;
#ifdef BUILD_ELEMENTS
    size_t dst_asset, src_asset = 0;

    ret = wally_map_find_integer(&dst->pset_fields, PSET_OUT_ASSET, &dst_asset);
    if (ret == WALLY_OK)
        ret = wally_map_find_integer(&src->pset_fields, PSET_OUT_ASSET, &src_asset);
    if (ret != WALLY_OK)
        return ret;
#endif

    if (for_clone) {
        /* Copy amount, script (and asset, for elements) */
        if (!dst->has_amount && src->has_amount) {
            dst->amount = src->amount;
            dst->has_amount = src->has_amount;
        }
        if (!dst->script && src->script)
            ret = wally_psbt_output_set_script(dst, src->script, src->script_len);
#ifdef BUILD_ELEMENTS
        if (ret == WALLY_OK && is_pset && src_asset) {
            const struct wally_map_item *src_p = src->pset_fields.items + src_asset - 1;
            ret = wally_map_replace_integer(&dst->pset_fields, PSET_OUT_ASSET,
                                            src_p->value, src_p->value_len);
        }
#endif
    } else {
        /* Ensure amount, script (and asset, for elements) match */
        if (dst->has_amount != src->has_amount || dst->amount != src->amount ||
            dst->script_len != src->script_len ||
            (dst->script_len && memcmp(dst->script, src->script, src->script_len)))
            ret = WALLY_EINVAL; /* Mismatched amount or script */
        else if (is_pset) {
#ifdef BUILD_ELEMENTS
            const struct wally_map_item *src_p = src->pset_fields.items + src_asset - 1;
            const struct wally_map_item *dst_p = dst->pset_fields.items + dst_asset - 1;
            if (!dst_asset || !src_asset ||
                dst_p->value_len != WALLY_TX_ASSET_TAG_LEN ||
                src_p->value_len != WALLY_TX_ASSET_TAG_LEN ||
                memcmp(dst_p->value, src_p->value, WALLY_TX_ASSET_TAG_LEN)) {
                ret = WALLY_EINVAL; /* Mismatched asset */
            }
#endif
        }
    }

    if (ret == WALLY_OK)
        ret = wally_map_combine(&dst->keypaths, &src->keypaths);
    if (ret == WALLY_OK)
        ret = wally_map_combine(&dst->unknowns, &src->unknowns);
    if (ret == WALLY_OK)
        ret = wally_map_combine(&dst->psbt_fields, &src->psbt_fields);
    if (ret == WALLY_OK)
        ret = combine_map_if_empty(&dst->taproot_tree, &src->taproot_tree);

    if (ret == WALLY_OK &&
        !dst->taproot_leaf_hashes.num_items && !dst->taproot_leaf_paths.num_items &&
        src->taproot_leaf_hashes.num_items && src->taproot_leaf_paths.num_items) {
        ret = wally_map_combine(&dst->taproot_leaf_hashes, &src->taproot_leaf_hashes);
        if (ret == WALLY_OK)
            ret = wally_map_combine(&dst->taproot_leaf_paths, &src->taproot_leaf_paths);
    }

#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK && is_pset) {
        uint64_t dst_state, src_state;

        if (for_clone) {
            if (!dst->has_blinder_index && src->has_blinder_index) {
                dst->blinder_index = src->blinder_index;
                dst->has_blinder_index = src->has_blinder_index;
            }
            return wally_map_combine(&dst->pset_fields, &src->pset_fields);
        }

        ret = psbt_output_get_blinding_state(dst, &dst_state);
        if (ret == WALLY_OK)
            ret = psbt_output_get_blinding_state(src, &src_state);

        if (ret == WALLY_OK && PSET_BLINDING_STATE_REQUIRED(dst_state) &&
            PSET_BLINDING_STATE_REQUIRED(src_state)) {
            /* Both outputs require blinding */
            if (!dst->blinder_index || dst->blinder_index != src->blinder_index ||
                !map_find_equal_integer(&dst->pset_fields, &src->pset_fields,
                                        PSET_OUT_BLINDING_PUBKEY))
                ret = WALLY_EINVAL; /* Blinding index/pubkey do not match */
        }

        if (ret == WALLY_OK && PSET_BLINDING_STATE_FULL(src_state)) {
            /* The source is fully blinded, either copy or verify the fields */
            uint32_t ft;
            for (ft = PSET_OUT_VALUE_COMMITMENT; ret == WALLY_OK && ft <= PSET_OUT_ASSET_SURJECTION_PROOF; ++ft) {
                if (!(PSET_OUT_BLINDING_FIELDS & PSET_FT(ft)))
                    continue;
                if (PSET_BLINDING_STATE_FULL(dst_state)) {
                    /* Both fully blinded: verify */
                    if (!map_find_equal_integer(&dst->pset_fields, &src->pset_fields, ft))
                        ret = WALLY_EINVAL; /* Fields do not match */
                } else {
                    /* Copy (overwriting if present) */
                    const struct wally_map_item *from;
                    from = wally_map_get_integer(&src->pset_fields, ft);
                    ret = wally_map_replace_integer(&dst->pset_fields, ft,
                                                    from->value, from->value_len);
                }
            }
        }
    }
#endif /* BUILD_ELEMENTS */

    return ret;
}

static int psbt_combine(struct wally_psbt *psbt, const struct wally_psbt *src,
                        bool is_pset, bool for_clone)
{
    size_t i;
    int ret = WALLY_OK;

    if (psbt->num_inputs != src->num_inputs || psbt->num_outputs != src->num_outputs)
        return WALLY_EINVAL;

    if (!psbt->has_fallback_locktime) {
        psbt->fallback_locktime = src->fallback_locktime;
        psbt->has_fallback_locktime = src->has_fallback_locktime;
    }

    /* Take any extra flags from the source psbt that we don't have  */
    psbt->tx_modifiable_flags |= src->tx_modifiable_flags;

    for (i = 0; ret == WALLY_OK && i < psbt->num_inputs; ++i)
        ret = combine_input(&psbt->inputs[i], &src->inputs[i], is_pset, for_clone);

    for (i = 0; ret == WALLY_OK && i < psbt->num_outputs; ++i)
        ret = combine_output(&psbt->outputs[i], &src->outputs[i], is_pset, for_clone);

    if (ret == WALLY_OK)
        ret = wally_map_combine(&psbt->unknowns, &src->unknowns);

    if (ret == WALLY_OK)
        ret = wally_map_combine(&psbt->global_xpubs, &src->global_xpubs);

#ifdef BUILD_ELEMENTS
    if (ret == WALLY_OK && is_pset) {
        psbt->pset_modifiable_flags |= src->pset_modifiable_flags;
        ret = wally_map_combine(&psbt->global_scalars, &src->global_scalars);
    }
#endif /* BUILD_ELEMENTS */

    return ret;
}

int wally_psbt_get_locktime(const struct wally_psbt *psbt, size_t *locktime)
{
    bool only_locktime = false, only_lockheight = false;
    uint32_t max_locktime = 0, max_lockheight = 0;

    if (locktime)
        *locktime = 0;
    if (!psbt_is_valid(psbt) || psbt->version != PSBT_2 || !locktime)
        return WALLY_EINVAL;

    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input *pi = &psbt->inputs[i];

        const bool has_locktime = pi->required_locktime != 0;
        const bool has_lockheight = pi->required_lockheight != 0;

        only_locktime |= has_locktime && !has_lockheight;
        only_lockheight |= has_lockheight && !has_locktime;

        if (only_locktime && only_lockheight)
            return WALLY_EINVAL; /* Conflicting lock types cannot be satisfied */

        if (has_locktime && max_locktime < pi->required_locktime)
            max_locktime = pi->required_locktime;

        if (has_lockheight && max_lockheight < pi->required_lockheight)
            max_lockheight = pi->required_lockheight;
    }

    if (only_locktime)
        *locktime = max_locktime;
    else if (only_lockheight)
        *locktime = max_lockheight;
    else {
        if (max_lockheight)
            *locktime = max_lockheight; /* Use height, even if time also given */
        else if (max_locktime)
            *locktime = max_locktime;
        else
            *locktime = psbt->has_fallback_locktime ? psbt->fallback_locktime : 0;
    }
    return WALLY_OK;
}

#define BUILD_ITEM(n, ft) const struct wally_map_item *n = wally_map_get_integer(&src->pset_fields, ft)
#define BUILD_PARAM(n) n ? n->value : NULL, n ? n->value_len : 0

static int psbt_build_input(const struct wally_psbt_input *src,
                            bool is_pset, bool unblinded, struct wally_tx *tx)
{
    if (is_pset) {
#ifndef BUILD_ELEMENTS
        (void)unblinded;
        return WALLY_EINVAL;
#else
        BUILD_ITEM(issuance_blinding_nonce, PSET_IN_ISSUANCE_BLINDING_NONCE);
        BUILD_ITEM(issuance_asset_entropy, PSET_IN_ISSUANCE_ASSET_ENTROPY);
        BUILD_ITEM(issuance_amount_commitment, PSET_IN_ISSUANCE_VALUE_COMMITMENT);
        BUILD_ITEM(inflation_keys_commitment, PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT);
        unsigned char issuance_amount[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
        unsigned char inflation_keys[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
        BUILD_ITEM(issuance_rangeproof, PSET_IN_ISSUANCE_VALUE_RANGEPROOF);
        BUILD_ITEM(inflation_keys_rangeproof, PSET_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF);
        struct wally_map_item issuance_amount_item = { NULL, 0, issuance_amount, sizeof(issuance_amount) };
        struct wally_map_item inflation_keys_item = { NULL, 0, inflation_keys, sizeof(inflation_keys) };
        int src_index = src->index;

        if (src->issuance_amount || src->inflation_keys || issuance_amount_commitment || inflation_keys_commitment)
            src_index |= WALLY_TX_ISSUANCE_FLAG;

        if (src->pegin_amount || src->pegin_witness)
            src_index |= WALLY_TX_PEGIN_FLAG;

        /* FIXME: Pegin parameters need to be set for pegins to work */
        /* NOTE: This is an area of PSET that needs improvement */

        if ((src->issuance_amount || src->inflation_keys) &&
            (unblinded || (!issuance_amount_commitment && !inflation_keys_commitment))) {
            /* We do not have issuance commitments, or the unblinded flag
             * has been given: Use the unblinded amounts */
            if (wally_tx_confidential_value_from_satoshi(src->issuance_amount,
                                                         issuance_amount,
                                                         sizeof(issuance_amount)) != WALLY_OK ||
                wally_tx_confidential_value_from_satoshi(src->inflation_keys,
                                                         inflation_keys,
                                                         sizeof(inflation_keys)) != WALLY_OK)
                return WALLY_EINVAL;
            issuance_amount_commitment = &issuance_amount_item;
            inflation_keys_commitment = &inflation_keys_item;
        }

        return wally_tx_add_elements_raw_input(tx,
                                               src->txhash, WALLY_TXHASH_LEN,
                                               src_index, src->sequence, NULL, 0, NULL,
                                               BUILD_PARAM(issuance_blinding_nonce),
                                               BUILD_PARAM(issuance_asset_entropy),
                                               BUILD_PARAM(issuance_amount_commitment),
                                               BUILD_PARAM(inflation_keys_commitment),
                                               BUILD_PARAM(issuance_rangeproof),
                                               BUILD_PARAM(inflation_keys_rangeproof), NULL, 0);
#endif /* BUILD_ELEMENTS */
    }
    return wally_tx_add_raw_input(tx, src->txhash, WALLY_TXHASH_LEN,
                                  src->index, src->sequence, NULL, 0, NULL, 0);
}

static int psbt_build_output(const struct wally_psbt_output *src,
                             bool is_pset, bool unblinded, struct wally_tx *tx)
{
    if (is_pset) {
#ifndef BUILD_ELEMENTS
        (void)unblinded;
        return WALLY_EINVAL;
#else
        BUILD_ITEM(value_commitment, PSET_OUT_VALUE_COMMITMENT);
        BUILD_ITEM(value_rangeproof, PSET_OUT_VALUE_RANGEPROOF);
        BUILD_ITEM(asset, PSET_OUT_ASSET);
        BUILD_ITEM(asset_commitment, PSET_OUT_ASSET_COMMITMENT);
        BUILD_ITEM(asset_surjectionproof, PSET_OUT_ASSET_SURJECTION_PROOF);
        BUILD_ITEM(ecdh_public_key, PSET_OUT_ECDH_PUBKEY);
        unsigned char value[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
        unsigned char asset_u[WALLY_TX_ASSET_CT_ASSET_LEN];
        struct wally_map_item value_item = { NULL, 0, value, sizeof(value) };
        struct wally_map_item asset_u_item = { NULL, 0, asset_u, sizeof(asset_u) };

        if (unblinded || (src->has_amount && !value_commitment)) {
            /* FIXME: Check the blind value proof */
            /* Use the unblinded amount */
            if (wally_tx_confidential_value_from_satoshi(src->amount,
                                                         value, sizeof(value)) != WALLY_OK)
                return WALLY_EINVAL;
            value_commitment = &value_item;
            value_rangeproof = NULL;
        }

        if (unblinded || !asset_commitment) {
            /* FIXME: Check the blind asset proof */
            if (!asset)
                asset_commitment = NULL;
            else {
                asset_u[0] = 0x1; /* Use the unblinded asset */
                if (asset->value_len != WALLY_TX_ASSET_TAG_LEN)
                    return WALLY_EINVAL;
                memcpy(asset_u + 1, asset->value, asset->value_len);
                asset_commitment = &asset_u_item;
            }
            asset_surjectionproof = NULL;
        }

        if (unblinded)
            ecdh_public_key = NULL;

        return wally_tx_add_elements_raw_output(tx,
                                                src->script, src->script_len,
                                                BUILD_PARAM(asset_commitment),
                                                BUILD_PARAM(value_commitment),
                                                BUILD_PARAM(ecdh_public_key),
                                                BUILD_PARAM(asset_surjectionproof),
                                                BUILD_PARAM(value_rangeproof), 0);
#endif /* BUILD_ELEMENTS */
    }
    if (!src->has_amount)
        return WALLY_EINVAL;
    return wally_tx_add_raw_output(tx, src->amount, src->script, src->script_len, 0);
}

static int psbt_build_tx(const struct wally_psbt *psbt, struct wally_tx **tx,
                         bool *is_pset, bool unblinded)
{
    size_t is_elements, locktime, i;
    int ret;

    *tx = NULL;
    *is_pset = 0;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx))
        return WALLY_EINVAL;

    if ((ret = wally_psbt_is_elements(psbt, &is_elements)) != WALLY_OK)
        return ret;
    *is_pset = !!is_elements;

    if (psbt->version == PSBT_0)
        return wally_tx_clone_alloc(psbt->tx, 0, tx);

    ret = wally_psbt_get_locktime(psbt, &locktime);
    if (ret == WALLY_OK)
        ret = wally_tx_init_alloc(psbt->tx_version, locktime, psbt->num_inputs, psbt->num_outputs, tx);

    for (i = 0; ret == WALLY_OK && i < psbt->num_inputs; ++i)
        ret = psbt_build_input(psbt->inputs + i, *is_pset, unblinded, *tx);

    for (i = 0; ret == WALLY_OK && i < psbt->num_outputs; ++i)
        ret = psbt_build_output(psbt->outputs + i, *is_pset, unblinded, *tx);

    if (ret != WALLY_OK) {
        wally_tx_free(*tx);
        *tx = NULL;
    }
    return ret;
}

static int psbt_v0_to_v2(struct wally_psbt *psbt)
{
    size_t i;

    /* Upgrade to v2 */
    psbt->version = PSBT_2;
    /* v2 requires a tx version of at least 2 */
    psbt->tx_version = psbt->tx->version < 2 ? 2 : psbt->tx->version;
    /* V0 only has the tx locktime, and no per-input locktimes,
     * so set the V2 fallback locktime to the tx locktime, unless
     * it is the default value of 0.
     */
    psbt->fallback_locktime = psbt->tx->locktime;
    psbt->has_fallback_locktime = psbt->fallback_locktime != 0;
    /* V0 PSBTs are implicitly modifiable; reflect that in our flags */
    psbt->tx_modifiable_flags = WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS;
    /* FIXME: Detect SIGHASH_SINGLE in any signatures present and
     * set WALLY_PSBT_TXMOD_SINGLE if found.
     */

    for (i = 0; i < psbt->tx->num_inputs; ++i) {
        struct wally_psbt_input *pi = &psbt->inputs[i];
        const struct wally_tx_input *txin = &psbt->tx->inputs[i];
        memcpy(pi->txhash, txin->txhash, sizeof(pi->txhash));
        pi->index = txin->index; /* No mask, since PSET is v2 only */
        pi->sequence = txin->sequence;
    }

    for (i = 0; i < psbt->tx->num_outputs; ++i) {
        struct wally_psbt_output *po = &psbt->outputs[i];
        struct wally_tx_output *txout = &psbt->tx->outputs[i];
        /* We steal script directly from the tx output so this can't fail */
        po->script = txout->script;
        txout->script = NULL;
        po->script_len = txout->script_len;
        txout->script_len = 0;
        po->amount = txout->satoshi;
        po->has_amount = true;
    }

    wally_tx_free(psbt->tx);
    psbt->tx = NULL;
    return WALLY_OK;
}

static int psbt_v2_to_v0(struct wally_psbt *psbt)
{
    size_t i;
    bool is_pset;
    int ret = psbt_build_tx(psbt, &psbt->tx, &is_pset, false);

    if (ret != WALLY_OK)
        return ret;

    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *pi = &psbt->inputs[i];
        pi->index = 0;
        pi->sequence = 0;
        pi->required_locktime = 0;
        pi->required_lockheight = 0;
    }

    for (i = 0; i < psbt->num_outputs; ++i) {
        struct wally_psbt_output *po = &psbt->outputs[i];
        po->amount = 0;
        po->has_amount = false;
        clear_and_free_bytes(&po->script, &po->script_len);
    }

    psbt->version = PSBT_0;
    psbt->tx_version = 0;
    psbt->fallback_locktime = 0;
    psbt->has_fallback_locktime = false;
    psbt->tx_modifiable_flags = 0;
    return WALLY_OK;
}

int wally_psbt_set_version(struct wally_psbt *psbt,
                           uint32_t flags,
                           uint32_t version)
{
    size_t is_pset;

    if (!psbt_is_valid(psbt) || flags || (version != PSBT_0 && version != PSBT_2))
        return WALLY_EINVAL;

    if (psbt->version == version)
        return WALLY_OK; /* No-op */

    if (wally_psbt_is_elements(psbt, &is_pset) != WALLY_OK || is_pset)
        return WALLY_EINVAL; /* PSET only supports v2 */

    return psbt->version == PSBT_0 ? psbt_v0_to_v2(psbt) : psbt_v2_to_v0(psbt);
}

int wally_psbt_get_id(const struct wally_psbt *psbt, uint32_t flags, unsigned char *bytes_out, size_t len)
{
    struct wally_tx *tx;
    size_t i;
    bool is_pset;
    int ret;

    if ((flags & ~PSBT_ID_ALL_FLAGS) || !bytes_out || len != WALLY_TXHASH_LEN)
        return WALLY_EINVAL;

    if ((ret = psbt_build_tx(psbt, &tx, &is_pset, true)) == WALLY_OK) {
        if (!(flags & WALLY_PSBT_ID_USE_LOCKTIME)) {
            /* Set locktime to 0. This is what core/Elements do,
             * although the specs aren't fixed to describe this yet */
            tx->locktime = 0;
        }
        if (psbt->version == PSBT_2 || (flags & WALLY_PSBT_ID_AS_V2)) {
            /* Set all inputs sequence numbers to 0 as per BIP-370 */
            for (i = 0; i < tx->num_inputs; ++i)
                tx->inputs[i].sequence = 0;
        }
        ret = wally_tx_get_txid(tx, bytes_out, len);
        wally_tx_free(tx);
    }
    return ret;
}

int wally_psbt_combine(struct wally_psbt *psbt, const struct wally_psbt *src)
{
    unsigned char id[WALLY_TXHASH_LEN], src_id[WALLY_TXHASH_LEN];
    size_t is_pset;
    int ret;

    if (!psbt_is_valid(psbt) || !psbt_is_valid(src) || psbt->version != src->version)
        return WALLY_EINVAL;

    if (psbt == src)
        return WALLY_OK; /* Combine with self: no-op */

    if ((ret = wally_psbt_get_id(psbt, 0, id, sizeof(id))) != WALLY_OK)
        return ret;

    if ((ret = wally_psbt_get_id(src, 0, src_id, sizeof(src_id))) == WALLY_OK &&
        (ret = wally_psbt_is_elements(psbt, &is_pset)) == WALLY_OK) {
        if (memcmp(src_id, id, sizeof(id)) != 0)
            ret = WALLY_EINVAL; /* Cannot combine different txs */
        else
            ret = psbt_combine(psbt, src, !!is_pset, false);
    }
    wally_clear_2(id, sizeof(id), src_id, sizeof(src_id));
    return ret;
}

int wally_psbt_clone_alloc(const struct wally_psbt *psbt, uint32_t flags,
                           struct wally_psbt **output)
{
    size_t is_pset;
    int ret;

    OUTPUT_CHECK;
    if (!psbt_is_valid(psbt) || flags || !output)
        return WALLY_EINVAL;

    ret = wally_psbt_is_elements(psbt, &is_pset);
    if (ret == WALLY_OK)
        ret = psbt_init_alloc(psbt->version,
                              psbt->inputs_allocation_len,
                              psbt->outputs_allocation_len,
                              psbt->unknowns.items_allocation_len,
                              is_pset ? WALLY_PSBT_INIT_PSET : 0,
                              psbt->inputs_allocation_len,
                              psbt->outputs_allocation_len,
                              output);
    if (ret == WALLY_OK) {
        (*output)->tx_version = psbt->tx_version;
        psbt_claim_allocated_inputs(*output, psbt->num_inputs, psbt->num_outputs);
        (*output)->tx_modifiable_flags = 0;
#ifdef BUILD_ELEMENTS
        (*output)->pset_modifiable_flags = 0;
#endif
        ret = psbt_combine(*output, psbt, !!is_pset, true);

        if (ret == WALLY_OK && psbt->tx)
            ret = tx_clone_alloc(psbt->tx, &(*output)->tx);
        if (ret != WALLY_OK) {
            wally_psbt_free(*output);
            *output = NULL;
        }
    }
    return ret;
}

int wally_psbt_get_input_bip32_key_from_alloc(const struct wally_psbt *psbt,
                                              size_t index, size_t subindex,
                                              uint32_t flags,
                                              const struct ext_key *hdkey,
                                              struct ext_key **output)
{
    const struct wally_psbt_input *inp = psbt_get_input(psbt, index);
    size_t sig_idx = 0;
    int ret;
    if (output)
        *output = NULL;
    if (!inp || flags || !hdkey || !output)
        return WALLY_EINVAL;

    /* Find any matching key in the inputs keypaths */
    ret = wally_map_keypath_get_bip32_key_from_alloc(&inp->keypaths, subindex,
                                                     hdkey, output);
    if (ret == WALLY_OK && *output) {
        /* Found: Make sure we don't have a signature already */
        ret = wally_map_find_bip32_public_key_from(&inp->signatures, 0,
                                                   *output, &sig_idx);
        if (ret == WALLY_OK && sig_idx) {
            bip32_key_free(*output);
            *output = NULL;
        }
    } else if (ret == WALLY_OK &&
               !wally_map_get_integer(&inp->psbt_fields, PSBT_IN_TAP_KEY_SIG)) {
        /* We don't have a taproot signature, so try matching the taproot key */
        ret = wally_map_keypath_get_bip32_key_from_alloc(&inp->taproot_leaf_paths,
                                                         subindex, hdkey, output);
    }
    return ret;
}

static bool is_matching_redeem(const unsigned char *scriptpk, size_t scriptpk_len,
                               const unsigned char *redeem, size_t redeem_len)
{
    unsigned char p2sh[WALLY_SCRIPTPUBKEY_P2SH_LEN];
    size_t p2sh_len;
    int ret = wally_scriptpubkey_p2sh_from_bytes(redeem, redeem_len,
                                                 WALLY_SCRIPT_HASH160,
                                                 p2sh, sizeof(p2sh), &p2sh_len);
    return ret == WALLY_OK && p2sh_len == scriptpk_len &&
           !memcmp(p2sh, scriptpk, p2sh_len);
}

/* Get the scriptpubkey or redeem script from an input */
static int get_signing_script(const struct wally_psbt *psbt, size_t index,
                              const unsigned char **script, size_t *script_len)
{
    const struct wally_psbt_input *inp = psbt_get_input(psbt, index);
    const struct wally_tx_output *utxo = utxo_from_input(psbt, inp);
    const struct wally_map_item *item;

    *script = NULL;
    *script_len = 0;
    if (!utxo)
        return WALLY_EINVAL;

    item = wally_map_get_integer(&inp->psbt_fields, PSBT_IN_REDEEM_SCRIPT);
    if (item) {
        if (!is_matching_redeem(utxo->script, utxo->script_len,
                                item->value, item->value_len))
            return WALLY_EINVAL;
        *script = item->value;
        *script_len = item->value_len;
    } else {
        *script = utxo->script;
        *script_len = utxo->script_len;
    }
    if (BYTES_INVALID(*script, *script_len)) {
        *script = NULL;
        *script_len = 0;
        return WALLY_EINVAL;
    }
    return WALLY_OK;
}

int wally_psbt_get_input_signing_script_len(const struct wally_psbt *psbt,
                                        size_t index, size_t *written)
{
    const unsigned char *p;
    return written ? get_signing_script(psbt, index, &p, written) : WALLY_EINVAL;
}

int wally_psbt_get_input_signing_script(const struct wally_psbt *psbt,
                                        size_t index,
                                        unsigned char *bytes_out, size_t len,
                                        size_t *written)
{
    const unsigned char *p;
    int ret;
    if (written)
        *written = 0;
    if (!bytes_out || !len || !written)
        return WALLY_EINVAL;
    ret = get_signing_script(psbt, index, &p, written);
    if (ret == WALLY_OK && *written <= len)
        memcpy(bytes_out, p, *written);
    return ret;
}

static int get_scriptcode(const struct wally_psbt *psbt, size_t index,
                          unsigned char *buff, size_t buff_len,
                          const unsigned char *scriptcode, size_t scriptcode_len,
                          const unsigned char **script, size_t *script_len)
{
    const struct wally_psbt_input *inp = psbt_get_input(psbt, index);
    int ret;

    if (script)
        *script = NULL;
    if (script_len)
        *script_len = 0;
    if (!inp || !buff || buff_len != WALLY_SCRIPTPUBKEY_P2PKH_LEN ||
        !scriptcode || !scriptcode_len || !script || !script_len)
        return WALLY_EINVAL;

    if (inp->witness_utxo) {
        /* Segwit input */
        size_t script_type, written;

        ret = wally_scriptpubkey_get_type(scriptcode, scriptcode_len, &script_type);

        if (ret == WALLY_OK && script_type == WALLY_SCRIPT_TYPE_P2WPKH) {
            /* P2WPKH */
            ret = wally_scriptpubkey_p2pkh_from_bytes(&scriptcode[2],
                                                      HASH160_LEN, 0,
                                                      buff, buff_len,
                                                      &written);
            if (ret != WALLY_OK || written > buff_len)
                return WALLY_EINVAL;
            *script = buff; /* Return the scriptpubkey */
            *script_len = written;
            return WALLY_OK;
        }

        if (ret == WALLY_OK && script_type == WALLY_SCRIPT_TYPE_P2WSH) {
            /* P2WSH */
            unsigned char p2wsh[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
            const struct wally_map_item *wit_script;

            if (!(wit_script = wally_map_get_integer(&inp->psbt_fields,
                                                     PSBT_IN_WITNESS_SCRIPT)))
                return WALLY_EINVAL;
            ret = wally_witness_program_from_bytes(wit_script->value,
                                                   wit_script->value_len,
                                                   WALLY_SCRIPT_SHA256,
                                                   p2wsh, sizeof(p2wsh),
                                                   &written);
            if (ret != WALLY_OK || written != sizeof(p2wsh) ||
                written != scriptcode_len || memcmp(p2wsh, scriptcode, written))
                return WALLY_EINVAL;
            *script = wit_script->value; /* Return the witness script */
            *script_len = wit_script->value_len;
            return WALLY_OK;
        }

        if (ret == WALLY_OK && script_type == WALLY_SCRIPT_TYPE_P2TR) {
            /* P2TR */
            *script = scriptcode; /* Return the scriptpubkey */
            *script_len = scriptcode_len;
            return WALLY_OK;
        }

        return WALLY_EINVAL; /* Unknown scriptPubKey type/not enough info */
    }

    if (inp->utxo) {
        /* Non-segwit input */
        unsigned char txid[WALLY_TXHASH_LEN];
        size_t is_pset;

        if (wally_psbt_is_elements(psbt, &is_pset) != WALLY_OK || is_pset)
            return WALLY_EINVAL; /* Elements doesn't support pre-segwit txs */

        ret = wally_psbt_get_input_previous_txid(psbt, index, txid, sizeof(txid));
        if (ret != WALLY_OK || !is_matching_txid(inp->utxo, txid, sizeof(txid)))
            return WALLY_EINVAL; /* Prevout doesn't match input */
        *script = scriptcode;
        *script_len = scriptcode_len;
        return WALLY_OK;
    }
    return WALLY_EINVAL; /* Missing prevout data in input */
}

int wally_psbt_get_input_scriptcode_len(const struct wally_psbt *psbt, size_t index,
                                        const unsigned char *script, size_t script_len,
                                        size_t *written)
{
    unsigned char p2pkh[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
    const unsigned char *p;
    return get_scriptcode(psbt, index, p2pkh, sizeof(p2pkh),
                          script, script_len, &p, written);
}

int wally_psbt_get_input_scriptcode(const struct wally_psbt *psbt, size_t index,
                                    const unsigned char *script, size_t script_len,
                                    unsigned char *bytes_out, size_t len,
                                    size_t *written)
{
    unsigned char p2pkh[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
    const unsigned char *p;
    int ret;
    if (written)
        *written = 0;
    if (!bytes_out || !len || !written)
        return WALLY_EINVAL;
    ret = get_scriptcode(psbt, index, p2pkh, sizeof(p2pkh),
                         script, script_len, &p, written);
    if (ret == WALLY_OK && *written <= len)
        memcpy(bytes_out, p, *written);
    return ret;
}

/* Get the input scripts and values for taproot signing.
 * Creates a non-value-owning map, avoiding allocating/copying the scripts.
 */
static int get_scripts_and_values(const struct wally_psbt *psbt,
                                  struct wally_map *scripts,
                                  uint64_t **values)
{
    size_t num_inputs = psbt->num_inputs, i;
    int ret = WALLY_OK;

    wally_clear(scripts, sizeof(scripts));

    if (!(*values = wally_malloc(num_inputs * sizeof(uint64_t))))
        return WALLY_ENOMEM;
    if (!(scripts->items = wally_calloc(num_inputs * sizeof(struct wally_map_item)))) {
        ret = WALLY_ENOMEM;
        goto fail;
    }
    scripts->items_allocation_len = num_inputs;

    for (i = 0; i < num_inputs && ret == WALLY_OK; ++i) {
        const struct wally_psbt_input *p = psbt->inputs + i;
        const struct wally_tx_output *utxo = utxo_from_input(psbt, p);
        if (!utxo || !utxo->script)
            ret = WALLY_EINVAL;
        else {
            (*values)[i] = utxo->satoshi; /* FIXME: Support for Elements */
            /* Add the script to the map without allocating/copying */
            scripts->items[i].key_len = i;
            scripts->items[i].value = utxo->script;
            scripts->items[i].value_len = utxo->script_len;
        }
    }
    if (ret == WALLY_OK)
        scripts->num_items = num_inputs;
    else {
        wally_free(scripts->items); /* No need to clear the value pointers */
        wally_clear(scripts, sizeof(scripts));
fail:
        wally_free(*values);
        *values = NULL;
    }
    return ret;
}

int wally_psbt_get_input_signature_hash(struct wally_psbt *psbt, size_t index,
                                        const struct wally_tx *tx,
                                        const unsigned char *script, size_t script_len,
                                        uint32_t flags,
                                        unsigned char *bytes_out, size_t len)
{
    struct wally_map scripts;
    const struct wally_psbt_input *inp = psbt_get_input(psbt, index);
    const bool is_taproot = is_taproot_input(psbt, inp);
    uint64_t satoshi, *values = NULL;
    uint32_t sighash, sig_flags;
    size_t is_pset;
    int ret;

    if (!inp || !tx || flags)
        return WALLY_EINVAL;

    if ((ret = wally_psbt_is_elements(psbt, &is_pset)) != WALLY_OK)
        return ret;

    sighash = inp->sighash;
    if (!sighash)
        sighash = is_taproot ? WALLY_SIGHASH_DEFAULT : WALLY_SIGHASH_ALL;
    else if (sighash & 0xffffff00)
        return WALLY_EINVAL;

    sig_flags = inp->witness_utxo ? WALLY_TX_FLAG_USE_WITNESS : 0;

    if (is_pset) {
        if (!inp->witness_utxo)
            return WALLY_EINVAL; /* Must be segwit */
#ifdef BUILD_ELEMENTS
        return wally_tx_get_elements_signature_hash(tx, index,
                                                    script, script_len,
                                                    inp->witness_utxo->value,
                                                    inp->witness_utxo->value_len,
                                                    sighash, sig_flags, bytes_out,
                                                    len);
#else
        return WALLY_EINVAL; /* Unsupported */
#endif /* BUILD_ELEMENTS */
    }

    if (!is_taproot) {
        satoshi = inp->witness_utxo ? inp->witness_utxo->satoshi : 0;
        return wally_tx_get_btc_signature_hash(tx, index, script, script_len,
                                               satoshi, sighash, sig_flags,
                                               bytes_out, len);
    }

    /* Taproot */
    if ((ret = get_scripts_and_values(psbt, &scripts, &values) == WALLY_OK)) {
        ret = wally_tx_get_btc_taproot_signature_hash(tx, index, &scripts,
                                                      values, psbt->num_inputs,
                                                      NULL, 0, 0, 0xFFFFFFFF,
                                                      NULL, 0, sighash, 0,
                                                      bytes_out, len);
        wally_free(values);
        wally_free(scripts.items); /* No need to clear the value pointers */
    }
    return ret;
}

int wally_psbt_sign_input_bip32(struct wally_psbt *psbt,
                                size_t index, size_t subindex,
                                const unsigned char *txhash, size_t txhash_len,
                                const struct ext_key *hdkey,
                                uint32_t flags)
{
    unsigned char sig[EC_SIGNATURE_LEN + 1], der[EC_SIGNATURE_DER_MAX_LEN + 1];
    unsigned char signing_key[EC_PRIVATE_KEY_LEN];
    size_t sig_len = EC_SIGNATURE_LEN, der_len, pubkey_idx;
    uint32_t sighash;
    struct wally_psbt_input *inp = psbt_get_input(psbt, index);
    const bool is_taproot = is_taproot_input(psbt, inp);
    int ret;

    if (!inp || !hdkey || hdkey->priv_key[0] != BIP32_FLAG_KEY_PRIVATE ||
        (flags & ~EC_FLAGS_ALL))
        return WALLY_EINVAL;

    /* Find the public key this signature is for */
    ret = wally_map_find_bip32_public_key_from(&inp->keypaths, subindex,
                                               hdkey, &pubkey_idx);
    if (ret != WALLY_OK || !pubkey_idx) {
        /* Try again with the taproot public key */
        ret = wally_map_find_bip32_public_key_from(&inp->taproot_leaf_hashes,
                                                   subindex, hdkey,
                                                   &pubkey_idx);
    }

    if (ret != WALLY_OK || !pubkey_idx)
        return WALLY_EINVAL; /* Signing pubkey key not found */

    /* Copy signing key so we can tweak it if needed */
    memcpy(signing_key, hdkey->priv_key + 1, EC_PRIVATE_KEY_LEN);

    if (is_taproot) {
        /* Schnorr BIP340: Tweak the private key */
        const struct wally_map_item *p = wally_map_get_integer(&inp->psbt_fields,
                                                               PSBT_IN_TAP_MERKLE_ROOT);
        const unsigned char *merkle_root = p ? p->value : NULL;
        const size_t merkle_root_len = p ? p->value_len : 0;
        ret = wally_ec_private_key_bip341_tweak(signing_key, sizeof(signing_key),
                                                merkle_root, merkle_root_len,
                                                0, signing_key, sizeof(signing_key));
        if (ret != WALLY_OK)
            goto done;
        flags = EC_FLAG_SCHNORR;
    } else {
        /* ECDSA: Only grinding flag is relevant */
        flags = EC_FLAG_ECDSA | (flags & EC_FLAG_GRIND_R);
    }

    sighash = inp->sighash;
    if (!sighash)
        sighash = is_taproot ? WALLY_SIGHASH_DEFAULT : WALLY_SIGHASH_ALL;
    else if (sighash & 0xffffff00) {
        ret = WALLY_EINVAL;
        goto done;
    }

    /* Compute the sig */
    ret = wally_ec_sig_from_bytes(signing_key, EC_PRIVATE_KEY_LEN,
                                  txhash, txhash_len, flags, sig, sig_len);
    if (ret == WALLY_OK) {
        if (flags & EC_FLAG_SCHNORR) {
            /* Add sighash byte (if needed) and store */
            if (sighash != WALLY_SIGHASH_DEFAULT)
                sig[sig_len++] = sighash & 0xff;
            ret = wally_psbt_input_set_taproot_signature(inp, sig, sig_len);
        } else {
            /* Convert to DER, add sighash byte and store */
            ret = wally_ec_sig_to_der(sig, sig_len, der, sizeof(der), &der_len);
            if (ret == WALLY_OK) {
                const struct wally_map_item *pk;
                der[der_len++] = sighash & 0xff;
                pk = &inp->keypaths.items[pubkey_idx - 1];
                ret = wally_psbt_input_add_signature(inp, pk->key, pk->key_len,
                                                     der, der_len);
            }
        }
    }
done:
    wally_clear_3(signing_key, sizeof(signing_key), sig,
                  sizeof(sig), der, sizeof(der));
    return ret;
}

int wally_psbt_sign_bip32(struct wally_psbt *psbt,
                          const struct ext_key *hdkey, uint32_t flags)
{
    unsigned char p2pkh[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
    size_t i;
    bool is_pset;
    int ret;
    struct wally_tx *tx;

    if (!hdkey || hdkey->priv_key[0] != BIP32_FLAG_KEY_PRIVATE ||
        (flags & ~EC_FLAGS_ALL))
        return WALLY_EINVAL;

    if ((ret = psbt_build_tx(psbt, &tx, &is_pset, false)) != WALLY_OK)
        return ret;

    /* Go through each of the inputs */
    for (i = 0; ret == WALLY_OK && i < psbt->num_inputs; ++i) {
        unsigned char txhash[WALLY_TXHASH_LEN];
        const unsigned char *script, *scriptcode;
        size_t script_len, scriptcode_len, subindex = 0;
        struct ext_key *derived = NULL;

        /* Get or derive a key for signing this input.
         * Note that we do not iterate subindex in this loop, so we will not
         * sign more than one signature that derives from the same parent key.
         */
        ret = wally_psbt_get_input_bip32_key_from_alloc(psbt, i, subindex,
                                                        0, hdkey, &derived);
        if (!derived)
            continue; /* No key to sign with */

        /* Get the scriptpubkey or redeemscript */
        if (ret == WALLY_OK)
            ret = get_signing_script(psbt, i, &script, &script_len);

        /* Get the actual script to sign with */
        if (ret == WALLY_OK)
            ret = get_scriptcode(psbt, i, p2pkh, sizeof(p2pkh),
                                 script, script_len,
                                 &scriptcode, &scriptcode_len);

        /* Get the hash to sign */
        if (ret == WALLY_OK)
            ret = wally_psbt_get_input_signature_hash(psbt, i, tx,
                                                      scriptcode, scriptcode_len,
                                                      0, txhash, sizeof(txhash));
        /* Sign the input */
        if (ret == WALLY_OK)
            ret = wally_psbt_sign_input_bip32(psbt, i, subindex,
                                              txhash, sizeof(txhash),
                                              hdkey, flags);
        bip32_key_free(derived);
    }

    wally_tx_free(tx);
    return ret;
}

int wally_psbt_sign(struct wally_psbt *psbt,
                    const unsigned char *priv_key, size_t priv_key_len, uint32_t flags)
{
    struct ext_key hdkey;
    const uint32_t ver = BIP32_VER_MAIN_PRIVATE;
    int ret;

    /* Build a partial/non-derivable key, and use the bip32 signing impl */
    ret = psbt ? bip32_key_from_private_key(ver, priv_key, priv_key_len,
                                            &hdkey) : WALLY_EINVAL;
    if (ret == WALLY_OK)
        ret = wally_psbt_sign_bip32(psbt, &hdkey, flags);
    wally_clear(&hdkey, sizeof(hdkey));
    return ret;
}

static const struct wally_map_item *get_sig(const struct wally_psbt_input *input,
                                            size_t i, size_t n)
{
    return input->signatures.num_items != n ? NULL : &input->signatures.items[i];
}

static bool finalize_p2pkh(struct wally_psbt_input *input)
{
    unsigned char script[WALLY_SCRIPTSIG_P2PKH_MAX_LEN];
    size_t script_len;
    const struct wally_map_item *sig = get_sig(input, 0, 1);

    if (!sig ||
        wally_scriptsig_p2pkh_from_der(sig->key, sig->key_len,
                                       sig->value, sig->value_len,
                                       script, sizeof(script),
                                       &script_len) != WALLY_OK)
        return false;

    return wally_psbt_input_set_final_scriptsig(input, script, script_len) == WALLY_OK;
}

static bool finalize_p2sh_wrapped(struct wally_psbt_input *input)
{
    /* P2SH wrapped witness: add scriptSig pushing the redeemScript */
    const struct wally_map_item *redeem_script;
    redeem_script = wally_map_get_integer(&input->psbt_fields, PSBT_IN_REDEEM_SCRIPT);
    if (redeem_script) {
        unsigned char script[WALLY_SCRIPTSIG_MAX_LEN + 1];
        size_t script_len;
        if (wally_script_push_from_bytes(redeem_script->value,
                                         redeem_script->value_len, 0,
                                         script, sizeof(script),
                                         &script_len) == WALLY_OK &&
            script_len <= sizeof(script) &&
            wally_psbt_input_set_final_scriptsig(input,
                                                 script, script_len) == WALLY_OK)
            return true;
    }
    /* Failed: clear caller-created witness stack before returning */
    wally_tx_witness_stack_free(input->final_witness);
    input->final_witness = NULL;
    return false;
}

static bool finalize_p2wpkh(struct wally_psbt_input *input)
{
    const struct wally_map_item *sig = get_sig(input, 0, 1);

    if (!sig ||
        wally_witness_p2wpkh_from_der(sig->key, sig->key_len,
                                      sig->value, sig->value_len,
                                      &input->final_witness) != WALLY_OK)
        return false;

    if (!wally_map_get_integer(&input->psbt_fields, PSBT_IN_REDEEM_SCRIPT))
        return true;
    return finalize_p2sh_wrapped(input);
}

static bool finalize_p2wsh(struct wally_psbt_input *input)
{
    (void)input;
    return false; /* TODO */
}

static bool finalize_multisig(struct wally_psbt_input *input,
                              const unsigned char *out_script, size_t out_script_len,
                              bool is_witness, bool is_p2sh)
{
    unsigned char sigs[EC_SIGNATURE_LEN * 15];
    uint32_t sighashes[15];
    const unsigned char *p = out_script, *end = p + out_script_len;
    size_t threshold, n_pubkeys, n_found = 0, i;
    bool ret = false;

    if (!script_is_op_n(out_script[0], false, &threshold) ||
        input->signatures.num_items < threshold ||
        !script_is_op_n(out_script[out_script_len - 2], false, &n_pubkeys) ||
        n_pubkeys > 15)
        goto fail; /* Failed to parse or invalid script */

    ++p; /* Skip the threshold */

    /* Collect signatures corresponding to pubkeys in the multisig script */
    for (i = 0; i < n_pubkeys && p < end; ++i) {
        size_t opcode_size, found_pubkey_len;
        const unsigned char *found_pubkey;
        const struct wally_map_item *found_sig;
        size_t sig_index;

        if (script_get_push_size_from_bytes(p, end - p,
                                            &found_pubkey_len) != WALLY_OK ||
            script_get_push_opcode_size_from_bytes(p, end - p,
                                                   &opcode_size) != WALLY_OK)
            goto fail; /* Script is malformed, bail */

        p += opcode_size;
        found_pubkey = p;
        p += found_pubkey_len; /* Move to next pubkey push */

        /* Find the associated signature for this pubkey */
        if (wally_map_find(&input->signatures,
                           found_pubkey, found_pubkey_len,
                           &sig_index) != WALLY_OK || !sig_index)
            continue; /* Not found: try the next pubkey in the script */

        found_sig = &input->signatures.items[sig_index - 1];

        /* Sighash is appended to the DER signature */
        sighashes[n_found] = found_sig->value[found_sig->value_len - 1];
        /* Convert the DER signature to compact form */
        if (wally_ec_sig_from_der(found_sig->value, found_sig->value_len - 1,
                                  sigs + n_found * EC_SIGNATURE_LEN,
                                  EC_SIGNATURE_LEN) != WALLY_OK)
            continue; /* Failed to parse, try next pubkey */

        if (++n_found == threshold)
            break; /* We have enough signatures, ignore any more */
    }

    if (n_found != threshold)
        goto fail; /* Failed to find enough signatures */

    if (is_witness) {
        if (wally_witness_multisig_from_bytes(out_script, out_script_len,
                                              sigs, n_found * EC_SIGNATURE_LEN,
                                              sighashes, n_found,
                                              0, &input->final_witness) != WALLY_OK)
            goto fail;

        if (is_p2sh && !finalize_p2sh_wrapped(input))
            goto fail;
    } else {
        unsigned char script[WALLY_SCRIPTSIG_MAX_LEN];
        size_t script_len;

        if (wally_scriptsig_multisig_from_bytes(out_script, out_script_len,
                                                sigs, n_found * EC_SIGNATURE_LEN,
                                                sighashes, n_found, 0,
                                                script, sizeof(script), &script_len) != WALLY_OK ||
            wally_psbt_input_set_final_scriptsig(input, script, script_len) != WALLY_OK)
            goto fail;
    }
    ret = true;
fail:
    wally_clear_2(sigs, sizeof(sigs), sighashes, sizeof(sighashes));
    return ret;
}

static bool finalize_p2tr(struct wally_psbt_input *input)
{
    const struct wally_map_item *sig;

    sig = wally_map_get_integer(&input->psbt_fields, PSBT_IN_TAP_KEY_SIG);

    /* TODO support tapleaf spends input->taproot_leaf_signatures */
    if (!sig ||
        wally_witness_p2tr_from_sig(sig->value, sig->value_len,
                                    &input->final_witness) != WALLY_OK)
        return false;

    return true;
}

int wally_psbt_finalize_input(struct wally_psbt *psbt, size_t index, uint32_t flags)
{
    struct wally_psbt_input *input = psbt_get_input(psbt, index);
    const struct wally_map_item *script;
    unsigned char *out_script = NULL;
    size_t out_script_len = 0, type = WALLY_SCRIPT_TYPE_UNKNOWN;
    uint32_t utxo_index;
    bool is_witness = false, is_p2sh = false;

    if (!psbt_is_valid(psbt) || !input || (flags & ~WALLY_PSBT_FINALIZE_NO_CLEAR))
        return WALLY_EINVAL;

    if (wally_psbt_get_input_output_index(psbt, index, &utxo_index) != WALLY_OK)
        return WALLY_EINVAL;

    if (input->final_witness ||
        wally_map_get_integer(&input->psbt_fields, PSBT_IN_FINAL_SCRIPTSIG))
        goto done; /* Already finalized */

    /* Note that if we supply the non-witness utxo tx field (tx) for
     * witness inputs also, we'll need a different way to signal
     * p2sh-p2wpkh scripts */
    if (input->witness_utxo && input->witness_utxo->script_len) {
        out_script = input->witness_utxo->script;
        out_script_len = input->witness_utxo->script_len;
        is_witness = true;
    } else if (input->utxo && utxo_index < input->utxo->num_outputs) {
        struct wally_tx_output *utxo = &input->utxo->outputs[utxo_index];
        out_script = utxo->script;
        out_script_len = utxo->script_len;
    }
    script = wally_map_get_integer(&input->psbt_fields, PSBT_IN_REDEEM_SCRIPT);
    if (script) {
        out_script = script->value;
        out_script_len = script->value_len;
        is_p2sh = true;
    }
    script = wally_map_get_integer(&input->psbt_fields, PSBT_IN_WITNESS_SCRIPT);
    if (script) {
        out_script = script->value;
        out_script_len = script->value_len;
        is_witness = true;
    }

    if (out_script &&
        wally_scriptpubkey_get_type(out_script, out_script_len, &type) != WALLY_OK)
        return WALLY_OK; /* Invalid/missing script */

    switch (type) {
    case WALLY_SCRIPT_TYPE_P2PKH:
        if (!finalize_p2pkh(input))
            return WALLY_OK;
        break;
    case WALLY_SCRIPT_TYPE_P2WPKH:
        if (!finalize_p2wpkh(input))
            return WALLY_OK;
        break;
    case WALLY_SCRIPT_TYPE_P2WSH:
        if (!finalize_p2wsh(input))
            return WALLY_OK;
        break;
    case WALLY_SCRIPT_TYPE_MULTISIG:
        if (!finalize_multisig(input, out_script, out_script_len, is_witness, is_p2sh))
            return WALLY_OK;
        break;
    case WALLY_SCRIPT_TYPE_P2TR:
        if (!finalize_p2tr(input))
            return WALLY_OK;
        break;
    default:
        return WALLY_OK; /* Unhandled script type  */
    }

done:
    if (!(flags & WALLY_PSBT_FINALIZE_NO_CLEAR)) {
        /* Clear non-final things */
        wally_map_remove_integer(&input->psbt_fields, PSBT_IN_REDEEM_SCRIPT);
        wally_map_remove_integer(&input->psbt_fields, PSBT_IN_WITNESS_SCRIPT);
        wally_map_remove_integer(&input->psbt_fields, PSBT_IN_TAP_KEY_SIG);
        wally_map_remove_integer(&input->psbt_fields, PSBT_IN_TAP_INTERNAL_KEY);
        wally_map_clear(&input->keypaths);
        wally_map_clear(&input->signatures);
        wally_map_clear(&input->taproot_leaf_paths);
        input->sighash = 0;
    }
    return WALLY_OK;
}

int wally_psbt_finalize(struct wally_psbt *psbt, uint32_t flags)
{
    size_t i;
    int ret = WALLY_OK;

    for (i = 0; ret == WALLY_OK && i < psbt->num_inputs; ++i)
        ret = wally_psbt_finalize_input(psbt, i, flags);
    return ret;
}

int wally_psbt_extract(const struct wally_psbt *psbt, uint32_t flags, struct wally_tx **output)
{
    struct wally_tx *result;
    size_t i;
    bool is_pset, for_final = !(flags & WALLY_PSBT_EXTRACT_NON_FINAL);
    int ret;

    OUTPUT_CHECK;

    if (!psbt || flags & ~WALLY_PSBT_EXTRACT_NON_FINAL)
        return WALLY_EINVAL;

    if ((ret = psbt_build_tx(psbt, &result, &is_pset, false)) != WALLY_OK)
        return ret;

    for (i = 0; for_final && i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input *input = &psbt->inputs[i];
        struct wally_tx_input *txin = &result->inputs[i];
        const struct wally_map_item *final_scriptsig;

        final_scriptsig = wally_map_get_integer(&input->psbt_fields, PSBT_IN_FINAL_SCRIPTSIG);

        if (!input->final_witness && !final_scriptsig) {
            ret = WALLY_EINVAL;
            break;
        }

        if (final_scriptsig) {
            if (txin->script) {
                /* Our global tx shouldn't have a scriptSig */
                ret = WALLY_EINVAL;
                break;
            }
            if (!clone_bytes(&txin->script,
                             final_scriptsig->value, final_scriptsig->value_len)) {
                ret = WALLY_ENOMEM;
                break;
            }
            txin->script_len = final_scriptsig->value_len;
        }
        if (input->final_witness) {
            if (txin->witness) {
                /* Our global tx shouldn't have a witness */
                ret = WALLY_EINVAL;
                break;
            }
            ret = wally_tx_witness_stack_clone_alloc(input->final_witness,
                                                     &txin->witness);
            if (ret != WALLY_OK)
                break;
        }
    }

    if (ret == WALLY_OK)
        *output = result;
    else
        wally_tx_free(result);
    return ret;
}

#ifdef BUILD_ELEMENTS
static int compute_final_vbf(struct wally_psbt *psbt,
                             const unsigned char *input_scalar,
                             unsigned char *output_scalar,
                             unsigned char *vbf)
{
    size_t i;
    int ret = wally_ec_scalar_subtract_from(output_scalar, EC_SCALAR_LEN,
                                            input_scalar, EC_SCALAR_LEN);
    if (ret == WALLY_OK) {
        ret = wally_ec_scalar_subtract_from(vbf, EC_SCALAR_LEN,
                                            output_scalar, EC_SCALAR_LEN);
        for (i = 0; ret == WALLY_OK && i < psbt->global_scalars.num_items; ++i) {
            const struct wally_map_item *scalar = psbt->global_scalars.items + i;
            ret = wally_ec_scalar_subtract_from(vbf, EC_SCALAR_LEN,
                                                scalar->key, scalar->key_len);
        }
    }
    if (ret == WALLY_OK && mem_is_zero(vbf, EC_SCALAR_LEN))
        ret = WALLY_ERROR;
    if (ret == WALLY_OK)
        ret = wally_map_clear(&psbt->global_scalars);
    return ret;
}
#endif /* BUILD_ELEMENTS */

int wally_psbt_blind(struct wally_psbt *psbt,
                     const struct wally_map *values,
                     const struct wally_map *vbfs,
                     const struct wally_map *assets,
                     const struct wally_map *abfs,
                     const unsigned char *entropy, size_t entropy_len,
                     uint32_t output_index, uint32_t flags,
                     struct wally_map *ephemeral_keys_out)
{
#ifdef BUILD_ELEMENTS
    const secp256k1_context *ctx = secp_ctx();
    unsigned char *fixed_input_tags, *ephemeral_input_tags, *input_abfs;
    unsigned char input_scalar[EC_SCALAR_LEN] = { 0 }, output_scalar[EC_SCALAR_LEN] = { 0 };
    unsigned char *output_statuses; /* Blinding status of each output */
    size_t i, num_to_blind = 0, num_blinded = 0;
    bool did_find_input = false, did_blind_output = false, did_blind_last = false;
    int ret = WALLY_OK;

    if (!ctx)
        return WALLY_ENOMEM;
#endif /* BUILD_ELEMENTS */

    if (!psbt_is_valid(psbt) || !psbt->num_inputs || !psbt->num_outputs ||
        !values || !vbfs || !assets || !abfs || flags ||
        (output_index != WALLY_PSET_BLIND_ALL && output_index >= psbt->num_outputs) ||
        !entropy || !entropy_len)
        return WALLY_EINVAL;
#ifndef BUILD_ELEMENTS
    (void)ephemeral_keys_out;
    return WALLY_OK; /* No-op */
#else
    if (entropy_len % BLINDING_FACTOR_LEN)
        return WALLY_EINVAL;
    output_statuses = wally_calloc(psbt->num_outputs * sizeof(unsigned char));
    fixed_input_tags = wally_calloc(psbt->num_inputs * ASSET_TAG_LEN);
    ephemeral_input_tags = wally_calloc(psbt->num_inputs * ASSET_GENERATOR_LEN);
    input_abfs = wally_calloc(psbt->num_inputs * BLINDING_FACTOR_LEN);
    if (!output_statuses || !fixed_input_tags || !ephemeral_input_tags || !input_abfs) {
        ret = WALLY_ENOMEM;
        goto done;
    }

    /* Compute the input data needed to blind our outputs */
    for (i = 0; ret == WALLY_OK && i < psbt->num_inputs; ++i) {
        /* TODO: Handle issuance */
        const struct wally_psbt_input *in = psbt->inputs + i;
        const struct wally_tx_output *utxo = utxo_from_input(psbt, in);
        unsigned char *ephemeral_input_tag = ephemeral_input_tags + i * ASSET_GENERATOR_LEN;
        const struct wally_map_item *value;

        if (!utxo || !utxo->asset || utxo->asset_len != WALLY_TX_ASSET_CT_ASSET_LEN)
            ret = WALLY_EINVAL; /* UTXO not found */
        else
            ret = wally_asset_generator_from_bytes(utxo->asset, utxo->asset_len, NULL, 0,
                                                   ephemeral_input_tag, ASSET_GENERATOR_LEN);
        if (ret != WALLY_OK)
            goto done;

        if ((value = wally_map_get_integer(values, i)) != NULL) {
            const struct wally_map_item *asset = wally_map_get_integer(assets, i);
            const struct wally_map_item *abf = wally_map_get_integer(abfs, i);
            const struct wally_map_item *vbf = wally_map_get_integer(vbfs, i);
            unsigned char tmp[EC_SCALAR_LEN];
            uint64_t satoshi;

            did_find_input = true; /* This input belongs to us */
            ret = wally_tx_confidential_value_to_satoshi(value->value, value->value_len,
                                                         &satoshi);
            if (ret != WALLY_OK ||
                !asset || asset->value_len != ASSET_TAG_LEN ||
                !abf || abf->value_len != BLINDING_FACTOR_LEN ||
                !vbf || vbf->value_len != BLINDING_FACTOR_LEN) {
                ret = WALLY_EINVAL;
                goto done;
            }

            memcpy(fixed_input_tags + i * ASSET_TAG_LEN, asset->value, asset->value_len);
            memcpy(input_abfs + i * BLINDING_FACTOR_LEN, abf->value, abf->value_len);
            /* Compute the input scalar */
            ret = wally_asset_scalar_offset(satoshi, abf->value, abf->value_len,
                                            vbf->value, vbf->value_len, tmp, sizeof(tmp));
            if (ret == WALLY_OK)
                ret = wally_ec_scalar_add_to(input_scalar, sizeof(input_scalar),
                                             tmp, sizeof(tmp));
        } else {
            /* Not ours: use the UTXO asset commitment and leave asset blinder as 0 */
            memcpy(fixed_input_tags + i * ASSET_TAG_LEN,
                   utxo->asset + 1, utxo->asset_len - 1);
        }
    }

    /* Compute which outputs need blinding */
    for (i = 0; ret == WALLY_OK && i < psbt->num_outputs; ++i) {
        size_t status;
        ret = wally_psbt_output_get_blinding_status(psbt->outputs + i, 0, &status);
        if (ret == WALLY_OK) {
            output_statuses[i] = status & 0xff; /* Store as char to reduce memory use */
            num_blinded += status == WALLY_PSET_BLINDED_FULL ? 1 : 0;
            num_to_blind += status == WALLY_PSET_BLINDED_NONE ? 0 : 1;
        }
    }
    if (ret != WALLY_OK || !num_to_blind || num_to_blind == num_blinded)
        goto done; /* Something failed, or there is nothing to do */

    if (!did_find_input) {
        ret = WALLY_EINVAL; /* No matching inputs found, so no output can be blinded */
        goto done;
    }

    /* Blind each output that needs it */
    for (i = 0; ret == WALLY_OK && i < psbt->num_outputs; ++i) {
        struct wally_psbt_output *out = psbt->outputs + i;
        const unsigned char *abf = entropy;
        const unsigned char *vbf = abf + BLINDING_FACTOR_LEN;
        const unsigned char *ephemeral_key = vbf + BLINDING_FACTOR_LEN;
        const unsigned char *explicit_rangeproof_seed = ephemeral_key + BLINDING_FACTOR_LEN;
        const unsigned char *surjectionproof_seed = explicit_rangeproof_seed + BLINDING_FACTOR_LEN;
        const struct wally_map_item *p = wally_map_get_integer(&out->pset_fields, PSET_OUT_ASSET);
        const unsigned char *asset = p && p->value_len == ASSET_TAG_LEN ? p->value : NULL;
        unsigned char tmp[EC_SCALAR_LEN];
        unsigned char asset_commitment[ASSET_COMMITMENT_LEN];
        unsigned char value_commitment[ASSET_COMMITMENT_LEN];
        unsigned char vbf_buf[EC_SCALAR_LEN];
        const size_t entropy_per_output = 5;

        if (output_index != WALLY_PSET_BLIND_ALL && output_index != i)
            continue; /* We havent been asked to blind this output */

        if (output_statuses[i] == WALLY_PSET_BLINDED_FULL) {
            /* TODO: This is Elements logic, treating an existing blinded output as ours */
            did_blind_output = true;
            continue;
        }

        if (!out->has_blinder_index || !wally_map_get_integer(values, out->blinder_index))
            continue; /* Not our output */

        if (!asset || !out->has_amount || entropy_len < BLINDING_FACTOR_LEN * entropy_per_output) {
            ret = WALLY_EINVAL; /* Missing asset, value, or insufficient entropy */
            goto done;
        }
        entropy += BLINDING_FACTOR_LEN * entropy_per_output;
        entropy_len -= BLINDING_FACTOR_LEN * entropy_per_output;

        /* Compute the output scalar */
        ret = wally_asset_scalar_offset(out->amount, abf, BLINDING_FACTOR_LEN,
                                        vbf, BLINDING_FACTOR_LEN, tmp, sizeof(tmp));
        if (ret == WALLY_OK)
            ret = wally_ec_scalar_add_to(output_scalar, sizeof(output_scalar),
                                         tmp, sizeof(tmp));

        if (++num_blinded == num_to_blind) {
            memcpy(vbf_buf, vbf, sizeof(vbf_buf));
            vbf = vbf_buf;
            ret = compute_final_vbf(psbt, input_scalar, output_scalar, vbf_buf);
            did_blind_last = ret == WALLY_OK;
        }

        if (ret == WALLY_OK)
            ret = wally_asset_generator_from_bytes(asset, ASSET_TAG_LEN,
                                                   abf, BLINDING_FACTOR_LEN,
                                                   asset_commitment, ASSET_COMMITMENT_LEN);
        if (ret == WALLY_OK)
            ret = wally_psbt_output_set_asset_commitment(out, asset_commitment,
                                                         ASSET_COMMITMENT_LEN);
        if (ret == WALLY_OK)
            ret = wally_asset_value_commitment(out->amount, vbf, BLINDING_FACTOR_LEN,
                                               asset_commitment, ASSET_COMMITMENT_LEN,
                                               value_commitment, ASSET_COMMITMENT_LEN);
        if (ret == WALLY_OK)
            ret = wally_psbt_output_set_value_commitment(out, value_commitment,
                                                         ASSET_COMMITMENT_LEN);
        if (ret == WALLY_OK) {
            const struct wally_map_item *blinding_pubkey;
            unsigned char rangeproof[ASSET_RANGEPROOF_MAX_LEN];
            size_t rangeproof_len;
            blinding_pubkey = wally_map_get_integer(&out->pset_fields, PSET_OUT_BLINDING_PUBKEY);
            ret = wally_asset_rangeproof(out->amount,
                                         blinding_pubkey->value, blinding_pubkey->value_len,
                                         ephemeral_key, EC_PRIVATE_KEY_LEN,
                                         asset, ASSET_TAG_LEN,
                                         abf, BLINDING_FACTOR_LEN,
                                         vbf, BLINDING_FACTOR_LEN,
                                         value_commitment, ASSET_COMMITMENT_LEN,
                                         out->script, out->script_len,
                                         asset_commitment, ASSET_COMMITMENT_LEN,
                                         1, 0, 52,
                                         rangeproof, sizeof(rangeproof),
                                         &rangeproof_len);
            if (ret == WALLY_OK)
                ret = wally_psbt_output_set_value_rangeproof(out, rangeproof,
                                                             rangeproof_len);
        }

        if (ret == WALLY_OK) {
            unsigned char rangeproof[ASSET_EXPLICIT_RANGEPROOF_MAX_LEN];
            size_t rangeproof_len;
            ret = wally_explicit_rangeproof(out->amount,
                                            explicit_rangeproof_seed, BLINDING_FACTOR_LEN,
                                            vbf, BLINDING_FACTOR_LEN,
                                            value_commitment, ASSET_COMMITMENT_LEN,
                                            asset_commitment, ASSET_COMMITMENT_LEN,
                                            rangeproof, sizeof(rangeproof),
                                            &rangeproof_len);
            if (ret == WALLY_OK)
                ret = wally_psbt_output_set_value_blinding_rangeproof(out, rangeproof,
                                                                      rangeproof_len);
        }

        if (ret == WALLY_OK) {
            /* FIXME: When issuance is implemented, the input array lengths
             * may be different than psbt->num_inputs * X as passed here */
            unsigned char surjectionproof[ASSET_SURJECTIONPROOF_MAX_LEN];
            size_t surjectionproof_len;
            ret = wally_asset_surjectionproof(asset, ASSET_TAG_LEN,
                                              abf, BLINDING_FACTOR_LEN,
                                              asset_commitment, ASSET_COMMITMENT_LEN,
                                              surjectionproof_seed, 32u,
                                              fixed_input_tags, psbt->num_inputs * ASSET_TAG_LEN,
                                              input_abfs, psbt->num_inputs * BLINDING_FACTOR_LEN,
                                              ephemeral_input_tags, psbt->num_inputs * ASSET_GENERATOR_LEN,
                                              surjectionproof, sizeof(surjectionproof),
                                              &surjectionproof_len);
            if (ret == WALLY_OK) {
                if (surjectionproof_len > sizeof(surjectionproof))
                    ret = WALLY_EINVAL; /* Should never happen */
                else
                    ret = wally_psbt_output_set_asset_surjectionproof(out, surjectionproof,
                                                                      surjectionproof_len);
            }
        }

        if (ret == WALLY_OK) {
            unsigned char surjectionproof[ASSET_EXPLICIT_SURJECTIONPROOF_LEN];
            ret = wally_explicit_surjectionproof(asset, ASSET_TAG_LEN,
                                                 abf, BLINDING_FACTOR_LEN,
                                                 asset_commitment, ASSET_COMMITMENT_LEN,
                                                 surjectionproof, sizeof(surjectionproof));
            if (ret == WALLY_OK)
                ret = wally_psbt_output_set_asset_blinding_surjectionproof(out, surjectionproof,
                                                                           sizeof(surjectionproof));
        }

        if (ret == WALLY_OK) {
            unsigned char pubkey[EC_PUBLIC_KEY_LEN];
            ret = wally_ec_public_key_from_private_key(ephemeral_key, EC_PRIVATE_KEY_LEN,
                                                       pubkey, sizeof(pubkey));
            if (ret == WALLY_OK) {
                ret = wally_psbt_output_set_ecdh_public_key(out, pubkey, sizeof(pubkey));
                if (ret == WALLY_OK && ephemeral_keys_out) {
                    /* Return the ephemeral private key for this output */
                    ret = wally_map_add_integer(ephemeral_keys_out, i,
                                                ephemeral_key, EC_PRIVATE_KEY_LEN);
                }
            }
        }

        if (ret == WALLY_OK) {
            did_blind_output = true;
        } else {
            /* FIXME: Delete blinding fields */
            break;
        }
    }

    if (ret == WALLY_OK && !did_blind_output) {
        ret = WALLY_EINVAL; /* We had outputs to blind but didn't blind anything */
        goto done;
    }

    if (ret == WALLY_OK && !did_blind_last && !mem_is_zero(output_scalar, EC_SCALAR_LEN)) {
        ret = wally_ec_scalar_subtract_from(output_scalar, EC_SCALAR_LEN,
                                            input_scalar, EC_SCALAR_LEN);
        if (ret == WALLY_OK)
            ret = wally_map_add(&psbt->global_scalars, output_scalar, EC_SCALAR_LEN, NULL, 0);
    }

done:
    if (ret != WALLY_OK)
        wally_map_clear(ephemeral_keys_out);
    clear_and_free(output_statuses, psbt->num_outputs * sizeof(unsigned char));
    clear_and_free(fixed_input_tags, psbt->num_inputs * ASSET_TAG_LEN);
    clear_and_free(ephemeral_input_tags, psbt->num_inputs * ASSET_GENERATOR_LEN);
    clear_and_free(input_abfs, psbt->num_inputs * BLINDING_FACTOR_LEN);
    return ret;
#endif /* BUILD_ELEMENTS */
}

int wally_psbt_blind_alloc(struct wally_psbt *psbt,
                           const struct wally_map *values,
                           const struct wally_map *vbfs,
                           const struct wally_map *assets,
                           const struct wally_map *abfs,
                           const unsigned char *entropy, size_t entropy_len,
                           uint32_t output_index, uint32_t flags,
                           struct wally_map **output)
{
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct wally_map);
    ret = wally_psbt_blind(psbt, values, vbfs, assets, abfs,
                           entropy, entropy_len, output_index, flags, *output);
    if (ret != WALLY_OK) {
        wally_map_free(*output);
        *output = NULL;
    }
    return ret;
}

int wally_psbt_is_elements(const struct wally_psbt *psbt, size_t *written)
{
    if (written)
        *written = 0;
    if (!psbt || !written)
        return WALLY_EINVAL;

    *written = memcmp(psbt->magic, PSET_MAGIC, sizeof(PSET_MAGIC)) ? 0 : 1;
    return WALLY_OK;
}

/* Getters for maps in inputs/outputs */
#define PSBT_GET_K(typ, name) \
    int wally_psbt_get_ ## typ ## _ ## name ## s_size(const struct wally_psbt *psbt, size_t index, \
                                                      size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written) return WALLY_EINVAL; \
        *written = p->name ## s ? p->name ## s->num_items : 0; \
        return WALLY_OK; \
    }

#define PSBT_GET_M(typ, name) \
    int wally_psbt_get_ ## typ ## _ ## name ## s_size(const struct wally_psbt *psbt, size_t index, \
                                                      size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written) return WALLY_EINVAL; \
        *written = p->name ## s.num_items; \
        return WALLY_OK; \
    } \
    int wally_psbt_find_ ## typ ## _ ## name(const struct wally_psbt *psbt, size_t index, \
                                             const unsigned char *key, size_t key_len, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !key || !key_len || !written) return WALLY_EINVAL; \
        return wally_psbt_ ## typ ## _find_ ## name(p, key, key_len, written); \
    } \
    int wally_psbt_get_ ## typ ## _ ## name(const struct wally_psbt *psbt, size_t index, \
                                            size_t subindex, unsigned char *bytes_out, size_t len, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !bytes_out || !len || !written || subindex >= p->name ## s.num_items) return WALLY_EINVAL; \
        *written = p->name ## s.items[subindex].value_len; \
        if (*written <= len) \
            memcpy(bytes_out, p->name ## s.items[subindex].value, *written); \
        return WALLY_OK; \
    } \
    int wally_psbt_get_ ## typ ## _ ## name ## _len(const struct wally_psbt *psbt, size_t index, \
                                                    size_t subindex, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || subindex >= p->name ## s.num_items) return WALLY_EINVAL; \
        *written = p->name ## s.items[subindex].value_len; \
        return WALLY_OK; \
    }


/* Get a binary buffer value from an input/output */
#define PSBT_GET_B(typ, name, v) \
    int wally_psbt_get_ ## typ ## _ ## name ## _len(const struct wally_psbt *psbt, size_t index, \
                                                    size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (v && psbt->version != v)) return WALLY_EINVAL; \
        *written = p->name ## _len; \
        return WALLY_OK; \
    } \
    int wally_psbt_get_ ## typ ## _ ## name(const struct wally_psbt *psbt, size_t index, \
                                            unsigned char *bytes_out, size_t len, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (v && psbt->version != v)) return WALLY_EINVAL; \
        *written = p->name ## _len; \
        if (p->name ## _len <= len) \
            memcpy(bytes_out, p->name, p->name ## _len); \
        return WALLY_OK; \
    }

/* Set a binary buffer value on an input/output */
#define PSBT_SET_B(typ, name, v) \
    int wally_psbt_set_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index, \
                                            const unsigned char *name, size_t name ## _len) { \
        if (!psbt || (v && psbt->version != v)) return WALLY_EINVAL; \
        return wally_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), name, name ## _len); \
    }

/* Get an integer value from an input/output */
#define PSBT_GET_I(typ, name, inttyp, v) \
    int wally_psbt_get_ ## typ ## _ ## name(const struct wally_psbt *psbt, size_t index, \
                                            inttyp *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (v && psbt->version != v)) return WALLY_EINVAL; \
        *written = p->name; \
        return WALLY_OK; \
    }

/* Set an integer value on an input/output */
#define PSBT_SET_I(typ, name, inttyp, v) \
    int wally_psbt_set_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index, \
                                            inttyp val) { \
        if (!psbt || (v && psbt->version != v)) return WALLY_EINVAL; \
        return wally_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), val); \
    }

/* Get a struct from an input/output */
#define PSBT_GET_S(typ, name, structtyp, clonefn) \
    int wally_psbt_get_ ## typ ## _ ## name ## _alloc(const struct wally_psbt *psbt, size_t index, \
                                                      struct structtyp **output) { \
        const struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (output) *output = NULL; \
        if (!p || !output) return WALLY_EINVAL; \
        return p->name ? clonefn(p->name, output) : WALLY_OK; \
    }

/* Set a struct on an input/output */
#define PSBT_SET_S(typ, name, structtyp) \
    int wally_psbt_set_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index, \
                                            const struct structtyp *p) { \
        return wally_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), p); \
    }

/* Methods for a binary fields */
#define PSBT_FIELD(typ, name, ver) \
    int wally_psbt_get_ ## typ ## _ ## name ## _len(const struct wally_psbt *psbt, \
                                                    size_t index, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (ver && psbt->version != ver)) return WALLY_EINVAL; \
        return wally_psbt_ ## typ ## _get_ ## name ## _len(p, written); \
    } \
    int wally_psbt_get_ ## typ ## _ ## name(const struct wally_psbt *psbt, size_t index, \
                                            unsigned char *bytes_out, size_t len, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (ver && psbt->version != ver)) return WALLY_EINVAL; \
        return wally_psbt_ ## typ ## _get_ ## name(p, bytes_out, len, written); \
    } \
    int wally_psbt_clear_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (!p || (ver && psbt->version != ver)) return WALLY_EINVAL; \
        return wally_psbt_ ## typ ## _clear_ ## name(p); \
    } \
    PSBT_SET_B(typ, name, ver)


PSBT_GET_S(input, utxo, wally_tx, tx_clone_alloc)
PSBT_GET_S(input, witness_utxo, wally_tx_output, wally_tx_output_clone_alloc)
int wally_psbt_get_input_best_utxo(const struct wally_psbt *psbt, size_t index,
                                   const struct wally_tx_output **output)
{
    const struct wally_psbt_input *p = psbt_get_input(psbt, index);
    const struct wally_tx_output *utxo = p ? utxo_from_input(psbt, p) : NULL;
    if (output) *output = NULL;
    if (!p || !output)
        return WALLY_EINVAL;
    *output = utxo;
    return WALLY_OK;
}
int wally_psbt_get_input_best_utxo_alloc(const struct wally_psbt *psbt, size_t index,
                                         struct wally_tx_output **output)
{
    int ret = wally_psbt_get_input_best_utxo(psbt, index, (const struct wally_tx_output **)output);
    if (ret == WALLY_OK)
        ret = *output ? wally_tx_output_clone_alloc(*output, output) : WALLY_OK;
    return ret;
}
PSBT_FIELD(input, redeem_script, PSBT_0)
PSBT_FIELD(input, witness_script, PSBT_0)
PSBT_FIELD(input, final_scriptsig, PSBT_0)
PSBT_FIELD(input, taproot_signature, PSBT_0)
PSBT_GET_S(input, final_witness, wally_tx_witness_stack, wally_tx_witness_stack_clone_alloc)
PSBT_GET_M(input, keypath)
PSBT_GET_M(input, signature)
PSBT_GET_M(input, unknown)
PSBT_GET_I(input, sighash, size_t, PSBT_0)
int wally_psbt_get_input_previous_txid(const struct wally_psbt *psbt, size_t index,
                                       unsigned char *bytes_out, size_t len)
{
    struct wally_psbt_input *p = psbt_get_input(psbt, index);
    const unsigned char *txid;
    if (!p || !bytes_out || len != WALLY_TXHASH_LEN)
        return WALLY_EINVAL;
    txid = psbt->version == PSBT_0 ? psbt->tx->inputs[index].txhash : p->txhash;
    memcpy(bytes_out, txid, WALLY_TXHASH_LEN);
    return WALLY_OK;
}

int wally_psbt_get_input_output_index(const struct wally_psbt *psbt, size_t index,
                                      uint32_t *written)
{
    struct wally_psbt_input *p = psbt_get_input(psbt, index);
    if (written)
        *written = 0;
    if (!p || !written)
        return WALLY_EINVAL;
    *written = psbt->version == PSBT_0 ? psbt->tx->inputs[index].index : p->index;
    return WALLY_OK;
}

int wally_psbt_get_input_sequence(const struct wally_psbt *psbt, size_t index,
                                  uint32_t *written)
{
    struct wally_psbt_input *p = psbt_get_input(psbt, index);
    if (written)
        *written = 0;
    if (!p || !written)
        return WALLY_EINVAL;
    *written = psbt->version == PSBT_0 ? psbt->tx->inputs[index].sequence : p->sequence;
    return WALLY_OK;
}

int wally_psbt_get_input_required_locktime(const struct wally_psbt *psbt,
                                           size_t index, uint32_t *written)
{
    struct wally_psbt_input *p = psbt_get_input(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return WALLY_EINVAL;
    if (!p->required_locktime) return WALLY_EINVAL;
    *written = p->required_locktime;
    return WALLY_OK;
}

int wally_psbt_has_input_required_locktime(const struct wally_psbt *psbt,
                                           size_t index, size_t *written)
{
    struct wally_psbt_input *p = psbt_get_input(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return WALLY_EINVAL;
    *written = p->required_locktime != 0;
    return WALLY_OK;
}

int wally_psbt_get_input_required_lockheight(const struct wally_psbt *psbt,
                                             size_t index, uint32_t *written)
{
    struct wally_psbt_input *p = psbt_get_input(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return WALLY_EINVAL;
    if (!p->required_lockheight) return WALLY_EINVAL;
    *written = p->required_lockheight;
    return WALLY_OK;
}

int wally_psbt_has_input_required_lockheight(const struct wally_psbt *psbt,
                                             size_t index, size_t *written)
{
    struct wally_psbt_input *p = psbt_get_input(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return WALLY_EINVAL;
    *written = p->required_lockheight != 0;
    return WALLY_OK;
}

PSBT_SET_S(input, utxo, wally_tx)
PSBT_SET_S(input, witness_utxo, wally_tx_output)
int wally_psbt_set_input_witness_utxo_from_tx(struct wally_psbt *psbt, size_t index,
                                              const struct wally_tx *utxo, uint32_t utxo_index)
{
    struct wally_psbt_input *p = psbt_get_input(psbt, index);
    return wally_psbt_input_set_witness_utxo_from_tx(p, utxo, utxo_index);
}
PSBT_SET_S(input, final_witness, wally_tx_witness_stack)
PSBT_SET_S(input, keypaths, wally_map)
PSBT_SET_S(input, signatures, wally_map)
int wally_psbt_add_input_signature(struct wally_psbt *psbt, size_t index,
                                   const unsigned char *pub_key, size_t pub_key_len,
                                   const unsigned char *sig, size_t sig_len)
{
    struct wally_psbt_input *p = psbt_get_input(psbt, index);
    int ret;
    if (!p)
        return WALLY_EINVAL;
    ret = wally_psbt_input_add_signature(p, pub_key, pub_key_len, sig, sig_len);
    if (ret == WALLY_OK && psbt->version == PSBT_2) {
        /* Update tx_modifiable_flags based on what the signature covers */
        const unsigned char sighash = sig[sig_len - 1];
        if (!(sighash & WALLY_SIGHASH_ANYONECANPAY))
            psbt->tx_modifiable_flags &= ~WALLY_PSBT_TXMOD_INPUTS;
        if ((sighash & WALLY_SIGHASH_MASK) != WALLY_SIGHASH_NONE)
            psbt->tx_modifiable_flags &= ~WALLY_PSBT_TXMOD_OUTPUTS;
        if ((sighash & WALLY_SIGHASH_MASK) == WALLY_SIGHASH_SINGLE)
            psbt->tx_modifiable_flags |= WALLY_PSBT_TXMOD_SINGLE;
    }
    return ret;
}

PSBT_SET_S(input, unknowns, wally_map)
PSBT_SET_I(input, sighash, uint32_t, PSBT_0)
PSBT_SET_B(input, previous_txid, PSBT_2)
PSBT_SET_I(input, output_index, uint32_t, PSBT_2)
PSBT_SET_I(input, sequence, uint32_t, PSBT_2)
int wally_psbt_clear_input_sequence(struct wally_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return WALLY_EINVAL;
    return wally_psbt_input_clear_sequence(psbt_get_input(psbt, index));
}
PSBT_SET_I(input, required_locktime, uint32_t, PSBT_2)
int wally_psbt_clear_input_required_locktime(struct wally_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return WALLY_EINVAL;
    return wally_psbt_input_clear_required_locktime(psbt_get_input(psbt, index));
}
PSBT_SET_I(input, required_lockheight, uint32_t, PSBT_2)
int wally_psbt_clear_input_required_lockheight(struct wally_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return WALLY_EINVAL;
    return wally_psbt_input_clear_required_lockheight(psbt_get_input(psbt, index));
}

#ifdef BUILD_ELEMENTS
PSBT_GET_I(input, amount, uint64_t, PSBT_2)
int wally_psbt_clear_input_amount(struct wally_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return WALLY_EINVAL;
    return wally_psbt_input_clear_amount(psbt_get_input(psbt, index));
}
PSBT_GET_I(input, issuance_amount, uint64_t, PSBT_2)
PSBT_GET_I(input, inflation_keys, uint64_t, PSBT_2)
PSBT_GET_I(input, pegin_amount, uint64_t, PSBT_2)

PSBT_SET_I(input, amount, uint64_t, PSBT_2)
PSBT_SET_I(input, issuance_amount, uint64_t, PSBT_2)
PSBT_SET_I(input, inflation_keys, uint64_t, PSBT_2)
PSBT_SET_I(input, pegin_amount, uint64_t, PSBT_2)

PSBT_FIELD(input, amount_rangeproof, PSBT_2)
PSBT_FIELD(input, asset, PSBT_2)
PSBT_FIELD(input, asset_surjectionproof, PSBT_2)
PSBT_FIELD(input, issuance_amount_commitment, PSBT_2)
PSBT_FIELD(input, issuance_amount_rangeproof, PSBT_2)
PSBT_FIELD(input, issuance_blinding_nonce, PSBT_2)
PSBT_FIELD(input, issuance_asset_entropy, PSBT_2)
PSBT_FIELD(input, issuance_amount_blinding_rangeproof, PSBT_2)
PSBT_FIELD(input, pegin_claim_script, PSBT_2)
PSBT_FIELD(input, pegin_genesis_blockhash, PSBT_2)
PSBT_FIELD(input, pegin_txout_proof, PSBT_2)
PSBT_FIELD(input, inflation_keys_commitment, PSBT_2)
PSBT_FIELD(input, inflation_keys_rangeproof, PSBT_2)
PSBT_FIELD(input, inflation_keys_blinding_rangeproof, PSBT_2)
PSBT_FIELD(input, utxo_rangeproof, PSBT_2)
int wally_psbt_generate_input_explicit_proofs(
    struct wally_psbt *psbt, size_t index,
    uint64_t satoshi,
    const unsigned char *asset, size_t asset_len,
    const unsigned char *abf, size_t abf_len,
    const unsigned char *vbf, size_t vbf_len,
    const unsigned char *entropy, size_t entropy_len)
{
    if (!psbt || psbt->version != PSBT_2) return WALLY_EINVAL;
    return wally_psbt_input_generate_explicit_proofs(psbt_get_input(psbt, index), satoshi,
                                                     asset, asset_len,
                                                     abf, abf_len,
                                                     vbf, vbf_len,
                                                     entropy, entropy_len);
}
#endif /* BUILD_ELEMENTS */

PSBT_FIELD(output, redeem_script, PSBT_0)
PSBT_FIELD(output, witness_script, PSBT_0)
PSBT_GET_M(output, keypath)
PSBT_GET_M(output, unknown)
PSBT_GET_I(output, amount, uint64_t, PSBT_2)
int wally_psbt_has_output_amount(const struct wally_psbt *psbt, size_t index, size_t *written) {
    struct wally_psbt_output *p = psbt_get_output(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return WALLY_EINVAL;
    *written = p->has_amount ? 1 : 0;
    return WALLY_OK;
}

int wally_psbt_get_output_script_len(const struct wally_psbt *psbt, size_t index,
                                     size_t *written) {
    struct wally_psbt_output *p = psbt_get_output(psbt, index);
    if (written)
        *written = 0;
    if (!p || !written)
        return WALLY_EINVAL;
    *written = psbt->version == PSBT_0 ? psbt->tx->outputs[index].script_len : p->script_len;
    return WALLY_OK;
}

int wally_psbt_get_output_script(const struct wally_psbt *psbt, size_t index,
                                 unsigned char *bytes_out, size_t len, size_t *written) {
    struct wally_psbt_output *p = psbt_get_output(psbt, index);
    if (written)
        *written = 0;
    if (!p || !written)
        return WALLY_EINVAL;
    *written = psbt->version == PSBT_0 ? psbt->tx->outputs[index].script_len : p->script_len;
    if (*written <= len && *written)
        memcpy(bytes_out,
               psbt->version == PSBT_0 ? psbt->tx->outputs[index].script : p->script,
               *written);
    return WALLY_OK;
}

PSBT_SET_S(output, keypaths, wally_map)
PSBT_SET_S(output, unknowns, wally_map)
PSBT_SET_I(output, amount, uint64_t, PSBT_2)
int wally_psbt_clear_output_amount(struct wally_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return WALLY_EINVAL;
    return wally_psbt_output_clear_amount(psbt_get_output(psbt, index));
}
PSBT_SET_B(output, script, PSBT_2)


#ifdef BUILD_ELEMENTS
PSBT_GET_I(output, blinder_index, uint32_t, PSBT_2)
int wally_psbt_has_output_blinder_index(const struct wally_psbt *psbt, size_t index, size_t *written) {
    struct wally_psbt_output *p = psbt_get_output(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return WALLY_EINVAL;
    *written = p->has_blinder_index ? 1 : 0;
    return WALLY_OK;
}

PSBT_SET_I(output, blinder_index, uint32_t, PSBT_2)
int wally_psbt_clear_output_blinder_index(struct wally_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return WALLY_EINVAL;
    return wally_psbt_output_clear_blinder_index(psbt_get_output(psbt, index));
}

PSBT_FIELD(output, value_commitment, PSBT_2)
PSBT_FIELD(output, asset, PSBT_2)
PSBT_FIELD(output, asset_commitment, PSBT_2)
PSBT_FIELD(output, value_rangeproof, PSBT_2)
PSBT_FIELD(output, asset_surjectionproof, PSBT_2)
PSBT_FIELD(output, blinding_public_key, PSBT_2)
PSBT_FIELD(output, ecdh_public_key, PSBT_2)
PSBT_FIELD(output, value_blinding_rangeproof, PSBT_2)
PSBT_FIELD(output, asset_blinding_surjectionproof, PSBT_2)
int wally_psbt_get_output_blinding_status(const struct wally_psbt *psbt, size_t index, uint32_t flags, size_t *written)
{
    struct wally_psbt_output *p = psbt_get_output(psbt, index);
    if (written) *written = WALLY_PSET_BLINDED_NONE;
    if (!p || !written || psbt->version != PSBT_2) return WALLY_EINVAL;
    return wally_psbt_output_get_blinding_status(p, flags, written);
}
#undef MAX_INVALID_SATOSHI
#endif /* BUILD_ELEMENTS */
