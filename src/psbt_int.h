#ifndef LIBWALLY_CORE_PSBT_INT_H
#define LIBWALLY_CORE_PSBT_INT_H 1

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined(SWIG_JAVASCRIPT_BUILD)

#include "wally_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PSBT */
WALLY_CORE_API int wally_psbt_get_global_tx_alloc(const struct wally_psbt *psbt, struct wally_tx **output);
WALLY_CORE_API int wally_psbt_get_version(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_num_inputs(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_num_outputs(const struct wally_psbt *psbt, size_t *written);

/* Inputs */
NESTED_STRUCT_DECL(WALLY_CORE_API, wally_psbt, input, wally_tx, utxo);
NESTED_STRUCT_DECL(WALLY_CORE_API, wally_psbt, input, wally_tx_output, witness_utxo);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, input, redeem_script);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, input, witness_script);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, input, final_scriptsig);
NESTED_STRUCT_DECL(WALLY_CORE_API, wally_psbt, input, wally_tx_witness_stack, final_witness);
NESTED_MAP____DECL(WALLY_CORE_API, wally_psbt, input, keypath);
NESTED_MAP____DECL(WALLY_CORE_API, wally_psbt, input, signature);
NESTED_MAP____DECL(WALLY_CORE_API, wally_psbt, input, unknown);
NESTED_INT____DECL(WALLY_CORE_API, wally_psbt, input, uint32_t, sighash);

#ifdef BUILD_ELEMENTS
NESTED_OPTINT_DECL(WALLY_CORE_API, wally_psbt, input, uint64_t, issuance_amount);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, input, issuance_amount_commitment);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, input, issuance_amount_rangeproof);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, input, inflation_keys_rangeproof);
NESTED_OPTINT_DECL(WALLY_CORE_API, wally_psbt, input, uint64_t, pegin_value);
NESTED_STRUCT_DECL(WALLY_CORE_API, wally_psbt, input, wally_tx, pegin_tx);
NESTED_STRUCT_DECL(WALLY_CORE_API, wally_psbt, input, wally_tx_witness_stack, pegin_witness);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, input, pegin_txoutproof);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, input, pegin_genesis_blockhash);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, input, pegin_claim_script);
#endif /* BUILD_ELEMENTS */

/* Outputs */
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, output, redeem_script);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, output, witness_script);
NESTED_MAP____DECL(WALLY_CORE_API, wally_psbt, output, keypath);
NESTED_MAP____DECL(WALLY_CORE_API, wally_psbt, output, unknown);

#ifdef BUILD_ELEMENTS
NESTED_OPTINT_DECL(WALLY_CORE_API, wally_psbt, output, uint64_t, value);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, output, value_commitment);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, output, asset);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, output, asset_commitment);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, output, rangeproof);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, output, surjectionproof);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, output, blinding_pub_key);
NESTED_VARBUF_DECL(WALLY_CORE_API, wally_psbt, output, ecdh_pub_key);
NESTED_OPTINT_DECL(WALLY_CORE_API, wally_psbt, output, uint32_t, blinding_index);
#endif /* BUILD_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* SWIG/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD/SWIG_JAVASCRIPT_BUILD */

#endif /* LIBWALLY_CORE_PSBT_INT_H */
