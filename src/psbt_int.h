#ifndef LIBWALLY_CORE_PSBT_INT_H
#define LIBWALLY_CORE_PSBT_INT_H 1

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined(SWIG_JAVASCRIPT_BUILD)

#ifdef __cplusplus
extern "C" {
#endif

/* PSBT */

WALLY_CORE_API int wally_psbt_get_global_tx_alloc(const struct wally_psbt *psbt, struct wally_tx **output);
WALLY_CORE_API int wally_psbt_get_version(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_num_inputs(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_num_outputs(const struct wally_psbt *psbt, size_t *written);

/* Inputs */
WALLY_CORE_API int wally_psbt_set_input_non_witness_utxo(struct wally_psbt *psbt, size_t index, const struct wally_tx *non_witness_utxo);
WALLY_CORE_API int wally_psbt_set_input_witness_utxo(struct wally_psbt *psbt, size_t index, const struct wally_tx_output *witness_utxo);
WALLY_CORE_API int wally_psbt_set_input_redeem_script(struct wally_psbt *psbt, size_t index, const unsigned char *redeem_script, size_t redeem_script_len);
WALLY_CORE_API int wally_psbt_set_input_witness_script(struct wally_psbt *psbt, size_t index, const unsigned char *witness_script, size_t witness_script_len);
WALLY_CORE_API int wally_psbt_set_input_final_script_sig(struct wally_psbt *psbt, size_t index, const unsigned char *final_script_sig, size_t final_script_sig_len);
WALLY_CORE_API int wally_psbt_set_input_final_witness(struct wally_psbt *psbt, size_t index, const struct wally_tx_witness_stack *final_witness);
WALLY_CORE_API int wally_psbt_set_input_keypaths(struct wally_psbt *psbt, size_t index, const struct wally_keypath_map *keypaths);
WALLY_CORE_API int wally_psbt_set_input_partial_sigs(struct wally_psbt *psbt, size_t index, const struct wally_partial_sigs_map *partial_sigs);
WALLY_CORE_API int wally_psbt_set_input_unknowns(struct wally_psbt *psbt, size_t index, const struct wally_unknowns_map *unknowns);
WALLY_CORE_API int wally_psbt_set_input_sighash_type(struct wally_psbt *psbt, size_t index, uint32_t sighash_type);
#ifdef BUILD_ELEMENTS
WALLY_CORE_API int wally_psbt_set_input_value(struct wally_psbt *psbt, size_t index, uint64_t value);
WALLY_CORE_API int wally_psbt_clear_input_value(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_vbf(struct wally_psbt *psbt, size_t index, const unsigned char *vbf, size_t vbf_len);
WALLY_CORE_API int wally_psbt_set_input_asset(struct wally_psbt *psbt, size_t index, const unsigned char *asset, size_t asset_len);
WALLY_CORE_API int wally_psbt_set_input_abf(struct wally_psbt *psbt, size_t index, const unsigned char *abf, size_t abf_len);
WALLY_CORE_API int wally_psbt_set_input_peg_in_tx(struct wally_psbt *psbt, size_t index, const struct wally_tx *peg_in_tx);
WALLY_CORE_API int wally_psbt_set_input_txoutproof(struct wally_psbt *psbt, size_t index, const unsigned char *proof, size_t proof_len);
WALLY_CORE_API int wally_psbt_set_input_genesis_blockhash(struct wally_psbt *psbt, size_t index, const unsigned char *genesis_blockhash, size_t genesis_blockhash_len);
WALLY_CORE_API int wally_psbt_set_input_claim_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
#endif /* BUILD_ELEMENTS */

/* Outputs */

WALLY_CORE_API int wally_psbt_set_output_redeem_script(struct wally_psbt *psbt, size_t index,  const unsigned char *redeem_script, size_t redeem_script_len);
WALLY_CORE_API int wally_psbt_set_output_witness_script(struct wally_psbt *psbt, size_t index,  const unsigned char *witness_script, size_t witness_script_len);
WALLY_CORE_API int wally_psbt_set_output_keypaths(struct wally_psbt *psbt, size_t index,  const struct wally_keypath_map *keypaths);
WALLY_CORE_API int wally_psbt_set_output_unknowns(struct wally_psbt *psbt, size_t index,  const struct wally_unknowns_map *unknowns);

#ifdef BUILD_ELEMENTS
WALLY_CORE_API int wally_psbt_set_output_blinding_pubkey(struct wally_psbt *psbt, size_t index, const unsigned char *pub_key, size_t pub_key_len);
WALLY_CORE_API int wally_psbt_set_output_value_commitment(struct wally_psbt *psbt, size_t index, const unsigned char *commitment, size_t commitment_len);
WALLY_CORE_API int wally_psbt_set_output_vbf(struct wally_psbt *psbt, size_t index, const unsigned char *vbf, size_t vbf_len);
WALLY_CORE_API int wally_psbt_set_output_asset_commitment(struct wally_psbt *psbt, size_t index, const unsigned char *commitment, size_t commitment_len);
WALLY_CORE_API int wally_psbt_set_output_abf(struct wally_psbt *psbt, size_t index, const unsigned char *abf, size_t abf_len);
WALLY_CORE_API int wally_psbt_set_output_nonce(struct wally_psbt *psbt, size_t index, const unsigned char *nonce, size_t nonce_len);
WALLY_CORE_API int wally_psbt_set_output_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *proof, size_t proof_len);
WALLY_CORE_API int wally_psbt_set_output_surjectionproof(struct wally_psbt *psbt, size_t index, const unsigned char *proof, size_t proof_len);
#endif /* BUILD_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* SWIG/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD/SWIG_JAVASCRIPT_BUILD */

#endif /* LIBWALLY_CORE_PSBT_INT_H */
