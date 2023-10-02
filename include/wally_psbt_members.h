#ifndef LIBWALLY_CORE_PSBT_MEMBERS_H
#define LIBWALLY_CORE_PSBT_MEMBERS_H 1

/* Accessors for PSBT/PSET members */

#ifdef __cplusplus
extern "C" {
#endif

/* PSBT */

WALLY_CORE_API int wally_psbt_get_global_tx_alloc(const struct wally_psbt *psbt, struct wally_tx **output);
WALLY_CORE_API int wally_psbt_get_version(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_num_inputs(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_num_outputs(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_fallback_locktime(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_has_fallback_locktime(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_tx_modifiable_flags(const struct wally_psbt *psbt, size_t *written);
#ifndef WALLY_ABI_NO_ELEMENTS
WALLY_CORE_API int wally_psbt_get_global_scalars_size(const struct wally_psbt *psbt, size_t *written);

/**
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_SCALAR_OFFSET_LEN)
 */
WALLY_CORE_API int wally_psbt_get_global_scalar(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len);

WALLY_CORE_API int wally_psbt_get_pset_modifiable_flags(const struct wally_psbt *psbt, size_t *written);
#endif /* WALLY_ABI_NO_ELEMENTS */

/* Inputs */
WALLY_CORE_API int wally_psbt_get_input_utxo_alloc(const struct wally_psbt *psbt, size_t index, struct wally_tx **output);
WALLY_CORE_API int wally_psbt_get_input_witness_utxo_alloc(const struct wally_psbt *psbt, size_t index, struct wally_tx_output **output);
/* Returns the witness UTXO if present, otherwise the correct output from the non-witness UTXO tx */
#ifndef SWIG
WALLY_CORE_API int wally_psbt_get_input_best_utxo(const struct wally_psbt *psbt, size_t index, const struct wally_tx_output **output);
#endif
WALLY_CORE_API int wally_psbt_get_input_best_utxo_alloc(const struct wally_psbt *psbt, size_t index, struct wally_tx_output **output);
WALLY_CORE_API int wally_psbt_get_input_redeem_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_redeem_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_witness_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_witness_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_final_scriptsig(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_final_scriptsig_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_final_witness_alloc(const struct wally_psbt *psbt, size_t index, struct wally_tx_witness_stack **output);
WALLY_CORE_API int wally_psbt_get_input_keypaths_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_input_keypath(const struct wally_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_keypath(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_keypath_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_signatures_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_input_signature(const struct wally_psbt *psbt, size_t index, const unsigned char *pub_key, size_t pub_key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_signature(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_signature_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_taproot_signature(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_taproot_signature_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_unknowns_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_input_unknown(const struct wally_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_unknown(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_unknown_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_sighash(const struct wally_psbt *psbt, size_t index, size_t *written);

/**
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_TXHASH_LEN)
 */
WALLY_CORE_API int wally_psbt_get_input_previous_txid(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len);

WALLY_CORE_API int wally_psbt_get_input_output_index(const struct wally_psbt *psbt, size_t index, uint32_t *value_out);
WALLY_CORE_API int wally_psbt_get_input_sequence(const struct wally_psbt *psbt, size_t index, uint32_t *value_out);
WALLY_CORE_API int wally_psbt_get_input_required_locktime(const struct wally_psbt *psbt, size_t index, uint32_t *value_out);
WALLY_CORE_API int wally_psbt_get_input_required_lockheight(const struct wally_psbt *psbt, size_t index, uint32_t *value_out);

WALLY_CORE_API int wally_psbt_set_input_utxo(struct wally_psbt *psbt, size_t index, const struct wally_tx *utxo);
WALLY_CORE_API int wally_psbt_set_input_witness_utxo(struct wally_psbt *psbt, size_t index, const struct wally_tx_output *witness_utxo);
WALLY_CORE_API int wally_psbt_set_input_witness_utxo_from_tx(struct wally_psbt *psbt, size_t index, const struct wally_tx *utxo, uint32_t utxo_index);

WALLY_CORE_API int wally_psbt_set_input_redeem_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_input_witness_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_input_final_scriptsig(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_input_final_witness(struct wally_psbt *psbt, size_t index, const struct wally_tx_witness_stack *final_witness);
WALLY_CORE_API int wally_psbt_set_input_keypaths(struct wally_psbt *psbt, size_t index, const struct wally_map *map_in);
WALLY_CORE_API int wally_psbt_set_input_signatures(struct wally_psbt *psbt, size_t index, const struct wally_map *map_in);
WALLY_CORE_API int wally_psbt_set_input_taproot_signature(struct wally_psbt *psbt, size_t index, const unsigned char *sig, size_t sig_len);
WALLY_CORE_API int wally_psbt_add_input_signature(struct wally_psbt *psbt, size_t index, const unsigned char *pub_key, size_t pub_key_len, const unsigned char *sig, size_t sig_len);
WALLY_CORE_API int wally_psbt_set_input_unknowns(struct wally_psbt *psbt, size_t index, const struct wally_map *map_in);
WALLY_CORE_API int wally_psbt_set_input_sighash(struct wally_psbt *psbt, size_t index, uint32_t sighash);
WALLY_CORE_API int wally_psbt_set_input_previous_txid(struct wally_psbt *psbt, size_t index, const unsigned char *txhash, size_t txhash_len);
WALLY_CORE_API int wally_psbt_set_input_output_index(struct wally_psbt *psbt, size_t index, uint32_t output_index);
WALLY_CORE_API int wally_psbt_set_input_sequence(struct wally_psbt *psbt, size_t index, uint32_t sequence);
WALLY_CORE_API int wally_psbt_clear_input_sequence(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_required_locktime(struct wally_psbt *psbt, size_t index, uint32_t locktime);
WALLY_CORE_API int wally_psbt_clear_input_required_locktime(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_has_input_required_locktime(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_set_input_required_lockheight(struct wally_psbt *psbt, size_t index, uint32_t lockheight);
WALLY_CORE_API int wally_psbt_clear_input_required_lockheight(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_has_input_required_lockheight(const struct wally_psbt *psbt, size_t index, size_t *written);
#ifndef WALLY_ABI_NO_ELEMENTS
WALLY_CORE_API int wally_psbt_get_input_amount(const struct wally_psbt *psbt, size_t index, uint64_t *value_out);
WALLY_CORE_API int wally_psbt_get_input_amount_rangeproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_amount_rangeproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_asset(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_asset_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_asset_surjectionproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_asset_surjectionproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_amount(const struct wally_psbt *psbt, size_t index, uint64_t *value_out);
WALLY_CORE_API int wally_psbt_get_input_inflation_keys(const struct wally_psbt *psbt, size_t index, uint64_t *value_out);
WALLY_CORE_API int wally_psbt_get_input_pegin_amount(const struct wally_psbt *psbt, size_t index, uint64_t *value_out);
WALLY_CORE_API int wally_psbt_get_input_pegin_txout_proof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_pegin_txout_proof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_pegin_genesis_blockhash(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_pegin_genesis_blockhash_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_pegin_claim_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_pegin_claim_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_amount_commitment(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_amount_commitment_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_amount_rangeproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_amount_rangeproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_blinding_nonce(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_blinding_nonce_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_asset_entropy(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_asset_entropy_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_amount_blinding_rangeproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_issuance_amount_blinding_rangeproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_inflation_keys_commitment(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_inflation_keys_commitment_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_inflation_keys_rangeproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_inflation_keys_rangeproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_inflation_keys_blinding_rangeproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_inflation_keys_blinding_rangeproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_utxo_rangeproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_utxo_rangeproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);

WALLY_CORE_API int wally_psbt_set_input_amount(struct wally_psbt *psbt, size_t index, uint64_t amount);
WALLY_CORE_API int wally_psbt_clear_input_amount(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_amount_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *rangeproof, size_t rangeproof_len);
WALLY_CORE_API int wally_psbt_clear_input_amount_rangeproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_asset(struct wally_psbt *psbt, size_t index, const unsigned char *asset, size_t asset_len);
WALLY_CORE_API int wally_psbt_clear_input_asset(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_asset_surjectionproof(struct wally_psbt *psbt, size_t index, const unsigned char *surjectionproof, size_t surjectionproof_len);
WALLY_CORE_API int wally_psbt_clear_input_asset_surjectionproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_issuance_amount(struct wally_psbt *psbt, size_t index, uint64_t amount);
WALLY_CORE_API int wally_psbt_set_input_inflation_keys(struct wally_psbt *psbt, size_t index, uint64_t amount);
WALLY_CORE_API int wally_psbt_set_input_pegin_amount(struct wally_psbt *psbt, size_t index, uint64_t amount);
WALLY_CORE_API int wally_psbt_set_input_pegin_txout_proof(struct wally_psbt *psbt, size_t index, const unsigned char *txout_proof, size_t txout_proof_len);
WALLY_CORE_API int wally_psbt_clear_input_pegin_txout_proof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_pegin_genesis_blockhash(struct wally_psbt *psbt, size_t index, const unsigned char *genesis_blockhash, size_t genesis_blockhash_len);
WALLY_CORE_API int wally_psbt_clear_input_pegin_genesis_blockhash(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_pegin_claim_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_clear_input_pegin_claim_script(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_issuance_amount_commitment(struct wally_psbt *psbt, size_t index, const unsigned char *commitment, size_t commitment_len);
WALLY_CORE_API int wally_psbt_clear_input_issuance_amount_commitment(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_issuance_amount_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *rangeproof, size_t rangeproof_len);
WALLY_CORE_API int wally_psbt_clear_input_issuance_amount_rangeproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_issuance_blinding_nonce(struct wally_psbt *psbt, size_t index, const unsigned char *nonce, size_t nonce_len);
WALLY_CORE_API int wally_psbt_clear_input_issuance_blinding_nonce(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_issuance_asset_entropy(struct wally_psbt *psbt, size_t index, const unsigned char *entropy, size_t entropy_len);
WALLY_CORE_API int wally_psbt_clear_input_issuance_asset_entropy(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_issuance_amount_blinding_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *rangeproof, size_t rangeproof_len);
WALLY_CORE_API int wally_psbt_clear_input_issuance_amount_blinding_rangeproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_inflation_keys_commitment(struct wally_psbt *psbt, size_t index, const unsigned char *commitment, size_t commitment_len);
WALLY_CORE_API int wally_psbt_clear_input_inflation_keys_commitment(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_inflation_keys_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *rangeproof, size_t rangeproof_len);
WALLY_CORE_API int wally_psbt_clear_input_inflation_keys_rangeproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_inflation_keys_blinding_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *rangeproof, size_t rangeproof_len);
WALLY_CORE_API int wally_psbt_clear_input_inflation_keys_blinding_rangeproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_utxo_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *rangeproof, size_t rangeproof_len);
WALLY_CORE_API int wally_psbt_clear_input_utxo_rangeproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_generate_input_explicit_proofs(struct wally_psbt *psbt, size_t index, uint64_t satoshi, const unsigned char *asset, size_t asset_len, const unsigned char *abf, size_t abf_len, const unsigned char *vbf, size_t vbf_len, const unsigned char *entropy, size_t entropy_len);
#endif /* WALLY_ABI_NO_ELEMENTS */

/* Outputs */
WALLY_CORE_API int wally_psbt_get_output_redeem_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_redeem_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_witness_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_witness_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_keypaths_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_output_keypath(const struct wally_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_keypath(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_keypath_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_unknowns_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_output_unknown(const struct wally_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_unknown(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_unknown_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_amount(const struct wally_psbt *psbt, size_t index, uint64_t *value_out);
WALLY_CORE_API int wally_psbt_has_output_amount(const struct wally_psbt *psbt, size_t index, size_t *written);

WALLY_CORE_API int wally_psbt_set_output_redeem_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_output_witness_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_output_keypaths(struct wally_psbt *psbt, size_t index, const struct wally_map *map_in);
WALLY_CORE_API int wally_psbt_set_output_unknowns(struct wally_psbt *psbt, size_t index, const struct wally_map *map_in);
WALLY_CORE_API int wally_psbt_set_output_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_output_amount(struct wally_psbt *psbt, size_t index, uint64_t amount);
WALLY_CORE_API int wally_psbt_clear_output_amount(struct wally_psbt *psbt, size_t index);

#ifndef WALLY_ABI_NO_ELEMENTS
WALLY_CORE_API int wally_psbt_get_output_blinder_index(const struct wally_psbt *psbt, size_t index, uint32_t *value_out);
WALLY_CORE_API int wally_psbt_has_output_blinder_index(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_value_commitment(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_value_commitment_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_asset(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_asset_len(const struct wally_psbt *psbt, size_t index, size_t *written);

WALLY_CORE_API int wally_psbt_get_output_asset_commitment(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_asset_commitment_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_value_rangeproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_value_rangeproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_asset_surjectionproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_asset_surjectionproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_blinding_public_key(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_blinding_public_key_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_ecdh_public_key(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_ecdh_public_key_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_value_blinding_rangeproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_value_blinding_rangeproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_asset_blinding_surjectionproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_asset_blinding_surjectionproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);

WALLY_CORE_API int wally_psbt_set_output_blinder_index(struct wally_psbt *psbt, size_t index, uint32_t idx);
WALLY_CORE_API int wally_psbt_clear_output_blinder_index(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_output_value_commitment(struct wally_psbt *psbt, size_t index, const unsigned char *commitment, size_t commitment_len);
WALLY_CORE_API int wally_psbt_clear_output_value_commitment(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_output_asset(struct wally_psbt *psbt, size_t index, const unsigned char *asset, size_t asset_len);
WALLY_CORE_API int wally_psbt_clear_output_asset(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_output_asset_commitment(struct wally_psbt *psbt, size_t index, const unsigned char *commitment, size_t commitment_len);
WALLY_CORE_API int wally_psbt_clear_output_asset_commitment(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_output_value_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *rangeproof, size_t rangeproof_len);
WALLY_CORE_API int wally_psbt_clear_output_value_rangeproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_output_asset_surjectionproof(struct wally_psbt *psbt, size_t index, const unsigned char *surjectionproof, size_t surjectionproof_len);
WALLY_CORE_API int wally_psbt_clear_output_asset_surjectionproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_output_blinding_public_key(struct wally_psbt *psbt, size_t index, const unsigned char *pub_key, size_t pub_key_len);
WALLY_CORE_API int wally_psbt_clear_output_blinding_public_key(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_output_ecdh_public_key(struct wally_psbt *psbt, size_t index, const unsigned char *pub_key, size_t pub_key_len);
WALLY_CORE_API int wally_psbt_clear_output_ecdh_public_key(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_output_value_blinding_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *rangeproof, size_t rangeproof_len);
WALLY_CORE_API int wally_psbt_clear_output_value_blinding_rangeproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_output_asset_blinding_surjectionproof(struct wally_psbt *psbt, size_t index, const unsigned char *surjectionproof, size_t surjectionproof_len);
WALLY_CORE_API int wally_psbt_clear_output_asset_blinding_surjectionproof(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_get_output_blinding_status(const struct wally_psbt *output, size_t index, uint32_t flags, size_t *written);
#endif /* WALLY_ABI_NO_ELEMENTS */
#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_PSBT_MEMBERS_H */
