#ifndef LIBWALLY_CORE_TRANSACTION_INT_H
#define LIBWALLY_CORE_TRANSACTION_INT_H 1

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined(SWIG_JAVASCRIPT_BUILD)

#ifdef __cplusplus
extern "C" {
#endif

/* Input */
WALLY_CORE_API int wally_tx_input_get_txhash(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_input_get_script(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_input_get_script_len(const struct wally_tx_input *tx_input_in, size_t *written);
WALLY_CORE_API int wally_tx_input_get_witness(const struct wally_tx_input *tx_input_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_input_get_witness_len(const struct wally_tx_input *tx_input_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_input_get_index(const struct wally_tx_input *tx_input_in, size_t *written);
WALLY_CORE_API int wally_tx_input_get_sequence(const struct wally_tx_input *tx_input_in, size_t *written);

/* Output */
WALLY_CORE_API int wally_tx_output_get_script(const struct wally_tx_output *tx_output_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_output_get_script_len(const struct wally_tx_output *tx_output_in, size_t *written);
WALLY_CORE_API int wally_tx_output_get_satoshi(const struct wally_tx_output *tx_output_in, uint64_t *value_out);

WALLY_CORE_API int wally_tx_output_set_script(struct wally_tx_output *tx_output_in, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_tx_output_set_satoshi(struct wally_tx_output *tx_output_in, uint64_t satoshi);

/* Transaction */
WALLY_CORE_API int wally_tx_get_version(const struct wally_tx *tx_in, size_t *written);
WALLY_CORE_API int wally_tx_get_locktime(const struct wally_tx *tx_in, size_t *written);
WALLY_CORE_API int wally_tx_get_num_inputs(const struct wally_tx *tx_in, size_t *written);
WALLY_CORE_API int wally_tx_get_num_outputs(const struct wally_tx *tx_in, size_t *written);

/* Transaction Inputs */
WALLY_CORE_API int wally_tx_get_input_txhash(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_get_input_script(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_input_script_len(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_input_witness(const struct wally_tx *tx_in, size_t index, size_t wit_index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_input_witness_len(const struct wally_tx *tx_in, size_t index, size_t wit_index, size_t *written);
WALLY_CORE_API int wally_tx_get_input_index(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_input_sequence(const struct wally_tx *tx_in, size_t index, size_t *written);

WALLY_CORE_API int wally_tx_set_input_index(const struct wally_tx *tx_in, size_t index, uint32_t index_in);
WALLY_CORE_API int wally_tx_set_input_sequence(const struct wally_tx *tx_in, size_t index, uint32_t sequence);

/* Transaction Outputs */
WALLY_CORE_API int wally_tx_get_output_script(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_output_script_len(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_output_satoshi(const struct wally_tx *tx_in, size_t index, uint64_t *value_out);

WALLY_CORE_API int wally_tx_set_output_script(const struct wally_tx *tx_in, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_tx_set_output_satoshi(const struct wally_tx *tx_in, size_t index, uint64_t satoshi);

#ifdef __cplusplus
}
#endif

#endif /* SWIG_JAVA_BUILD/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD */

#endif /* LIBWALLY_CORE_TRANSACTION_INT_H */
