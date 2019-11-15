#ifndef LIBWALLY_CORE_TRANSACTION_SHARED_H
#define LIBWALLY_CORE_TRANSACTION_SHARED_H 1

#ifdef __cplusplus
extern "C" {
#endif

#define TX_CHECK_OUTPUT if (!output) return WALLY_EINVAL; else *output = NULL
#define TX_OUTPUT_ALLOC(typ) \
    *output = wally_malloc(sizeof(typ)); \
    if (!*output) return WALLY_ENOMEM; \
    wally_clear((void *)*output, sizeof(typ)); \
    result = (typ *) *output;

bool clone_bytes(unsigned char **dst, const unsigned char *src, size_t len);
void clear_and_free(void *p, size_t len);
int analyze_tx(const unsigned char *bytes, size_t bytes_len,
               uint32_t flags, size_t *num_inputs, size_t *num_outputs,
               bool *expect_witnesses);
struct wally_tx_witness_stack *clone_witness(
    const struct wally_tx_witness_stack *stack);
int clone_tx(struct wally_tx *tx, struct wally_tx **output);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_TRANSACTION_SHARED_H */
