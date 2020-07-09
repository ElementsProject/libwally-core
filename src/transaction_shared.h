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

#define BYTES_VALID(p, len) ((p != NULL) == (len != 0))
#define BYTES_INVALID(p, len) (!BYTES_VALID(p, len))
#define BYTES_INVALID_N(p, len, siz) ((p != NULL) != (len == siz))

bool clone_bytes(unsigned char **dst, const unsigned char *src, size_t len);
int replace_bytes(const unsigned char *bytes, size_t bytes_len,
                  unsigned char **bytes_out, size_t *bytes_len_out);
void clear_and_free(void *p, size_t len);
void *realloc_array(const void *src, size_t old_n, size_t new_n, size_t size);
int analyze_tx(const unsigned char *bytes, size_t bytes_len,
               uint32_t flags, size_t *num_inputs, size_t *num_outputs,
               bool *expect_witnesses);
struct wally_tx_witness_stack *clone_witness(
    const struct wally_tx_witness_stack *stack);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_TRANSACTION_SHARED_H */
