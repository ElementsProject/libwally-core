#ifndef LIBWALLY_CORE_SCRIPT_INT_H
#define LIBWALLY_CORE_SCRIPT_INT_H 1

#ifdef __cplusplus
extern "C" {
#endif

/* NOTE: These internal functions do no parameter checking */
static inline size_t memcpy_len(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
    return len;
}

/* Read v from bytes_out in little endian */
static inline size_t uint8_from_le_bytes(const unsigned char *bytes_in, uint8_t *v)
{
    *v = *bytes_in;
    return sizeof(*v);
}

#define UINT_FROM_LE_BYTES(N) static inline size_t \
    uint ## N ## _from_le_bytes(const unsigned char *bytes_in, uint ## N ## _t * v) { \
        leint ## N ## _t tmp; \
        memcpy(&tmp, bytes_in, sizeof(tmp)); \
        *v = le ## N ## _to_cpu(tmp); \
        return sizeof(tmp); \
    }
UINT_FROM_LE_BYTES(16)
UINT_FROM_LE_BYTES(32)
UINT_FROM_LE_BYTES(64)
#undef UINT_FROM_LE_BYTES

/* Write v to bytes_out in little endian */
static inline size_t uint8_to_le_bytes(uint8_t v, unsigned char *bytes_out)
{
    *bytes_out = v;
    return sizeof(v);
}

#define UINT_TO_LE_BYTES(N) static inline size_t \
    uint ## N ## _to_le_bytes(uint ## N ## _t v, unsigned char *bytes_out) { \
        leint ## N ## _t tmp = cpu_to_le ## N(v); \
        return memcpy_len(bytes_out, &tmp, sizeof(tmp)); \
    }
UINT_TO_LE_BYTES(16)
UINT_TO_LE_BYTES(32)
UINT_TO_LE_BYTES(64)
#undef UINT_TO_LE_BYTES

/* Get the number of bytes required to encode v as a varint */
size_t varint_get_length(uint64_t v);

/* Write v to bytes_out as a varint */
size_t varint_to_bytes(uint64_t v, unsigned char *bytes_out);

/* Read a variant from bytes_in */
size_t varint_from_bytes(const unsigned char *bytes_in, uint64_t *v);

size_t varint_length_from_bytes(const unsigned char *bytes_in);

/* varbuff is a buffer of data prefixed with a varint length */

/* Get the number of bytes required to write len_in as a varbuff */
static inline size_t varbuff_get_length(size_t len_in)
{
    return varint_get_length(len_in) + len_in;
}

/* Write bytes_in to bytes_out as a varbuff */
size_t varbuff_to_bytes(const unsigned char *bytes_in, size_t len_in,
                        unsigned char *bytes_out);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_SCRIPT_INT_H */
