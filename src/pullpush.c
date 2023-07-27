#include "internal.h"
#include "script_int.h"

#if 0
#include <assert.h>
#endif
#include <limits.h>
#include "pullpush.h"
#include <include/wally_transaction.h>

unsigned char *push_bytes(unsigned char **cursor, size_t *max,
                          const void *src, size_t len)
{
    if (cursor == NULL || *cursor == NULL) {
        *max += len;
        return NULL;
    }
    if (len > *max) {
        if (src)
            memcpy(*cursor, src, *max);
        /* From now on, max records the room we *needed* */
        *max = len - *max;
        *cursor = NULL;
        return NULL;
    }
    if (src)
        memcpy(*cursor, src, len);

    *cursor += len;
    *max -= len;

    return *cursor - len;
}

void pull_bytes(void *dst, size_t len,
                const unsigned char **cursor, size_t *max)
{
    if (len > *max) {
        if (*max && *cursor)
            memcpy(dst, *cursor, *max);
        memset((char *)dst + *max, 0, len - *max);
        pull_failed(cursor, max);
        return;
    }
    if (len && *cursor) {
        memcpy(dst, *cursor, len);
        *cursor += len;
        *max -= len;
    }
}

const unsigned char *pull_skip(const unsigned char **cursor, size_t *max,
                               size_t len)
{
    const unsigned char *p;

    if (*cursor == NULL) {
        return NULL;
    }

    if (len > *max) {
        pull_failed(cursor, max);
        return NULL;
    }

    p = *cursor;
    *cursor += len;
    *max -= len;
    return p;
}

void pull_failed(const unsigned char **cursor, size_t *max)
{
    *cursor = NULL;
    *max = 0;
}

void push_le64(unsigned char **cursor, size_t *max, uint64_t v)
{
    leint64_t lev = cpu_to_le64(v);
    push_bytes(cursor, max, &lev, sizeof(lev));
}

uint64_t pull_le64(const unsigned char **cursor, size_t *max)
{
    leint64_t lev = 0;
    pull_bytes(&lev, sizeof(lev), cursor, max);
    return le64_to_cpu(lev);
}

void push_le32(unsigned char **cursor, size_t *max, uint32_t v)
{
    leint32_t lev = cpu_to_le32(v);
    push_bytes(cursor, max, &lev, sizeof(lev));
}

uint32_t pull_le32(const unsigned char **cursor, size_t *max)
{
    leint32_t lev = 0;
    pull_bytes(&lev, sizeof(lev), cursor, max);
    return le32_to_cpu(lev);
}

void push_u8(unsigned char **cursor, size_t *max, uint8_t v)
{
    push_bytes(cursor, max, &v, sizeof(uint8_t));
}

uint8_t pull_u8(const unsigned char **cursor, size_t *max)
{
    uint8_t v = 0;
    pull_bytes(&v, sizeof(v), cursor, max);
    return v;
}

uint8_t peek_u8(const unsigned char **cursor, size_t *max)
{
    uint8_t v = pull_u8(cursor, max);
    if (*cursor) {
        *cursor -= sizeof(v);
        *max += sizeof(v);
    }
    return v;
}

void push_varint(unsigned char **cursor, size_t *max, uint64_t v)
{
    unsigned char buf[sizeof(uint8_t) + sizeof(uint64_t)];
    size_t len = varint_to_bytes(v, buf);

    push_bytes(cursor, max, buf, len);
}

void push_witness_stack(unsigned char **cursor, size_t *max,
                        const struct wally_tx_witness_stack *witness)
{
    size_t i;
    push_varint(cursor, max, witness->num_items);
    for (i = 0; i < witness->num_items; ++i) {
        push_varbuff(cursor, max, witness->items[i].witness,
                     witness->items[i].witness_len);
    }
}

uint64_t pull_varint(const unsigned char **cursor, size_t *max)
{
    unsigned char buf[sizeof(uint8_t) + sizeof(uint64_t)];
    size_t len;
    uint64_t v;

    pull_bytes(buf, 1, cursor, max);
    if ((len = varint_length_from_bytes(buf) - 1))
        pull_bytes(buf + 1, len, cursor, max);
    varint_from_bytes(buf, &v);
    return v;
}

void push_varbuff(unsigned char **cursor, size_t *max,
                  const unsigned char *bytes, size_t bytes_len)
{
    push_varint(cursor, max, bytes_len);
    push_bytes(cursor, max, bytes, bytes_len);
}

size_t pull_varlength(const unsigned char **cursor, size_t *max)
{
    uint64_t len = pull_varint(cursor, max);

    if (len > *max) {
        /* Impossible length. */
        pull_failed(cursor, max);
        return 0;
    }
    return len;
}

void pull_varlength_buff(const unsigned char **cursor, size_t *max,
                         const unsigned char **dst, size_t *len)
{
    *len = pull_varlength(cursor, max);
    *dst = pull_skip(cursor, max, *len);
}

void pull_varint_buff(const unsigned char **cursor, size_t *max,
                      const unsigned char **dst, size_t *len)
{
    uint64_t varint_len = pull_varint(cursor, max);
    *len = varint_len;
    *dst = pull_skip(cursor, max, varint_len);
}

void pull_subfield_start(const unsigned char *const *cursor, const size_t *max,
                         size_t subfield_len,
                         const unsigned char **subcursor, size_t *submax)
{
    if (subfield_len > *max) {
        pull_failed(subcursor, submax);
    } else {
        *subcursor = *cursor;
        *submax = subfield_len;
    }
}

void pull_subfield_end(const unsigned char **cursor, size_t *max,
                       const unsigned char *subcursor, size_t submax)
{
    if (subcursor == NULL) {
        pull_failed(cursor, max);
    } else if (*cursor != NULL) {
        const unsigned char *subend = subcursor + submax;
        if (subcursor < *cursor || subend > *cursor + *max) {
            pull_failed(cursor, max);
        } else {
            *max -= (subend - *cursor);
            *cursor = subend;
        }
    }
}

void subfield_nomore_end(const unsigned char **cursor, size_t *max,
                         const unsigned char *subcursor,
                         const size_t submax)
{
    if (submax)
        pull_failed(cursor, max);
    else
        pull_subfield_end(cursor, max, subcursor, submax);
}

int pull_witness(const unsigned char **cursor, size_t *max,
                 struct wally_tx_witness_stack **witness_out,
                 bool for_psbt)
{
    const unsigned char *val;
    size_t val_len;
    uint64_t num_witnesses, i;
    int ret;

    if (*witness_out)
        return WALLY_EINVAL; /* Duplicate */

    if (for_psbt)
        pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    else {
        val = *cursor;
        val_len = *max;
    }
    num_witnesses = pull_varint(&val, &val_len);
    ret = wally_tx_witness_stack_init_alloc(num_witnesses, witness_out);

    for (i = 0; ret == WALLY_OK && i < num_witnesses; ++i) {
        const unsigned char *wit;
        size_t wit_len;
        pull_varint_buff(&val, &val_len, &wit, &wit_len);
        ret = wally_tx_witness_stack_set(*witness_out, i, wit, wit_len);
    }
    if (ret == WALLY_OK) {
        if (for_psbt) {
            subfield_nomore_end(cursor, max, val, val_len);
            if (!*cursor && !*max)
                ret = WALLY_EINVAL; // Trailing data
        } else if (!val && !val_len)
            ret = WALLY_EINVAL; // Trailing data
    }
    if (ret != WALLY_OK) {
        wally_tx_witness_stack_free(*witness_out);
        *witness_out = NULL;
    }
    return ret;
}
