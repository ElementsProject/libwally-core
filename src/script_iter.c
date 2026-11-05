#include "script_iter.h"
#include <include/wally_core.h>
#include <include/wally_script.h>

void si_init(script_iter *si, const unsigned char *script, size_t script_len)
{
    si->script = script || !script_len ? script : NULL;
    si->script_len = script_len;
    si->next = 0;
    si->data = NULL;
    si->data_len = 0;
    si->opcode = 0;
}

static bool si_set_error(script_iter *si)
{
    si->script = NULL;
    si->data = NULL;
    si->data_len = 0;
    return false;
}

bool si_next(script_iter *si)
{
    size_t len_bytes = 0, push_len = 0, i;

    if (si_is_error(si) || si->next >= si->script_len)
        return false;

    si->opcode = si->script[si->next++];
    si->data = NULL;
    si->data_len = 0;
    if (!si_is_push(si))
        return true;

    if (si->opcode < OP_PUSHDATA1)
        push_len = si->opcode;
    else
        len_bytes = si->opcode == OP_PUSHDATA1 ? 1 : si->opcode == OP_PUSHDATA2 ? 2 : 4;

    if (len_bytes > si->script_len - si->next)
        return si_set_error(si); /* Truncated push length */
    for (i = 0; i < len_bytes; ++i)
        push_len |= (size_t)si->script[si->next + i] << (i * 8);
    si->next += len_bytes;

    if (push_len > si->script_len - si->next)
        return si_set_error(si); /* Truncated push data */
    si->data = si->script + si->next;
    si->data_len = push_len;
    si->next += push_len;
    return true;
}

bool si_is_error(const script_iter *si)
{
    return !si->script && si->script_len;
}

bool si_is_push(const script_iter *si)
{
    return si->opcode <= OP_PUSHDATA4;
}

bool si_is_minimal_push(const script_iter *si)
{
    const size_t len = si->data_len;

    if (!si_is_push(si))
        return false;
    if (!len)
        return si->opcode == OP_0;
    if (len == 1 && ((si->data[0] >= 1 && si->data[0] <= 16) || si->data[0] == 0x81))
        return false; /* Should be OP_1 to OP_16 or OP_1NEGATE */
    if (len < OP_PUSHDATA1)
        return si->opcode == len;
    if (len <= 0xff)
        return si->opcode == OP_PUSHDATA1;
    if (len <= 0xffff)
        return si->opcode == OP_PUSHDATA2;
    return si->opcode == OP_PUSHDATA4;
}

bool si_get_number(const script_iter *si, int64_t *value_out)
{
    const size_t len = si->data_len;
    int64_t v = 0;
    size_t i;

    *value_out = 0;
    if (si->opcode == OP_0)
        return true;
    if (si->opcode == OP_1NEGATE) {
        *value_out = -1;
        return true;
    }
    if (si->opcode >= OP_1 && si->opcode <= OP_16) {
        *value_out = si->opcode - OP_1 + 1;
        return true;
    }
    if (!si_is_minimal_push(si) || len > 4)
        return false; /* Not a minimal push of a 4 byte number */
    if (!(si->data[len - 1] & 0x7f) &&
        (len == 1 || !(si->data[len - 2] & 0x80)))
        return false; /* Not minimally encoded (the push is never empty here) */
    for (i = 0; i < len; ++i)
        v |= (int64_t)si->data[i] << (i * 8);
    if (si->data[len - 1] & 0x80)
        v = -(v & ~((int64_t)0x80 << ((len - 1) * 8))); /* Negative */
    *value_out = v;
    return true;
}

bool si_match(script_iter *si, const uint32_t *pattern, size_t pattern_len,
              script_iter *matched)
{
    script_iter s = *si;
    size_t i = 0;
    int64_t v;

    if (!pattern || !pattern_len || si_is_error(si) || !si->next)
        return false; /* No pattern, or no current opcode */

    while (i < pattern_len) {
        const uint32_t elem = pattern[i++];
        if (elem == SI_PUSH) {
            if (i >= pattern_len || !si_is_minimal_push(&s) ||
                s.data_len != pattern[i++])
                return false;
        } else if (elem == SI_NUMBER) {
            if (i + 1 >= pattern_len || !si_get_number(&s, &v) ||
                v < (int64_t)pattern[i] || v > (int64_t)pattern[i + 1])
                return false;
            i += 2;
        } else if (elem > 0xff || s.opcode != elem)
            return false;
        if (matched)
            *matched++ = s;
        if (i < pattern_len && !si_next(&s))
            return false; /* Script ended before the pattern */
    }
    *si = s;
    return true;
}
