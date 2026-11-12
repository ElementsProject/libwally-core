#ifndef LIBWALLY_CORE_SCRIPT_ITER_H
#define LIBWALLY_CORE_SCRIPT_ITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* An iterator over the opcodes of a script.
 * Iterating does not allocate memory or copy any script data.
 */
typedef struct script_iter {
    const unsigned char *script; /* The script, or NULL if it is malformed */
    size_t script_len;           /* Length of 'script' */
    size_t next;                 /* Position of the next opcode in 'script' */
    const unsigned char *data;   /* The data pushed by the current opcode */
    size_t data_len;             /* Length of 'data' (0 for non-pushes) */
    unsigned char opcode;        /* The current opcode */
} script_iter;

/* Pattern elements for si_match(). Each element of a pattern is an opcode,
 * or one of the following followed by its arguments:
 * SI_PUSH, len: A minimal push of exactly 'len' bytes.
 * SI_NUMBER, min, max: A number from 'min' to 'max' inclusive (see si_get_number).
 */
#define SI_PUSH   0x100
#define SI_NUMBER 0x200

/* Prepare to iterate a script. si_next() reads the first opcode. */
void si_init(script_iter *si, const unsigned char *script, size_t script_len);

/* Move to the next opcode. Returns false at the end of the script, or if the
 * script is malformed (see si_is_error()).
 */
bool si_next(script_iter *si);

/* Whether the script is malformed (a push overran the end of the script) */
bool si_is_error(const script_iter *si);

/* Whether the current opcode pushes data (OP_0 to OP_PUSHDATA4) */
bool si_is_push(const script_iter *si);

/* Whether the current opcode pushes its data using the minimal encoding */
bool si_is_minimal_push(const script_iter *si);

/* Get the number pushed by the current opcode: OP_0, OP_1NEGATE, OP_1 to OP_16,
 * or a minimally encoded number push of up to 4 bytes.
 */
bool si_get_number(const script_iter *si, int64_t *value_out);

/* Match the opcodes from the current opcode onwards against a pattern.
 * On success, the iterator is left at the last matched opcode and if 'matched'
 * is non-NULL, it receives the iterator state of each matched opcode. On
 * failure the iterator is left unchanged.
 */
bool si_match(script_iter *si, const uint32_t *pattern, size_t pattern_len,
              script_iter *matched);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_SCRIPT_ITER_H */
