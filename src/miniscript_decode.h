#ifndef LIBWALLY_MINISCRIPT_DECODE_H
#define LIBWALLY_MINISCRIPT_DECODE_H

#include "config.h"
#include "descriptor_int.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* Opcode-only tokens */
    TK_BOOL_AND,
    TK_BOOL_OR,
    TK_ADD,
    TK_EQUAL,
    TK_NUM_EQUAL,
    TK_CHECK_SIG,
    TK_CHECK_SIG_ADD,
    TK_CHECK_MULTI_SIG,
    TK_CHECK_SEQUENCE_VERIFY,
    TK_CHECK_LOCK_TIME_VERIFY,
    TK_FROM_ALT_STACK,
    TK_TO_ALT_STACK,
    TK_DROP,
    TK_DUP,
    TK_IF,
    TK_IF_DUP,
    TK_NOT_IF,
    TK_ELSE,
    TK_END_IF,
    TK_ZERO_NOT_EQUAL,
    TK_SIZE,
    TK_SWAP,
    TK_VERIFY,
    TK_RIPEMD160,
    TK_HASH160,
    TK_SHA256,
    TK_HASH256,
    /* Data-carrying tokens */
    TK_NUM,      /* uint32_t */
    TK_HASH20,   /* 20-byte digest (RIPEMD160 / HASH160) */
    TK_BYTES32,  /* 32-byte digest (SHA256 / HASH256) or KEY32 */
    TK_BYTES33,  /* 33-byte compressed pubkey */
    TK_BYTES65,  /* 65-byte uncompressed pubkey */
} tk_kind;

typedef struct token_t {
    tk_kind kind;
    union {
        uint32_t num;           /* TK_NUM */
        uint8_t  hash20[20];   /* TK_HASH20 */
        uint8_t  bytes32[32];  /* TK_BYTES32 */
        uint8_t  bytes33[33];  /* TK_BYTES33 */
        uint8_t  bytes65[65];  /* TK_BYTES65 */
    } data;
} token_t;

/* Tokenize a Script into an array of tokens.
 * tokens must point to a caller-allocated array of at least max_tokens elements.
 * On success *out_count is set to the number of tokens written.
 */
int tokenize_script(const unsigned char *script, size_t script_len,
                    token_t *tokens, size_t max_tokens,
                    size_t *out_count);

typedef enum {
    NT_EXPRESSION,
    NT_W_EXPRESSION,
    NT_SWAP,
    NT_MAYBE_AND_V,
    NT_ALT,
    NT_CHECK,
    NT_DUP_IF,
    NT_VERIFY,
    NT_NON_ZERO,
    NT_ZERO_NOT_EQUAL,
    NT_AND_V,
    NT_AND_B,
    NT_TERN,
    NT_OR_B,
    NT_OR_D,
    NT_OR_C,
    NT_THRESH_W,   /* carries k, n */
    NT_THRESH_E,   /* carries k, n */
    NT_END_IF,
    NT_END_IF_NOT_IF,
    NT_END_IF_ELSE,
} nonterm_kind;

typedef struct nonterm_t {
    nonterm_kind kind;
    uint32_t k;   /* used by NT_THRESH_W / NT_THRESH_E */
    uint32_t n;
} nonterm_t;

typedef struct terminal_stack_t terminal_stack_t;

terminal_stack_t *terminal_stack_new(size_t capacity);
void terminal_stack_free(terminal_stack_t *s);
int terminal_stack_push(terminal_stack_t *s, ms_node *node);
ms_node *terminal_stack_pop(terminal_stack_t *s);
size_t terminal_stack_size(const terminal_stack_t *s);

typedef struct nonterm_stack_t nonterm_stack_t;

nonterm_stack_t *nonterm_stack_new(size_t capacity);
void             nonterm_stack_free(nonterm_stack_t *s);
int              nonterm_stack_push(nonterm_stack_t *s, nonterm_t nt);
bool             nonterm_stack_pop(nonterm_stack_t *s, nonterm_t *out);
size_t           nonterm_stack_size(const nonterm_stack_t *s);

/* Decode a raw Bitcoin Script into an ms_node AST.
 * ctx_flags: WALLY_MINISCRIPT_TAPSCRIPT or 0 (segwit v0).
 * On success *output owns the tree; caller must free with ms_node_free().
 */
int decode_script_to_node(const unsigned char *script, size_t script_len,
                          uint32_t ctx_flags, ms_node **output);

/* Free a decoder-allocated ms_node tree (children + data). */
void ms_node_free(ms_node *node);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_MINISCRIPT_DECODE_H */
