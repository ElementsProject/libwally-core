#ifndef LIBWALLY_MINISCRIPT_DECODE_H
#define LIBWALLY_MINISCRIPT_DECODE_H

#include "descriptor_int.h"
#include <stdint.h>
#include <stddef.h>

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
    TK_BYTES32,  /* 32-byte digest (SHA256 / HASH256) or x-only pubkey */
    TK_BYTES33,  /* 33-byte compressed pubkey */
} tk_kind;

typedef struct token_t {
    tk_kind kind;
    uint32_t num;               /* TK_NUM */
    const unsigned char *bytes; /* TK_HASH20/TK_BYTES32/TK_BYTES33: points
                                 * into the script being tokenized; the length
                                 * is implied by the token kind */
} token_t;

/* Maximum script lengths accepted by the decoder, matching Bitcoin Core's
 * MaxScriptSize(). Callers pass attacker-controlled PSBT scripts here, so
 * anything larger is rejected before any allocation.
 *
 * Segwit v0: the P2WSH standardness limit (MAX_STANDARD_P2WSH_SCRIPT_SIZE).
 *
 * Tapscript: leaf scripts have no explicit limit, so Core bounds them by what
 * a maximum-standard-weight transaction can still spend with a maximum-sized
 * witness, i.e. MAX_STANDARD_TX_WEIGHT (400000)
 *   - TX_BODY_LEEWAY_WEIGHT (378: version, locktime, 1 input, 1 P2WSH output,
 *     compact sizes, segwit marker, all x4, plus 2)
 *   - MAX_TAPSCRIPT_SAT_SIZE (70135: 1000 stack elements of 65 bytes with
 *     their compact sizes, plus a maximum 4129-byte control block)
 *   = 329487, less the 5-byte compact size of that length. */
#define MS_DECODE_MAX_SCRIPT_LEN_SEGWIT_V0 3600
#define MS_DECODE_MAX_SCRIPT_LEN_TAPSCRIPT 329482

/* Tokenize a Script into an array of tokens.
 * tokens must point to a caller-allocated array of at least max_tokens elements.
 * On success *out_count is set to the number of tokens written. Only minimal
 * push encodings are accepted (OP_0/OP_1-OP_16, direct pushes of 1-4 byte
 * script numbers and 20/32/33-byte data); OP_PUSHDATA1/2/4 are always
 * non-minimal for these sizes and are rejected.
 */
int ms_tokenize_script(const unsigned char *script, size_t script_len,
                       token_t *tokens, size_t max_tokens,
                       size_t *out_count);

/* Decode a raw Bitcoin Script into an ms_node AST.
 * ctx_flags: WALLY_MINISCRIPT_TAPSCRIPT or 0 (segwit v0).
 * The decoded tree is type-checked against the BIP-379 correctness rules
 * (types B/V/K/W and the z/o/n/d/u properties) and the top-level expression
 * must be of type B; each node's type_properties holds the computed
 * correctness bits (malleability properties are not computed).
 * On success *output owns the tree; caller must free with ms_node_free().
 */
int ms_node_from_script(const unsigned char *script, size_t script_len,
                        uint32_t ctx_flags, ms_node **output);

/* Free a decoder-allocated ms_node tree. Unlike descriptor.c's node_free(),
 * this always frees node->data (decoded nodes always own their data). */
void ms_node_free(ms_node *node);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_MINISCRIPT_DECODE_H */
