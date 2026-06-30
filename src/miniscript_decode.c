#include "config.h"
#include "miniscript_decode.h"
#include <include/wally_core.h>
#include <include/wally_descriptor.h>
#include <include/wally_script.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MULTI_A_NUM_KEYS_MAX 999

/* --- terminal_stack_t --- */

typedef struct terminal_stack_t {
    ms_node **nodes;
    size_t len;
    size_t cap;
} terminal_stack_t;

static terminal_stack_t *terminal_stack_new(size_t capacity)
{
    terminal_stack_t *s = wally_malloc(sizeof(*s));
    if (!s) return NULL;
    s->nodes = wally_malloc(capacity * sizeof(ms_node *));
    if (!s->nodes) { wally_free(s); return NULL; }
    s->len = 0;
    s->cap = capacity;
    return s;
}

static void terminal_stack_free(terminal_stack_t *s)
{
    if (s) { wally_free(s->nodes); wally_free(s); }
}

static int terminal_stack_push(terminal_stack_t *s, ms_node *node)
{
    if (s->len == s->cap) {
        size_t new_cap = s->cap ? s->cap * 2 : 1;
        ms_node **new_nodes = wally_malloc(new_cap * sizeof(ms_node *));
        if (!new_nodes) return WALLY_ENOMEM;
        memcpy(new_nodes, s->nodes, s->len * sizeof(ms_node *));
        wally_free(s->nodes);
        s->nodes = new_nodes;
        s->cap = new_cap;
    }
    s->nodes[s->len++] = node;
    return WALLY_OK;
}

static ms_node *terminal_stack_pop(terminal_stack_t *s)
{
    if (s->len == 0) return NULL;
    return s->nodes[--s->len];
}

static size_t terminal_stack_size(const terminal_stack_t *s)
{
    return s->len;
}

/* Decode a minimally-encoded little-endian script number (CScriptNum).
 * Accepts 1-4 byte values only (parsing scripts, not evaluating them). */
static bool scriptnum_from_le(const unsigned char *data, size_t len, int64_t *out)
{
    int64_t v = 0;
    size_t i;

    if (!len || len > 4)
        return false;
    for (i = 0; i < len; ++i)
        v |= (int64_t)data[i] << (8 * i);
    if (data[len - 1] & 0x80) {
        /* Negative number: clear the sign bit and negate */
        v ^= (int64_t)0x80 << (8 * (len - 1));
        v = -v;
    }
    *out = v;
    return true;
}

/* Simple opcode to token mapping. Opcodes that fold in a trailing VERIFY
 * (e.g. OP_EQUALVERIFY) emit their base token followed by TK_VERIFY. */
static const struct op_token_map_t {
    unsigned char op;
    tk_kind kind;
    bool add_verify;
} g_op_tokens[] = {
    { OP_BOOLAND,             TK_BOOL_AND,                false },
    { OP_BOOLOR,              TK_BOOL_OR,                 false },
    { OP_ADD,                 TK_ADD,                     false },
    { OP_EQUAL,               TK_EQUAL,                   false },
    { OP_EQUALVERIFY,         TK_EQUAL,                   true },
    { OP_NUMEQUAL,            TK_NUM_EQUAL,               false },
    { OP_NUMEQUALVERIFY,      TK_NUM_EQUAL,               true },
    { OP_CHECKSIG,            TK_CHECK_SIG,               false },
    { OP_CHECKSIGVERIFY,      TK_CHECK_SIG,               true },
    { OP_CHECKSIGADD,         TK_CHECK_SIG_ADD,           false },
    { OP_CHECKMULTISIG,       TK_CHECK_MULTI_SIG,         false },
    { OP_CHECKMULTISIGVERIFY, TK_CHECK_MULTI_SIG,         true },
    { OP_CHECKSEQUENCEVERIFY, TK_CHECK_SEQUENCE_VERIFY,   false },
    { OP_CHECKLOCKTIMEVERIFY, TK_CHECK_LOCK_TIME_VERIFY,  false },
    { OP_FROMALTSTACK,        TK_FROM_ALT_STACK,          false },
    { OP_TOALTSTACK,          TK_TO_ALT_STACK,            false },
    { OP_DROP,                TK_DROP,                    false },
    { OP_DUP,                 TK_DUP,                     false },
    { OP_IF,                  TK_IF,                      false },
    { OP_IFDUP,               TK_IF_DUP,                  false },
    { OP_NOTIF,               TK_NOT_IF,                  false },
    { OP_ELSE,                TK_ELSE,                    false },
    { OP_ENDIF,               TK_END_IF,                  false },
    { OP_0NOTEQUAL,           TK_ZERO_NOT_EQUAL,          false },
    { OP_SIZE,                TK_SIZE,                    false },
    { OP_SWAP,                TK_SWAP,                    false },
    { OP_RIPEMD160,           TK_RIPEMD160,               false },
    { OP_HASH160,             TK_HASH160,                 false },
    { OP_SHA256,              TK_SHA256,                  false },
    { OP_HASH256,             TK_HASH256,                 false },
};

int ms_tokenize_script(const unsigned char *script, size_t script_len,
                       token_t *tokens, size_t max_tokens, size_t *out_count)
{
    size_t i, n = 0;

    for (i = 0; i < script_len; ++i) {
        unsigned char op = script[i];
        size_t j;

        if (op == OP_0) {
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n].kind = TK_NUM;
            tokens[n++].data.num = 0;
            continue;
        }
        if (op == OP_1NEGATE)
            return WALLY_EINVAL;
        if (op >= OP_1 && op <= OP_16) {
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n].kind = TK_NUM;
            tokens[n++].data.num = (uint32_t)(op - OP_1 + 1);
            continue;
        }
        if (op >= 0x01 && op <= OP_PUSHDATA4) {
            size_t data_len;
            const unsigned char *data;

            if (op < OP_PUSHDATA1) {
                data_len = op;
                if (i + 1 + data_len > script_len) return WALLY_EINVAL;
                data = script + i + 1;
                i += data_len;
            } else if (op == OP_PUSHDATA1) {
                if (i + 1 >= script_len) return WALLY_EINVAL;
                data_len = script[i + 1];
                if (i + 2 + data_len > script_len) return WALLY_EINVAL;
                data = script + i + 2;
                i += 1 + data_len;
            } else if (op == OP_PUSHDATA2) {
                if (i + 2 >= script_len) return WALLY_EINVAL;
                data_len = (size_t)script[i + 1] | ((size_t)script[i + 2] << 8);
                if (i + 3 + data_len > script_len) return WALLY_EINVAL;
                data = script + i + 3;
                i += 2 + data_len;
            } else { /* OP_PUSHDATA4 */
                if (i + 4 >= script_len) return WALLY_EINVAL;
                data_len = (size_t)script[i + 1] | ((size_t)script[i + 2] << 8) |
                           ((size_t)script[i + 3] << 16) | ((size_t)script[i + 4] << 24);
                if (i + 5 + data_len > script_len) return WALLY_EINVAL;
                data = script + i + 5;
                i += 4 + data_len;
            }

            if (n >= max_tokens) return WALLY_EINVAL;
            if (data_len == 20) {
                tokens[n].kind = TK_HASH20;
                memcpy(tokens[n].data.hash20, data, 20);
            } else if (data_len == 32) {
                tokens[n].kind = TK_BYTES32;
                memcpy(tokens[n].data.bytes32, data, 32);
            } else if (data_len == 33) {
                tokens[n].kind = TK_BYTES33;
                memcpy(tokens[n].data.bytes33, data, 33);
            } else if (data_len == 65) {
                tokens[n].kind = TK_BYTES65;
                memcpy(tokens[n].data.bytes65, data, 65);
            } else if (data_len >= 1 && data_len <= 4) {
                /* Script number (CScriptNum): 1-4 byte little-endian with sign bit */
                int64_t n64;
                if (!scriptnum_from_le(data, data_len, &n64))
                    return WALLY_EINVAL;
                if (n64 < 0 || n64 > UINT32_MAX)
                    return WALLY_EINVAL;
                /* Enforce minimal push encoding (anti-malleability): values
                 * 0..16 must use OP_0/OP_1..OP_16, and the CScriptNum must be
                 * minimally encoded (no redundant high 0x00 / negative-zero). */
                if (n64 <= 16)
                    return WALLY_EINVAL;
                if ((data[data_len - 1] & 0x7f) == 0 &&
                    (data_len < 2 || (data[data_len - 2] & 0x80) == 0))
                    return WALLY_EINVAL;
                tokens[n].kind = TK_NUM;
                tokens[n].data.num = (uint32_t)n64;
            } else {
                return WALLY_EINVAL;
            }
            n++;
            continue;
        }

        if (op == OP_VERIFY) {
            /* NonMinimalVerify: standalone VERIFY after Equal/CheckSig/CheckMultiSig
             * is non-minimal - the combined opcode should have been used instead */
            if (n > 0) {
                tk_kind last = tokens[n - 1].kind;
                if (last == TK_EQUAL || last == TK_CHECK_SIG || last == TK_CHECK_MULTI_SIG)
                    return WALLY_EINVAL;
            }
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            continue;
        }

        for (j = 0; j < sizeof(g_op_tokens) / sizeof(g_op_tokens[0]); ++j) {
            if (g_op_tokens[j].op == op)
                break;
        }
        if (j == sizeof(g_op_tokens) / sizeof(g_op_tokens[0]))
            return WALLY_EINVAL; /* Unknown/unsupported opcode */
        if (n >= max_tokens) return WALLY_EINVAL;
        tokens[n++].kind = g_op_tokens[j].kind;
        if (g_op_tokens[j].add_verify) {
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
        }
    }

    *out_count = n;
    return WALLY_OK;
}

/* --- nonterm_stack_t --- */

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

typedef struct nonterm_stack_t {
    nonterm_t *items;
    size_t     len;
    size_t     cap;
} nonterm_stack_t;

static nonterm_stack_t *nonterm_stack_new(size_t capacity)
{
    nonterm_stack_t *s = wally_malloc(sizeof(*s));
    if (!s) return NULL;
    s->items = wally_malloc(capacity * sizeof(nonterm_t));
    if (!s->items) { wally_free(s); return NULL; }
    s->len = 0;
    s->cap = capacity;
    return s;
}

static void nonterm_stack_free(nonterm_stack_t *s)
{
    if (s) { wally_free(s->items); wally_free(s); }
}

static int nonterm_stack_push(nonterm_stack_t *s, nonterm_t nt)
{
    if (s->len == s->cap) {
        size_t new_cap = s->cap ? s->cap * 2 : 1;
        nonterm_t *new_items = wally_malloc(new_cap * sizeof(nonterm_t));
        if (!new_items) return WALLY_ENOMEM;
        memcpy(new_items, s->items, s->len * sizeof(nonterm_t));
        wally_free(s->items);
        s->items = new_items;
        s->cap = new_cap;
    }
    s->items[s->len++] = nt;
    return WALLY_OK;
}

static bool nonterm_stack_pop(nonterm_stack_t *s, nonterm_t *out)
{
    if (s->len == 0) return false;
    *out = s->items[--s->len];
    return true;
}

static int push_nt(nonterm_stack_t *s, nonterm_kind kind, uint32_t k, uint32_t n)
{
    nonterm_t nt;
    nt.kind = kind;
    nt.k = k;
    nt.n = n;
    return nonterm_stack_push(s, nt);
}

/* --- tk_cursor_t --- */

typedef struct {
    const token_t *tokens;
    size_t         pos;
} tk_cursor_t;

static void tk_cursor_init(tk_cursor_t *c, const token_t *t, size_t n)
{
    c->tokens = t;
    c->pos    = n;
}

static const token_t *tk_cursor_next(tk_cursor_t *c)
{
    if (c->pos == 0) return NULL;
    return &c->tokens[--c->pos];
}

static const token_t *tk_cursor_peek(const tk_cursor_t *c)
{
    if (c->pos == 0) return NULL;
    return &c->tokens[c->pos - 1];
}

static void tk_cursor_un_next(tk_cursor_t *c)
{
    c->pos++;
}

/* --- ms_node helpers --- */

void ms_node_free(ms_node *node)
{
    /* Free `node` and all of its descendants iteratively. Recursing on ->child
     * would overflow the stack on deeply-nested attacker-supplied scripts, so we
     * thread an explicit work-list through the ->next links of the descendant
     * nodes we own. node->next (a sibling still owned by the caller) is untouched. */
    ms_node *stack;
    if (!node) return;
    stack = node->child;
    wally_free((void *)node->data);
    wally_free(node);
    while (stack) {
        ms_node *m = stack;
        ms_node *child;
        stack = stack->next;
        child = m->child;
        while (child) {
            ms_node *sib = child->next;
            child->next = stack;
            stack = child;
            child = sib;
        }
        wally_free((void *)m->data);
        wally_free(m);
    }
}

/* Free an unattached sibling list of nodes (and their descendants) */
static void node_list_free(ms_node *head)
{
    while (head) {
        ms_node *next = head->next;
        head->next = NULL;
        ms_node_free(head);
        head = next;
    }
}

static ms_node *node_alloc(uint32_t kind)
{
    ms_node *n = wally_calloc(sizeof(*n));
    if (n) n->kind = kind;
    return n;
}

/* --- reduce helpers --- */

static int reduce1(terminal_stack_t *term, uint32_t kind)
{
    ms_node *child = terminal_stack_pop(term);
    if (!child) return WALLY_EINVAL;
    ms_node *parent = node_alloc(kind);
    if (!parent) { ms_node_free(child); return WALLY_ENOMEM; }
    parent->child  = child;
    child->parent  = parent;
    int ret = terminal_stack_push(term, parent);
    if (ret != WALLY_OK) ms_node_free(parent);
    return ret;
}

static int reduce2(terminal_stack_t *term, uint32_t kind)
{
    ms_node *left  = terminal_stack_pop(term);
    ms_node *right = terminal_stack_pop(term);
    if (!left || !right) {
        ms_node_free(left);
        ms_node_free(right);
        return WALLY_EINVAL;
    }
    ms_node *parent = node_alloc(kind);
    if (!parent) { ms_node_free(left); ms_node_free(right); return WALLY_ENOMEM; }
    parent->child  = left;
    left->next     = right;
    left->parent   = parent;
    right->parent  = parent;
    int ret = terminal_stack_push(term, parent);
    if (ret != WALLY_OK) ms_node_free(parent);
    return ret;
}

/* Consume the SIZE 32 EQUALVERIFY prefix (tokens right-to-left: VERIFY EQUAL NUM(32) SIZE). */
static bool consume_hash_suffix(tk_cursor_t *c)
{
    const token_t *t;
    t = tk_cursor_next(c); if (!t || t->kind != TK_VERIFY) return false;
    t = tk_cursor_next(c); if (!t || t->kind != TK_EQUAL)  return false;
    t = tk_cursor_next(c); if (!t || t->kind != TK_NUM || t->data.num != 32) return false;
    t = tk_cursor_next(c); if (!t || t->kind != TK_SIZE)   return false;
    return true;
}

static ms_node *make_hash_node(uint32_t kind, const unsigned char *hash, size_t hash_len)
{
    ms_node *n = node_alloc(kind);
    if (!n) return NULL;
    unsigned char *buf = wally_malloc(hash_len);
    if (!buf) { ms_node_free(n); return NULL; }
    memcpy(buf, hash, hash_len);
    n->data = (const char *)buf;
    n->data_len = (uint32_t)hash_len;
    return n;
}

static bool is_and_v(const tk_cursor_t *cursor)
{
    const token_t *tok = tk_cursor_peek(cursor);
    if (!tok) return false;
    switch (tok->kind) {
    case TK_IF:
    case TK_NOT_IF:
    case TK_ELSE:
    case TK_TO_ALT_STACK:
    case TK_SWAP:
        return false;
    default:
        return true;
    }
}

/* --- ms_node_from_script --- */

int ms_node_from_script(const unsigned char *script, size_t script_len,
                        uint32_t ctx_flags, ms_node **output)
{
    int ret = WALLY_OK;
    nonterm_stack_t *nonterm = NULL;
    terminal_stack_t *term   = NULL;
    token_t *tokens          = NULL;

    /* Guard the allocations below against overflow: token_t is the largest
     * of the (n_tokens + 4)-sized element types allocated (nonterm_t and
     * ms_node* are smaller), so bounding (2 * script_len + 5) * sizeof(token_t)
     * covers them all. */
    if (script_len >= ((SIZE_MAX / sizeof(token_t)) - 5) / 2)
        return WALLY_EINVAL; /* Script too large to tokenize */

    size_t max_tokens = script_len * 2 + 1;
    tokens = wally_malloc(max_tokens * sizeof(token_t));
    if (!tokens) return WALLY_ENOMEM;
    size_t n_tokens = 0;
    ret = ms_tokenize_script(script, script_len, tokens, max_tokens, &n_tokens);
    if (ret != WALLY_OK) { wally_free(tokens); return ret; }

    tk_cursor_t cursor;
    tk_cursor_init(&cursor, tokens, n_tokens);

    nonterm = nonterm_stack_new(n_tokens + 4);
    term    = terminal_stack_new(n_tokens + 4);
    if (!nonterm || !term) { ret = WALLY_ENOMEM; goto cleanup; }

    if ((ret = push_nt(nonterm, NT_MAYBE_AND_V, 0, 0)) != WALLY_OK) goto cleanup;
    if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;

    nonterm_t cur;
    while (nonterm_stack_pop(nonterm, &cur)) {
        switch (cur.kind) {

        case NT_EXPRESSION: {
            const token_t *tok = tk_cursor_peek(&cursor);
            if (!tok) { ret = WALLY_EINVAL; goto cleanup; }

            if (tok->kind == TK_BYTES33 || tok->kind == TK_BYTES65 || tok->kind == TK_BYTES32) {
                /* pk_k: single key push */
                const unsigned char *key_bytes;
                size_t key_len;
                unsigned char *buf;
                ms_node *n;
                tok = tk_cursor_next(&cursor);
                if (tok->kind == TK_BYTES33) {
                    key_bytes = tok->data.bytes33; key_len = 33;
                } else if (tok->kind == TK_BYTES65) {
                    key_bytes = tok->data.bytes65; key_len = 65;
                } else {
                    /* 32-byte x-only keys are only valid in tapscript context */
                    if (!(ctx_flags & WALLY_MINISCRIPT_TAPSCRIPT)) {
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }
                    key_bytes = tok->data.bytes32; key_len = 32;
                }
                n = node_alloc(KIND_MINISCRIPT_PK_K);
                if (!n) { ret = WALLY_ENOMEM; goto cleanup; }
                buf = wally_malloc(key_len);
                if (!buf) { ms_node_free(n); ret = WALLY_ENOMEM; goto cleanup; }
                memcpy(buf, key_bytes, key_len);
                n->data = (const char *)buf;
                n->data_len = (uint32_t)key_len;
                if (key_len == 32 && (ctx_flags & WALLY_MINISCRIPT_TAPSCRIPT))
                    n->flags |= WALLY_MS_IS_X_ONLY;
                ret = terminal_stack_push(term, n);
                if (ret != WALLY_OK) { ms_node_free(n); goto cleanup; }
                break;
            } else if (tok->kind == TK_EQUAL) {
                /* Hash fragments (sha256/hash256/ripemd160/hash160) or thresh.
                 * Script: SIZE 32 EQUALVERIFY <hashop> <digest> EQUAL
                 * Tokens right-to-left: EQUAL, <digest>, <hashop>, VERIFY, EQUAL, NUM(32), SIZE */
                const token_t *t2, *t3;
                ms_node *n;
                tk_cursor_next(&cursor); /* consume TK_EQUAL */
                t2 = tk_cursor_next(&cursor);
                if (!t2) { ret = WALLY_EINVAL; goto cleanup; }

                if (t2->kind == TK_BYTES32) {
                    unsigned char hash32[32];
                    memcpy(hash32, t2->data.bytes32, 32);
                    t3 = tk_cursor_next(&cursor);
                    if (!t3) { ret = WALLY_EINVAL; goto cleanup; }
                    uint32_t kind;
                    if (t3->kind == TK_SHA256)       kind = KIND_MINISCRIPT_SHA256;
                    else if (t3->kind == TK_HASH256) kind = KIND_MINISCRIPT_HASH256;
                    else { ret = WALLY_EINVAL; goto cleanup; }
                    if (!consume_hash_suffix(&cursor)) { ret = WALLY_EINVAL; goto cleanup; }
                    n = make_hash_node(kind, hash32, 32);
                    if (!n) { ret = WALLY_ENOMEM; goto cleanup; }
                    ret = terminal_stack_push(term, n);
                    if (ret != WALLY_OK) { ms_node_free(n); goto cleanup; }
                } else if (t2->kind == TK_HASH20) {
                    unsigned char hash20[20];
                    memcpy(hash20, t2->data.hash20, 20);
                    t3 = tk_cursor_next(&cursor);
                    if (!t3) { ret = WALLY_EINVAL; goto cleanup; }
                    uint32_t kind;
                    if (t3->kind == TK_RIPEMD160)    kind = KIND_MINISCRIPT_RIPEMD160;
                    else if (t3->kind == TK_HASH160) kind = KIND_MINISCRIPT_HASH160;
                    else { ret = WALLY_EINVAL; goto cleanup; }
                    if (!consume_hash_suffix(&cursor)) { ret = WALLY_EINVAL; goto cleanup; }
                    n = make_hash_node(kind, hash20, 20);
                    if (!n) { ret = WALLY_ENOMEM; goto cleanup; }
                    ret = terminal_stack_push(term, n);
                    if (ret != WALLY_OK) { ms_node_free(n); goto cleanup; }
                } else if (t2->kind == TK_NUM) {
                    /* thresh continuation: EQUAL NUM(k) -> ThreshW{k,0} */
                    if ((ret = push_nt(nonterm, NT_THRESH_W, t2->data.num, 0)) != WALLY_OK) goto cleanup;
                } else {
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
                break;
            } else if (tok->kind == TK_CHECK_SEQUENCE_VERIFY || tok->kind == TK_CHECK_LOCK_TIME_VERIFY) {
                uint32_t kind = (tok->kind == TK_CHECK_SEQUENCE_VERIFY)
                                ? KIND_MINISCRIPT_OLDER : KIND_MINISCRIPT_AFTER;
                const token_t *t2;
                ms_node *n;
                tk_cursor_next(&cursor); /* consume CSV/CLTV token */
                t2 = tk_cursor_next(&cursor);
                if (!t2 || t2->kind != TK_NUM) { ret = WALLY_EINVAL; goto cleanup; }
                n = node_alloc(kind);
                if (!n) { ret = WALLY_ENOMEM; goto cleanup; }
                n->number = (int64_t)t2->data.num;
                ret = terminal_stack_push(term, n);
                if (ret != WALLY_OK) { ms_node_free(n); goto cleanup; }
                break;
            } else if (tok->kind == TK_VERIFY) {
                /* pk_h, v:hash_fragment, v:thresh, or general v:X.
                 * Tokens right-to-left: VERIFY [EQUAL <digest> <hashop> VERIFY EQUAL NUM(32) SIZE]
                 *                    or VERIFY EQUAL HASH20 HASH160 DUP  (pk_h)
                 *                    or VERIFY <X tokens>                (v:X) */
                const token_t *t2, *t3, *t4, *t5;
                ms_node *n;
                tk_cursor_next(&cursor); /* consume TK_VERIFY */
                t2 = tk_cursor_peek(&cursor);

                if (t2 && t2->kind == TK_EQUAL) {
                    tk_cursor_next(&cursor); /* consume TK_EQUAL */
                    t3 = tk_cursor_next(&cursor);
                    if (!t3) { ret = WALLY_EINVAL; goto cleanup; }

                    if (t3->kind == TK_HASH20) {
                        unsigned char hash20[20];
                        memcpy(hash20, t3->data.hash20, 20);
                        t4 = tk_cursor_next(&cursor);
                        if (!t4) { ret = WALLY_EINVAL; goto cleanup; }

                        if (t4->kind == TK_HASH160) {
                            /* pk_h or v:hash160: disambiguate by next token */
                            t5 = tk_cursor_peek(&cursor);
                            if (!t5) { ret = WALLY_EINVAL; goto cleanup; }
                            if (t5->kind == TK_DUP) {
                                /* pk_h: DUP HASH160 <hash20> EQUALVERIFY */
                                tk_cursor_next(&cursor); /* consume TK_DUP */
                                n = make_hash_node(KIND_MINISCRIPT_PK_H, hash20, 20);
                                if (!n) { ret = WALLY_ENOMEM; goto cleanup; }
                                ret = terminal_stack_push(term, n);
                                if (ret != WALLY_OK) { ms_node_free(n); goto cleanup; }
                            } else if (t5->kind == TK_VERIFY) {
                                /* v:hash160: SIZE 32 EQUALVERIFY HASH160 <h> EQUALVERIFY */
                                if (!consume_hash_suffix(&cursor)) { ret = WALLY_EINVAL; goto cleanup; }
                                if ((ret = push_nt(nonterm, NT_VERIFY, 0, 0)) != WALLY_OK) goto cleanup;
                                n = make_hash_node(KIND_MINISCRIPT_HASH160, hash20, 20);
                                if (!n) { ret = WALLY_ENOMEM; goto cleanup; }
                                ret = terminal_stack_push(term, n);
                                if (ret != WALLY_OK) { ms_node_free(n); goto cleanup; }
                            } else {
                                ret = WALLY_EINVAL;
                                goto cleanup;
                            }
                        } else if (t4->kind == TK_RIPEMD160) {
                            /* v:ripemd160: SIZE 32 EQUALVERIFY RIPEMD160 <h> EQUALVERIFY */
                            if (!consume_hash_suffix(&cursor)) { ret = WALLY_EINVAL; goto cleanup; }
                            if ((ret = push_nt(nonterm, NT_VERIFY, 0, 0)) != WALLY_OK) goto cleanup;
                            n = make_hash_node(KIND_MINISCRIPT_RIPEMD160, hash20, 20);
                            if (!n) { ret = WALLY_ENOMEM; goto cleanup; }
                            ret = terminal_stack_push(term, n);
                            if (ret != WALLY_OK) { ms_node_free(n); goto cleanup; }
                        } else {
                            ret = WALLY_EINVAL;
                            goto cleanup;
                        }
                    } else if (t3->kind == TK_BYTES32) {
                        unsigned char hash32[32];
                        memcpy(hash32, t3->data.bytes32, 32);
                        t4 = tk_cursor_next(&cursor);
                        if (!t4) { ret = WALLY_EINVAL; goto cleanup; }
                        uint32_t kind;
                        if (t4->kind == TK_SHA256)       kind = KIND_MINISCRIPT_SHA256;
                        else if (t4->kind == TK_HASH256) kind = KIND_MINISCRIPT_HASH256;
                        else { ret = WALLY_EINVAL; goto cleanup; }
                        /* v:sha256 or v:hash256 */
                        if (!consume_hash_suffix(&cursor)) { ret = WALLY_EINVAL; goto cleanup; }
                        if ((ret = push_nt(nonterm, NT_VERIFY, 0, 0)) != WALLY_OK) goto cleanup;
                        n = make_hash_node(kind, hash32, 32);
                        if (!n) { ret = WALLY_ENOMEM; goto cleanup; }
                        ret = terminal_stack_push(term, n);
                        if (ret != WALLY_OK) { ms_node_free(n); goto cleanup; }
                    } else if (t3->kind == TK_NUM) {
                        /* v:thresh */
                        if ((ret = push_nt(nonterm, NT_VERIFY, 0, 0)) != WALLY_OK) goto cleanup;
                        if ((ret = push_nt(nonterm, NT_THRESH_W, t3->data.num, 0)) != WALLY_OK) goto cleanup;
                    } else {
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }
                } else {
                    /* general v:X - TK_VERIFY already consumed, X starts at current position */
                    if ((ret = push_nt(nonterm, NT_VERIFY, 0, 0)) != WALLY_OK) goto cleanup;
                    if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
                }
                break;
            } else if (tok->kind == TK_CHECK_MULTI_SIG) {
                const token_t *t2;
                uint32_t n, k;
                ms_node *prev = NULL, *parent;

                /* OP_CHECKMULTISIG(VERIFY) is disabled in tapscript (BIP-342);
                 * only multi_a (OP_CHECKSIGADD form) is permitted there. */
                if (ctx_flags & WALLY_MINISCRIPT_TAPSCRIPT) {
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }

                tk_cursor_next(&cursor); /* consume TK_CHECK_MULTI_SIG */

                t2 = tk_cursor_next(&cursor);
                if (!t2 || t2->kind != TK_NUM || t2->data.num < 1 || t2->data.num > 20) {
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
                n = t2->data.num;

                for (uint32_t i = 0; i < n; i++) {
                    const token_t *kt = tk_cursor_next(&cursor);
                    const unsigned char *kbytes;
                    size_t klen;
                    ms_node *key_node;
                    unsigned char *buf;

                    if (!kt || (kt->kind != TK_BYTES33 && kt->kind != TK_BYTES65)) {
                        node_list_free(prev);
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }
                    if (kt->kind == TK_BYTES33) { kbytes = kt->data.bytes33; klen = 33; }
                    else { kbytes = kt->data.bytes65; klen = 65; }

                    key_node = node_alloc(KIND_MINISCRIPT_PK_K);
                    buf = key_node ? wally_malloc(klen) : NULL;
                    if (!key_node || !buf) {
                        ms_node_free(key_node);
                        node_list_free(prev);
                        ret = WALLY_ENOMEM;
                        goto cleanup;
                    }
                    memcpy(buf, kbytes, klen);
                    key_node->data = (const char *)buf;
                    key_node->data_len = (uint32_t)klen;
                    key_node->next = prev;
                    prev = key_node;
                }

                t2 = tk_cursor_next(&cursor);
                if (!t2 || t2->kind != TK_NUM || t2->data.num < 1 || t2->data.num > n) {
                    node_list_free(prev);
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
                k = t2->data.num;

                parent = node_alloc(KIND_MINISCRIPT_MULTI);
                if (!parent) {
                    node_list_free(prev);
                    ret = WALLY_ENOMEM;
                    goto cleanup;
                }
                parent->number = (int64_t)k;
                { ms_node *p = prev; while (p) { p->parent = parent; p = p->next; } }
                parent->child = prev;

                ret = terminal_stack_push(term, parent);
                if (ret != WALLY_OK) { ms_node_free(parent); goto cleanup; }
                break;
            } else if (tok->kind == TK_NUM_EQUAL) {
                /* multi_a / sortedmulti_a:
                 * script: K1 OP_CHECKSIG K2 OP_CHECKSIGADD ... Kn OP_CHECKSIGADD k OP_NUMEQUAL
                 * reading right-to-left: NUMEQUAL k (CHECKSIGADD Kn)... (CHECKSIG K1) */
                const token_t *t2;
                uint32_t n = 0, k;
                ms_node *prev = NULL, *parent;
                bool done = false;

                tk_cursor_next(&cursor); /* consume TK_NUM_EQUAL */

                t2 = tk_cursor_next(&cursor);
                if (!t2 || t2->kind != TK_NUM || t2->data.num < 1) {
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
                k = t2->data.num;

                while (!done) {
                    const token_t *opcode_tok, *key_tok;
                    ms_node *key_node;
                    unsigned char *buf;

                    if (n >= MULTI_A_NUM_KEYS_MAX) {
                        node_list_free(prev);
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }

                    opcode_tok = tk_cursor_next(&cursor);
                    if (!opcode_tok) {
                        node_list_free(prev);
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }

                    if (opcode_tok->kind == TK_CHECK_SIG) {
                        done = true;
                    } else if (opcode_tok->kind != TK_CHECK_SIG_ADD) {
                        node_list_free(prev);
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }

                    key_tok = tk_cursor_next(&cursor);
                    if (!key_tok || key_tok->kind != TK_BYTES32) {
                        node_list_free(prev);
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }

                    key_node = node_alloc(KIND_MINISCRIPT_PK_K);
                    buf = key_node ? wally_malloc(32) : NULL;
                    if (!key_node || !buf) {
                        ms_node_free(key_node);
                        node_list_free(prev);
                        ret = WALLY_ENOMEM;
                        goto cleanup;
                    }
                    memcpy(buf, key_tok->data.bytes32, 32);
                    key_node->data = (const char *)buf;
                    key_node->data_len = 32;
                    key_node->next = prev; /* prepend - keys decode Kn..K1, prepend restores K1..Kn */
                    prev = key_node;
                    n++;
                }

                if (k > n) {
                    node_list_free(prev);
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }

                parent = node_alloc(KIND_MINISCRIPT_MULTI_A);
                if (!parent) {
                    node_list_free(prev);
                    ret = WALLY_ENOMEM;
                    goto cleanup;
                }
                parent->number = (int64_t)k;
                { ms_node *p = prev; while (p) { p->parent = parent; p = p->next; } }
                parent->child = prev;

                ret = terminal_stack_push(term, parent);
                if (ret != WALLY_OK) { ms_node_free(parent); goto cleanup; }
                break;
            } else if (tok->kind == TK_BOOL_AND) {
                tk_cursor_next(&cursor); /* consume TK_BOOL_AND */
                if ((ret = push_nt(nonterm, NT_AND_B, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_W_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
                break;
            } else if (tok->kind == TK_BOOL_OR) {
                tk_cursor_next(&cursor); /* consume TK_BOOL_OR */
                if ((ret = push_nt(nonterm, NT_OR_B, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_W_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
                break;
            } else if (tok->kind == TK_END_IF) {
                tk_cursor_next(&cursor); /* consume TK_END_IF */
                if ((ret = push_nt(nonterm, NT_END_IF, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_MAYBE_AND_V, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
                break;
            } else if (tok->kind == TK_CHECK_SIG) {
                tk_cursor_next(&cursor); /* consume TK_CHECK_SIG */
                if ((ret = push_nt(nonterm, NT_CHECK, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
                break;
            } else if (tok->kind == TK_ZERO_NOT_EQUAL) {
                tk_cursor_next(&cursor); /* consume TK_ZERO_NOT_EQUAL */
                if ((ret = push_nt(nonterm, NT_ZERO_NOT_EQUAL, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
                break;
            } else if (tok->kind == TK_NUM && (tok->data.num == 0 || tok->data.num == 1)) {
                tok = tk_cursor_next(&cursor); /* consume TK_NUM */
                uint32_t just_kind = (tok->data.num == 0) ? KIND_MINISCRIPT_JUST_0 : KIND_MINISCRIPT_JUST_1;
                ms_node *jn = node_alloc(just_kind);
                if (!jn) { ret = WALLY_ENOMEM; goto cleanup; }
                ret = terminal_stack_push(term, jn);
                if (ret != WALLY_OK) { ms_node_free(jn); goto cleanup; }
                break;
            }
            ret = WALLY_EINVAL;
            goto cleanup;
        }

        case NT_MAYBE_AND_V:
            if (is_and_v(&cursor)) {
                if ((ret = push_nt(nonterm, NT_AND_V, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
            }
            break;

        case NT_SWAP: {
            const token_t *tok = tk_cursor_next(&cursor);
            if (!tok || tok->kind != TK_SWAP) { ret = WALLY_EINVAL; goto cleanup; }
            ret = reduce1(term, KIND_MINISCRIPT_SWAP);
            if (ret != WALLY_OK) goto cleanup;
            break;
        }

        case NT_ALT: {
            const token_t *tok = tk_cursor_next(&cursor);
            if (!tok || tok->kind != TK_TO_ALT_STACK) { ret = WALLY_EINVAL; goto cleanup; }
            ret = reduce1(term, KIND_MINISCRIPT_ALT);
            if (ret != WALLY_OK) goto cleanup;
            break;
        }

        case NT_CHECK:
            ret = reduce1(term, KIND_MINISCRIPT_CHECK);
            if (ret != WALLY_OK) goto cleanup;
            break;

        case NT_DUP_IF:
            ret = reduce1(term, KIND_MINISCRIPT_DUP_IF);
            if (ret != WALLY_OK) goto cleanup;
            break;

        case NT_VERIFY:
            ret = reduce1(term, KIND_MINISCRIPT_VERIFY);
            if (ret != WALLY_OK) goto cleanup;
            break;

        case NT_NON_ZERO:
            ret = reduce1(term, KIND_MINISCRIPT_NON_ZERO);
            if (ret != WALLY_OK) goto cleanup;
            break;

        case NT_ZERO_NOT_EQUAL:
            ret = reduce1(term, KIND_MINISCRIPT_ZERO_NOT_EQUAL);
            if (ret != WALLY_OK) goto cleanup;
            break;

        case NT_AND_V:
            if (is_and_v(&cursor)) {
                if ((ret = push_nt(nonterm, NT_AND_V, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_MAYBE_AND_V, 0, 0)) != WALLY_OK) goto cleanup;
            } else {
                ret = reduce2(term, KIND_MINISCRIPT_AND_V);
                if (ret != WALLY_OK) goto cleanup;
            }
            break;

        case NT_AND_B:
            ret = reduce2(term, KIND_MINISCRIPT_AND_B);
            if (ret != WALLY_OK) goto cleanup;
            break;

        case NT_OR_B:
            ret = reduce2(term, KIND_MINISCRIPT_OR_B);
            if (ret != WALLY_OK) goto cleanup;
            break;

        case NT_OR_C:
            ret = reduce2(term, KIND_MINISCRIPT_OR_C);
            if (ret != WALLY_OK) goto cleanup;
            break;

        case NT_OR_D:
            ret = reduce2(term, KIND_MINISCRIPT_OR_D);
            if (ret != WALLY_OK) goto cleanup;
            break;

        case NT_TERN: {
            ms_node *a = terminal_stack_pop(term);
            ms_node *b = terminal_stack_pop(term);
            ms_node *c = terminal_stack_pop(term);
            if (!a || !b || !c) {
                ms_node_free(a); ms_node_free(b); ms_node_free(c);
                ret = WALLY_EINVAL; goto cleanup;
            }
            ms_node *parent = node_alloc(KIND_MINISCRIPT_ANDOR);
            if (!parent) {
                ms_node_free(a); ms_node_free(b); ms_node_free(c);
                ret = WALLY_ENOMEM; goto cleanup;
            }
            parent->child = a;
            a->next       = c;
            c->next       = b;
            a->parent = c->parent = b->parent = parent;
            if ((ret = terminal_stack_push(term, parent)) != WALLY_OK) {
                ms_node_free(parent);
                goto cleanup;
            }
            break;
        }

        case NT_THRESH_W: {
            const token_t *tok = tk_cursor_next(&cursor);
            if (!tok) { ret = WALLY_EINVAL; goto cleanup; }
            if (tok->kind == TK_ADD) {
                if ((ret = push_nt(nonterm, NT_THRESH_W, cur.k, cur.n + 1)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_W_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
            } else {
                tk_cursor_un_next(&cursor);
                if ((ret = push_nt(nonterm, NT_THRESH_E, cur.k, cur.n + 1)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
            }
            break;
        }

        case NT_THRESH_E: {
            ms_node *parent = node_alloc(KIND_MINISCRIPT_THRESH);
            ms_node *tail = NULL;
            if (!parent) { ret = WALLY_ENOMEM; goto cleanup; }
            if (cur.k == 0 || cur.k > cur.n) {
                ms_node_free(parent);
                ret = WALLY_EINVAL;
                goto cleanup;
            }
            parent->number = (int64_t)cur.k;
            /* Attach children as they are popped so freeing parent on error
             * also frees any children collected so far */
            for (uint32_t i = 0; i < cur.n; i++) {
                ms_node *child = terminal_stack_pop(term);
                if (!child) { ms_node_free(parent); ret = WALLY_EINVAL; goto cleanup; }
                child->parent = parent;
                child->next   = NULL;
                if (!tail) parent->child = child;
                else       tail->next = child;
                tail = child;
            }
            if ((ret = terminal_stack_push(term, parent)) != WALLY_OK) {
                ms_node_free(parent);
                goto cleanup;
            }
            break;
        }

        case NT_END_IF: {
            const token_t *tok = tk_cursor_next(&cursor);
            if (!tok) { ret = WALLY_EINVAL; goto cleanup; }
            if (tok->kind == TK_ELSE) {
                if ((ret = push_nt(nonterm, NT_END_IF_ELSE, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_MAYBE_AND_V, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
            } else if (tok->kind == TK_IF) {
                const token_t *tok2 = tk_cursor_next(&cursor);
                if (!tok2) { ret = WALLY_EINVAL; goto cleanup; }
                if (tok2->kind == TK_DUP) {
                    if ((ret = push_nt(nonterm, NT_DUP_IF, 0, 0)) != WALLY_OK) goto cleanup;
                } else if (tok2->kind == TK_ZERO_NOT_EQUAL) {
                    const token_t *tok3 = tk_cursor_next(&cursor);
                    if (!tok3 || tok3->kind != TK_SIZE) { ret = WALLY_EINVAL; goto cleanup; }
                    if ((ret = push_nt(nonterm, NT_NON_ZERO, 0, 0)) != WALLY_OK) goto cleanup;
                } else {
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
            } else if (tok->kind == TK_NOT_IF) {
                if ((ret = push_nt(nonterm, NT_END_IF_NOT_IF, 0, 0)) != WALLY_OK) goto cleanup;
            } else {
                ret = WALLY_EINVAL;
                goto cleanup;
            }
            break;
        }

        case NT_END_IF_NOT_IF: {
            const token_t *tok = tk_cursor_next(&cursor);
            if (!tok) { ret = WALLY_EINVAL; goto cleanup; }
            if (tok->kind == TK_IF_DUP) {
                if ((ret = push_nt(nonterm, NT_OR_D, 0, 0)) != WALLY_OK) goto cleanup;
            } else {
                tk_cursor_un_next(&cursor);
                if ((ret = push_nt(nonterm, NT_OR_C, 0, 0)) != WALLY_OK) goto cleanup;
            }
            if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
            break;
        }

        case NT_END_IF_ELSE: {
            const token_t *tok = tk_cursor_next(&cursor);
            if (!tok) { ret = WALLY_EINVAL; goto cleanup; }
            if (tok->kind == TK_IF) {
                ret = reduce2(term, KIND_MINISCRIPT_OR_I);
                if (ret != WALLY_OK) goto cleanup;
            } else if (tok->kind == TK_NOT_IF) {
                if ((ret = push_nt(nonterm, NT_TERN, 0, 0)) != WALLY_OK) goto cleanup;
                if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
            } else {
                ret = WALLY_EINVAL;
                goto cleanup;
            }
            break;
        }

        case NT_W_EXPRESSION: {
            const token_t *tok = tk_cursor_next(&cursor);
            if (!tok) { ret = WALLY_EINVAL; goto cleanup; }
            if (tok->kind == TK_FROM_ALT_STACK) {
                if ((ret = push_nt(nonterm, NT_ALT, 0, 0)) != WALLY_OK) goto cleanup;
            } else {
                tk_cursor_un_next(&cursor);
                if ((ret = push_nt(nonterm, NT_SWAP, 0, 0)) != WALLY_OK) goto cleanup;
            }
            if ((ret = push_nt(nonterm, NT_MAYBE_AND_V, 0, 0)) != WALLY_OK) goto cleanup;
            if ((ret = push_nt(nonterm, NT_EXPRESSION, 0, 0)) != WALLY_OK) goto cleanup;
            break;
        }

        } /* end switch */
    } /* end while */

    if (cursor.pos != 0 || terminal_stack_size(term) != 1) {
        ret = WALLY_EINVAL; /* Unconsumed leading tokens or incomplete expression */
        goto cleanup;
    }
    *output = terminal_stack_pop(term);
    ret = WALLY_OK;

cleanup:
    if (ret != WALLY_OK && term) {
        ms_node *node;
        while ((node = terminal_stack_pop(term)) != NULL)
            ms_node_free(node);
    }
    wally_free(tokens);
    nonterm_stack_free(nonterm);
    terminal_stack_free(term);
    return ret;
}
