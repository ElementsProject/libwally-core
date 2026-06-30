#include "config.h"
#include "miniscript_decode.h"
#include <include/wally_core.h>
#include <include/wally_descriptor.h>
#include <include/wally_script.h>
#include <string.h>
#include "script_int.h"

#define MULTI_A_NUM_KEYS_MAX 999

struct terminal_stack_t {
    ms_node **nodes;
    size_t len;
    size_t cap;
};

terminal_stack_t *terminal_stack_new(size_t capacity)
{
    terminal_stack_t *s = wally_malloc(sizeof(*s));
    if (!s) return NULL;
    s->nodes = wally_malloc(capacity * sizeof(ms_node *));
    if (!s->nodes) { wally_free(s); return NULL; }
    s->len = 0;
    s->cap = capacity;
    return s;
}

void terminal_stack_free(terminal_stack_t *s)
{
    if (s) { wally_free(s->nodes); wally_free(s); }
}

int terminal_stack_push(terminal_stack_t *s, ms_node *node)
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

ms_node *terminal_stack_pop(terminal_stack_t *s)
{
    if (s->len == 0) return NULL;
    return s->nodes[--s->len];
}

size_t terminal_stack_size(const terminal_stack_t *s)
{
    return s->len;
}

int tokenize_script(const unsigned char *script, size_t script_len,
                    token_t *tokens, size_t max_tokens, size_t *out_count)
{
    size_t i, n = 0;

    for (i = 0; i < script_len; ++i) {
        unsigned char op = script[i];

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
                /* Script number (CScriptNum): 1–4 byte little-endian with sign bit */
                unsigned char sbuf[5];
                int64_t n64;
                sbuf[0] = (unsigned char)data_len;
                memcpy(sbuf + 1, data, data_len);
                if (scriptint_from_bytes(sbuf, data_len + 1, &n64) != WALLY_OK)
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

        switch (op) {
        case OP_BOOLAND:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_BOOL_AND;
            break;
        case OP_BOOLOR:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_BOOL_OR;
            break;
        case OP_ADD:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_ADD;
            break;
        case OP_EQUAL:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_EQUAL;
            break;
        case OP_EQUALVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_EQUAL;
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_NUMEQUAL:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_NUM_EQUAL;
            break;
        case OP_NUMEQUALVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_NUM_EQUAL;
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_CHECKSIG:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_SIG;
            break;
        case OP_CHECKSIGVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_SIG;
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_CHECKSIGADD:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_SIG_ADD;
            break;
        case OP_CHECKMULTISIG:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_MULTI_SIG;
            break;
        case OP_CHECKMULTISIGVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_MULTI_SIG;
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_CHECKSEQUENCEVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_SEQUENCE_VERIFY;
            break;
        case OP_CHECKLOCKTIMEVERIFY:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_CHECK_LOCK_TIME_VERIFY;
            break;
        case OP_FROMALTSTACK:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_FROM_ALT_STACK;
            break;
        case OP_TOALTSTACK:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_TO_ALT_STACK;
            break;
        case OP_DROP:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_DROP;
            break;
        case OP_DUP:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_DUP;
            break;
        case OP_IF:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_IF;
            break;
        case OP_IFDUP:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_IF_DUP;
            break;
        case OP_NOTIF:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_NOT_IF;
            break;
        case OP_ELSE:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_ELSE;
            break;
        case OP_ENDIF:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_END_IF;
            break;
        case OP_0NOTEQUAL:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_ZERO_NOT_EQUAL;
            break;
        case OP_SIZE:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_SIZE;
            break;
        case OP_SWAP:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_SWAP;
            break;
        case OP_VERIFY:
            /* NonMinimalVerify: standalone VERIFY after Equal/CheckSig/CheckMultiSig
             * is non-minimal — the combined opcode should have been used instead */
            if (n > 0) {
                tk_kind last = tokens[n - 1].kind;
                if (last == TK_EQUAL || last == TK_CHECK_SIG || last == TK_CHECK_MULTI_SIG)
                    return WALLY_EINVAL;
            }
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_VERIFY;
            break;
        case OP_RIPEMD160:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_RIPEMD160;
            break;
        case OP_HASH160:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_HASH160;
            break;
        case OP_SHA256:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_SHA256;
            break;
        case OP_HASH256:
            if (n >= max_tokens) return WALLY_EINVAL;
            tokens[n++].kind = TK_HASH256;
            break;
        default:
            return WALLY_EINVAL;
        }
    }

    *out_count = n;
    return WALLY_OK;
}

/* ─── nonterm_stack_t ─────────────────────────────────────────────────────── */

struct nonterm_stack_t {
    nonterm_t *items;
    size_t     len;
    size_t     cap;
};

nonterm_stack_t *nonterm_stack_new(size_t capacity)
{
    nonterm_stack_t *s = wally_malloc(sizeof(*s));
    if (!s) return NULL;
    s->items = wally_malloc(capacity * sizeof(nonterm_t));
    if (!s->items) { wally_free(s); return NULL; }
    s->len = 0;
    s->cap = capacity;
    return s;
}

void nonterm_stack_free(nonterm_stack_t *s)
{
    if (s) { wally_free(s->items); wally_free(s); }
}

int nonterm_stack_push(nonterm_stack_t *s, nonterm_t nt)
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

bool nonterm_stack_pop(nonterm_stack_t *s, nonterm_t *out)
{
    if (s->len == 0) return false;
    *out = s->items[--s->len];
    return true;
}

size_t nonterm_stack_size(const nonterm_stack_t *s)
{
    return s->len;
}

/* ─── tk_cursor_t ────────────────────────────────────────────────────────── */

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

/* ─── ms_node helpers ────────────────────────────────────────────────────── */

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

static ms_node *node_alloc(uint32_t kind)
{
    ms_node *n = wally_calloc(sizeof(*n));
    if (n) n->kind = kind;
    return n;
}

/* ─── reduce helpers ─────────────────────────────────────────────────────── */

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

/* ─── decode_script_to_node ──────────────────────────────────────────────── */

int decode_script_to_node(const unsigned char *script, size_t script_len,
                          uint32_t ctx_flags, ms_node **output)
{
    int ret = WALLY_OK;
    nonterm_stack_t *nonterm = NULL;
    terminal_stack_t *term   = NULL;
    token_t *tokens          = NULL;
    nonterm_t nt;

    size_t max_tokens = script_len * 2 + 1;
    tokens = wally_malloc(max_tokens * sizeof(token_t));
    if (!tokens) return WALLY_ENOMEM;
    size_t n_tokens = 0;
    ret = tokenize_script(script, script_len, tokens, max_tokens, &n_tokens);
    if (ret != WALLY_OK) { wally_free(tokens); return ret; }

    tk_cursor_t cursor;
    tk_cursor_init(&cursor, tokens, n_tokens);

    nonterm = nonterm_stack_new(n_tokens + 4);
    term    = terminal_stack_new(n_tokens + 4);
    if (!nonterm || !term) { ret = WALLY_ENOMEM; goto cleanup; }

    nt.kind = NT_MAYBE_AND_V; nt.k = nt.n = 0;
    if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
    nt.kind = NT_EXPRESSION;
    if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;

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
                    /* thresh continuation: EQUAL NUM(k) → ThreshW{k,0} */
                    nt.kind = NT_THRESH_W;
                    nt.k = t2->data.num;
                    nt.n = 0;
                    if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
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
                                nt.kind = NT_VERIFY; nt.k = nt.n = 0;
                                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
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
                            nt.kind = NT_VERIFY; nt.k = nt.n = 0;
                            if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
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
                        nt.kind = NT_VERIFY; nt.k = nt.n = 0;
                        if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                        n = make_hash_node(kind, hash32, 32);
                        if (!n) { ret = WALLY_ENOMEM; goto cleanup; }
                        ret = terminal_stack_push(term, n);
                        if (ret != WALLY_OK) { ms_node_free(n); goto cleanup; }
                    } else if (t3->kind == TK_NUM) {
                        /* v:thresh */
                        nt.kind = NT_VERIFY; nt.k = nt.n = 0;
                        if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                        nt.kind = NT_THRESH_W;
                        nt.k = t3->data.num;
                        nt.n = 0;
                        if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                    } else {
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }
                } else {
                    /* general v:X — TK_VERIFY already consumed, X starts at current position */
                    nt.kind = NT_VERIFY; nt.k = nt.n = 0;
                    if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                    nt.kind = NT_EXPRESSION;
                    if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
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
                        ms_node *p = prev;
                        while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }
                    if (kt->kind == TK_BYTES33) { kbytes = kt->data.bytes33; klen = 33; }
                    else { kbytes = kt->data.bytes65; klen = 65; }

                    key_node = node_alloc(KIND_MINISCRIPT_PK_K);
                    buf = key_node ? wally_malloc(klen) : NULL;
                    if (!key_node || !buf) {
                        ms_node_free(key_node);
                        ms_node *p = prev;
                        while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
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
                    ms_node *p = prev;
                    while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
                k = t2->data.num;

                parent = node_alloc(KIND_MINISCRIPT_MULTI);
                if (!parent) {
                    ms_node *p = prev;
                    while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
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
                        ms_node *p = prev;
                        while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }

                    opcode_tok = tk_cursor_next(&cursor);
                    if (!opcode_tok) {
                        ms_node *p = prev;
                        while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }

                    if (opcode_tok->kind == TK_CHECK_SIG) {
                        done = true;
                    } else if (opcode_tok->kind != TK_CHECK_SIG_ADD) {
                        ms_node *p = prev;
                        while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }

                    key_tok = tk_cursor_next(&cursor);
                    if (!key_tok || key_tok->kind != TK_BYTES32) {
                        ms_node *p = prev;
                        while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
                        ret = WALLY_EINVAL;
                        goto cleanup;
                    }

                    key_node = node_alloc(KIND_MINISCRIPT_PK_K);
                    buf = key_node ? wally_malloc(32) : NULL;
                    if (!key_node || !buf) {
                        ms_node_free(key_node);
                        ms_node *p = prev;
                        while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
                        ret = WALLY_ENOMEM;
                        goto cleanup;
                    }
                    memcpy(buf, key_tok->data.bytes32, 32);
                    key_node->data = (const char *)buf;
                    key_node->data_len = 32;
                    key_node->next = prev; /* prepend — keys decode Kn..K1, prepend restores K1..Kn */
                    prev = key_node;
                    n++;
                }

                if (k > n) {
                    ms_node *p = prev;
                    while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }

                parent = node_alloc(KIND_MINISCRIPT_MULTI_A);
                if (!parent) {
                    ms_node *p = prev;
                    while (p) { ms_node *nx = p->next; p->next = NULL; ms_node_free(p); p = nx; }
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
                nt.kind = NT_AND_B; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_EXPRESSION; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_W_EXPRESSION; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                break;
            } else if (tok->kind == TK_BOOL_OR) {
                tk_cursor_next(&cursor); /* consume TK_BOOL_OR */
                nt.kind = NT_OR_B; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_EXPRESSION; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_W_EXPRESSION; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                break;
            } else if (tok->kind == TK_END_IF) {
                tk_cursor_next(&cursor); /* consume TK_END_IF */
                nt.kind = NT_END_IF; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_MAYBE_AND_V; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_EXPRESSION; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                break;
            } else if (tok->kind == TK_CHECK_SIG) {
                tk_cursor_next(&cursor); /* consume TK_CHECK_SIG */
                nt.kind = NT_CHECK; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_EXPRESSION;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                break;
            } else if (tok->kind == TK_ZERO_NOT_EQUAL) {
                tk_cursor_next(&cursor); /* consume TK_ZERO_NOT_EQUAL */
                nt.kind = NT_ZERO_NOT_EQUAL; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_EXPRESSION;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
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
                nt.kind = NT_AND_V; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_EXPRESSION;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
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
                nt.kind = NT_AND_V; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_MAYBE_AND_V;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
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
                nt.kind = NT_THRESH_W;
                nt.k    = cur.k;
                nt.n    = cur.n + 1;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_W_EXPRESSION; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            } else {
                tk_cursor_un_next(&cursor);
                nt.kind = NT_THRESH_E;
                nt.k    = cur.k;
                nt.n    = cur.n + 1;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_EXPRESSION; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            }
            break;
        }

        case NT_THRESH_E: {
            ms_node *parent = node_alloc(KIND_MINISCRIPT_THRESH);
            if (!parent) { ret = WALLY_ENOMEM; goto cleanup; }
            if (cur.k == 0 || cur.k > cur.n) {
                ms_node_free(parent);
                ret = WALLY_EINVAL;
                goto cleanup;
            }
            parent->number = (int64_t)cur.k;
            ms_node *head = NULL, *tail = NULL;
            for (uint32_t i = 0; i < cur.n; i++) {
                ms_node *child = terminal_stack_pop(term);
                if (!child) { ms_node_free(parent); ret = WALLY_EINVAL; goto cleanup; }
                child->parent = parent;
                child->next   = NULL;
                if (!head) { head = tail = child; }
                else       { tail->next = child; tail = child; }
            }
            parent->child = head;
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
                nt.kind = NT_END_IF_ELSE; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_MAYBE_AND_V;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_EXPRESSION;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            } else if (tok->kind == TK_IF) {
                const token_t *tok2 = tk_cursor_next(&cursor);
                if (!tok2) { ret = WALLY_EINVAL; goto cleanup; }
                if (tok2->kind == TK_DUP) {
                    nt.kind = NT_DUP_IF; nt.k = nt.n = 0;
                    if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                } else if (tok2->kind == TK_ZERO_NOT_EQUAL) {
                    const token_t *tok3 = tk_cursor_next(&cursor);
                    if (!tok3 || tok3->kind != TK_SIZE) { ret = WALLY_EINVAL; goto cleanup; }
                    nt.kind = NT_NON_ZERO; nt.k = nt.n = 0;
                    if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                } else {
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
            } else if (tok->kind == TK_NOT_IF) {
                nt.kind = NT_END_IF_NOT_IF; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
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
                nt.kind = NT_OR_D; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            } else {
                tk_cursor_un_next(&cursor);
                nt.kind = NT_OR_C; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            }
            nt.kind = NT_EXPRESSION; nt.k = nt.n = 0;
            if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            break;
        }

        case NT_END_IF_ELSE: {
            const token_t *tok = tk_cursor_next(&cursor);
            if (!tok) { ret = WALLY_EINVAL; goto cleanup; }
            if (tok->kind == TK_IF) {
                ret = reduce2(term, KIND_MINISCRIPT_OR_I);
                if (ret != WALLY_OK) goto cleanup;
            } else if (tok->kind == TK_NOT_IF) {
                nt.kind = NT_TERN; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
                nt.kind = NT_EXPRESSION;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
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
                nt.kind = NT_ALT; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            } else {
                tk_cursor_un_next(&cursor);
                nt.kind = NT_SWAP; nt.k = nt.n = 0;
                if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            }
            nt.kind = NT_MAYBE_AND_V; nt.k = nt.n = 0;
            if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            nt.kind = NT_EXPRESSION;
            if ((ret = nonterm_stack_push(nonterm, nt)) != WALLY_OK) goto cleanup;
            break;
        }

        } /* end switch */
    } /* end while */

    if (terminal_stack_size(term) != 1) {
        ret = WALLY_EINVAL;
        goto cleanup;
    }
    *output = terminal_stack_pop(term);
    ret = WALLY_OK;

cleanup:
    if (ret != WALLY_OK) {
        ms_node *node;
        while ((node = terminal_stack_pop(term)) != NULL)
            ms_node_free(node);
    }
    wally_free(tokens);
    nonterm_stack_free(nonterm);
    terminal_stack_free(term);
    return ret;
}
