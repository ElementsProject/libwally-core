#include "internal.h"

#include "descriptor_int.h"
#include "miniscript_decode.h"
#include "script_iter.h"

#include <include/wally_address.h>
#include <include/wally_crypto.h>
#include <include/wally_descriptor.h>
#include <include/wally_map.h>
#include <include/wally_script.h>

/* Script to miniscript decoding.
 *
 * The script is iterated forwards, building a tree of the expressions found,
 * which is then printed as text. This decodes scripts as Bitcoin Core's
 * DecodeScript() does (which iterates backwards):
 *
 * - Expressions, e.g. "<key>" or "<n> OP_CHECKSEQUENCEVERIFY", are added
 *   as items to the current scope.
 * - Operators take their operands from the last items of the current scope,
 *   e.g. OP_CHECKSIG wraps the last item in c:, while OP_BOOLAND combines the
 *   last two. Each operand is a single item, so that and_v is always the
 *   outermost expression, e.g. and_v(X,c:Y) rather than c:and_v(X,Y).
 * - OP_IF, OP_NOTIF, OP_ELSE, OP_TOALTSTACK and OP_SWAP begin a new scope,
 *   which is closed by the operator that ends the expression they begin
 *   (OP_ELSE, OP_ENDIF, OP_FROMALTSTACK, or for s:, the OP_BOOLAND, OP_BOOLOR
 *   or OP_ADD that uses it). The items of a closed scope are combined using
 *   and_v, nesting to the left, e.g. and_v(and_v(X,Y),Z).
 * - The W expressions a:X and s:X are only valid as the last operand of
 *   and_b, or_b and thresh.
 *
 * Decoding only checks that the script is a miniscript; the resulting
 * expression is type checked by parsing it.
 */

#define NO_NODE 0xffffffff
#define MAX_WRAPPERS 11 /* Maximum wrappers on an expression (ms_node.wrapper_str) */
#define MULTI_MAX_KEYS 20
#define MULTI_A_MAX_KEYS 999 /* BIP-342: stack limited to 1000 elements, one used by the threshold */
#define LOCKTIME_MAX 0x7fffffff
#define SEQ_LOCKTIME_TYPE_FLAG 0x00400000 /* BIP-68 time based relative lock */
#define SEQ_LOCKTIME_MASK 0x0000ffff /* BIP-68 relative lock value */

/* Expression fragments */
enum {
    FRAG_JUST_0, FRAG_JUST_1, FRAG_PK_K, FRAG_PK_H, FRAG_PK, FRAG_PKH,
    FRAG_OLDER, FRAG_AFTER, FRAG_SHA256, FRAG_HASH256, FRAG_RIPEMD160,
    FRAG_HASH160, FRAG_MULTI, FRAG_MULTI_A, FRAG_AND_V, FRAG_AND_B,
    FRAG_AND_N, FRAG_ANDOR, FRAG_OR_B, FRAG_OR_C, FRAG_OR_D, FRAG_OR_I,
    FRAG_THRESH,
    /* Wrappers */
    FRAG_A, FRAG_S, FRAG_C, FRAG_D, FRAG_V, FRAG_J, FRAG_N, FRAG_T, FRAG_L,
    FRAG_U
};
#define IS_WRAPPER(frag) ((frag) >= FRAG_A)

/* Fragment names, in FRAG_ order */
static const char *const g_frag_names[] = {
    "0", "1", "pk_k", "pk_h", "pk", "pkh",
    "older", "after", "sha256", "hash256", "ripemd160",
    "hash160", "multi", "multi_a", "and_v", "and_b",
    "and_n", "andor", "or_b", "or_c", "or_d", "or_i",
    "thresh",
    "a", "s", "c", "d", "v", "j", "n", "t", "l",
    "u"
};

static const struct ms_hash_t {
    unsigned char opcode;
    unsigned char frag;
    unsigned char len;
} g_hashes[] = {
    { OP_SHA256, FRAG_SHA256, SHA256_LEN },
    { OP_HASH256, FRAG_HASH256, SHA256_LEN },
    { OP_RIPEMD160, FRAG_RIPEMD160, RIPEMD160_LEN },
    { OP_HASH160, FRAG_HASH160, HASH160_LEN }
};

/* A decoded expression */
typedef struct ms_dnode {
    uint32_t child;  /* First sub-expression */
    uint32_t next;   /* Next sibling sub-expression */
    uint32_t parent; /* Parent expression */
    uint32_t value;  /* Number/threshold, key index (pk_h), or number of wrappers */
    uint32_t offset; /* Script offset of the key/hash, or first key push (multi/multi_a) */
    uint32_t depth;  /* Nesting depth, as calculated by wally_descriptor_parse() */
    unsigned char frag;
} ms_dnode;

/* Item kinds */
#define ITEM_EXPR   0 /* An expression */
#define ITEM_W      1 /* An a: expression, which must be used by the next operator */
#define ITEM_THRESH 2 /* An incomplete thresh */

typedef struct ms_ditem {
    uint32_t node;
    uint32_t last;  /* ITEM_THRESH: The last sub-expression */
    uint32_t count; /* ITEM_THRESH: The number of sub-expressions */
    unsigned char kind;
} ms_ditem;

/* Scope kinds, with the script decoded when they are opened */
enum {
    SCOPE_TOP,    /* The script */
    SCOPE_OR_I,   /* OP_IF */
    SCOPE_OR_I_Z, /* OP_IF X OP_ELSE */
    SCOPE_NOTIF,  /* X OP_NOTIF */
    SCOPE_OR_D,   /* X OP_IFDUP OP_NOTIF */
    SCOPE_ANDOR,  /* X OP_NOTIF Z OP_ELSE */
    SCOPE_D,      /* OP_DUP OP_IF */
    SCOPE_J,      /* OP_SIZE OP_0NOTEQUAL OP_IF */
    SCOPE_A,      /* OP_TOALTSTACK */
    SCOPE_S       /* OP_SWAP */
};

typedef struct ms_dscope {
    size_t base; /* Index of the first item in the scope */
    uint32_t x;  /* Condition (or_c/or_d/andor) or first branch (or_i) */
    uint32_t z;  /* Second branch (andor) */
    unsigned char kind;
} ms_dscope;

typedef struct ms_decoder {
    const unsigned char *script;
    size_t script_len;
    size_t key_len; /* Length of keys in the script */
    bool is_tapscript;
    const struct wally_map *keys; /* Keys for pk_h */
    unsigned char *key_hashes; /* HASH160 of each key in 'keys' */
    ms_dnode *nodes;
    size_t num_nodes, nodes_len;
    ms_ditem *items;
    size_t num_items, items_len;
    ms_dscope *scopes;
    size_t num_scopes, scopes_len;
} ms_decoder;

/* Ensure there is space for another element in an array */
static int array_reserve(void **p, size_t num_elems, size_t *allocation_len,
                         size_t elem_size)
{
    size_t n;
    void *new_p;

    if (num_elems < *allocation_len)
        return WALLY_OK;
    n = *allocation_len ? *allocation_len * 2 : 16;
    if (!(new_p = wally_malloc(n * elem_size)))
        return WALLY_ENOMEM;
    if (*p) {
        memcpy(new_p, *p, num_elems * elem_size);
        wally_free(*p);
    }
    *p = new_p;
    *allocation_len = n;
    return WALLY_OK;
}

static int node_new(ms_decoder *d, unsigned char frag, uint32_t value,
                    size_t offset, uint32_t *output)
{
    ms_dnode *node;
    int ret = array_reserve((void **)&d->nodes, d->num_nodes,
                            &d->nodes_len, sizeof(*d->nodes));
    if (ret == WALLY_OK) {
        node = d->nodes + d->num_nodes;
        node->child = node->next = node->parent = NO_NODE;
        node->value = value;
        node->offset = (uint32_t)offset;
        node->depth = frag == FRAG_JUST_0 || frag == FRAG_JUST_1 ? 1 : 2;
        node->frag = frag;
        *output = (uint32_t)d->num_nodes++;
    }
    return ret;
}

/* Create an expression from its sub-expressions */
static int node_make(ms_decoder *d, unsigned char frag,
                     const uint32_t *subs, size_t num_subs, uint32_t *output)
{
    ms_dnode *node, *sub;
    uint32_t depth = 0;
    size_t i;
    int ret = node_new(d, frag, 0, 0, output);

    if (ret != WALLY_OK)
        return ret;
    node = d->nodes + *output;
    node->child = subs[0];
    for (i = 0; i < num_subs; ++i) {
        sub = d->nodes + subs[i];
        sub->parent = *output;
        sub->next = i + 1 < num_subs ? subs[i + 1] : NO_NODE;
        if (sub->depth > depth)
            depth = sub->depth;
    }
    if (IS_WRAPPER(frag)) {
        sub = d->nodes + subs[0];
        node->value = IS_WRAPPER(sub->frag) ? sub->value + 1 : 1;
        node->depth = depth;
        if (node->value > MAX_WRAPPERS)
            return WALLY_EINVAL; /* Too many wrappers */
    } else
        node->depth = depth + 1;
    return node->depth > MS_DECODE_MAX_DEPTH ? WALLY_EINVAL : WALLY_OK;
}

/* Apply a wrapper to an expression */
static int node_wrap(ms_decoder *d, unsigned char frag, uint32_t *node)
{
    const uint32_t sub = *node;
    return node_make(d, frag, &sub, 1, node);
}

static bool node_is(const ms_decoder *d, uint32_t node, unsigned char frag)
{
    return d->nodes[node].frag == frag;
}

static ms_dscope *scope_current(ms_decoder *d)
{
    return d->scopes + d->num_scopes - 1;
}

/* Get the last item in the current scope, or NULL if it has none */
static ms_ditem *item_last(ms_decoder *d)
{
    if (d->num_items == scope_current(d)->base)
        return NULL;
    return d->items + d->num_items - 1;
}

static int item_push(ms_decoder *d, uint32_t node, unsigned char kind)
{
    ms_ditem *item;
    int ret = array_reserve((void **)&d->items, d->num_items,
                            &d->items_len, sizeof(*d->items));
    if (ret == WALLY_OK) {
        item = d->items + d->num_items++;
        item->node = node;
        item->last = NO_NODE;
        item->count = 0;
        item->kind = kind;
    }
    return ret;
}

/* Remove the last item in the current scope, which must be an expression */
static int item_pop(ms_decoder *d, uint32_t *node)
{
    const ms_ditem *item = item_last(d);

    if (!item || item->kind != ITEM_EXPR)
        return WALLY_EINVAL;
    *node = item->node;
    --d->num_items;
    return WALLY_OK;
}

static int item_push_new(ms_decoder *d, unsigned char frag, uint32_t value,
                         size_t offset)
{
    uint32_t node;
    int ret = node_new(d, frag, value, offset, &node);
    return ret == WALLY_OK ? item_push(d, node, ITEM_EXPR) : ret;
}

/* Apply a wrapper to the last item in the current scope */
static int item_wrap(ms_decoder *d, unsigned char frag)
{
    uint32_t node;
    int ret = item_pop(d, &node);

    if (ret == WALLY_OK) {
        if (frag == FRAG_C && node_is(d, node, FRAG_PK_K))
            d->nodes[node].frag = FRAG_PK; /* pk(K) is c:pk_k(K) */
        else if (frag == FRAG_C && node_is(d, node, FRAG_PK_H))
            d->nodes[node].frag = FRAG_PKH; /* pkh(K) is c:pk_h(K) */
        else
            ret = node_wrap(d, frag, &node);
    }
    return ret == WALLY_OK ? item_push(d, node, ITEM_EXPR) : ret;
}

static int scope_open(ms_decoder *d, unsigned char kind, uint32_t x, uint32_t z)
{
    ms_dscope *scope;
    int ret = array_reserve((void **)&d->scopes, d->num_scopes,
                            &d->scopes_len, sizeof(*d->scopes));
    if (ret == WALLY_OK) {
        scope = d->scopes + d->num_scopes++;
        scope->base = d->num_items;
        scope->x = x;
        scope->z = z;
        scope->kind = kind;
    }
    return ret;
}

/* Close the current scope, combining its items into a single expression */
static int scope_close(ms_decoder *d, uint32_t *output)
{
    const size_t base = scope_current(d)->base;
    uint32_t subs[2];
    size_t i;
    int ret = base < d->num_items ? WALLY_OK : WALLY_EINVAL; /* Empty scope */

    for (i = base; ret == WALLY_OK && i < d->num_items; ++i) {
        if (d->items[i].kind != ITEM_EXPR)
            ret = WALLY_EINVAL; /* Incomplete thresh, or unused a: */
        else if (i == base)
            *output = d->items[i].node;
        else if (node_is(d, d->items[i].node, FRAG_JUST_1))
            ret = node_wrap(d, FRAG_T, output); /* t:X is and_v(X,1) */
        else {
            subs[0] = *output;
            subs[1] = d->items[i].node;
            ret = node_make(d, FRAG_AND_V, subs, 2, output);
        }
    }
    d->num_items = base;
    --d->num_scopes;
    return ret;
}

/* Find the key with a given HASH160 */
static int lookup_key(ms_decoder *d, const unsigned char *hash, uint32_t *index)
{
    const struct wally_map_item *item;
    const size_t num_keys = d->keys ? d->keys->num_items : 0;
    size_t i;
    int ret = WALLY_OK;

    if (!d->key_hashes && num_keys) {
        /* Calculate the key hashes the first time they are needed */
        if (!(d->key_hashes = wally_malloc(num_keys * HASH160_LEN)))
            return WALLY_ENOMEM;
        for (i = 0; ret == WALLY_OK && i < num_keys; ++i) {
            item = d->keys->items + i;
            if (item->key && item->key_len == d->key_len)
                ret = wally_hash160(item->key, item->key_len,
                                    d->key_hashes + i * HASH160_LEN, HASH160_LEN);
        }
        if (ret != WALLY_OK)
            return ret;
    }
    for (i = 0; i < num_keys; ++i) {
        item = d->keys->items + i;
        if (item->key && item->key_len == d->key_len &&
            !memcmp(hash, d->key_hashes + i * HASH160_LEN, HASH160_LEN)) {
            *index = (uint32_t)i;
            return WALLY_OK;
        }
    }
    return WALLY_EINVAL; /* Key not found */
}

/* multi(k,key1,...,keyn): <k> <key1> ... <keyn> <n> OP_CHECKMULTISIG */
static int decode_multi(ms_decoder *d, script_iter *si, int64_t k, bool *matched)
{
    script_iter s = *si;
    size_t num_keys = 0;
    int64_t n;
    int ret;

    *matched = false;
    for (;;) {
        if (!si_next(&s))
            return WALLY_OK; /* Not a multi */
        if (s.opcode != d->key_len)
            break; /* Not a key push */
        if (++num_keys > MULTI_MAX_KEYS)
            return WALLY_OK; /* Not a multi */
    }
    if (!si_get_number(&s, &n) || !si_next(&s) ||
        (s.opcode != OP_CHECKMULTISIG && s.opcode != OP_CHECKMULTISIGVERIFY))
        return WALLY_OK; /* Not a multi */

    *matched = true;
    if (n != (int64_t)num_keys || !num_keys || k < 1 || k > n)
        return WALLY_EINVAL;
    ret = item_push_new(d, FRAG_MULTI, (uint32_t)k, si->next);
    if (ret == WALLY_OK && s.opcode == OP_CHECKMULTISIGVERIFY)
        ret = item_wrap(d, FRAG_V);
    *si = s;
    return ret;
}

/* multi_a(k,key1,...,keyn):
 * <key1> OP_CHECKSIG <key2> OP_CHECKSIGADD ... <keyn> OP_CHECKSIGADD <k> OP_NUMEQUAL
 */
static int decode_multi_a(ms_decoder *d, script_iter *si, bool *matched)
{
    script_iter s = *si;
    size_t num_keys = 1;
    int64_t k;
    int ret;

    *matched = false;
    if (!si_next(&s) || s.opcode != OP_CHECKSIG)
        return WALLY_OK; /* Not a multi_a */
    for (;;) {
        if (!si_next(&s))
            return WALLY_OK; /* Not a multi_a */
        if (s.opcode != d->key_len)
            break; /* Not a key push */
        if (!si_next(&s) || s.opcode != OP_CHECKSIGADD)
            return WALLY_OK; /* Not a multi_a */
        ++num_keys;
    }
    if (!si_get_number(&s, &k) || !si_next(&s) ||
        (s.opcode != OP_NUMEQUAL && s.opcode != OP_NUMEQUALVERIFY))
        return WALLY_OK; /* Not a multi_a */

    *matched = true;
    if (num_keys > MULTI_A_MAX_KEYS || k < 1 || k > (int64_t)num_keys)
        return WALLY_EINVAL;
    ret = item_push_new(d, FRAG_MULTI_A, (uint32_t)k, si->next - 1 - d->key_len);
    if (ret == WALLY_OK && s.opcode == OP_NUMEQUALVERIFY)
        ret = item_wrap(d, FRAG_V);
    *si = s;
    return ret;
}

/* Complete a thresh: X1 X2 OP_ADD ... Xn OP_ADD <k> OP_EQUAL */
static int decode_thresh(ms_decoder *d, int64_t k, bool verify)
{
    ms_ditem *item = item_last(d);
    uint32_t sub, count = 1;
    int ret = WALLY_OK;

    if (!item || item->kind == ITEM_W)
        return WALLY_EINVAL;
    if (item->kind == ITEM_THRESH)
        count = item->count;
    else {
        /* A thresh with a single sub-expression */
        sub = item->node;
        ret = node_make(d, FRAG_THRESH, &sub, 1, &item->node);
    }
    if (ret == WALLY_OK && (k < 1 || k > count))
        ret = WALLY_EINVAL;
    if (ret == WALLY_OK) {
        d->nodes[item->node].value = (uint32_t)k;
        item->kind = ITEM_EXPR;
        if (verify)
            ret = item_wrap(d, FRAG_V);
    }
    return ret;
}

/* A number: older, after, multi, the end of a thresh, or 0/1 */
static int decode_number(ms_decoder *d, script_iter *si, int64_t v)
{
    script_iter next = *si;
    bool matched;
    int ret;

    if (si_next(&next)) {
        switch (next.opcode) {
        case OP_CHECKSEQUENCEVERIFY:
        case OP_CHECKLOCKTIMEVERIFY:
            /* older(n): <n> OP_CHECKSEQUENCEVERIFY
             * after(n): <n> OP_CHECKLOCKTIMEVERIFY */
            if (v < 1 || v > LOCKTIME_MAX)
                return WALLY_EINVAL;
            if (next.opcode == OP_CHECKSEQUENCEVERIFY &&
                (v & ~SEQ_LOCKTIME_TYPE_FLAG) > SEQ_LOCKTIME_MASK)
                return WALLY_EINVAL; /* Lock value beyond 16 bits */
            *si = next;
            return item_push_new(d, next.opcode == OP_CHECKSEQUENCEVERIFY ?
                                 FRAG_OLDER : FRAG_AFTER, (uint32_t)v, 0);
        case OP_EQUAL:
        case OP_EQUALVERIFY:
            *si = next;
            return decode_thresh(d, v, next.opcode == OP_EQUALVERIFY);
        }
        if (!d->is_tapscript) {
            ret = decode_multi(d, si, v, &matched);
            if (ret != WALLY_OK || matched)
                return ret;
        }
    }
    if (si->opcode == OP_0 || si->opcode == OP_1)
        return item_push_new(d, si->opcode == OP_0 ? FRAG_JUST_0 : FRAG_JUST_1, 0, 0);
    return WALLY_EINVAL;
}

/* pk_k(key): <key>, or multi_a */
static int decode_key(ms_decoder *d, script_iter *si)
{
    bool matched;
    int ret;

    if (d->is_tapscript) {
        ret = decode_multi_a(d, si, &matched);
        if (ret != WALLY_OK || matched)
            return ret;
    }
    return item_push_new(d, FRAG_PK_K, 0, si->data - d->script);
}

static int decode_dup(ms_decoder *d, script_iter *si)
{
    static const uint32_t pk_h[] = {
        OP_DUP, OP_HASH160, SI_PUSH, HASH160_LEN, OP_EQUALVERIFY
    };
    static const uint32_t dup_if[] = { OP_DUP, OP_IF };
    script_iter matched[4];
    uint32_t key_index;
    int ret;

    if (si_match(si, pk_h, NUM_ELEMS(pk_h), matched)) {
        /* pk_h(key): OP_DUP OP_HASH160 <HASH160(key)> OP_EQUALVERIFY */
        ret = lookup_key(d, matched[2].data, &key_index);
        return ret == WALLY_OK ? item_push_new(d, FRAG_PK_H, key_index, 0) : ret;
    }
    if (si_match(si, dup_if, NUM_ELEMS(dup_if), NULL))
        return scope_open(d, SCOPE_D, NO_NODE, NO_NODE);
    return WALLY_EINVAL;
}

static int decode_size(ms_decoder *d, script_iter *si)
{
    static const uint32_t size_if[] = { OP_SIZE, OP_0NOTEQUAL, OP_IF };
    uint32_t hash[] = {
        OP_SIZE, SI_NUMBER, SHA256_LEN, SHA256_LEN, OP_EQUALVERIFY, 0, SI_PUSH, 0
    };
    script_iter matched[5], next;
    size_t i;
    int ret;

    if (si_match(si, size_if, NUM_ELEMS(size_if), NULL))
        return scope_open(d, SCOPE_J, NO_NODE, NO_NODE);

    /* sha256(h): OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <h> OP_EQUAL
     * (and similarly for hash256, ripemd160 and hash160) */
    for (i = 0; i < NUM_ELEMS(g_hashes); ++i) {
        hash[5] = g_hashes[i].opcode;
        hash[7] = g_hashes[i].len;
        if (si_match(si, hash, NUM_ELEMS(hash), matched)) {
            next = *si;
            if (!si_next(&next) ||
                (next.opcode != OP_EQUAL && next.opcode != OP_EQUALVERIFY))
                return WALLY_EINVAL;
            *si = next;
            ret = item_push_new(d, g_hashes[i].frag, 0, matched[4].data - d->script);
            if (ret == WALLY_OK && next.opcode == OP_EQUALVERIFY)
                ret = item_wrap(d, FRAG_V);
            return ret;
        }
    }
    return WALLY_EINVAL;
}

/* or_c(X,Z): X OP_NOTIF Z OP_ENDIF
 * or_d(X,Z): X OP_IFDUP OP_NOTIF Z OP_ENDIF
 * andor(X,Y,Z): X OP_NOTIF Z OP_ELSE Y OP_ENDIF
 */
static int decode_notif(ms_decoder *d, unsigned char kind)
{
    uint32_t x;
    int ret = item_pop(d, &x);
    return ret == WALLY_OK ? scope_open(d, kind, x, NO_NODE) : ret;
}

static int decode_else(ms_decoder *d)
{
    const unsigned char kind = scope_current(d)->kind;
    const uint32_t x = scope_current(d)->x;
    uint32_t branch;
    int ret;

    if (kind != SCOPE_OR_I && kind != SCOPE_NOTIF)
        return WALLY_EINVAL;
    ret = scope_close(d, &branch);
    if (ret == WALLY_OK) {
        if (kind == SCOPE_OR_I)
            ret = scope_open(d, SCOPE_OR_I_Z, branch, NO_NODE);
        else
            ret = scope_open(d, SCOPE_ANDOR, x, branch);
    }
    return ret;
}

static int decode_endif(ms_decoder *d)
{
    const unsigned char kind = scope_current(d)->kind;
    uint32_t subs[3], node;
    int ret;

    subs[0] = scope_current(d)->x;
    subs[2] = scope_current(d)->z;
    if (kind == SCOPE_TOP || kind == SCOPE_OR_I ||
        kind == SCOPE_A || kind == SCOPE_S)
        return WALLY_EINVAL;
    ret = scope_close(d, &subs[1]);
    if (ret != WALLY_OK)
        return ret;

    switch (kind) {
    case SCOPE_OR_I_Z:
        /* or_i(X,Z): OP_IF X OP_ELSE Z OP_ENDIF */
        if (node_is(d, subs[0], FRAG_JUST_0))
            ret = node_make(d, FRAG_L, subs + 1, 1, &node); /* l:X is or_i(0,X) */
        else if (node_is(d, subs[1], FRAG_JUST_0))
            ret = node_make(d, FRAG_U, subs, 1, &node); /* u:X is or_i(X,0) */
        else
            ret = node_make(d, FRAG_OR_I, subs, 2, &node);
        break;
    case SCOPE_NOTIF:
        ret = node_make(d, FRAG_OR_C, subs, 2, &node);
        break;
    case SCOPE_OR_D:
        ret = node_make(d, FRAG_OR_D, subs, 2, &node);
        break;
    case SCOPE_ANDOR:
        if (node_is(d, subs[2], FRAG_JUST_0))
            ret = node_make(d, FRAG_AND_N, subs, 2, &node); /* and_n(X,Y) is andor(X,Y,0) */
        else
            ret = node_make(d, FRAG_ANDOR, subs, 3, &node);
        break;
    case SCOPE_D:
        /* d:X: OP_DUP OP_IF X OP_ENDIF */
        ret = node_make(d, FRAG_D, subs + 1, 1, &node);
        break;
    default:
        /* j:X: OP_SIZE OP_0NOTEQUAL OP_IF X OP_ENDIF */
        ret = node_make(d, FRAG_J, subs + 1, 1, &node);
        break;
    }
    return ret == WALLY_OK ? item_push(d, node, ITEM_EXPR) : ret;
}

/* a:X: OP_TOALTSTACK X OP_FROMALTSTACK */
static int decode_fromaltstack(ms_decoder *d)
{
    uint32_t node;
    int ret = WALLY_EINVAL;

    if (scope_current(d)->kind == SCOPE_A)
        ret = scope_close(d, &node);
    if (ret == WALLY_OK)
        ret = node_wrap(d, FRAG_A, &node);
    return ret == WALLY_OK ? item_push(d, node, ITEM_W) : ret;
}

/* Add a W expression to an incomplete thresh */
static int thresh_add(ms_decoder *d, ms_ditem *item, uint32_t w)
{
    ms_dnode *thresh = d->nodes + item->node, *sub = d->nodes + w;

    d->nodes[item->last].next = w;
    sub->parent = item->node;
    item->last = w;
    ++item->count;
    if (sub->depth + 1 > thresh->depth)
        thresh->depth = sub->depth + 1;
    return thresh->depth > MS_DECODE_MAX_DEPTH ? WALLY_EINVAL : WALLY_OK;
}

/* and_b(X,Y): X Y OP_BOOLAND
 * or_b(X,Z): X Z OP_BOOLOR
 * thresh(k,X1,...,Xn): X1 X2 OP_ADD ... Xn OP_ADD <k> OP_EQUAL
 * Where Y, Z and X2 to Xn are W expressions.
 */
static int decode_combine(ms_decoder *d, unsigned char opcode)
{
    ms_ditem *item = item_last(d);
    uint32_t subs[2];
    int ret = WALLY_OK;

    if (item && item->kind == ITEM_W) {
        subs[1] = item->node; /* a:X */
        --d->num_items;
    } else if (scope_current(d)->kind == SCOPE_S) {
        ret = scope_close(d, &subs[1]); /* s:X */
        if (ret == WALLY_OK)
            ret = node_wrap(d, FRAG_S, &subs[1]);
    } else
        ret = WALLY_EINVAL; /* No W expression */

    if (ret == WALLY_OK && !(item = item_last(d)))
        ret = WALLY_EINVAL;
    if (ret != WALLY_OK)
        return ret;
    if (opcode == OP_ADD && item->kind == ITEM_THRESH)
        return thresh_add(d, item, subs[1]);
    if (item->kind != ITEM_EXPR)
        return WALLY_EINVAL;
    subs[0] = item->node;
    if (opcode == OP_BOOLAND)
        return node_make(d, FRAG_AND_B, subs, 2, &item->node);
    if (opcode == OP_BOOLOR)
        return node_make(d, FRAG_OR_B, subs, 2, &item->node);
    ret = node_make(d, FRAG_THRESH, subs, 2, &item->node);
    item->kind = ITEM_THRESH;
    item->last = subs[1];
    item->count = 2;
    return ret;
}

static int decode_opcode(ms_decoder *d, script_iter *si)
{
    static const uint32_t ifdup_notif[] = { OP_IFDUP, OP_NOTIF };
    int64_t v;
    int ret;

    if (si_is_push(si) && !si_is_minimal_push(si))
        return WALLY_EINVAL;
    if (si_is_push(si) || (si->opcode >= OP_1 && si->opcode <= OP_16)) {
        if (si_get_number(si, &v))
            return decode_number(d, si, v);
        if (si->data_len == d->key_len)
            return decode_key(d, si);
        return WALLY_EINVAL;
    }

    switch (si->opcode) {
    case OP_DUP:
        return decode_dup(d, si);
    case OP_SIZE:
        return decode_size(d, si);
    case OP_IF:
        return scope_open(d, SCOPE_OR_I, NO_NODE, NO_NODE);
    case OP_NOTIF:
        return decode_notif(d, SCOPE_NOTIF);
    case OP_IFDUP:
        if (!si_match(si, ifdup_notif, NUM_ELEMS(ifdup_notif), NULL))
            return WALLY_EINVAL;
        return decode_notif(d, SCOPE_OR_D);
    case OP_ELSE:
        return decode_else(d);
    case OP_ENDIF:
        return decode_endif(d);
    case OP_TOALTSTACK:
        return scope_open(d, SCOPE_A, NO_NODE, NO_NODE);
    case OP_FROMALTSTACK:
        return decode_fromaltstack(d);
    case OP_SWAP:
        return scope_open(d, SCOPE_S, NO_NODE, NO_NODE);
    case OP_CHECKSIG:
        return item_wrap(d, FRAG_C);
    case OP_CHECKSIGVERIFY:
        ret = item_wrap(d, FRAG_C);
        return ret == WALLY_OK ? item_wrap(d, FRAG_V) : ret;
    case OP_VERIFY:
        return item_wrap(d, FRAG_V);
    case OP_0NOTEQUAL:
        return item_wrap(d, FRAG_N);
    case OP_BOOLAND:
    case OP_BOOLOR:
    case OP_ADD:
        return decode_combine(d, si->opcode);
    }
    return WALLY_EINVAL;
}

static int decode_script(ms_decoder *d, uint32_t *root)
{
    script_iter si;
    unsigned char prev_opcode = OP_INVALIDOPCODE;
    int ret = scope_open(d, SCOPE_TOP, NO_NODE, NO_NODE);

    si_init(&si, d->script, d->script_len);
    while (ret == WALLY_OK && si_next(&si)) {
        if (si.opcode == OP_VERIFY &&
            (prev_opcode == OP_CHECKSIG || prev_opcode == OP_CHECKMULTISIG ||
             prev_opcode == OP_EQUAL || prev_opcode == OP_NUMEQUAL))
            ret = WALLY_EINVAL; /* Should use OP_CHECKSIGVERIFY etc */
        else
            ret = decode_opcode(d, &si);
        prev_opcode = si.opcode;
    }
    if (ret == WALLY_OK && (si_is_error(&si) || d->num_scopes != 1))
        ret = WALLY_EINVAL; /* Malformed script, or unterminated expression */
    if (ret == WALLY_OK)
        ret = scope_close(d, root);
    return ret;
}

typedef struct ms_writer {
    char *buf; /* Output buffer, or NULL to calculate the output length */
    size_t len;
    size_t written;
} ms_writer;

static void put(ms_writer *w, const char *str, size_t len)
{
    if (w->buf && w->written <= w->len && len <= w->len - w->written)
        memcpy(w->buf + w->written, str, len);
    w->written += len;
}

static void put_hex(ms_writer *w, const unsigned char *bytes, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    char c[2];
    size_t i;

    for (i = 0; i < len; ++i) {
        c[0] = hex[bytes[i] >> 4];
        c[1] = hex[bytes[i] & 0xf];
        put(w, c, 2);
    }
}

static void put_number(ms_writer *w, uint32_t v)
{
    char buf[10];
    size_t i = sizeof(buf);

    do {
        buf[--i] = '0' + v % 10;
        v /= 10;
    } while (v);
    put(w, buf + i, sizeof(buf) - i);
}

/* Write an expression, up to its first sub-expression (if it has any) */
static void put_node(const ms_decoder *d, ms_writer *w, uint32_t index)
{
    const ms_dnode *node = d->nodes + index;
    const char *name = g_frag_names[node->frag];
    const struct wally_map_item *key;
    script_iter si;

    if (node->parent != NO_NODE && !IS_WRAPPER(node->frag) &&
        IS_WRAPPER(d->nodes[node->parent].frag))
        put(w, ":", 1); /* End of the wrappers */
    put(w, name, strlen(name));

    switch (node->frag) {
    case FRAG_JUST_0:
    case FRAG_JUST_1:
        return;
    case FRAG_PK_K:
    case FRAG_PK:
        put(w, "(", 1);
        put_hex(w, d->script + node->offset, d->key_len);
        break;
    case FRAG_PK_H:
    case FRAG_PKH:
        key = d->keys->items + node->value;
        put(w, "(", 1);
        put_hex(w, key->key, key->key_len);
        break;
    case FRAG_OLDER:
    case FRAG_AFTER:
        put(w, "(", 1);
        put_number(w, node->value);
        break;
    case FRAG_SHA256:
    case FRAG_HASH256:
        put(w, "(", 1);
        put_hex(w, d->script + node->offset, SHA256_LEN);
        break;
    case FRAG_RIPEMD160:
    case FRAG_HASH160:
        put(w, "(", 1);
        put_hex(w, d->script + node->offset, HASH160_LEN);
        break;
    case FRAG_MULTI:
    case FRAG_MULTI_A:
        put(w, "(", 1);
        put_number(w, node->value);
        si_init(&si, d->script + node->offset, d->script_len - node->offset);
        while (si_next(&si) && si.opcode == d->key_len) {
            put(w, ",", 1);
            put_hex(w, si.data, si.data_len);
            if (node->frag == FRAG_MULTI_A)
                si_next(&si); /* Skip OP_CHECKSIG/OP_CHECKSIGADD */
        }
        break;
    case FRAG_THRESH:
        put(w, "(", 1);
        put_number(w, node->value);
        put(w, ",", 1);
        return;
    default:
        if (!IS_WRAPPER(node->frag))
            put(w, "(", 1);
        return;
    }
    put(w, ")", 1);
}

/* Write an expression tree, returning the length of its text */
static size_t put_tree(const ms_decoder *d, uint32_t root, char *buf, size_t len)
{
    ms_writer w = { buf, len, 0 };
    uint32_t node = root;

    for (;;) {
        put_node(d, &w, node);
        if (d->nodes[node].child != NO_NODE) {
            node = d->nodes[node].child;
            continue;
        }
        /* Close the expressions that end here */
        while (node != root && d->nodes[node].next == NO_NODE) {
            node = d->nodes[node].parent;
            if (!IS_WRAPPER(d->nodes[node].frag))
                put(&w, ")", 1);
        }
        if (node == root)
            break;
        put(&w, ",", 1);
        node = d->nodes[node].next;
    }
    return w.written;
}

int ms_script_to_miniscript(const unsigned char *script, size_t script_len,
                            const struct wally_map *keys, uint32_t flags,
                            char **output)
{
    const bool is_tapscript = flags & WALLY_MINISCRIPT_TAPSCRIPT;
    const size_t max_len = is_tapscript ? MS_DECODE_MAX_SCRIPT_LEN_TAPSCRIPT :
                                          MS_DECODE_MAX_SCRIPT_LEN_SEGWIT_V0;
    ms_decoder d;
    uint32_t root;
    size_t len;
    int ret;

    if (output)
        *output = NULL;
    if (!script || !script_len || script_len > max_len ||
        (flags & ~WALLY_MINISCRIPT_TAPSCRIPT) || !output)
        return WALLY_EINVAL;

    memset(&d, 0, sizeof(d));
    d.script = script;
    d.script_len = script_len;
    d.key_len = is_tapscript ? EC_XONLY_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_LEN;
    d.is_tapscript = is_tapscript;
    d.keys = keys;

    ret = decode_script(&d, &root);
    if (ret == WALLY_OK) {
        len = put_tree(&d, root, NULL, 0);
        if (!(*output = wally_malloc(len + 1)))
            ret = WALLY_ENOMEM;
        else if (put_tree(&d, root, *output, len) != len) {
            wally_free(*output);
            *output = NULL;
            ret = WALLY_ERROR; /* Should not happen */
        } else
            (*output)[len] = '\0';
    }
    if (d.nodes)
        wally_free(d.nodes);
    if (d.items)
        wally_free(d.items);
    if (d.scopes)
        wally_free(d.scopes);
    if (d.key_hashes)
        wally_free(d.key_hashes);
    return ret;
}

int ms_descriptor_from_script(const unsigned char *script, size_t script_len,
                              const struct wally_map *keys, uint32_t flags,
                              struct wally_descriptor **output)
{
    /* The script already exists, so decode it even if it is not sane */
    const uint32_t parse_flags = WALLY_MINISCRIPT_ONLY | WALLY_MINISCRIPT_ALLOW_NON_SANE |
                                 flags | (MS_DECODE_MAX_DEPTH << WALLY_MINISCRIPT_DEPTH_SHIFT);
    unsigned char *generated = NULL;
    char *text = NULL;
    size_t written;
    int ret;

    if (output)
        *output = NULL;
    if (!output)
        return WALLY_EINVAL;

    ret = ms_script_to_miniscript(script, script_len, keys, flags, &text);
    if (ret == WALLY_OK) {
        ret = wally_descriptor_parse(text, NULL, WALLY_NETWORK_NONE,
                                     parse_flags, output);
        wally_free_string(text);
    }
    if (ret == WALLY_OK &&
        ((*output)->top_node->type_properties & TYPE_MASK) != TYPE_B)
        ret = WALLY_EINVAL; /* Not a valid top level expression */
    if (ret == WALLY_OK && !(generated = wally_malloc(script_len)))
        ret = WALLY_ENOMEM;
    if (ret == WALLY_OK)
        ret = wally_descriptor_to_script(*output, 0, 0, 0, 0, 0, 0,
                                         generated, script_len, &written);
    if (ret == WALLY_OK &&
        (written != script_len || memcmp(generated, script, script_len)))
        ret = WALLY_EINVAL; /* Does not generate the decoded script */
    if (generated)
        wally_free(generated);
    if (ret != WALLY_OK) {
        wally_descriptor_free(*output);
        *output = NULL;
    }
    return ret;
}
