#include "config.h"
#include "internal.h"
#include "miniscript_satisfy.h"
#include <include/wally_crypto.h>
#include <stdint.h>

/* Witness item constants: a single 0x01 byte (true/IF branch selector)
 * and a 32-byte all-zero value (hash dissatisfaction). */
static const unsigned char push_1[] = {0x01};
static const unsigned char zero32[32] = {0};

/* Securely clear memory that may hold signatures, preimages or keys.
 * Uses the public wally_bzero (a non-elidable clear) rather than the
 * internal wally_clear so that this file can also be compiled into
 * test binaries that only link the public API. */
static void ms_clear(void *p, size_t len)
{
    if (p)
        wally_bzero(p, len);
}

static void ms_witness_init(ms_witness *w, uint32_t kind)
{
    memset(w, 0, sizeof(*w));
    w->kind = kind;
}

static void ms_witness_free(ms_witness *w)
{
    if (w) {
        for (size_t i = 0; i < w->num_items; i++) {
            /* Witness data can hold signatures/preimages: clear before freeing */
            ms_clear(w->items[i].data, w->items[i].data_len);
            wally_free(w->items[i].data);
        }
        wally_free(w->items);
        ms_clear(w, sizeof(*w));
    }
}

static void ms_satisfaction_init(ms_satisfaction *s, uint32_t witness_kind)
{
    ms_witness_init(&s->witness, witness_kind);
    s->has_sig = false;
    s->absolute_timelock = 0;
    s->relative_timelock = 0;
}

void ms_satisfaction_free(ms_satisfaction *s)
{
    if (s) {
        ms_witness_free(&s->witness);
        ms_clear(s, sizeof(*s));
    }
}

/* Whether a satisfaction failed to allocate, and so has no result. Results
 * computed from it must also fail, rather than e.g. treating it as impossible
 * and choosing a different (valid, but not the best) satisfaction instead. */
#define IS_OOM(s) ((s).witness.kind == MS_WITNESS_OOM)

/* Free a and b, returning an allocation failure. Consumes a and b. */
static ms_satisfaction satisfaction_oom(ms_satisfaction *a, ms_satisfaction *b)
{
    ms_satisfaction result;
    ms_satisfaction_free(a);
    ms_satisfaction_free(b);
    ms_satisfaction_init(&result, MS_WITNESS_OOM);
    return result;
}

static size_t witness_weight(const ms_witness *w)
{
    if (w->kind != MS_WITNESS_STACK)
        return SIZE_MAX;
    size_t total = 0;
    for (size_t i = 0; i < w->num_items; i++) {
        size_t item = w->items[i].data_len;
        /* Saturate at SIZE_MAX-1 so SIZE_MAX stays the non-stack sentinel. */
        if (item >= SIZE_MAX - 1 || total >= SIZE_MAX - 1 - item)
            return SIZE_MAX - 1;
        total += item + 1;
    }
    return total;
}

/* Weight delta (sat - dissat) for sorting thresh candidates.
 * Returns INT64_MAX when sat is unavailable/impossible (avoid choosing).
 * Returns INT64_MIN when dissat is unavailable/impossible (prefer choosing). */
static int64_t thresh_weight_delta(const ms_satisfaction *sat, const ms_satisfaction *dsat)
{
    if (sat->witness.kind == MS_WITNESS_IMPOSSIBLE ||
        sat->witness.kind == MS_WITNESS_UNAVAILABLE)
        return INT64_MAX;
    if (dsat->witness.kind == MS_WITNESS_IMPOSSIBLE ||
        dsat->witness.kind == MS_WITNESS_UNAVAILABLE)
        return INT64_MIN;
    return (int64_t)witness_weight(&sat->witness) -
           (int64_t)witness_weight(&dsat->witness);
}

/* Precomputed sort key for a single thresh element. The key depends only on
 * the element, so it can be computed once instead of in the O(n^2) sort. */
struct thresh_key {
    int imp;        /* sat is impossible (sorts last) */
    int has_sig;    /* sat carries a signature (sorts after sig-less) */
    int64_t delta;  /* weight(sat) - weight(dissat) */
};

static struct thresh_key thresh_make_key(const ms_satisfaction *sat,
                                         const ms_satisfaction *dissat)
{
    struct thresh_key k;
    k.imp = sat->witness.kind == MS_WITNESS_IMPOSSIBLE ? 1 : 0;
    k.has_sig = sat->has_sig ? 1 : 0;
    k.delta = thresh_weight_delta(sat, dissat);
    return k;
}

/* Non-malleable order: (is_impossible, has_sig, weight_delta) ascending */
static int thresh_cmp_full(const struct thresh_key *a, const struct thresh_key *b)
{
    if (a->imp != b->imp) return a->imp - b->imp;
    if (a->has_sig != b->has_sig) return a->has_sig - b->has_sig;
    return (a->delta > b->delta) - (a->delta < b->delta);
}

/* Malleable order: weight_delta only */
static int thresh_cmp_mall(const struct thresh_key *a, const struct thresh_key *b)
{
    return (a->delta > b->delta) - (a->delta < b->delta);
}

/* Insertion sort on index array (ascending).
 *
 * Each element's sort key is computed once up front (O(n) weight passes)
 * rather than re-derived for every comparison (O(n^2) weight passes). On OOM
 * the key array is left NULL and the keys are computed on demand instead. */
static void thresh_sort(size_t *indices, size_t n,
                        const ms_satisfaction *sats,
                        const ms_satisfaction *dissats, int mall)
{
    struct thresh_key *keys = n ? wally_malloc(n * sizeof(*keys)) : NULL;

    for (size_t i = 0; keys && i < n; i++)
        keys[i] = thresh_make_key(&sats[i], &dissats[i]);

    for (size_t i = 1; i < n; i++) {
        size_t key = indices[i];
        size_t j = i;
        while (j > 0) {
            struct thresh_key ka, kb;
            const struct thresh_key *pa, *pb;
            if (keys) {
                pa = &keys[indices[j - 1]];
                pb = &keys[key];
            } else {
                ka = thresh_make_key(&sats[indices[j - 1]], &dissats[indices[j - 1]]);
                kb = thresh_make_key(&sats[key], &dissats[key]);
                pa = &ka;
                pb = &kb;
            }
            if ((mall ? thresh_cmp_mall(pa, pb) : thresh_cmp_full(pa, pb)) <= 0)
                break;
            indices[j] = indices[j - 1];
            j--;
        }
        indices[j] = key;
    }
    wally_free(keys);
}

/*
 * Select the non-malleable minimum-weight satisfaction between a and b.
 * Both a and b are consumed by this call; the caller must not use them
 * afterwards. The caller owns the returned ms_satisfaction and must free
 * it with ms_satisfaction_free() when done.
 */
static ms_satisfaction satisfaction_best(ms_satisfaction a, ms_satisfaction b)
{
    ms_satisfaction result;

    if (IS_OOM(a) || IS_OOM(b))
        return satisfaction_oom(&a, &b);

    /* Impossible short-circuits: if one side is impossible, take the other */
    if (a.witness.kind == MS_WITNESS_IMPOSSIBLE)
        return b;
    if (b.witness.kind == MS_WITNESS_IMPOSSIBLE)
        return a;

    /* Neither has a sig: malleability vector, return unavailable */
    if (!a.has_sig && !b.has_sig) {
        ms_satisfaction_free(&a);
        ms_satisfaction_free(&b);
        ms_satisfaction_init(&result, MS_WITNESS_UNAVAILABLE);
        return result;
    }

    /* Only b has a sig: third party can't malleate a (no sig to remove) */
    if (!a.has_sig) {
        ms_satisfaction_free(&b);
        return a;
    }

    /* Only a has a sig: take b */
    if (!b.has_sig) {
        ms_satisfaction_free(&a);
        return b;
    }

    /* Both have sigs: choose the lighter witness */
    if (witness_weight(&a.witness) <= witness_weight(&b.witness)) {
        ms_satisfaction_free(&b);
        return a;
    }
    ms_satisfaction_free(&a);
    return b;
}

/* Clone a satisfaction, deep-copying witness item data. On OOM returns OOM. */
static ms_satisfaction ms_satisfaction_clone(const ms_satisfaction *src)
{
    ms_satisfaction result;
    ms_satisfaction_init(&result, src->witness.kind);
    result.has_sig = src->has_sig;
    result.absolute_timelock = src->absolute_timelock;
    result.relative_timelock = src->relative_timelock;

    if (src->witness.kind != MS_WITNESS_STACK || !src->witness.num_items)
        return result;

    result.witness.items = wally_malloc(src->witness.num_items * sizeof(ms_witness_item));
    if (!result.witness.items) {
        result.witness.kind = MS_WITNESS_OOM;
        return result;
    }
    result.witness.items_allocation_len = src->witness.num_items;

    for (size_t i = 0; i < src->witness.num_items; i++) {
        const ms_witness_item *si = &src->witness.items[i];
        unsigned char *data = NULL;
        if (si->data_len) {
            data = wally_malloc(si->data_len);
            if (!data) {
                ms_satisfaction_free(&result);
                ms_satisfaction_init(&result, MS_WITNESS_OOM);
                return result;
            }
            memcpy(data, si->data, si->data_len);
        }
        result.witness.items[i].data = data;
        result.witness.items[i].data_len = si->data_len;
        result.witness.num_items++;
    }
    return result;
}

/*
 * Concatenate two satisfactions: result has a's items followed by b's items.
 * Consumes a and b. On OOM returns OOM.
 *
 * Mirrors rust-miniscript Witness::combine(b.stack, a.stack) called as
 * a.concatenate_rev(b) - the caller must pass args in (right, left) order
 * when building a witness where right-fragment items precede left-fragment
 * items (the common case for binary fragments).
 */
static ms_satisfaction satisfaction_concat(ms_satisfaction a, ms_satisfaction b)
{
    bool b_has_sig;
    uint32_t b_abs, b_rel;
    size_t new_count;
    ms_witness_item *new_items;

    if (IS_OOM(a) || IS_OOM(b))
        return satisfaction_oom(&a, &b);
    if (a.witness.kind == MS_WITNESS_IMPOSSIBLE) {
        ms_satisfaction_free(&b);
        return a;
    }
    if (b.witness.kind == MS_WITNESS_IMPOSSIBLE) {
        ms_satisfaction_free(&a);
        return b;
    }
    if (a.witness.kind == MS_WITNESS_UNAVAILABLE) {
        ms_satisfaction_free(&b);
        return a;
    }
    if (b.witness.kind == MS_WITNESS_UNAVAILABLE) {
        ms_satisfaction_free(&a);
        return b;
    }

    /* Save b's scalar fields before it is freed */
    b_has_sig = b.has_sig;
    b_abs = b.absolute_timelock;
    b_rel = b.relative_timelock;

    new_count = a.witness.num_items + b.witness.num_items;

    if (new_count > a.witness.items_allocation_len) {
        new_items = wally_malloc(new_count * sizeof(ms_witness_item));
        if (!new_items)
            return satisfaction_oom(&a, &b);
        if (a.witness.num_items)
            memcpy(new_items, a.witness.items, a.witness.num_items * sizeof(ms_witness_item));
        wally_free(a.witness.items);
        a.witness.items = new_items;
        a.witness.items_allocation_len = new_count;
    }

    /* Transfer ownership of b's item data pointers into a */
    for (size_t i = 0; i < b.witness.num_items; i++)
        a.witness.items[a.witness.num_items + i] = b.witness.items[i];
    a.witness.num_items = new_count;

    /* Prevent double-free: item data is now owned by a */
    b.witness.num_items = 0;
    ms_satisfaction_free(&b);

    a.has_sig |= b_has_sig;
    if (b_abs > a.absolute_timelock)
        a.absolute_timelock = b_abs;
    if (b_rel > a.relative_timelock)
        a.relative_timelock = b_rel;

    return a;
}

/*
 * Malleable minimum: pick the cheaper satisfaction without enforcing
 * non-malleability. Consumes a and b.
 *
 * Mirrors rust-miniscript Satisfaction::minimum_mall.
 */
static ms_satisfaction satisfaction_minimum_mall(ms_satisfaction a, ms_satisfaction b)
{
    bool has_sig;

    if (IS_OOM(a) || IS_OOM(b))
        return satisfaction_oom(&a, &b);
    if (a.witness.kind == MS_WITNESS_IMPOSSIBLE || a.witness.kind == MS_WITNESS_UNAVAILABLE) {
        ms_satisfaction_free(&a);
        return b;
    }
    if (b.witness.kind == MS_WITNESS_IMPOSSIBLE || b.witness.kind == MS_WITNESS_UNAVAILABLE) {
        ms_satisfaction_free(&b);
        return a;
    }

    /* Both are stacks: take the lighter; has_sig only if both carry a sig */
    has_sig = a.has_sig && b.has_sig;

    if (witness_weight(&a.witness) <= witness_weight(&b.witness)) {
        ms_satisfaction_free(&b);
        a.has_sig = has_sig;
        return a;
    }
    ms_satisfaction_free(&a);
    b.has_sig = has_sig;
    return b;
}

/*
 * Append a single push item to a satisfaction's witness stack, taking
 * ownership of `data` (no copy). data == NULL / data_len == 0 pushes an
 * empty item. Consumes s and `data`; on OOM frees `data` and returns OOM.
 */
static ms_satisfaction satisfaction_push_item_take(ms_satisfaction s,
                                                   unsigned char *data,
                                                   size_t data_len)
{
    size_t n;
    ms_witness_item *new_items;

    if (s.witness.kind != MS_WITNESS_STACK) {
        ms_clear(data, data_len);
        wally_free(data);
        return s;
    }

    n = s.witness.num_items;

    if (n + 1 > s.witness.items_allocation_len) {
        /* Grow geometrically: building a k-item stack via repeated pushes
         * is then amortized O(k) rather than O(k^2) reallocations. */
        size_t new_cap = s.witness.items_allocation_len ?
                         s.witness.items_allocation_len * 2 : 4;
        new_items = wally_malloc(new_cap * sizeof(ms_witness_item));
        if (!new_items) {
            ms_clear(data, data_len);
            wally_free(data);
            ms_satisfaction_free(&s);
            ms_satisfaction_init(&s, MS_WITNESS_OOM);
            return s;
        }
        if (n)
            memcpy(new_items, s.witness.items, n * sizeof(ms_witness_item));
        wally_free(s.witness.items);
        s.witness.items = new_items;
        s.witness.items_allocation_len = new_cap;
    }

    s.witness.items[n].data = data;
    s.witness.items[n].data_len = data_len;
    s.witness.num_items = n + 1;
    return s;
}

/*
 * Append a single push item to a satisfaction's witness stack, copying
 * `data`. data == NULL / data_len == 0 pushes an empty item (OP_0 / false).
 * Consumes s; on OOM returns OOM.
 *
 * Used by satisfaction_or_i to attach the IF/ELSE branch selector byte.
 */
static ms_satisfaction satisfaction_push_item(ms_satisfaction s,
                                              const unsigned char *data,
                                              size_t data_len)
{
    unsigned char *item_data = NULL;

    if (s.witness.kind != MS_WITNESS_STACK)
        return s;

    if (data_len) {
        item_data = wally_malloc(data_len);
        if (!item_data) {
            ms_satisfaction_free(&s);
            ms_satisfaction_init(&s, MS_WITNESS_OOM);
            return s;
        }
        memcpy(item_data, data, data_len);
    }
    return satisfaction_push_item_take(s, item_data, data_len);
}

/*
 * or_b(X, Y) satisfaction and dissatisfaction.
 *
 * Script: [X] [Y] BOOLOR
 * Witnesses (right/inner items precede left/outer in array):
 *   sat  = best( concat(r_sat, l_dis), concat(r_dis, l_sat) )
 *   dsat = concat(r_dis, l_dis)
 *
 * Mirrors rust-miniscript Terminal::OrB arm in sat_dissat.rs.
 */
static void satisfaction_or_b(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                       bool malleable)
{
    ms_satisfaction dissat_l_clone = ms_satisfaction_clone(&dissat_l);
    ms_satisfaction dissat_r_clone = ms_satisfaction_clone(&dissat_r);

    *dissat_out = satisfaction_concat(dissat_r_clone, dissat_l_clone);

    if (malleable)
        *sat_out = satisfaction_minimum_mall(
            satisfaction_concat(sat_r, dissat_l),
            satisfaction_concat(dissat_r, sat_l));
    else
        *sat_out = satisfaction_best(
            satisfaction_concat(sat_r, dissat_l),
            satisfaction_concat(dissat_r, sat_l));
}

/*
 * or_c(X, Y) satisfaction and dissatisfaction.
 *
 * Script: [X] NOTIF [Y] ENDIF
 * Witnesses:
 *   sat  = best( sat_l, concat(r_sat, l_dis) )
 *   dsat = IMPOSSIBLE (or_c has no valid dissatisfaction)
 *
 * Mirrors rust-miniscript Terminal::OrC arm in sat_dissat.rs.
 */
static void satisfaction_or_c(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                       bool malleable)
{
    ms_satisfaction_free(&dissat_r);
    ms_satisfaction_init(dissat_out, MS_WITNESS_IMPOSSIBLE);

    if (malleable)
        *sat_out = satisfaction_minimum_mall(sat_l, satisfaction_concat(sat_r, dissat_l));
    else
        *sat_out = satisfaction_best(sat_l, satisfaction_concat(sat_r, dissat_l));
}

/*
 * or_d(X, Y) satisfaction and dissatisfaction.
 *
 * Script: [X] IFDUP NOTIF [Y] ENDIF
 * Witnesses:
 *   sat  = best( sat_l, concat(r_sat, l_dis) )
 *   dsat = concat(r_dis, l_dis)
 *
 * Mirrors rust-miniscript Terminal::OrD arm in sat_dissat.rs.
 */
static void satisfaction_or_d(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                       bool malleable)
{
    ms_satisfaction dissat_l_clone = ms_satisfaction_clone(&dissat_l);

    *dissat_out = satisfaction_concat(dissat_r, dissat_l_clone);

    if (malleable)
        *sat_out = satisfaction_minimum_mall(sat_l, satisfaction_concat(sat_r, dissat_l));
    else
        *sat_out = satisfaction_best(sat_l, satisfaction_concat(sat_r, dissat_l));
}

/*
 * or_i(X, Y) satisfaction and dissatisfaction.
 *
 * Script: IF [X] ELSE [Y] ENDIF
 * The branch selector byte (0x01 = left / empty = right) is appended to the
 * sub-satisfaction and sits on top of the witness stack when the script runs.
 * Witnesses:
 *   sat  = best( sat_l ++ [0x01], sat_r ++ [] )
 *   dsat = minimum_mall( dissat_l ++ [0x01], dissat_r ++ [] )
 *
 * Mirrors rust-miniscript Terminal::OrI arm in sat_dissat.rs.
 */
static void satisfaction_or_i(ms_satisfaction sat_l, ms_satisfaction dissat_l,
                       ms_satisfaction sat_r, ms_satisfaction dissat_r,
                       ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                       bool malleable)
{
    if (malleable)
        *sat_out = satisfaction_minimum_mall(
            satisfaction_push_item(sat_l, push_1, 1),
            satisfaction_push_item(sat_r, NULL, 0));
    else
        *sat_out = satisfaction_best(
            satisfaction_push_item(sat_l, push_1, 1),
            satisfaction_push_item(sat_r, NULL, 0));

    *dissat_out = satisfaction_minimum_mall(
        satisfaction_push_item(dissat_l, push_1, 1),
        satisfaction_push_item(dissat_r, NULL, 0));
}

/*
 * andor(X, Y, Z) satisfaction and dissatisfaction.
 *
 * Script: [X] NOTIF [Z] ELSE [Y] ENDIF
 * Witnesses:
 *   sat  = best( concat(sat_y, sat_x), concat(sat_z, dissat_x) )
 *   dsat = concat(dissat_z, dissat_x)
 *
 * (inner/Y-Z items precede outer/X in array)
 *
 * dissat_y is unused: the Y branch is only reached when X is satisfied,
 * so the overall dissatisfaction always takes the Z path (dissat_x + dissat_z).
 *
 * Mirrors rust-miniscript Terminal::AndOr arm in sat_dissat.rs.
 */
static void satisfaction_andor(ms_satisfaction sat_x, ms_satisfaction dissat_x,
                        ms_satisfaction sat_y, ms_satisfaction dissat_y,
                        ms_satisfaction sat_z, ms_satisfaction dissat_z,
                        ms_satisfaction *sat_out, ms_satisfaction *dissat_out,
                        bool malleable)
{
    ms_satisfaction dissat_x_clone = ms_satisfaction_clone(&dissat_x);

    ms_satisfaction_free(&dissat_y);

    *dissat_out = satisfaction_concat(dissat_z, dissat_x_clone);

    if (malleable)
        *sat_out = satisfaction_minimum_mall(
            satisfaction_concat(sat_y, sat_x),
            satisfaction_concat(sat_z, dissat_x));
    else
        *sat_out = satisfaction_best(
            satisfaction_concat(sat_y, sat_x),
            satisfaction_concat(sat_z, dissat_x));
}

/*
 * thresh(k, X1, ..., Xn) satisfaction and dissatisfaction.
 *
 * Consumes every element in sats[] and dissats[]. When malleable is false
 * two extra checks reject choices a third party could malleate.
 * Mirrors rust-miniscript Satisfaction::thresh / Satisfaction::thresh_mall.
 */
static void satisfaction_thresh(size_t k, size_t n,
                                ms_satisfaction *sats,
                                ms_satisfaction *dissats,
                                ms_satisfaction *sat_out,
                                ms_satisfaction *dissat_out,
                                bool malleable)
{
    size_t i;

    /* 1. Compute dissat_out from clones of original dissats */
    ms_satisfaction dsat_acc;
    ms_satisfaction_init(&dsat_acc, MS_WITNESS_STACK);
    for (i = 0; i < n; i++) {
        ms_satisfaction cl = ms_satisfaction_clone(&dissats[i]);
        dsat_acc = satisfaction_concat(cl, dsat_acc);
    }
    *dissat_out = dsat_acc;

    /* 2. Build and sort index array by weight delta */
    for (i = 0; i < n; i++)
        if (IS_OOM(sats[i]) || IS_OOM(dissats[i]))
            break; /* A sub-satisfaction failed to allocate */
    size_t *indices = i == n ? wally_malloc(n * sizeof(size_t)) : NULL;
    if (!indices) {
        for (i = 0; i < n; i++) {
            ms_satisfaction_free(&sats[i]);
            ms_satisfaction_free(&dissats[i]);
        }
        ms_satisfaction_init(sat_out, MS_WITNESS_OOM);
        return;
    }
    for (i = 0; i < n; i++) indices[i] = i;
    thresh_sort(indices, n, sats, dissats, malleable ? 1 : 0);

    /* 3. Swap first k: dissats[indices[i]] gets the chosen sat */
    for (i = 0; i < k; i++) {
        ms_satisfaction tmp = dissats[indices[i]];
        dissats[indices[i]] = sats[indices[i]];
        sats[indices[i]] = tmp;
    }

    if (!malleable) {
        /* 4. Malleability check A: if k-th chosen's original dissat is Impossible,
         *    we could not find k non-impossible satisfactions - overall impossible. */
        if (sats[indices[k - 1]].witness.kind == MS_WITNESS_IMPOSSIBLE) {
            for (i = 0; i < n; i++) {
                ms_satisfaction_free(&sats[i]);
                ms_satisfaction_free(&dissats[i]);
            }
            wally_free(indices);
            ms_satisfaction_init(sat_out, MS_WITNESS_IMPOSSIBLE);
            return;
        }

        /* 5. Malleability check B: if the first unchosen element's original sat is
         *    not impossible and has no sig, a third party can malleate - unavailable. */
        if (k < n &&
            sats[indices[k]].witness.kind != MS_WITNESS_IMPOSSIBLE &&
            !sats[indices[k]].has_sig) {
            for (i = 0; i < n; i++) {
                ms_satisfaction_free(&sats[i]);
                ms_satisfaction_free(&dissats[i]);
            }
            wally_free(indices);
            ms_satisfaction_init(sat_out, MS_WITNESS_UNAVAILABLE);
            return;
        }
    }

    /* 6. Free leftover sats[] entries (unchosen sats + swapped-out dissats),
     *    then fold dissats[] (now ret_stack) for sat_out */
    for (i = 0; i < n; i++) ms_satisfaction_free(&sats[i]);
    ms_satisfaction sat_acc;
    ms_satisfaction_init(&sat_acc, MS_WITNESS_STACK);
    for (i = 0; i < n; i++)
        sat_acc = satisfaction_concat(dissats[i], sat_acc);
    *sat_out = sat_acc;

    wally_free(indices);
}

typedef struct {
    ms_satisfaction sat;
    ms_satisfaction dissat;
} sat_dissat_t;

/* Pop and free the top child_n child results from the result stack.
 * Used when a case cannot proceed (e.g. OOM) and must discard its
 * children's satisfactions. */
static void drain_children(sat_dissat_t *result, size_t *rsp, size_t child_n)
{
    for (size_t i = 0; i < child_n; i++) {
        (*rsp)--;
        ms_satisfaction_free(&result[*rsp].sat);
        ms_satisfaction_free(&result[*rsp].dissat);
    }
}

/* Select the k cheapest available signatures for a multi/multi_a fragment.
 *
 * On success returns MS_WITNESS_STACK with *avail_out set to an array (owned
 * by the caller) whose first k entries are the chosen key indices in
 * ascending key order; unchosen-but-available sats[] entries are freed and
 * reset to IMPOSSIBLE. On failure returns MS_WITNESS_OOM (allocation failure)
 * or MS_WITNESS_IMPOSSIBLE (fewer than k signatures available) with
 * *avail_out NULL, freeing every sats[] entry.
 */
static uint32_t multisig_select_k(ms_satisfaction *sats, size_t child_n, size_t k,
                                  size_t **avail_out)
{
    size_t *avail = wally_malloc(child_n * sizeof(size_t));
    size_t navail = 0;
    uint32_t kind = avail ? MS_WITNESS_IMPOSSIBLE : MS_WITNESS_OOM;

    *avail_out = NULL;

    /* Collect indices of keys with available signatures */
    for (size_t i = 0; avail && i < child_n; i++) {
        if (IS_OOM(sats[i])) {
            kind = MS_WITNESS_OOM;
            break; /* A signature failed to allocate */
        }
        if (sats[i].witness.kind == MS_WITNESS_STACK)
            avail[navail++] = i;
    }

    if (kind == MS_WITNESS_OOM || navail < k) {
        for (size_t i = 0; i < child_n; i++)
            ms_satisfaction_free(&sats[i]);
        wally_free(avail);
        return kind;
    }

    if (navail > k) {
        /* Sort avail[] by witness weight ascending, keep k lightest */
        for (size_t i = 1; i < navail; i++) {
            size_t tmp = avail[i], j = i;
            size_t tmp_w = witness_weight(&sats[tmp].witness);
            while (j > 0 &&
                   witness_weight(&sats[avail[j - 1]].witness) > tmp_w) {
                avail[j] = avail[j - 1];
                j--;
            }
            avail[j] = tmp;
        }
        /* Free the heaviest sigs and mark them freed */
        for (size_t i = k; i < navail; i++) {
            ms_satisfaction_free(&sats[avail[i]]);
            ms_satisfaction_init(&sats[avail[i]], MS_WITNESS_IMPOSSIBLE);
        }
        /* Re-sort chosen indices by key position (ascending) */
        for (size_t i = 1; i < k; i++) {
            size_t tmp = avail[i], j = i;
            while (j > 0 && avail[j - 1] > tmp) {
                avail[j] = avail[j - 1];
                j--;
            }
            avail[j] = tmp;
        }
    }
    /* avail[0..k-1] holds chosen key indices in ascending order */
    *avail_out = avail;
    return MS_WITNESS_STACK;
}


static size_t ms_node_count(const ms_node *node)
{
    /* Count `node`, its ->next siblings and all descendants iteratively. An
     * explicit heap stack (grown by hand, as there is no wally_realloc) avoids
     * the unbounded recursion that would overflow the stack on deeply-nested
     * attacker-supplied scripts. On allocation failure we return 0, which the
     * caller (ms_satisfy_node) treats as an allocation failure. */
    size_t count = 0, cap = 0, sp = 0;
    const ms_node **stack = NULL;
    const ms_node *cur = node;

    while (cur || sp) {
        if (cur) {
            ++count;
            if (cur->child) {
                if (sp == cap) {
                    size_t new_cap = cap ? cap * 2 : 32;
                    const ms_node **grown = wally_malloc(new_cap * sizeof(*grown));
                    if (!grown) { wally_free(stack); return 0; }
                    if (sp)
                        memcpy(grown, stack, sp * sizeof(*grown));
                    wally_free(stack);
                    stack = grown;
                    cap = new_cap;
                }
                stack[sp++] = cur->child;
            }
            cur = cur->next;
        } else
            cur = stack[--sp];
    }
    wally_free(stack);
    return count;
}

/* Get the first sub-expression of an expression, or NULL if it has none
 * (the children of other expressions are keys, hashes or numbers) */
static const ms_node *first_sub(const ms_node *node)
{
    switch (node->kind) {
    case KIND_MINISCRIPT_THRESH:
        return node->child->next; /* Skip the threshold */
    case KIND_MINISCRIPT_ANDOR:
    case KIND_MINISCRIPT_AND_V:
    case KIND_MINISCRIPT_AND_B:
    case KIND_MINISCRIPT_AND_N:
    case KIND_MINISCRIPT_OR_B:
    case KIND_MINISCRIPT_OR_C:
    case KIND_MINISCRIPT_OR_D:
    case KIND_MINISCRIPT_OR_I:
        return node->child;
    }
    return NULL;
}

static size_t num_children(const ms_node *node)
{
    size_t n = 0;
    for (node = node->child; node; node = node->next)
        ++n;
    return n;
}

/* The satisfaction of 0 or 1 */
static void satisfy_constant(sat_dissat_t *entry, bool value)
{
    ms_satisfaction_init(&entry->sat, value ? MS_WITNESS_STACK : MS_WITNESS_IMPOSSIBLE);
    ms_satisfaction_init(&entry->dissat, value ? MS_WITNESS_IMPOSSIBLE : MS_WITNESS_STACK);
}

/* The satisfaction of a key: its signature */
static ms_satisfaction satisfy_key(const ms_node *key, const ms_satisfier *stfr)
{
    unsigned char sig_buf[EC_SIGNATURE_DER_MAX_LEN + 1];
    size_t sig_len = 0;
    ms_satisfaction sat;

    ms_satisfaction_init(&sat, MS_WITNESS_IMPOSSIBLE);
    if (key->kind == KIND_PUBLIC_KEY && stfr && stfr->lookup_sig &&
        stfr->lookup_sig(stfr, (const unsigned char *)key->data,
                         key->data_len, sig_buf, &sig_len)) {
        ms_satisfaction_init(&sat, MS_WITNESS_STACK);
        sat = satisfaction_push_item(sat, sig_buf, sig_len);
        sat.has_sig = true;
    }
    ms_clear(sig_buf, sizeof(sig_buf));
    return sat;
}

/* and_v(X,Y): [X] [Y] */
static void satisfy_and_v(sat_dissat_t x, sat_dissat_t y, sat_dissat_t *entry)
{
    ms_satisfaction x_sat_clone = ms_satisfaction_clone(&x.sat);
    ms_satisfaction_free(&x.dissat);
    entry->sat    = satisfaction_concat(y.sat,    x.sat);
    entry->dissat = satisfaction_concat(y.dissat, x_sat_clone);
}

/* multi(k,key1,...,keyn) and multi_a(k,key1,...,keyn) */
static void satisfy_multi(const ms_node *n, const ms_satisfier *stfr,
                          sat_dissat_t *entry)
{
    const bool is_multi_a = n->kind == KIND_MINISCRIPT_MULTI_A;
    const size_t k = (size_t)n->child->number;
    const size_t child_n = num_children(n) - 1;
    ms_satisfaction *sats = wally_malloc(child_n * sizeof(ms_satisfaction));
    const ms_node *key;
    size_t *avail, i;
    uint32_t kind;

    if (!sats) {
        ms_satisfaction_init(&entry->sat,    MS_WITNESS_OOM);
        ms_satisfaction_init(&entry->dissat, MS_WITNESS_OOM);
        return;
    }
    for (i = 0, key = n->child->next; key; ++i, key = key->next)
        sats[i] = satisfy_key(key, stfr);

    /* dissat: multi: a dummy item and k empty items (signatures),
     * multi_a: an empty item (signature) for each key */
    ms_satisfaction_init(&entry->dissat, MS_WITNESS_STACK);
    for (i = 0; i < (is_multi_a ? child_n : k + 1); i++)
        entry->dissat = satisfaction_push_item(entry->dissat, NULL, 0);

    kind = multisig_select_k(sats, child_n, k, &avail);
    if (kind != MS_WITNESS_STACK) {
        wally_free(sats);
        ms_satisfaction_init(&entry->sat, kind); /* IMPOSSIBLE or OOM */
        return;
    }

    ms_satisfaction_init(&entry->sat, MS_WITNESS_STACK);
    if (!is_multi_a) {
        /* sat: dummy item followed by k signatures in key order */
        size_t ai = 0;
        for (i = 0; i < child_n; i++) {
            if (ai < k && avail[ai] == i)
                ai++;
            else
                ms_satisfaction_free(&sats[i]); /* Unchosen */
        }
        entry->sat = satisfaction_push_item(entry->sat, NULL, 0);
        for (i = 0; i < k; i++) {
            const size_t idx = avail[i];
            if (sats[idx].witness.num_items > 0) {
                /* Move the signature item into entry->sat (no copy) */
                entry->sat = satisfaction_push_item_take(entry->sat,
                    sats[idx].witness.items[0].data,
                    sats[idx].witness.items[0].data_len);
                sats[idx].witness.items[0].data = NULL;
                sats[idx].witness.items[0].data_len = 0;
            }
            ms_satisfaction_free(&sats[idx]);
        }
    } else {
        /*
         * sat: n witness items in reverse key order (Kn first at stack
         * bottom, K1 last at stack top). Chosen keys contribute their sig;
         * unchosen keys contribute an empty byte string.
         * Use two-pointer scan since avail[] is sorted ascending.
         */
        size_t ai = k;
        for (i = child_n; i-- > 0; ) {
            const bool chosen = (ai > 0 && avail[ai - 1] == i);
            if (chosen) {
                ai--;
                if (sats[i].witness.num_items > 0) {
                    /* Move the signature item into entry->sat (no copy) */
                    entry->sat = satisfaction_push_item_take(entry->sat,
                        sats[i].witness.items[0].data,
                        sats[i].witness.items[0].data_len);
                    sats[i].witness.items[0].data = NULL;
                    sats[i].witness.items[0].data_len = 0;
                }
            } else {
                entry->sat = satisfaction_push_item(entry->sat, NULL, 0);
            }
            ms_satisfaction_free(&sats[i]);
        }
    }
    entry->sat.has_sig = true;

    wally_free(sats);
    wally_free(avail);
}

/* Satisfy an expression, given the results for its sub-expressions */
static void satisfy_expression(const ms_node *n, const ms_satisfier *stfr,
                               bool malleable, sat_dissat_t *result,
                               size_t *rsp, sat_dissat_t *entry)
{
    switch (n->kind) {

    case KIND_NUMBER:
        satisfy_constant(entry, n->number != 0);
        break;

    case KIND_MINISCRIPT_PK_K:
    case KIND_DESCRIPTOR_PK | KIND_MINISCRIPT_PK:
        /* pk_k(key): <key>, pk(key) is c:pk_k(key) */
        entry->sat = satisfy_key(n->child, stfr);
        ms_satisfaction_init(&entry->dissat, MS_WITNESS_STACK);
        entry->dissat = satisfaction_push_item(entry->dissat, NULL, 0);
        break;

    case KIND_MINISCRIPT_PK_H:
    case KIND_DESCRIPTOR_PKH | KIND_MINISCRIPT_PKH: {
        /* pk_h(key): DUP HASH160 <HASH160(key)> EQUALVERIFY,
         * pkh(key) is c:pk_h(key) */
        const ms_node *key = n->child;
        if (key->kind != KIND_PUBLIC_KEY) {
            ms_satisfaction_init(&entry->dissat, MS_WITNESS_UNAVAILABLE);
            break;
        }
        /* sat: [sig, pubkey], dissat: [0, pubkey] */
        entry->sat = satisfy_key(key, stfr);
        entry->sat = satisfaction_push_item(entry->sat,
                                            (const unsigned char *)key->data,
                                            key->data_len);
        ms_satisfaction_init(&entry->dissat, MS_WITNESS_STACK);
        entry->dissat = satisfaction_push_item(entry->dissat, NULL, 0);
        entry->dissat = satisfaction_push_item(entry->dissat,
                                               (const unsigned char *)key->data,
                                               key->data_len);
        break;
    }

    case KIND_MINISCRIPT_SHA256:
    case KIND_MINISCRIPT_HASH256:
    case KIND_MINISCRIPT_RIPEMD160:
    case KIND_MINISCRIPT_HASH160: {
        const ms_node *hash = n->child;
        unsigned char preimage[32];
        uint32_t hash_type;
        if (n->kind == KIND_MINISCRIPT_SHA256)         hash_type = MS_HASH_SHA256;
        else if (n->kind == KIND_MINISCRIPT_HASH256)   hash_type = MS_HASH_HASH256;
        else if (n->kind == KIND_MINISCRIPT_RIPEMD160) hash_type = MS_HASH_RIPEMD160;
        else                                           hash_type = MS_HASH_HASH160;
        if (stfr && stfr->lookup_preimage &&
            stfr->lookup_preimage(stfr, (const unsigned char *)hash->data,
                                  hash->data_len, hash_type, preimage)) {
            ms_satisfaction_init(&entry->sat, MS_WITNESS_STACK);
            entry->sat = satisfaction_push_item(entry->sat, preimage, 32);
        } else {
            ms_satisfaction_init(&entry->sat, MS_WITNESS_UNAVAILABLE);
        }
        /* Dissatisfaction for hash fragments is always possible:
         * any 32-byte non-matching value suffices. */
        ms_satisfaction_init(&entry->dissat, MS_WITNESS_STACK);
        entry->dissat = satisfaction_push_item(entry->dissat, zero32, 32);
        ms_clear(preimage, sizeof(preimage));
        break;
    }

    case KIND_MINISCRIPT_OLDER: {
        const uint32_t lock = (uint32_t)n->child->number;
        if (stfr && stfr->check_older && stfr->check_older(stfr, lock)) {
            ms_satisfaction_init(&entry->sat, MS_WITNESS_STACK);
            entry->sat.relative_timelock = lock;
        } else {
            ms_satisfaction_init(&entry->sat, MS_WITNESS_UNAVAILABLE);
        }
        break;
    }

    case KIND_MINISCRIPT_AFTER: {
        const uint32_t lock = (uint32_t)n->child->number;
        if (stfr && stfr->check_after && stfr->check_after(stfr, lock)) {
            ms_satisfaction_init(&entry->sat, MS_WITNESS_STACK);
            entry->sat.absolute_timelock = lock;
        } else {
            ms_satisfaction_init(&entry->sat, MS_WITNESS_UNAVAILABLE);
        }
        break;
    }

    case KIND_DESCRIPTOR_MULTI | KIND_MINISCRIPT_MULTI:
    case KIND_MINISCRIPT_MULTI_A:
        satisfy_multi(n, stfr, entry);
        break;

    case KIND_MINISCRIPT_AND_B: {
        sat_dissat_t r = result[--*rsp];
        sat_dissat_t l = result[--*rsp];
        entry->sat    = satisfaction_concat(r.sat,    l.sat);
        entry->dissat = satisfaction_concat(r.dissat, l.dissat);
        break;
    }

    case KIND_MINISCRIPT_AND_V: {
        sat_dissat_t r = result[--*rsp];
        sat_dissat_t l = result[--*rsp];
        satisfy_and_v(l, r, entry);
        break;
    }

    case KIND_MINISCRIPT_AND_N:
    case KIND_MINISCRIPT_ANDOR: {
        /* and_n(X,Y) is andor(X,Y,0) */
        sat_dissat_t z, y, x;
        if (n->kind == KIND_MINISCRIPT_AND_N)
            satisfy_constant(&z, false);
        else
            z = result[--*rsp];
        y = result[--*rsp];
        x = result[--*rsp];
        satisfaction_andor(x.sat, x.dissat, y.sat, y.dissat,
                           z.sat, z.dissat,
                           &entry->sat, &entry->dissat, malleable);
        break;
    }

    case KIND_MINISCRIPT_OR_B: {
        sat_dissat_t r = result[--*rsp];
        sat_dissat_t l = result[--*rsp];
        satisfaction_or_b(l.sat, l.dissat, r.sat, r.dissat,
                          &entry->sat, &entry->dissat, malleable);
        break;
    }

    case KIND_MINISCRIPT_OR_C: {
        sat_dissat_t r = result[--*rsp];
        sat_dissat_t l = result[--*rsp];
        satisfaction_or_c(l.sat, l.dissat, r.sat, r.dissat,
                          &entry->sat, &entry->dissat, malleable);
        break;
    }

    case KIND_MINISCRIPT_OR_D: {
        sat_dissat_t r = result[--*rsp];
        sat_dissat_t l = result[--*rsp];
        satisfaction_or_d(l.sat, l.dissat, r.sat, r.dissat,
                          &entry->sat, &entry->dissat, malleable);
        break;
    }

    case KIND_MINISCRIPT_OR_I: {
        sat_dissat_t r = result[--*rsp];
        sat_dissat_t l = result[--*rsp];
        satisfaction_or_i(l.sat, l.dissat, r.sat, r.dissat,
                          &entry->sat, &entry->dissat, malleable);
        break;
    }

    case KIND_MINISCRIPT_THRESH: {
        const size_t k = (size_t)n->child->number;
        const size_t child_n = num_children(n) - 1;
        ms_satisfaction *sats    = wally_malloc(child_n * sizeof(ms_satisfaction));
        ms_satisfaction *dissats = wally_malloc(child_n * sizeof(ms_satisfaction));
        if (!sats || !dissats) {
            wally_free(sats); wally_free(dissats);
            drain_children(result, rsp, child_n);
            ms_satisfaction_init(&entry->sat,    MS_WITNESS_OOM);
            ms_satisfaction_init(&entry->dissat, MS_WITNESS_OOM);
            break;
        }
        for (size_t i = child_n; i-- > 0; ) {
            sat_dissat_t sd = result[--*rsp];
            sats[i]    = sd.sat;
            dissats[i] = sd.dissat;
        }
        satisfaction_thresh(k, child_n, sats, dissats,
                            &entry->sat, &entry->dissat, malleable);
        wally_free(sats);
        wally_free(dissats);
        break;
    }

    default:
        break; /* Not a miniscript expression: impossible to satisfy */
    }
}

/* Apply the wrappers of an expression to its satisfaction */
static void satisfy_wrappers(const ms_node *n, bool malleable, sat_dissat_t *entry)
{
    size_t i = strlen(n->wrapper_str);
    sat_dissat_t c;

    while (i--) {
        /* Apply the innermost wrapper first */
        const char wrapper = n->wrapper_str[i];
        switch (wrapper) {
        case 'd':
            /* d:X: DUP IF [X] ENDIF */
            ms_satisfaction_free(&entry->dissat);
            ms_satisfaction_init(&entry->dissat, MS_WITNESS_STACK);
            entry->dissat = satisfaction_push_item(entry->dissat, NULL, 0);
            entry->sat = satisfaction_push_item(entry->sat, push_1, 1);
            break;
        case 'v':
            /* v:X: [X] VERIFY */
            ms_satisfaction_free(&entry->dissat);
            ms_satisfaction_init(&entry->dissat, MS_WITNESS_IMPOSSIBLE);
            break;
        case 'j':
            /* j:X: SIZE 0NOTEQUAL IF [X] ENDIF. Satisfied by X's satisfaction
             * (whose top element is non-zero-length); dissatisfied by a single
             * empty push (SIZE=0 -> false -> IF skipped). */
            ms_satisfaction_free(&entry->dissat);
            ms_satisfaction_init(&entry->dissat, MS_WITNESS_STACK);
            entry->dissat = satisfaction_push_item(entry->dissat, NULL, 0);
            break;
        case 't':
            /* t:X is and_v(X,1) */
            satisfy_constant(&c, true);
            satisfy_and_v(*entry, c, entry);
            break;
        case 'l':
        case 'u':
            /* l:X is or_i(0,X), u:X is or_i(X,0) */
            satisfy_constant(&c, false);
            if (wrapper == 'l')
                satisfaction_or_i(c.sat, c.dissat, entry->sat, entry->dissat,
                                  &entry->sat, &entry->dissat, malleable);
            else
                satisfaction_or_i(entry->sat, entry->dissat, c.sat, c.dissat,
                                  &entry->sat, &entry->dissat, malleable);
            break;
        default:
            /* a:, s:, c: and n: are satisfied as the wrapped expression */
            break;
        }
    }
}

typedef struct {
    const ms_node *node;
    const ms_node *cur_child;
} trav_frame_t;

void ms_satisfy_node(const ms_node *node, const ms_satisfier *stfr,
                     bool malleable,
                     ms_satisfaction *sat_out, ms_satisfaction *dissat_out)
{
    size_t cap = ms_node_count(node); /* Zero on allocation failure */
    trav_frame_t  *trav   = cap ? wally_malloc(cap * sizeof(trav_frame_t)) : NULL;
    sat_dissat_t  *result = cap ? wally_malloc(cap * sizeof(sat_dissat_t)) : NULL;
    if (!trav || !result) {
        wally_free(trav); wally_free(result);
        ms_satisfaction_init(sat_out,    MS_WITNESS_OOM);
        ms_satisfaction_init(dissat_out, MS_WITNESS_OOM);
        return;
    }

    size_t tsp = 0;
    size_t rsp = 0;

    trav[tsp++] = (trav_frame_t){ node, first_sub(node) };

    while (tsp > 0) {
        trav_frame_t *top = &trav[tsp - 1];

        if (top->cur_child) {
            const ms_node *child = top->cur_child;
            top->cur_child = child->next;
            trav[tsp++] = (trav_frame_t){ child, first_sub(child) };
            continue;
        }

        const ms_node *n = top->node;
        tsp--;

        sat_dissat_t entry;
        ms_satisfaction_init(&entry.sat,    MS_WITNESS_IMPOSSIBLE);
        ms_satisfaction_init(&entry.dissat, MS_WITNESS_IMPOSSIBLE);
        satisfy_expression(n, stfr, malleable, result, &rsp, &entry);
        satisfy_wrappers(n, malleable, &entry);
        result[rsp++] = entry;
    }

    /* Each expression pops exactly its sub-expressions' results, so
     * exactly one result remains. */
    if (rsp == 1) {
        *sat_out    = result[0].sat;
        *dissat_out = result[0].dissat;
    } else {
        drain_children(result, &rsp, rsp);
        ms_satisfaction_init(sat_out,    MS_WITNESS_IMPOSSIBLE);
        ms_satisfaction_init(dissat_out, MS_WITNESS_IMPOSSIBLE);
    }

    wally_free(trav);
    wally_free(result);
}
