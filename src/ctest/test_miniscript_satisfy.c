#include "config.h"

#include <wally_core.h>
#include <wally_address.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>
#include <wally_map.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "../miniscript_decode.h"
#include "../miniscript_satisfy.h"

#define NUM_ELEMS(a) (sizeof(a) / sizeof(a[0]))
#define TAP WALLY_MINISCRIPT_TAPSCRIPT

/* Compressed keys, and their x-only equivalents */
#define K1 "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
#define K2 "03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"
#define K3 "025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc"
#define K4 "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"
#define X1 "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
#define X2 "d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"
#define X3 "5601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc"
#define H32 "9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2"

static const char *const g_keys[] = { K1, K2, K3, K4 };
static unsigned char g_key_bytes[NUM_ELEMS(g_keys)][EC_PUBLIC_KEY_LEN];

#define SIG(n) (1u << ((n) - 1)) /* A signature is available for key n */
#define NO_SATISFIER 0x80000000  /* Pass a NULL satisfier */

/* The assets available to satisfy an expression */
typedef struct {
    uint32_t sigs;
    bool preimage;
    uint32_t older;
    uint32_t after;
} assets_t;

/* Find a key from g_keys, returning its 1-based index or 0 if not found */
static size_t key_index(const unsigned char *pk, size_t pk_len)
{
    const size_t offset = EC_PUBLIC_KEY_LEN - pk_len;
    size_t i;

    for (i = 0; i < NUM_ELEMS(g_keys); ++i)
        if (!memcmp(pk, g_key_bytes[i] + offset, pk_len))
            return i + 1;
    return 0;
}

/* A fake ECDSA (with sighash byte) or schnorr signature for key n */
static size_t make_sig(size_t n, bool is_schnorr, unsigned char *sig)
{
    if (is_schnorr) {
        memset(sig, (int)n, 64);
        return 64;
    }
    sig[0] = 0x30; sig[1] = 0x44;
    sig[2] = 0x02; sig[3] = 0x20;
    memset(sig + 4, (int)n, 32);
    sig[36] = 0x02; sig[37] = 0x20;
    memset(sig + 38, (int)n, 32);
    sig[70] = 0x01;
    return 71;
}

static bool lookup_sig(const ms_satisfier *stfr,
                       const unsigned char *pk, size_t pk_len,
                       unsigned char *sig_out, size_t *sig_len_out)
{
    const assets_t *assets = (const assets_t *)stfr->user_data;
    const size_t n = key_index(pk, pk_len);

    if (!n || !(assets->sigs & SIG(n)))
        return false;
    *sig_len_out = make_sig(n, pk_len == EC_XONLY_PUBLIC_KEY_LEN, sig_out);
    return true;
}

static bool lookup_preimage(const ms_satisfier *stfr,
                            const unsigned char *hash, size_t hash_len,
                            uint32_t hash_type, unsigned char preimage_out[32])
{
    const assets_t *assets = (const assets_t *)stfr->user_data;
    (void)hash;
    (void)hash_len;
    (void)hash_type;
    if (assets->preimage)
        memset(preimage_out, 0x42, 32);
    return assets->preimage;
}

static bool check_older(const ms_satisfier *stfr, uint32_t lock)
{
    return lock <= ((const assets_t *)stfr->user_data)->older;
}

static bool check_after(const ms_satisfier *stfr, uint32_t lock)
{
    return lock <= ((const assets_t *)stfr->user_data)->after;
}

/* Check a witness against a description: "IMPOSSIBLE", "UNAVAILABLE", or
 * its items separated by spaces: "-" (empty), "S<n>" (key n's signature),
 * "P<n>" (key n), "H" (preimage), "Z" (32 zero bytes), or hex */
static bool witness_is(const ms_satisfaction *s, const char *expected, bool is_tapscript)
{
    unsigned char item[128];
    char token[16];
    size_t i = 0, item_len, token_len;
    const char *p = expected;

    if (!strcmp(expected, "IMPOSSIBLE"))
        return s->witness.kind == MS_WITNESS_IMPOSSIBLE;
    if (!strcmp(expected, "UNAVAILABLE"))
        return s->witness.kind == MS_WITNESS_UNAVAILABLE;
    if (s->witness.kind != MS_WITNESS_STACK)
        return false;

    while (*p) {
        token_len = strcspn(p, " ");
        memcpy(token, p, token_len);
        token[token_len] = '\0';
        p += token_len + (p[token_len] == ' ');

        if (!strcmp(token, "-"))
            item_len = 0;
        else if (token[0] == 'S')
            item_len = make_sig(token[1] - '0', is_tapscript, item);
        else if (token[0] == 'P') {
            item_len = is_tapscript ? EC_XONLY_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_LEN;
            memcpy(item, g_key_bytes[token[1] - '1'] + EC_PUBLIC_KEY_LEN - item_len, item_len);
        } else if (!strcmp(token, "H") || !strcmp(token, "Z")) {
            item_len = 32;
            memset(item, token[0] == 'H' ? 0x42 : 0, item_len);
        } else if (wally_hex_to_bytes(token, item, sizeof(item), &item_len) != WALLY_OK)
            return false;

        if (i >= s->witness.num_items || s->witness.items[i].data_len != item_len ||
            (item_len && memcmp(s->witness.items[i].data, item, item_len)))
            return false;
        ++i;
    }
    return i == s->witness.num_items;
}

static bool test_satisfy(void)
{
    static const struct {
        const char *miniscript;
        uint32_t flags;
        uint32_t sigs; /* SIG(n) for each available signature, or NO_SATISFIER */
        bool preimage;
        uint32_t older, after;
        bool malleable;
        const char *sat, *dissat;
        uint32_t sat_older, sat_after; /* Timelocks of the satisfaction */
    } cases[] = {
        /* multi: a dummy item, then the signatures */
        { "multi(2," K1 "," K2 "," K3 ")", 0, SIG(1) | SIG(2) | SIG(3), false, 0, 0, false,
          "- S1 S2", "- - -", 0, 0 },
        { "multi(2," K1 "," K2 "," K3 ")", 0, SIG(1), false, 0, 0, false,
          "IMPOSSIBLE", "- - -", 0, 0 },
        { "multi(2," K1 "," K2 "," K3 ")", 0, NO_SATISFIER, false, 0, 0, false,
          "IMPOSSIBLE", "- - -", 0, 0 },
        { "multi(1," K1 ")", 0, SIG(1), false, 0, 0, false, "- S1", "- -", 0, 0 },
        /* multi_a: an item for each key, in reverse order */
        { "multi_a(2," X1 "," X2 "," X3 ")", TAP, SIG(1) | SIG(2) | SIG(3), false, 0, 0, false,
          "- S2 S1", "- - -", 0, 0 },
        { "multi_a(2," X1 "," X2 "," X3 ")", TAP, SIG(2), false, 0, 0, false,
          "IMPOSSIBLE", "- - -", 0, 0 },
        { "multi_a(2," X1 "," X2 "," X3 ")", TAP, NO_SATISFIER, false, 0, 0, false,
          "IMPOSSIBLE", "- - -", 0, 0 },
        { "multi_a(1," X1 ")", TAP, SIG(1), false, 0, 0, false, "S1", "-", 0, 0 },
        /* Timelocks */
        { "older(100)", 0, 0, false, 100, 0, false, "", "IMPOSSIBLE", 100, 0 },
        { "older(100)", 0, 0, false, 0, 0, false, "UNAVAILABLE", "IMPOSSIBLE", 0, 0 },
        { "older(100)", 0, NO_SATISFIER, false, 0, 0, false, "UNAVAILABLE", "IMPOSSIBLE", 0, 0 },
        { "after(500)", 0, 0, false, 0, 500, false, "", "IMPOSSIBLE", 0, 500 },
        { "after(500)", 0, 0, false, 0, 0, false, "UNAVAILABLE", "IMPOSSIBLE", 0, 0 },
        { "and_v(v:older(100),older(200))", 0, 0, false, 200, 0, false, "", "IMPOSSIBLE", 200, 0 },
        { "and_v(v:older(100),after(500))", 0, 0, false, 100, 500, false, "", "IMPOSSIBLE", 100, 500 },
        /* Keys */
        { "pk(" K1 ")", 0, SIG(1), false, 0, 0, false, "S1", "-", 0, 0 },
        { "pk(" K1 ")", 0, 0, false, 0, 0, false, "IMPOSSIBLE", "-", 0, 0 },
        { "pk(" X1 ")", TAP, SIG(1), false, 0, 0, false, "S1", "-", 0, 0 },
        { "pkh(" K1 ")", 0, SIG(1), false, 0, 0, false, "S1 P1", "- P1", 0, 0 },
        { "pkh(" K1 ")", 0, 0, false, 0, 0, false, "IMPOSSIBLE", "- P1", 0, 0 },
        { "pkh(" X1 ")", TAP, SIG(1), false, 0, 0, false, "S1 P1", "- P1", 0, 0 },
        /* Hashes */
        { "sha256(" H32 ")", 0, 0, true, 0, 0, false, "H", "Z", 0, 0 },
        { "sha256(" H32 ")", 0, 0, false, 0, 0, false, "UNAVAILABLE", "Z", 0, 0 },
        /* or_b(X,Z): [X] [Z] BOOLOR */
        { "or_b(dv:older(100),s:pk(" K1 "))", 0, 0, false, 100, 0, false, "- 01", "- -", 100, 0 },
        { "or_b(dv:older(100),s:pk(" K1 "))", 0, 0, false, 0, 0, false, "UNAVAILABLE", "- -", 0, 0 },
        { "or_b(dv:older(100),s:pk(" K1 "))", 0, NO_SATISFIER, false, 0, 0, false, "UNAVAILABLE", "- -", 0, 0 },
        /* or_c(X,Z): [X] NOTIF [Z] ENDIF */
        { "t:or_c(ndv:older(100),v:pk(" K2 "))", 0, 0, false, 100, 0, false, "01", "IMPOSSIBLE", 100, 0 },
        { "t:or_c(ndv:older(100),v:pk(" K2 "))", 0, 0, false, 0, 0, false, "UNAVAILABLE", "IMPOSSIBLE", 0, 0 },
        { "t:or_c(ndv:older(100),v:pk(" K2 "))", 0, NO_SATISFIER, false, 0, 0, false, "UNAVAILABLE", "IMPOSSIBLE", 0, 0 },
        /* or_d(X,Z): [X] IFDUP NOTIF [Z] ENDIF */
        { "or_d(ndv:older(100),pk(" K3 "))", 0, 0, false, 100, 0, false, "01", "- -", 100, 0 },
        { "or_d(ndv:older(100),pk(" K3 "))", 0, 0, false, 0, 0, false, "UNAVAILABLE", "- -", 0, 0 },
        { "or_d(ndv:older(100),pk(" K3 "))", 0, NO_SATISFIER, false, 0, 0, false, "UNAVAILABLE", "- -", 0, 0 },
        { "or_d(pk(" K1 "),j:pk(" K2 "))", 0, SIG(2), false, 0, 0, false, "S2 -", "- -", 0, 0 },
        /* or_i(X,Z): IF [X] ELSE [Z] ENDIF */
        { "or_i(older(100),pk(" K4 "))", 0, 0, false, 100, 0, false, "01", "- -", 100, 0 },
        { "or_i(older(100),pk(" K4 "))", 0, 0, false, 0, 0, false, "UNAVAILABLE", "- -", 0, 0 },
        { "or_i(older(100),pk(" K4 "))", 0, NO_SATISFIER, false, 0, 0, false, "UNAVAILABLE", "- -", 0, 0 },
        { "u:pk(" K1 ")", 0, SIG(1), false, 0, 0, false, "S1 01", "-", 0, 0 },
        { "l:pk(" K1 ")", 0, SIG(1), false, 0, 0, false, "S1 -", NULL, 0, 0 },
        /* andor(X,Y,Z): [X] NOTIF [Z] ELSE [Y] ENDIF */
        { "andor(pk(" K1 "),pk(" K2 "),pk(" K3 "))", 0, SIG(1) | SIG(2), false, 0, 0, false, "S2 S1", "- -", 0, 0 },
        { "andor(pk(" K1 "),pk(" K2 "),pk(" K3 "))", 0, SIG(1), false, 0, 0, false, "IMPOSSIBLE", "- -", 0, 0 },
        { "andor(pk(" K1 "),pk(" K2 "),pk(" K3 "))", 0, SIG(3), false, 0, 0, false, "S3 -", "- -", 0, 0 },
        { "andor(pk(" K1 "),1,pk(" K2 "))", 0, SIG(1), false, 0, 0, false, "S1", "- -", 0, 0 },
        { "and_n(pk(" K1 "),pk(" K2 "))", 0, SIG(1) | SIG(2), false, 0, 0, false, "S2 S1", "-", 0, 0 },
        /* and_v(X,Y): [X] [Y], and_b(X,Y): [X] [Y] BOOLAND */
        { "and_v(v:pk(" K1 "),pk(" K2 "))", 0, SIG(1) | SIG(2), false, 0, 0, false, "S2 S1", "- S1", 0, 0 },
        { "tv:pk(" K1 ")", 0, SIG(1), false, 0, 0, false, "S1", "IMPOSSIBLE", 0, 0 },
        { "and_b(pk(" K1 "),a:pk(" K2 "))", 0, SIG(1) | SIG(2), false, 0, 0, false, "S2 S1", "- -", 0, 0 },
        /* thresh(k,X1,...,Xn): [X1] [X2] ADD ... [Xn] ADD <k> EQUAL */
        { "thresh(2,ndv:older(100),s:pk(" K1 "))", 0, SIG(1), false, 100, 0, false, "S1 01", "- -", 100, 0 },
        { "thresh(2,ndv:older(100),s:pk(" K1 "))", 0, SIG(1), false, 0, 0, false, "UNAVAILABLE", NULL, 0, 0 },
        { "thresh(2,ndv:older(100),s:pk(" K1 "))", 0, 0, false, 100, 0, false, "IMPOSSIBLE", NULL, 0, 0 },
        { "thresh(2,ndv:older(100),s:pk(" K1 "))", 0, NO_SATISFIER, false, 0, 0, false, "IMPOSSIBLE", NULL, 0, 0 },
        { "thresh(3,ndv:older(100),s:pk(" K1 "),s:pk(" K2 "))", 0, SIG(1) | SIG(2), false, 100, 0, false,
          "S2 S1 01", "- - -", 100, 0 },
        { "thresh(3,ndv:older(100),s:pk(" K1 "),s:pk(" K2 "))", 0, SIG(1), false, 100, 0, false,
          "IMPOSSIBLE", NULL, 0, 0 },
        { "thresh(3,ndv:older(100),s:pk(" K1 "),s:pk(" K2 "))", 0, SIG(1) | SIG(2), false, 100, 0, true,
          "S2 S1 01", "- - -", 100, 0 },
    };
    struct wally_map keys;
    unsigned char script[1024];
    size_t i, written;
    bool ok = true;

    wally_map_init(NUM_ELEMS(g_keys) * 2, NULL, &keys);
    for (i = 0; i < NUM_ELEMS(g_keys); ++i) {
        wally_hex_to_bytes(g_keys[i], g_key_bytes[i], EC_PUBLIC_KEY_LEN, &written);
        wally_map_add(&keys, g_key_bytes[i], EC_PUBLIC_KEY_LEN, NULL, 0);
        wally_map_add(&keys, g_key_bytes[i] + 1, EC_XONLY_PUBLIC_KEY_LEN, NULL, 0);
    }

    for (i = 0; i < NUM_ELEMS(cases); ++i) {
        const char *ms = cases[i].miniscript;
        const bool is_tapscript = cases[i].flags & TAP;
        assets_t assets = { cases[i].sigs, cases[i].preimage, cases[i].older, cases[i].after };
        ms_satisfier stfr = { lookup_sig, lookup_preimage, check_older, check_after, &assets };
        struct wally_descriptor *d;
        ms_satisfaction sat, dissat;
        int ret;

        /* Generate the script, then decode it. Many test vectors are
         * not sane, e.g. timelock-only scripts */
        ret = wally_descriptor_parse(ms, NULL, WALLY_NETWORK_NONE,
                                     WALLY_MINISCRIPT_ONLY | WALLY_MINISCRIPT_ALLOW_NON_SANE |
                                     cases[i].flags, &d);
        if (ret == WALLY_OK) {
            ret = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0,
                                             script, sizeof(script), &written);
            wally_descriptor_free(d);
        }
        if (ret == WALLY_OK)
            ret = ms_descriptor_from_script(script, written, &keys, cases[i].flags, &d);
        if (ret != WALLY_OK) {
            printf("FAIL: decode %s\n", ms);
            ok = false;
            continue;
        }

        ms_satisfy_node(d->top_node, cases[i].sigs == NO_SATISFIER ? NULL : &stfr,
                        cases[i].malleable, &sat, &dissat);
        if (!witness_is(&sat, cases[i].sat, is_tapscript) ||
            (sat.witness.kind == MS_WITNESS_STACK &&
             (sat.has_sig != !!strchr(cases[i].sat, 'S') ||
              sat.relative_timelock != cases[i].sat_older ||
              sat.absolute_timelock != cases[i].sat_after))) {
            printf("FAIL: satisfaction %s (sigs %x)\n", ms, cases[i].sigs);
            ok = false;
        }
        if (cases[i].dissat && !witness_is(&dissat, cases[i].dissat, is_tapscript)) {
            printf("FAIL: dissatisfaction %s (sigs %x)\n", ms, cases[i].sigs);
            ok = false;
        }
        ms_satisfaction_free(&sat);
        ms_satisfaction_free(&dissat);
        wally_descriptor_free(d);
    }
    wally_map_clear(&keys);
    return ok;
}

int main(void)
{
    return test_satisfy() ? 0 : 1;
}
