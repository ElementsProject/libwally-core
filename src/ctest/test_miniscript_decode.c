#include "config.h"

#include <wally_core.h>
#include <wally_address.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>
#include <wally_map.h>
#include <wally_script.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "../miniscript_decode.h"

#define NUM_ELEMS(a) (sizeof(a) / sizeof(a[0]))
#define TAP WALLY_MINISCRIPT_TAPSCRIPT

/* Compressed keys, and their x-only equivalents */
#define K1 "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
#define K2 "03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"
#define K3 "025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc"
#define X1 "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
#define X2 "d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"
#define X3 "5601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc"
#define H32 "9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2"
#define H20 "d0721279e70d39fb4aa409b52839a0056454e3b5"

static bool check(bool ok, const char *what, const char *detail)
{
    if (!ok)
        printf("FAIL: %s: %s\n", what, detail);
    return ok;
}

/* Generate the script of a miniscript expression */
static int to_script(const char *miniscript, uint32_t flags,
                     unsigned char *script, size_t script_len, size_t *written,
                     struct wally_map *keys)
{
    struct wally_descriptor *d;
    uint32_t i, num_keys;
    unsigned char key[EC_PUBLIC_KEY_LEN];
    size_t key_len;
    char *key_hex;
    /* Many test vectors are not sane, e.g. timelock-only scripts */
    int ret = wally_descriptor_parse(miniscript, NULL, WALLY_NETWORK_NONE,
                                     WALLY_MINISCRIPT_ONLY | WALLY_MINISCRIPT_ALLOW_NON_SANE | flags,
                                     &d);
    if (ret != WALLY_OK)
        return ret;
    ret = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0,
                                     script, script_len, written);
    if (ret == WALLY_OK && *written > script_len)
        ret = WALLY_ERROR;
    /* Collect the keys of the expression, to look up pk_h keys from */
    if (ret == WALLY_OK && keys)
        ret = wally_descriptor_get_num_keys(d, &num_keys);
    for (i = 0; ret == WALLY_OK && keys && i < num_keys; ++i) {
        ret = wally_descriptor_get_key(d, i, &key_hex);
        if (ret == WALLY_OK) {
            ret = wally_hex_to_bytes(key_hex, key, sizeof(key), &key_len);
            if (ret == WALLY_OK)
                ret = wally_map_add(keys, key, key_len, NULL, 0);
            wally_free_string(key_hex);
        }
    }
    wally_descriptor_free(d);
    return ret;
}

/* Decode a script, returning WALLY_OK if both the decoded text matches
 * 'expected' and the parsed expression generates the script */
static int decode(const unsigned char *script, size_t script_len,
                  const struct wally_map *keys, uint32_t flags,
                  const char *expected)
{
    struct wally_descriptor *d;
    char *text;
    int ret = ms_script_to_miniscript(script, script_len, keys, flags, &text);

    if (ret == WALLY_OK) {
        if (expected && strcmp(text, expected)) {
            printf("decoded %s, expected %s\n", text, expected);
            ret = WALLY_ERROR;
        }
        wally_free_string(text);
    }
    if (ret == WALLY_OK) {
        ret = ms_descriptor_from_script(script, script_len, keys, flags, &d);
        if (ret == WALLY_OK)
            wally_descriptor_free(d);
    }
    return ret;
}

static bool test_round_trip(void)
{
    static const struct {
        const char *miniscript;
        uint32_t flags;
        const char *expected; /* Decoded expression, if not 'miniscript' */
    } cases[] = {
        /* Fragments */
        { "pk(" K1 ")", 0, NULL },
        { "pk(" X1 ")", TAP, NULL },
        { "pkh(" K1 ")", 0, NULL },
        { "pkh(" X1 ")", TAP, NULL },
        { "and_v(vc:pk_h(" K1 "),older(1))", 0, "and_v(v:pkh(" K1 "),older(1))" },
        { "and_v(v:pk(" K1 "),older(4259839))", 0, NULL },
        { "and_v(v:pk(" K1 "),after(500000000))", 0, NULL },
        { "and_v(v:pk(" K1 "),sha256(" H32 "))", 0, NULL },
        { "and_v(v:pk(" K1 "),hash256(" H32 "))", 0, NULL },
        { "and_v(v:pk(" K1 "),ripemd160(" H20 "))", 0, NULL },
        { "and_v(v:pk(" K1 "),hash160(" H20 "))", 0, NULL },
        { "multi(1," K1 ")", 0, NULL },
        { "multi(2," K1 "," K2 "," K3 ")", 0, NULL },
        { "multi_a(1," X1 ")", TAP, NULL },
        { "multi_a(2," X1 "," X2 "," X3 ")", TAP, NULL },
        { "and_v(v:multi(2," K1 "," K2 "),pk(" K3 "))", 0, NULL },
        { "and_v(v:multi_a(2," X1 "," X2 "),pk(" X3 "))", TAP, NULL },
        { "and_b(pk(" K1 "),s:pk(" K2 "))", 0, NULL },
        { "and_b(pk(" K1 "),a:pk(" K2 "))", 0, NULL },
        { "or_b(pk(" K1 "),s:pk(" K2 "))", 0, NULL },
        { "or_b(pk(" K1 "),a:pk(" K2 "))", 0, NULL },
        { "t:or_c(pk(" K1 "),v:pk(" K2 "))", 0, NULL },
        { "or_d(pk(" K1 "),pk(" K2 "))", 0, NULL },
        { "or_i(pk(" K1 "),pk(" K2 "))", 0, NULL },
        { "andor(pk(" K1 "),pk(" K2 "),pk(" K3 "))", 0, NULL },
        { "and_n(pk(" K1 "),pk(" K2 "))", 0, NULL },
        { "andor(pk(" K1 "),pk(" K2 "),0)", 0, "and_n(pk(" K1 "),pk(" K2 "))" },
        { "thresh(1,pk(" K1 "))", 0, NULL },
        { "thresh(2,pk(" K1 "),s:pk(" K2 "),a:pk(" K3 "))", 0, NULL },
        { "thresh(2,pk(" X1 "),s:pk(" X2 "),sdv:older(10))", TAP, NULL },
        /* Wrappers */
        { "c:pk_k(" K1 ")", 0, "pk(" K1 ")" },
        { "c:pk_h(" K1 ")", 0, "pkh(" K1 ")" },
        { "and_v(vc:pk_k(" K1 "),pk(" K2 "))", 0, "and_v(v:pk(" K1 "),pk(" K2 "))" },
        { "and_b(pk(" K1 "),sc:pk_k(" K2 "))", 0, "and_b(pk(" K1 "),s:pk(" K2 "))" },
        { "or_d(pk(" K1 "),dv:older(1))", 0, NULL },
        { "or_d(pk(" K1 "),j:pk(" K2 "))", 0, NULL },
        { "and_b(pk(" K1 "),sn:pk(" K2 "))", 0, NULL },
        { "and_v(v:pk(" K1 "),1)", 0, "tv:pk(" K1 ")" },
        { "or_i(0,pk(" K1 "))", 0, "l:pk(" K1 ")" },
        { "or_i(pk(" K1 "),0)", 0, "u:pk(" K1 ")" },
        { "or_i(0,0)", 0, "l:0" },
        { "nnnnnnnnnnn:pk(" K1 ")", 0, NULL },
        { "c:or_i(pk_k(" K1 "),pk_h(" K2 "))", 0, NULL },
        { "and_v(vc:or_i(pk_k(" K1 "),pk_h(" K2 ")),pk(" K3 "))", 0, NULL },
        /* and_v is the outermost expression, nesting to the left */
        { "and_v(v:pk(" K1 "),and_v(v:pk(" K2 "),pk(" K3 ")))", 0,
          "and_v(and_v(v:pk(" K1 "),v:pk(" K2 ")),pk(" K3 "))" },
        { "c:and_v(v:pk(" K1 "),pk_k(" K2 "))", 0, "and_v(v:pk(" K1 "),pk(" K2 "))" },
        { "and_b(pk(" K1 "),s:and_v(v:older(1),pk(" K2 ")))", 0, NULL },
        { "and_b(pk(" K1 "),a:and_v(v:pk(" K2 "),pk(" K3 ")))", 0, NULL },
        { "or_d(pk(" K1 "),and_v(v:pk(" K2 "),pk(" K3 ")))", 0, NULL },
        { "or_i(and_v(v:pk(" K1 "),pk(" K2 ")),and_v(v:pk(" K2 "),pk(" K3 ")))", 0, NULL },
        { "andor(pk(" K1 "),and_v(v:pk(" K2 "),pk(" K3 ")),and_v(v:pk(" K2 "),pk(" K1 ")))", 0, NULL },
        { "j:and_v(v:pk(" K1 "),pk(" K2 "))", 0, NULL },
        { "thresh(2,pk(" K1 "),a:andor(pk(" K2 "),pk(" K3 "),pk(" K1 ")),s:pk(" K3 "))", 0, NULL },
        { "and_b(pk(" K1 "),a:and_b(pk(" K2 "),a:pk(" K3 ")))", 0, NULL },
        { "thresh(1,pk(" K1 "),s:thresh(1,pk(" K2 ")))", 0, NULL },
        /* BIP-379 vectors */
        { "and_b(lltvln:after(1231488000),s:pk(03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))", 0, NULL },
        { "uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))", 0, NULL },
        { "or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))", 0, NULL },
        { "j:and_v(vdv:after(1567547623),older(16))", 0, NULL },
        { "t:and_v(vu:hash256(" H32 "),v:sha256(" H32 "))", 0, NULL },
        { "t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(" H32 "))", 0, NULL },
        { "or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))", 0, NULL },
        { "or_d(sha256(" H32 "),and_n(un:after(499999999),older(4194305)))", 0, NULL },
        { "and_v(or_i(v:multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb),v:multi(2,03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)),sha256(" H32 "))", 0, NULL },
        { "j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))", 0, NULL },
        { "and_b(older(16),s:or_d(sha256(" H32 "),n:after(1567547623)))", 0, NULL },
        { "j:and_v(v:ripemd160(" H20 "),or_d(sha256(" H32 "),older(16)))", 0, NULL },
        { "and_b(hash256(" H32 "),a:and_b(hash256(" H32 "),a:older(1)))", 0, NULL },
        { "thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))", 0,
          "thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:pk(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))" },
        { "and_n(sha256(" H32 "),t:or_i(v:older(4252898),v:older(16)))", 0, NULL },
        { "or_d(nd:and_v(v:older(4252898),v:older(4252898)),sha256(" H32 "))", 0, NULL },
        { "c:and_v(or_c(sha256(" H32 "),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk_k(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))", 0,
          "and_v(or_c(sha256(" H32 "),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))" },
        { "c:and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(" H20 ")),pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))", 0,
          "and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(" H20 ")),pk(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))" },
        { "and_v(andor(hash256(" H32 "),v:hash256(" H32 "),v:older(50000)),after(1231488000))", 0, NULL },
        { "andor(hash256(" H32 "),j:and_v(v:ripemd160(" H20 "),older(4194305)),ripemd160(" H20 "))", 0, NULL },
        { "or_i(c:and_v(v:after(500000),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(" H32 "))", 0,
          "or_i(and_v(v:after(500000),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(" H32 "))" },
        { "thresh(2,c:pk_h(025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(" H32 "),a:ripemd160(" H20 "))", 0,
          "thresh(2,pkh(025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(" H32 "),a:ripemd160(" H20 "))" },
        { "and_n(sha256(" H32 "),uc:and_v(v:older(16),pk_k(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))", 0,
          "and_n(sha256(" H32 "),u:and_v(v:older(16),pk(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))" },
        { "and_n(c:pk_k(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(15),a:older(16)))", 0,
          "and_n(pk(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(15),a:older(16)))" },
        { "c:or_i(and_v(v:older(16),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)),pk_h(026a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4))", 0, NULL },
        { "or_d(c:pk_h(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))", 0,
          "or_d(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),andor(pk(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))" },
        { "c:andor(ripemd160(" H20 "),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e),and_v(v:hash256(" H32 "),pk_h(03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)))", 0, NULL },
        { "c:andor(u:ripemd160(" H20 "),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),or_i(pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)))", 0, NULL },
        { "c:or_i(andor(c:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))", 0,
          "c:or_i(andor(pkh(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))" },
        { "thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00))", 0, NULL },
        /* Tapscript */
        { "or_d(pk(" X1 "),and_v(v:pkh(" X2 "),after(500000)))", TAP, NULL },
        { "andor(pk(" X1 "),multi_a(1," X2 "),sha256(" H32 "))", TAP, NULL },
        { "or_b(pk(" X1 "),s:pk(" X2 "))", TAP, NULL },
        { "j:and_v(v:hash160(" H20 "),multi_a(1," X1 "," X2 "))", TAP, NULL },
        { "or_d(pk(" X1 "),dv:older(1))", TAP, NULL },
    };
    struct wally_map keys;
    unsigned char script[1024];
    size_t i, written;
    bool ok = true;
    int ret;

    for (i = 0; i < NUM_ELEMS(cases); ++i) {
        const char *ms = cases[i].miniscript;
        const char *expected = cases[i].expected ? cases[i].expected : ms;
        const uint32_t other = cases[i].flags ^ TAP;

        wally_map_init(0, NULL, &keys);
        ret = to_script(ms, cases[i].flags, script, sizeof(script), &written, &keys);
        if (!check(ret == WALLY_OK, "round trip: parse", ms))
            ok = false;
        else {
            ok &= check(decode(script, written, &keys, cases[i].flags, expected) == WALLY_OK,
                        "round trip: decode", ms);
            /* Scripts with keys are only valid in one context */
            if (keys.num_items)
                ok &= check(decode(script, written, &keys, other, NULL) != WALLY_OK,
                            "round trip: decode in the wrong context", ms);
        }
        wally_map_clear(&keys);
    }
    return ok;
}

#define PUSH_K1 "21" K1
#define PUSH_K2 "21" K2
#define PUSH_K3 "21" K3
#define PUSH_X1 "20" X1
#define PUSH_X2 "20" X2

/* Decoding, without type checking */
static bool test_decode(void)
{
    static const struct {
        const char *script;
        uint32_t flags;
        const char *expected;
    } cases[] = {
        { "51", 0, "1" },
        { "00", 0, "0" },
        { PUSH_K1, 0, "pk_k(" K1 ")" },
        { PUSH_X1, TAP, "pk_k(" X1 ")" },
        { PUSH_K1 "ad", 0, "v:pk(" K1 ")" },
        { PUSH_K1 "ac" PUSH_K2 "ac" PUSH_K3 "ac", 0,
          "and_v(and_v(pk(" K1 "),pk(" K2 ")),pk(" K3 "))" },
        /* The W operand is a:X if the operator follows OP_FROMALTSTACK,
         * otherwise s:X, where X is everything after the OP_SWAP */
        { PUSH_K1 "ac7c" PUSH_K2 "ac" PUSH_K3 "ac9a", 0,
          "and_b(pk(" K1 "),s:and_v(pk(" K2 "),pk(" K3 ")))" },
        { PUSH_K1 "ac7c" PUSH_K2 "ac6b" PUSH_K3 "ac6c9a9a", 0,
          "and_b(pk(" K1 "),s:and_b(pk(" K2 "),a:pk(" K3 ")))" },
        { PUSH_K1 "ac7c" PUSH_K2 "ac6b" PUSH_K3 "ac6c9351879a", 0,
          "and_b(pk(" K1 "),s:thresh(1,pk(" K2 "),a:pk(" K3 ")))" },
        /* Operands are single expressions */
        { PUSH_K1 "ac" PUSH_K2 "ac6b" PUSH_K3 "ac6c9b", 0,
          "and_v(pk(" K1 "),or_b(pk(" K2 "),a:pk(" K3 ")))" },
        { PUSH_K1 "ac" PUSH_K2 "ac64" PUSH_K3 "ac68", 0,
          "and_v(pk(" K1 "),or_c(pk(" K2 "),pk(" K3 ")))" },
        { PUSH_K1 "ac" PUSH_K2 "ac5187", 0,
          "and_v(pk(" K1 "),thresh(1,pk(" K2 ")))" },
        { PUSH_X1 "ac" PUSH_X2 "ac519c", TAP,
          "and_v(pk(" X1 "),multi_a(1," X2 "))" },
    };
    char *text;
    size_t i;
    bool ok = true;
    unsigned char script[256];
    size_t written;

    for (i = 0; i < NUM_ELEMS(cases); ++i) {
        if (wally_hex_to_bytes(cases[i].script, script, sizeof(script), &written) != WALLY_OK ||
            ms_script_to_miniscript(script, written, NULL, cases[i].flags, &text) != WALLY_OK)
            ok &= check(false, "decode", cases[i].expected);
        else {
            ok &= check(!strcmp(text, cases[i].expected), "decode", text);
            wally_free_string(text);
        }
    }
    return ok;
}

/* Decode a hex script, returning the result */
static int decode_hex(const char *hex, uint32_t flags, bool parse,
                      const struct wally_map *keys)
{
    unsigned char script[MS_DECODE_MAX_SCRIPT_LEN_SEGWIT_V0 + 1];
    struct wally_descriptor *d;
    char *text;
    size_t written;
    int ret = wally_hex_to_bytes(hex, script, sizeof(script), &written);

    if (ret == WALLY_OK && written > sizeof(script))
        ret = WALLY_ERROR;
    if (ret == WALLY_OK) {
        if (parse) {
            ret = ms_descriptor_from_script(script, written, keys, flags, &d);
            if (ret == WALLY_OK)
                wally_descriptor_free(d);
        } else {
            ret = ms_script_to_miniscript(script, written, keys, flags, &text);
            if (ret == WALLY_OK)
                wally_free_string(text);
        }
    }
    return ret;
}

static bool test_invalid(void)
{
    static const struct {
        const char *script;
        uint32_t flags;
        const char *comment;
    } cases[] = {
        { "", 0, "Empty script" },
        { "21" "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817", 0, "Truncated push" },
        { "4c21" K1 "ac", 0, "Non-minimal push" },
        { "0105b2", 0, "Non-minimal number push" },
        { "020500b2", 0, "Non-minimally encoded number" },
        { "4f", 0, "OP_1NEGATE" },
        { "52", 0, "A number that is not 0 or 1" },
        { PUSH_K1 "ac69", 0, "OP_CHECKSIG OP_VERIFY" },
        { "82012088a820" H32 "8769" PUSH_K1 "ac", 0, "OP_EQUAL OP_VERIFY" },
        { "82012087" "69a820" H32 "87", 0, "Hash with OP_EQUAL OP_VERIFY" },
        { "82012188a820" H32 "87", 0, "Hash size not 32" },
        { "82012088a814" H20 "87", 0, "SHA256 with a 20 byte hash" },
        { "82012088a820" H32 "ac", 0, "Hash without OP_EQUAL" },
        { PUSH_X1 "ac", 0, "x-only key in segwit v0" },
        { PUSH_K1 "ac", TAP, "Compressed key in tapscript" },
        { "4104" "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
          "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac", 0, "Uncompressed key" },
        { "1400112233445566778899aabbccddeeff00112233ac", 0, "20 byte push" },
        { "00b2", 0, "older(0)" },
        { "0500000080 00b2", 0, "older(2^31)" },
        { "0400000080b2", 0, "older(-0)" },
        { "04ffffff7fb2", 0, "older(2^31-1), beyond the 16 bit lock value" },
        { "00b1", 0, "after(0)" },
        { PUSH_K1 "ac0087", 0, "thresh(0,...)" },
        { PUSH_K1 "ac5287", 0, "thresh(2,X)" },
        { PUSH_K1 "ac7c" PUSH_K2 "ac935387", 0, "thresh(3,X,Y)" },
        { "5187", 0, "thresh without a sub-expression" },
        { PUSH_K1 "ac6b" PUSH_K2 "ac6c", 0, "a: without operator" },
        { PUSH_K1 "ac6b" PUSH_K2 "ac6c" PUSH_K1 "ac9a", 0, "a: not used immediately" },
        { "6b" PUSH_K2 "ac6c9a", 0, "a: without first operand" },
        { PUSH_K1 "ac7c" PUSH_K2 "ac", 0, "s: without operator" },
        { PUSH_K1 "ac" PUSH_K2 "ac9a", 0, "and_b without W operand" },
        { PUSH_K1 "ac" PUSH_K2 "ac93", 0, "thresh without W operand" },
        { PUSH_K1 "ac7c" PUSH_K2 "ac93", 0, "Incomplete thresh" },
        { PUSH_K1 "ac7c" PUSH_K2 "ac93" PUSH_K1 "ac5187", 0, "Interrupted thresh" },
        { PUSH_K1 "ac6c", 0, "OP_FROMALTSTACK without OP_TOALTSTACK" },
        { PUSH_K1 "ac6b" PUSH_K2 "ac", 0, "Unterminated a:" },
        { "63" PUSH_K1 "ac68", 0, "OP_IF X OP_ENDIF" },
        { "63" PUSH_K1 "ac67" PUSH_K2 "ac", 0, "Unterminated or_i" },
        { "63" PUSH_K1 "ac67" "68", 0, "Empty or_i branch" },
        { "6367" PUSH_K1 "ac68", 0, "Empty or_i branch" },
        { PUSH_K1 "ac68", 0, "OP_ENDIF without OP_IF" },
        { PUSH_K1 "ac67", 0, "OP_ELSE without OP_IF" },
        { "64" PUSH_K1 "ac68", 0, "OP_NOTIF without condition" },
        { PUSH_K1 "ac73" PUSH_K2 "ac68", 0, "OP_IFDUP without OP_NOTIF" },
        { PUSH_K1 "ac7364" PUSH_K2 "ac67" PUSH_K2 "ac68", 0, "or_d with OP_ELSE" },
        { PUSH_K1 "ac6467" PUSH_K2 "ac68", 0, "Empty or_c branch" },
        { "7663" PUSH_K1 "ac67" PUSH_K2 "ac68", 0, "d: with OP_ELSE" },
        { "829263" PUSH_K1 "ac67" PUSH_K2 "ac68", 0, "j: with OP_ELSE" },
        { "7663" PUSH_K1 "ac", 0, "Unterminated d:" },
        { "76", 0, "OP_DUP alone" },
        { "82", 0, "OP_SIZE alone" },
        { "ac", 0, "OP_CHECKSIG without operand" },
        { "69", 0, "OP_VERIFY without operand" },
        { "92", 0, "OP_0NOTEQUAL without operand" },
        { PUSH_K1 "ac9c", 0, "Unsupported opcode" },
        { "51" PUSH_K1 PUSH_K2 "51ae", 0, "multi with too few keys" },
        { "51" PUSH_K1 PUSH_K2 "53ae", 0, "multi with too many keys" },
        { "53" PUSH_K1 PUSH_K2 "52ae", 0, "multi(3) of 2 keys" },
        { "00" PUSH_K1 "51ae", 0, "multi(0)" },
        { "5100ae", 0, "multi with no keys" },
        { "51" PUSH_X1 PUSH_X2 "52ae", TAP, "multi in tapscript" },
        { PUSH_X1 "ac" PUSH_X2 "ba519c", 0, "multi_a in segwit v0" },
        { PUSH_X1 "ac" PUSH_X2 "ba539c", TAP, "multi_a(3) of 2 keys" },
        { PUSH_X1 "ac" PUSH_X2 "ba009c", TAP, "multi_a(0)" },
        { PUSH_X1 "ba" PUSH_X2 "ba519c", TAP, "multi_a without OP_CHECKSIG" },
        { PUSH_X1 "ac" PUSH_X2 "ba519c69", TAP, "OP_NUMEQUAL OP_VERIFY" },
        { PUSH_K1 "ac929292929292929292929292", 0, "12 wrappers" },
        { "76a914" H20 "88ac", 0, "pk_h with an unknown key" },
    };
    size_t i;
    bool ok = true;

    for (i = 0; i < NUM_ELEMS(cases); ++i) {
        char hex[1024];
        size_t j, n = 0;
        /* Remove any spaces */
        for (j = 0; cases[i].script[j]; ++j)
            if (cases[i].script[j] != ' ')
                hex[n++] = cases[i].script[j];
        hex[n] = '\0';
        ok &= check(decode_hex(hex, cases[i].flags, false, NULL) == WALLY_EINVAL,
                    "invalid script", cases[i].comment);
    }
    return ok;
}

/* Scripts that decode, but not to a valid miniscript */
static bool test_invalid_type(void)
{
    static const struct {
        const char *script;
        uint32_t flags;
        const char *comment;
    } cases[] = {
        { PUSH_K1, 0, "pk_k() alone is type K" },
        { PUSH_K1 "ad", 0, "v:pk() alone is type V" },
        { PUSH_K1 "ac" PUSH_K2 "ac", 0, "and_v(pk(),pk()) is not V,B" },
        { "51b27c52b29b", 0, "or_b(older(1),s:older(2))" },
        { PUSH_K1 "ac64" PUSH_K2 "ac68", 0, "or_c with B second operand" },
        { PUSH_X1 "ac" PUSH_X2 "ac519c", TAP, "and_v(pk(),multi_a()) is not V,B" },
        { "51", 0, "1 (unsupported by the parser)" },
    };
    size_t i;
    bool ok = true;

    for (i = 0; i < NUM_ELEMS(cases); ++i)
        ok &= check(decode_hex(cases[i].script, cases[i].flags, true, NULL) == WALLY_EINVAL,
                    "invalid type", cases[i].comment);
    return ok;
}

static bool test_limits(void)
{
    unsigned char script[MS_DECODE_MAX_SCRIPT_LEN_SEGWIT_V0 + 1];
    struct wally_descriptor *d;
    size_t i, depth, len;
    bool ok = true;
    char *text;

    /* Nesting depth: or_i(or_i(...(1,1)...,1),1) */
    for (depth = MS_DECODE_MAX_DEPTH - 1; depth <= MS_DECODE_MAX_DEPTH; ++depth) {
        len = 0;
        for (i = 0; i < depth; ++i)
            script[len++] = OP_IF;
        script[len++] = OP_1;
        for (i = 0; i < depth; ++i) {
            script[len++] = OP_ELSE;
            script[len++] = OP_1;
            script[len++] = OP_ENDIF;
        }
        /* An expression of depth+1, as there are depth or_i's around 1 */
        if (depth + 1 <= MS_DECODE_MAX_DEPTH) {
            ok &= check(ms_descriptor_from_script(script, len, NULL, 0, &d) == WALLY_OK,
                        "limits", "maximum depth");
            wally_descriptor_free(d);
        } else
            ok &= check(ms_script_to_miniscript(script, len, NULL, 0, &text) == WALLY_EINVAL,
                        "limits", "too deep");
    }

    /* Script length: thresh(1,1,s:1,...) */
    len = 0;
    script[len++] = OP_1;
    while (len < MS_DECODE_MAX_SCRIPT_LEN_SEGWIT_V0 - 2) {
        script[len++] = OP_SWAP;
        script[len++] = OP_1;
        script[len++] = OP_ADD;
    }
    script[len++] = OP_1;
    script[len++] = OP_EQUAL;
    ok &= check(ms_script_to_miniscript(script, len, NULL, 0, &text) == WALLY_OK,
                "limits", "maximum length");
    wally_free_string(text);
    script[len - 1] = OP_EQUALVERIFY;
    script[len++] = OP_1;
    ok &= check(ms_script_to_miniscript(script, len, NULL, 0, &text) == WALLY_EINVAL,
                "limits", "too long");
    ok &= check(ms_script_to_miniscript(script, len, NULL, TAP, &text) == WALLY_OK,
                "limits", "tapscript length");
    wally_free_string(text);

    /* Scripts larger than 520 bytes: multi() with 20 keys, and
     * and_v(...and_v(v:pk(K1),v:pk(K2))...,pk(K20)) */
    for (i = 0; i < 4; ++i) {
        const bool is_multi = i % 2 == 0, is_tapscript = i >= 2;
        const size_t key_len = is_tapscript ? EC_XONLY_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_LEN;
        unsigned char priv[EC_PRIVATE_KEY_LEN] = { 0 }, pub[EC_PUBLIC_KEY_LEN];
        size_t j;

        if (is_multi && is_tapscript)
            continue;
        len = 0;
        if (is_multi)
            script[len++] = OP_1;
        for (j = 0; j < 20; ++j) {
            priv[EC_PRIVATE_KEY_LEN - 1] = j + 1;
            wally_ec_public_key_from_private_key(priv, sizeof(priv), pub, sizeof(pub));
            script[len++] = key_len;
            memcpy(script + len, pub + EC_PUBLIC_KEY_LEN - key_len, key_len);
            len += key_len;
            if (!is_multi)
                script[len++] = j == 19 ? OP_CHECKSIG : OP_CHECKSIGVERIFY;
        }
        if (is_multi) {
            script[len++] = 1;
            script[len++] = 20;
            script[len++] = OP_CHECKMULTISIG;
        }
        ok &= check(ms_descriptor_from_script(script, len, NULL,
                                              is_tapscript ? TAP : 0, &d) == WALLY_OK,
                    "limits", is_multi ? "multi() with 20 keys" : "large script");
        wally_descriptor_free(d);
    }

    /* Invalid arguments */
    ok &= check(ms_script_to_miniscript(NULL, 1, NULL, 0, &text) == WALLY_EINVAL, "args", "NULL script");
    ok &= check(ms_script_to_miniscript(script, 0, NULL, 0, &text) == WALLY_EINVAL, "args", "empty script");
    ok &= check(ms_script_to_miniscript(script, 1, NULL, 0x2, &text) == WALLY_EINVAL, "args", "bad flags");
    ok &= check(ms_script_to_miniscript(script, 1, NULL, 0, NULL) == WALLY_EINVAL, "args", "NULL output");
    ok &= check(ms_descriptor_from_script(script, 1, NULL, 0, NULL) == WALLY_EINVAL, "args", "NULL output");
    return ok;
}

int main(void)
{
    bool ok = test_round_trip();
    ok &= test_decode();
    ok &= test_invalid();
    ok &= test_invalid_type();
    ok &= test_limits();
    wally_cleanup(0);
    return ok ? 0 : 1;
}
