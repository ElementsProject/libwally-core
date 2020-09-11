#include "config.h"

#include <wally_core.h>
#include <wally_address.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

/*
   {
   pubkey: '038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048',
   privkey: 'cNha6ams8o6qokphL3XfcUTRs7ggweD3SWn7YXLtB3Rrm3QDNxD4'
   },{
   pubkey: '03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7',
   privkey: 'cQbGCCA1P9aGWiyrGVXueofGJZmQAHBQhrrsX49rsExFKzeGTXT2'
   },{
   pubkey: '03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284',
   privkey: 'cQezKD6V8dtqkLz1Mh6JHYiz1TsZBXyizTtzY1xm3pqdMsxJ6wXT'
   },{
   pubkey: '04a238b0cbea14c9b3f59d0a586a82985f69af3da50579ed5971eefa41e6758ee7f1d77e4d673c6e7aac39759bb762d22259e27bf93572e9d5e363d5a64b6c062b',
   privkey: 'bc2f39635ef2e24b4689345fb68c615987b6b0388fdffb57f907bd44445603a4'
   }
 */

struct wally_miniscript_ref_test {
    const char *miniscript;
    const char *scriptpubkey;
};

struct wally_miniscript_test {
    const char *name;
    const char *descriptor;
    const char *scriptpubkey;
    const char *miniscript;
    const char *p2wsh_scriptpubkey;
};

struct wally_descriptor_test {
    const char *name;
    const char *descriptor;
    const char *scriptpubkey;
    const uint32_t *bip32_index;
    const char *checksum;
};

struct wally_descriptor_depth_test {
    const char *name;
    const char *descriptor;
    const uint32_t depth;
    const uint32_t index;
    const char *scriptpubkey;
};

struct wally_descriptor_address_test {
    const char *name;
    const char *descriptor;
    const uint32_t bip32_index;
    const uint32_t network;
    const char *address;
};

struct wally_descriptor_address_list_test {
    const char *name;
    const char *descriptor;
    const uint32_t start_index;
    const uint32_t end_index;
    const uint32_t network;
    const size_t address_list_num;
    const char *address_list[30];
};

struct wally_descriptor_err_test {
    const char *name;
    const char *descriptor;
    const uint32_t network;
};

static const char *const g_miniscript_keyname_list[] = {
    "key_1",
    "key_2",
    "key_3",
    "key_likely",
    "key_unlikely",
    "key_user",
    "key_service",
    "key_local",
    "key_remote",
    "key_revocation",
    "H", /* HASH160(key_local) */
};

static const uint32_t g_miniscript_index_0 = 0;
static const uint32_t g_miniscript_index_16 = 0x10;

static const char *const g_miniscript_keyvalue_list[] = {
    "038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048",
    "03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7",
    "03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284",
    "038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048",
    "03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7",
    "038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048",
    "03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7",
    "038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048",
    "03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7",
    "03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284",
    "d0721279e70d39fb4aa409b52839a0056454e3b5", /* HASH160(key_local) */
};

struct wally_miniscript_ref_test g_miniscript_ref_test_table[] = {
    /* Randomly generated test set that covers the majority of type and node type combinations */
    {"lltvln:after(1231488000)", "6300676300676300670400046749b1926869516868"},
    {"uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))", "6363829263522103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a21025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc52af0400046749b168670068670068"},
    {"or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))", "63522103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee872921024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae926700686b63006760b2686c9b"},
    {"j:and_v(vdv:after(1567547623),older(2016))", "829263766304e7e06e5db169686902e007b268"},
    {"t:and_v(vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5))", "6382012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876700686982012088a820ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc58851"},
    {"t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))", "532102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975562102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1353ae6482012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2886703010040b2696851"},
    {"or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))", "512102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f951ae73645321022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a0121032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f2103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a53ae7c630320a107b16700689b68"},
    {"or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305)))", "82012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68773646304ff64cd1db19267006864006703010040b26868"},
    {"and_v(or_i(v:multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb),v:multi(2,03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)),sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68))", "63522102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb52af67522103e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a21025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc52af6882012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c6887"},
    {"j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))", "82926352210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae7c6351b26703e2e440b2689a68"},
    {"and_b(older(16),s:or_d(sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),n:after(1567547623)))", "60b27c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87736404e7e06e5db192689a"},
    {"j:and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))", "82926382012088a91420195b5a3d650c17f0f29f91c33f8f6335193d078882012088a82096de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c4787736460b26868"},
    {"and_b(hash256(32ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac),a:and_b(hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),a:older(1)))", "82012088aa2032ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac876b82012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876b51b26c9a6c9a"},
    {"thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))", "522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287"},
    {"and_n(sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68),t:or_i(v:older(4252898),v:older(144)))", "82012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68876400676303e2e440b26967029000b269685168"},
    {"or_d(d:and_v(v:older(4252898),v:older(4252898)),sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6))", "766303e2e440b26903e2e440b26968736482012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68768"},
    {"c:and_v(or_c(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk_k(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))", "82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764512102c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db51af682103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbeac"},
    {"c:and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(1b0f3c404d12075c68c938f9f60ebea4f74941a0)),pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))", "5221036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a002102352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d552ae6482012088a6141b0f3c404d12075c68c938f9f60ebea4f74941a088682103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ac"},
    {"and_v(andor(hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),v:hash256(939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735),v:older(50000)),after(499999999))", "82012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b2587640350c300b2696782012088aa20939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735886804ff64cd1db1"},
    {"andor(hash256(5f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040),j:and_v(v:hash160(3a2bff0da9d96868e66abc4427bea4691cf61ccd),older(4194305)),ripemd160(44d90e2d3714c8663b632fcf0f9d5f22192cc4c8))", "82012088aa205f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040876482012088a61444d90e2d3714c8663b632fcf0f9d5f22192cc4c8876782926382012088a9143a2bff0da9d96868e66abc4427bea4691cf61ccd8803010040b26868"},
    {"or_i(c:and_v(v:after(500000),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946))", "630320a107b1692102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac6782012088a820d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f9468768"},
    {"thresh(2,c:pk_h(025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))", "76a9145dedfbf9ea599dd4e3ca6a80b333c472fd0b3f6988ac7c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87936b82012088a914dd69735817e0e3f6f826a9238dc2e291184f0131876c935287"},
    {"and_n(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),uc:and_v(v:older(144),pk_k(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))", "82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764006763029000b2692103fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ceac67006868"},
    {"and_n(c:pk_k(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(4252898),a:older(16)))", "2103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729ac64006763006703e2e440b2686b60b26c9a68"},
    {"c:or_i(and_v(v:older(16),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)),pk_h(026a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4))", "6360b26976a9149fc5dbe5efdce10374a4dd4053c93af540211718886776a9142fbd32c8dd59ee7c17e66cb6ebea7e9846c3040f8868ac"},
    {"or_d(c:pk_h(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))", "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac736421024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97ac6404e7e06e5db16702e007b26868"},
    {"c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)))", "82012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba876482012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b258876a914dd100be7d9aea5721158ebde6d6a1fd8fff93bb1886776a9149fc5dbe5efdce10374a4dd4053c93af5402117188868ac"},
    {"c:andor(u:ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),or_i(pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)))", "6382012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba87670068646376a9149652d86bedf43ad264362e6e6eba6eb764508127886776a914751e76e8199196d454941c45d1b3a323f1433bd688686776a91420d637c1a6404d2227f3561fdbaff5a680dba6488868ac"},
    {"c:or_i(andor(c:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))", "6376a914fcd35ddacad9f2d5be5e464639441c6065e6955d88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9149652d86bedf43ad264362e6e6eba6eb7645081278868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac"},
};

struct wally_miniscript_test g_miniscript_test_table[] = {
    {
        "miniscript - A single key",
        "c:pk_k(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048)",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac",
        "c:pk_k(key_1)",
        "0020fa5bf4aae3ee617c6cce1976f6d7d285c359613ffeed481f1067f62bc0f54852"
    },
    {
        "miniscript - One of two keys (equally likely)",
        "or_b(c:pk_k(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),sc:pk_k(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7))",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac7c2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac9b",
        "or_b(c:pk_k(key_1),sc:pk_k(key_2))",
        "002018a9df986ba10bcd8f503f495cab5fd00c9fb23c05143e65dbba49ef4d8a825f"
    },
    {
        "miniscript - A user and a 2FA service need to sign off, but after 90 days the user alone is enough",
        "and_v(vc:pk_k(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),or_d(c:pk_k(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7),older(12960)))",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ad2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac736402a032b268",
        "and_v(vc:pk_k(key_user),or_d(c:pk_k(key_service),older(12960)))",
        "00201264946c666958d9522f63dcdcfc85941bdd5b9308b1e6c68696857506f6cced"
    },
    {
        "miniscript - A 3-of-3 that turns into a 2-of-3 after 90 days",
        "thresh(3,c:pk_k(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),sc:pk_k(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7),sc:pk_k(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284),sdv:older(12960))",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac7c2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac937c2103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac937c766302a032b26968935387",
        "thresh(3,c:pk_k(key_1),sc:pk_k(key_2),sc:pk_k(key_3),sdv:older(12960))",
        "0020ab3551bec623130218a9ca5da0e3adb82b8569f91355a483653a49f2a2dd6e70"
    },
    {
        "miniscript - The BOLT #3 to_local policy",
        "andor(c:pk_k(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),older(1008),c:pk_k(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284))",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac6702f003b268",
        "andor(c:pk_k(key_local),older(1008),c:pk_k(key_revocation))",
        "0020052cf1e9c90e9a2883d890467a6a01837e21b3b755a743c9d96a2b6f8285d7c0"
    },
    {
        "miniscript - The BOLT #3 offered HTLC policy ",
        "t:or_c(c:pk_k(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284),and_v(vc:pk_k(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7),or_c(c:pk_k(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),v:hash160(d0721279e70d39fb4aa409b52839a0056454e3b5))))",
        "2103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac642103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ad21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac6482012088a914d0721279e70d39fb4aa409b52839a0056454e3b588686851",
        "t:or_c(c:pk_k(key_revocation),and_v(vc:pk_k(key_remote),or_c(c:pk_k(key_local),v:hash160(H))))",
        "0020f9259363db0facc7b97ab2c0294c4f21a0cd56b01bb54ecaaa5899012aae1bc2"
    },
    {
        "miniscript - The BOLT #3 received HTLC policy ",
        "andor(c:pk_k(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7),or_i(and_v(vc:pk_h(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),hash160(d0721279e70d39fb4aa409b52839a0056454e3b5)),older(1008)),c:pk_k(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284))",
        "2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac676376a914d0721279e70d39fb4aa409b52839a0056454e3b588ad82012088a914d0721279e70d39fb4aa409b52839a0056454e3b5876702f003b26868",
        "andor(c:pk_k(key_remote),or_i(and_v(vc:pk_h(key_local),hash160(H)),older(1008)),c:pk_k(key_revocation))",
        "002087515e0059c345eaa5cccbaa9cd16ad1266e7a69e350db82d8e1f33c86285303"
    },
    {
        "miniscript(2) - A single key",
        "pk(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048)",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac",
        "pk(key_1)",
        "0020fa5bf4aae3ee617c6cce1976f6d7d285c359613ffeed481f1067f62bc0f54852"
    },
    {
        "miniscript(2) - One of two keys (equally likely)",
        "or_b(pk(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),s:pk(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7))",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac7c2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac9b",
        "or_b(pk(key_1),s:pk(key_2))",
        "002018a9df986ba10bcd8f503f495cab5fd00c9fb23c05143e65dbba49ef4d8a825f"
    },
    {
        "miniscript(2) - A user and a 2FA service need to sign off, but after 90 days the user alone is enough",
        "and_v(v:pk(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),or_d(pk(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7),older(12960)))",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ad2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac736402a032b268",
        "and_v(v:pk(key_user),or_d(pk(key_service),older(12960)))",
        "00201264946c666958d9522f63dcdcfc85941bdd5b9308b1e6c68696857506f6cced"
    },
    {
        "miniscript(2) - A 3-of-3 that turns into a 2-of-3 after 90 days",
        "thresh(3,pk(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),s:pk(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7),s:pk(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284),sdv:older(12960))",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac7c2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac937c2103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac937c766302a032b26968935387",
        "thresh(3,pk(key_1),s:pk(key_2),s:pk(key_3),sdv:older(12960))",
        "0020ab3551bec623130218a9ca5da0e3adb82b8569f91355a483653a49f2a2dd6e70"
    },
    {
        "miniscript(2) - The BOLT #3 to_local policy",
        "andor(pk(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),older(1008),pk(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284))",
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac6702f003b268",
        "andor(pk(key_local),older(1008),pk(key_revocation))",
        "0020052cf1e9c90e9a2883d890467a6a01837e21b3b755a743c9d96a2b6f8285d7c0"
    },
    {
        "miniscript(2) - The BOLT #3 offered HTLC policy ",
        "t:or_c(pk(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284),and_v(v:pk(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7),or_c(pk(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),v:hash160(d0721279e70d39fb4aa409b52839a0056454e3b5))))",
        "2103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac642103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ad21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac6482012088a914d0721279e70d39fb4aa409b52839a0056454e3b588686851",
        "t:or_c(pk(key_revocation),and_v(v:pk(key_remote),or_c(pk(key_local),v:hash160(H))))",
        "0020f9259363db0facc7b97ab2c0294c4f21a0cd56b01bb54ecaaa5899012aae1bc2"
    },
    {
        "miniscript(2) - The BOLT #3 received HTLC policy ",
        "andor(pk(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7),or_i(and_v(v:pkh(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),hash160(d0721279e70d39fb4aa409b52839a0056454e3b5)),older(1008)),pk(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284))",
        "2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac676376a914d0721279e70d39fb4aa409b52839a0056454e3b588ad82012088a914d0721279e70d39fb4aa409b52839a0056454e3b5876702f003b26868",
        "andor(pk(key_remote),or_i(and_v(v:pkh(key_local),hash160(H)),older(1008)),pk(key_revocation))",
        "002087515e0059c345eaa5cccbaa9cd16ad1266e7a69e350db82d8e1f33c86285303"
    },
    {
        "miniscript(2) - The BOLT #3 received HTLC policy ",
        "andor(pk(03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7),or_i(and_v(v:pkh(038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048),hash160(d0721279e70d39fb4aa409b52839a0056454e3b5)),older(1008)),pk(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284))",
        "2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac676376a914d0721279e70d39fb4aa409b52839a0056454e3b588ad82012088a914d0721279e70d39fb4aa409b52839a0056454e3b5876702f003b26868",
        "andor(pk(key_remote),or_i(and_v(v:pkh(key_local),hash160(H)),older(1008)),pk(key_revocation))",
        "002087515e0059c345eaa5cccbaa9cd16ad1266e7a69e350db82d8e1f33c86285303"
    },
};

struct wally_descriptor_test g_descriptor_test_table[] = {
    {
        "descriptor - p2pk",
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7",
        "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        NULL,
        "gn28ywm7"
    },{
        "descriptor - p2pkh",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac",
        NULL,
        "8fhd9pwu"
    },{
        "descriptor - p2wpkh",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc",
        NULL,
        "8zl0zxma"
    },{
        "descriptor - p2sh-p2wpkh",
        "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        "a914cc6ffbc0bf31af759451068f90ba7a0272b6b33287",
        NULL,
        "qkrrc7je"
    },{
        "descriptor - combo(p2wpkh)",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        NULL,
        "lq9sf04s"
    },{
        "descriptor - combo(p2pkh)",
        "combo(04a238b0cbea14c9b3f59d0a586a82985f69af3da50579ed5971eefa41e6758ee7f1d77e4d673c6e7aac39759bb762d22259e27bf93572e9d5e363d5a64b6c062b)",
        "76a91448cb866ee3edb295e4cfeb3da65b4003ab9fa6a288ac",
        NULL,
        "r3wj6k68"
    },{
        "descriptor - p2sh-p2wsh",
        "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
        "a91455e8d5e8ee4f3604aba23c71c2684fa0a56a3a1287",
        NULL,
        "2wtr0ej5"
    },{
        "descriptor - multisig",
        "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)",
        "5121022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe421025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc52ae",
        NULL,
        "hzhjw406"
    },{
        "descriptor - p2sh-multi",
        "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
        "a914a6a8b030a38762f4c1f5cbe387b61a3c5da5cd2687",
        NULL,
        "y9zthqta"
    },{
        "descriptor - p2sh-sortedmulti",
        "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))",
        "a914a6a8b030a38762f4c1f5cbe387b61a3c5da5cd2687",
        NULL,
        "qwx6n9lh"
    },{
        "descriptor - p2wsh-multi",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        "0020773d709598b76c4e3b575c08aad40658963f9322affc0f8c28d1d9a68d0c944a",
        NULL,
        "en3tu306"
    },{
        "descriptor - p2sh-p2wsh-multi",
        "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        "a914aec509e284f909f769bb7dda299a717c87cc97ac87",
        NULL,
        "ks05yr6p"
    },{
        "descriptor - p2pk-xpub",
        "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)",
        "210339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2ac",
        NULL,
        "axav5m0j"
    },{
        "descriptor - p2pkh-xpub-derive",
        "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)",
        "76a914f833c08f02389c451ae35ec797fccf7f396616bf88ac",
        NULL,
        "kczqajcv"
    },{
        "descriptor - p2pkh-parent-derive",
        "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)",
        "76a914d234825a563de8b4fd31d2b30f60b1e60fe57ee788ac",
        &g_miniscript_index_16,
        "ml40v0wf"
    },{
        "descriptor - p2wsh-multi-xpub",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        "00204616bb4e66d0b540b480c5b26c619385c4c2b83ed79f4f3eab09b01745443a55",
        &g_miniscript_index_16,
        "t2zpj2eu"
    },{
        "descriptor - p2wsh-sortedmulti-xpub",
        "wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        "002002aeee9c3773dfecfe6215f2eea2908776b1232513a700e1ee516b634883ecb0",
        &g_miniscript_index_16,
        "v66cvalc"
    },{
        "descriptor - addr-btc-legacy-testnet",
        "addr(moUfpGiXWcFd5ueRn3988VDqRSkB5NrEmW)",
        "76a91457526b1a1534d4bde788253281649fc2e91dc70b88ac",
        NULL,
        "9amhxcar"
    },{
        "descriptor - addr-btc-segwit-mainnet",
        "addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        NULL,
        "8kzm8txf"
    },{
        "descriptor - raw-checksum",
        "raw(6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e)#zf2avljj",
        "6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e",
        NULL,
        "zf2avljj"
    },{
        "descriptor - p2pkh-xpriv",
        "pkh(xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU/1h/2)",
        "76a914b28d12ab72a51b10114b17ce76b536265194e1fb88ac",
        NULL,
        "wghlxksl"
    },{
        "descriptor - p2pkh-privkey-wif mainnet",
        "pkh(L1AAHuEC7XuDM7pJ7yHLEqYK1QspMo8n1kgxyZVdgvEpVC1rkUrM)",
        "76a91492ed3283cfb01caec1163aefba29caf1182f478e88ac",
        NULL,
        "qm00tjwh"
    },{
        "descriptor - p2pkh-privkey-wif testnet uncompress",
        "pkh(936Xapr4wpeuiKToGeXtEcsVJAfE6ze8KUEb2UQu72rzBQsMZdX)",
        "76a91477b6f27ac523d8b9aa8abcfc94fd536493202ae088ac",
        NULL,
        "9gv5p2gj"
    },{
        "descriptor - A single key",
        "wsh(c:pk_k(key_1))",
        "0020fa5bf4aae3ee617c6cce1976f6d7d285c359613ffeed481f1067f62bc0f54852",
        NULL,
        "k05wwvdw"
    },{
        "descriptor - One of two keys (equally likely)",
        "wsh(or_b(c:pk_k(key_1),sc:pk_k(key_2)))",
        "002018a9df986ba10bcd8f503f495cab5fd00c9fb23c05143e65dbba49ef4d8a825f",
        NULL,
        "4dxelu43"
    },{
        "descriptor - A user and a 2FA service need to sign off, but after 90 days the user alone is enough",
        "wsh(and_v(vc:pk_k(key_user),or_d(c:pk_k(key_service),older(12960))))",
        "00201264946c666958d9522f63dcdcfc85941bdd5b9308b1e6c68696857506f6cced",
        NULL,
        "7sxzh689"
    },{
        "descriptor - A 3-of-3 that turns into a 2-of-3 after 90 days",
        "wsh(thresh(3,c:pk_k(key_1),sc:pk_k(key_2),sc:pk_k(key_3),sdv:older(12960)))",
        "0020ab3551bec623130218a9ca5da0e3adb82b8569f91355a483653a49f2a2dd6e70",
        NULL,
        "vvsamau0"
    },{
        "descriptor - The BOLT #3 to_local policy",
        "wsh(andor(c:pk_k(key_local),older(1008),c:pk_k(key_revocation)))",
        "0020052cf1e9c90e9a2883d890467a6a01837e21b3b755a743c9d96a2b6f8285d7c0",
        NULL,
        "0j0vrece"
    },{
        "descriptor - The BOLT #3 offered HTLC policy",
        "wsh(t:or_c(c:pk_k(key_revocation),and_v(vc:pk_k(key_remote),or_c(c:pk_k(key_local),v:hash160(H)))))",
        "0020f9259363db0facc7b97ab2c0294c4f21a0cd56b01bb54ecaaa5899012aae1bc2",
        NULL,
        "v4t6pzy6"
    },{
        "descriptor - The BOLT #3 received HTLC policy",
        "wsh(andor(c:pk_k(key_remote),or_i(and_v(vc:pk_h(key_local),hash160(H)),older(1008)),c:pk_k(key_revocation)))",
        "002087515e0059c345eaa5cccbaa9cd16ad1266e7a69e350db82d8e1f33c86285303",
        NULL,
        "8rap84p2"
    },{
        "descriptor - derive key index 0.",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        "002064969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b",
        &g_miniscript_index_0,
        "t2zpj2eu"
    },
};

struct wally_descriptor_depth_test g_descriptor_depth_test_table[] = {
    {
        "descriptor depth - p2sh-p2wsh-multi (p2sh-p2wsh)",
        "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        0,
        0,
        "a914aec509e284f909f769bb7dda299a717c87cc97ac87"
    },
    {
        "descriptor depth - p2sh-p2wsh-multi (p2wsh)",
        "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        1,
        0,
        "0020ef8110fa7ddefb3e2d02b2c1b1480389b4bc93f606281570cfc20dba18066aee"
    },
    {
        "descriptor depth - p2sh-p2wsh-multi (multi)",
        "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        2,
        0,
        "512103f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa82103499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e42102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e53ae"
    },
    {
        "descriptor depth - p2sh-p2wsh-multi (multi[0])",
        "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        3,
        0,
        "51"
    },
    {
        "descriptor depth - p2sh-p2wsh-multi (multi[1])",
        "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        3,
        1,
        "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8"
    },
    {
        "descriptor depth - p2sh-p2wsh-multi (multi[2])",
        "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        3,
        2,
        "03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4"
    },
    {
        "descriptor depth - p2sh-p2wsh-multi (multi[3])",
        "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        3,
        3,
        "02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e"
    },
};

struct wally_descriptor_address_test g_descriptor_address_test_table[] = {
    {
        "address - p2pkh - mainnet",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"
    },{
        "address - p2pkh - testnet",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        0,
        WALLY_NETWORK_BITCOIN_TESTNET,
        "mg8Jz5776UdyiYcBb9Z873NTozEiADRW5H"
    },{
        "address - p2pkh - regtest",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        0,
        WALLY_NETWORK_BITCOIN_REGTEST,
        "mg8Jz5776UdyiYcBb9Z873NTozEiADRW5H"
    },{
        "address - p2wpkh - mainnet",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1q0ht9tyks4vh7p5p904t340cr9nvahy7u3re7zg"
    },{
        "address - p2wpkh - testnet",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        0,
        WALLY_NETWORK_BITCOIN_TESTNET,
        "tb1q0ht9tyks4vh7p5p904t340cr9nvahy7um9zdem"
    },{
        "address - p2wpkh - regtest",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        0,
        WALLY_NETWORK_BITCOIN_REGTEST,
        "bcrt1q0ht9tyks4vh7p5p904t340cr9nvahy7uevmqwj"
    },{
        "address - p2sh-p2wpkh - mainnet",
        "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "3LKyvRN6SmYXGBNn8fcQvYxW9MGKtwcinN"
    },{
        "address - p2sh-p2wpkh - liquidv1",
        "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        0,
        WALLY_NETWORK_LIQUID,
        "H1pVQ7VtauJK4v7ixvwFQpDFYW2Q6eiPVx"
    },{
        "address - p2sh-p2wpkh - liquidregtest",
        "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        0,
        WALLY_NETWORK_LIQUID_REGTEST,
        "XVzCr2EG9PyrWX8qr2visL1aCfJMhGTZyS"
    },{
        "address - p2sh-p2wsh - mainnet",
        "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "39XGHYpYmJV9sGFoGHZeU2rLkY6r1MJ6C1"
    },{
        "address - p2sh-p2wsh - liquidv1",
        "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
        0,
        WALLY_NETWORK_LIQUID,
        "Gq1mmExLuSEwfzzk6YtUxJ769grv6T5Tak"
    },{
        "address - p2wsh-multi - mainnet",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39qn4zazc"
    },{
        "address - p2wsh-multi - testnet",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        0,
        WALLY_NETWORK_BITCOIN_TESTNET,
        "tb1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39qya5jch"
    },{
        "address - p2wsh-multi - regtest",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        0,
        WALLY_NETWORK_BITCOIN_REGTEST,
        "bcrt1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39qfy75dd"
    },{
        "address - p2wsh-multi - liquidv1",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        0,
        WALLY_NETWORK_LIQUID,
        "ex1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39q06fgz7"
    },{
        "address - p2wsh-multi - liquidregtest",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        0,
        WALLY_NETWORK_LIQUID_REGTEST,
        "ert1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39qchk2yf"
    },{
        "address - p2pkh-xpub-derive",
        "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "1PdNaNxbyQvHW5QHuAZenMGVHrrRaJuZDJ"
    },{
        "address - p2pkh-parent-derive",
        "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "14qCH92HCyDDBFFZdhDt1WMfrMDYnBFYMF"
    },{
        "address - p2wsh-multi-xpub",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c"
    },{
        "address - p2wsh-sortedmulti-xpub",
        "wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c"
    },{
        "address - addr-btc-legacy-testnet",
        "addr(moUfpGiXWcFd5ueRn3988VDqRSkB5NrEmW)",
        0,
        WALLY_NETWORK_BITCOIN_TESTNET,
        "moUfpGiXWcFd5ueRn3988VDqRSkB5NrEmW"
    },{
        "address - addr-btc-segwit-mainnet",
        "addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
    },{
        "address - p2pkh-xpriv",
        "pkh(xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU/1h/2)",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "1HH6H4km128m4NsJMNVN2qqCHukbEhgU3V"
    },{
        "address - A single key",
        "wsh(c:pk_k(key_1))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qlfdlf2hraeshcmxwr9m0d47jshp4jcfllmk5s8csvlmzhs84fpfqa6ufv5"
    },{
        "address - One of two keys (equally likely)",
        "wsh(or_b(c:pk_k(key_1),sc:pk_k(key_2)))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qrz5alxrt5y9umr6s8ay4e26l6qxflv3uq52ruewmhfy77nv2sf0spz2em3"
    },{
        "address - A user and a 2FA service need to sign off, but after 90 days the user alone is enough",
        "wsh(and_v(vc:pk_k(key_user),or_d(c:pk_k(key_service),older(12960))))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qzfjfgmrxd9vdj530v0wdely9jsda6kunpzc7d35xj6zh2phkenkstn6ur7"
    },{
        "address - A 3-of-3 that turns into a 2-of-3 after 90 days",
        "wsh(thresh(3,c:pk_k(key_1),sc:pk_k(key_2),sc:pk_k(key_3),sdv:older(12960)))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1q4v64r0kxyvfsyx9fefw6pcadhq4c260ezd26fqm98fyl9gkadecqy9uufs"
    },{
        "address - The BOLT #3 to_local policy",
        "wsh(andor(c:pk_k(key_local),older(1008),c:pk_k(key_revocation)))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qq5k0r6wfp6dz3q7cjpr856spsdlzrvah2kn58jwedg4klq596lqq90rr7h"
    },{
        "address - The BOLT #3 offered HTLC policy",
        "wsh(t:or_c(c:pk_k(key_revocation),and_v(vc:pk_k(key_remote),or_c(c:pk_k(key_local),v:hash160(H)))))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qlyjexc7mp7kv0wt6ktqzjnz0yxsv644srw65aj42tzvsz24wr0pqc6enkg"
    },{
        "address - The BOLT #3 received HTLC policy",
        "wsh(andor(c:pk_k(key_remote),or_i(and_v(vc:pk_h(key_local),hash160(H)),older(1008)),c:pk_k(key_revocation)))",
        0,
        WALLY_NETWORK_BITCOIN_MAINNET,
        "bc1qsag4uqzecdz74fwvew4fe5t26ynxu7nfudgdhqkcu8enep3g2vpsvp0wl0"
    },
};

struct wally_descriptor_address_list_test g_descriptor_addresses_test_table[] = {
    {
        "address list - p2wsh multisig (0-29)",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))#t2zpj2eu",
        0,
        29,
        WALLY_NETWORK_BITCOIN_MAINNET,
        30,
        {
            "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c",
            "bc1qp6rfclasvmwys7w7j4svgc2mrujq9m73s5shpw4e799hwkdcqlcsj464fw",
            "bc1qsflxzyj2f2evshspl9n5n745swcvs5k7p5t8qdww5unxpjwdvw5qx53ms4",
            "bc1qmhmj2mswyvyj4az32mzujccvd4dgr8s0lfzaum4n4uazeqc7xxvsr7e28n",
            "bc1qjeu2wa5jwvs90tv9t9xz99njnv3we3ux04fn7glw3vqsk4ewuaaq9kdc9t",
            "bc1qc6626sa08a4ktk3nqjrr65qytt9k273u24mfy2ld004g76jzxmdqjgpm2c",
            "bc1qwlq7jjqcklrcqypvdndjx0fyrudgrymm67gcx3e09sekgs28u47smq0lx5",
            "bc1qx8qq9k2mtqarugg3ctcsm2um22ahmq5uttrecy5ufku0ukfgpwrs7epn38",
            "bc1qgrs4qzvw4aat2k38fvmrqf3ucaanqz2wxe5yy5cewwmqn06evxgq02wv43",
            "bc1qnkpr4y7fp7jwad3gfngczwsv9069rq96cl7lpq4h9j3eng9mwjzsssr520",
            "bc1q7yzadku3kxs855wgjxnyr2nk3e44ed75p07lzhnj53ynpczg78nq0leae5",
            "bc1qpg9ag0ugqeucujyagca0n3httpgrgcsxftfgpymvmdeuyyejq9ks79c99t",
            "bc1qt2sv92tuklq28hptplvq7v75mmc8h6a0ynd7vd7y0h07mr8uzf5seh30gh",
            "bc1qdyfk0c5ksrxg6klz93acchg0xvavduzv3g4zj02fa3tm2yfy445q27zmar",
            "bc1qrpfz6zpargqu9s2qy0ef9uk82x6fcg6jfwjhxdaewgj880nxj2rqt0hwcm",
            "bc1qz6l0ar69xhk209nfdna68fkkg9tqp7pz7eq8mmu6hf5lvpltfx9slc9y6y",
            "bc1qgcttknnx6z65pdyqckexccvnshzv9wp76705704tpxcpw32y8f2suf5fx8",
            "bc1q0pauhlw2y4nyc2hud7dsmtc97k6kc30nz5u05dt6stahrfwy68tsnvl7l6",
            "bc1qhgv6v7jgxxpf0cpzxd9zga52mx3c5xrnkvchk35ypavesumh8yqscvxrjh",
            "bc1qrshvtv8ldqpdtv4z9z8fsah3plkl57drk7d8xgasgwj6puxpcxessp57hv",
            "bc1qma56gu8mxywqjpeh56cwltmaddrtvyxec4ppdx4j733j8wtva09qnldwgs",
            "bc1qj25wzn56y79x6tm67hpwr9d8vew87nk8asgwcc8mp53g4wh6hr9s2lh8nn",
            "bc1q2ct0r07txjd32gh5c0cwg59ml0ahrzg07q3cm5naykdzdstmxhmqe8rtdu",
            "bc1qn3n488yufhn2zfxtu4c7cqrmasqslrkmdyh7jen3yx8lj9z4cdfq03v349",
            "bc1q89u4zs3vxyyznzzp99w8n8w7rh6hr4z3nvvtvkhyzkkqsgppvv8sgq0hqh",
            "bc1q588dgge2vx0azcslfktlpeehqlh6y34hg6ur3rluxmkkm28f69dswj664f",
            "bc1qv9eul0xtc8pg0sheuxp5ve9z7kl95j00efdxts8ae7ls7utcl4mq67jgqp",
            "bc1qygswuelpc3rcuvzmempn0ku9h35fcpnc6sjd6h6exq4zx9zvxmrqz2eacm",
            "bc1q2t74yd2ec7qx4j5xe9pj2y522whj3lz4lmhsxeasu8z00ggapgnqjxvlnk",
            "bc1qp0rlvd76cmsv9ls5jv9az8kmra44rzgm5mz8008ypyfjayk70r8qwrg6c6",
        },
    },
    {
        "address list - p2wsh multisig (30-40)",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))#t2zpj2eu",
        30,
        40,
        WALLY_NETWORK_BITCOIN_MAINNET,
        11,
        {
            "bc1qz7ymgzfyx5x0qk04e0je54zwlh8mcshzwdmyd72jpgp33zkl3ekqxl6xuc",
            "bc1qt07wnht6j90aczg7e7wsvnpzxveueyud34a90d99phm7apesvp0sw63ceh",
            "bc1qwwl8fkywdhpn2xh8k95qglhkrjlt7xp60nahvc6yderj53wg79rs8kdfrv",
            "bc1qxu7g60rcjlfulna079ccmta7ytazck82vwth3hktqeey2e5vh4lqp4s0a3",
            "bc1q8v89njuqn66w7elpxjy79j2fpksnafje2xs0l268typfm553hwcqsw9wza",
            "bc1qn66uht0ndvdw6nna8pm8nhjhulrp8yq84rcarkfr3u5nprdzyq0sx3k9g6",
            "bc1q3em7pyxvyte20n5mx4yeswkfq7vkj77xty06vu5gk47z7tews48q39g324",
            "bc1qytjx24vzm7q5munv9yn3j7ltg23q86sqxnzunhhvsrx5hrnu47rsplzqux",
            "bc1q283cq3dknnypqzjdtkhx3mjq7ncex5snfjpcl0vuq5k8v9nmcr8sxfdfr2",
            "bc1qqdte9nnnam9zpgg5zfttyw7hmgh0secxnj6ukrq20c60fcjx7lhqv6am95",
            "bc1qd6ffgpayzpywa6hps0c65xuur5letl9hdy3pv5y40t8p9nrjpdtqqkan7a"
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        },
    },
};

struct wally_descriptor_err_test g_descriptor_err_test_table[] = {
    {
        "descriptor errchk - invalid checksum",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)#8rap84p2",
        WALLY_NETWORK_BITCOIN_MAINNET
    },{
        "descriptor errchk - privkey - unmatch network1",
        "wpkh(cSMSHUGbEiZQUXVw9zA33yT3m8fgC27rn2XEGZJupwCpsRS3rAYa)",
        WALLY_NETWORK_BITCOIN_MAINNET
    },{
        "descriptor errchk - privkey - unmatch network2",
        "wpkh(cSMSHUGbEiZQUXVw9zA33yT3m8fgC27rn2XEGZJupwCpsRS3rAYa)",
        WALLY_NETWORK_LIQUID
    },{
        "descriptor errchk - privkey - unmatch network3",
        "wpkh(L4gLCkRn5VfJsDSWsrrC57kqVgq6Z2sjeRELmim5zzAgJisysh17)",
        WALLY_NETWORK_BITCOIN_TESTNET
    },{
        "descriptor errchk - privkey - unmatch network4",
        "wpkh(L4gLCkRn5VfJsDSWsrrC57kqVgq6Z2sjeRELmim5zzAgJisysh17)",
        WALLY_NETWORK_BITCOIN_REGTEST
    },{
        "descriptor errchk - privkey - unmatch network5",
        "wpkh(L4gLCkRn5VfJsDSWsrrC57kqVgq6Z2sjeRELmim5zzAgJisysh17)",
        WALLY_NETWORK_LIQUID_REGTEST
    },{
        "descriptor errchk - xpubkey - unmatch network1",
        "wpkh(tpubD6NzVbkrYhZ4XJDrzRvuxHEyQaPd1mwwdDofEJwekX18tAdsqeKfxss79AJzg1431FybXg5rfpTrJF4iAhyR7RubberdzEQXiRmXGADH2eA)",
        WALLY_NETWORK_BITCOIN_MAINNET
    },{
        "descriptor errchk - xpubkey - unmatch network2",
        "wpkh(tpubD6NzVbkrYhZ4XJDrzRvuxHEyQaPd1mwwdDofEJwekX18tAdsqeKfxss79AJzg1431FybXg5rfpTrJF4iAhyR7RubberdzEQXiRmXGADH2eA)",
        WALLY_NETWORK_LIQUID
    },{
        "descriptor errchk - xpubkey - unmatch network3",
        "wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB)",
        WALLY_NETWORK_BITCOIN_TESTNET
    },{
        "descriptor errchk - xpubkey - unmatch network4",
        "wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB)",
        WALLY_NETWORK_BITCOIN_REGTEST
    },{
        "descriptor errchk - xpubkey - unmatch network5",
        "wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB)",
        WALLY_NETWORK_LIQUID_REGTEST
    },{
        "descriptor errchk - xprivkey - unmatch network1",
        "wpkh(tprv8jDG3g2yc8vh71x9ejCDSfMz4AuQRx7MMNBXXvpD4jh7CkDuB3ZmnLVcEM99jgg5MaSp7gYNpnKS5dvkGqq7ad8X63tE7yFaMGTfp6gD54p)",
        WALLY_NETWORK_BITCOIN_MAINNET
    },{
        "descriptor errchk - xprivkey - unmatch network2",
        "wpkh(tprv8jDG3g2yc8vh71x9ejCDSfMz4AuQRx7MMNBXXvpD4jh7CkDuB3ZmnLVcEM99jgg5MaSp7gYNpnKS5dvkGqq7ad8X63tE7yFaMGTfp6gD54p)",
        WALLY_NETWORK_LIQUID
    },{
        "descriptor errchk - xprivkey - unmatch network3",
        "wpkh(xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU)",
        WALLY_NETWORK_BITCOIN_TESTNET
    },{
        "descriptor errchk - xprivkey - unmatch network4",
        "wpkh(xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU)",
        WALLY_NETWORK_BITCOIN_REGTEST
    },{
        "descriptor errchk - xprivkey - unmatch network5",
        "wpkh(xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU)",
        WALLY_NETWORK_LIQUID_REGTEST
    },{
        "descriptor errchk - addr - unmatch network1",
        "addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        WALLY_NETWORK_BITCOIN_TESTNET
    },{
        "descriptor errchk - addr - unmatch network2",
        "addr(ex1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39q06fgz7)",
        WALLY_NETWORK_LIQUID_REGTEST
    },
};

struct wally_descriptor_err_test g_address_err_test_table[] = {
    {
        "address errchk - invalid network",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        0xf0
    },{
        "address errchk - addr - unmatch network1",
        "addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        WALLY_NETWORK_BITCOIN_TESTNET
    },{
        "address errchk - addr - unmatch network2",
        "addr(ex1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39q06fgz7)",
        WALLY_NETWORK_LIQUID_REGTEST
    },{
        "address errchk - unsupport address - p2pk",
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_BITCOIN_MAINNET
    },{
        "address errchk - unsupport address - raw",
        "raw(6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e)#zf2avljj",
        WALLY_NETWORK_BITCOIN_MAINNET
    },
};

static bool check_parse_miniscript(const char *function, const char *descriptor,
                                   const char *expected,
                                   const char **key_name_list,
                                   const char **key_value_list, size_t list_num)
{
    size_t written = 0;
    unsigned char script[520];
    char *hex = NULL;
    int ret;
    bool is_success = false;
    uint32_t index = 0;
    uint32_t flag = 0;

    ret = wally_descriptor_parse_miniscript(
        descriptor,
        key_name_list,
        key_value_list,
        list_num,
        index,
        flag,
        script,
        sizeof(script),
        &written);
    if (ret != WALLY_OK) {
        printf("wally_descriptor_parse_miniscript NG[%d]\n", ret);
        return false;
    }

    ret = wally_hex_from_bytes(script, written, &hex);
    if (ret != WALLY_OK) {
        printf("wally_hex_from_bytes NG[%d]\n", ret);
        return false;
    }

    if (strncmp(hex, expected, strlen(hex) + 1) == 0) {
        is_success = true;
    } else
        printf("%s:\n  Input: %s\n  Output: %s\n  Expect: %s\n",
               function, descriptor, hex, expected);

    wally_free_string(hex);
    return is_success;
}

static bool check_descriptor_to_scriptpubkey(const char *function,
                                             const char *descriptor,
                                             const char *expected,
                                             const uint32_t *bip32_index,
                                             const char *expected_checksum)
{
    size_t written = 0;
    unsigned char script[520];
    char *hex = NULL;
    char *checksum = NULL;
    int ret;
    bool is_success = false;
    uint32_t network = 0;
    uint32_t desc_depth = 0;
    uint32_t desc_index = 0;
    uint32_t flag = 0;
    uint32_t index = 0;
    if (bip32_index) {
        index = *bip32_index;
    }

    ret = wally_descriptor_to_scriptpubkey(
        descriptor,
        (const char **)g_miniscript_keyname_list,
        (const char **)g_miniscript_keyvalue_list,
        sizeof(g_miniscript_keyname_list) / sizeof(char *),
        index,
        network,
        desc_depth,
        desc_index,
        flag,
        script,
        sizeof(script),
        &written);
    if (ret != WALLY_OK) {
        printf("wally_descriptor_to_scriptpubkey NG[%d]\n", ret);
        return false;
    }

    ret = wally_hex_from_bytes(script, written, &hex);
    if (ret != WALLY_OK) {
        printf("wally_hex_from_bytes NG[%d]\n", ret);
        return false;
    }

    ret = wally_descriptor_create_checksum(
        descriptor,
        (const char **)g_miniscript_keyname_list,
        (const char **)g_miniscript_keyvalue_list,
        sizeof(g_miniscript_keyname_list) / sizeof(char *),
        flag,
        &checksum);
    if (ret != WALLY_OK) {
        printf("wally_descriptor_create_checksum NG[%d]\n", ret);
        wally_free_string(hex);
        return false;
    }

    if (strncmp(hex, expected, strlen(hex) + 1) != 0) {
        printf("%s:\n  Input: %s\n  Output: %s\n", function, descriptor, hex);
    } else if (strncmp(checksum, expected_checksum, 9) != 0) {
        printf("%s:\n  Input: %s\n  Checksum: %s\n", function, descriptor, checksum);
    } else
        is_success = true;

    wally_free_string(checksum);
    wally_free_string(hex);
    return is_success;
}

static bool check_descriptor_to_scriptpubkey_depth(const char *function,
                                                   const char *descriptor,
                                                   const uint32_t depth,
                                                   const uint32_t index,
                                                   const char *expected_scriptpubkey)
{
    size_t written = 0;
    unsigned char script[520];
    char *hex = NULL;
    int ret;
    bool is_success = false;
    uint32_t network = 0;
    uint32_t flag = 0;

    ret = wally_descriptor_to_scriptpubkey(
        descriptor,
        (const char **)g_miniscript_keyname_list,
        (const char **)g_miniscript_keyvalue_list,
        sizeof(g_miniscript_keyname_list) / sizeof(char *),
        0,
        network,
        depth,
        index,
        flag,
        script,
        sizeof(script),
        &written);
    if (ret != WALLY_OK) {
        printf("wally_descriptor_to_scriptpubkey NG[%d]\n", ret);
        return false;
    }

    ret = wally_hex_from_bytes(script, written, &hex);
    if (ret != WALLY_OK) {
        printf("wally_hex_from_bytes NG[%d]\n", ret);
        return false;
    }

    if (strncmp(hex, expected_scriptpubkey, strlen(hex) + 1) != 0) {
        printf("%s:\n  Input: %s\n  Output: %s\n", function, descriptor, hex);
    } else
        is_success = true;

    wally_free_string(hex);
    return is_success;
}

static bool check_descriptor_to_address(const char *function,
                                        const char *descriptor,
                                        const uint32_t bip32_index,
                                        const uint32_t network,
                                        const char *expected_address)
{
    char *address = NULL;
    int ret;
    uint32_t flag = 0;
    bool is_success = false;

    ret = wally_descriptor_to_address(
        descriptor,
        (const char **)g_miniscript_keyname_list,
        (const char **)g_miniscript_keyvalue_list,
        sizeof(g_miniscript_keyname_list) / sizeof(char *),
        bip32_index,
        network,
        flag,
        &address);
    if (ret != WALLY_OK) {
        printf("wally_descriptor_to_address NG[%d]\n", ret);
        return false;
    }

    if (strncmp(expected_address, address, strlen(expected_address) + 1) != 0) {
        printf("%s:\n  Address: %s\n  Expect: %s\n", function, address, expected_address);
    } else
        is_success = true;

    wally_free_string(address);
    return is_success;
}

static bool check_descriptor_to_addresses(const char *function,
                                          const char *descriptor,
                                          const uint32_t start_index,
                                          const uint32_t end_index,
                                          const uint32_t network,
                                          const char **expected_address_list,
                                          size_t address_list_len)
{
    struct wally_descriptor_addresses addresses = {NULL, 0};
    int ret;
    uint32_t flag = 0;
    uint32_t index = 0;
    bool is_success = true;

    ret = wally_descriptor_to_addresses(
        descriptor,
        (const char **)g_miniscript_keyname_list,
        (const char **)g_miniscript_keyvalue_list,
        sizeof(g_miniscript_keyname_list) / sizeof(char *),
        start_index,
        end_index,
        network,
        flag,
        &addresses);
    if (ret != WALLY_OK) {
        printf("wally_descriptor_to_addresses NG[%d]\n", ret);
        return false;
    }

    if (addresses.num_items != address_list_len) {
        printf("%s:\n  Address length: %zu\n  Expect: %zu\n", function, addresses.num_items, address_list_len);
    } else {
        for (index = 0; index < address_list_len; ++index) {
            const char *expected_address = expected_address_list[index];
            const char *addr = addresses.items[index].address;
            uint32_t child_num = addresses.items[index].child_num;
            uint32_t exp_child_num = start_index + index;
            if (strncmp(expected_address, addr, strlen(expected_address) + 1) != 0) {
                printf("%s:\n  Address[%u]: %s\n  Expect: %s\n", function, index, addr, expected_address_list[index]);
                is_success = false;
            }
            if (child_num != exp_child_num) {
                printf("%s:\n  childNum[%u]: %u\n  Expect: %u\n", function, index, child_num, exp_child_num);
                is_success = false;
            }
        }
    }

    wally_free_descriptor_addresses(&addresses);
    return is_success;
}

static bool check_descriptor_scriptpubkey_error(const char *function,
                                                const char *descriptor,
                                                const uint32_t network)
{
    int ret;
    size_t written = 0;
    unsigned char script[520];
    uint32_t flag = 0;
    uint32_t desc_depth = 0;
    uint32_t desc_index = 0;

    ret = wally_descriptor_to_scriptpubkey(
        descriptor,
        (const char **)g_miniscript_keyname_list,
        (const char **)g_miniscript_keyvalue_list,
        sizeof(g_miniscript_keyname_list) / sizeof(char *),
        0,
        network,
        desc_depth,
        desc_index,
        flag,
        script,
        sizeof(script),
        &written);
    if (ret == WALLY_EINVAL) {
        return true;
    } else if (ret != WALLY_OK) {
        printf("wally_descriptor_to_scriptpubkey NG[%d]\n", ret);
        return false;
    }
    printf("wally_descriptor_to_scriptpubkey Fail[Not Error] name[%s]\n", function);

    return false;
}

static bool check_descriptor_address_error(const char *function,
                                           const char *descriptor,
                                           const uint32_t network)
{
    char *address = NULL;
    int ret;
    uint32_t flag = 0;

    ret = wally_descriptor_to_address(
        descriptor,
        (const char **)g_miniscript_keyname_list,
        (const char **)g_miniscript_keyvalue_list,
        sizeof(g_miniscript_keyname_list) / sizeof(char *),
        0,
        network,
        flag,
        &address);
    if (ret == WALLY_EINVAL) {
        return true;
    } else if (ret != WALLY_OK) {
        printf("wally_descriptor_to_address NG[%d]\n", ret);
        return false;
    }
    printf("wally_descriptor_to_address Fail[Not Error] name[%s]\n", function);

    wally_free_string(address);
    return false;
}

int main(void)
{
    bool tests_ok = true;
    size_t index;
    size_t miniscript_ref_max = sizeof(g_miniscript_ref_test_table) / sizeof(struct wally_miniscript_ref_test);
    size_t miniscript_max = sizeof(g_miniscript_test_table) / sizeof(struct wally_miniscript_test);
    size_t desc_max = sizeof(g_descriptor_test_table) / sizeof(struct wally_descriptor_test);
    size_t desc_depth_max = sizeof(g_descriptor_depth_test_table) / sizeof(struct wally_descriptor_depth_test);
    size_t addr_max = sizeof(g_descriptor_address_test_table) / sizeof(struct wally_descriptor_address_test);
    size_t addr_list_max = sizeof(g_descriptor_addresses_test_table) / sizeof(struct wally_descriptor_address_list_test);
    size_t desc_err_max = sizeof(g_descriptor_err_test_table) / sizeof(struct wally_descriptor_err_test);
    size_t addr_err_max = sizeof(g_address_err_test_table) / sizeof(struct wally_descriptor_err_test);

    for (index = 0; index < miniscript_ref_max; ++index) {
        if (!check_parse_miniscript(
                g_miniscript_ref_test_table[index].miniscript,
                g_miniscript_ref_test_table[index].miniscript,
                g_miniscript_ref_test_table[index].scriptpubkey,
                NULL, NULL, 0)) {
            printf("[%s] test failed!\n", g_miniscript_ref_test_table[index].miniscript);
            tests_ok = false;
        }
    }

    for (index = 0; index < miniscript_max; ++index) {
        if (!check_parse_miniscript(
                g_miniscript_test_table[index].name,
                g_miniscript_test_table[index].descriptor,
                g_miniscript_test_table[index].scriptpubkey,
                NULL, NULL, 0)) {
            printf("[%s] test failed!\n", g_miniscript_test_table[index].name);
            tests_ok = false;
        }
    }

    for (index = 0; index < desc_max; ++index) {
        if (!check_descriptor_to_scriptpubkey(
                g_descriptor_test_table[index].name,
                g_descriptor_test_table[index].descriptor,
                g_descriptor_test_table[index].scriptpubkey,
                g_descriptor_test_table[index].bip32_index,
                g_descriptor_test_table[index].checksum)) {
            printf("[%s] test failed!\n", g_descriptor_test_table[index].name);
            tests_ok = false;
        }
    }

    for (index = 0; index < desc_depth_max; ++index) {
        if (!check_descriptor_to_scriptpubkey_depth(
                g_descriptor_depth_test_table[index].name,
                g_descriptor_depth_test_table[index].descriptor,
                g_descriptor_depth_test_table[index].depth,
                g_descriptor_depth_test_table[index].index,
                g_descriptor_depth_test_table[index].scriptpubkey)) {
            printf("[%s] keylist test failed!\n", g_descriptor_depth_test_table[index].name);
            tests_ok = false;
        }
    }

    for (index = 0; index < addr_max; ++index) {
        if (!check_descriptor_to_address(
                g_descriptor_address_test_table[index].name,
                g_descriptor_address_test_table[index].descriptor,
                g_descriptor_address_test_table[index].bip32_index,
                g_descriptor_address_test_table[index].network,
                g_descriptor_address_test_table[index].address)) {
            printf("[%s] test failed!\n", g_descriptor_address_test_table[index].name);
            tests_ok = false;
        }
    }

    for (index = 0; index < addr_list_max; ++index) {
        if (!check_descriptor_to_addresses(
                g_descriptor_addresses_test_table[index].name,
                g_descriptor_addresses_test_table[index].descriptor,
                g_descriptor_addresses_test_table[index].start_index,
                g_descriptor_addresses_test_table[index].end_index,
                g_descriptor_addresses_test_table[index].network,
                g_descriptor_addresses_test_table[index].address_list,
                g_descriptor_addresses_test_table[index].address_list_num)) {
            printf("[%s] test failed!\n", g_descriptor_addresses_test_table[index].name);
            tests_ok = false;
        }
    }

    for (index = 0; index < desc_err_max; ++index) {
        if (!check_descriptor_scriptpubkey_error(
                g_descriptor_err_test_table[index].name,
                g_descriptor_err_test_table[index].descriptor,
                g_descriptor_err_test_table[index].network)) {
            printf("[%s] test failed!\n", g_descriptor_err_test_table[index].name);
            tests_ok = false;
        }
    }

    for (index = 0; index < addr_err_max; ++index) {
        if (!check_descriptor_address_error(
                g_address_err_test_table[index].name,
                g_address_err_test_table[index].descriptor,
                g_address_err_test_table[index].network)) {
            printf("[%s] test failed!\n", g_address_err_test_table[index].name);
            tests_ok = false;
        }
    }

    return tests_ok ? 0 : 1;
}
