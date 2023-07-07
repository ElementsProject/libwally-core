#include "config.h"

#include <wally_descriptor.h>
#include <wally_address.h>
#include <wally_psbt.h>
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

#define B(str) (unsigned char *)(str), sizeof(str)-1
#define NUM_ELEMS(a) (sizeof(a) / sizeof(a[0]))

static struct wally_map_item g_key_map_items[] = {
    { B("key_1"), B("038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048") },
    { B("key_2"), B("03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7") },
    { B("key_3"), B("03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284") },
    { B("key_likely"), B("038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048") },
    { B("key_unlikely"), B("03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7") },
    { B("key_user"), B("038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048") },
    { B("key_service"), B("03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7") },
    { B("key_local"), B("038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048") },
    { B("key_remote"), B("03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7") },
    { B("key_revocation"), B("03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284") },
    { B("H"), B("d0721279e70d39fb4aa409b52839a0056454e3b5") }, /* HASH160(key_local) */
    { B("testnet_xpub"), B("tpubD6NzVbkrYhZ4XJDrzRvuxHEyQaPd1mwwdDofEJwekX18tAdsqeKfxss79AJzg1431FybXg5rfpTrJF4iAhyR7RubberdzEQXiRmXGADH2eA") },
    { B("mainnet_xpub"), B("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL") },
    { B("mainnet_xpriv"), B("xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU") },
    { B("uncompressed"), B("0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf") },
};

static const struct wally_map g_key_map = {
    g_key_map_items,
    NUM_ELEMS(g_key_map_items),
    NUM_ELEMS(g_key_map_items),
    NULL
};

static const uint32_t g_miniscript_index_0 = 0;
static const uint32_t g_miniscript_index_16 = 0x10;

static bool check_ret(const char *function, int ret, int expected)
{
    if (ret != expected)
        printf("%s: expected %d, got %d\n", function, expected, ret);
    return ret == expected;
}

static bool check_varbuff(const char *function, const unsigned char *src, size_t src_len, const char *expected)
{
    char *hex = NULL;

    if (!check_ret(function, wally_hex_from_bytes(src, src_len, &hex), WALLY_OK))
        return false;

    if (strcmp(hex, expected)) {
        printf("%s: mismatch, expected [%s], got [%s]\n", function, expected, hex);
        return false;
    }
    wally_free_string(hex);
    return true;
}

#define DEPTH_TEST_DESCRIPTOR "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))"

static const struct descriptor_test {
    const char *name;
    const char *descriptor;
    const uint32_t network;
    const uint32_t depth;
    const uint32_t index;
    const uint32_t variant;
    const uint32_t *child_num;
    const uint32_t flags;
    const char *script;
    const char *checksum;
} g_descriptor_cases[] = {
    /*
     * Output descriptors
     */
    {
        "descriptor - p2pk with checksum",
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "gn28ywm7"
    },{
        "descriptor - p2pk uncompressed",
        "pk(uncompressed)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "410414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cfac",
        "xfwtewl7"
    },{
        "descriptor - p2pkh",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac",
        "8fhd9pwu"
    },{
        "descriptor - p2pkh uncompressed",
        "pkh(uncompressed)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a914bc11f399122b0bda5e5432aba3f5206dbb7dc18388ac",
        "svxeae4h"
    },{
        "descriptor - p2wpkh",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc",
        "8zl0zxma"
    },{
        "descriptor - p2wpkh (bip143 test vector)",
        "wpkh(025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        /* From script "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac" */
        "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1",
        "pw3pfgx0"
    },{
        "descriptor - p2sh-p2wpkh",
        "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "a914cc6ffbc0bf31af759451068f90ba7a0272b6b33287",
        "qkrrc7je"
    },{
        "descriptor - p2sh-p2wpkh (bip143 test vector)",
        "sh(wpkh(03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        /* From script "76a91479091972186c449eb1ded22b78e40d009bdf008988ac" */
        "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387",
        "946zr4e5"
    },{
        "descriptor - combo(variant 0, p2pk)",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "lq9sf04s"
    },{
        "descriptor - combo(variant 1, p2pkh)",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_NONE, 0, 0, 1, NULL, 0,
        "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
        "lq9sf04s"
    },{
        "descriptor - combo(variant 2, p2wpkh)",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_NONE, 0, 0, 2, NULL, 0,
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        "lq9sf04s"
    },{
        "descriptor - combo(variant 3, p2sh-p2wpkh)",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_NONE, 0, 0, 3, NULL, 0,
        "a914bcfeb728b584253d5f3f70bcb780e9ef218a68f487",
        "lq9sf04s"
    },{
        "descriptor - combo(variant 0, p2pk uncompressed)",
        "combo(04a238b0cbea14c9b3f59d0a586a82985f69af3da50579ed5971eefa41e6758ee7f1d77e4d673c6e7aac39759bb762d22259e27bf93572e9d5e363d5a64b6c062b)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "4104a238b0cbea14c9b3f59d0a586a82985f69af3da50579ed5971eefa41e6758ee7f1d77e4d673c6e7aac39759bb762d22259e27bf93572e9d5e363d5a64b6c062bac",
        "r3wj6k68"
    },{
        "descriptor - combo(variant 1, p2pkh uncompressed)",
        "combo(04a238b0cbea14c9b3f59d0a586a82985f69af3da50579ed5971eefa41e6758ee7f1d77e4d673c6e7aac39759bb762d22259e27bf93572e9d5e363d5a64b6c062b)",
        WALLY_NETWORK_NONE, 0, 0, 1, NULL, 0,
        "76a91448cb866ee3edb295e4cfeb3da65b4003ab9fa6a288ac",
        "r3wj6k68"
    },{
        "descriptor - combo(variant 2, p2wpkh uncompressed, invalid)",
        "combo(04a238b0cbea14c9b3f59d0a586a82985f69af3da50579ed5971eefa41e6758ee7f1d77e4d673c6e7aac39759bb762d22259e27bf93572e9d5e363d5a64b6c062b)",
        WALLY_NETWORK_NONE, 0, 0, 2, NULL, 0,
        NULL,
        ""
    },{
        "descriptor - combo(variant 3, p2sh-p2wpkh uncompressed, invalid)",
        "combo(04a238b0cbea14c9b3f59d0a586a82985f69af3da50579ed5971eefa41e6758ee7f1d77e4d673c6e7aac39759bb762d22259e27bf93572e9d5e363d5a64b6c062b)",
        WALLY_NETWORK_NONE, 0, 0, 3, NULL, 0,
        NULL,
        ""
    },{
        "descriptor - p2sh-p2wsh",
        "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "a91455e8d5e8ee4f3604aba23c71c2684fa0a56a3a1287",
        "2wtr0ej5"
    },{
        "descriptor - multisig",
        "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "5121022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe421025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc52ae",
        "hzhjw406"
    },{
        "descriptor - p2sh-multi",
        "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "a914a6a8b030a38762f4c1f5cbe387b61a3c5da5cd2687",
        "y9zthqta"
    },{
        "descriptor - p2sh-sortedmulti 1",
        "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "a914a6a8b030a38762f4c1f5cbe387b61a3c5da5cd2687",
        "qwx6n9lh"
    },{
        "descriptor - p2sh-sortedmulti 2",
        "sh(sortedmulti(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "a914a6a8b030a38762f4c1f5cbe387b61a3c5da5cd2687",
        "fjpjdnvk" /* Note different checksum from p2sh-sortedmulti 1 */
    },{
        "descriptor - p2wsh-multi",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "0020773d709598b76c4e3b575c08aad40658963f9322affc0f8c28d1d9a68d0c944a",
        "en3tu306"
    },{
        "descriptor - p2wsh-multi (from bitcoind's `createmultisig`)",
        "wsh(multi(2,03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd,03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        /* From script "522103789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd2103dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a6162652ae" */
        "00207ca68449d39a95da91c6c283871f587b74b45c1645a37f8c8337fd3d9ac4fee6",
        "5wacx8g6"
    },{
        "descriptor - p2sh-p2wsh-multi",
        "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "a914aec509e284f909f769bb7dda299a717c87cc97ac87",
        "ks05yr6p"
    },{
        "descriptor - p2sh-p2wsh-multi (from bitcoind's `createmultisig`)",
        "sh(wsh(multi(2,03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd,03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        /* From script "522103789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd2103dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a6162652ae" */
        "a91411aca2b63fbee2cdda856217a8863135b070978b87",
        "du4tngj2"
    },{
        "descriptor - p2sh multisig 15",
        /*          1     2     3     4     5     6     7     8     9     10    11    12    13    14    15 */
        "sh(multi(1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "a914276b4ebc33265436a9c9b46ca23d6781aef98fe087",
        "pckwejvm"
    },{
        "descriptor - p2pk-xpub",
        "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "210339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2ac",
        "axav5m0j"
    },{
        "descriptor - p2pkh-xpub-derive single child",
        "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac",
        "kd8wch8l"
    },{
        "descriptor - p2pkh-xpub-derive",
        "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a914f833c08f02389c451ae35ec797fccf7f396616bf88ac",
        "kczqajcv"
    },{
        "descriptor - p2pkh-empty-path",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a91431a507b815593dfc51ffc7245ae7e5aee304246e88ac",
        "ee44hjhg"
    },{
        "descriptor - p2pkh-empty-path h-hardened",
        "pkh([d34db33f/44h/0h/0h]mainnet_xpub/)#ltv22yxk",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a91431a507b815593dfc51ffc7245ae7e5aee304246e88ac",
        "ltv22yxk" /* Note different checksum despite being the same expression as above */
    },{
        "descriptor - p2pkh-parent-derive",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1/*)",
        WALLY_NETWORK_NONE, 0, 0, 0, &g_miniscript_index_16, 0,
        "76a914d234825a563de8b4fd31d2b30f60b1e60fe57ee788ac",
        "ml40v0wf"
    },{
        "descriptor - ranged and non-ranged keys (1)",
        "multi(2,mainnet_xpub,mainnet_xpub/*)",
        WALLY_NETWORK_NONE, 0, 0, 0, &g_miniscript_index_16, 0,
        "522102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f02102fb7d86f93bb0f5958171e05473bf36d99a850596b0a8dbe086a0101d4946083a52ae",
        "e0pf8z74"
    },{
        "descriptor - p2wsh-multi-xpub",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        WALLY_NETWORK_NONE, 0, 0, 0, &g_miniscript_index_16, 0,
        "00204616bb4e66d0b540b480c5b26c619385c4c2b83ed79f4f3eab09b01745443a55",
        "t2zpj2eu"
    },{
        "descriptor - p2wsh-sortedmulti-xpub",
        "wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        WALLY_NETWORK_NONE, 0, 0, 0, &g_miniscript_index_16, 0,
        "002002aeee9c3773dfecfe6215f2eea2908776b1232513a700e1ee516b634883ecb0",
        "v66cvalc"
    },{
        "descriptor - addr-btc-legacy-testnet",
        "addr(moUfpGiXWcFd5ueRn3988VDqRSkB5NrEmW)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a91457526b1a1534d4bde788253281649fc2e91dc70b88ac",
        "9amhxcar"
    },{
        "descriptor - addr-btc-segwit-mainnet",
        "addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        "8kzm8txf"
    },{
        "descriptor - empty raw",
        "raw()",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "",
        "58lrscpx"
    }, {
        "descriptor - raw-checksum",
        "raw(6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e)#zf2avljj",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e",
        "zf2avljj"
    },{
        "descriptor - p2pkh-xpriv",
        "pkh(mainnet_xpriv/1h/2)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a914b28d12ab72a51b10114b17ce76b536265194e1fb88ac",
        "wghlxksl"
    },{
        "descriptor - p2pkh-xpriv hardened last child",
        "pkh(mainnet_xpriv/1h/2h)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a9148ab3d0acbde6766fb0a24e0e4286168c2a24a7a088ac",
        "cj20v7ag"
    },{
        "descriptor - p2pkh-privkey-wif mainnet",
        "pkh(L1AAHuEC7XuDM7pJ7yHLEqYK1QspMo8n1kgxyZVdgvEpVC1rkUrM)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a91492ed3283cfb01caec1163aefba29caf1182f478e88ac",
        "qm00tjwh"
    },{
        "descriptor - p2pkh-privkey-wif testnet uncompressed",
        "pkh(936Xapr4wpeuiKToGeXtEcsVJAfE6ze8KUEb2UQu72rzBQsMZdX)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "76a91477b6f27ac523d8b9aa8abcfc94fd536493202ae088ac",
        "9gv5p2gj"
    },{
        "descriptor - A single key",
        "wsh(c:pk_k(key_1))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "0020fa5bf4aae3ee617c6cce1976f6d7d285c359613ffeed481f1067f62bc0f54852",
        "9u0h8j4t"
    },{
        "descriptor - One of two keys (equally likely)",
        "wsh(or_b(c:pk_k(key_1),sc:pk_k(key_2)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "002018a9df986ba10bcd8f503f495cab5fd00c9fb23c05143e65dbba49ef4d8a825f",
        "hyh0kcqw"
    },{
        "descriptor - A user and a 2FA service need to sign off, but after 90 days the user alone is enough",
        "wsh(and_v(vc:pk_k(key_user),or_d(c:pk_k(key_service),older(12960))))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "00201264946c666958d9522f63dcdcfc85941bdd5b9308b1e6c68696857506f6cced",
        "nwlxsraz"
    },{
        "descriptor - The BOLT #3 to_local policy",
        "wsh(andor(c:pk_k(key_local),older(1008),c:pk_k(key_revocation)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "0020052cf1e9c90e9a2883d890467a6a01837e21b3b755a743c9d96a2b6f8285d7c0",
        "hthd6qg9"
    },{
        "descriptor - The BOLT #3 offered HTLC policy",
        "wsh(t:or_c(c:pk_k(key_revocation),and_v(vc:pk_k(key_remote),or_c(c:pk_k(key_local),v:hash160(H)))))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "0020f9259363db0facc7b97ab2c0294c4f21a0cd56b01bb54ecaaa5899012aae1bc2",
        "0hmjukva"
    },{
        "descriptor - The BOLT #3 received HTLC policy",
        "wsh(andor(c:pk_k(key_remote),or_i(and_v(vc:pk_h(key_local),hash160(H)),older(1008)),c:pk_k(key_revocation)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "002087515e0059c345eaa5cccbaa9cd16ad1266e7a69e350db82d8e1f33c86285303",
        "8re62ejc"
    },{
        "descriptor - derive key index 0",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        WALLY_NETWORK_NONE, 0, 0, 0, &g_miniscript_index_0, 0,
        "002064969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b",
        "t2zpj2eu"
    },
    /* https://github.com/rust-bitcoin/rust-miniscript/blob/master/src/descriptor/checksum.rs */
    {
        "descriptor - rust-bitcoin checksum",
        "wpkh(tprv8ZgxMBicQKsPdpkqS7Eair4YxjcuuvDPNYmKX3sCniCf16tHEVrjjiSXEkFRnUH77yXc6ZcwHHcLNfjdi5qUvw3VDfgYiH5mNsj5izuiu2N/1/2/*)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "0014e2d19350c9d8722e2994c81791f4a0ba115bc479",
        "tqz0nc62"
    }, {
        /* https://github.com/bitcoin/bitcoin/blob/7ae86b3c6845873ca96650fc69beb4ae5285c801/src/test/descriptor_tests.cpp#L352-L354 */
        "descriptor - core checksum",
        "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "a91445a9a622a8b0a1269944be477640eedc447bbd8487",
        "ggrsrxfy"
    },
    /*
     * Depth/index test cases (for generating sub-scripts)
     */
    {
        "descriptor depth - p2sh-p2wsh-multi (p2sh-p2wsh)",
        DEPTH_TEST_DESCRIPTOR,
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "a914aec509e284f909f769bb7dda299a717c87cc97ac87",
        "ks05yr6p"
    }, {
        "descriptor depth - p2sh-p2wsh-multi (p2wsh)",
        DEPTH_TEST_DESCRIPTOR,
        WALLY_NETWORK_NONE, 1, 0, 0, NULL, 0,
        "0020ef8110fa7ddefb3e2d02b2c1b1480389b4bc93f606281570cfc20dba18066aee",
        "ks05yr6p"
    }, {
        "descriptor depth - p2sh-p2wsh-multi (multi)",
        DEPTH_TEST_DESCRIPTOR,
        WALLY_NETWORK_NONE, 2, 0, 0, NULL, 0,
        "512103f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa82103499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e42102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e53ae",
        "ks05yr6p"
    }, {
        "descriptor depth - p2sh-p2wsh-multi (multi[0])",
        DEPTH_TEST_DESCRIPTOR,
        WALLY_NETWORK_NONE, 3, 0, 0, NULL, 0,
        "51",
        "ks05yr6p"
    }, {
        "descriptor depth - p2sh-p2wsh-multi (multi[1])",
        DEPTH_TEST_DESCRIPTOR,
        WALLY_NETWORK_NONE, 3, 1, 0, NULL, 0,
        "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
        "ks05yr6p"
    }, {
        "descriptor depth - p2sh-p2wsh-multi (multi[2])",
        DEPTH_TEST_DESCRIPTOR,
        WALLY_NETWORK_NONE, 3, 2, 0, NULL, 0,
        "03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4",
        "ks05yr6p"
    }, {
        "descriptor depth - p2sh-p2wsh-multi (multi[3])",
        DEPTH_TEST_DESCRIPTOR,
        WALLY_NETWORK_NONE, 3, 3, 0, NULL, 0,
        "02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e",
        "ks05yr6p"
    },
    /*
     * Miniscript: Randomly generated test set that covers the majority of type and node type combinations
     */
    {
        "miniscript - random 1",
        "lltvln:after(1231488000)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6300676300676300670400046749b1926869516868",
        ""
    }, {
        "miniscript - random 2",
        "uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6363829263522103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a21025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc52af0400046749b168670068670068",
        ""
    }, {
        "miniscript - random 3",
        "or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "63522103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee872921024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae926700686b63006760b2686c9b",
        ""
    }, {
        "miniscript - random 4",
        "j:and_v(vdv:after(1567547623),older(2016))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "829263766304e7e06e5db169686902e007b268",
        ""
    }, {
        "miniscript - random 5",
        "t:and_v(vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6382012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876700686982012088a820ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc58851",
        ""
    }, {
        "miniscript - random 6",
        "t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "532102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975562102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1353ae6482012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2886703010040b2696851",
        ""
    }, {
        "miniscript - random 7",
        "or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "512102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f951ae73645321022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a0121032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f2103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a53ae7c630320a107b16700689b68",
        ""
    }, {
        "miniscript - random 8",
        "or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68773646304ff64cd1db19267006864006703010040b26868",
        ""
    }, {
        "miniscript - random 9",
        "and_v(or_i(v:multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb),v:multi(2,03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)),sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "63522102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb52af67522103e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a21025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc52af6882012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c6887",
        ""
    }, {
        "miniscript - random 10",
        "j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82926352210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae7c6351b26703e2e440b2689a68",
        ""
    }, {
        "miniscript - random 11",
        "and_b(older(16),s:or_d(sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),n:after(1567547623)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "60b27c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87736404e7e06e5db192689a",
        ""
    }, {
        "miniscript - random 12",
        "j:and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82926382012088a91420195b5a3d650c17f0f29f91c33f8f6335193d078882012088a82096de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c4787736460b26868",
        ""
    }, {
        "miniscript - random 13",
        "and_b(hash256(32ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac),a:and_b(hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),a:older(1)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82012088aa2032ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac876b82012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876b51b26c9a6c9a",
        ""
    }, {
        "miniscript - random 14",
        "thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287",
        ""
    }, {
        "miniscript - random 15",
        "and_n(sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68),t:or_i(v:older(4252898),v:older(144)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68876400676303e2e440b26967029000b269685168",
        ""
    }, {
        "miniscript - random 16",
        "or_d(d:and_v(v:older(4252898),v:older(4252898)),sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "766303e2e440b26903e2e440b26968736482012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68768",
        ""
    }, {
        "miniscript - random 17",
        "c:and_v(or_c(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk_k(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764512102c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db51af682103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbeac",
        ""
    }, {
        "miniscript - random 18",
        "c:and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(1b0f3c404d12075c68c938f9f60ebea4f74941a0)),pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "5221036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a002102352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d552ae6482012088a6141b0f3c404d12075c68c938f9f60ebea4f74941a088682103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ac",
        ""
    }, {
        "miniscript - random 19",
        "and_v(andor(hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),v:hash256(939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735),v:older(50000)),after(499999999))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b2587640350c300b2696782012088aa20939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735886804ff64cd1db1",
        ""
    }, {
        "miniscript - random 20",
        "andor(hash256(5f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040),j:and_v(v:hash160(3a2bff0da9d96868e66abc4427bea4691cf61ccd),older(4194305)),ripemd160(44d90e2d3714c8663b632fcf0f9d5f22192cc4c8))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82012088aa205f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040876482012088a61444d90e2d3714c8663b632fcf0f9d5f22192cc4c8876782926382012088a9143a2bff0da9d96868e66abc4427bea4691cf61ccd8803010040b26868",
        ""
    }, {
        "miniscript - random 21",
        "or_i(c:and_v(v:after(500000),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "630320a107b1692102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac6782012088a820d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f9468768",
        ""
    }, {
        "miniscript - random 22",
        "thresh(2,c:pk_h(025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "76a9145dedfbf9ea599dd4e3ca6a80b333c472fd0b3f6988ac7c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87936b82012088a914dd69735817e0e3f6f826a9238dc2e291184f0131876c935287",
        ""
    }, {
        "miniscript - random 23",
        "and_n(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),uc:and_v(v:older(144),pk_k(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764006763029000b2692103fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ceac67006868",
        ""
    }, {
        "miniscript - random 24",
        "and_n(c:pk_k(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(4252898),a:older(16)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "2103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729ac64006763006703e2e440b2686b60b26c9a68",
        ""
    }, {
        "miniscript - random 25",
        "c:or_i(and_v(v:older(16),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)),pk_h(026a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6360b26976a9149fc5dbe5efdce10374a4dd4053c93af540211718886776a9142fbd32c8dd59ee7c17e66cb6ebea7e9846c3040f8868ac",
        ""
    }, {
        "miniscript - random 26",
        "or_d(c:pk_h(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac736421024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97ac6404e7e06e5db16702e007b26868",
        ""
    }, {
        "miniscript - random 27",
        "c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "82012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba876482012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b258876a914dd100be7d9aea5721158ebde6d6a1fd8fff93bb1886776a9149fc5dbe5efdce10374a4dd4053c93af5402117188868ac",
        ""
    }, {
        "miniscript - random 28",
        "c:andor(u:ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),or_i(pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6382012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba87670068646376a9149652d86bedf43ad264362e6e6eba6eb764508127886776a914751e76e8199196d454941c45d1b3a323f1433bd688686776a91420d637c1a6404d2227f3561fdbaff5a680dba6488868ac",
        ""
    }, {
        "miniscript - random 29",
        "c:or_i(andor(c:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6376a914fcd35ddacad9f2d5be5e464639441c6065e6955d88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9149652d86bedf43ad264362e6e6eba6eb7645081278868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac",
        ""
    }, {
        "miniscript - random 30",
        "thresh(1,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),altv:after(1000000000),altv:after(100))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac6b6300670400ca9a3bb16951686c936b6300670164b16951686c935187",
        ""
    }, {
        "miniscript - random 31",
        "thresh(2,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),ac:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),altv:after(1000000000),altv:after(100))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac6b2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ac6c936b6300670400ca9a3bb16951686c936b6300670164b16951686c935287",
        ""
    }, {
        "miniscript - random 32",
        "thresh(2,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),altv:after(100))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac6b6300670164b16951686c935287",
        ""
    }, {
        "miniscript - random 33",
        "thresh(1,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac7c2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ac935187",
        ""
    }, {
        "miniscript - random 34",
        "after(100)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "0164b1",
        ""
    }, {
        "miniscript - random 35",
        "after(1000000000)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "0400ca9a3bb1",
        ""
    }, {
        "miniscript - random 36",
        "or_b(l:after(100),al:after(1000000000))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6300670164b1686b6300670400ca9a3bb1686c9b",
        ""
    }, {
        "miniscript - random 37",
        "and_b(after(100),a:after(1000000000))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "0164b16b0400ca9a3bb16c9a",
        ""
    }, {
        "miniscript - random 38",
        "thresh(2,ltv:after(1000000000),altv:after(100),a:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6300670400ca9a3bb16951686b6300670164b16951686c936b2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac6c935287",
        ""
    },
    /*
     * Miniscript: Error cases
     */
    {
        "miniscript - Too many wrappers",
        "lltvlnlltvln:after(1231488000)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        NULL,
        ""
    }, {
        "miniscript - Number too small to parse",
        "older(-9223372036854775808)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        NULL,
        ""
    }, {
        "miniscript - Number too large to parse",
        "older(9223372036854775807)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        NULL,
        ""
    }, {
        "miniscript - Rust-miniscript issue 63",
        "nl:0",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        NULL,
        ""
    }, {
        "miniscript - Rust-miniscript context test",
        "or_i(pk(uncompressed),pk(uncompressed))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        NULL,
        ""
    }, {
        "miniscript - Threshold greater than the number of policies",
        "thresh(3,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        NULL,
        ""
    }, {
        "miniscript - Threshold of 0 is not allowed",
        "thresh(0,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        NULL,
        ""
    }, {
        "miniscript - Unknown wrapper type",
        "z:1",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        NULL,
        ""
    },
    /*
     * Miniscript: BOLT examples
     */
    {
        "miniscript - A single key",
        "c:pk_k(key_1)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac",
        ""
    }, {
        "miniscript - A single key (2)",
        "pk(key_1)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac",
        ""
    }, {
        "miniscript - One of two keys (equally likely)",
        "or_b(c:pk_k(key_1),sc:pk_k(key_2))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac7c2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac9b",
        ""
    }, {
        "miniscript - One of two keys (equally likely) (2)",
        "or_b(pk(key_1),s:pk(key_2))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac7c2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac9b",
        ""
    }, {
        "miniscript - A user and a 2FA service need to sign off, but after 90 days the user alone is enough",
        "and_v(vc:pk_k(key_user),or_d(c:pk_k(key_service),older(12960)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ad2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac736402a032b268",
        ""
    }, {
        "miniscript - A user and a 2FA service need to sign off, but after 90 days the user alone is enough (2)",
        "and_v(v:pk(key_user),or_d(pk(key_service),older(12960)))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ad2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac736402a032b268",
        ""
    }, {
        "miniscript - The BOLT #3 to_local policy",
        "andor(c:pk_k(key_local),older(1008),c:pk_k(key_revocation))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac6702f003b268",
        ""
    }, {
        "miniscript - The BOLT #3 to_local policy (2)",
        "andor(pk(key_local),older(1008),pk(key_revocation))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac6702f003b268",
        ""
    }, {
        "miniscript - The BOLT #3 offered HTLC policy",
        "t:or_c(c:pk_k(key_revocation),and_v(vc:pk_k(key_remote),or_c(c:pk_k(key_local),v:hash160(H))))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "2103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac642103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ad21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac6482012088a914d0721279e70d39fb4aa409b52839a0056454e3b588686851",
        ""
    }, {
        "miniscript - The BOLT #3 offered HTLC policy (2)",
        "t:or_c(pk(key_revocation),and_v(v:pk(key_remote),or_c(pk(key_local),v:hash160(H))))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "2103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac642103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ad21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac6482012088a914d0721279e70d39fb4aa409b52839a0056454e3b588686851",
        ""
    }, {
        "miniscript - The BOLT #3 received HTLC policy",
        "andor(c:pk_k(key_remote),or_i(and_v(vc:pk_h(key_local),hash160(H)),older(1008)),c:pk_k(key_revocation))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac676376a914d0721279e70d39fb4aa409b52839a0056454e3b588ad82012088a914d0721279e70d39fb4aa409b52839a0056454e3b5876702f003b26868",
        ""
    }, {
        "miniscript - The BOLT #3 received HTLC policy (2)",
        "andor(pk(key_remote),or_i(and_v(v:pkh(key_local),hash160(H)),older(1008)),pk(key_revocation))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac676376a914d0721279e70d39fb4aa409b52839a0056454e3b588ad82012088a914d0721279e70d39fb4aa409b52839a0056454e3b5876702f003b26868",
        ""
    },
    /*
     * Wrappers ('a' case and positioning is handled below)
     */
    {
        /* NOTE: Core generates "OP_SWAP 1", but "1" is not type O and so
         * should be invalid according to https://bitcoin.sipa.be/miniscript/:
         * s:X requires X is Bo
         */
        "miniscript - 's' wrapper",
        "s:1",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY, NULL, ""
    },
    {
        /* NOTE: Core generates "1 OP_CHECKSIG", but "1" is not type K and so
         * should be invalid according to https://bitcoin.sipa.be/miniscript/:
         * c:X requires X is K
         */
        "miniscript - 'c' wrapper",
        "c:1",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY, NULL, ""
    },
    {
        /* NOTE: Core generates "1 1", but "1" is not type V and so
         * should be invalid according to https://bitcoin.sipa.be/miniscript/:
         * t:X == and_v(X,1) requires X is V
         */
        "miniscript - 't' wrapper",
        "t:1",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY, NULL, ""
    },
    {
        /* NOTE: Core generates "OP_DUP OP_IF 1 OP_ENDIF", but "1" is not type
         * V and so should be invalid according to https://bitcoin.sipa.be/miniscript/:
         * d:X requires X is Vz
         */
        "miniscript - 'd' wrapper",
        "d:1",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY, NULL, ""
    },
    {
        "miniscript - 'v' wrapper",
        "v:1",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "5169", /* 1 OP_VERIFY */
        "zd904w4w"
    },
    {
        /* NOTE: Core generates "OP_SIZE OP_0NOTEQUAL OP_IF 1 OP_ENDIF", but
         * "1" is not type Bn and so should be invalid according
         * to https://bitcoin.sipa.be/miniscript/:
         * j:X requires X is Bn
         */
        "miniscript - 'j' wrapper",
        "j:1",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY, NULL, ""
    },
    {
        "miniscript - 'n' wrapper",
        "n:1",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "5192", /* 1 OP_0NOTEQUAL */
        "d959hk4q"
    },
    /*
     * Taproot cases
     */
    {
        "miniscript - taproot raw pubkey",
        "c:pk_k(daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY | WALLY_MINISCRIPT_TAPSCRIPT,
        "20daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729ac",
        ""
    }, {
        "miniscript - taproot bip32 key",
        "c:pk_k([bd16bee5/0]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/1)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY | WALLY_MINISCRIPT_TAPSCRIPT,
        "208c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816ac",
        ""
    }, {
        "miniscript - taproot WIF",
        "c:pk_k(L1AAHuEC7XuDM7pJ7yHLEqYK1QspMo8n1kgxyZVdgvEpVC1rkUrM)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY | WALLY_MINISCRIPT_TAPSCRIPT,
        "20ff7e7b1d3c4ba385cb1f2e6423bf30c96fb5007e7917b09ec1b6c965ef644d13ac",
        ""
    },
    /*
     * Ledger 'a' wrapper vulnerability:
     * See https://wizardsardine.com/blog/ledger-vulnerability-disclosure/
     */
    {
        "miniscript - Ledger 'a' wrapper bug (outside a built-in)",
        "a:1",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6b516c", /* OP_TOALTSTACK 1 OP_FROMALTSTACK */
        "7yjru3ju"
    },
    {
        "miniscript - Ledger 'a' wrapper bug (interior arg of a built-in)",
        "and_b(a:1,pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "6b516c210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac9a",
        "c27u392r"
    },
    {
        "miniscript - Ledger 'a' wrapper bug (final arg of built-in)",
        "and_b(pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),a:1)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, WALLY_MINISCRIPT_ONLY,
        "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac6b516c9a",
        "cj9s6y5g"
    },
    /* Multi-path */
    {
        "descriptor - multi-path",
        "pkh(mainnet_xpub/<0;1>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0,
        "76a914bb57ca9e62c7084081edc68d2cbc9524a523784288ac",
        "uvzwp2pn"
    }, {
        "descriptor - hardened multi-path",
        "pkh(mainnet_xpriv/<0';1>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0,
        "76a91417bf6f67bef3cdea94ebf7dae2193e7d7d2c654588ac",
        "e9pr7748"
    }, {
        "descriptor - ranged multi-path",
        "pkh(mainnet_xpub/<0;1>/*)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0,
        "76a9143099ad49dfdd021bf3748f7f858e0d1fa0b4f6f888ac",
        "ydnzkve4"
    },{
        "descriptor - variant ranged multi-path)",
        "combo(mainnet_xpub/<0;1>/*)",
        WALLY_NETWORK_NONE, 0, 0, 0, NULL, 0,
        "21038145454b87fc9ec3557478d6eadc2aea290b50f3c469b828abeb542ae8f8849dac",
        "j7jej0ue"
    }, {
        "descriptor - multi-path and non-multi-path elements (1)",
        "multi(2,mainnet_xpub,mainnet_xpub/<0;1;2>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0,
        "522102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f021025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b652ae",
        "la88a48t"
    }, {
        "descriptor - multi-path and non-multi-path elements (2)",
        "multi(2,mainnet_xpub/<0;1;2>/*,mainnet_xpub)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0,
        "5221038145454b87fc9ec3557478d6eadc2aea290b50f3c469b828abeb542ae8f8849d2102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f052ae",
        "y5pky4r2"
    },
    /*
     * Misc error cases (code coverage)
     */
    {
        "descriptor errchk - invalid checksum",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)#8rap84p2",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - missing required checksum",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, WALLY_MINISCRIPT_REQUIRE_CHECKSUM,
        NULL,
        ""
    },{
        "descriptor errchk - hardened xpub", /* TODO: Allow setting an xpriv into the descriptor */
        "pkh(mainnet_xpub/1'/2)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - upper case hardened indicator",
        "pkh(mainnet_xpriv/1H/2)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - trailing path",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)/1/2",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - privkey - unmatch network1",
        "wpkh(cSMSHUGbEiZQUXVw9zA33yT3m8fgC27rn2XEGZJupwCpsRS3rAYa)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - privkey - unmatch network2",
        "wpkh(cSMSHUGbEiZQUXVw9zA33yT3m8fgC27rn2XEGZJupwCpsRS3rAYa)",
        WALLY_NETWORK_LIQUID, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - privkey - unmatch network3",
        "wpkh(L4gLCkRn5VfJsDSWsrrC57kqVgq6Z2sjeRELmim5zzAgJisysh17)",
        WALLY_NETWORK_BITCOIN_TESTNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - privkey - unmatch network4",
        "wpkh(L4gLCkRn5VfJsDSWsrrC57kqVgq6Z2sjeRELmim5zzAgJisysh17)",
        WALLY_NETWORK_BITCOIN_REGTEST, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - privkey - unmatch network5",
        "wpkh(L4gLCkRn5VfJsDSWsrrC57kqVgq6Z2sjeRELmim5zzAgJisysh17)",
        WALLY_NETWORK_LIQUID_REGTEST, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xpubkey - unmatch network1",
        "wpkh(testnet_xpub)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xpubkey - unmatch network2",
        "wpkh(testnet_xpub)",
        WALLY_NETWORK_LIQUID, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xpubkey - unmatch network3",
        "wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB)",
        WALLY_NETWORK_BITCOIN_TESTNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xpubkey - unmatch network4",
        "wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB)",
        WALLY_NETWORK_BITCOIN_REGTEST, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xpubkey - unmatch network5",
        "wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB)",
        WALLY_NETWORK_LIQUID_REGTEST, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xprivkey - unmatch network1",
        "wpkh(tprv8jDG3g2yc8vh71x9ejCDSfMz4AuQRx7MMNBXXvpD4jh7CkDuB3ZmnLVcEM99jgg5MaSp7gYNpnKS5dvkGqq7ad8X63tE7yFaMGTfp6gD54p)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xprivkey - unmatch network2",
        "wpkh(tprv8jDG3g2yc8vh71x9ejCDSfMz4AuQRx7MMNBXXvpD4jh7CkDuB3ZmnLVcEM99jgg5MaSp7gYNpnKS5dvkGqq7ad8X63tE7yFaMGTfp6gD54p)",
        WALLY_NETWORK_LIQUID, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xprivkey - unmatch network3",
        "wpkh(mainnet_xpriv)",
        WALLY_NETWORK_BITCOIN_TESTNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xprivkey - unmatch network4",
        "wpkh(mainnet_xpriv)",
        WALLY_NETWORK_BITCOIN_REGTEST, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - xprivkey - unmatch network5",
        "wpkh(mainnet_xpriv)",
        WALLY_NETWORK_LIQUID_REGTEST, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - addr - empty addr",
        "addr()",
        WALLY_NETWORK_LIQUID_REGTEST, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - addr - unmatch network1",
        "addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        WALLY_NETWORK_BITCOIN_TESTNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - addr - unmatch network2",
        "addr(ex1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39q06fgz7)",
        WALLY_NETWORK_LIQUID_REGTEST, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - multisig too many keys",
        /*        1     2     3     4     5     6     7     8     9     10    11    12    13    14    15      16 */
        "sh(multi(1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1,key_1))",
        WALLY_NETWORK_LIQUID_REGTEST, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sh - non-root",
        "sh(sh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sh - multi-child",
        "sh(sh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - wsh - non-sh parent",
        "wsh(wsh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - wsh uncompressed",
        "wsh(936Xapr4wpeuiKToGeXtEcsVJAfE6ze8KUEb2UQu72rzBQsMZdX)",
        WALLY_NETWORK_BITCOIN_TESTNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - wsh - multi-child",
        "wsh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - pk - non-key child",
        "pk(1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - pk - multi-child",
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - wpkh - multi-child",
        "wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - wpkh - non-key child",
        "wpkh(1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - wpkh - wsh parent",
        "wsh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - wpkh - descriptor type parent",
        "pk(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - wpkh uncompressed",
        "wpkh(uncompressed)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sh(wpkh) uncompressed",
        "sh(wpkh(uncompressed))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - combo - any parent",
        "pk(combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - combo - multi-child",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - multi - no args",
        "multi",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - multi - no children",
        "multi()",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - multi - not enough children",
        "multi(1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - multi - no number",
        "multi(022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - multi - negative number",
        "multi(-1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - multi - non-key child",
        "multi(1,1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sortedmulti - no args",
        "sortedmulti",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sortedmulti - no children",
        "sortedmulti()",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sortedmulti - not enough children",
        "sortedmulti(1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sortedmulti - no number",
        "sortedmulti(022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sortedmulti - negative number",
        "sortedmulti(-1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sortedmulti - non-key child",
        "sortedmulti(1,1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - addr - multi-child",
        "addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3,bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - addr - non-address child",
        /* Note: The actual check in verify_addr is unreachable as children
         *       of addr() nodes are only analysed as addresses. */
        "addr(1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - addr - any parent",
        "pk(addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - raw - multi-child",
        "raw(000102030405060708090a0b0c0d0e0f,000102030405060708090a0b0c0d0e0f)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - raw - non-raw child",
        /* Note: The actual check in verify_raw is unreachable as children
         *       of raw() nodes are only analysed as raw hex. */
        "raw(1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - raw - any parent",
        "pk(raw(000102030405060708090a0b0c0d0e0f))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - after - non number child",
        "wsh(after(key_1))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - after - zero delay",
        "wsh(after(0))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - after - negative delay",
        "wsh(after(-1))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - after - delay too large",
        "wsh(after(2147483648))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - older - non number child",
        "wsh(older(key_1))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - older - zero delay",
        "wsh(older(0))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - older - negative delay",
        "wsh(older(-1))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - older - delay too large",
        "wsh(older(2147483648))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "miniscript - thresh - zero required",
        "wsh(thresh(0,c:pk_k(key_1),sc:pk_k(key_2),sc:pk_k(key_3)))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "miniscript - thresh - require more than available children",
        "wsh(thresh(4,c:pk_k(key_1),sc:pk_k(key_2),sc:pk_k(key_3)))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - wsh-pk uncompressed",
        "wsh(pk(uncompressed))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor - sh(wsh-pk) uncompressed",
        "sh(wsh(pk(uncompressed)))",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "miniscript - core recursion limit",
        "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },{
        "descriptor errchk - wrapper on non-miniscript element",
        "v:addr(moUfpGiXWcFd5ueRn3988VDqRSkB5NrEmW)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },
    /* https://github.com/rust-bitcoin/rust-miniscript/blob/master/src/descriptor/key.rs
     * (Adapted)
     */
    {
        "miniscript - invalid xpub",
        "pk([78412e3a]xpub1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaLcgJvLJuZZvRcEL/1/1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "miniscript - invalid raw key",
        "pk([78412e3a]0208a117f3897c3a13c9384b8695eed98dc31bc2500feb19a1af424cd47a5d83/1/1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "miniscript - invalid fingerprint separator",
        "pk([78412e3a]]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798/1/1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "miniscript - fuzzer error (1)",
        "pk([11111f11]033333333333333333333333333333323333333333333333333333333433333333]]333]]3]]101333333333333433333]]]10]333333mmmm)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "miniscript - fuzzer error (2)",
        "pk(0777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "miniscript - Non-hex fingerprint",
        "pk([NonHexor]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "miniscript - Short fingerprint",
        "pk([1122334]",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "miniscript - Long fingerprint",
        "pk([112233445]",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },
    /* https://github.com/rust-bitcoin/rust-miniscript/blob/master/src/descriptor/mod.rs */
    {
        "descriptor - unclosed brace",
        "(",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - unclosed brace (nested)",
        "(x()",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - invalid char",
        "(\x7f()3",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - empty pk",
        "pk(]",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    },
    /* TODO: Add more tests for verify_x cases */
    /* Multi-path error cases */
    {
        "descriptor - unterminated multi-path (1)",
        "pkh(mainnet_xpub/<)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - unterminated multi-path (2)",
        "pkh(mainnet_xpub/<0)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - unterminated multi-path (3)",
        "pkh(mainnet_xpub/<0;)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - unterminated multi-path (4)",
        "pkh(mainnet_xpub/<0;1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - multi-path missing first child",
        "pkh(mainnet_xpub/<;1>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - multi-path missing final child",
        "pkh(mainnet_xpub/<0;1;>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - multi-path non-number child",
        "pkh(mainnet_xpub/<0;a>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - multi-path child separator",
        "pkh(mainnet_xpub/<0;/>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - multi-path whildcard (1)",
        "pkh(mainnet_xpub/<*;1>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - multi-path whildcard (2)",
        "pkh(mainnet_xpub/<0;*>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - not enough  multi-path elements",
        "pkh(mainnet_xpub/<0>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - Too many multi-path elements (>255)",
        "pkh(mainnet_xpub/<1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - mismatched multi-path element counts",
        "multi(2,mainnet_xpub/<0;1>,mainnet_xpub/<0;1;2>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }, {
        "descriptor - hardened xpub multi-path", /* TODO: Allow setting an xpriv into the descriptor */
        "pkh(mainnet_xpub/<0';1>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, NULL, 0, NULL, ""
    }
};

#define ADDR(a) 1, { a, "", "", "", "", "", "", "", "", "", "", "", "", "", \
    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "" }

static const struct address_test {
    const char *name;
    const char *descriptor;
    const uint32_t network;
    const uint32_t variant;
    const uint32_t multi_index;
    const uint32_t child_num;
    const size_t num_addresses;
    const char *addresses[30];
} g_address_cases[] = {
    /*
     * Single address cases
     */
    {
        "address - p2pkh - mainnet",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP")
    },{
        "address - p2pkh - testnet",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        WALLY_NETWORK_BITCOIN_TESTNET,
        0, 0, 0,
        ADDR("mg8Jz5776UdyiYcBb9Z873NTozEiADRW5H")
    },{
        "address - p2pkh - regtest",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        0, 0, 0,
        ADDR("mg8Jz5776UdyiYcBb9Z873NTozEiADRW5H")
    },{
        "address - p2wpkh - mainnet",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1q0ht9tyks4vh7p5p904t340cr9nvahy7u3re7zg")
    },{
        "address - p2wpkh - testnet",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        WALLY_NETWORK_BITCOIN_TESTNET,
        0, 0, 0,
        ADDR("tb1q0ht9tyks4vh7p5p904t340cr9nvahy7um9zdem")
    },{
        "address - p2wpkh - regtest",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        0, 0, 0,
        ADDR("bcrt1q0ht9tyks4vh7p5p904t340cr9nvahy7uevmqwj")
    },{
        "address - p2sh-p2wpkh - mainnet",
        "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("3LKyvRN6SmYXGBNn8fcQvYxW9MGKtwcinN")
    },{
        "address - p2sh-p2wpkh - liquidv1",
        "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_LIQUID,
        0, 0, 0,
        ADDR("H1pVQ7VtauJK4v7ixvwFQpDFYW2Q6eiPVx")
    },{
        "address - p2sh-p2wpkh - liquidregtest",
        "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        WALLY_NETWORK_LIQUID_REGTEST,
        0, 0, 0,
        ADDR("XVzCr2EG9PyrWX8qr2visL1aCfJMhGTZyS")
    },{
        "address - p2sh-p2wsh - mainnet",
        "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("39XGHYpYmJV9sGFoGHZeU2rLkY6r1MJ6C1")
    },{
        "address - p2sh-p2wsh - liquidv1",
        "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
        WALLY_NETWORK_LIQUID,
        0, 0, 0,
        ADDR("Gq1mmExLuSEwfzzk6YtUxJ769grv6T5Tak")
    },{
        "address - p2wsh-multi - mainnet",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39qn4zazc")
    },{
        "address - p2wsh-multi - testnet",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        WALLY_NETWORK_BITCOIN_TESTNET,
        0, 0, 0,
        ADDR("tb1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39qya5jch")
    },{
        "address - p2wsh-multi - regtest",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        WALLY_NETWORK_BITCOIN_REGTEST,
        0, 0, 0,
        ADDR("bcrt1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39qfy75dd")
    },{
        "address - p2wsh-multi - liquidv1",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        WALLY_NETWORK_LIQUID,
        0, 0, 0,
        ADDR("ex1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39q06fgz7")
    },{
        "address - p2wsh-multi - liquidregtest",
        "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        WALLY_NETWORK_LIQUID_REGTEST,
        0, 0, 0,
        ADDR("ert1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39qchk2yf")
    },{
        "address - p2pkh-xpub-derive",
        "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("1PdNaNxbyQvHW5QHuAZenMGVHrrRaJuZDJ")
    },{
        "descriptor - p2pkh-empty-path",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/)",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("15XVotxCAV7sRx1PSCkQNsGw3W9jT9A94R")
    },{
        "address - p2pkh-parent-derive",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1/*)",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("14qCH92HCyDDBFFZdhDt1WMfrMDYnBFYMF")
    },{
        "address - p2wsh-multi-xpub",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c")
    },{
        "address - p2wsh-sortedmulti-xpub",
        "wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c")
    },{
        "address - addr-btc-legacy-testnet",
        "addr(moUfpGiXWcFd5ueRn3988VDqRSkB5NrEmW)",
        WALLY_NETWORK_BITCOIN_TESTNET,
        0, 0, 0,
        ADDR("moUfpGiXWcFd5ueRn3988VDqRSkB5NrEmW")
    },{
        "address - addr-btc-legacy-testnet/regtest",
        "addr(moUfpGiXWcFd5ueRn3988VDqRSkB5NrEmW)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        0, 0, 0,
        ADDR("moUfpGiXWcFd5ueRn3988VDqRSkB5NrEmW")
    },{
        "address - addr-btc-segwit-mainnet",
        "addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
    },{
        "address - p2pkh-xpriv",
        "pkh(mainnet_xpriv/1h/2)",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("1HH6H4km128m4NsJMNVN2qqCHukbEhgU3V")
    },{
        "address - A single key",
        "wsh(c:pk_k(key_1))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qlfdlf2hraeshcmxwr9m0d47jshp4jcfllmk5s8csvlmzhs84fpfqa6ufv5")
    },{
        "address - One of two keys (equally likely)",
        "wsh(or_b(c:pk_k(key_1),sc:pk_k(key_2)))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qrz5alxrt5y9umr6s8ay4e26l6qxflv3uq52ruewmhfy77nv2sf0spz2em3")
    },{
        "address - A user and a 2FA service need to sign off, but after 90 days the user alone is enough",
        "wsh(and_v(vc:pk_k(key_user),or_d(c:pk_k(key_service),older(12960))))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qzfjfgmrxd9vdj530v0wdely9jsda6kunpzc7d35xj6zh2phkenkstn6ur7")
    },{
        "address - The BOLT #3 to_local policy",
        "wsh(andor(c:pk_k(key_local),older(1008),c:pk_k(key_revocation)))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qq5k0r6wfp6dz3q7cjpr856spsdlzrvah2kn58jwedg4klq596lqq90rr7h")
    },{
        "address - The BOLT #3 offered HTLC policy",
        "wsh(t:or_c(c:pk_k(key_revocation),and_v(vc:pk_k(key_remote),or_c(c:pk_k(key_local),v:hash160(H)))))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qlyjexc7mp7kv0wt6ktqzjnz0yxsv644srw65aj42tzvsz24wr0pqc6enkg")
    },{
        "address - The BOLT #3 received HTLC policy",
        "wsh(andor(c:pk_k(key_remote),or_i(and_v(vc:pk_h(key_local),hash160(H)),older(1008)),c:pk_k(key_revocation)))",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0,
        ADDR("bc1qsag4uqzecdz74fwvew4fe5t26ynxu7nfudgdhqkcu8enep3g2vpsvp0wl0")
    },
    /*
     * combo()
     */
    {
        "address - combo(variant 0, p2pk) invalid (no addr representation)",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        0, 0, 0,
        ADDR("")
    },{
        "address - combo(variant 1, p2pkh)",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        1, 0, 0,
        ADDR("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r")
    },{
        "address - combo(variant 2, p2wpkh)",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        2, 0, 0,
        ADDR("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
    },{
        "address - combo(variant 3, p2sh-p2wpkh)",
        "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        3, 0, 0,
        ADDR("2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN")
    },{
        "address - combo(variant 0, p2pk uncompressed ) invalid (no addr representation)",
        "combo(04a238b0cbea14c9b3f59d0a586a82985f69af3da50579ed5971eefa41e6758ee7f1d77e4d673c6e7aac39759bb762d22259e27bf93572e9d5e363d5a64b6c062b)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        0, 0, 0,
        ADDR("")
    },{
        "address - combo(variant 1, p2pkh uncompressed)",
        "combo(04a238b0cbea14c9b3f59d0a586a82985f69af3da50579ed5971eefa41e6758ee7f1d77e4d673c6e7aac39759bb762d22259e27bf93572e9d5e363d5a64b6c062b)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        1, 0, 0,
        ADDR("mn9rm3FtHUHANae2p5jURy9GXJGDM1ox43")
    },
    /*
     * Multi-path
     */
    {
        "address - multi-path (index 0)",
        "pkh(testnet_xpub/<0;1>)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        0, 0, 0,
        ADDR("mokrWMifUTCBysucKZTZ7Uij8915VYcwWX")
    }, {
        "address - multi-path (index 1)",
        "pkh(testnet_xpub/<0;1>)",
        WALLY_NETWORK_BITCOIN_REGTEST,
        0, 1, 0,
        ADDR("mjqyCpkZkwdh47mKQxYFSiu1RMVSdrVvSZ")
    },
    /*
     * Multiple address cases
     */
    {
        "address list - p2wsh multisig (0-29)",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))#t2zpj2eu",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 0, 30,
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
        }
    }, {
        "address list - p2wsh multisig (30-40)",
        "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))#t2zpj2eu",
        WALLY_NETWORK_BITCOIN_MAINNET,
        0, 0, 30, 11,
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
            "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""
        }
    },
    /*
     * Address error cases
     */
    {
        "address errchk - no network",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        WALLY_NETWORK_NONE, 0, 0, 0, ADDR("")
    },{
        "address errchk - invalid network",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        0xf0, 0, 0, 0, ADDR("")
    },{
        "address errchk - addr - mismatched network 1",
        "addr(bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        WALLY_NETWORK_BITCOIN_TESTNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - addr - unmatched network 2",
        "addr(ex1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39q06fgz7)",
        WALLY_NETWORK_LIQUID_REGTEST, 0, 0, 0, ADDR("")
    },{
        "address errchk - addr - network conflict",
        "multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB,testnet_xpub)",
        WALLY_NETWORK_NONE, 0, 0, 0, ADDR("")
    },{
        "address errchk - addr - no HRP",
        "addr(bcqrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3)",
        WALLY_NETWORK_BITCOIN_TESTNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - unsupported address - p2pk",
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - unsupported address - uncompressed p2pk",
        "pk(uncompressed)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - unsupported address - raw",
        "raw(6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e)#zf2avljj",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - unterminated key origin",
        "pkh([d34db33f/44'/0'/0'mainnet_xpub/1/*)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - double slash",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub//)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - middle double slash",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1//2)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - end slash",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1/2/)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - duplicate wildcard (1)",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1/**)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - duplicate wildcard (2)",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1/*/*)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - non-final wildcard",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1/*/1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - hardened from xpub",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1h)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - hardened wildcard from xpub",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1/*h)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - index too large",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/2147483648/1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - invalid path character",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/3c/1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        /* Note: mainnet_xpub depth is 4, so this valid path takes it over the depth limit */
        "address errchk - depth exceeded",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        /* Paths over 255 elements in length are up-front invalid */
        "address errchk - path too long",
        "pkh([d34db33f/44'/0'/0']mainnet_xpub/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - invalid descriptor character",
        "pkh(\b)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - unknown function",
        "foo(mainnet_xpub)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - missing leading brace",
        ")",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - trailing value",
        "pkh(mainnet_xpub),1",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 0, 0, ADDR("")
    },{
        "address errchk - Invalid multi-path index",
        "pkh(mainnet_xpub/<0;1>)",
        WALLY_NETWORK_BITCOIN_MAINNET, 0, 2, 0, ADDR("")
    }
};

static bool check_descriptor_to_script(const struct descriptor_test* test)
{
    struct wally_descriptor *descriptor;
    size_t written, max_written;
    const size_t script_len = 520;
    unsigned char *script = malloc(script_len);
    char *checksum, *canonical;
    int expected_ret, ret, len_ret;
    uint32_t multi_index = 0;
    uint32_t child_num = test->child_num ? *test->child_num : 0, features;

    expected_ret = test->script ? WALLY_OK : WALLY_EINVAL;

    ret = wally_descriptor_parse(test->descriptor, &g_key_map, test->network,
                                 test->flags, &descriptor);
    if (expected_ret == WALLY_OK || ret == expected_ret) {
        /* For failure cases, we may fail when generating instead of parsing,
         * we catch those cases below */
        if (!check_ret("descriptor_parse", ret, expected_ret))
            return false;

        if (expected_ret != WALLY_OK) {
            free(script);
            return true;
        }
    }

    ret = wally_descriptor_to_script(descriptor,
                                     test->depth, test->index,
                                     test->variant, multi_index,
                                     child_num, 0,
                                     script, script_len, &written);
    if (!check_ret("descriptor_to_script", ret, expected_ret))
        return false;
    if (expected_ret != WALLY_OK) {
        wally_descriptor_free(descriptor);
        free(script);
        return true;
    }

    ret = wally_descriptor_get_features(descriptor, &features);
    if (!check_ret("descriptor_get_features", ret, WALLY_OK))
        return false;

    len_ret = wally_descriptor_to_script_get_maximum_length(descriptor,
                                                            0, 0, 0, 0, 0, 0,
                                                            &max_written);
    if (!check_ret("descriptor_to_script_get_maximum_length", len_ret, WALLY_OK) ||
        max_written < written)
        return false;

    ret = wally_descriptor_get_checksum(descriptor, 0, &checksum);
    if (!check_ret("descriptor_get_checksum", ret, WALLY_OK))
        return false;

    ret = wally_descriptor_canonicalize(descriptor, 0, &canonical);
    wally_free_string(canonical);
    if (!check_ret("descriptor_canonicalize", ret, WALLY_OK))
        return false;

    ret = check_varbuff("descriptor_to_script", script, written, test->script) &&
          (!*test->checksum || !strcmp(checksum, test->checksum));
    if (!ret)
        printf("%s:  expected [%s], got [%s]\n", "descriptor_to_script",
               test->checksum, checksum);

    wally_free_string(checksum);
    wally_descriptor_free(descriptor);
    free(script);
    return !!ret;
}

static bool check_descriptor_to_address(const struct address_test *test)
{
    struct wally_descriptor *descriptor;
    char *addresses[64];
    uint32_t flags = 0;
    size_t i;
    int ret, expected_ret = *test->addresses[0] ? WALLY_OK : WALLY_EINVAL;

    ret = wally_descriptor_parse(test->descriptor, &g_key_map, test->network,
                                 flags, &descriptor);

    if (expected_ret == WALLY_OK || ret == expected_ret) {
        /* For failure cases, we may fail when generating instead of parsing,
         * we catch those cases below */
        if (!check_ret("descriptor_parse", ret, expected_ret))
            return false;

        if (expected_ret != WALLY_OK)
            return true;
    }

    ret = wally_descriptor_to_addresses(descriptor, test->variant,
                                        test->multi_index, test->child_num,
                                        flags, addresses, test->num_addresses);
    if (!check_ret("descriptor_to_addresses", ret, expected_ret))
        return false;

    if (expected_ret == WALLY_OK) {
        for (i = 0; i < test->num_addresses; ++i) {
            if (strcmp(test->addresses[i], addresses[i]) != 0) {
                printf("%s: expected address: %s, got %s\n", "descriptor_to_addresses",
                       test->addresses[i], addresses[i]);
                return false;
            }
            wally_free_string(addresses[i]);
        }
    }
    wally_descriptor_free(descriptor);
    return true;
}

int main(void)
{
    bool tests_ok = true;
    size_t i;

    for (i = 0; i < NUM_ELEMS(g_descriptor_cases); ++i) {
        if (!check_descriptor_to_script(&g_descriptor_cases[i])) {
            printf("[%s] descriptor test failed!\n", g_descriptor_cases[i].name);
            tests_ok = false;
        }
    }

    for (i = 0; i < NUM_ELEMS(g_address_cases); ++i) {
        if (!check_descriptor_to_address(&g_address_cases[i])) {
            printf("[%s] descriptor_address test failed!\n", g_address_cases[i].name);
            tests_ok = false;
        }
    }

    wally_cleanup(0);
    return tests_ok ? 0 : 1;
}
