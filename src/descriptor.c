#include "internal.h"

#include "script.h"
#include "script_int.h"

#include <include/wally_address.h>
#include <include/wally_bip32.h>
#include <include/wally_crypto.h>
#include <include/wally_psbt.h>
#include <include/wally_script.h>
#include <include/wally_descriptor.h>

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#define NUM_ELEMS(a) (sizeof(a) / sizeof(a[0]))

/* Properties and expressions definition */
#define TYPE_NONE  0x00
#define TYPE_B     0x01  /* Base expressions */
#define TYPE_V     0x02  /* Verify expressions */
#define TYPE_K     0x04  /* Key expressions */
#define TYPE_W     0x08  /* Wrapped expressions */
#define TYPE_MASK  0x0F  /* expressions mask */

#define PROP_Z  0x00000100  /* Zero-arg property */
#define PROP_O  0x00000200  /* One-arg property */
#define PROP_N  0x00000400  /* Nonzero arg property */
#define PROP_D  0x00000800  /* Dissatisfiable property */
#define PROP_U  0x00001000  /* Unit property */
#define PROP_E  0x00002000  /* Expression property */
#define PROP_F  0x00004000  /* Forced property */
#define PROP_S  0x00008000  /* Safe property */
#define PROP_M  0x00010000  /* Nonmalleable property */
#define PROP_X  0x00020000  /* Expensive verify */

/* OP_0 properties: Bzudemsx */
#define PROP_OP_0  (TYPE_B | PROP_Z | PROP_U | PROP_D | PROP_E | PROP_M | PROP_S | PROP_X)
/* OP_1 properties: Bzufmx */
#define PROP_OP_1  (TYPE_B | PROP_Z | PROP_U | PROP_F | PROP_M | PROP_X)

#define KIND_MINISCRIPT 0x01
#define KIND_DESCRIPTOR 0x02 /* Output Descriptor */
#define KIND_RAW        0x04
#define KIND_NUMBER     0x08
#define KIND_ADDRESS    0x10
#define KIND_KEY        0x20

#define KIND_BASE58    (0x0100 | KIND_ADDRESS)
#define KIND_BECH32    (0x0200 | KIND_ADDRESS)

#define KIND_PUBLIC_KEY          (0x001000 | KIND_KEY)
#define KIND_PRIVATE_KEY         (0x002000 | KIND_KEY)
#define KIND_BIP32               (0x004000 | KIND_KEY)
#define KIND_BIP32_PRIVATE_KEY   (0x010000 | KIND_BIP32)
#define KIND_BIP32_PUBLIC_KEY    (0x020000 | KIND_BIP32)

/* FIXME: Calculate the script length instead of using this maximal size */
#define DESCRIPTOR_MAX_SIZE     1000000
#define DESCRIPTOR_MIN_SIZE     20
#define MINISCRIPT_MULTI_MAX    20
#define REDEEM_SCRIPT_MAX_SIZE  520
#define WITNESS_SCRIPT_MAX_SIZE 10000

#define DESCRIPTOR_CHECKSUM_LENGTH  8

/* output descriptor */
#define KIND_DESCRIPTOR_PK       (0x00000100 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_PKH      (0x00000200 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_MULTI    (0x00000300 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_MULTI_S  (0x00000400 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_SH       (0x00000500 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_WPKH     (0x00010000 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_WSH      (0x00020000 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_COMBO    (0x00030000 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_ADDR     (0x00040000 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_RAW      (0x00050000 | KIND_DESCRIPTOR)

/* miniscript */
#define KIND_MINISCRIPT_PK        (0x00000100 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_PKH       (0x00000200 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_MULTI     (0x00000300 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_PK_K      (0x00001000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_PK_H      (0x00002000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OLDER     (0x00010000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_AFTER     (0x00020000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_SHA256    (0x00030000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_HASH256   (0x00040000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_RIPEMD160 (0x00050000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_HASH160   (0x00060000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_THRESH    (0x00070000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_ANDOR     (0x01000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_AND_V     (0x02000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_AND_B     (0x03000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_AND_N     (0x04000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OR_B      (0x05000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OR_C      (0x06000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OR_D      (0x07000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_OR_I      (0x08000000 | KIND_MINISCRIPT)

/* A node in a parsed miniscript expression */
typedef struct ms_node_t {
    struct ms_node_t *next;
    struct ms_node_t *child;
    struct ms_node_t *parent;
    uint32_t kind;
    uint32_t type_properties;
    int64_t number;
    const char *child_path;
    const char *data;
    uint32_t data_len;
    uint32_t child_path_len;
    char wrapper_str[12];
    unsigned char builtin;
    bool is_uncompressed_key;
    bool is_xonly_key;
} ms_node;

/* Built-in miniscript expressions */
typedef int (*node_verify_fn_t)(ms_node *node);
typedef int (*node_gen_fn_t)(ms_node *node, int32_t child_num,
                             unsigned char *script, size_t script_len, size_t *written);

struct ms_builtin_t {
    const char *name;
    const uint32_t name_len;
    const uint32_t kind;
    const uint32_t type_properties;
    const uint32_t child_count; /* Number of expected children */
    const node_verify_fn_t verify_fn;
    const node_gen_fn_t generate_fn;
};

struct ms_context {
    unsigned char *script;
    size_t script_len;
    uint32_t child_num; /* Start child number for derivation */
    size_t num_derivations; /* How many incrementing children to derive */
};

struct multisig_sort_data_t {
    size_t pubkey_len;
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
};

struct addr_ver_t {
    const unsigned char network;
    const unsigned char version_p2pkh;
    const unsigned char version_p2sh;
    const unsigned char version_wif;
    const char family[8];
};

static const struct addr_ver_t g_address_versions[] = {
    {
        WALLY_NETWORK_BITCOIN_MAINNET,
        WALLY_ADDRESS_VERSION_P2PKH_MAINNET,
        WALLY_ADDRESS_VERSION_P2SH_MAINNET,
        WALLY_ADDRESS_VERSION_WIF_MAINNET,
        { 'b', 'c', '\0', '\0', '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_BITCOIN_TESTNET,
        WALLY_ADDRESS_VERSION_P2PKH_TESTNET,
        WALLY_ADDRESS_VERSION_P2SH_TESTNET,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        { 't', 'b', '\0', '\0', '\0', '\0', '\0', '\0' }
    },
    {   /* Bitcoin regtest. This must remain immediately after WALLY_NETWORK_BITCOIN_TESTNET */
        WALLY_NETWORK_BITCOIN_REGTEST,
        WALLY_ADDRESS_VERSION_P2PKH_TESTNET,
        WALLY_ADDRESS_VERSION_P2SH_TESTNET,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        { 'b', 'c', 'r', 't', '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_LIQUID,
        WALLY_ADDRESS_VERSION_P2PKH_LIQUID,
        WALLY_ADDRESS_VERSION_P2SH_LIQUID,
        WALLY_ADDRESS_VERSION_WIF_MAINNET,
        { 'e', 'x', '\0', '\0', '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_LIQUID_TESTNET,
        WALLY_ADDRESS_VERSION_P2PKH_LIQUID_TESTNET,
        WALLY_ADDRESS_VERSION_P2SH_LIQUID_TESTNET,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        { 't', 'e', 'x', '\0', '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_LIQUID_REGTEST,
        WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST,
        WALLY_ADDRESS_VERSION_P2SH_LIQUID_REGTEST,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        { 'e', 'r', 't', '\0', '\0', '\0', '\0', '\0' }
    },
};

static const struct addr_ver_t *addr_ver_from_network(uint32_t network)
{
    size_t i;
    for (i = 0; i < NUM_ELEMS(g_address_versions); ++i) {
        if (network == g_address_versions[i].network)
            return g_address_versions + i;
    }
    return NULL; /* Not found */
}

static const struct addr_ver_t *addr_ver_from_version(
    uint32_t version, const struct addr_ver_t *expected, bool *is_p2sh)
{
    size_t i;

    for (i = 0; i < NUM_ELEMS(g_address_versions); ++i) {
        const struct addr_ver_t *addr_ver = g_address_versions + i;
        if (version == addr_ver->version_p2pkh || version == addr_ver->version_p2sh) {
            /* Found a matching network based on base58 address version */
            if (expected && addr_ver->network != expected->network) {
                /* Mismatch on caller provided network */
                if (addr_ver->network == WALLY_NETWORK_BITCOIN_TESTNET &&
                    expected->network == WALLY_NETWORK_BITCOIN_REGTEST)
                    ++addr_ver; /* testnet/regtest use the same versions; use regtest */
                else
                    return NULL; /* Mismatch on provided network: Not found */
            }
            *is_p2sh = version == addr_ver->version_p2sh;
            return addr_ver; /* Found */
        }
    }
    return NULL; /* Not found */
}

static const struct addr_ver_t *addr_ver_from_family(
    const char *family, size_t family_len, uint32_t network)
{
    const struct addr_ver_t *addr_ver = addr_ver_from_network(network);
    if (!addr_ver || !family || strlen(addr_ver->family) != family_len ||
        memcmp(family, addr_ver->family, family_len))
        return NULL; /* Not found or mismatched address version */
    return addr_ver; /* Found */
}

/* Function prototype */
static const struct ms_builtin_t *builtin_get(const ms_node *node);
static int analyze_address(const char *str, size_t str_len,
                           ms_node *node, ms_node *parent,
                           const struct addr_ver_t *addr_ver,
                           unsigned char *script, size_t script_len, size_t *written);
static int generate_script(ms_node *node, uint32_t child_num,
                           unsigned char *script, size_t script_len, size_t *written);

/* Wrapper for strtoll */
static bool strtoll_n(const char *str, size_t str_len, int64_t *v)
{
    char buf[21]; /* from -9223372036854775808 to 9223372036854775807 */
    char *end = NULL;

    if (!str_len || str_len > sizeof(buf) - 1u ||
        (str[0] != '-' && (str[0] < '0' || str[0] > '9')))
        return false; /* Too short/long, or invalid format */

    memcpy(buf, str, str_len);
    buf[str_len] = '\0';
    *v = strtoll(buf, &end, 10);
    return end == buf + str_len && *v != LLONG_MIN && *v != LLONG_MAX;
}

static uint32_t node_get_child_count(const ms_node *node)
{
    int32_t ret = 0;
    const ms_node *child;
    for (child = node->child; child; child = child->next)
        ++ret;
    return ret;
}

static bool node_has_uncompressed_key(const ms_node *node)
{
    const ms_node *child;
    for (child = node->child; child; child = child->next)
        if (child->is_uncompressed_key || node_has_uncompressed_key(child))
            return true;
    return false;
}

static bool node_is_root(const ms_node *node)
{
    /* True if this is a (possibly temporary) top level node, or an argument of a builtin */
    return !node->parent || node->parent->builtin;
}

static void node_free(ms_node *node)
{
    if (node) {
        ms_node *child = node->child;
        while (child) {
            ms_node *next = child->next;
            node_free(child);
            child = next;
        }
        clear_and_free(node, sizeof(*node));
    }
}

static int verify_sh(ms_node *node)
{
    if (node->parent || !node->child->builtin)
        return WALLY_EINVAL;

    node->type_properties = node->child->type_properties;
    return WALLY_OK;
}

static int verify_wsh(ms_node *node)
{
    if (node->parent && node->parent->kind != KIND_DESCRIPTOR_SH)
        return WALLY_EINVAL;
    if (!node->child->builtin || node_has_uncompressed_key(node))
        return WALLY_EINVAL;

    node->type_properties = node->child->type_properties;
    return WALLY_OK;
}

static int verify_pk(ms_node *node)
{
    if (node->child->builtin || !(node->child->kind & KIND_KEY))
        return WALLY_EINVAL;

    node->type_properties = builtin_get(node)->type_properties;
    return WALLY_OK;
}

static int verify_wpkh(ms_node *node)
{
    ms_node *parent = node->parent;
    if (parent && (!parent->builtin || parent->kind & KIND_MINISCRIPT))
        return WALLY_EINVAL;
    if (node->child->builtin || !(node->child->kind & KIND_KEY))
        return WALLY_EINVAL;

    for (/* no-op */; parent; parent = parent->parent)
        if (parent->kind == KIND_DESCRIPTOR_WSH)
            return WALLY_EINVAL;

    return node_has_uncompressed_key(node) ?  WALLY_EINVAL : WALLY_OK;
}

static int verify_combo(ms_node *node)
{
    if (node->parent)
        return WALLY_EINVAL;

    /* Since the combo is of multiple return types, the return value is wpkh or pkh. */
    return node_has_uncompressed_key(node) ? verify_pk(node) : verify_wpkh(node);
}

static int verify_multi(ms_node *node)
{
    const int64_t count = node_get_child_count(node);
    ms_node *top, *key;

    if (count < 2 || count - 1 > MINISCRIPT_MULTI_MAX)
        return WALLY_EINVAL;

    top = node->child;
    if (!top->next || top->builtin || top->kind != KIND_NUMBER ||
        top->number <= 0 || count < top->number)
        return WALLY_EINVAL;

    key = top->next;
    while (key) {
        if (key->builtin || !(key->kind & KIND_KEY))
            return WALLY_EINVAL;
        key = key->next;
    }

    node->type_properties = builtin_get(node)->type_properties;
    return WALLY_OK;
}

static int verify_addr(ms_node *node)
{
    if (node->parent || node->child->builtin || !(node->child->kind & KIND_ADDRESS))
        return WALLY_EINVAL;
    return WALLY_OK;
}

static int verify_raw(ms_node *node)
{
    if (node->parent || node->child->builtin || !(node->child->kind & KIND_RAW))
        return WALLY_EINVAL;
    return WALLY_OK;
}

static int verify_delay(ms_node *node)
{
    if (node->child->builtin || node->child->kind != KIND_NUMBER ||
        node->child->number <= 0 || node->child->number > 0x7fffffff)
        return WALLY_EINVAL;

    node->type_properties = builtin_get(node)->type_properties;
    return WALLY_OK;
}

static int verify_hash_type(ms_node *node)
{
    if (node->child->builtin || !(node->child->kind & KIND_RAW))
        return WALLY_EINVAL;

    node->type_properties = builtin_get(node)->type_properties;
    return WALLY_OK;
}

static uint32_t verify_andor_property(uint32_t x_property, uint32_t y_property, uint32_t z_property)
{
    /* Y and Z are both B, K, or V */
    uint32_t prop = PROP_X;
    uint32_t need_x = TYPE_B | PROP_D | PROP_U;
    uint32_t need_yz = TYPE_B | TYPE_K | TYPE_V;
    if (!(x_property & TYPE_B) || !(x_property & need_x))
        return 0;
    if (!(y_property & z_property & need_yz))
        return 0;

    prop |= y_property & z_property & need_yz;
    prop |= x_property & y_property & z_property & PROP_Z;
    prop |= (x_property | (y_property & z_property)) & PROP_O;
    prop |= y_property & z_property & PROP_U;
    prop |= z_property & PROP_D;
    if (x_property & PROP_S || y_property & PROP_F) {
        prop |= z_property & PROP_F;
        prop |= x_property & z_property & PROP_E;
    }
    if (x_property & PROP_E &&
        (x_property | y_property | z_property) & PROP_S) {
        prop |= x_property & y_property & z_property & PROP_M;
    }
    prop |= z_property & (x_property | y_property) & PROP_S;
    return prop;
}

static int verify_andor(ms_node *node)
{
    node->type_properties = verify_andor_property(node->child->type_properties,
                                                  node->child->next->type_properties,
                                                  node->child->next->next->type_properties);
    return node->type_properties ? WALLY_OK : WALLY_EINVAL;
}

static uint32_t verify_and_v_property(uint32_t x_property, uint32_t y_property)
{
    uint32_t prop = 0;
    prop |= x_property & PROP_N;
    prop |= y_property & (PROP_U | PROP_X);
    prop |= x_property & y_property & (PROP_D | PROP_M | PROP_Z);
    prop |= (x_property | y_property) & PROP_S;
    if (x_property & TYPE_V)
        prop |= y_property & (TYPE_K | TYPE_V | TYPE_B);
    if (x_property & PROP_Z)
        prop |= y_property & PROP_N;
    if ((x_property | y_property) & PROP_Z)
        prop |= (x_property | y_property) & PROP_O;
    if (y_property & PROP_F || x_property & PROP_S)
        prop |= PROP_F;

    return prop & TYPE_MASK ? prop : 0;
}

static int verify_and_v(ms_node *node)
{
    node->type_properties = verify_and_v_property(
        node->child->type_properties,
        node->child->next->type_properties);
    return node->type_properties ? WALLY_OK : WALLY_EINVAL;
}

static int verify_and_b(ms_node *node)
{
    const uint32_t x_prop = node->child->type_properties;
    const uint32_t y_prop = node->child->next->type_properties;
    node->type_properties = PROP_U | PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_D | PROP_Z | PROP_M);
    node->type_properties |= (x_prop | y_prop) & PROP_S;
    node->type_properties |= x_prop & PROP_N;
    if (y_prop & TYPE_W)
        node->type_properties |= x_prop & TYPE_B;
    if ((x_prop | y_prop) & PROP_Z)
        node->type_properties |= (x_prop | y_prop) & PROP_O;
    if (x_prop & PROP_Z)
        node->type_properties |= y_prop & PROP_N;
    if ((x_prop & y_prop) & PROP_S)
        node->type_properties |= x_prop & y_prop & PROP_E;
    if (((x_prop & y_prop) & PROP_F) ||
        !(~x_prop & (PROP_S | PROP_F)) ||
        !(~y_prop & (PROP_S | PROP_F)))
        node->type_properties |= PROP_F;

    return WALLY_OK;
}

static int verify_and_n(ms_node *node)
{
    node->type_properties = verify_andor_property(node->child->type_properties,
                                                  node->child->next->type_properties,
                                                  PROP_OP_0);
    return node->type_properties ? WALLY_OK : WALLY_EINVAL;
}

static int verify_or_b(ms_node *node)
{
    const uint32_t x_prop = node->child->type_properties;
    const uint32_t y_prop = node->child->next->type_properties;
    node->type_properties = PROP_D | PROP_U | PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_Z | PROP_S | PROP_E);
    if (!(~x_prop & (TYPE_B | PROP_D)) &&
        !(~y_prop & (TYPE_W | PROP_D)))
        node->type_properties |= TYPE_B;
    if ((x_prop | y_prop) & PROP_Z)
        node->type_properties |= (x_prop | y_prop) & PROP_O;
    if (((x_prop | y_prop) & PROP_S) &&
        ((x_prop & y_prop) & PROP_E))
        node->type_properties |= x_prop & y_prop & PROP_M;

    return WALLY_OK;
}

static int verify_or_c(ms_node *node)
{
    const uint32_t x_prop = node->child->type_properties;
    const uint32_t y_prop = node->child->next->type_properties;
    node->type_properties = PROP_F | PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_Z | PROP_S);
    if (!(~x_prop & (TYPE_B | PROP_D | PROP_U)))
        node->type_properties |= y_prop & TYPE_V;
    if (y_prop & PROP_Z)
        node->type_properties |= x_prop & PROP_O;
    if (x_prop & PROP_E && ((x_prop | y_prop) & PROP_S))
        node->type_properties |= x_prop & y_prop & PROP_M;

    return WALLY_OK;
}

static int verify_or_d(ms_node *node)
{
    const uint32_t x_prop = node->child->type_properties;
    const uint32_t y_prop = node->child->next->type_properties;
    node->type_properties = PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_Z | PROP_E | PROP_S);
    node->type_properties |= y_prop & (PROP_U | PROP_F | PROP_D);
    if (!(~x_prop & (TYPE_B | PROP_D | PROP_U)))
        node->type_properties |= y_prop & TYPE_B;
    if (y_prop & PROP_Z)
        node->type_properties |= x_prop & PROP_O;
    if (x_prop & PROP_E && ((x_prop | y_prop) & PROP_S))
        node->type_properties |= x_prop & y_prop & PROP_M;

    return WALLY_OK;
}

static uint32_t verify_or_i_property(uint32_t x_property, uint32_t y_property)
{
    uint32_t prop = PROP_X;
    prop |= x_property & y_property & (TYPE_V | TYPE_B | TYPE_K | PROP_U | PROP_F | PROP_S);
    if (!(prop & TYPE_MASK))
        return 0;

    prop |= (x_property | y_property) & PROP_D;
    if ((x_property & y_property) & PROP_Z)
        prop |= PROP_O;
    if ((x_property | y_property) & PROP_F)
        prop |= (x_property | y_property) & PROP_E;
    if ((x_property | y_property) & PROP_S)
        prop |= x_property & y_property & PROP_M;

    return prop;
}

static int verify_or_i(ms_node *node)
{
    node->type_properties = verify_or_i_property(node->child->type_properties,
                                                 node->child->next->type_properties);
    return node->type_properties ? WALLY_OK : WALLY_EINVAL;
}

static int verify_thresh(ms_node *node)
{
    ms_node *top = top = node->child, *child;
    int64_t count = 0, num_s = 0, args = 0;
    bool all_e = true, all_m = true;

    if (!top || top->builtin || top->kind != KIND_NUMBER)
        return WALLY_EINVAL;

    for (child = top->next; child; child = child->next) {
        const uint32_t expected_type = count ? TYPE_W : TYPE_B;

        if (!child->builtin || (~child->type_properties & (expected_type | PROP_D | PROP_U)))
            return WALLY_EINVAL;

        if (~child->type_properties & PROP_E)
            all_e = false;
        if (~child->type_properties & PROP_M)
            all_m = false;
        if (child->type_properties & PROP_S)
            ++num_s;
        if (child->type_properties & PROP_Z)
            args += (~child->type_properties & PROP_O) ? 2 : 1;

        ++count;
    }
    if (count < 3 || top->number < 1 || top->number >= count)
        return WALLY_EINVAL;

    node->type_properties = TYPE_B | PROP_D | PROP_U;
    if (args == 0)
        node->type_properties |= PROP_Z;
    else if (args == 1)
        node->type_properties |= PROP_O;
    if (all_e && num_s == count)
        node->type_properties |= PROP_E;
    if (all_e && all_m && num_s >= count - top->number)
        node->type_properties |= PROP_M;
    if (num_s >= count - top->number + 1)
        node->type_properties |= PROP_S;

    return WALLY_OK;
}

static int node_verify_wrappers(ms_node *node)
{
    uint32_t *properties = &node->type_properties;
    size_t i;

    if (node->wrapper_str[0] == '\0')
        return WALLY_OK; /* No wrappers */

    /* Validate the nodes wrappers in reserve order */
    for (i = strlen(node->wrapper_str); i != 0; --i) {
        const uint32_t x_prop = *properties;
#define PROP_REQUIRE(props) if ((x_prop & (props)) != (props)) return WALLY_EINVAL
#define PROP_CHANGE_TYPE(clr, set) *properties &= ~(clr); *properties |= set
#define PROP_CHANGE(keep, set) *properties &= (TYPE_MASK | keep); *properties |= set

        switch(node->wrapper_str[i - 1]) {
        case 'a':
            PROP_REQUIRE(TYPE_B);
            PROP_CHANGE_TYPE(TYPE_B, TYPE_W);
            PROP_CHANGE(PROP_U | PROP_D | PROP_F | PROP_E | PROP_M | PROP_S, PROP_X);
            break;
        case 's':
            PROP_REQUIRE(TYPE_B | PROP_O);
            PROP_CHANGE_TYPE(TYPE_B | PROP_O, TYPE_W);
            PROP_CHANGE(PROP_U | PROP_D | PROP_F | PROP_E | PROP_M | PROP_S | PROP_X, 0);
            break;
        case 'c':
            PROP_REQUIRE(TYPE_K);
            PROP_CHANGE_TYPE(TYPE_K, TYPE_B);
            PROP_CHANGE(PROP_O | PROP_N | PROP_D | PROP_F | PROP_E | PROP_M, PROP_U | PROP_S);
            break;
        case 't':
            *properties = verify_and_v_property(x_prop, PROP_OP_1);
            if (!(*properties & TYPE_MASK))
                return WALLY_EINVAL;
            /* prop >= PROP_F */
            break;
        case 'd':
            PROP_REQUIRE(TYPE_V | PROP_Z);
            PROP_CHANGE_TYPE(TYPE_V | PROP_Z, TYPE_B);
            PROP_CHANGE(PROP_M | PROP_S, PROP_N | PROP_U | PROP_D | PROP_X);
            if (x_prop & PROP_Z)
                *properties |= PROP_O;
            if (x_prop & PROP_F) {
                *properties &= ~PROP_F;
                *properties |= PROP_E;
            }
            break;
        case 'v':
            PROP_REQUIRE(TYPE_B);
            PROP_CHANGE_TYPE(TYPE_B, TYPE_V);
            PROP_CHANGE(PROP_Z | PROP_O | PROP_N | PROP_M | PROP_S, PROP_F | PROP_X);
            break;
        case 'j':
            PROP_REQUIRE(TYPE_B | PROP_N);
            *properties &= TYPE_MASK | PROP_O | PROP_U | PROP_M | PROP_S;
            *properties |= PROP_N | PROP_D | PROP_X;
            if (x_prop & PROP_F) {
                PROP_CHANGE(~PROP_F, PROP_E);
            }
            break;
        case 'n':
            PROP_REQUIRE(TYPE_B);
            PROP_CHANGE(PROP_Z | PROP_O | PROP_N | PROP_D | PROP_F | PROP_E | PROP_M | PROP_S, PROP_X);
            break;
        case 'l':
            *properties = verify_or_i_property(PROP_OP_0, x_prop);
            break;
        case 'u':
            *properties = verify_or_i_property(x_prop, PROP_OP_0);
            break;
        default:
            return WALLY_EINVAL;     /* Wrapper type not found */
            break;
        }
    }

    switch (*properties & TYPE_MASK) {
    case TYPE_B:
    case TYPE_V:
    case TYPE_K:
    case TYPE_W:
        break;
    default:
        return WALLY_EINVAL; /* K, V, B, W all conflict with each other */
    }

    if (((*properties & PROP_Z) && (*properties & PROP_O)) ||
        ((*properties & PROP_N) && (*properties & PROP_Z)) ||
        ((*properties & TYPE_V) && (*properties & PROP_D)) ||
        ((*properties & TYPE_K) && !(*properties & PROP_U)) ||
        ((*properties & TYPE_V) && (*properties & PROP_U)) ||
        ((*properties & PROP_E) && (*properties & PROP_F)) ||
        ((*properties & PROP_E) && !(*properties & PROP_D)) ||
        ((*properties & TYPE_V) && (*properties & PROP_E)) ||
        ((*properties & PROP_D) && (*properties & PROP_F)) ||
        ((*properties & TYPE_V) && !(*properties & PROP_F)) ||
        ((*properties & TYPE_K) && !(*properties & PROP_S)) ||
        ((*properties & PROP_Z) && !(*properties & PROP_M)))
        return WALLY_EINVAL;

    return WALLY_OK;
}

static int generate_script_from_number(int64_t number, ms_node *parent,
                                       unsigned char *script, size_t script_len, size_t *written)
{
    if ((parent && !parent->builtin) || !script_len)
        return WALLY_EINVAL;

    if (number == -1) {
        script[0] = OP_1NEGATE;
        *written = 1;
    } else if (number >= 0 && number <= 16) {
        script[0] = value_to_op_n(number);
        *written = 1;
    } else {
        /* PUSH <number> */
        script[0] = scriptint_get_length(number);
        if (script_len < script[0] + 1u)
            return WALLY_EINVAL;
        scriptint_to_bytes(number, script + 1);
        *written = script[0] + 1;
    }
    return WALLY_OK;
}

static int generate_pk_k(ms_node *node, int32_t child_num,
                         unsigned char *script, size_t script_len, size_t *written)
{
    int ret;

    if (!node->child || script_len < EC_PUBLIC_KEY_LEN * 2 || !node_is_root(node))
        return WALLY_EINVAL;

    ret = generate_script(node->child, child_num, &script[1], script_len - 1, written);
    if (ret != WALLY_OK)
        return ret;

    if (*written + 1 > REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    script[0] = (unsigned char)*written;
    ++(*written);
    return ret;
}

static int generate_pk_h(ms_node *node, int32_t child_num,
                         unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    size_t output_len = *written;
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];

    if (!node->child || script_len < WALLY_SCRIPTPUBKEY_P2PKH_LEN - 1 || !node_is_root(node))
        return WALLY_EINVAL;
    if (node->child->is_xonly_key)
        return WALLY_EINVAL;

    ret = generate_script(node->child, child_num, pubkey, sizeof(pubkey), &output_len);
    if (ret != WALLY_OK)
        return ret;

    ret = wally_hash160(pubkey, output_len, &script[3], HASH160_LEN);
    if (ret != WALLY_OK)
        return ret;

    script[0] = OP_DUP;
    script[1] = OP_HASH160;
    script[2] = HASH160_LEN;
    script[HASH160_LEN + 3] = OP_EQUALVERIFY;
    *written = HASH160_LEN + 4;
    return ret;
}

static int generate_sh_wsh(ms_node *node, int32_t child_num,
                           unsigned char *script, size_t script_len, size_t *written)
{
    const bool is_sh = node->kind == KIND_DESCRIPTOR_SH;
    const size_t required_len = is_sh ? WALLY_SCRIPTPUBKEY_P2SH_LEN : WALLY_SCRIPTPUBKEY_P2WSH_LEN;
    const uint32_t flags = is_sh ? WALLY_SCRIPT_HASH160 : WALLY_SCRIPT_SHA256;
    size_t output_len = *written;
    unsigned char output[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
    int ret;

    if (!node->child || script_len < required_len || !node_is_root(node))
        return WALLY_EINVAL;

    ret = generate_script(node->child, child_num, script, script_len, &output_len);
    if (ret != WALLY_OK)
        return ret;

    if (output_len > REDEEM_SCRIPT_MAX_SIZE)
        ret = WALLY_EINVAL;

    ret = (is_sh ? wally_scriptpubkey_p2sh_from_bytes : wally_witness_program_from_bytes)(
        script, output_len, flags, output, required_len, written);
    if (ret == WALLY_OK)
        memcpy(script, output, *written);

    return ret;
}

static int generate_checksig(unsigned char *script, size_t script_len, size_t *written)
{
    if (!*written || (*written + 1 > script_len) || (*written + 1 > WITNESS_SCRIPT_MAX_SIZE))
        return WALLY_EINVAL;

    script[*written] = OP_CHECKSIG;
    *written += 1;
    return WALLY_OK;
}

static int generate_pk(ms_node *node, int32_t child_num,
                       unsigned char *script, size_t script_len, size_t *written)
{
    int ret = generate_pk_k(node, child_num, script, script_len, written);
    return ret == WALLY_OK ? generate_checksig(script, script_len, written) : ret;
}

static int generate_pkh(ms_node *node, int32_t child_num,
                        unsigned char *script, size_t script_len, size_t *written)
{
    int ret = generate_pk_h(node, child_num, script, script_len, written);
    return ret == WALLY_OK ? generate_checksig(script, script_len, written) : ret;
}

static int generate_wpkh(ms_node *node, int32_t child_num,
                         unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    size_t output_len = *written;
    unsigned char output[WALLY_SCRIPTPUBKEY_P2WPKH_LEN];

    if (!node->child || script_len < sizeof(output) || !node_is_root(node))
        return WALLY_EINVAL;

    ret = generate_script(node->child, child_num, script, script_len, &output_len);
    if (ret == WALLY_OK) {
        if (output_len > REDEEM_SCRIPT_MAX_SIZE)
            return WALLY_EINVAL;

        ret = wally_witness_program_from_bytes(script, output_len, WALLY_SCRIPT_HASH160,
                                               output, WALLY_SCRIPTPUBKEY_P2WPKH_LEN, written);
        if (ret == WALLY_OK)
            memcpy(script, output, *written);
    }
    return ret;
}

static int generate_combo(ms_node *node, int32_t child_num,
                          unsigned char *script, size_t script_len, size_t *written)
{
    if (node_has_uncompressed_key(node))
        return generate_pkh(node, child_num, script, script_len, written);
    return generate_wpkh(node, child_num, script, script_len, written);
}

static int compare_multisig_node(const void *lhs, const void *rhs)
{
    const struct multisig_sort_data_t *l = lhs;
    /* Note: if pubkeys are different sizes, the head byte will differ and so this
     * memcmp will not read beyond either */
    return memcmp(l->pubkey, ((const struct multisig_sort_data_t *)rhs)->pubkey, l->pubkey_len);
}

static int generate_multi(ms_node *node, int32_t child_num,
                          unsigned char *script, size_t script_len, size_t *written)
{
    size_t offset;
    uint32_t count, i;
    ms_node *child = node->child;
    struct multisig_sort_data_t sorted[15]; /* 15 = Max number of pubkeys for OP_CHECKMULTISIG */
    size_t check_len = script_len <= REDEEM_SCRIPT_MAX_SIZE ? script_len : REDEEM_SCRIPT_MAX_SIZE;
    int ret;

    if (!child || !node_is_root(node) || !node->builtin)
        return WALLY_EINVAL;

    if ((ret = generate_script(child, child_num, script, script_len, &offset)) != WALLY_OK)
        return ret;

    child = child->next;
    for (count = 0; ret == WALLY_OK && child && count < NUM_ELEMS(sorted); ++count) {
        struct multisig_sort_data_t *item = sorted + count;
        ret = generate_script(child, child_num,
                              item->pubkey, sizeof(item->pubkey), &item->pubkey_len);
        if (ret == WALLY_OK && item->pubkey_len > sizeof(item->pubkey))
            ret = WALLY_EINVAL;
        child = child->next;
    }

    if (ret == WALLY_OK && (!count || child))
        ret = WALLY_EINVAL; /* Not enough, or too many keys for multisig */

    if (ret == WALLY_OK) {
        if (node->kind == KIND_DESCRIPTOR_MULTI_S)
            qsort(sorted, count, sizeof(sorted[0]), compare_multisig_node);

        for (i = 0; ret == WALLY_OK && i < count; ++i) {
            const size_t pubkey_len = sorted[i].pubkey_len;
            if (offset + pubkey_len + 1 > check_len)
                return WALLY_EINVAL;
            script[offset] = pubkey_len;
            memcpy(&script[offset + 1], sorted[i].pubkey, pubkey_len);
            offset += pubkey_len + 1;
        }

        if (ret == WALLY_OK) {
            size_t number_len = 0;
            ret = generate_script_from_number(count, node->parent, &script[offset],
                                              check_len - offset, &number_len);
            if (ret == WALLY_OK) {
                offset += number_len;
                if (offset + 1 > check_len)
                    return WALLY_EINVAL;
                script[offset] = OP_CHECKMULTISIG;
                *written = offset + 1;
            }
        }
    }
    return ret;
}

static int generate_raw(ms_node *node, int32_t child_num,
                        unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    if (!node->child || !script_len || !node_is_root(node))
        return WALLY_EINVAL;

    ret = generate_script(node->child, child_num, script, script_len, written);
    return *written > REDEEM_SCRIPT_MAX_SIZE ?  WALLY_EINVAL : ret;
}

static int generate_delay(ms_node *node, int32_t child_num,
                          unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    size_t output_len = *written;
    if (!node->child || script_len < DESCRIPTOR_MIN_SIZE || !node_is_root(node) || !node->builtin)
        return WALLY_EINVAL;

    ret = generate_script(node->child, child_num, script, script_len, &output_len);
    if (ret != WALLY_OK)
        return ret;

    if (output_len + 1 > REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    if (node->kind == KIND_MINISCRIPT_OLDER)
        script[output_len] = OP_CHECKSEQUENCEVERIFY;
    else if (node->kind == KIND_MINISCRIPT_AFTER)
        script[output_len] = OP_CHECKLOCKTIMEVERIFY;
    else
        return WALLY_ERROR; /* Shouldn't happen */
    *written = output_len + 1;
    return ret;
}

static int generate_hash_type(ms_node *node, int32_t child_num,
                              unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    unsigned char op_code;
    size_t hash_size;
    size_t output_len = *written;
    size_t check_len = script_len <= REDEEM_SCRIPT_MAX_SIZE ? script_len : REDEEM_SCRIPT_MAX_SIZE;

    if (!node->child || !node_is_root(node) || !node->builtin)
        return WALLY_EINVAL;

    if (node->kind == KIND_MINISCRIPT_SHA256) {
        op_code = OP_SHA256;
        hash_size = SHA256_LEN;
    } else if (node->kind == KIND_MINISCRIPT_HASH256) {
        op_code = OP_HASH256;
        hash_size = SHA256_LEN;
    } else if (node->kind == KIND_MINISCRIPT_RIPEMD160) {
        op_code = OP_RIPEMD160;
        hash_size = RIPEMD160_LEN;
    } else if (node->kind == KIND_MINISCRIPT_HASH160) {
        op_code = OP_HASH160;
        hash_size = HASH160_LEN;
    } else
        return WALLY_ERROR; /* Shouldn't happen */

    if (script_len < hash_size + 8)
        return WALLY_EINVAL;

    ret = generate_script(node->child, child_num, &script[6], script_len - 8, &output_len);
    if (ret == WALLY_OK) {
        if (output_len + 7 > check_len)
            return WALLY_EINVAL;

        script[0] = OP_SIZE;
        script[1] = 0x01;
        script[2] = 0x20;
        script[3] = OP_EQUALVERIFY;
        script[4] = op_code;
        script[5] = hash_size;
        script[output_len + 6] = OP_EQUAL;
        *written = output_len + 7;
    }
    return ret;
}

static int generate_concat(ms_node *node, int32_t child_num, size_t target_num,
                           const size_t *reference_indices,
                           const unsigned char *prev_insert, size_t prev_insert_num,
                           const unsigned char *first_insert, size_t first_insert_num,
                           const unsigned char *second_insert, size_t second_insert_num,
                           const unsigned char *last_append, size_t last_append_num,
                           unsigned char *script, size_t script_len, size_t *written)
{
    size_t output_len;
    size_t total = prev_insert_num + first_insert_num + second_insert_num;
    size_t i = 0, offset = 0;
    ms_node *child[3] = { NULL, NULL, NULL };
    size_t default_indices[] = { 0, 1, 2 };
    const size_t *indices = reference_indices;
    size_t check_len = script_len <= REDEEM_SCRIPT_MAX_SIZE ? script_len : REDEEM_SCRIPT_MAX_SIZE;
    int ret = WALLY_OK;

    if (!node->child || !node_is_root(node))
        return WALLY_EINVAL;

    if (!reference_indices)
        indices = default_indices;

    for (i = 0; i < target_num; ++i) {
        child[i] = (i == 0) ? node->child : child[i - 1]->next;
        if (!child[i])
            return WALLY_EINVAL;
    }

    for (i = 0; i < target_num; ++i) {
        if (i == 0 && prev_insert_num) {
            memcpy(script + offset, prev_insert, prev_insert_num);
            offset += prev_insert_num;
        }
        if (i == 1 && first_insert_num) {
            memcpy(script + offset, first_insert, first_insert_num);
            offset += first_insert_num;
        }
        if (i == 2 && second_insert_num) {
            memcpy(script + offset, second_insert, second_insert_num);
            offset += second_insert_num;
        }

        output_len = 0;
        ret = generate_script(child[indices[i]], child_num,
                              &script[offset], script_len - offset - 1, &output_len);
        if (ret != WALLY_OK)
            return ret;

        offset += output_len;
        total += output_len;
        if (total > check_len)
            return WALLY_EINVAL;
    }

    if (total + last_append_num > check_len)
        return WALLY_EINVAL;
    if (last_append_num) {
        memcpy(script + offset, last_append, last_append_num);
        offset += last_append_num;
    }

    if (ret == WALLY_OK)
        *written = offset;

    return ret;
}

static int generate_andor(ms_node *node, int32_t child_num,
                          unsigned char *script, size_t script_len, size_t *written)
{
    const unsigned char first_op[1] = { OP_NOTIF };
    const unsigned char second_op[1] = { OP_ELSE };
    const unsigned char last_op[1] = { OP_ENDIF };
    const size_t indices[3] = { 0, 2, 1 };
    /* [X] NOTIF 0 ELSE [Y] ENDIF */
    return generate_concat(node, child_num, 3, indices,
                           NULL, 0,
                           first_op, NUM_ELEMS(first_op),
                           second_op, NUM_ELEMS(second_op),
                           last_op, NUM_ELEMS(last_op),
                           script, script_len, written);
}

static int generate_and_v(ms_node *node, int32_t child_num,
                          unsigned char *script, size_t script_len, size_t *written)
{
    /* [X] [Y] */
    const size_t indices[2] = { 0, 1 };
    return generate_concat(node, child_num, 2, indices,
                           NULL, 0,
                           NULL, 0,
                           NULL, 0,
                           NULL, 0,
                           script, script_len, written);
}

static int generate_and_b(ms_node *node, int32_t child_num,
                          unsigned char *script, size_t script_len, size_t *written)
{
    const unsigned char append[1] = { OP_BOOLAND };
    const size_t indices[2] = { 0, 1 };
    /* [X] [Y] BOOLAND */
    return generate_concat(node, child_num, 2, indices,
                           NULL, 0,
                           NULL, 0,
                           NULL, 0,
                           append, NUM_ELEMS(append),
                           script, script_len, written);
}

static int generate_and_n(ms_node *node, int32_t child_num,
                          unsigned char *script, size_t script_len, size_t *written)
{
    const unsigned char middle_op[3] = { OP_NOTIF, OP_0, OP_ELSE };
    const unsigned char last_op[1] = { OP_ENDIF };
    const size_t indices[2] = { 0, 1 };
    /* [X] NOTIF 0 ELSE [Y] ENDIF */
    return generate_concat(node, child_num, 2, indices,
                           NULL, 0,
                           middle_op, NUM_ELEMS(middle_op),
                           NULL, 0,
                           last_op, NUM_ELEMS(last_op),
                           script, script_len, written);
}

static int generate_or_b(ms_node *node, int32_t child_num,
                         unsigned char *script, size_t script_len, size_t *written)
{
    const unsigned char append[1] = { OP_BOOLOR };
    const size_t indices[2] = { 0, 1 };
    /* [X] [Y] OP_BOOLOR */
    return generate_concat(node, child_num, 2, indices,
                           NULL, 0,
                           NULL, 0,
                           NULL, 0,
                           append, NUM_ELEMS(append),
                           script, script_len, written);
}

static int generate_or_c(ms_node *node, int32_t child_num,
                         unsigned char *script, size_t script_len, size_t *written)
{
    const unsigned char middle_op[1] = { OP_NOTIF };
    const unsigned char last_op[1] = { OP_ENDIF };
    const size_t indices[2] = { 0, 1 };
    /* [X] NOTIF [Z] ENDIF */
    return generate_concat(node, child_num, 2, indices,
                           NULL, 0,
                           middle_op, NUM_ELEMS(middle_op),
                           NULL, 0,
                           last_op, NUM_ELEMS(last_op),
                           script, script_len, written);
}

static int generate_or_d(ms_node *node, int32_t child_num,
                         unsigned char *script, size_t script_len, size_t *written)
{
    const unsigned char middle_op[2] = { OP_IFDUP, OP_NOTIF };
    const unsigned char last_op[1] = { OP_ENDIF };
    const size_t indices[2] = { 0, 1 };
    /* [X] IFDUP NOTIF [Z] ENDIF */
    return generate_concat(node, child_num, 2, indices,
                           NULL, 0,
                           middle_op, NUM_ELEMS(middle_op),
                           NULL, 0,
                           last_op, NUM_ELEMS(last_op),
                           script, script_len, written);
}

static int generate_or_i(ms_node *node, int32_t child_num,
                         unsigned char *script, size_t script_len, size_t *written)
{
    const unsigned char top_op[1] = { OP_IF };
    const unsigned char middle_op[1] = { OP_ELSE };
    const unsigned char last_op[1] = { OP_ENDIF };
    const size_t indices[2] = { 0, 1 };
    /* IF [X] ELSE [Z] ENDIF */
    return generate_concat(node, child_num, 2, indices,
                           top_op, NUM_ELEMS(top_op),
                           middle_op, NUM_ELEMS(middle_op),
                           NULL, 0,
                           last_op, NUM_ELEMS(last_op),
                           script, script_len, written);
}

static int generate_thresh(ms_node *node, int32_t child_num,
                           unsigned char *script, size_t script_len, size_t *written)
{
    /* [X1] [X2] ADD ... [Xn] ADD <k> EQUAL */
    int ret;
    size_t output_len, offset = 0, count = 0;
    ms_node *child = node->child;
    size_t check_len = script_len <= REDEEM_SCRIPT_MAX_SIZE ? script_len : REDEEM_SCRIPT_MAX_SIZE;

    if (!child || !node_is_root(node))
        return WALLY_EINVAL;

    child = child->next;
    while (child) {
        output_len = 0;
        ret = generate_script(child, child_num,
                              &script[offset], script_len - offset - 1, &output_len);
        if (ret != WALLY_OK)
            return ret;

        ++count;
        offset += output_len;
        if (offset >= check_len)
            return WALLY_EINVAL;

        if (count != 1) {
            if (offset + 1 >= check_len)
                return WALLY_EINVAL;

            script[offset] = OP_ADD;
            ++offset;
        }

        child = child->next;
    }

    ret = generate_script(node->child, child_num,
                          &script[offset], script_len - offset - 1, &output_len);
    if (ret != WALLY_OK)
        return ret;

    offset += output_len;
    if (offset + 1 >= check_len)
        return WALLY_EINVAL;

    script[offset] = OP_EQUAL;
    *written = offset + 1;
    return WALLY_OK;
}

static int generate_wrappers(ms_node *node,
                             unsigned char *script, size_t script_len, size_t *written)
{
    size_t i;

    if (node->wrapper_str[0] == '\0')
        return WALLY_OK; /* No wrappers */

    if (!*written)
        return WALLY_EINVAL; /* Nothing to wrap */

#define WRAP_REQUIRE(req, move_by) output_len = (req); \
    if (*written + output_len > script_len || *written + output_len > WITNESS_SCRIPT_MAX_SIZE) \
        return WALLY_EINVAL; \
    if (move_by) memmove(script + (move_by), script, *written)

    /* Generate the nodes wrappers in reserve order */
    for (i = strlen(node->wrapper_str); i != 0; --i) {
        size_t output_len = 0;
        switch(node->wrapper_str[i - 1]) {
        case 'a':
            WRAP_REQUIRE(2, 1);
            script[0] = OP_TOALTSTACK;
            script[*written + 1] = OP_FROMALTSTACK;
            break;
        case 's':
            WRAP_REQUIRE(1, 1);
            script[0] = OP_SWAP;
            break;
        case 'c':
            WRAP_REQUIRE(1, 0);
            script[*written] = OP_CHECKSIG;
            break;
        case 't':
            WRAP_REQUIRE(1, 0);
            script[*written] = OP_1;
            break;
        case 'd':
            WRAP_REQUIRE(3, 2);
            script[0] = OP_DUP;
            script[1] = OP_IF;
            script[*written + 2] = OP_ENDIF;
            break;
        case 'v': {
            unsigned char *last = script + *written - 1;
            if (*last == OP_EQUAL)
                *last = OP_EQUALVERIFY;
            else if (*last == OP_NUMEQUAL)
                *last = OP_NUMEQUALVERIFY;
            else if (*last == OP_CHECKSIG)
                *last = OP_CHECKSIGVERIFY;
            else if (*last == OP_CHECKMULTISIG)
                *last = OP_CHECKMULTISIGVERIFY;
            else if (*last == OP_CHECKMULTISIG)
                *last = OP_CHECKMULTISIGVERIFY;
            else {
                WRAP_REQUIRE(1, 0);
                script[*written] = OP_VERIFY;
            }
            break;
        }
        case 'j':
            WRAP_REQUIRE(4, 3);
            script[0] = OP_SIZE;
            script[1] = OP_0NOTEQUAL;
            script[2] = OP_IF;
            script[*written + 3] = OP_ENDIF;
            break;
        case 'n':
            WRAP_REQUIRE(1, 0);
            script[*written] = OP_0NOTEQUAL;
            break;
        case 'l':
            WRAP_REQUIRE(4, 3);
            script[0] = OP_IF;
            script[1] = OP_0;
            script[2] = OP_ELSE;
            script[*written + 3] = OP_ENDIF;
            break;
        case 'u':
            WRAP_REQUIRE(4, 1);
            script[0] = OP_IF;
            script[*written + 1] = OP_ELSE;
            script[*written + 2] = OP_0;
            script[*written + 3] = OP_ENDIF;
            break;
        default:
            return WALLY_ERROR; /* Wrapper type not found, should not happen */
        }
        *written += output_len;
    }
    return WALLY_OK;
}

#define I_NAME(name) name, sizeof(name) - 1
static const struct ms_builtin_t g_builtins[] = {
    /* output descriptor */
    {
        I_NAME("sh"),
        KIND_DESCRIPTOR_SH,
        TYPE_NONE,
        1, verify_sh, generate_sh_wsh
    }, {
        I_NAME("wsh"),
        KIND_DESCRIPTOR_WSH,
        TYPE_NONE,
        1, verify_wsh, generate_sh_wsh
    }, {   /* c:pk_k */
        I_NAME("pk"),
        KIND_DESCRIPTOR_PK | KIND_MINISCRIPT_PK,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X,
        1, verify_pk, generate_pk
    }, {   /* c:pk_h */
        I_NAME("pkh"),
        KIND_DESCRIPTOR_PKH | KIND_MINISCRIPT_PKH,
        TYPE_B | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X,
        1, verify_pk, generate_pkh
    }, {
        I_NAME("wpkh"),
        KIND_DESCRIPTOR_WPKH,
        TYPE_NONE,
        1, verify_wpkh, generate_wpkh
    }, {
        I_NAME("combo"),
        KIND_DESCRIPTOR_COMBO,
        TYPE_NONE,
        1, verify_combo, generate_combo
    }, {
        I_NAME("multi"),
        KIND_DESCRIPTOR_MULTI | KIND_MINISCRIPT_MULTI,
        TYPE_B | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S,
        0xffffffff, verify_multi, generate_multi
    }, {
        I_NAME("sortedmulti"),
        KIND_DESCRIPTOR_MULTI_S,
        TYPE_NONE,
        0xffffffff, verify_multi, generate_multi
    }, {
        I_NAME("addr"),
        KIND_DESCRIPTOR_ADDR,
        TYPE_NONE,
        1, verify_addr, generate_raw
    }, {
        I_NAME("raw"),
        KIND_DESCRIPTOR_RAW,
        TYPE_NONE,
        1, verify_raw, generate_raw
    },
    /* miniscript */
    {
        I_NAME("pk_k"),
        KIND_MINISCRIPT_PK_K,
        TYPE_K | PROP_O | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X,
        1, verify_pk, generate_pk_k
    }, {
        I_NAME("pk_h"),
        KIND_MINISCRIPT_PK_H,
        TYPE_K | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X,
        1, verify_pk, generate_pk_h
    }, {
        I_NAME("older"),
        KIND_MINISCRIPT_OLDER,
        TYPE_B | PROP_Z | PROP_F | PROP_M | PROP_X,
        1, verify_delay, generate_delay
    }, {
        I_NAME("after"),
        KIND_MINISCRIPT_AFTER,
        TYPE_B | PROP_Z | PROP_F | PROP_M | PROP_X,
        1, verify_delay, generate_delay
    }, {
        I_NAME("sha256"),
        KIND_MINISCRIPT_SHA256,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M,
        1, verify_hash_type, generate_hash_type
    }, {
        I_NAME("hash256"),
        KIND_MINISCRIPT_HASH256,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M,
        1, verify_hash_type, generate_hash_type
    }, {
        I_NAME("ripemd160"),
        KIND_MINISCRIPT_RIPEMD160,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M,
        1, verify_hash_type, generate_hash_type
    }, {
        I_NAME("hash160"),
        KIND_MINISCRIPT_HASH160,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M,
        1, verify_hash_type, generate_hash_type
    }, {
        I_NAME("andor"),
        KIND_MINISCRIPT_ANDOR,
        TYPE_NONE,
        3, verify_andor, generate_andor
    }, {
        I_NAME("and_v"),
        KIND_MINISCRIPT_AND_V,
        TYPE_NONE, 2, verify_and_v, generate_and_v
    }, {
        I_NAME("and_b"),
        KIND_MINISCRIPT_AND_B,
        TYPE_B | PROP_U,
        2, verify_and_b, generate_and_b
    }, {
        I_NAME("and_n"),
        KIND_MINISCRIPT_AND_N,
        TYPE_NONE,
        2, verify_and_n, generate_and_n
    }, {
        I_NAME("or_b"),
        KIND_MINISCRIPT_OR_B,
        TYPE_B | PROP_D | PROP_U,
        2, verify_or_b, generate_or_b
    }, {
        I_NAME("or_c"),
        KIND_MINISCRIPT_OR_C,
        TYPE_V,
        2, verify_or_c, generate_or_c
    }, {
        I_NAME("or_d"),
        KIND_MINISCRIPT_OR_D,
        TYPE_B,
        2, verify_or_d, generate_or_d
    }, {
        I_NAME("or_i"),
        KIND_MINISCRIPT_OR_I,
        TYPE_NONE,
        2, verify_or_i, generate_or_i
    }, {
        I_NAME("thresh"),
        KIND_MINISCRIPT_THRESH, TYPE_B | PROP_D | PROP_U,
        0xffffffff, verify_thresh, generate_thresh
    }
};
#undef I_NAME

static unsigned char builtin_lookup(const char *name, size_t name_len, uint32_t kind)
{
    unsigned char i;

    for (i = 0; i < NUM_ELEMS(g_builtins); ++i) {
        if ((g_builtins[i].kind & kind) &&
            g_builtins[i].name_len == name_len &&
            !memcmp(g_builtins[i].name, name, name_len))
            return i + 1;
    }
    return 0;
}

static const struct ms_builtin_t *builtin_get(const ms_node *node)
{
    return node->builtin ? &g_builtins[node->builtin - 1] : NULL;
}

static int generate_script(ms_node *node, uint32_t child_num,
                           unsigned char *script, size_t script_len, size_t *written)
{
    int ret = WALLY_EINVAL;
    size_t output_len;

    if (node->builtin) {
        output_len = *written;
        ret = builtin_get(node)->generate_fn(node, child_num, script, script_len, &output_len);
        if (ret == WALLY_OK) {
            ret = generate_wrappers(node, script, script_len, &output_len);
            if (ret == WALLY_OK)
                *written = output_len;
        }
        return ret;
    }

    /* value data */
    if (node->kind & KIND_RAW || node->kind == KIND_PUBLIC_KEY) {
        ret = wally_hex_n_to_bytes(node->data, node->data_len, script, script_len, written);
    } else if (node->kind == KIND_NUMBER) {
        ret = generate_script_from_number(node->number, node->parent, script, script_len, written);
    } else if (node->kind == KIND_BASE58 || node->kind == KIND_BECH32) {
        ret = analyze_address(node->data, node->data_len,
                              NULL, NULL, NULL,
                              script, script_len, written);
    } else if (node->kind == KIND_PRIVATE_KEY) {
        unsigned char privkey[2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN];
        unsigned char pubkey[EC_PUBLIC_KEY_LEN];
        if (script_len < EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
            return WALLY_EINVAL;

        ret = wally_base58_n_to_bytes(node->data, node->data_len, BASE58_FLAG_CHECKSUM,
                                      privkey, sizeof(privkey), &output_len);
        if (ret == WALLY_OK && output_len < EC_PRIVATE_KEY_LEN + 1)
            return WALLY_EINVAL;

        ret = wally_ec_public_key_from_private_key(&privkey[1], EC_PRIVATE_KEY_LEN,
                                                   pubkey, sizeof(pubkey));
        if (ret == WALLY_OK) {
            if (output_len == EC_PRIVATE_KEY_LEN + 2 && privkey[EC_PRIVATE_KEY_LEN + 1] == 1) {
                if (node->is_xonly_key) {
                    memcpy(script, &pubkey[1], EC_XONLY_PUBLIC_KEY_LEN);
                    *written = EC_XONLY_PUBLIC_KEY_LEN;
                } else {
                    memcpy(script, pubkey, EC_PUBLIC_KEY_LEN);
                    *written = EC_PUBLIC_KEY_LEN;
                }
            } else {
                ret = wally_ec_public_key_decompress(pubkey, sizeof(pubkey), script,
                                                     EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
                if (ret == WALLY_OK)
                    *written = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
            }
        }
    } else if ((node->kind & KIND_BIP32) == KIND_BIP32) {
        struct ext_key master;

        if ((ret = bip32_key_from_base58_n(node->data, node->data_len, &master)) != WALLY_OK)
            return ret;

        if (node->child_path_len) {
            const uint32_t flags = BIP32_FLAG_STR_WILDCARD | BIP32_FLAG_STR_BARE | \
                                   BIP32_FLAG_SKIP_HASH | BIP32_FLAG_KEY_PUBLIC;
            struct ext_key derived;

            ret = bip32_key_from_parent_path_str_n(&master, node->child_path, node->child_path_len,
                                                   child_num, flags, &derived);
            if (ret != WALLY_OK)
                return ret;

            memcpy(&master, &derived, sizeof(master));
        }
        if (node->is_xonly_key) {
            memcpy(script, &master.pub_key[1], EC_XONLY_PUBLIC_KEY_LEN);
            *written = EC_XONLY_PUBLIC_KEY_LEN;
        } else {
            memcpy(script, master.pub_key, EC_PUBLIC_KEY_LEN);
            *written = EC_PUBLIC_KEY_LEN;
        }
    }
    return ret;
}

static int analyze_address(const char *str, size_t str_len,
                           ms_node *node, ms_node *parent,
                           const struct addr_ver_t *addr_ver,
                           unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    unsigned char buf[SHA256_LEN + 2];
    unsigned char decoded[1 + HASH160_LEN + BASE58_CHECKSUM_LEN];
    char *hrp_end;
    size_t hrp_len, output_len;

    if (parent && !node)
        return WALLY_EINVAL;

    if (script && (script_len < sizeof(buf) || !written))
        return WALLY_EINVAL;

    if (node) {
        node->data = str;
        node->data_len = str_len;
    }

    ret = wally_base58_n_to_bytes(str, str_len, BASE58_FLAG_CHECKSUM,
                                  decoded, sizeof(decoded), &output_len);
    if (ret == WALLY_OK) {
        /* base58 address: Check for P2PKH/P2SH */
        bool is_p2sh;

        if (output_len != HASH160_LEN + 1)
            return WALLY_EINVAL; /* Unexpected address length */

        if (!addr_ver_from_version(decoded[0], addr_ver, &is_p2sh))
            return WALLY_EINVAL; /* Network not found */

        if (node)
            node->kind = KIND_BASE58;

        if (script) {
            /* Create the scriptpubkey */
            ret = (is_p2sh ? wally_scriptpubkey_p2sh_from_bytes : wally_scriptpubkey_p2pkh_from_bytes)(
                decoded + 1, HASH160_LEN, 0, script, script_len, written);
        }
        return ret;
    }

    /* segwit */
    hrp_end = memchr(str, '1', str_len);
    if (!hrp_end)
        return WALLY_EINVAL; /* Address family missing */
    hrp_len = hrp_end - str;

    if (addr_ver && !addr_ver_from_family(str, hrp_len, addr_ver->network))
        return WALLY_EINVAL; /* Unknown network or address family mismatch */

    ret = wally_addr_segwit_n_to_bytes(str, str_len, str, hrp_len, 0, buf, sizeof(buf), &output_len);
    if (ret == WALLY_OK && output_len != HASH160_LEN + 2 && output_len != SHA256_LEN + 2)
        return WALLY_EINVAL;

    if (ret == WALLY_OK) {
        if (node)
            node->kind = KIND_BECH32;
        if (script) {
            memcpy(script, buf, output_len);
            *written = output_len;
        }
    }
    return ret;
}

static bool analyze_pubkey_hex(const char *str, size_t str_len, uint32_t flags, ms_node *node)
{
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN + 1];
    size_t offset = flags & WALLY_MINISCRIPT_TAPSCRIPT ? 1 : 0;
    size_t written;

    if (offset) {
        if (str_len != EC_XONLY_PUBLIC_KEY_LEN * 2)
            return false; /* Only X-only pubkeys allowed under tapscript */
        pubkey[0] = 2; /* Non-X-only pubkey prefix, for validation below */
    } else {
        if (str_len != EC_PUBLIC_KEY_LEN * 2 && str_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN * 2)
            return false; /* Unknown public key size */
    }

    if (wally_hex_n_to_bytes(str, str_len, pubkey + offset, sizeof(pubkey) - offset, &written) != WALLY_OK ||
        wally_ec_public_key_verify(pubkey, written + offset) != WALLY_OK)
        return false;

    node->kind = KIND_PUBLIC_KEY;
    node->is_uncompressed_key = str_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN * 2;
    node->is_xonly_key = str_len == EC_XONLY_PUBLIC_KEY_LEN * 2;
    return true;
}

static int analyze_miniscript_key(const struct addr_ver_t *addr_ver, uint32_t flags,
                                  ms_node *node, ms_node *parent)
{
    int ret;
    size_t buf_len, size;
    unsigned char privkey[2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN];
    struct ext_key extkey;

    if (!node || (parent && !parent->builtin))
        return WALLY_EINVAL;

    /*
     * key origin identification
     * https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#key-origin-identification
     */
    if (node->data[0] == '[') {
        const char *end = memchr(node->data, ']', node->data_len);
        if (!end || end < node->data + 10 ||
            wally_hex_n_verify(node->data + 1, 8u) != WALLY_OK ||
            (node->data[9] != ']' && node->data[9] != '/'))
            return WALLY_EINVAL; /* Invalid key origin fingerprint */
        size = end - node->data + 1;
        /* cut parent path */
        node->data = end + 1;
        node->data_len -= size;
    }

    /* check key (public key) */
    if (analyze_pubkey_hex(node->data, node->data_len, flags, node))
        return WALLY_OK;

    /* check key (private key(wif)) */
    ret = wally_base58_n_to_bytes(node->data, node->data_len, BASE58_FLAG_CHECKSUM,
                                  privkey, sizeof(privkey), &buf_len);
    if (ret == WALLY_OK && buf_len <= EC_PRIVATE_KEY_LEN + 2) {
        if (addr_ver && (addr_ver->version_wif != privkey[0]))
            ret = WALLY_EINVAL;
        else if (buf_len == EC_PRIVATE_KEY_LEN + 1 ||
                 (buf_len == EC_PRIVATE_KEY_LEN + 2 && privkey[EC_PRIVATE_KEY_LEN + 1] == 0x01)) {
            node->kind = KIND_PRIVATE_KEY;
            if (buf_len == EC_PRIVATE_KEY_LEN + 1) {
                node->is_uncompressed_key = true;
                if (flags & WALLY_MINISCRIPT_TAPSCRIPT)
                    ret = WALLY_EINVAL;
            }
            if (flags & WALLY_MINISCRIPT_TAPSCRIPT)
                node->is_xonly_key = true;
            if (ret == WALLY_OK)
                ret = wally_ec_private_key_verify(&privkey[1], EC_PRIVATE_KEY_LEN);
        } else
            ret = WALLY_EINVAL;
        wally_clear(privkey, sizeof(privkey));
        return ret;
    }

    /* check bip32 key */
    if ((node->child_path = memchr(node->data, '/', node->data_len))) {
        node->child_path_len = node->data_len - (node->child_path - node->data);
        node->data_len = node->child_path - node->data; /* Trim node data to just the bip32 key */
        if (node->child_path_len) {
            if (node->child_path[1] == '/')
                return WALLY_EINVAL; /* Double slash, invalid */
            ++node->child_path; /* Skip leading '/' */
            --node->child_path_len;
            if (memchr(node->child_path, '*', node->child_path_len)) {
                if (node->child_path[node->child_path_len - 1] != '*' &&
                    node->child_path[node->child_path_len - 2] != '*')
                    return WALLY_EINVAL; /* Wildcard must be the last element */
            }
        }
    }

    if ((ret = bip32_key_from_base58_n(node->data, node->data_len, &extkey)) != WALLY_OK)
        return ret;

    if (extkey.priv_key[0] == BIP32_FLAG_KEY_PRIVATE)
        node->kind = KIND_BIP32_PRIVATE_KEY;
    else
        node->kind = KIND_BIP32_PUBLIC_KEY;

    if (addr_ver) {
        const bool main_key = extkey.version == BIP32_VER_MAIN_PUBLIC ||
                              extkey.version == BIP32_VER_MAIN_PRIVATE;
        const bool main_net = addr_ver->network == WALLY_NETWORK_BITCOIN_MAINNET ||
                              addr_ver->network == WALLY_NETWORK_LIQUID;
        if (main_key != main_net)
            ret = WALLY_EINVAL; /* Mismatched main/test network */
    }

    if (ret == WALLY_OK && (flags & WALLY_MINISCRIPT_TAPSCRIPT))
        node->is_xonly_key = true;
    wally_clear(&extkey, sizeof(extkey));
    return ret;
}

static int analyze_miniscript_value(const char *str, size_t str_len,
                                    const struct addr_ver_t *addr_ver, uint32_t flags,
                                    ms_node *node, ms_node *parent)
{

    if (!node || (parent && !parent->builtin) || !str || !str_len)
        return WALLY_EINVAL;

    if (parent && parent->kind == KIND_DESCRIPTOR_ADDR)
        return analyze_address(str, str_len, node, parent, addr_ver, NULL, 0, NULL);

    if (!node->data) {
        node->data = str;
        node->data_len = str_len;
    }

    if (parent) {
        const uint32_t kind = parent->kind;
        if (kind == KIND_DESCRIPTOR_RAW || kind == KIND_MINISCRIPT_SHA256 ||
            kind == KIND_MINISCRIPT_HASH256 || kind == KIND_MINISCRIPT_RIPEMD160 ||
            kind == KIND_MINISCRIPT_HASH160) {
            node->kind = KIND_RAW;
            return wally_hex_n_verify(node->data, node->data_len);
        }
    }

    if (strtoll_n(node->data, node->data_len, &node->number)) {
        node->kind = KIND_NUMBER;
        node->type_properties = TYPE_B | PROP_Z | PROP_U | PROP_M | PROP_X;
        node->type_properties |= (node->number ? PROP_F : (PROP_D | PROP_E | PROP_S));
        return WALLY_OK;
    }

    return analyze_miniscript_key(addr_ver, flags, node, parent);
}

static int analyze_miniscript(const char *str, size_t str_len, uint32_t kind,
                              const struct addr_ver_t *addr_ver, uint32_t flags,
                              ms_node *prev_node, ms_node *parent, ms_node **output)
{
    size_t i, offset = 0, child_offset = 0;
    uint32_t indent = 0;
    bool seen_indent = false, collect_child = false, copy_child = false;
    ms_node *node, *child = NULL, *prev_child = NULL;
    int ret = WALLY_OK;

    if (!(node = wally_calloc(sizeof(*node))))
        return WALLY_ENOMEM;

    if (parent)
        node->parent = parent;

    for (i = 0; i < str_len; ++i) {
        if (!node->builtin && str[i] == ':') {
            if (i - offset > sizeof(node->wrapper_str)) {
                ret = WALLY_EINVAL;
                break;
            }
            memcpy(node->wrapper_str, &str[offset], i - offset);
            offset = i + 1;
        } else if (str[i] == '(') {
            if (!node->builtin && indent == 0) {
                collect_child = true;
                node->builtin = builtin_lookup(str + offset, i - offset, kind);
                if (!node->builtin ||
                    (node->wrapper_str[0] != '\0' && !(builtin_get(node)->kind & KIND_MINISCRIPT))) {
                    ret = WALLY_EINVAL;
                    break;
                }
                node->kind = builtin_get(node)->kind;
                offset = i + 1;
                child_offset = offset;
            }
            ++indent;
            seen_indent = true;
        } else if (str[i] == ')') {
            if (indent) {
                --indent;
                if (collect_child && (indent == 0)) {
                    collect_child = false;
                    offset = i + 1;
                    copy_child = true;
                }
            }
            seen_indent = true;
        } else if (str[i] == ',') {
            if (!indent) {
                ret = WALLY_EINVAL; /* Comma outside of ()'s */
                break;
            }
            if (collect_child && (indent == 1)) {
                copy_child = true;
            }
            seen_indent = true;
        } else if (str[i] == '#') {
            if (!parent && node->builtin && !collect_child && indent == 0) {
                break;  /* end */
            }
        }

        if (copy_child) {
            if ((ret = analyze_miniscript(str + child_offset, i - child_offset, kind,
                                          addr_ver, flags, prev_child, node, &child)) != WALLY_OK)
                break;

            prev_child = child;
            child = NULL;
            copy_child = false;
            if (str[i] == ',') {
                offset = i + 1;
                child_offset = offset;
            }
        }
    }

    if (ret == WALLY_OK && !seen_indent)
        ret = analyze_miniscript_value(str, str_len, addr_ver, flags, node, parent);

    if (ret == WALLY_OK && node->builtin) {
        const uint32_t expected_children = builtin_get(node)->child_count;
        if (expected_children != 0xffffffff && node_get_child_count(node) != expected_children)
            ret = WALLY_EINVAL; /* Too many or too few children */
        else
            ret = builtin_get(node)->verify_fn(node);
    }

    if (ret == WALLY_OK)
        ret = node_verify_wrappers(node);

    if (ret != WALLY_OK)
        node_free(node);
    else {
        *output = node;
        if (parent && !parent->child)
            parent->child = node;
        if (prev_node)
            prev_node->next = node;
    }

    return ret;
}

static int node_generate_script(ms_node *node,
                                uint32_t child_num, uint32_t depth, uint32_t index,
                                unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    unsigned char *buf;
    size_t output_len = 0;
    ms_node *p = node, *parent;
    uint32_t count;

    *written = 0;

    for (count = 0; count < depth; ++count) {
        if (!p->child)
            return WALLY_EINVAL;
        p = p->child;
    }
    for (count = 0; count < index; ++count) {
        if (!p->next)
            return WALLY_EINVAL;
        p = p->next;
    }

    if (!(buf = wally_malloc(DESCRIPTOR_MAX_SIZE)))
        return WALLY_ENOMEM;

    parent = p->parent;
    p->parent = NULL;
    ret = generate_script(p, child_num, buf, DESCRIPTOR_MAX_SIZE, &output_len);
    p->parent = parent;

    if (ret == WALLY_OK) {
        *written = output_len;
        if (output_len > script_len) {
            /* return WALLY_OK, but data is not written. */
        } else {
            memcpy(script, buf, output_len);
        }
    }

    clear_and_free(buf, DESCRIPTOR_MAX_SIZE);
    return ret;
}

/* Parse miniscript/output descriptor into script(s) or address(es).
 * Called with:
 * - addresses == NULL: Generate a single script
 * - addresses != NULL: Generate a range of scripts and then their addresses
 */
static int parse_miniscript(const char *str, size_t str_len,
                            uint32_t flags, uint32_t kind,
                            const struct addr_ver_t *addr_ver,
                            uint32_t descriptor_depth, uint32_t descriptor_index,
                            struct ms_context *ctx, char **addresses)
{
    int ret;
    size_t i;
    ms_node *top_node = NULL;

    if (!str || !str_len || flags & ~WALLY_MINISCRIPT_TAPSCRIPT || (addresses && !addr_ver))
        return WALLY_EINVAL;

    if (ctx->child_num >= BIP32_INITIAL_HARDENED_CHILD ||
        (uint64_t)ctx->child_num + ctx->num_derivations >= BIP32_INITIAL_HARDENED_CHILD)
        return WALLY_EINVAL; /* Don't allow private derivation via child_num */

    ret = analyze_miniscript(str, str_len, kind, addr_ver, flags, NULL, NULL, &top_node);
    if (ret == WALLY_OK && (kind & KIND_DESCRIPTOR) &&
        (!top_node->builtin || !(top_node->kind & KIND_DESCRIPTOR)))
        ret = WALLY_EINVAL;

    for (i = 0; ret == WALLY_OK && i < ctx->num_derivations; ++i) {
        size_t written = 0;
        ret = node_generate_script(top_node, ctx->child_num + i,
                                   descriptor_depth, descriptor_index,
                                   ctx->script, ctx->script_len,
                                   &written);
        if (ret == WALLY_OK && !addresses) {
            ctx[i].script_len = written; /* Tell the caller how much was written/needed */
        } else if (ret == WALLY_OK) {
            /* Generate the address corresponding to this script */
            ret = wally_scriptpubkey_to_address(ctx->script, written,
                                                addr_ver->network, &addresses[i]);
            if (ret == WALLY_EINVAL)
                ret = wally_addr_segwit_from_bytes(ctx->script, written,
                                                   addr_ver->family, 0, &addresses[i]);
        }
    }

    if (addresses && ret != WALLY_OK) {
        for (i = 0; i < ctx->num_derivations; ++i) {
            wally_free_string(addresses[i]);
            addresses[i] = NULL;
        }
    }

    node_free(top_node);
    return ret;
}

int wally_miniscript_to_script(const char *miniscript, const struct wally_map *vars_in,
                               uint32_t child_num, uint32_t flags,
                               unsigned char *bytes_out, size_t len, size_t *written)
{
    struct ms_context ctx = { bytes_out, len, child_num, 1 };
    char *str;
    int ret;

    if (written)
        *written = 0;

    if (!miniscript || !bytes_out || !len || !written)
        return WALLY_EINVAL;

    if ((ret = wally_descriptor_canonicalize(miniscript, vars_in, 0, &str)) == WALLY_OK)
        ret = parse_miniscript(str, strlen(str), flags, KIND_MINISCRIPT, NULL, 0, 0, &ctx, NULL);
    if (ret == WALLY_OK)
        *written = ctx.script_len;

    wally_free_string(str);
    return ret;
}

int wally_miniscript_to_script_len(const char *miniscript, const struct wally_map *vars_in,
                                   uint32_t child_num, uint32_t flags,
                                   size_t *written)
{
    unsigned char buff[1];
    return wally_miniscript_to_script(miniscript, vars_in, child_num, flags,
                                      buff, sizeof(buff), written);
}

int wally_descriptor_to_scriptpubkey(const char *descriptor, const struct wally_map *vars_in,
                                     uint32_t child_num, uint32_t network,
                                     uint32_t depth, uint32_t index, uint32_t flags,
                                     unsigned char *bytes_out, size_t len, size_t *written)
{
    const struct addr_ver_t *addr_ver = addr_ver_from_network(network);
    struct ms_context ctx = { bytes_out, len, child_num, 1 };
    char *str;
    int ret;

    if (written)
        *written = 0;

    if (!descriptor || (network && !addr_ver) || !bytes_out || !len || !written)
        return WALLY_EINVAL;

    if ((ret = wally_descriptor_canonicalize(descriptor, vars_in, 0, &str)) == WALLY_OK)
        ret = parse_miniscript(str, strlen(str), flags, KIND_MINISCRIPT | KIND_DESCRIPTOR,
                               addr_ver, depth, index, &ctx, NULL);
    if (ret == WALLY_OK)
        *written = ctx.script_len;

    wally_free_string(str);
    return ret;
}

int wally_descriptor_to_scriptpubkey_len(const char *descriptor, const struct wally_map *vars_in,
                                         uint32_t child_num, uint32_t network,
                                         uint32_t depth, uint32_t index, uint32_t flags,
                                         size_t *written)
{
    unsigned char buff[1];
    return wally_descriptor_to_scriptpubkey(descriptor, vars_in, child_num, network,
                                            depth, index, flags, buff, sizeof(buff), written);
}

int wally_descriptor_to_addresses(const char *descriptor, const struct wally_map *vars_in,
                                  uint32_t child_num, uint32_t network, uint32_t flags,
                                  char **addresses_out, size_t addresses_out_len)
{
    char *str;
    const struct addr_ver_t *addr_ver = addr_ver_from_network(network);
    struct ms_context ctx = { NULL, DESCRIPTOR_MAX_SIZE, child_num, addresses_out_len };
    int ret;

    if (addresses_out && addresses_out_len)
        wally_clear(addresses_out, addresses_out_len * sizeof(*addresses_out));

    if (!descriptor || !addr_ver || !addresses_out || !addresses_out_len)
        return WALLY_EINVAL;

    if ((ret = wally_descriptor_canonicalize(descriptor, vars_in, 0, &str)) == WALLY_OK) {
        if (!(ctx.script = wally_malloc(DESCRIPTOR_MAX_SIZE))) {
            wally_free_string(str);
            return WALLY_ENOMEM;
        }
        ret = parse_miniscript(str, strlen(str), flags, KIND_MINISCRIPT | KIND_DESCRIPTOR,
                               addr_ver, 0, 0, &ctx, addresses_out);
    }

    clear_and_free(ctx.script, DESCRIPTOR_MAX_SIZE);
    wally_free_string(str);
    return ret;
}

int wally_descriptor_to_address(const char *descriptor, const struct wally_map *vars_in,
                                uint32_t child_num, uint32_t network, uint32_t flags,
                                char **output)
{
    return wally_descriptor_to_addresses(descriptor, vars_in, child_num, network, flags,
                                         output, 1);
}

int wally_descriptor_get_checksum(const char *descriptor,
                                  const struct wally_map *vars_in, uint32_t flags,
                                  char **output)
{
    char *str;
    int ret;

    if (output)
        *output = NULL;

    if (!descriptor || flags || !output)
        return WALLY_EINVAL;

    if (((ret = wally_descriptor_canonicalize(descriptor, vars_in, 0, &str)) == WALLY_OK) &&
        !(*output = wally_strdup(str + strlen(str) - DESCRIPTOR_CHECKSUM_LENGTH)))
        ret = WALLY_ENOMEM;

    wally_free_string(str);
    return ret;
}

/*
 * Checksum code adapted from bitcoin core: bitcoin/src/script/descriptor.cpp DescriptorChecksum()
 */
/* The character set for the checksum itself (same as bech32). */
static const char *checksum_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const unsigned char checksum_positions[] = {
    0x5f, 0x3c, 0x5d, 0x5c, 0x1d, 0x1e, 0x33, 0x10, 0x0b, 0x0c, 0x12, 0x34, 0x0f, 0x35, 0x36, 0x11,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x1c, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x1b, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x0d, 0x5e, 0x0e, 0x3d, 0x3e,
    0x5b, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x1f, 0x3f, 0x20, 0x40
};

static inline size_t checksum_get_position(char c)
{
    return c < ' ' || c > '~' ? 0 : checksum_positions[(unsigned char)(c - ' ')];
}

static uint64_t poly_mod_descriptor_checksum(uint64_t c, int val)
{
    uint8_t c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    if (c0 & 1) c ^= 0xf5dee51989;
    if (c0 & 2) c ^= 0xa9fdca3312;
    if (c0 & 4) c ^= 0x1bab10e32d;
    if (c0 & 8) c ^= 0x3706b1677a;
    if (c0 & 16) c ^= 0x644d626ffd;
    return c;
}

static int generate_checksum(const char *str, size_t str_len, char *checksum_out)
{
    uint64_t c = 1;
    int cls = 0;
    int clscount = 0;
    size_t pos;
    size_t i;

    for (i = 0; i < str_len; ++i) {
        if ((pos = checksum_get_position(str[i])) == 0)
            return WALLY_EINVAL; /* Invalid character */
        --pos;
        /* Emit a symbol for the position inside the group, for every character. */
        c = poly_mod_descriptor_checksum(c, pos & 31);
        /* Accumulate the group numbers */
        cls = cls * 3 + (int)(pos >> 5);
        if (++clscount == 3) {
            /* Emit an extra symbol representing the group numbers, for every 3 characters. */
            c = poly_mod_descriptor_checksum(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0)
        c = poly_mod_descriptor_checksum(c, cls);
    for (i = 0; i < DESCRIPTOR_CHECKSUM_LENGTH; ++i)
        c = poly_mod_descriptor_checksum(c, 0);
    c ^= 1;

    for (i = 0; i < DESCRIPTOR_CHECKSUM_LENGTH; ++i)
        checksum_out[i] = checksum_charset[(c >> (5 * (7 - i))) & 31];
    checksum_out[DESCRIPTOR_CHECKSUM_LENGTH] = '\0';

    return WALLY_OK;
}

static inline bool is_identifer_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

static const struct wally_map_item *lookup_identifier(const struct wally_map *map_in,
                                                      const char *key, size_t key_len)
{
    size_t i;
    for (i = 0; i < map_in->num_items; ++i) {
        const struct wally_map_item *item = &map_in->items[i];
        if (key_len == item->key_len - 1 && memcmp(key, item->key, key_len) == 0)
            return item;
    }
    return NULL;
}

int wally_descriptor_canonicalize(const char *descriptor,
                                  const struct wally_map *vars_in, uint32_t flags,
                                  char **output)
{
    const size_t VAR_MAX_NAME_LEN = 16;
    size_t required_len = 0;
    const char *p = descriptor, *start;
    char *out;

    if (output)
        *output = NULL;

    if (!descriptor || flags || !output)
        return WALLY_EINVAL;

    /* First, find the length of the canonicalized descriptor */
    while (*p && *p != '#') {
        while (*p && *p != '#' && !is_identifer_char(*p)) {
            ++required_len;
            ++p;
        }
        start = p;
        while (is_identifer_char(*p))
            ++p;
        if (p != start) {
            const bool starts_with_digit = *start >= '0' && *start <= '9';
            const size_t lookup_len = p - start;
            if (!vars_in || lookup_len > VAR_MAX_NAME_LEN || starts_with_digit) {
                required_len += lookup_len; /* Too long/wrong format for an identifier */
            } else {
                /* Lookup the potential identifier */
                const struct wally_map_item *item = lookup_identifier(vars_in, start, lookup_len);
                required_len += item ? item->value_len - 1 : lookup_len;
            }
        }
    }

    if (!(*output = wally_malloc(required_len + 1 + DESCRIPTOR_CHECKSUM_LENGTH + 1)))
        return WALLY_ENOMEM;

    p = descriptor;
    out = *output;
    while (*p && *p != '#') {
        while (*p && *p != '#' && !is_identifer_char(*p)) {
            *out++ = *p++;
        }
        start = p;
        while (is_identifer_char(*p))
            ++p;
        if (p != start) {
            const bool is_number = *start >= '0' && *start <= '9';
            size_t lookup_len = p - start;
            if (!vars_in || lookup_len > VAR_MAX_NAME_LEN || is_number) {
                memcpy(out, start, lookup_len);
            } else {
                /* Lookup the potential identifier */
                const struct wally_map_item *item = lookup_identifier(vars_in, start, lookup_len);
                lookup_len = item ? item->value_len - 1 : lookup_len;
                memcpy(out, item ? (char *)item->value : start, lookup_len);
            }
            out += lookup_len;
        }
    }
    *out++ = '#';
    out[DESCRIPTOR_CHECKSUM_LENGTH] = '\0';
    if (generate_checksum(*output, required_len, out) != WALLY_OK ||
        (*p == '#' && strcmp(p + 1, out))) {
        /* Invalid character in input or failed to match passed in checksum */
        clear_and_free(*output, required_len + 1 + DESCRIPTOR_CHECKSUM_LENGTH + 1);
        *output = NULL;
        return WALLY_EINVAL;
    }
    return WALLY_OK;
}
