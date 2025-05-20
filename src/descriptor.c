#include "internal.h"

#include "script.h"
#include "script_int.h"

#include <include/wally_address.h>
#include <include/wally_bip32.h>
#include <include/wally_crypto.h>
#include <include/wally_descriptor.h>
#include <include/wally_map.h>
#include <include/wally_script.h>
#ifdef BUILD_ELEMENTS
#include <include/wally_elements.h>
#endif

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#define MS_FLAGS_ALL (WALLY_MINISCRIPT_TAPSCRIPT | \
        WALLY_MINISCRIPT_ONLY | \
        WALLY_MINISCRIPT_REQUIRE_CHECKSUM | \
        WALLY_MINISCRIPT_POLICY_TEMPLATE | \
        WALLY_MINISCRIPT_UNIQUE_KEYPATHS | \
        WALLY_MINISCRIPT_AS_ELEMENTS)
#define MS_FLAGS_CANONICALIZE (WALLY_MINISCRIPT_REQUIRE_CHECKSUM | \
        WALLY_MINISCRIPT_POLICY_TEMPLATE)

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
#define PROP_G  0x00040000  /* Relative time timelock */
#define PROP_H  0x00080000  /* Relative height timelock */
#define PROP_I  0x00100000  /* Absolute time timelock */
#define PROP_J  0x00200000  /* Absolute time heightlock */
#define PROP_K  0x00400000  /* No timelock mixing allowed */

/* OP_0 properties: Bzudemsxk */
#define PROP_OP_0  (TYPE_B | PROP_Z | PROP_U | PROP_D | PROP_E | PROP_M | PROP_S | PROP_X | PROP_K)
/* OP_1 properties: Bzufmxk */
#define PROP_OP_1  (TYPE_B | PROP_Z | PROP_U | PROP_F | PROP_M | PROP_X | PROP_K)

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

#define DESCRIPTOR_MIN_SIZE     20
#define MINISCRIPT_MULTI_MAX    20
#define REDEEM_SCRIPT_MAX_SIZE  520
#define WITNESS_SCRIPT_MAX_SIZE 10000
#define DESCRIPTOR_SEQUENCE_LOCKTIME_TYPE_FLAG 0x00400000
#define DESCRIPTOR_LOCKTIME_THRESHOLD          500000000
#define DESCRIPTOR_CHECKSUM_LENGTH 8

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
#define KIND_DESCRIPTOR_RAW_TR   (0x00100000 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_TR       (0x00200000 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_CT       (0x00300000 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_SLIP77   (0x00400000 | KIND_DESCRIPTOR)
#define KIND_DESCRIPTOR_ELIP151  (0x00500000 | KIND_DESCRIPTOR)

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

struct addr_ver_t {
    const unsigned char network;
    const unsigned char version_p2pkh;
    const unsigned char version_p2sh;
    const unsigned char version_wif;
    const unsigned char elements_prefix;
    const char bech32[5];  /* bech32 prefix */
    const char blech32[4]; /* blech32 prefix */
};

static const struct addr_ver_t g_address_versions[] = {
    {
        WALLY_NETWORK_BITCOIN_MAINNET,
        WALLY_ADDRESS_VERSION_P2PKH_MAINNET,
        WALLY_ADDRESS_VERSION_P2SH_MAINNET,
        WALLY_ADDRESS_VERSION_WIF_MAINNET,
        0,
        { 'b', 'c', '\0', '\0', '\0' },
        { '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_BITCOIN_TESTNET,
        WALLY_ADDRESS_VERSION_P2PKH_TESTNET,
        WALLY_ADDRESS_VERSION_P2SH_TESTNET,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        0,
        { 't', 'b', '\0', '\0', '\0' },
        { '\0', '\0', '\0', '\0' }
    },
    {   /* Bitcoin regtest. This must remain immediately after WALLY_NETWORK_BITCOIN_TESTNET */
        WALLY_NETWORK_BITCOIN_REGTEST,
        WALLY_ADDRESS_VERSION_P2PKH_TESTNET,
        WALLY_ADDRESS_VERSION_P2SH_TESTNET,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        0,
        { 'b', 'c', 'r', 't', '\0' },
        { '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_LIQUID,
        WALLY_ADDRESS_VERSION_P2PKH_LIQUID,
        WALLY_ADDRESS_VERSION_P2SH_LIQUID,
        WALLY_ADDRESS_VERSION_WIF_MAINNET,
        12,
        { 'e', 'x', '\0', '\0', '\0' },
        { 'l', 'q', '\0', '\0' }
    },
    {
        WALLY_NETWORK_LIQUID_TESTNET,
        WALLY_ADDRESS_VERSION_P2PKH_LIQUID_TESTNET,
        WALLY_ADDRESS_VERSION_P2SH_LIQUID_TESTNET,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        23,
        { 't', 'e', 'x', '\0', '\0' },
        { 't', 'l', 'q', '\0' }
    },
    {
        WALLY_NETWORK_LIQUID_REGTEST,
        WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST,
        WALLY_ADDRESS_VERSION_P2SH_LIQUID_REGTEST,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        4,
        { 'e', 'r', 't', '\0', '\0' },
        { 'e', 'l', '\0', '\0' }
    },
};

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
    unsigned short flags; /* WALLY_MS_IS_ flags */
    unsigned char builtin;
} ms_node;

typedef struct wally_descriptor {
    char *src; /* The canonical source script */
    size_t src_len; /* Length of src */
    ms_node *top_node; /* The first node of the parse tree */
    const struct addr_ver_t *addr_ver;
    uint32_t features; /* Features present in the parsed tree */
    uint32_t num_variants; /* Number of script variants in the expression */
    uint32_t num_multipaths; /* Number of multi-path items in the expression */
    size_t script_len; /* Max script length generatable from this expression */
    /* User modified for generation */
    uint32_t variant; /* Variant for derivation of multi-type expressions */
    uint32_t child_num; /* BIP32 child number for derivation */
    uint32_t multi_index; /* Multi-path index for derivation */
    uint32_t *path_buff; /* Path buffer for deriving keys */
    uint32_t max_path_elems; /* Max path length seen in the descriptor */
    struct wally_map keys;
} ms_ctx;

static int ctx_add_key_node(ms_ctx *ctx, ms_node *node)
{
    const char *v = (char *)node;
    return map_add(&ctx->keys, NULL, ctx->keys.num_items,
                   (unsigned char *)v, 1, true, false);
}

static int ensure_unique_policy_keys(const ms_ctx *ctx);

/* Built-in miniscript expressions */
typedef int (*node_verify_fn_t)(ms_ctx *ctx, ms_node *node);
typedef int (*node_gen_fn_t)(ms_ctx *ctx, ms_node *node,
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

/* FIXME: the max is actually 20 in a witness script */
#define CHECKMULTISIG_NUM_KEYS_MAX 15
struct multisig_sort_data_t {
    size_t pubkey_len;
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
};

static const struct addr_ver_t *addr_ver_from_network(uint32_t network)
{
    size_t i;
    if (network != WALLY_NETWORK_NONE) {
        for (i = 0; i < NUM_ELEMS(g_address_versions); ++i) {
            if (network == g_address_versions[i].network)
                return g_address_versions + i;
        }
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
    if (!addr_ver || !family || strlen(addr_ver->bech32) != family_len ||
        memcmp(family, addr_ver->bech32, family_len))
        return NULL; /* Not found or mismatched address version */
    return addr_ver; /* Found */
}

/* Function prototype */
static const struct ms_builtin_t *builtin_get(const ms_node *node);
static int generate_script(ms_ctx *ctx, ms_node *node,
                           unsigned char *script, size_t script_len, size_t *written);
static bool is_valid_policy_map(const struct wally_map *map_in);

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

typedef bool (*is_identifer_fn)(char c);

static bool is_identifer_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}
static bool is_policy_start_char(char c) { return c == '@'; }
static bool is_policy_identifer_char(char c) { return c >= '0' && c <= '9'; }

static int canonicalize_impl(const char *descriptor,
                             const struct wally_map *vars_in, uint32_t flags,
                             char **output, size_t *num_substitutions)
{
    const size_t VAR_MAX_NAME_LEN = 16;
    is_identifer_fn is_id_start = is_identifer_char, is_id_char = is_identifer_char;
    size_t required_len = 0;
    int key_index_hwm = -1;
    const char *p = descriptor, *start;
    char *out;
    bool found_policy_single = false, found_policy_multi = false;;

    *output = NULL;
    *num_substitutions = 0;
    if (!descriptor || (flags & ~MS_FLAGS_CANONICALIZE))
        return WALLY_EINVAL;

    if (flags & WALLY_MINISCRIPT_POLICY_TEMPLATE) {
        if (!is_valid_policy_map(vars_in))
            return WALLY_EINVAL; /* Invalid policy variables given */
        is_id_start = is_policy_start_char;
        is_id_char = is_policy_identifer_char;
    }

    /* First, find the length of the canonicalized descriptor */
    while (*p && *p != '#') {
        while (*p && *p != '#' && !is_id_start(*p)) {
            ++required_len;
            ++p;
        }
        if (!is_id_start(*p))
            break;
        start = p++;
        while (is_id_char(*p))
            ++p;
        if (p != start) {
            const bool starts_with_digit = *start >= '0' && *start <= '9';
            const size_t lookup_len = p - start;
            if (!vars_in || lookup_len > VAR_MAX_NAME_LEN || starts_with_digit) {
                required_len += lookup_len; /* Too long/wrong format for an identifier */
            } else {
                /* Lookup the potential identifier */
                const struct wally_map_item *item;
                item = wally_map_get(vars_in, (unsigned char*)start, lookup_len);
                if (!item) {
                    required_len += lookup_len;
                    continue;
                }
                required_len += item->value_len;
                ++*num_substitutions;
                if (flags & WALLY_MINISCRIPT_POLICY_TEMPLATE) {
                    int key_index = (int)(item - vars_in->items);
                    if (key_index > key_index_hwm + 1)
                        return WALLY_EINVAL; /* Must be ordered with no gaps */
                    if (key_index > key_index_hwm)
                        key_index_hwm = key_index;
                    if (*p++ != '/')
                        return WALLY_EINVAL;
                    ++required_len;
                    if (*p == '<') {
                        found_policy_multi = true;
                        continue;
                    }
                    if (*p++ != '*')
                        return WALLY_EINVAL;
                    if (*p == '*') {
                        found_policy_multi = true;
                        ++p;
                        required_len += strlen("<0;1>/*");
                    } else {
                        found_policy_single = true;
                        required_len += 1;
                    }
                }
            }
        }
    }

    if (!*p && (flags & WALLY_MINISCRIPT_REQUIRE_CHECKSUM))
        return WALLY_EINVAL; /* Checksum required but not present */
    if (flags & WALLY_MINISCRIPT_POLICY_TEMPLATE) {
        if (found_policy_single && found_policy_multi)
            return WALLY_EINVAL; /* Cannot mix cardinality of policy keys */
        if (key_index_hwm == -1 || key_index_hwm != (int)vars_in->num_items - 1)
            return WALLY_EINVAL; /* One or more keys wasn't substituted */
    }
    if (!(*output = wally_malloc(required_len + 1 + DESCRIPTOR_CHECKSUM_LENGTH + 1)))
        return WALLY_ENOMEM;

    p = descriptor;
    out = *output;
    while (*p && *p != '#') {
        while (*p && *p != '#' && !is_id_start(*p)) {
            *out++ = *p++;
        }
        if (!is_id_start(*p))
            break;
        start = p++;
        while (is_id_char(*p))
            ++p;
        if (p != start) {
            const bool is_number = *start >= '0' && *start <= '9';
            size_t lookup_len = p - start;
            if (!vars_in || lookup_len > VAR_MAX_NAME_LEN || is_number)
                memcpy(out, start, lookup_len);
            else {
                /* Lookup the potential identifier */
                const struct wally_map_item *item;
                item = wally_map_get(vars_in, (unsigned char*)start, lookup_len);
                lookup_len = item ? item->value_len : lookup_len;
                memcpy(out, item ? (char *)item->value : start, lookup_len);
                if (item && flags & WALLY_MINISCRIPT_POLICY_TEMPLATE) {
                    if (p[1] == '*' && p[2] == '*') {
                        out += lookup_len;
                        lookup_len = strlen("/<0;1>/*");
                        memcpy(out, "/<0;1>/*", lookup_len);
                        p += strlen("/**");
                    }
                }
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

static uint32_t node_get_child_count(const ms_node *node)
{
    int32_t ret = 0;
    const ms_node *child;
    for (child = node->child; child; child = child->next)
        ++ret;
    return ret;
}

static bool node_has_uncompressed_key(const ms_ctx *ctx, const ms_node *node)
{
    if (ctx->features & WALLY_MS_IS_UNCOMPRESSED) {
        const ms_node *child;
        for (child = node->child; child; child = child->next)
            if ((child->flags & WALLY_MS_IS_UNCOMPRESSED) || node_has_uncompressed_key(ctx, child))
                return true;
    }
    return false;
}

static int node_is_top(const ms_node *node)
{
    /* True if this is the top node in the descriptor
     * (disregarding any ct() parent for Elements).
     */
#ifdef BUILD_ELEMENTS
    return !node->parent || node->parent->kind == KIND_DESCRIPTOR_CT;
#else
    return !node->parent;
#endif
}

static bool node_is_root(const ms_node *node)
{
    /* True if this is a (possibly temporary) top level node, or an argument of a builtin */
    return !node->parent || node->parent->builtin;
}

#ifdef BUILD_ELEMENTS
static bool node_is_ct(const ms_node *node)
{
    return !node->parent && node->kind == KIND_DESCRIPTOR_CT;
}
#endif

static void node_free(ms_node *node)
{
    if (node) {
        ms_node *child = node->child;
        while (child) {
            ms_node *next = child->next;
            node_free(child);
            child = next;
        }
        if (node->kind & (KIND_RAW | KIND_ADDRESS) ||
            node->kind == KIND_PUBLIC_KEY || node->kind == KIND_PRIVATE_KEY)
            clear_and_free((void*)node->data, node->data_len);
        clear_and_free(node, sizeof(*node));
    }
}

static bool has_two_different_lock_states(uint32_t primary, uint32_t secondary)
{
    return ((primary & PROP_G) && (secondary & PROP_H)) ||
            ((primary & PROP_H) && (secondary & PROP_G)) ||
            ((primary & PROP_I) && (secondary & PROP_J)) ||
            ((primary & PROP_J) && (secondary & PROP_I));
}

int wally_descriptor_free(ms_ctx *ctx)
{
    if (ctx) {
        /* Just clear the item storage, the actual items are owned by
         * the tree of nodes */
        clear_and_free(ctx->keys.items,
                       ctx->keys.num_items * sizeof(*ctx->keys.items));
        wally_free_string(ctx->src);
        node_free(ctx->top_node);
        clear_and_free(ctx, sizeof(*ctx));
    }
    return WALLY_OK;
}

static int verify_sh(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (!node_is_top(node) || !node->child->builtin)
        return WALLY_EINVAL;

    node->type_properties = node->child->type_properties;
    return WALLY_OK;
}

static int verify_wsh(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (node->parent && node->parent->kind != KIND_DESCRIPTOR_SH &&
        node->parent->kind != KIND_DESCRIPTOR_CT)
        return WALLY_EINVAL;
    if (!node->child->builtin || node_has_uncompressed_key(ctx, node))
        return WALLY_EINVAL;

    node->type_properties = node->child->type_properties;
    return WALLY_OK;
}

static int verify_pk(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (node->child->builtin || !(node->child->kind & KIND_KEY))
        return WALLY_EINVAL;
    if (node->parent && node_has_uncompressed_key(ctx, node) &&
        node->parent->kind != KIND_DESCRIPTOR_SH &&
        node->parent->kind != KIND_DESCRIPTOR_WSH)
        return WALLY_EINVAL;
    node->type_properties = builtin_get(node)->type_properties;
    return WALLY_OK;
}

static int verify_wpkh(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    ms_node *parent = node->parent;
    if (parent && (!parent->builtin || parent->kind & KIND_MINISCRIPT))
        return WALLY_EINVAL;
    if (node->child->builtin || !(node->child->kind & KIND_KEY))
        return WALLY_EINVAL;

    for (/* no-op */; parent; parent = parent->parent)
        if (parent->kind == KIND_DESCRIPTOR_WSH)
            return WALLY_EINVAL;

    return node_has_uncompressed_key(ctx, node) ?  WALLY_EINVAL : WALLY_OK;
}

static int verify_combo(ms_ctx *ctx, ms_node *node)
{
    const bool has_uncompressed_key = node_has_uncompressed_key(ctx, node);
    int ret;

    if (!node_is_top(node))
        return WALLY_EINVAL;

    if (has_uncompressed_key) {
        ctx->num_variants = 2; /* p2pk and p2pkh */
    } else {
        ctx->num_variants = 4; /* p2pk, p2pkh, p2wpkh and p2sh-p2wpkh */
    }
    ret = verify_pk(ctx, node);
    /* pkh is the same verification as pk, so skipped */
    if (ret == WALLY_OK && !has_uncompressed_key) {
        ret = verify_wpkh(ctx, node);
        /* p2sh, i.e. p2sh-wpkh is valid if pk and wpkh are */
    }
    /* Take our properties from the combo builtin; this means
     * you can't really say anything about combo validity.
     */
    node->type_properties = builtin_get(node)->type_properties;
    return ret;
}

static int verify_multi(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
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

static int verify_addr(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (node->parent || node->child->builtin || !(node->child->kind & KIND_ADDRESS))
        return WALLY_EINVAL;
    return WALLY_OK;
}

static int verify_raw(ms_ctx *ctx, ms_node *node)
{
    const uint32_t child_count = node_get_child_count(node);
    (void)ctx;
    if (node->parent || child_count > 1)
        return WALLY_EINVAL;
    if (child_count && (node->child->builtin || !(node->child->kind & KIND_RAW)))
        return WALLY_EINVAL;
    return WALLY_OK;
}

static int verify_raw_tr(ms_ctx *ctx, ms_node *node)
{
    if (node->parent || node->child->builtin || !(node->child->kind & KIND_KEY) ||
        node_has_uncompressed_key(ctx, node))
        return WALLY_EINVAL;
    node->type_properties = builtin_get(node)->type_properties;
    return WALLY_OK;
}

static int verify_tr(ms_ctx *ctx, ms_node *node)
{
    const uint32_t child_count = node_get_child_count(node);
    if (child_count != 1u)
        return WALLY_EINVAL; /* FIXME: Support script paths */
    if (!node_is_top(node) || node->child->builtin || !(node->child->kind & KIND_KEY) ||
        node_has_uncompressed_key(ctx, node))
        return WALLY_EINVAL;
    node->type_properties = builtin_get(node)->type_properties;
    return WALLY_OK;
}

static int verify_delay(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (node->child->builtin || node->child->kind != KIND_NUMBER ||
        node->child->number <= 0 || node->child->number > 0x7fffffff)
        return WALLY_EINVAL;

    node->type_properties = builtin_get(node)->type_properties;
    if (builtin_get(node)->kind == KIND_MINISCRIPT_OLDER) {
        if (node->child->number & DESCRIPTOR_SEQUENCE_LOCKTIME_TYPE_FLAG)
            node->type_properties |= PROP_G;
        else
            node->type_properties |= PROP_H;
    } else {
        /* KIND_MINISCRIPT_AFTER */
        if (node->child->number >= DESCRIPTOR_LOCKTIME_THRESHOLD)
            node->type_properties |= PROP_I;
        else
            node->type_properties |= PROP_J;
    }
    return WALLY_OK;
}

static int verify_hash_type(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (node->child->builtin || !(node->child->kind & KIND_RAW))
        return WALLY_EINVAL;

    node->type_properties = builtin_get(node)->type_properties;
    return WALLY_OK;
}

static uint32_t verify_andor_property(uint32_t x_prop, uint32_t y_prop, uint32_t z_prop)
{
    /* Y and Z are both B, K, or V */
    uint32_t prop = PROP_X;
    uint32_t need_x = TYPE_B | PROP_D | PROP_U;
    uint32_t need_yz = TYPE_B | TYPE_K | TYPE_V;
    if (!(x_prop & TYPE_B) || !(x_prop & need_x))
        return 0;
    if (!(y_prop & z_prop & need_yz))
        return 0;

    prop |= y_prop & z_prop & need_yz;
    prop |= x_prop & y_prop & z_prop & PROP_Z;
    prop |= (x_prop | (y_prop & z_prop)) & PROP_O;
    prop |= y_prop & z_prop & PROP_U;
    prop |= z_prop & PROP_D;
    prop |= (x_prop | y_prop | z_prop) & (PROP_G | PROP_H | PROP_I | PROP_J);
    if (x_prop & PROP_S || y_prop & PROP_F) {
        prop |= z_prop & PROP_F;
        prop |= x_prop & z_prop & PROP_E;
    }
    if (x_prop & PROP_E &&
        (x_prop | y_prop | z_prop) & PROP_S) {
        prop |= x_prop & y_prop & z_prop & PROP_M;
    }
    prop |= z_prop & (x_prop | y_prop) & PROP_S;
    if ((x_prop & y_prop & z_prop & PROP_K) &&
        !has_two_different_lock_states(x_prop, y_prop))
        prop |= PROP_K;
    return prop;
}

static int verify_andor(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    node->type_properties = verify_andor_property(node->child->type_properties,
                                                  node->child->next->type_properties,
                                                  node->child->next->next->type_properties);
    return node->type_properties ? WALLY_OK : WALLY_EINVAL;
}

static uint32_t verify_and_v_property(uint32_t x_prop, uint32_t y_prop)
{
    uint32_t prop = 0;
    prop |= x_prop & PROP_N;
    prop |= y_prop & (PROP_U | PROP_X);
    prop |= x_prop & y_prop & (PROP_D | PROP_M | PROP_Z);
    prop |= (x_prop | y_prop) & PROP_S;
    prop |= (x_prop | y_prop) & (PROP_G | PROP_H | PROP_I | PROP_J);
    if (x_prop & TYPE_V)
        prop |= y_prop & (TYPE_K | TYPE_V | TYPE_B);
    if (x_prop & PROP_Z)
        prop |= y_prop & PROP_N;
    if ((x_prop | y_prop) & PROP_Z)
        prop |= (x_prop | y_prop) & PROP_O;
    if (y_prop & PROP_F || x_prop & PROP_S)
        prop |= PROP_F;
    if ((x_prop & y_prop & PROP_K) &&
        !has_two_different_lock_states(x_prop, y_prop))
        prop |= PROP_K;

    return prop & TYPE_MASK ? prop : 0;
}

static int verify_and_v(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    node->type_properties = verify_and_v_property(
        node->child->type_properties,
        node->child->next->type_properties);
    return node->type_properties ? WALLY_OK : WALLY_EINVAL;
}

static int verify_and_b(ms_ctx *ctx, ms_node *node)
{
    const uint32_t x_prop = node->child->type_properties;
    const uint32_t y_prop = node->child->next->type_properties;
    (void)ctx;
    node->type_properties = PROP_U | PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_D | PROP_Z | PROP_M);
    node->type_properties |= (x_prop | y_prop) & PROP_S;
    node->type_properties |= (x_prop | y_prop) & (PROP_G | PROP_H | PROP_I | PROP_J);
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
    if ((x_prop & y_prop & PROP_K) &&
        !has_two_different_lock_states(x_prop, y_prop))
        node->type_properties |= PROP_K;

    return WALLY_OK;
}

static int verify_and_n(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    node->type_properties = verify_andor_property(node->child->type_properties,
                                                  node->child->next->type_properties,
                                                  PROP_OP_0);
    return node->type_properties ? WALLY_OK : WALLY_EINVAL;
}

static int verify_or_b(ms_ctx *ctx, ms_node *node)
{
    const uint32_t x_prop = node->child->type_properties;
    const uint32_t y_prop = node->child->next->type_properties;
    (void)ctx;
    node->type_properties = PROP_D | PROP_U | PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_Z | PROP_S | PROP_E);
    node->type_properties |= (x_prop | y_prop) & (PROP_G | PROP_H | PROP_I | PROP_J);
    node->type_properties |= (x_prop & y_prop) & PROP_K;
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

static int verify_or_c(ms_ctx *ctx, ms_node *node)
{
    const uint32_t x_prop = node->child->type_properties;
    const uint32_t y_prop = node->child->next->type_properties;
    (void)ctx;
    node->type_properties = PROP_F | PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_Z | PROP_S);
    node->type_properties |= (x_prop | y_prop) & (PROP_G | PROP_H | PROP_I | PROP_J);
    node->type_properties |= (x_prop & y_prop) & PROP_K;
    if (!(~x_prop & (TYPE_B | PROP_D | PROP_U)))
        node->type_properties |= y_prop & TYPE_V;
    if (y_prop & PROP_Z)
        node->type_properties |= x_prop & PROP_O;
    if (x_prop & PROP_E && ((x_prop | y_prop) & PROP_S))
        node->type_properties |= x_prop & y_prop & PROP_M;

    return WALLY_OK;
}

static int verify_or_d(ms_ctx *ctx, ms_node *node)
{
    const uint32_t x_prop = node->child->type_properties;
    const uint32_t y_prop = node->child->next->type_properties;
    (void)ctx;
    node->type_properties = PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_Z | PROP_E | PROP_S);
    node->type_properties |= y_prop & (PROP_U | PROP_F | PROP_D);
    node->type_properties |= (x_prop | y_prop) & (PROP_G | PROP_H | PROP_I | PROP_J);
    node->type_properties |= (x_prop & y_prop) & PROP_K;
    if (!(~x_prop & (TYPE_B | PROP_D | PROP_U)))
        node->type_properties |= y_prop & TYPE_B;
    if (y_prop & PROP_Z)
        node->type_properties |= x_prop & PROP_O;
    if (x_prop & PROP_E && ((x_prop | y_prop) & PROP_S))
        node->type_properties |= x_prop & y_prop & PROP_M;

    return WALLY_OK;
}

static uint32_t verify_or_i_property(uint32_t x_prop, uint32_t y_prop)
{
    uint32_t prop = PROP_X;
    prop |= x_prop & y_prop & (TYPE_V | TYPE_B | TYPE_K | PROP_U | PROP_F | PROP_S);
    prop |= (x_prop | y_prop) & (PROP_G | PROP_H | PROP_I | PROP_J);
    prop |= (x_prop & y_prop) & PROP_K;
    if (!(prop & TYPE_MASK))
        return 0;

    prop |= (x_prop | y_prop) & PROP_D;
    if ((x_prop & y_prop) & PROP_Z)
        prop |= PROP_O;
    if ((x_prop | y_prop) & PROP_F)
        prop |= (x_prop | y_prop) & PROP_E;
    if ((x_prop | y_prop) & PROP_S)
        prop |= x_prop & y_prop & PROP_M;

    return prop;
}

static int verify_or_i(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    node->type_properties = verify_or_i_property(node->child->type_properties,
                                                 node->child->next->type_properties);
    return node->type_properties ? WALLY_OK : WALLY_EINVAL;
}

static int verify_thresh(ms_ctx *ctx, ms_node *node)
{
    ms_node *top = node->child, *child;
    int64_t count = 0, num_s = 0, args = 0;
    uint32_t acc_tl = PROP_K, tmp_acc_tl;
    bool all_e = true, all_m = true;

    (void)ctx;
    if (!top || top->builtin || top->kind != KIND_NUMBER)
        return WALLY_EINVAL;

    for (child = top->next; child; child = child->next) {
        const uint32_t expected_type = count ? TYPE_W : TYPE_B;

        if (!child->builtin || (~child->type_properties & (expected_type | PROP_D)))
            return WALLY_EINVAL;

        if (~child->type_properties & PROP_E)
            all_e = false;
        if (~child->type_properties & PROP_M)
            all_m = false;
        if (child->type_properties & PROP_S)
            ++num_s;
        if (child->type_properties & PROP_Z)
            args += (~child->type_properties & PROP_O) ? 2 : 1;


        tmp_acc_tl = ((acc_tl | child->type_properties) & (PROP_G | PROP_H | PROP_I | PROP_J));
        if ((acc_tl & child->type_properties) & PROP_K) {
            if (top->number <= 1 || (top->number > 1 &&
                !has_two_different_lock_states(acc_tl, child->type_properties)))
                tmp_acc_tl |= PROP_K;
        }
        acc_tl = tmp_acc_tl;
        ++count;
    }
    if (top->number < 1 || top->number > count)
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
    node->type_properties |= acc_tl;

    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
static int verify_ct(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (node->parent || node->wrapper_str[0])
        return WALLY_EINVAL;
    if (node->child->kind != KIND_DESCRIPTOR_SLIP77 &&
        !(node->child->kind & KIND_KEY) &&
        node->child->kind != KIND_DESCRIPTOR_ELIP151)
        return WALLY_EINVAL;
    if (node->child->kind & KIND_KEY) {
        if (node_has_uncompressed_key(ctx, node) ||
            (node->flags & WALLY_MS_IS_X_ONLY))
        return WALLY_EINVAL; /* Blinding keys must be compressed non-x-only */
    }
    /* Ensure the second child is a valid top level node */
    switch (node->child->next->kind) {
    case KIND_DESCRIPTOR_PK | KIND_MINISCRIPT_PK:
    case KIND_DESCRIPTOR_PKH | KIND_MINISCRIPT_PKH:
    case KIND_DESCRIPTOR_MULTI | KIND_MINISCRIPT_MULTI:
    case KIND_DESCRIPTOR_MULTI_S:
    case KIND_DESCRIPTOR_SH:
    case KIND_DESCRIPTOR_WPKH:
    case KIND_DESCRIPTOR_WSH:
    case KIND_DESCRIPTOR_COMBO:
    case KIND_DESCRIPTOR_TR:
    case KIND_MINISCRIPT_PK_K:
    case KIND_MINISCRIPT_PK_H:
        return WALLY_OK;
    }
    return WALLY_EINVAL;
}

static int verify_slip77(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (!node->parent || node->parent->kind != KIND_DESCRIPTOR_CT)
        return WALLY_EINVAL;
    if (node->child->builtin || !(node->child->kind & KIND_RAW) ||
        node->child->data_len != 32 || node->wrapper_str[0])

        return WALLY_EINVAL;
    return WALLY_OK;
}
#endif /* ifdef BUILD_ELEMENTS */

static int node_verify_wrappers(ms_node *node)
{
    uint32_t *properties = &node->type_properties;
    size_t i;

    if (node->wrapper_str[0] == '\0')
        return WALLY_OK; /* No wrappers */

    /* Validate the nodes wrappers in reverse order */
    for (i = strlen(node->wrapper_str); i != 0; --i) {
        const uint32_t x_prop = *properties;
#define PROP_REQUIRE(props) if ((x_prop & (props)) != (props)) return WALLY_EINVAL
#define PROP_CHANGE_TYPE(clr, set) *properties &= ~(clr); *properties |= set
#define PROP_CHANGE(keep, set) *properties &= (TYPE_MASK | keep); *properties |= set

        switch(node->wrapper_str[i - 1]) {
        case 'a':
            PROP_REQUIRE(TYPE_B);
            PROP_CHANGE_TYPE(TYPE_B, TYPE_W);
            PROP_CHANGE(PROP_U | PROP_D | PROP_F | PROP_E | PROP_M | PROP_S |
                        PROP_G | PROP_H | PROP_I | PROP_J | PROP_K, PROP_X);
            break;
        case 's':
            PROP_REQUIRE(TYPE_B | PROP_O);
            PROP_CHANGE_TYPE(TYPE_B | PROP_O, TYPE_W);
            PROP_CHANGE(PROP_U | PROP_D | PROP_F | PROP_E | PROP_M | PROP_S |
                        PROP_X | PROP_G | PROP_H | PROP_I | PROP_J | PROP_K, 0);
            break;
        case 'c':
            PROP_REQUIRE(TYPE_K);
            PROP_CHANGE_TYPE(TYPE_K, TYPE_B);
            PROP_CHANGE(PROP_O | PROP_N | PROP_D | PROP_F | PROP_E | PROP_M |
                        PROP_G | PROP_H | PROP_I | PROP_J | PROP_K, PROP_U | PROP_S);
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
            PROP_CHANGE(PROP_M | PROP_S, PROP_N | PROP_D | PROP_X |
                        PROP_G | PROP_H | PROP_I | PROP_J | PROP_K);
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
            PROP_CHANGE(PROP_Z | PROP_O | PROP_N | PROP_M | PROP_S | PROP_G |
                        PROP_H | PROP_I | PROP_J | PROP_K, PROP_F | PROP_X);
            break;
        case 'j':
            PROP_REQUIRE(TYPE_B | PROP_N);
            PROP_CHANGE(PROP_O | PROP_U | PROP_M | PROP_S | PROP_N | PROP_D |
                        PROP_X, PROP_N | PROP_D | PROP_X);
            if (x_prop & PROP_F) {
                PROP_CHANGE(~PROP_F, PROP_E);
            }
            break;
        case 'n':
            PROP_REQUIRE(TYPE_B);
            PROP_CHANGE(PROP_Z | PROP_O | PROP_N | PROP_D | PROP_F | PROP_E |
                        PROP_M | PROP_S | PROP_N | PROP_D | PROP_X, PROP_X);
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
        ((*properties & TYPE_W) && (*properties & PROP_N)) ||
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

static int generate_number(int64_t number, ms_node *parent,
                           unsigned char *script, size_t script_len, size_t *written)
{
    if ((parent && !parent->builtin))
        return WALLY_EINVAL;

    if (number >= -1 && number <= 16) {
        *written = 1;
        if (*written <= script_len)
            script[0] = number == -1 ? OP_1NEGATE : value_to_op_n(number);
    } else {
        /* PUSH <number> */
        *written = 1 + scriptint_get_length(number);
        if (*written <= script_len) {
            script[0] = *written - 1;
            scriptint_to_bytes(number, script + 1);
        }
    }
    return WALLY_OK;
}

static int generate_pk_k_impl(ms_ctx *ctx, ms_node *node,
                              unsigned char *script, size_t script_len,
                              bool force_xonly, size_t *written)
{
    unsigned char buff[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    int ret;

    if (!node->child || !node_is_root(node))
        return WALLY_EINVAL;

    ret = generate_script(ctx, node->child, buff, sizeof(buff), written);
    if (ret == WALLY_OK) {
        if (*written != EC_PUBLIC_KEY_LEN && *written != EC_XONLY_PUBLIC_KEY_LEN &&
            *written != EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
            return WALLY_EINVAL; /* Invalid pubkey length */
        if (force_xonly) {
            if (*written == EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
                return WALLY_EINVAL; /* Can't make x-only from uncompressed key */
            if (*written == EC_XONLY_PUBLIC_KEY_LEN)
                force_xonly = false; /* Already x-only */
            else
                *written -= 1; /* Account for stripping the lead byte below */
        }
        if (*written + 1 <= script_len) {
            script[0] = *written & 0xff; /* push opcode */
            memcpy(script + 1, buff + (force_xonly ? 1 : 0), *written);
        }
        *written += 1;
    }
    return ret;
}

static int generate_pk_k(ms_ctx *ctx, ms_node *node,
                         unsigned char *script, size_t script_len, size_t *written)
{
    const bool force_xonly = false;
    return generate_pk_k_impl(ctx, node, script, script_len, force_xonly, written);
}

static int generate_pk_h(ms_ctx *ctx, ms_node *node,
                         unsigned char *script, size_t script_len, size_t *written)
{
    /* Note 4 instead of 1 here to align the data to hash to 32 bits */
    unsigned char buff[4 + EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    int ret = WALLY_OK;

    if (script_len >= WALLY_SCRIPTPUBKEY_P2PKH_LEN - 1) {
        ret = generate_pk_k(ctx, node, buff+3, sizeof(buff)-3, written);
        if (ret == WALLY_OK) {
            if (node->child->flags & WALLY_MS_IS_X_ONLY)
                return WALLY_EINVAL;
            script[0] = OP_DUP;
            script[1] = OP_HASH160;
            script[2] = HASH160_LEN;
            ret = wally_hash160(buff+4, *written - 1, script + 3, HASH160_LEN);
            script[3 + HASH160_LEN] = OP_EQUALVERIFY;
        }
    }
    *written = WALLY_SCRIPTPUBKEY_P2PKH_LEN - 1;
    return ret;
}

static int generate_sh_wsh(ms_ctx *ctx, ms_node *node,
                           unsigned char *script, size_t script_len, size_t *written)
{
    const bool is_sh = node->kind == KIND_DESCRIPTOR_SH;
    const size_t final_len = is_sh ? WALLY_SCRIPTPUBKEY_P2SH_LEN : WALLY_SCRIPTPUBKEY_P2WSH_LEN;
    const uint32_t flags = is_sh ? WALLY_SCRIPT_HASH160 : WALLY_SCRIPT_SHA256;
    unsigned char output[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
    size_t output_len;
    int ret;

    if (!node->child || !node_is_root(node))
        return WALLY_EINVAL;

    ret = generate_script(ctx, node->child, script, script_len, &output_len);
    if (ret == WALLY_OK) {
        if (output_len > REDEEM_SCRIPT_MAX_SIZE)
            ret = WALLY_EINVAL;
        else {
           const size_t required = output_len > final_len ? output_len : final_len;
           if (script_len < required) {
               *written = required; /* To generate, not for the final script */
           } else {
               ret = (is_sh ? wally_scriptpubkey_p2sh_from_bytes :
                              wally_witness_program_from_bytes)(
                      script, output_len, flags, output, sizeof(output), written);
               if (ret == WALLY_OK && *written <= script_len)
                   memcpy(script, output, *written);
           }
        }
    }
    return ret;
}

static int generate_inplace_checksig(unsigned char *script, size_t script_len,
                                     size_t *written)
{
    if (!*written || (*written + 1 > WITNESS_SCRIPT_MAX_SIZE))
        return WALLY_EINVAL;

    *written += 1;
    if (*written <= script_len)
        script[*written - 1] = OP_CHECKSIG;
    return WALLY_OK;
}

static int generate_pk(ms_ctx *ctx, ms_node *node,
                       unsigned char *script, size_t script_len, size_t *written)
{
    int ret = generate_pk_k(ctx, node, script, script_len, written);
    if (ret == WALLY_OK)
       ret = generate_inplace_checksig(script, script_len, written);
    return ret;
}

static int generate_pkh(ms_ctx *ctx, ms_node *node,
                        unsigned char *script, size_t script_len, size_t *written)
{
    int ret = generate_pk_h(ctx, node, script, script_len, written);
    if (ret == WALLY_OK)
        ret = generate_inplace_checksig(script, script_len, written);
    return ret;
}

static int generate_wpkh(ms_ctx *ctx, ms_node *node,
                         unsigned char *script, size_t script_len, size_t *written)
{
    unsigned char output[WALLY_SCRIPTPUBKEY_P2WPKH_LEN];
    size_t output_len;
    int ret;

    if (!node->child || !node_is_root(node))
        return WALLY_EINVAL;

    ret = generate_script(ctx, node->child, script, script_len, &output_len);
    if (ret == WALLY_OK) {
        if (output_len > REDEEM_SCRIPT_MAX_SIZE)
            ret = WALLY_EINVAL;
        else {
            const size_t final_len = sizeof(output);
            const size_t required = output_len > final_len ? output_len : final_len;
            if (script_len < required) {
                *written = required; /* To generate, not for the final script */
            } else {
                ret = wally_witness_program_from_bytes(script, output_len,
                                                       WALLY_SCRIPT_HASH160,
                                                       output, final_len, written);
                if (ret == WALLY_OK && *written <= script_len)
                    memcpy(script, output, *written);
            }
        }
    }
    return ret;
}

static int generate_sh_wpkh(ms_ctx *ctx, ms_node *node,
                            unsigned char *script, size_t script_len, size_t *written)
{
    /* Create a fake parent sh() node to wrap our combo w2pkh child */
    ms_ctx fake_ctx;
    const unsigned char builtin_sh_index = 0 + 1;
    ms_node sh_node = { NULL, node, NULL, KIND_DESCRIPTOR_SH,
                        TYPE_NONE, 0, NULL, NULL, 0, 0,
                        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                        0, builtin_sh_index };

    if (ctx->variant != 3)
        return WALLY_ERROR; /* Should only be called to generate sh-wpkh */
    memcpy(&fake_ctx, ctx, sizeof(fake_ctx));
    fake_ctx.variant = 2; /* Generate wpkh from the combo node */
    return builtin_get(&sh_node)->generate_fn(&fake_ctx, &sh_node,
                                              script, script_len,
                                              written);
}

static int generate_combo(ms_ctx *ctx, ms_node *node,
                          unsigned char *script, size_t script_len, size_t *written)
{
    const node_gen_fn_t funcs[4] = { generate_pk, generate_pkh, generate_wpkh, generate_sh_wpkh };
    return funcs[ctx->variant](ctx, node, script, script_len, written);
}

static int compare_multisig_node(const void *lhs, const void *rhs)
{
    const struct multisig_sort_data_t *l = lhs;
    /* Note: if pubkeys are different sizes, the head byte will differ and so this
     * memcmp will not read beyond either */
    return memcmp(l->pubkey, ((const struct multisig_sort_data_t *)rhs)->pubkey, l->pubkey_len);
}

static int generate_multi(ms_ctx *ctx, ms_node *node,
                          unsigned char *script, size_t script_len, size_t *written)
{
    size_t offset;
    uint32_t count, i;
    ms_node *child = node->child;
    struct multisig_sort_data_t *sorted;
    int ret;

    if (!child || !node_is_root(node) || !node->builtin)
        return WALLY_EINVAL;

    count = node_get_child_count(node) - 1;
    /* FIXME: We should allow 20 keys in witness scriptss */
    if (count > CHECKMULTISIG_NUM_KEYS_MAX)
        return WALLY_EINVAL; /* Too many keys for multisig */

    if ((ret = generate_script(ctx, child, script, script_len, &offset)) != WALLY_OK)
        return ret;

    if (!(sorted = wally_malloc(count * sizeof(struct multisig_sort_data_t))))
        return WALLY_ENOMEM;

    child = child->next;
    for (i = 0; ret == WALLY_OK && i < count; ++i) {
        struct multisig_sort_data_t *item = sorted + i;
        ret = generate_script(ctx, child,
                              item->pubkey, sizeof(item->pubkey), &item->pubkey_len);
        if (ret == WALLY_OK && item->pubkey_len > sizeof(item->pubkey))
            ret = WALLY_ERROR; /* FIXME: check for valid pubkey lengths */
        child = child->next;
    }

    if (ret == WALLY_OK) {
        /* Note we don't bother sorting if we are already beyond the output
         * size, since sorting won't change the final size computed */
        if (node->kind == KIND_DESCRIPTOR_MULTI_S && offset <= script_len)
            qsort(sorted, count, sizeof(sorted[0]), compare_multisig_node);

        for (i = 0; ret == WALLY_OK && i < count; ++i) {
            const size_t pubkey_len = sorted[i].pubkey_len;
            if (offset + pubkey_len + 1 <= script_len) {
                script[offset] = pubkey_len;
                memcpy(script + offset + 1, sorted[i].pubkey, pubkey_len);
            }
            offset += pubkey_len + 1;
        }

        if (ret == WALLY_OK) {
            size_t number_len;
            size_t remaining_len = offset > script_len ? 0 : script_len - offset;
            ret = generate_number(count, node->parent, script + offset,
                                  remaining_len, &number_len);
            if (ret == WALLY_OK) {
                *written = offset + number_len + 1;
                if (*written > REDEEM_SCRIPT_MAX_SIZE)
                    return WALLY_EINVAL;
                if (*written <= script_len)
                    script[*written - 1] = OP_CHECKMULTISIG;
            }
        }
    }
    wally_free(sorted);
    return ret;
}

static int generate_raw(ms_ctx *ctx, ms_node *node,
                        unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    if (!script_len || !node_is_root(node))
        return WALLY_EINVAL;
    if (!node->child) {
        if (node->kind == KIND_DESCRIPTOR_RAW) {
            *written = 0; /* raw() - empty script */
            return WALLY_OK;
        }
        return WALLY_EINVAL; /* addr() is not valid */
    }
    ret = generate_script(ctx, node->child, script, script_len, written);
    return *written > REDEEM_SCRIPT_MAX_SIZE ?  WALLY_EINVAL : ret;
}

static int generate_raw_tr(ms_ctx *ctx, ms_node *node,
                           unsigned char *script, size_t script_len, size_t *written)
{
    int ret = WALLY_OK;

    if (script_len >= WALLY_SCRIPTPUBKEY_P2TR_LEN) {
        script[0] = OP_1;
        const bool force_xonly = true;
        ret = generate_pk_k_impl(ctx, node, script + 1, script_len - 1,
                                 force_xonly, written);
    }
    *written = WALLY_SCRIPTPUBKEY_P2TR_LEN;
    return ret;
}

static int generate_tr(ms_ctx *ctx, ms_node *node,
                       unsigned char *script, size_t script_len, size_t *written)
{
    unsigned char tweaked[EC_PUBLIC_KEY_LEN];
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN + 1];
    size_t pubkey_len = 0;
    uint32_t tweak_flags = 0;
    int ret;

    /* Generate a push of the x-only public key of our child */
    const bool force_xonly = true;
    ret = generate_pk_k_impl(ctx, node, pubkey, sizeof(pubkey), force_xonly, &pubkey_len);
    if (ret != WALLY_OK || pubkey_len != EC_XONLY_PUBLIC_KEY_LEN + 1)
        return WALLY_EINVAL; /* Should be PUSH_32 [x-only pubkey] */

    /* Tweak it into a compressed pubkey */
#ifdef BUILD_ELEMENTS
    if (ctx->features & WALLY_MS_IS_ELEMENTS)
        tweak_flags = EC_FLAG_ELEMENTS;
#endif
    ret = wally_ec_public_key_bip341_tweak(pubkey + 1, pubkey_len - 1,
                                           NULL, 0, /* FIXME: Support script path */
                                           tweak_flags, tweaked, sizeof(tweaked));

    if (ret == WALLY_OK && script_len >= WALLY_SCRIPTPUBKEY_P2TR_LEN) {
        /* Generate the script using the x-only part of the tweaked key */
        script[0] = OP_1;
        script[1] = sizeof(tweaked) - 1;
        memcpy(script + 2, tweaked + 1, sizeof(tweaked) - 1);
    }
    *written = WALLY_SCRIPTPUBKEY_P2TR_LEN;
    return ret;
}

static int generate_delay(ms_ctx *ctx, ms_node *node,
                          unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    size_t output_len;
    if (!node->child || !node_is_root(node) || !node->builtin)
        return WALLY_EINVAL;

    ret = generate_script(ctx, node->child, script, script_len, &output_len);
    if (ret == WALLY_OK) {
        *written = output_len + 1;
        if (*written <= script_len) {
            if (node->kind == KIND_MINISCRIPT_OLDER)
                script[output_len] = OP_CHECKSEQUENCEVERIFY;
            else if (node->kind == KIND_MINISCRIPT_AFTER)
                script[output_len] = OP_CHECKLOCKTIMEVERIFY;
            else
                ret = WALLY_ERROR; /* Shouldn't happen */
        }
    }
    return ret;
}

static int generate_hash_type(ms_ctx *ctx, ms_node *node,
                              unsigned char *script, size_t script_len,
                              size_t *written)
{
    int ret;
    size_t hash_size,  remaining_len = 0;
    unsigned char op_code;

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

    if (script_len >= 7)
        remaining_len = script_len - 7;
    ret = generate_script(ctx, node->child, script + 6, remaining_len, written);
    if (ret == WALLY_OK) {
        if (*written + 7 <= script_len) {
            script[0] = OP_SIZE;
            script[1] = 0x01;
            script[2] = 0x20;
            script[3] = OP_EQUALVERIFY;
            script[4] = op_code;
            script[5] = hash_size;
            script[6 + *written] = OP_EQUAL;
        }
        *written += 7;
    }
    return ret;
}

static int generate_concat(ms_ctx *ctx, ms_node *node, size_t target_num,
                           const unsigned char *indices,
                           const unsigned char **insert, const uint8_t *insert_len,
                           unsigned char *script, size_t script_len, size_t *written)
{
    size_t i = 0, offset = 0;
    ms_node *children[3] = { NULL, NULL, NULL };
    static const unsigned char default_indices[] = { 0, 1, 2 };
    int ret = WALLY_OK;

    if (!node->child || !node_is_root(node))
        return WALLY_EINVAL;

    if (!indices)
        indices = default_indices;

    for (i = 0; i < target_num; ++i) {
        children[i] = i == 0 ? node->child : children[i - 1]->next;
        if (!children[i])
            return WALLY_EINVAL;
    }

    for (i = 0; i < target_num; ++i) {
        size_t output_len, remaining_len = 0;

        if (insert_len[i] && offset + insert_len[i] <= script_len)
            memcpy(script + offset, insert[i], insert_len[i]);
        offset += insert_len[i];
        if (offset < script_len)
            remaining_len = script_len - offset - 1;
        ret = generate_script(ctx, children[indices[i]],
                              script + offset, remaining_len, &output_len);
        if (ret != WALLY_OK)
            return ret;
        offset += output_len;
    }

    if (insert_len[3] && offset + insert_len[3] <= script_len)
        memcpy(script + offset, insert[3], insert_len[3]);
    *written = offset + insert_len[3];
    if (*written > REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;
    return ret;
}

static int generate_andor(ms_ctx *ctx, ms_node *node,
                          unsigned char *script, size_t script_len, size_t *written)
{
    /* [X] NOTIF 0 ELSE [Y] ENDIF */
    static const unsigned char first_op[1] = { OP_NOTIF };
    static const unsigned char second_op[1] = { OP_ELSE };
    static const unsigned char last_op[1] = { OP_ENDIF };
    static const unsigned char indices[3] = { 0, 2, 1 };
    static const unsigned char *insert[4] = { NULL, first_op, second_op, last_op };
    static const uint8_t insert_len[4] = { 0, NUM_ELEMS(first_op), NUM_ELEMS(second_op), NUM_ELEMS(last_op) };
    return generate_concat(ctx, node, 3, indices, insert, insert_len,
                           script, script_len, written);
}

static int generate_and_v(ms_ctx *ctx, ms_node *node,
                          unsigned char *script, size_t script_len, size_t *written)
{
    /* [X] [Y] */
    static const unsigned char indices[2] = { 0, 1 };
    static const unsigned char *insert[4] = { NULL, NULL, NULL, NULL };
    static const uint8_t insert_len[4] = { 0, 0, 0, 0 };
    return generate_concat(ctx, node, 2, indices, insert, insert_len,
                           script, script_len, written);
}

static int generate_and_b(ms_ctx *ctx, ms_node *node,
                          unsigned char *script, size_t script_len, size_t *written)
{
    /* [X] [Y] BOOLAND */
    static const unsigned char append[1] = { OP_BOOLAND };
    static const unsigned char indices[2] = { 0, 1 };
    static const unsigned char *insert[4] = { NULL, NULL, NULL, append };
    static const uint8_t insert_len[4] = { 0, 0, 0, NUM_ELEMS(append) };
    return generate_concat(ctx, node, 2, indices, insert, insert_len,
                           script, script_len, written);
}

static int generate_and_n(ms_ctx *ctx, ms_node *node,
                          unsigned char *script, size_t script_len, size_t *written)
{
    /* [X] NOTIF 0 ELSE [Y] ENDIF */
    static const unsigned char middle_op[3] = { OP_NOTIF, OP_0, OP_ELSE };
    static const unsigned char last_op[1] = { OP_ENDIF };
    static const unsigned char indices[2] = { 0, 1 };
    static const unsigned char *insert[4] = { NULL, middle_op, NULL, last_op };
    static const uint8_t insert_len[4] = { 0, NUM_ELEMS(middle_op), 0, NUM_ELEMS(last_op) };
    return generate_concat(ctx, node, 2, indices, insert, insert_len,
                           script, script_len, written);
}

static int generate_or_b(ms_ctx *ctx, ms_node *node,
                         unsigned char *script, size_t script_len, size_t *written)
{
    /* [X] [Y] OP_BOOLOR */
    static const unsigned char append[1] = { OP_BOOLOR };
    static const unsigned char indices[2] = { 0, 1 };
    static const unsigned char *insert[4] = { NULL, NULL, NULL, append };
    static const uint8_t insert_len[4] = { 0, 0, 0, NUM_ELEMS(append) };
    return generate_concat(ctx, node, 2, indices, insert, insert_len,
                           script, script_len, written);
}

static int generate_or_c(ms_ctx *ctx, ms_node *node,
                         unsigned char *script, size_t script_len, size_t *written)
{
    /* [X] NOTIF [Z] ENDIF */
    static const unsigned char middle_op[1] = { OP_NOTIF };
    static const unsigned char last_op[1] = { OP_ENDIF };
    static const unsigned char indices[2] = { 0, 1 };
    static const unsigned char *insert[4] = { NULL, middle_op, NULL, last_op };
    static const uint8_t insert_len[4] = { 0, NUM_ELEMS(middle_op), 0, NUM_ELEMS(last_op) };
    return generate_concat(ctx, node, 2, indices, insert, insert_len,
                           script, script_len, written);
}

static int generate_or_d(ms_ctx *ctx, ms_node *node,
                         unsigned char *script, size_t script_len, size_t *written)
{
    /* [X] IFDUP NOTIF [Z] ENDIF */
    static const unsigned char middle_op[2] = { OP_IFDUP, OP_NOTIF };
    static const unsigned char last_op[1] = { OP_ENDIF };
    static const unsigned char indices[2] = { 0, 1 };
    static const unsigned char *insert[4] = { NULL, middle_op, NULL, last_op };
    static const uint8_t insert_len[4] = { 0, NUM_ELEMS(middle_op), 0, NUM_ELEMS(last_op) };
    return generate_concat(ctx, node, 2, indices, insert, insert_len,
                           script, script_len, written);
}

static int generate_or_i(ms_ctx *ctx, ms_node *node,
                         unsigned char *script, size_t script_len, size_t *written)
{
    /* IF [X] ELSE [Z] ENDIF */
    static const unsigned char top_op[1] = { OP_IF };
    static const unsigned char middle_op[1] = { OP_ELSE };
    static const unsigned char last_op[1] = { OP_ENDIF };
    static const unsigned char indices[2] = { 0, 1 };
    static const unsigned char *insert[4] = { top_op, middle_op, NULL, last_op };
    static const uint8_t insert_len[4] = { NUM_ELEMS(top_op), NUM_ELEMS(middle_op), 0, NUM_ELEMS(last_op) };
    return generate_concat(ctx, node, 2, indices, insert, insert_len,
                           script, script_len, written);
}

static int generate_thresh(ms_ctx *ctx, ms_node *node,
                           unsigned char *script, size_t script_len, size_t *written)
{
    /* [X1] [X2] ADD ... [Xn] ADD <k> EQUAL */
    ms_node *child = node->child;
    size_t output_len, remaining_len, offset = 0, count = 0;
    int ret = WALLY_OK;

    if (!child || !node_is_root(node))
        return WALLY_EINVAL;

    for (child = child->next; child && ret == WALLY_OK; child = child->next) {
        remaining_len = offset >= script_len ? 0 : script_len - offset - 1;
        ret = generate_script(ctx, child,
                              script + offset, remaining_len, &output_len);
        if (ret == WALLY_OK) {
            offset += output_len;
            if (count++) {
                if (++offset < script_len)
                    script[offset - 1] = OP_ADD;
            }
        }
    }
    if (ret == WALLY_OK) {
        remaining_len = offset >= script_len ? 0 : script_len - offset - 1;
        ret = generate_script(ctx, node->child,
                              script + offset, remaining_len, &output_len);
    }
    if (ret == WALLY_OK) {
        *written = offset + output_len + 1;
        if (*written > REDEEM_SCRIPT_MAX_SIZE)
            return WALLY_EINVAL;
        if (*written <= script_len)
            script[*written - 1] = OP_EQUAL;
    }
    return ret;
}

static int generate_inplace_wrappers(ms_node *node,
                                     unsigned char *script, size_t script_len,
                                     size_t *written)
{
    size_t i = strlen(node->wrapper_str);

    if (!i)
        return WALLY_OK; /* No wrappers */

    if (!*written)
        return WALLY_EINVAL; /* Nothing to wrap */

#define WRAP_REQUIRE(req, move_by) output_len = (req); \
    if (*written + output_len <= script_len) { \
        if (move_by) memmove(script + (move_by), script, *written)
#define WRAP_REQUIRE_END } break

    /* Generate the nodes wrappers in reserve order */
    while (i--) {
        size_t output_len = 0;
        switch(node->wrapper_str[i]) {
        case 'a':
            WRAP_REQUIRE(2, 1);
            script[0] = OP_TOALTSTACK;
            script[*written + 1] = OP_FROMALTSTACK;
            WRAP_REQUIRE_END;
        case 's':
            WRAP_REQUIRE(1, 1);
            script[0] = OP_SWAP;
            WRAP_REQUIRE_END;
        case 'c':
            WRAP_REQUIRE(1, 0);
            script[*written] = OP_CHECKSIG;
            WRAP_REQUIRE_END;
        case 't':
            WRAP_REQUIRE(1, 0);
            script[*written] = OP_1;
            WRAP_REQUIRE_END;
        case 'd':
            WRAP_REQUIRE(3, 2);
            script[0] = OP_DUP;
            script[1] = OP_IF;
            script[*written + 2] = OP_ENDIF;
            WRAP_REQUIRE_END;
        case 'v':
            if (*written >= script_len) {
                /* If we aren't actually generating output because the script
                 * output is too small, we have to assume the worst case, i.e.
                 * that this wrapper will require an extra opcode rather than
                 * modifying in place.
                 */
                output_len = 1;
            } else {
                unsigned char *last = script + *written - 1;
                /* The following check cannot happen, but scan-build believes
                 * it can - check for it to avoid false positives */
                if (last < script)
                    return WALLY_ERROR;
                if (*last == OP_EQUAL)
                    *last = OP_EQUALVERIFY;
                else if (*last == OP_NUMEQUAL)
                    *last = OP_NUMEQUALVERIFY;
                else if (*last == OP_CHECKSIG)
                    *last = OP_CHECKSIGVERIFY;
                else if (*last == OP_CHECKMULTISIG)
                    *last = OP_CHECKMULTISIGVERIFY;
                else {
                    WRAP_REQUIRE(1, 0);
                    script[*written] = OP_VERIFY;
                    WRAP_REQUIRE_END;
                }
            }
            break;
        case 'j':
            WRAP_REQUIRE(4, 3);
            script[0] = OP_SIZE;
            script[1] = OP_0NOTEQUAL;
            script[2] = OP_IF;
            script[*written + 3] = OP_ENDIF;
            WRAP_REQUIRE_END;
        case 'n':
            WRAP_REQUIRE(1, 0);
            script[*written] = OP_0NOTEQUAL;
            WRAP_REQUIRE_END;
        case 'l':
            WRAP_REQUIRE(4, 3);
            script[0] = OP_IF;
            script[1] = OP_0;
            script[2] = OP_ELSE;
            script[*written + 3] = OP_ENDIF;
            WRAP_REQUIRE_END;
        case 'u':
            WRAP_REQUIRE(4, 1);
            script[0] = OP_IF;
            script[*written + 1] = OP_ELSE;
            script[*written + 2] = OP_0;
            script[*written + 3] = OP_ENDIF;
            WRAP_REQUIRE_END;
        default:
            return WALLY_ERROR; /* Wrapper type not found, should not happen */
        }
        if (*written + output_len > WITNESS_SCRIPT_MAX_SIZE)
            return WALLY_EINVAL;
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
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X | PROP_K,
        1, verify_pk, generate_pk
    }, {   /* c:pk_h */
        I_NAME("pkh"),
        KIND_DESCRIPTOR_PKH | KIND_MINISCRIPT_PKH,
        TYPE_B | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X | PROP_K,
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
        TYPE_B | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_K,
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
        0xffffffff, verify_raw, generate_raw
    }, {
        I_NAME("rawtr"),
        KIND_DESCRIPTOR_RAW_TR,
        TYPE_NONE,
        1, verify_raw_tr, generate_raw_tr
    }, {
        I_NAME("tr"),
        KIND_DESCRIPTOR_TR,
        TYPE_NONE,
        0xffffffff, verify_tr, generate_tr
    },
    /* miniscript */
    {
        I_NAME("pk_k"),
        KIND_MINISCRIPT_PK_K,
        TYPE_K | PROP_O | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X | PROP_K,
        1, verify_pk, generate_pk_k
    }, {
        I_NAME("pk_h"),
        KIND_MINISCRIPT_PK_H,
        TYPE_K | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X | PROP_K,
        1, verify_pk, generate_pk_h
    }, {
        I_NAME("older"),
        KIND_MINISCRIPT_OLDER,
        TYPE_B | PROP_Z | PROP_F | PROP_M | PROP_X | PROP_K,
        1, verify_delay, generate_delay
    }, {
        I_NAME("after"),
        KIND_MINISCRIPT_AFTER,
        TYPE_B | PROP_Z | PROP_F | PROP_M | PROP_X | PROP_K,
        1, verify_delay, generate_delay
    }, {
        I_NAME("sha256"),
        KIND_MINISCRIPT_SHA256,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M | PROP_K,
        1, verify_hash_type, generate_hash_type
    }, {
        I_NAME("hash256"),
        KIND_MINISCRIPT_HASH256,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M | PROP_K,
        1, verify_hash_type, generate_hash_type
    }, {
        I_NAME("ripemd160"),
        KIND_MINISCRIPT_RIPEMD160,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M | PROP_K,
        1, verify_hash_type, generate_hash_type
    }, {
        I_NAME("hash160"),
        KIND_MINISCRIPT_HASH160,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M | PROP_K,
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
    /* Elements confidential descriptors */
#ifdef BUILD_ELEMENTS
    , {
        I_NAME("ct"),
        KIND_DESCRIPTOR_CT,
        TYPE_NONE,
        2, verify_ct, NULL /* Generation is skipped for this node type */
    }, {
        I_NAME("slip77"),
        KIND_DESCRIPTOR_SLIP77,
        TYPE_NONE,
        1, verify_slip77, NULL /* Generation is skipped for this node type */
    }
#endif /* ifdef BUILD_ELEMENTS */
};
#undef I_NAME

#ifdef BUILD_ELEMENTS
static inline bool builtin_is_elements(const char *name, size_t name_len)
{
    /* Elements descriptor builtins are prefixed with "el" */
    return name_len > 2 && name[0] == 'e' && name[1] == 'l';
}
#endif /* ifdef BUILD_ELEMENTS */

static unsigned char builtin_lookup(const char *name, size_t name_len, uint32_t kind)
{
    unsigned char i;
#ifdef BUILD_ELEMENTS
    if (builtin_is_elements(name, name_len)) {
        name += 2; /* Look up without matching the prefix */
        name_len -= 2;
    }
#endif /* ifdef BUILD_ELEMENTS */

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

static int generate_script(ms_ctx *ctx, ms_node *node,
                           unsigned char *script, size_t script_len, size_t *written)
{
    int ret = WALLY_EINVAL;
    size_t output_len = 0;
    *written = 0;

    if (node->builtin) {
        ret = builtin_get(node)->generate_fn(ctx, node, script, script_len, &output_len);
    } else if (node->kind == KIND_NUMBER) {
        ret = generate_number(node->number, node->parent, script, script_len, &output_len);
    } else if (node->kind & (KIND_RAW | KIND_ADDRESS) || node->kind == KIND_PUBLIC_KEY) {
        if (node->data_len <= script_len)
            memcpy(script, node->data, node->data_len);
        output_len = node->data_len;
        ret = WALLY_OK;
    } else if (node->kind == KIND_PRIVATE_KEY) {
        unsigned char pubkey[EC_PUBLIC_KEY_LEN];
        ret = wally_ec_public_key_from_private_key((const unsigned char*)node->data, node->data_len,
                                                   pubkey, sizeof(pubkey));
        if (ret == WALLY_OK) {
            if (node->flags & WALLY_MS_IS_UNCOMPRESSED) {
                output_len = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
                if (output_len <= script_len)
                    ret = wally_ec_public_key_decompress(pubkey, sizeof(pubkey), script,
                                                         EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
            } else {
                if (node->flags & WALLY_MS_IS_X_ONLY) {
                    output_len = EC_XONLY_PUBLIC_KEY_LEN;
                    if (output_len <= script_len)
                        memcpy(script, &pubkey[1], EC_XONLY_PUBLIC_KEY_LEN);
                } else {
                    output_len = EC_PUBLIC_KEY_LEN;
                    if (output_len <= script_len)
                        memcpy(script, pubkey, EC_PUBLIC_KEY_LEN);
                }
            }
        }
    } else if ((node->kind & KIND_BIP32) == KIND_BIP32) {
        output_len = node->flags & WALLY_MS_IS_X_ONLY ? EC_XONLY_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_LEN;
        if (output_len > script_len) {
            ret = WALLY_OK; /* Return required length without writing */
        } else {
            struct ext_key master;

            ret = bip32_key_from_base58_n(node->data, node->data_len, &master);
            if (ret == WALLY_OK && node->child_path_len) {
                size_t path_len;
                const uint32_t flags = BIP32_FLAG_STR_WILDCARD |
                                       BIP32_FLAG_STR_BARE |
                                       BIP32_FLAG_STR_MULTIPATH;
                const uint32_t derive_flags = BIP32_FLAG_SKIP_HASH |
                                              BIP32_FLAG_KEY_PUBLIC;
                const bool is_ranged = node->flags & WALLY_MS_IS_RANGED;
                const bool is_multi = node->flags & WALLY_MS_IS_MULTIPATH;
                struct ext_key derived;

                ret = bip32_path_from_str_n(node->child_path, node->child_path_len,
                                            is_ranged ? ctx->child_num : 0,
                                            is_multi ? ctx->multi_index : 0,
                                            flags, ctx->path_buff, ctx->max_path_elems,
                                            &path_len);
                if (ret == WALLY_OK)
                    ret = bip32_key_from_parent_path(&master, ctx->path_buff, path_len,
                                                     derive_flags, &derived);
                if (ret == WALLY_OK)
                    memcpy(&master, &derived, sizeof(master));
            }
            if (ret == WALLY_OK)
                memcpy(script, master.pub_key + ((node->flags & WALLY_MS_IS_X_ONLY) ? 1 : 0), output_len);
            wally_clear(&master, sizeof(master));
        }
    }
    if (ret == WALLY_OK) {
        ret = generate_inplace_wrappers(node, script, script_len, &output_len);
        if (ret == WALLY_OK)
            *written = output_len;
    }
    return ret;
}

static int analyze_address(ms_ctx *ctx, const char *str, size_t str_len,
                           ms_node *node)
{
    /* Generated script buffer, big enough for ADDRESS_PUBKEY_MAX_LEN too */
    unsigned char buff[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    unsigned char decoded[1 + HASH160_LEN + BASE58_CHECKSUM_LEN];
    size_t decoded_len, written;
    int ret;
    (void)ctx;

    ret = wally_base58_n_to_bytes(str, str_len, BASE58_FLAG_CHECKSUM,
                                  decoded, sizeof(decoded), &decoded_len);
    if (ret == WALLY_OK) {
        /* P2PKH/P2SH base58 address */
        bool is_p2sh;

        if (decoded_len != HASH160_LEN + 1)
            return WALLY_EINVAL; /* Unexpected address length */

        if (!addr_ver_from_version(decoded[0], ctx->addr_ver, &is_p2sh))
            return WALLY_EINVAL; /* Network not found */

        /* Create the scriptpubkey and copy it into the node */
        ret = (is_p2sh ? wally_scriptpubkey_p2sh_from_bytes : wally_scriptpubkey_p2pkh_from_bytes)(
            decoded + 1, HASH160_LEN, 0, buff, sizeof(buff), &written);
        if (ret == WALLY_OK) {
            if (written != (is_p2sh ? WALLY_SCRIPTPUBKEY_P2SH_LEN : WALLY_SCRIPTPUBKEY_P2PKH_LEN))
               ret = WALLY_ERROR; /* Should not happen! */
            else if (!clone_bytes((unsigned char **)&node->data, buff, written))
                ret = WALLY_ENOMEM;
            else {
                node->data_len = written;
                node->kind = KIND_BASE58;
            }
        }
    } else {
        /* Segwit bech32 address */
        char *hrp_end = memchr(str, '1', str_len);
        size_t hrp_len;

        if (!hrp_end)
            return WALLY_EINVAL; /* Address family missing */
        hrp_len = hrp_end - str;

        if (ctx->addr_ver &&
            !addr_ver_from_family(str, hrp_len, ctx->addr_ver->network))
            return WALLY_EINVAL; /* Unknown network or address family mismatch */

        ret = wally_addr_segwit_n_to_bytes(str, str_len, str, hrp_len, 0,
                                           buff, sizeof(buff), &written);
        if (ret == WALLY_OK) {
            if (written != HASH160_LEN + 2 && written != SHA256_LEN + 2)
                ret = WALLY_EINVAL; /* Unknown address format */
            else if (!clone_bytes((unsigned char **)&node->data, buff, written))
                ret = WALLY_ENOMEM;
            else {
                node->data_len = written;
                node->kind = KIND_BECH32;
            }
        }
    }
    return ret;
}

/* take the possible hex data in node->data, if it is a valid key then
 * convert it to an allocated binary buffer and make this node a key node
 */
static int analyze_key_hex(ms_ctx *ctx, ms_node *node,
                           uint32_t flags, bool is_ct_key, bool *is_hex)
{
    unsigned char key[EC_PUBLIC_KEY_UNCOMPRESSED_LEN], *key_p = key;
    size_t key_len;
    bool allow_xonly, make_xonly = false, is_private = false;

    *is_hex = wally_hex_n_to_bytes(node->data, node->data_len,
                                   key, sizeof(key), &key_len) == WALLY_OK;
    if (!*is_hex)
        return WALLY_OK; /* Not a hex string */

    if (key_len == EC_PRIVATE_KEY_LEN && is_ct_key) {
        if (wally_ec_private_key_verify(key, key_len) != WALLY_OK)
            return WALLY_OK; /* Not a valid private key */
        is_private = true;
    } else if (key_len == EC_XONLY_PUBLIC_KEY_LEN) {
        if (wally_ec_xonly_public_key_verify(key, key_len) != WALLY_OK)
            return WALLY_OK; /* Not a valid x-only key */
    } else if (key_len == EC_PUBLIC_KEY_LEN ||
               key_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN) {
        if (wally_ec_public_key_verify(key, key_len) != WALLY_OK)
            return WALLY_OK; /* Not a valid compressed/uncompressed pubkey */
    } else
        return WALLY_OK; /* Not a pubkey */

    if (!is_private) {
        /* Ensure the pubkey is allowed in this context/convert as needed */
        make_xonly = node->parent &&
            (node->parent->kind == KIND_DESCRIPTOR_RAW_TR ||
             node->parent->kind == KIND_DESCRIPTOR_TR);
        allow_xonly = make_xonly || flags & WALLY_MINISCRIPT_TAPSCRIPT;
        if (key_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN && allow_xonly)
            return WALLY_OK; /* Uncompressed key not allowed here */
        if (key_len == EC_XONLY_PUBLIC_KEY_LEN && !allow_xonly)
            return WALLY_OK; /* X-only not allowed here */
        if (key_len != EC_XONLY_PUBLIC_KEY_LEN) {
            if (flags & WALLY_MINISCRIPT_TAPSCRIPT)
                return WALLY_OK; /* Only X-only pubkeys allowed under tapscript */
            if (make_xonly) {
                /* Convert to x-only */
                --key_len;
                ++key_p;
            }
        }
    }

    if (!clone_bytes((unsigned char **)&node->data, key_p, key_len))
        return WALLY_ENOMEM;
    node->data_len = key_len;

    if (is_ct_key)
        ctx->features |= WALLY_MS_IS_ELIP150;
    if (is_private) {
        node->kind = KIND_PRIVATE_KEY;
        node->flags |= (WALLY_MS_IS_PRIVATE | WALLY_MS_IS_RAW);
        return WALLY_OK;
    }
    node->kind = KIND_PUBLIC_KEY;
    if (is_ct_key)
        return WALLY_OK;
    if (key_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN) {
        node->flags |= WALLY_MS_IS_UNCOMPRESSED;
        ctx->features |= WALLY_MS_IS_UNCOMPRESSED;
    }
    if (key_len == EC_XONLY_PUBLIC_KEY_LEN) {
        node->flags |= WALLY_MS_IS_X_ONLY;
        ctx->features |= WALLY_MS_IS_X_ONLY;
    }
    node->flags |= WALLY_MS_IS_RAW;
    ctx->features |= WALLY_MS_IS_RAW;
    return ctx_add_key_node(ctx, node);
}

static int analyze_miniscript_key(ms_ctx *ctx, uint32_t flags,
                                  ms_node *node, ms_node *parent)
{
    unsigned char privkey[2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN];
    struct ext_key extkey;
    size_t privkey_len = 0, size;
    int ret;
    bool is_hex;
#ifdef BUILD_ELEMENTS
    /* Whether we are the blinding key child of a ct() expression */
    const bool is_ct_key = parent && parent->kind == KIND_DESCRIPTOR_CT &&
        !parent->child; /* If no child, we are the first child */
#else
    const bool is_ct_key = false;
#endif

    if (!node || (parent && !parent->builtin))
        return WALLY_EINVAL;

    /*
     * key origin identification
     * https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#key-origin-identification
     */
    if (node->data[0] == '[') {
        const char *end = memchr(node->data, ']', node->data_len);
        uint32_t features;
        if (!end || end < node->data + 9 ||
            wally_hex_n_verify(node->data + 1, 8u) != WALLY_OK ||
            (node->data[9] != ']' && node->data[9] != '/'))
            return WALLY_EINVAL; /* Invalid key origin fingerprint */
        size = end - node->data + 1;
        /* Store offset and length of any origin info in the number field */
        node->number = (uint64_t)(node->data - ctx->src) << 32u;
        node->number |= size;
        ctx->features |= WALLY_MS_IS_PARENTED;
        node->flags |= WALLY_MS_IS_PARENTED;
        if (size > 10u) {
            if (size == 11u)
                return WALLY_EINVAL; /* Single leading '/' */
            /* The key origin has a path. It must be a valid bare path
             * without wildcards or multi-indices.
             */
            ret = bip32_path_str_n_get_features(node->data + 10, size - 11, &features);
            if (ret != WALLY_OK ||
                features & (BIP32_PATH_IS_WILDCARD | BIP32_PATH_IS_MULTIPATH) ||
                !(features & BIP32_PATH_IS_BARE))
                return WALLY_EINVAL;
        }
        /* Remove the key origin info from the key data */
        node->data = end + 1;
        node->data_len -= size;
    }

    /* Check for a hex public key (hex private keys allowed for ct() only) */
    ret = analyze_key_hex(ctx, node, flags, is_ct_key, &is_hex);
    if (ret == WALLY_OK && is_hex)
        return WALLY_OK;

    /* Check for a WIF private key (not allowed for ct() blinding keys) */
    if (!is_ct_key)
        ret = wally_base58_n_to_bytes(node->data, node->data_len, BASE58_FLAG_CHECKSUM,
                                      privkey, sizeof(privkey), &privkey_len);
    if (ret == WALLY_OK && privkey_len && privkey_len <= EC_PRIVATE_KEY_LEN + 2) {
        if (ctx->addr_ver && ctx->addr_ver->version_wif != privkey[0])
            return WALLY_EINVAL;
        if (privkey_len == EC_PRIVATE_KEY_LEN + 1) {
            if (flags & WALLY_MINISCRIPT_TAPSCRIPT)
                return WALLY_EINVAL; /* Tapscript only allows x-only keys */
            node->flags |= WALLY_MS_IS_UNCOMPRESSED;
            ctx->features |= WALLY_MS_IS_UNCOMPRESSED;
        } else if (privkey_len != EC_PRIVATE_KEY_LEN + 2 ||
                   privkey[EC_PRIVATE_KEY_LEN + 1] != 1)
            return WALLY_EINVAL; /* Unknown WIF format */

        node->flags |= (flags & WALLY_MINISCRIPT_TAPSCRIPT) ? WALLY_MS_IS_X_ONLY : 0;
        ret = wally_ec_private_key_verify(&privkey[1], EC_PRIVATE_KEY_LEN);
        if (ret == WALLY_OK && !clone_bytes((unsigned char **)&node->data, &privkey[1], EC_PRIVATE_KEY_LEN))
            ret = WALLY_EINVAL;
        else {
            node->data_len = EC_PRIVATE_KEY_LEN;
            node->kind = KIND_PRIVATE_KEY;
            ctx->features |= (WALLY_MS_IS_PRIVATE | WALLY_MS_IS_RAW);
            node->flags |= (WALLY_MS_IS_PRIVATE | WALLY_MS_IS_RAW);
            ret = ctx_add_key_node(ctx, node);
        }
        wally_clear(privkey, sizeof(privkey));
        return ret;
    }

    /* Check for a bip32 key */
    if ((node->child_path = memchr(node->data, '/', node->data_len))) {
        node->child_path_len = node->data_len - (node->child_path - node->data);
        node->data_len = node->child_path - node->data; /* Trim to bip32 key */
        if (node->child_path_len > 1) {
            uint32_t features, num_elems, num_multi, wildcard_pos;
            ++node->child_path; /* Skip leading '/' */
            --node->child_path_len;
            if (bip32_path_str_n_get_features(node->child_path,
                                              node->child_path_len,
                                              &features) != WALLY_OK)
                return WALLY_EINVAL; /* Invalid key path */
            if (!(features & BIP32_PATH_IS_BARE))
                return WALLY_EINVAL; /* Must be a bare path */
            num_elems = (features & BIP32_PATH_LEN_MASK) >> BIP32_PATH_LEN_SHIFT;
            /* TODO: Check length of key origin plus our length < 255 */
            num_multi = (features & BIP32_PATH_MULTI_MASK) >> BIP32_PATH_MULTI_SHIFT;
            if (is_ct_key &&
                (features & (BIP32_PATH_IS_WILDCARD | BIP32_PATH_IS_MULTIPATH))) {
                /* ct() blinding keys must resolve to a single key */
                return WALLY_EINVAL;
            }
            if (num_multi) {
                if (ctx->num_multipaths != 1 && ctx->num_multipaths != num_multi)
                    return WALLY_EINVAL; /* Different multi-path lengths */
                ctx->num_multipaths = num_multi;
                ctx->features |= WALLY_MS_IS_MULTIPATH;
                node->flags |= WALLY_MS_IS_MULTIPATH;
            }
            if (features & BIP32_PATH_IS_WILDCARD) {
                wildcard_pos = (features & BIP32_PATH_WILDCARD_MASK) >> BIP32_PATH_WILDCARD_SHIFT;
                if (wildcard_pos != num_elems - 1)
                    return WALLY_EINVAL; /* Must be the last element */
                ctx->features |= WALLY_MS_IS_RANGED;
                node->flags |= WALLY_MS_IS_RANGED;
            }
            if (num_elems > ctx->max_path_elems)
                ctx->max_path_elems = num_elems;
        } else {
            node->child_path = NULL; /* Empty path */
            node->child_path_len = 0;
        }
    }

    if ((ret = bip32_key_from_base58_n(node->data, node->data_len, &extkey)) != WALLY_OK)
        return ret;

    if (extkey.priv_key[0] == BIP32_FLAG_KEY_PRIVATE) {
        node->kind = KIND_BIP32_PRIVATE_KEY;
        node->flags |= WALLY_MS_IS_PRIVATE;
        if (!is_ct_key) {
            /* MS_IS_PRIVATE refers only to signing keys - not blinding keys */
            ctx->features |= WALLY_MS_IS_PRIVATE;
        }
    } else
        node->kind = KIND_BIP32_PUBLIC_KEY;

    if (ctx->addr_ver) {
        const bool main_key = extkey.version == BIP32_VER_MAIN_PUBLIC ||
                              extkey.version == BIP32_VER_MAIN_PRIVATE;
        const bool main_net = ctx->addr_ver->network == WALLY_NETWORK_BITCOIN_MAINNET ||
                              ctx->addr_ver->network == WALLY_NETWORK_LIQUID;
        if (main_key != main_net)
            ret = WALLY_EINVAL; /* Mismatched main/test network */
    }

    if (ret == WALLY_OK) {
        if (is_ct_key) {
            ctx->features |= WALLY_MS_IS_ELIP150;
        } else {
            if (flags & WALLY_MINISCRIPT_TAPSCRIPT) {
                node->flags |= WALLY_MS_IS_X_ONLY;
                ctx->features |= WALLY_MS_IS_X_ONLY;
            }
            ret = ctx_add_key_node(ctx, node);
        }
    }
    wally_clear(&extkey, sizeof(extkey));
    return ret;
}

static int analyze_miniscript_value(ms_ctx *ctx, const char *str, size_t str_len,
                                    uint32_t flags, ms_node *node, ms_node *parent)
{

    if (!node || (parent && !parent->builtin) || !str || !str_len)
        return WALLY_EINVAL;

    if (parent && parent->kind == KIND_DESCRIPTOR_ADDR)
        return analyze_address(ctx, str, str_len, node);

    if (parent) {
        const uint32_t kind = parent->kind;
        if (kind == KIND_DESCRIPTOR_RAW || kind == KIND_MINISCRIPT_SHA256 ||
            kind == KIND_MINISCRIPT_HASH256 || kind == KIND_MINISCRIPT_RIPEMD160 ||
            kind == KIND_MINISCRIPT_HASH160 || kind == KIND_DESCRIPTOR_SLIP77) {
            int ret;
            if (kind == KIND_DESCRIPTOR_SLIP77 && str_len != 64)
                ret = WALLY_EINVAL; /* slip77 blinding keys must be 32 bytes */
            else if ((ret = wally_hex_n_verify(str, str_len)) == WALLY_OK) {
                if (!(node->data = wally_malloc(str_len / 2)))
                    ret = WALLY_ENOMEM;
                else {
                    size_t written;
                    wally_hex_n_to_bytes(str, str_len,
                                         (unsigned char*)node->data, str_len / 2,
                                         &written);
                    node->data_len = written;
                    node->kind = KIND_RAW;
                    if (kind == KIND_DESCRIPTOR_SLIP77) {
                        ctx->features |= (WALLY_MS_IS_ELEMENTS | WALLY_MS_IS_SLIP77);
                    }
                }
            }
            return ret;
        }
    }

    node->data = str;
    node->data_len = str_len;

    if (strtoll_n(node->data, node->data_len, &node->number)) {
        node->type_properties = TYPE_B | PROP_Z | PROP_U | PROP_M | PROP_X;
        node->type_properties |= (node->number ? PROP_F : (PROP_D | PROP_E | PROP_S));
        node->kind = KIND_NUMBER;
        return WALLY_OK;
    }
    return analyze_miniscript_key(ctx, flags, node, parent);
}

static int analyze_miniscript(ms_ctx *ctx, const char *str, size_t str_len,
                              uint32_t kind, uint32_t flags, ms_node *prev_node,
                              ms_node *parent, ms_node **output)
{
    size_t i, offset = 0, child_offset = 0;
    uint32_t indent = 0;
    bool seen_indent = false, collect_child = false, copy_child = false;
    ms_node *node, *child = NULL, *prev_child = NULL;
    int ret = WALLY_OK;

    if (!(node = wally_calloc(sizeof(*node))))
        return WALLY_ENOMEM;

    node->parent = parent;

    for (i = 0; i < str_len; ++i) {
        if (!node->builtin && str[i] == ':') {
            if (i - offset > sizeof(node->wrapper_str) - 1) {
                ret = WALLY_EINVAL;
                break;
            }
            memcpy(node->wrapper_str, &str[offset], i - offset);
            offset = i + 1;
        } else if (str[i] == '(') {
            if (!node->builtin && indent == 0) {
                collect_child = true;
                if (!(node->builtin = builtin_lookup(str + offset, i - offset, kind))) {
                    ret = WALLY_EINVAL; /* Unknown built-in fragment */
                    break;
                }
                node->kind = builtin_get(node)->kind;
                if (node->wrapper_str[0] && !(node->kind & KIND_MINISCRIPT)) {
                    ret = WALLY_EINVAL; /* Wrapper on a descriptor built-in */
                    break;
                }
                if ((node->kind & KIND_MINISCRIPT) && !(node->kind & KIND_DESCRIPTOR)) {
                    /* Not a pure descriptor */
                    ctx->features &= ~WALLY_MS_IS_DESCRIPTOR;
                }
#ifdef BUILD_ELEMENTS
                if (builtin_is_elements(str + offset, i - offset)) {
                    ctx->features |= WALLY_MS_IS_ELEMENTS;
                }
#endif /* ifdef BUILD_ELEMENTS */
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
            if (i - offset != 0) {
                if (!node->builtin && node->wrapper_str[0] &&
                    i - offset == strlen(node->wrapper_str)) {
                    /* wrapper:value followed by checksum */
                    str_len -= (DESCRIPTOR_CHECKSUM_LENGTH + 1);
                    break;
                }
                ret = WALLY_EINVAL; /* Garbage before checksum */
                break;
            }
            if (!parent && node->builtin && !collect_child && indent == 0) {
                break;  /* end */
            }
        }

        if (copy_child) {
            if (i - child_offset &&
                (ret = analyze_miniscript(ctx, str + child_offset, i - child_offset,
                                          kind, flags, prev_child,
                                          node, &child)) != WALLY_OK)
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

    if (ret == WALLY_OK && !seen_indent) {
        /* A constant value. Parse it ignoring any already added wrappers */
        offset = node->wrapper_str[0] ? strlen(node->wrapper_str) + 1 : 0;
        ret = analyze_miniscript_value(ctx, str + offset, str_len - offset,
                                       flags, node, parent);
    }

    if (ret == WALLY_OK && node->builtin) {
        const uint32_t expected_children = builtin_get(node)->child_count;
        if (expected_children != 0xffffffff && node_get_child_count(node) != expected_children)
            ret = WALLY_EINVAL; /* Too many or too few children */
        else
            ret = builtin_get(node)->verify_fn(ctx, node);
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

/* Compute the maximum size of the buffer we need to generate a script.
 * Although our final script may be small, we need a larger scratch
 * buffer to generate its sub-components to assemble the final script.
 * For example, we may need to generate a sub-script then hash it to
 * produce a top level p2pkh/p2sh etc. Note that the exact size of a
 * script cannot be known up-front without generating it; the 'v' wrapper
 * for example modifies or appends depending on its sub-scripts final
 * opcode, which isn't known until its generated.
 * This can result in over-estimating the size required substantially in
 * some cases, in order to be safe without requiring a huge up-front
 * allocation. The alternative is repeated sub-allocations as we generate,
 * which is undesirable as its slow, and leads to memory fragmentation.
 */
static int node_generation_size(const ms_node *node, size_t *total)
{
    const struct ms_builtin_t *builtin = builtin_get(node);
    const ms_node *child;
    size_t i;
    int ret = WALLY_OK;

    if (builtin) {
        /* TODO: we could collect this into a subtotal and use
         *       max(subtotal, final) to minimise the allocation size
         *       slightly, e.g. for sh-wrapped scripts.
         */
        for (child = node->child; ret == WALLY_OK && child; child = child->next)
            ret = node_generation_size(child, total);
        if (ret != WALLY_OK)
            return ret;

        switch (builtin->kind) {
        case KIND_DESCRIPTOR_PK | KIND_MINISCRIPT_PK:
            *total += 2;
            break;
        case KIND_DESCRIPTOR_PKH | KIND_MINISCRIPT_PKH:
            *total += WALLY_SCRIPTPUBKEY_P2PKH_LEN;
            break;
        case KIND_DESCRIPTOR_MULTI | KIND_MINISCRIPT_MULTI:
        case KIND_DESCRIPTOR_MULTI_S:
            *total += CHECKMULTISIG_NUM_KEYS_MAX * EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
            *total += 5; /* worst case OP_PUSHDATA1 <N> * 2 + OP_CHECKMULTISIG */
            break;
        case KIND_DESCRIPTOR_SH:
            *total += WALLY_SCRIPTPUBKEY_P2SH_LEN;
            break;
        case KIND_DESCRIPTOR_WSH:
            *total += WALLY_SCRIPTPUBKEY_P2WSH_LEN;
            break;
        case KIND_DESCRIPTOR_WPKH:
            *total += WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
            break;
        case KIND_DESCRIPTOR_COMBO:
            /* max of p2pk, p2pkh, p2wpkh, or p2sh-p2wpkh */
            *total += WALLY_SCRIPTPUBKEY_P2PKH_LEN;
            break;
        case KIND_DESCRIPTOR_RAW:
            /* Add an extra byte to handle 'raw()' which results in nothing,
             * as empty output buffers cannot be passed to descriptor calls.
             */
            *total += 1;
        case KIND_DESCRIPTOR_ADDR:
            /* No-op */
            break;
        case KIND_DESCRIPTOR_RAW_TR:
        case KIND_DESCRIPTOR_TR:
            *total += WALLY_SCRIPTPUBKEY_P2TR_LEN;
            break;
        case KIND_MINISCRIPT_PK_K:
            *total += 1;
            break;
        case KIND_MINISCRIPT_PK_H:
            *total += WALLY_SCRIPTPUBKEY_P2PKH_LEN - 1;
            break;
        case KIND_MINISCRIPT_OLDER:
        case KIND_MINISCRIPT_AFTER:
            *total += 1;
            break;
        case KIND_MINISCRIPT_SHA256:
        case KIND_MINISCRIPT_HASH256:
        case KIND_MINISCRIPT_RIPEMD160:
        case KIND_MINISCRIPT_HASH160:
            *total += 7;
            break;
        case KIND_MINISCRIPT_THRESH:
            *total += node_get_child_count(node) - 1 + 1;
            break;
        case KIND_MINISCRIPT_AND_B:
        case KIND_MINISCRIPT_OR_B:
            *total += 1;
            break;
        case KIND_MINISCRIPT_OR_C:
            *total += 2;
            break;
        case KIND_MINISCRIPT_OR_D:
        case KIND_MINISCRIPT_OR_I:
            *total += 3;
            break;
        case KIND_MINISCRIPT_AND_N:
        case KIND_MINISCRIPT_ANDOR:
            *total += 4;
            break;
        case KIND_MINISCRIPT_AND_V:
            /* no-op */
            break;
#ifdef BUILD_ELEMENTS
        case KIND_DESCRIPTOR_CT:
        case KIND_DESCRIPTOR_SLIP77:
        case KIND_DESCRIPTOR_ELIP151:
            /* Confidential blinding nodes don't change the script */
            break;
#endif
        default:
            return WALLY_ERROR; /* Should not happen! */
        }
    } else if (node->kind == KIND_NUMBER) {
        if (node->number >= -1 && node->number <= 16)
            *total += 1;
        else
            *total += 1 + scriptint_get_length(node->number);
    } else if (node->kind & (KIND_RAW | KIND_ADDRESS) || node->kind == KIND_PUBLIC_KEY) {
        *total += node->data_len;
    } else if (node->kind == KIND_PRIVATE_KEY || (node->kind & KIND_BIP32) == KIND_BIP32) {
        if (node->flags & WALLY_MS_IS_UNCOMPRESSED)
            *total += EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
        else if (node->flags & WALLY_MS_IS_X_ONLY)
            *total += EC_XONLY_PUBLIC_KEY_LEN;
        else
            *total += EC_PUBLIC_KEY_LEN;
    } else
        return WALLY_ERROR; /* Should not happen */

    for (i = 0; i < strlen(node->wrapper_str); ++i) {
        switch(node->wrapper_str[i]) {
        case 's': case 'c': case 't': case 'n': case 'v':
            *total += 1; /* max: 'v' can can be 0 or 1 */
            break;
        case 'a':
            *total += 2;
            break;
        case 'd':
            *total += 3;
            break;
        case 'j': case 'l': case 'u':
            *total += 4;
            break;
        }
    }
    return WALLY_OK;
}

static int node_generate_script(ms_ctx *ctx, uint32_t depth, uint32_t index,
                                unsigned char *bytes_out, size_t len,
                                size_t *written)
{
    ms_node *node = ctx->top_node, *parent;
    size_t i;
    int ret;

    *written = 0;

#ifdef BUILD_ELEMENTS
    if (node->kind == KIND_DESCRIPTOR_CT) {
        /* Generate using the actual descriptor as the root */
        node = node->child->next;
    }
#endif

    for (i = 0; i < depth; ++i) {
        if (!node->child)
            return WALLY_EINVAL;
        node = node->child;
    }
    for (i = 0; i < index; ++i) {
        if (!node->next)
            return WALLY_EINVAL;
        node = node->next;
    }

    parent = node->parent;
    node->parent = NULL;
    ret = generate_script(ctx, node, bytes_out, len, written);
    node->parent = parent;
    return ret;
}

static uint32_t get_max_depth(const char *miniscript, size_t miniscript_len)
{
    size_t i;
    uint32_t depth = 1, max_depth = 1;

    for (i = 0; i < miniscript_len; ++i) {
        if (miniscript[i] == '(' && ++depth > max_depth)
            max_depth = depth;
        else if (miniscript[i] == ')' && depth-- == 1)
            return 0xffffffff; /* Mismatched */
    }
    return depth == 1 ? max_depth : 0xffffffff;
}

static bool is_valid_policy_map(const struct wally_map *map_in)
{
    struct wally_map keys;
    ms_ctx ctx;
    ms_node* node;
    int64_t v;
    size_t i;
    int ret = WALLY_OK;

    if (!map_in || !map_in->num_items)
        return WALLY_EINVAL; /* Must contain at least one key expression */

    memset(&ctx, 0, sizeof(ctx));
    ret = wally_map_init(map_in->num_items, NULL, &keys);

    for (i = 0; ret == WALLY_OK && i < map_in->num_items; ++i) {
        const struct wally_map_item *item = &map_in->items[i];
        if (!item->key || item->key_len < 2 || item->key[0] != '@' ||
            !strtoll_n((const char *)item->key + 1, item->key_len - 1, &v) || v < 0)
            ret = WALLY_EINVAL; /* Policy keys can only be @n */
        else if ((size_t)v != i)
            ret = WALLY_EINVAL; /* Must be sorted in order from 0-n */
        else if (!item->value || !item->value_len)
            ret = WALLY_EINVAL; /* No key value */
        else if (!(node = wally_calloc(sizeof(*node))))
            ret = WALLY_EINVAL;
        else {
            node->data = (const char*)item->value;
            node->data_len = item->value_len;
            if (analyze_miniscript_key(&ctx, 0, node, NULL) != WALLY_OK ||
                node->kind != KIND_BIP32_PUBLIC_KEY ||
                node->child_path_len) {
                ret = WALLY_EINVAL; /* Only BIP32 xpubs are allowed */
            } else if (ctx.features & (WALLY_MS_IS_MULTIPATH | WALLY_MS_IS_RANGED)) {
                /* Range or multipath must be part of the expression, not the key */
                ret = WALLY_EINVAL;
            } else {
                ret = wally_map_add(&keys, item->value, item->value_len, NULL, 0);
            }
            node_free(node);
        }
    }
    if (ret == WALLY_OK && keys.num_items != map_in->num_items)
        ret = WALLY_EINVAL; /* One of more keys is not unique */
    clear_and_free(ctx.keys.items,
                   ctx.keys.num_items * sizeof(*ctx.keys.items));
    wally_map_clear(&keys);
    return ret == WALLY_OK;
}

int wally_descriptor_parse(const char *miniscript,
                           const struct wally_map *vars_in,
                           uint32_t network, uint32_t flags,
                           ms_ctx **output)
{
    const struct addr_ver_t *addr_ver = addr_ver_from_network(network);
    size_t num_substitutions;
    uint32_t kind = KIND_MINISCRIPT | (flags & WALLY_MINISCRIPT_ONLY ? 0 : KIND_DESCRIPTOR);
    uint32_t max_depth = flags >> WALLY_MINISCRIPT_DEPTH_SHIFT;
    ms_ctx *ctx;
    int ret;

    *output = NULL;
    flags &= ~WALLY_MINISCRIPT_DEPTH_MASK;

    if (!miniscript || flags & ~MS_FLAGS_ALL ||
        (network != WALLY_NETWORK_NONE && !addr_ver))
        return WALLY_EINVAL;

#ifndef BUILD_ELEMENTS
    if (flags & WALLY_MINISCRIPT_AS_ELEMENTS) {
        return WALLY_EINVAL;
    }
#endif
    /* Allocate a context to hold the canonicalized/parsed expression */
    if (!(*output = wally_calloc(sizeof(ms_ctx))))
        return WALLY_ENOMEM;
    ctx = *output;
    ctx->addr_ver = addr_ver;
    ctx->num_variants = 1;
    ctx->num_multipaths = 1;
    ret = wally_map_init(vars_in ? vars_in->num_items : 1, NULL, &ctx->keys);
    if (ret == WALLY_OK)
        ret = canonicalize_impl(miniscript, vars_in, flags & MS_FLAGS_CANONICALIZE,
                                &ctx->src, &num_substitutions);
    if (ret == WALLY_OK) {
        ctx->src_len = strlen(ctx->src);
        ctx->features = WALLY_MS_IS_DESCRIPTOR; /* Un-set if miniscript found */
        if (flags & WALLY_MINISCRIPT_AS_ELEMENTS) {
            ctx->features |= WALLY_MS_IS_ELEMENTS; /* Treat as an elements descriptor */
        }

        if (max_depth && get_max_depth(ctx->src, ctx->src_len) > max_depth)
            ret = WALLY_EINVAL;
        else
            ret = analyze_miniscript(ctx, ctx->src, ctx->src_len, kind,
                                     flags, NULL, NULL, &ctx->top_node);
        if (ret == WALLY_OK)
            ret = node_generation_size(ctx->top_node, &ctx->script_len);
        if (ret == WALLY_OK && (flags & WALLY_MINISCRIPT_POLICY_TEMPLATE)) {
            if (ctx->keys.num_items != num_substitutions)
                ret = WALLY_EINVAL; /* non-substituted key in the expression */
            else if (vars_in && ctx->keys.num_items < vars_in->num_items)
                ret = WALLY_EINVAL; /* non-substituted key in substitutions */
            else if (ctx->num_variants > 1 || ctx->num_multipaths > 2)
                ret = WALLY_EINVAL; /* Solved cardinality must be 1 or 2 */
            else if (flags & WALLY_MINISCRIPT_UNIQUE_KEYPATHS)
                ret = ensure_unique_policy_keys(ctx);
        }
    }
    if (ret != WALLY_OK) {
        wally_descriptor_free(ctx);
        *output = NULL;
    }
    return ret;
}

int wally_descriptor_to_script(const struct wally_descriptor *descriptor,
                               uint32_t depth, uint32_t index,
                               uint32_t variant, uint32_t multi_index,
                               uint32_t child_num, uint32_t flags,
                               unsigned char *bytes_out, size_t len, size_t *written)
{
    ms_ctx ctx;
    int ret;

    if (written)
        *written = 0;

    if (!descriptor || variant >= descriptor->num_variants ||
        child_num >= BIP32_INITIAL_HARDENED_CHILD ||
        (child_num && !(descriptor->features & WALLY_MS_IS_RANGED)) ||
        multi_index >= descriptor->num_multipaths ||
        (flags & WALLY_MINISCRIPT_ONLY) || !bytes_out || !len || !written)
        return WALLY_EINVAL;

    memcpy(&ctx, descriptor, sizeof(ctx));
    ctx.variant = variant;
    ctx.child_num = child_num;
    ctx.multi_index = multi_index;
    if (ctx.max_path_elems &&
        !(ctx.path_buff = wally_malloc(ctx.max_path_elems * sizeof(uint32_t))))
        return WALLY_ENOMEM;
    ret = node_generate_script(&ctx, depth, index, bytes_out, len, written);
    wally_free(ctx.path_buff);
    return ret;
}

int wally_descriptor_to_script_get_maximum_length(
    const struct wally_descriptor *descriptor,
    uint32_t depth, uint32_t index, uint32_t variant, uint32_t multi_index,
    uint32_t child_num, uint32_t flags, size_t *written)
{
    (void)depth;
    (void)index;
    (void)variant;
    (void)multi_index;
    (void)child_num;
    if (written)
        *written = 0;
    if (!descriptor || (flags & ~MS_FLAGS_ALL) || !written)
        return WALLY_EINVAL;
#ifndef BUILD_ELEMENTS
    if (flags & WALLY_MINISCRIPT_AS_ELEMENTS) {
        return WALLY_EINVAL;
    }
#endif
    *written = descriptor->script_len;
    return WALLY_OK;
}

static int descriptor_get_addr(struct wally_descriptor *descriptor,
                               const unsigned char* script, size_t script_len,
                               char **output)
{
    const struct addr_ver_t *addr_ver = descriptor->addr_ver;
    char *address = NULL;
    bool is_segwit = false;
    int ret = wally_scriptpubkey_to_address(script, script_len,
                                            addr_ver->network, &address);
    if (ret == WALLY_EINVAL) {
        /* Try a segwit address */
        ret = wally_addr_segwit_from_bytes(script, script_len,
                                           addr_ver->bech32, 0, &address);
        is_segwit = true;
    }
    if (ret != WALLY_OK)
        return ret;

#ifndef BUILD_ELEMENTS
    (void)is_segwit;
#else
    if (descriptor->features & WALLY_MS_IS_ELEMENTS) {
        /* Elements: compute the blinding key and blind the address */
        unsigned char pubkey[EC_PUBLIC_KEY_LEN];
        const ms_node *blinding_node = descriptor->top_node->child->child;
        if (descriptor->features & WALLY_MS_IS_SLIP77) {
            /* SLIP77 blinding key */
            const unsigned char* seed;
            seed = (const unsigned char*)blinding_node->data;
            ret = wally_asset_blinding_key_to_ec_public_key(seed, 32,
                                                            script, script_len,
                                                            pubkey, sizeof(pubkey));
        } else if (descriptor->features & WALLY_MS_IS_ELIP150) {
            /* ELIP-150 blinding key */
            size_t written;
            ret = generate_script(descriptor, descriptor->top_node->child,
                                  pubkey, sizeof(pubkey), &written);
            if (ret == WALLY_OK && written != sizeof(pubkey))
                ret = WALLY_ERROR; /* Unsupported pubkey - should not happen! */
            if (ret == WALLY_OK)
                ret = wally_elip150_public_key_to_ec_public_key(pubkey, sizeof(pubkey),
                                                                script, script_len,
                                                                pubkey, sizeof(pubkey));
        } else
            ret = WALLY_ERROR; /* FIXME: Support ELIP 151 */

        if (ret == WALLY_OK) {
            char *conf_addr = NULL;
            if (is_segwit)
                ret = wally_confidential_addr_from_addr_segwit(address,
                                                               addr_ver->bech32,
                                                               addr_ver->blech32,
                                                               pubkey, sizeof(pubkey),
                                                               &conf_addr);
            else
                ret = wally_confidential_addr_from_addr(address,
                                                        addr_ver->elements_prefix,
                                                        pubkey, sizeof(pubkey),
                                                        &conf_addr);
            wally_free_string(address);
            address = conf_addr;
            wally_clear(pubkey, sizeof(pubkey));
        }
    }
#endif /* BUILD_ELEMENTS */
    *output = address;
    return ret;
}

int wally_descriptor_to_addresses(const struct wally_descriptor *descriptor,
                                  uint32_t variant, uint32_t multi_index,
                                  uint32_t child_num, uint32_t flags,
                                  char **addresses, size_t num_addresses)
{
    ms_ctx ctx;
    unsigned char *p;
    size_t i, written;
    int ret = WALLY_OK;

    if (!descriptor || !descriptor->addr_ver || !descriptor->script_len ||
        variant >= descriptor->num_variants ||
         child_num >= BIP32_INITIAL_HARDENED_CHILD ||
        (uint64_t)child_num + num_addresses >= BIP32_INITIAL_HARDENED_CHILD ||
        (child_num && !(descriptor->features & WALLY_MS_IS_RANGED)) ||
        multi_index >= descriptor->num_multipaths ||
        flags || !addresses || !num_addresses)
        return WALLY_EINVAL;

    wally_clear(addresses, num_addresses * sizeof(*addresses));
    if (!(p = wally_malloc(descriptor->script_len)))
        return WALLY_ENOMEM;

#ifdef BUILD_ELEMENTS
    if (descriptor->features & WALLY_MS_IS_ELEMENTS &&
       !(descriptor->features & WALLY_MS_ANY_BLINDING_KEY)) {
        // Elements requires a blinding key to generate addresses
        return WALLY_ERROR;
    }
#endif

    memcpy(&ctx, descriptor, sizeof(ctx));
    ctx.variant = variant;
    if (ctx.max_path_elems &&
        !(ctx.path_buff = wally_malloc(ctx.max_path_elems * sizeof(uint32_t))))
        return WALLY_ENOMEM;

    for (i = 0; ret == WALLY_OK && i < num_addresses; ++i) {
        ctx.child_num = child_num + i;
        ctx.multi_index = multi_index;
        ret = node_generate_script(&ctx, 0, 0, p, ctx.script_len, &written);
        if (ret == WALLY_OK) {
            if (written > ctx.script_len)
                ret = WALLY_ERROR; /* Not enough room - should not happen! */
            else {
                /* Generate the address corresponding to this script */
                ret = descriptor_get_addr(&ctx, p, written, &addresses[i]);
            }
        }
    }

    if (ret != WALLY_OK) {
        /* Free any partial results */
        for (i = 0; i < num_addresses; ++i) {
            wally_free_string(addresses[i]);
            addresses[i] = NULL;
        }
    }
    wally_free(ctx.path_buff);
    wally_free(p);
    return ret;
}

int wally_descriptor_to_address(const struct wally_descriptor *descriptor,
                                uint32_t variant, uint32_t multi_index,
                                uint32_t child_num, uint32_t flags,
                                char **output)
{
    return wally_descriptor_to_addresses(descriptor, variant, multi_index,
                                         child_num, flags, output, 1);
}

int wally_descriptor_get_checksum(const struct wally_descriptor *descriptor,
                                  uint32_t flags, char **output)
{
    size_t start_offset;
    if (output)
        *output = NULL;

    if (!descriptor || flags || !output)
        return WALLY_EINVAL;

    start_offset = descriptor->src_len - DESCRIPTOR_CHECKSUM_LENGTH;
    if (!(*output = wally_strdup_n(descriptor->src + start_offset, DESCRIPTOR_CHECKSUM_LENGTH)))
        return WALLY_ENOMEM;
    return WALLY_OK;
}

int wally_descriptor_canonicalize(const struct wally_descriptor *descriptor,
                                  uint32_t flags, char **output)
{
    size_t copy_len;

    if (output)
        *output = NULL;

    if (!descriptor || !descriptor->src ||
        descriptor->src_len < DESCRIPTOR_CHECKSUM_LENGTH + 1 ||
        (flags & ~WALLY_MS_CANONICAL_NO_CHECKSUM) || !output)
        return WALLY_EINVAL;

    copy_len = descriptor->src_len;
    if (flags & WALLY_MS_CANONICAL_NO_CHECKSUM)
        copy_len -= (DESCRIPTOR_CHECKSUM_LENGTH + 1);
    if (!(*output = wally_strdup_n(descriptor->src, copy_len)))
        return WALLY_ENOMEM;
    return WALLY_OK;
}

int wally_descriptor_get_network(const struct wally_descriptor *descriptor,
                                 uint32_t *value_out)
{
    if (value_out)
        *value_out = 0;
    if (!descriptor || !value_out)
        return WALLY_EINVAL;
    *value_out = descriptor->addr_ver ? descriptor->addr_ver->network : WALLY_NETWORK_NONE;
    return WALLY_OK;
}

int wally_descriptor_set_network(struct wally_descriptor *descriptor,
                                 uint32_t network)
{
     /* Allow setting a non-NONE network only if there isn't one already */
    if (!descriptor || network == WALLY_NETWORK_NONE)
        return WALLY_EINVAL;
    if (descriptor->addr_ver && descriptor->addr_ver->network == network)
        return WALLY_OK; /* No-op */
    if (descriptor->addr_ver)
        return WALLY_EINVAL; /* Already have a network */
    descriptor->addr_ver = addr_ver_from_network(network);
    return descriptor->addr_ver ? WALLY_OK : WALLY_EINVAL;
}

static int descriptor_uint32(const void *descriptor,
                             uint32_t *value_out, size_t offset)
{
    if (value_out)
        *value_out = 0;
    if (!descriptor || !value_out)
        return WALLY_EINVAL;
    memcpy(value_out, (char*)descriptor + offset, sizeof(uint32_t));
    return WALLY_OK;
}

int wally_descriptor_get_features(const struct wally_descriptor *descriptor,
                                  uint32_t *value_out)
{
    return descriptor_uint32(descriptor, value_out,
                             offsetof(struct wally_descriptor, features));
}

int wally_descriptor_get_num_variants(const struct wally_descriptor *descriptor,
                                      uint32_t *value_out)
{
    return descriptor_uint32(descriptor, value_out,
                             offsetof(struct wally_descriptor, num_variants));
}

int wally_descriptor_get_num_paths(const struct wally_descriptor *descriptor,
                                   uint32_t *value_out)
{
    return descriptor_uint32(descriptor, value_out,
                             offsetof(struct wally_descriptor, num_multipaths));
}

static uint32_t node_get_depth(const ms_node *node)
{
    uint32_t max_child_depth = 0;
    while (node) {
        uint32_t child_depth = node_get_depth(node->child);
        if (child_depth > max_child_depth)
            max_child_depth = child_depth;
        node = node->next;
    }
    return 1 + max_child_depth;
}

int wally_descriptor_get_depth(const struct wally_descriptor *descriptor,
                               uint32_t *value_out)
{
    if (value_out)
        *value_out = 0;
    if (!descriptor || !value_out)
        return WALLY_EINVAL;
    *value_out = node_get_depth(descriptor->top_node) - 1;
    return WALLY_OK;
}

int wally_descriptor_get_num_keys(const struct wally_descriptor *descriptor,
                                  uint32_t *value_out)
{
    if (value_out)
        *value_out = 0;
    if (!descriptor || !value_out)
        return WALLY_EINVAL;
    *value_out = (uint32_t)descriptor->keys.num_items;
    return WALLY_OK;
}

/* Ignore incorrect warnings from the ms_node cast below */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wcast-align"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wcast-align"
#endif
static const ms_node *descriptor_get_key(const struct wally_descriptor *descriptor,
                                         size_t index)
{
    if (!descriptor || index >= descriptor->keys.num_items)
        return NULL;
    return (ms_node *)descriptor->keys.items[index].value;
}

int wally_descriptor_get_key(const struct wally_descriptor *descriptor,
                             size_t index, char **output)
{
    const ms_node *node = NULL;
#ifdef BUILD_ELEMENTS
    if (index == WALLY_MS_BLINDING_KEY_INDEX) {
        if (descriptor && node_is_ct(descriptor->top_node)) {
            node = descriptor->top_node->child;
            if (node && node->kind == KIND_DESCRIPTOR_SLIP77)
                node = node->child;
        }
    } else
#endif
        node = descriptor_get_key(descriptor, index);

    if (output)
        *output = 0;
    if (!node || !output)
        return WALLY_EINVAL;

#ifdef BUILD_ELEMENTS
    if (index == WALLY_MS_BLINDING_KEY_INDEX) {
        if (node->kind == KIND_PRIVATE_KEY || node->kind == KIND_RAW)
            goto return_hex;
    }
#endif
    if (node->kind == KIND_PUBLIC_KEY) {
#ifdef BUILD_ELEMENTS
return_hex:
#endif
        return wally_hex_from_bytes((const unsigned char *)node->data,
                                    node->data_len, output);
    }
    if (node->kind == KIND_PRIVATE_KEY) {
        uint32_t flags = node->flags & WALLY_MS_IS_UNCOMPRESSED ? WALLY_WIF_FLAG_UNCOMPRESSED : 0;
        if (!descriptor->addr_ver)
            return WALLY_EINVAL; /* Must have a network to fetch private keys */
        return wally_wif_from_bytes((const unsigned char *)node->data, node->data_len,
                                    descriptor->addr_ver->version_wif,
                                    flags, output);
    }
    if ((node->kind & KIND_BIP32) != KIND_BIP32)
        return WALLY_ERROR; /* Unknown key type, should not happen */
    if (!(*output = wally_strdup_n(node->data, node->data_len)))
        return WALLY_ENOMEM;
    return WALLY_OK;
}

int wally_descriptor_get_key_features(const struct wally_descriptor *descriptor,
                                      size_t index, uint32_t *value_out)
{
    const ms_node *node = NULL;
#ifdef BUILD_ELEMENTS
    if (index == WALLY_MS_BLINDING_KEY_INDEX) {
        if (descriptor && node_is_ct(descriptor->top_node)) {
            node = descriptor->top_node->child;
            if (node && node->kind == KIND_DESCRIPTOR_SLIP77)
                node = node->child;
        }
    } else
#endif
        node = descriptor_get_key(descriptor, index);

    if (value_out)
        *value_out = 0;
    if (!node || !value_out)
        return WALLY_EINVAL;
    *value_out = node->flags;
    return WALLY_OK;
}

int wally_descriptor_get_key_child_path_str_len(
    const struct wally_descriptor *descriptor, size_t index, size_t *written)
{
    const ms_node *node = descriptor_get_key(descriptor, index);

    if (written)
        *written = 0;
    if (!node || !written)
        return WALLY_EINVAL;
    *written = node->child_path_len;
    return WALLY_OK;
}

int wally_descriptor_get_key_child_path_str(
    const struct wally_descriptor *descriptor, size_t index, char **output)
{
    const ms_node *node = descriptor_get_key(descriptor, index);

    if (output)
        *output = 0;
    if (!node || !output)
        return WALLY_EINVAL;
    if (!(*output = wally_strdup_n(node->child_path, node->child_path_len)))
        return WALLY_ENOMEM;
    return WALLY_OK;
}

int wally_descriptor_get_key_origin_fingerprint(
    const struct wally_descriptor *descriptor, size_t index,
    unsigned char *bytes_out, size_t len)
{
    const ms_node *node = descriptor_get_key(descriptor, index);
    const char *fingerprint;
    size_t written;
    int ret;

    if (!node || !bytes_out || len != BIP32_KEY_FINGERPRINT_LEN ||
        !(node->flags & WALLY_MS_IS_PARENTED))
        return WALLY_EINVAL;
    fingerprint = descriptor->src + (((uint64_t)node->number) >> 32u) + 1;
    ret = wally_hex_n_to_bytes(fingerprint, BIP32_KEY_FINGERPRINT_LEN * 2,
                               bytes_out, len, &written);
    return ret == WALLY_OK && written != BIP32_KEY_FINGERPRINT_LEN ? WALLY_EINVAL : ret;
}

int wally_descriptor_get_key_origin_path_str_len(
    const struct wally_descriptor *descriptor, size_t index, size_t *written)
{
    const ms_node *node = descriptor_get_key(descriptor, index);

    if (written)
        *written = 0;
    if (!node || !written)
        return WALLY_EINVAL;
    *written = node->flags & WALLY_MS_IS_PARENTED ? node->number & 0xffffffff : 0;
    *written = *written < 11u ? 0 : *written - 11u;
    return WALLY_OK;
}

int wally_descriptor_get_key_origin_path_str(
    const struct wally_descriptor *descriptor, size_t index, char **output)
{
    const ms_node *node = descriptor_get_key(descriptor, index);
    const char *path;
    size_t path_len;

    if (output)
        *output = NULL;
    if (!node || !output)
        return WALLY_EINVAL;
    path_len = node->flags & WALLY_MS_IS_PARENTED ? node->number & 0xffffffff : 0;
    path_len = path_len < 11u ? 0 : path_len - 11u;
    path = descriptor->src + (((uint64_t)node->number) >> 32u) + 10u;
    if (!(*output = wally_strdup_n(path, path_len)))
        return WALLY_ENOMEM;
    return WALLY_OK;
}

static const char *get_multipath_child(const char* p, uint32_t *v)
{
    *v = 0;
    if (*p != '<' && *p != ';')
        return NULL;
    else {
        ++p;
        while (*p >= '0' && *p <= '9') {
            *v *= 10;
            *v += (*p++ - '0');
        }
        if (*p == '\'' || *p == 'h' || *p == 'H') {
            *v |= BIP32_INITIAL_HARDENED_CHILD;
            ++p;
        }
    }
    return p;
}

static int are_keys_overlapped(const ms_ctx *ctx,
                               const ms_node *lhs, const ms_node *rhs)
{
    const char *p;
    uint32_t l1, l2, r1, r2;

    if (lhs->data_len != rhs->data_len ||
        memcmp(lhs->data, rhs->data, lhs->data_len))
        return WALLY_OK; /* Different root keys */
    if (lhs->child_path_len == rhs->child_path_len &&
        !memcmp(lhs->child_path, rhs->child_path, lhs->child_path_len))
        return WALLY_EINVAL; /* Identical paths */
    if (!(lhs->flags & WALLY_MS_IS_MULTIPATH))
        return WALLY_OK; /* Non-identical ranged, non-multipath keys */
    if (ctx->max_path_elems != 2 || !(rhs->flags & WALLY_MS_IS_MULTIPATH))
        return WALLY_ERROR; /* Should never happen! */
    /* Check the set of multi-path indices is disjoint */
    if (!(p = get_multipath_child(strchr(lhs->child_path, '<'), &l1)) ||
        !get_multipath_child(p, &l2) ||
        !(p = get_multipath_child(strchr(rhs->child_path, '<'), &r1)) ||
        !get_multipath_child(p, &r2))
        return WALLY_ERROR; /* Should never happen! */
    if (l1 == r1 || l1 == r2 || l2 == r1 || l2 == r2)
        return WALLY_EINVAL; /* indices are not disjoint */
    return WALLY_OK;
}

static int ensure_unique_policy_keys(const ms_ctx *ctx)
{
    size_t i, j;

    for (i = 0; i < ctx->keys.num_items; ++i) {
        const ms_node *node = descriptor_get_key(ctx, i);
        for (j = i + 1; j < ctx->keys.num_items; ++j) {
            int ret = are_keys_overlapped(ctx, node, descriptor_get_key(ctx, j));
            if (ret != WALLY_OK)
                return ret;
        }
    }
    return WALLY_OK;
}
