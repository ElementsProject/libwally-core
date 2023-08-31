#include "internal.h"

#include "script.h"
#include "script_int.h"

#include <include/wally_address.h>
#include <include/wally_bip32.h>
#include <include/wally_crypto.h>
#include <include/wally_descriptor.h>
#include <include/wally_map.h>
#include <include/wally_script.h>

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#define NUM_ELEMS(a) (sizeof(a) / sizeof(a[0]))
#define MS_FLAGS_ALL (WALLY_MINISCRIPT_TAPSCRIPT | \
        WALLY_MINISCRIPT_ONLY | \
        WALLY_MINISCRIPT_REQUIRE_CHECKSUM)

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

#define NF_IS_UNCOMPRESSED 0x01
#define NF_IS_XONLY        0x02
#define NF_IS_RANGED       0x04
#define NF_IS_MULTI        0x08

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
    unsigned char flags; /* NF_ flags */
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
} ms_ctx;

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
    if (!addr_ver || !family || strlen(addr_ver->family) != family_len ||
        memcmp(family, addr_ver->family, family_len))
        return NULL; /* Not found or mismatched address version */
    return addr_ver; /* Found */
}

/* Function prototype */
static const struct ms_builtin_t *builtin_get(const ms_node *node);
static int generate_script(ms_ctx *ctx, ms_node *node,
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

static int canonicalize(const char *descriptor,
                        const struct wally_map *vars_in, uint32_t flags,
                        char **output)
{
    const size_t VAR_MAX_NAME_LEN = 16;
    size_t required_len = 0;
    const char *p = descriptor, *start;
    char *out;

    if (output)
        *output = NULL;

    if (!descriptor || (flags & ~WALLY_MINISCRIPT_REQUIRE_CHECKSUM) || !output)
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
                const struct wally_map_item *item;
                item = wally_map_get(vars_in, (unsigned char*)start, lookup_len);
                required_len += item ? item->value_len : lookup_len;
            }
        }
    }

    if (!*p && (flags & WALLY_MINISCRIPT_REQUIRE_CHECKSUM))
        return WALLY_EINVAL; /* Checksum required but not present */

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
                const struct wally_map_item *item;
                item = wally_map_get(vars_in, (unsigned char*)start, lookup_len);
                lookup_len = item ? item->value_len : lookup_len;
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
            if ((child->flags & NF_IS_UNCOMPRESSED) || node_has_uncompressed_key(ctx, child))
                return true;
    }
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
        if (node->kind & (KIND_RAW | KIND_ADDRESS) || node->kind == KIND_PUBLIC_KEY || node->kind == KIND_PRIVATE_KEY)
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
        wally_free_string(ctx->src);
        node_free(ctx->top_node);
        clear_and_free(ctx, sizeof(*ctx));
    }
    return WALLY_OK;
}

static int verify_sh(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (node->parent || !node->child->builtin)
        return WALLY_EINVAL;

    node->type_properties = node->child->type_properties;
    return WALLY_OK;
}

static int verify_wsh(ms_ctx *ctx, ms_node *node)
{
    (void)ctx;
    if (node->parent && node->parent->kind != KIND_DESCRIPTOR_SH)
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

    if (node->parent)
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

static int generate_pk_k(ms_ctx *ctx, ms_node *node,
                         unsigned char *script, size_t script_len, size_t *written)
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
        if (*written <= script_len) {
            script[0] = *written & 0xff; /* push opcode */
            memcpy(script + 1, buff, *written);
        }
        *written += 1;
    }
    return ret;
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
            if (node->child->flags & NF_IS_XONLY)
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

static int generate_checksig(unsigned char *script, size_t script_len, size_t *written)
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
    return ret == WALLY_OK ? generate_checksig(script, script_len, written) : ret;
}

static int generate_pkh(ms_ctx *ctx, ms_node *node,
                        unsigned char *script, size_t script_len, size_t *written)
{
    int ret = generate_pk_h(ctx, node, script, script_len, written);
    return ret == WALLY_OK ? generate_checksig(script, script_len, written) : ret;
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
                ret = wally_witness_program_from_bytes(script, output_len, WALLY_SCRIPT_HASH160,
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
                        builtin_sh_index, 0 };

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
            ret = WALLY_EINVAL; /* FIXME: check for valid pubkey lengths */
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

static int generate_delay(ms_ctx *ctx, ms_node *node,
                          unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    size_t output_len = *written;
    if (!node->child || !node_is_root(node) || !node->builtin)
        return WALLY_EINVAL;

    ret = generate_script(ctx, node->child, script, script_len, &output_len);
    if (ret != WALLY_OK)
        return ret;

    *written = output_len + 1;
    if (*written <= script_len) {
        if (node->kind == KIND_MINISCRIPT_OLDER)
            script[output_len] = OP_CHECKSEQUENCEVERIFY;
        else if (node->kind == KIND_MINISCRIPT_AFTER)
            script[output_len] = OP_CHECKLOCKTIMEVERIFY;
        else
            ret = WALLY_ERROR; /* Shouldn't happen */
    }
    return ret;
}

static int generate_hash_type(ms_ctx *ctx, ms_node *node,
                              unsigned char *script, size_t script_len, size_t *written)
{
    int ret;
    size_t hash_size,  output_len = *written, remaining_len = 0;
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
    ret = generate_script(ctx, node->child, script + 6, remaining_len, &output_len);
    if (ret == WALLY_OK) {
        *written = output_len + 7;
        if (*written <= script_len) {
            script[0] = OP_SIZE;
            script[1] = 0x01;
            script[2] = 0x20;
            script[3] = OP_EQUALVERIFY;
            script[4] = op_code;
            script[5] = hash_size;
            script[6 + output_len] = OP_EQUAL;
        }
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
        size_t output_len = 0, remaining_len = 0;

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

static int generate_wrappers(ms_node *node,
                             unsigned char *script, size_t script_len, size_t *written)
{
    size_t i;

    if (node->wrapper_str[0] == '\0')
        return WALLY_OK; /* No wrappers */

    if (!*written)
        return WALLY_EINVAL; /* Nothing to wrap */

#define WRAP_REQUIRE(req, move_by) output_len = (req); \
    if (*written + output_len <= script_len) { \
        if (move_by) memmove(script + (move_by), script, *written)
#define WRAP_REQUIRE_END } break

    /* Generate the nodes wrappers in reserve order */
    for (i = strlen(node->wrapper_str); i != 0; --i) {
        size_t output_len = 0;
        switch(node->wrapper_str[i - 1]) {
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

static int generate_script(ms_ctx *ctx, ms_node *node,
                           unsigned char *script, size_t script_len, size_t *written)
{
    int ret = WALLY_EINVAL;
    size_t output_len = *written;

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
            if (node->flags & NF_IS_UNCOMPRESSED) {
                output_len = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
                if (output_len <= script_len)
                    ret = wally_ec_public_key_decompress(pubkey, sizeof(pubkey), script,
                                                         EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
            } else {
                if (node->flags & NF_IS_XONLY) {
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
        output_len = node->flags & NF_IS_XONLY ? EC_XONLY_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_LEN;
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
                const bool is_ranged = node->flags & NF_IS_RANGED;
                const bool is_multi = node->flags & NF_IS_MULTI;
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
                memcpy(script, master.pub_key + ((node->flags & NF_IS_XONLY) ? 1 : 0), output_len);
            wally_clear(&master, sizeof(master));
        }
    }
    if (ret == WALLY_OK) {
        ret = generate_wrappers(node, script, script_len, &output_len);
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

static bool analyze_pubkey_hex(ms_ctx *ctx, const char *str, size_t str_len,
                               uint32_t flags, ms_node *node)
{
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN + 1];
    size_t offset = flags & WALLY_MINISCRIPT_TAPSCRIPT ? 1 : 0;
    size_t written;
    (void)ctx;

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

    if (!clone_bytes((unsigned char **)&node->data, pubkey + offset, written))
        return false; /* FIXME: This needs to return ENOMEM, not continue checking */
    node->data_len = str_len / 2;
    if (str_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN * 2) {
        node->flags |= NF_IS_UNCOMPRESSED;
        ctx->features |= WALLY_MS_IS_UNCOMPRESSED;
    }
    if (str_len == EC_XONLY_PUBLIC_KEY_LEN * 2)
        node->flags |= NF_IS_XONLY;
    node->kind = KIND_PUBLIC_KEY;
    ctx->features |= WALLY_MS_IS_RAW;
    return true;
}

static int analyze_miniscript_key(ms_ctx *ctx, uint32_t flags,
                                  ms_node *node, ms_node *parent)
{
    unsigned char privkey[2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN];
    struct ext_key extkey;
    size_t privkey_len, size;
    int ret;

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
    if (analyze_pubkey_hex(ctx, node->data, node->data_len, flags, node))
        return WALLY_OK;

    /* check key (private key(wif)) */
    ret = wally_base58_n_to_bytes(node->data, node->data_len, BASE58_FLAG_CHECKSUM,
                                  privkey, sizeof(privkey), &privkey_len);
    if (ret == WALLY_OK && privkey_len <= EC_PRIVATE_KEY_LEN + 2) {
        if (ctx->addr_ver && ctx->addr_ver->version_wif != privkey[0])
            return WALLY_EINVAL;
        if (privkey_len == EC_PRIVATE_KEY_LEN + 1) {
            if (flags & WALLY_MINISCRIPT_TAPSCRIPT)
                return WALLY_EINVAL; /* Tapscript only allows x-only keys */
            node->flags |= NF_IS_UNCOMPRESSED;
            ctx->features |= WALLY_MS_IS_UNCOMPRESSED;
        } else if (privkey_len != EC_PRIVATE_KEY_LEN + 2 ||
                   privkey[EC_PRIVATE_KEY_LEN + 1] != 1)
            return WALLY_EINVAL; /* Unknown WIF format */

        node->flags |= (flags & WALLY_MINISCRIPT_TAPSCRIPT) ? NF_IS_XONLY : 0;
        ret = wally_ec_private_key_verify(&privkey[1], EC_PRIVATE_KEY_LEN);
        if (ret == WALLY_OK && !clone_bytes((unsigned char **)&node->data, &privkey[1], EC_PRIVATE_KEY_LEN))
            ret = WALLY_EINVAL;
        else {
            node->data_len = EC_PRIVATE_KEY_LEN;
            node->kind = KIND_PRIVATE_KEY;
            ctx->features |= (WALLY_MS_IS_PRIVATE | WALLY_MS_IS_RAW);
        }
        wally_clear(privkey, sizeof(privkey));
        return ret;
    }

    /* check bip32 key */
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
            if (num_multi) {
                if (ctx->num_multipaths != 1 && ctx->num_multipaths != num_multi)
                    return WALLY_EINVAL; /* Different multi-path lengths */
                ctx->num_multipaths = num_multi;
                ctx->features |= WALLY_MS_IS_MULTIPATH;
                node->flags |= NF_IS_MULTI;
            }
            if (features & BIP32_PATH_IS_WILDCARD) {
                wildcard_pos = (features & BIP32_PATH_WILDCARD_MASK) >> BIP32_PATH_WILDCARD_SHIFT;
                if (wildcard_pos != num_elems - 1)
                    return WALLY_EINVAL; /* Must be the last element */
                ctx->features |= WALLY_MS_IS_RANGED;
                node->flags |= NF_IS_RANGED;
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
        ctx->features |= WALLY_MS_IS_PRIVATE;
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

    if (ret == WALLY_OK && (flags & WALLY_MINISCRIPT_TAPSCRIPT))
        node->flags |= NF_IS_XONLY;
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
            kind == KIND_MINISCRIPT_HASH160) {
            int ret = wally_hex_n_verify(str, str_len);
            if (ret == WALLY_OK) {
                if (!(node->data = wally_malloc(str_len / 2)))
                    ret = WALLY_ENOMEM;
                else {
                    size_t written;
                    wally_hex_n_to_bytes(str, str_len,
                                         (unsigned char*)node->data, str_len / 2,
                                         &written);
                    node->data_len = written;
                    node->kind = KIND_RAW;
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
        case KIND_DESCRIPTOR_ADDR:
        case KIND_DESCRIPTOR_RAW:
            /* No-op */
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
        if (node->flags & NF_IS_UNCOMPRESSED)
            *total += EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
        else if (node->flags & NF_IS_XONLY)
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

int wally_descriptor_parse(const char *miniscript,
                           const struct wally_map *vars_in,
                           uint32_t network, uint32_t flags,
                           ms_ctx **output)
{
    const struct addr_ver_t *addr_ver = addr_ver_from_network(network);
    uint32_t kind = KIND_MINISCRIPT | (flags & WALLY_MINISCRIPT_ONLY ? 0 : KIND_DESCRIPTOR);
    uint32_t max_depth = flags >> WALLY_MINISCRIPT_DEPTH_SHIFT;
    ms_ctx *ctx;
    int ret;

    *output = NULL;
    flags &= ~WALLY_MINISCRIPT_DEPTH_MASK;

    if (!miniscript || flags & ~MS_FLAGS_ALL ||
        (network != WALLY_NETWORK_NONE && !addr_ver))
        return WALLY_EINVAL;

    /* Allocate a context to hold the canonicalized/parsed expression */
    if (!(*output = wally_calloc(sizeof(ms_ctx))))
        return WALLY_ENOMEM;
    ctx = *output;
    ctx->addr_ver = addr_ver;
    ctx->num_variants = 1;
    ctx->num_multipaths = 1;
    ret = canonicalize(miniscript, vars_in,
                       flags & WALLY_MINISCRIPT_REQUIRE_CHECKSUM,
                       &ctx->src);
    if (ret == WALLY_OK) {
        ctx->src_len = strlen(ctx->src);
        ctx->features = WALLY_MS_IS_DESCRIPTOR; /* Un-set if miniscript found */

        if (max_depth && get_max_depth(ctx->src, ctx->src_len) > max_depth)
            ret = WALLY_EINVAL;
        else
            ret = analyze_miniscript(ctx, ctx->src, ctx->src_len, kind,
                                     flags, NULL, NULL, &ctx->top_node);
        if (ret == WALLY_OK)
            ret = node_generation_size(ctx->top_node, &ctx->script_len);
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
    *written = descriptor->script_len;
    return WALLY_OK;
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
                ret = wally_scriptpubkey_to_address(p, written,
                                                    ctx.addr_ver->network,
                                                    &addresses[i]);
                if (ret == WALLY_EINVAL)
                    ret = wally_addr_segwit_from_bytes(p, written,
                                                       ctx.addr_ver->family,
                                                       0, &addresses[i]);
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

int wally_descriptor_get_features(const struct wally_descriptor *descriptor,
                                  uint32_t *value_out)
{
    if (value_out)
        *value_out = 0;
    if (!descriptor || !value_out)
        return WALLY_EINVAL;
    *value_out = descriptor->features;
    return WALLY_OK;
}

int wally_descriptor_get_num_variants(const struct wally_descriptor *descriptor,
                                      uint32_t *value_out)
{
    if (value_out)
        *value_out = 0;
    if (!descriptor || !value_out)
        return WALLY_EINVAL;
    *value_out = descriptor->num_variants;
    return WALLY_OK;
}

int wally_descriptor_get_num_paths(const struct wally_descriptor *descriptor,
                                   uint32_t *value_out)
{
    if (value_out)
        *value_out = 0;
    if (!descriptor || !value_out)
        return WALLY_EINVAL;
    *value_out = descriptor->num_multipaths;
    return WALLY_OK;
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
