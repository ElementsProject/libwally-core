#ifndef LIBWALLY_CORE_DESCRIPTOR_INT_H
#define LIBWALLY_CORE_DESCRIPTOR_INT_H 1

#include <include/wally_map.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

struct addr_ver_t;

struct wally_descriptor {
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
};

typedef struct wally_descriptor ms_ctx;

#endif /* LIBWALLY_CORE_DESCRIPTOR_INT_H */
