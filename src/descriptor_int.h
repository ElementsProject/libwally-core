#ifndef WALLY_DESCRIPTOR_INT_H
#define WALLY_DESCRIPTOR_INT_H

#include <stdint.h>
#include <stddef.h>

/* ms_node kind base values */
#define KIND_MINISCRIPT 0x01

/* Miniscript terminal/compound node kinds */
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
#define KIND_MINISCRIPT_MULTI_A   (0x09000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_MULTI_A_S (0x0A000000 | KIND_MINISCRIPT)

/* Wrapper node kinds (decoder-only; not used by the string parser) */
#define KIND_MINISCRIPT_ALT            (0x0B000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_SWAP           (0x0C000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_CHECK          (0x0D000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_DUP_IF         (0x0E000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_VERIFY         (0x0F000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_NON_ZERO       (0x10000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_ZERO_NOT_EQUAL (0x11000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_JUST_0         (0x12000000 | KIND_MINISCRIPT)
#define KIND_MINISCRIPT_JUST_1         (0x13000000 | KIND_MINISCRIPT)

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

typedef struct wally_descriptor ms_ctx;

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

extern const struct ms_builtin_t g_builtins[];

#endif /* WALLY_DESCRIPTOR_INT_H */
