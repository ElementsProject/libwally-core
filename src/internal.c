#include "internal.h"
#include <include/wally_crypto.h>
#include "ccan/ccan/build_assert/build_assert.h"
#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
#include <stdbool.h>

#undef malloc
#undef free

/* Caller is responsible for thread safety */
static secp256k1_context *global_ctx = NULL;

const secp256k1_context *secp_ctx(void)
{
    const uint32_t flags = SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN;

    if (!global_ctx)
        global_ctx = secp256k1_context_create(flags);

    return global_ctx;
}


int wally_secp_randomize(const unsigned char *bytes_in, size_t len_in)
{
    secp256k1_context *ctx;

    if (!bytes_in || len_in != WALLY_SECP_RANDOMISE_LEN)
        return WALLY_EINVAL;

    if (!(ctx = (secp256k1_context *)secp_ctx()))
        return WALLY_ENOMEM;

    if (!secp256k1_context_randomize(ctx, bytes_in))
        return WALLY_ERROR;

    return WALLY_OK;
}

int wally_free_string(char *str)
{
    if (!str)
        return WALLY_EINVAL;
    wally_clear(str, strlen(str));
    wally_free(str);
    return WALLY_OK;
}

int wally_bzero(void *bytes, size_t len)
{
    if (!bytes)
        return WALLY_EINVAL;
    wally_clear(bytes, len);
    return WALLY_OK;
}

int wally_sha256(const unsigned char *bytes_in, size_t len_in,
                 unsigned char *bytes_out, size_t len)
{
    struct sha256 sha;
    bool aligned = alignment_ok(bytes_out, sizeof(sha.u.u32));

    if (!bytes_in || !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    sha256(aligned ? (struct sha256 *)bytes_out : &sha, bytes_in, len_in);
    if (!aligned) {
        memcpy(bytes_out, &sha, sizeof(sha));
        wally_clear(&sha, sizeof(sha));
    }
    return WALLY_OK;
}

int wally_sha256d(const unsigned char *bytes_in, size_t len_in,
                  unsigned char *bytes_out, size_t len)
{
    struct sha256 sha_1, sha_2;
    bool aligned = alignment_ok(bytes_out, sizeof(sha_1.u.u32));

    if (!bytes_in || !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    sha256(&sha_1, bytes_in, len_in);
    sha256(aligned ? (struct sha256 *)bytes_out : &sha_2, &sha_1, sizeof(sha_1));
    if (!aligned) {
        memcpy(bytes_out, &sha_2, sizeof(sha_2));
        wally_clear(&sha_2, sizeof(sha_2));
    }
    wally_clear(&sha_1, sizeof(sha_1));
    return WALLY_OK;
}

int wally_sha512(const unsigned char *bytes_in, size_t len_in,
                 unsigned char *bytes_out, size_t len)
{
    struct sha512 sha;
    bool aligned = alignment_ok(bytes_out, sizeof(sha.u.u64));

    if (!bytes_in || !bytes_out || len != SHA512_LEN)
        return WALLY_EINVAL;

    sha512(aligned ? (struct sha512 *)bytes_out : &sha, bytes_in, len_in);
    if (!aligned) {
        memcpy(bytes_out, &sha, sizeof(sha));
        wally_clear(&sha, sizeof(sha));
    }
    return WALLY_OK;
}

int wally_hash160(const unsigned char *bytes_in, size_t len_in,
                  unsigned char *bytes_out, size_t len)
{
    struct sha256 sha;
    struct ripemd160 ripemd;
    bool aligned = alignment_ok(bytes_out, sizeof(ripemd.u.u32));

    if (!bytes_in || !bytes_out || len != HASH160_LEN)
        return WALLY_EINVAL;

    BUILD_ASSERT(sizeof(ripemd) == HASH160_LEN);

    sha256(&sha, bytes_in, len_in);
    ripemd160(aligned ? (struct ripemd160 *)bytes_out : &ripemd, &sha, sizeof(sha));
    if (!aligned) {
        memcpy(bytes_out, &ripemd, sizeof(ripemd));
        wally_clear(&ripemd, sizeof(ripemd));
    }
    wally_clear(&sha, sizeof(sha));
    return WALLY_OK;
}

static void wally_internal_bzero(void *dest, size_t len)
{
#ifdef HAVE_MEMSET_S
    memset_s(dest, len, 0, len);
#else
    memset(dest, 0, len);
#if 0
    /* This is used by boringssl to prevent memset from being elided. It
     * works by forcing a memory barrier and so can be slow.
     */
    __asm__ __volatile__ ("" : : "r" (dest) : "memory");
#endif
#endif
}

static void *wally_internal_malloc(size_t size)
{
    return malloc(size);
}

static void wally_internal_free(void *ptr)
{
    free(ptr);
}

static int wally_internal_ec_nonce_fn(unsigned char *nonce32,
                                      const unsigned char *msg32, const unsigned char *key32,
                                      const unsigned char *algo16, void *data, unsigned int attempt)
{
    return secp256k1_nonce_function_default(nonce32, msg32, key32, algo16, data, attempt);
}

static struct wally_operations _ops = {
    wally_internal_malloc,
    wally_internal_free,
    wally_internal_bzero,
    wally_internal_ec_nonce_fn
};

void *wally_malloc(size_t size)
{
    return _ops.malloc_fn(size);
}

void wally_free(void *ptr)
{
    _ops.free_fn(ptr);
}

char *wally_strdup(const char *str)
{
    size_t len = strlen(str) + 1;
    char *new_str = (char *)wally_malloc(len);
    if (new_str)
        memcpy(new_str, str, len); /* Copies terminating nul */
    return new_str;
}

const struct wally_operations *wally_ops(void)
{
    return &_ops;
}

int wally_get_operations(struct wally_operations *output)
{
    if (!output)
        return WALLY_EINVAL;
    memcpy(output, &_ops, sizeof(_ops));
    return WALLY_OK;
}

int wally_set_operations(const struct wally_operations *ops)
{
    if (!ops)
        return WALLY_EINVAL;
#define COPY_FN_PTR(name) if (ops->name) _ops.name = ops->name
    COPY_FN_PTR(malloc_fn);
    COPY_FN_PTR(free_fn);
    COPY_FN_PTR (bzero_fn);
    COPY_FN_PTR (ec_nonce_fn);
#undef COPY_FN_PTR
    return WALLY_OK;
}

void wally_clear(void *p, size_t len){
    _ops.bzero_fn(p, len);
}

void wally_clear_2(void *p, size_t len, void *p2, size_t len2){
    _ops.bzero_fn(p, len);
    _ops.bzero_fn(p2, len2);
}

void wally_clear_3(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3){
    _ops.bzero_fn(p, len);
    _ops.bzero_fn(p2, len2);
    _ops.bzero_fn(p3, len3);
}

void wally_clear_4(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3, void *p4, size_t len4){
    _ops.bzero_fn(p, len);
    _ops.bzero_fn(p2, len2);
    _ops.bzero_fn(p3, len3);
    _ops.bzero_fn(p4, len4);
}

void wally_clear_5(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3, void *p4, size_t len4,
                   void *p5, size_t len5){
    _ops.bzero_fn(p, len);
    _ops.bzero_fn(p2, len2);
    _ops.bzero_fn(p3, len3);
    _ops.bzero_fn(p4, len4);
    _ops.bzero_fn(p5, len5);
}

void wally_clear_6(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3, void *p4, size_t len4,
                   void *p5, size_t len5, void *p6, size_t len6){
    _ops.bzero_fn(p, len);
    _ops.bzero_fn(p2, len2);
    _ops.bzero_fn(p3, len3);
    _ops.bzero_fn(p4, len4);
    _ops.bzero_fn(p5, len5);
    _ops.bzero_fn(p6, len6);
}

#ifdef __ANDROID__
#define malloc(size) wally_malloc(size)
#define free(ptr) wally_free(ptr)
#include "cpufeatures/cpu-features.c"
#endif
