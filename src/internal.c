#include "internal.h"
#include <include/wally_crypto.h>
#include "ccan/ccan/build_assert/build_assert.h"
#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
#include "ccan/ccan/endian/endian.h"

#undef malloc
#undef free

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

/* Caller is responsible for thread safety */
static secp256k1_context *global_ctx = NULL;

int pubkey_combine(secp256k1_pubkey *pubnonce, const secp256k1_pubkey *const *pubnonces, size_t n)
{
    return secp256k1_ec_pubkey_combine(secp256k1_context_no_precomp, pubnonce, pubnonces, n);
}

int pubkey_negate(secp256k1_pubkey *pubkey)
{
    return secp256k1_ec_pubkey_negate(secp256k1_context_no_precomp, pubkey);
}

int pubkey_parse(secp256k1_pubkey *pubkey, const unsigned char *input, size_t input_len)
{
    return secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, pubkey, input, input_len);
}

int pubkey_serialize(unsigned char *output, size_t *outputlen, const secp256k1_pubkey *pubkey, unsigned int flags)
{
    return secp256k1_ec_pubkey_serialize(secp256k1_context_no_precomp, output, outputlen, pubkey, flags);
}

int xpubkey_parse(secp256k1_xonly_pubkey *xpubkey, const unsigned char *input, size_t input_len)
{
    const secp256k1_context *ctx = secp256k1_context_no_precomp;
    if (input_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
        return 0;
    if (input_len == EC_PUBLIC_KEY_LEN) {
        secp256k1_pubkey pubkey;
        if (!pubkey_parse(&pubkey, input, input_len))
            return 0;
        return secp256k1_xonly_pubkey_from_pubkey(ctx, xpubkey, NULL, &pubkey);
    }
    if (input_len == EC_XONLY_PUBLIC_KEY_LEN)
        return secp256k1_xonly_pubkey_parse(ctx, xpubkey, input);
    return 0;
}

int xpubkey_tweak_add(secp256k1_pubkey *pubkey,
                      const secp256k1_xonly_pubkey *xpubkey,
                      const unsigned char *tweak)
{
    return secp256k1_xonly_pubkey_tweak_add(secp256k1_context_no_precomp,
                                            pubkey, xpubkey, tweak);
}

int xpubkey_serialize(unsigned char *output, const secp256k1_xonly_pubkey *xpubkey)
{
    return secp256k1_xonly_pubkey_serialize(secp256k1_context_no_precomp, output, xpubkey);
}

int seckey_verify(const unsigned char *seckey)
{
    return secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, seckey);
}

int seckey_negate(unsigned char *seckey)
{
    return secp256k1_ec_seckey_negate(secp256k1_context_no_precomp, seckey);
}

int seckey_tweak_add(unsigned char *seckey, const unsigned char *tweak)
{
    return secp256k1_ec_seckey_tweak_add(secp256k1_context_no_precomp, seckey, tweak);
}

int seckey_tweak_mul(unsigned char *seckey, const unsigned char *tweak)
{
    return secp256k1_ec_seckey_tweak_mul(secp256k1_context_no_precomp, seckey, tweak);
}

int keypair_create(secp256k1_keypair *keypair, const unsigned char *priv_key)
{
    return secp256k1_keypair_create(secp_ctx(), keypair, priv_key);
}

int keypair_xonly_pub(secp256k1_xonly_pubkey *xpubkey, const secp256k1_keypair *keypair)
{
    return secp256k1_keypair_xonly_pub(secp256k1_context_no_precomp, xpubkey, NULL, keypair);
}

int keypair_sec(unsigned char *output, const secp256k1_keypair *keypair)
{
    return secp256k1_keypair_sec(secp256k1_context_no_precomp, output, keypair);
}

int keypair_xonly_tweak_add(secp256k1_keypair *keypair, const unsigned char *tweak)
{
    return secp256k1_keypair_xonly_tweak_add(secp256k1_context_no_precomp, keypair, tweak);
}

#ifndef SWIG
struct secp256k1_context_struct *wally_get_secp_context(void)
{
    return (struct secp256k1_context_struct *)secp_ctx();
}
#endif

int wally_secp_randomize(const unsigned char *bytes, size_t bytes_len)
{
    secp256k1_context *ctx;

    if (!bytes || bytes_len != WALLY_SECP_RANDOMIZE_LEN)
        return WALLY_EINVAL;

    if (!(ctx = (secp256k1_context *)secp_ctx()))
        return WALLY_ENOMEM;

    if (!secp256k1_context_randomize(ctx, bytes))
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

int wally_bip340_tagged_hash(const unsigned char *bytes, size_t bytes_len,
                             const char *tag, unsigned char *bytes_out, size_t len)
{
    struct sha256 sha;
    struct sha256_ctx ctx;

    if (!bytes || !bytes_len || !tag || !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    /* SHA256(SHA256(tag) || SHA256(tag) || msg) */
    /* TODO: Add optimised impls for Taproot fixed tags */
    sha256(&sha, tag, strlen(tag));
    sha256_init(&ctx);
    sha256_update(&ctx, &sha, sizeof(sha));
    sha256_update(&ctx, &sha, sizeof(sha));
    sha256_update(&ctx, bytes, bytes_len);
    sha256_done(&ctx, &sha);

    memcpy(bytes_out, &sha, sizeof(sha));
    wally_clear_2(&sha, sizeof(sha), &ctx, sizeof(ctx));
    return WALLY_OK;
}

int wally_sha256(const unsigned char *bytes, size_t bytes_len,
                 unsigned char *bytes_out, size_t len)
{
    struct sha256 sha;
    const bool aligned = alignment_ok(bytes_out, sizeof(sha.u.u32[0]));

    if ((!bytes && bytes_len != 0) || !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    sha256(aligned ? (void *)bytes_out : (void *)&sha, bytes, bytes_len);
    if (!aligned) {
        memcpy(bytes_out, &sha, sizeof(sha));
        wally_clear(&sha, sizeof(sha));
    }
    return WALLY_OK;
}

static void sha256_midstate(struct sha256_ctx *ctx, struct sha256 *res)
{
    size_t i;

#ifdef CCAN_CRYPTO_SHA256_USE_MBEDTLS
#define SHA_CTX_STATE c.state
#else
#define SHA_CTX_STATE s
#endif

    for (i = 0; i < sizeof(ctx->SHA_CTX_STATE) / sizeof(ctx->SHA_CTX_STATE[0]); i++)
        res->u.u32[i] = cpu_to_be32(ctx->SHA_CTX_STATE[i]);

#ifndef CCAN_CRYPTO_SHA256_USE_MBEDTLS
    ctx->bytes = (size_t)-1;
#endif
}

int wally_sha256_midstate(const unsigned char *bytes, size_t bytes_len,
                          unsigned char *bytes_out, size_t len)
{
    struct sha256 sha;
    struct sha256_ctx ctx;
    const bool aligned = alignment_ok(bytes_out, sizeof(sha.u.u32[0]));

    if ((!bytes && bytes_len != 0) || !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    sha256_init(&ctx);
#if defined(CCAN_CRYPTO_SHA256_USE_MBEDTLS) && \
    defined(MBEDTLS_SHA256_ALT) && defined(SOC_SHA_SUPPORT_PARALLEL_ENG)
    /* HW sha engine doesn't allow to extract the midstate */
    ctx.c.mode = ESP_MBEDTLS_SHA256_SOFTWARE;
#endif
    sha256_update(&ctx, bytes, bytes_len);
    sha256_midstate(&ctx, aligned ? (void *)bytes_out : (void *)&sha);
    wally_clear(&ctx, sizeof(ctx));

    if (!aligned) {
        memcpy(bytes_out, &sha, sizeof(sha));
        wally_clear(&sha, sizeof(sha));
    }
    return WALLY_OK;
}

int wally_sha256d(const unsigned char *bytes, size_t bytes_len,
                  unsigned char *bytes_out, size_t len)
{
    struct sha256 sha_1, sha_2;
    const bool aligned = alignment_ok(bytes_out, sizeof(sha_1.u.u32[0]));

    if ((!bytes && bytes_len != 0) || !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    sha256(&sha_1, bytes, bytes_len);
    sha256(aligned ? (void *)bytes_out : (void *)&sha_2, &sha_1, sizeof(sha_1));
    if (!aligned) {
        memcpy(bytes_out, &sha_2, sizeof(sha_2));
        wally_clear(&sha_2, sizeof(sha_2));
    }
    wally_clear(&sha_1, sizeof(sha_1));
    return WALLY_OK;
}

int wally_sha512(const unsigned char *bytes, size_t bytes_len,
                 unsigned char *bytes_out, size_t len)
{
    struct sha512 sha;
    const bool aligned = alignment_ok(bytes_out, sizeof(sha.u.u64[0]));

    if ((!bytes && bytes_len != 0) || !bytes_out || len != SHA512_LEN)
        return WALLY_EINVAL;

    sha512(aligned ? (void *)bytes_out : (void *)&sha, bytes, bytes_len);
    if (!aligned) {
        memcpy(bytes_out, &sha, sizeof(sha));
        wally_clear(&sha, sizeof(sha));
    }
    return WALLY_OK;
}

int wally_ripemd160(const unsigned char *bytes, size_t bytes_len,
                    unsigned char *bytes_out, size_t len)
{
    struct ripemd160 ripemd;
    const bool aligned = alignment_ok(bytes_out, sizeof(ripemd.u.u32[0]));

    if ((!bytes && bytes_len != 0) || !bytes_out || len != RIPEMD160_LEN)
        return WALLY_EINVAL;

    BUILD_ASSERT(sizeof(ripemd) == RIPEMD160_LEN);

    ripemd160(aligned ? (void *)bytes_out : (void *)&ripemd, bytes, bytes_len);
    if (!aligned) {
        memcpy(bytes_out, &ripemd, sizeof(ripemd));
        wally_clear(&ripemd, sizeof(ripemd));
    }
    return WALLY_OK;
}

int wally_hash160(const unsigned char *bytes, size_t bytes_len,
                  unsigned char *bytes_out, size_t len)
{
    unsigned char buff[SHA256_LEN];
    struct ripemd160 ripemd;
    const bool aligned = alignment_ok(bytes_out, sizeof(ripemd.u.u32[0]));

    if (!bytes_out || len != HASH160_LEN)
        return WALLY_EINVAL;

    BUILD_ASSERT(sizeof(ripemd) == HASH160_LEN);

    if (wally_sha256(bytes, bytes_len, buff, sizeof(buff)) != WALLY_OK)
        return WALLY_EINVAL;

    ripemd160(aligned ? (void *)bytes_out : (void *)&ripemd, &buff, sizeof(buff));
    if (!aligned) {
        memcpy(bytes_out, &ripemd, sizeof(ripemd));
        wally_clear(&ripemd, sizeof(ripemd));
    }
    wally_clear(&buff, sizeof(buff));
    return WALLY_OK;
}

/*
 * For clang 7.0.1 and up it may be useful to disable the memset builtin for this code to not be elided when on -O3.
 * The following program can be used to check what your compiler is doing.
 * printf "#include <string.h> \n int main() { unsigned char s[10]; memset(s, 0, sizeof(s)); }" | clang -O3 -fno-builtin-memset -o memset.ll -S -emit-llvm -x c -
 */
static void wally_internal_bzero(void *dest, size_t len)
{
#ifdef _WIN32
    SecureZeroMemory(dest, len);
#elif defined(HAVE_MEMSET_S)
    memset_s(dest, len, 0, len);
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(dest, len);
#elif defined(HAVE_EXPLICIT_MEMSET)
    explicit_memset(dest, 0, len);
#else
    memset(dest, 0, len);
#endif
#if defined(HAVE_INLINE_ASM)
    /* This is used by boringssl to prevent memset from being elided. It
     * works by forcing a memory barrier and so can be slow.
     */
    __asm__ __volatile__ ("" : : "r" (dest) : "memory");
#endif
}

static void *wally_internal_malloc(size_t size)
{
    return malloc(size);
}

static void wally_internal_free(void *ptr)
{
    if (ptr)
        free(ptr);
}

static int wally_internal_ec_nonce_fn(unsigned char *nonce32,
                                      const unsigned char *msg32, const unsigned char *key32,
                                      const unsigned char *algo16, void *data, unsigned int attempt)
{
    return secp256k1_nonce_function_default(nonce32, msg32, key32, algo16, data, attempt);
}

struct secp256k1_context_struct *wally_get_new_secp_context(void)
{
    return secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
}

struct secp256k1_context_struct *wally_internal_secp_context(void)
{
    /* Default implementation uses a lazy-initialized global context,
     * this should be fetched or set by the caller before any threads
     * are created in order to be thread-safe. */
    if (!global_ctx)
        global_ctx = wally_get_new_secp_context();

    return global_ctx;
}

static struct wally_operations _ops = {
    sizeof(struct wally_operations),
    wally_internal_malloc,
    wally_internal_free,
    wally_internal_bzero,
    wally_internal_ec_nonce_fn,
    wally_internal_secp_context,
    NULL,
    NULL,
    NULL,
    NULL
};

const secp256k1_context *secp_ctx(void)
{
    return (const secp256k1_context *)_ops.secp_context_fn();
}

void *wally_malloc(size_t size)
{
    return _ops.malloc_fn(size);
}

void *wally_calloc(size_t size)
{
    void *p = _ops.malloc_fn(size);
    (void) wally_bzero(p, size);
    return p;
}

void wally_free(void *ptr)
{
    _ops.free_fn(ptr);
}

char *wally_strdup_n(const char *str, size_t str_len)
{
    char *new_str = (char *)wally_malloc(str_len + 1);
    if (new_str) {
        memcpy(new_str, str, str_len);
        new_str[str_len] = '\0';
    }
    return new_str;
}

char *wally_strdup(const char *str)
{
    return wally_strdup_n(str, strlen(str));
}

const struct wally_operations *wally_ops(void)
{
    return &_ops;
}

int wally_get_operations(struct wally_operations *output)
{
    if (!output || output->struct_size != sizeof(struct wally_operations))
        return WALLY_EINVAL;
    memcpy(output, &_ops, sizeof(_ops));
    return WALLY_OK;
}

int wally_set_operations(const struct wally_operations *ops)
{
    if (!ops || ops->struct_size != sizeof(struct wally_operations))
        return WALLY_EINVAL; /* Null or invalid version of ops */
    /* Reserved pointers must be null so they can be enabled in the
     * future without breaking back compatibility */
    if (ops->reserved_1 || ops->reserved_2 || ops->reserved_3 || ops->reserved_4)
        return WALLY_EINVAL;

#define COPY_FN_PTR(name) if (ops->name) _ops.name = ops->name
    COPY_FN_PTR(malloc_fn);
    COPY_FN_PTR(free_fn);
    COPY_FN_PTR (bzero_fn);
    COPY_FN_PTR (ec_nonce_fn);
    COPY_FN_PTR (secp_context_fn);
#undef COPY_FN_PTR
    return WALLY_OK;
}

int wally_is_elements_build(size_t *written)
{
    if (!written)
        return WALLY_EINVAL;
#ifdef BUILD_ELEMENTS
    *written = 1;
#else
    *written = 0;
#endif
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

void clear_and_free(void *p, size_t len)
{
    if (p) {
        wally_clear(p, len);
        wally_free(p);
    }
}

void clear_and_free_bytes(unsigned char **p, size_t *len)
{
    if (p && len) {
        clear_and_free(*p, *len);
        *p = NULL;
        *len = 0;
    }
}

bool mem_is_zero(const void *mem, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i)
        if (((const unsigned char *)mem)[i])
            return false;
    return true;
}

static bool wally_init_done = false;

int wally_init(uint32_t flags)
{
    if (flags)
        return WALLY_EINVAL;

    if (!wally_init_done) {
        sha256_optimize();
        wally_init_done = true;
    }

    return WALLY_OK;
}

int wally_cleanup(uint32_t flags)
{
    if (flags)
        return WALLY_EINVAL;
    if (global_ctx) {
        wally_secp_context_free(global_ctx);
        global_ctx = NULL;
    }
    return WALLY_OK;
}

void wally_secp_context_free(struct secp256k1_context_struct *ctx)
{
#undef secp256k1_context_destroy
    if (ctx)
        secp256k1_context_destroy(ctx);
}

bool clone_data(void **dst, const void *src, size_t len)
{
    if (!len) {
        *dst = NULL;
        return true;
    }
    *dst = wally_malloc(len);
    if (*dst)
        memcpy(*dst, src, len);
    return *dst != NULL;
}

bool clone_bytes(unsigned char **dst, const unsigned char *src, size_t len)
{
    return clone_data((void **)dst, src, len);
}

int replace_bytes(const unsigned char *bytes, size_t bytes_len,
                  unsigned char **bytes_out, size_t *bytes_len_out)
{
    unsigned char *new_bytes = NULL;

    if (BYTES_INVALID(bytes, bytes_len) || BYTES_INVALID(*bytes_out, *bytes_len_out))
        return WALLY_EINVAL;

    /* TODO: Avoid reallocation if new bytes is smaller than the existing one */
    if (!clone_bytes(&new_bytes, bytes, bytes_len))
        return WALLY_ENOMEM;

    clear_and_free(*bytes_out, *bytes_len_out);
    *bytes_out = new_bytes;
    *bytes_len_out = bytes_len;
    return WALLY_OK;
}



void *array_realloc(const void *src, size_t old_n, size_t new_n, size_t size)
{
    unsigned char *p = wally_malloc(new_n * size);
    if (!p)
        return NULL;
    if (src)
        memcpy(p, src, old_n * size);
    wally_clear(p + old_n * size, (new_n - old_n) * size);
    return p;
}

int array_grow(void **src, size_t num_items, size_t *allocation_len,
               size_t item_size)
{
    if (num_items == *allocation_len) {
        /* Array is full, allocate more space */
        const size_t n = (*allocation_len == 0 ? 1 : *allocation_len) * 2;
        void *p = array_realloc(*src, *allocation_len, n, item_size);
        if (!p)
            return WALLY_ENOMEM;
        /* Free and replace the old array with the new enlarged copy */
        clear_and_free(*src, num_items * item_size);
        *src = p;
        *allocation_len = n;
    }
    return WALLY_OK;
}


#ifdef __ANDROID__
#define malloc(size) wally_malloc(size)
#define free(ptr) wally_free(ptr)
#include "cpufeatures/cpu-features.c"
#endif
