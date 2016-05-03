#include <include/wally_core.h>
#include <include/wally_crypto.h>
#include "internal.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef __ANDROID__
#include "cpufeatures/cpu-features.c"
#endif

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
        return -1;
    clear(str, strlen(str));
    free(str);
    return WALLY_OK;
}

int wally_bzero(void *bytes, size_t len)
{
    if (!bytes)
        return -1;
    clear(bytes, len);
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
        clear(&sha, sizeof(sha));
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
        clear(&sha_2, sizeof(sha_2));
    }
    clear(&sha_1, sizeof(sha_1));
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
    if (!aligned)
        memcpy(bytes_out, &sha, sizeof(sha));
    return WALLY_OK;
}

#if 0
/* This idea is taken from libressl's explicit_bzero.
 * Use a weak symbol to force the compiler to consider dest as being read,
 * since it can't know what any interposed function may read. Not ideal for
 * us in case someone includes a __clear_fn symbol in a third party library,
 * since it gets called with an address right in the middle of interesting
 * things we are clearing out (even if the actual block is zeroed).
 */
__attribute__ ((visibility ("default"))) __attribute__((weak)) void __clear_fn(void *dest, size_t len);
#endif

/* Our implementation of secure clearing uses a variadic function.
 * This appears sufficient to prevent the compiler detecting that
 * the memory is not read after being zeroed and eliminating the
 * call.
 */
void clear_n(unsigned int count, ...)
{
    va_list args;
    unsigned int i;

    va_start(args, count);

    for (i = 0; i < count; ++i) {
        void *dest = va_arg(args, void *);
        size_t len = va_arg(args, size_t);
#ifdef HAVE_MEMSET_S
        memset_s(dest, len, 0, len);
#else
        memset(dest, 0, len);
#endif
#if 0
        /* This is used by boringssl to prevent memset from being elided. It
         * works by forcing a memory barrier and so can be slow.
         */
        __asm__ __volatile__ ("" : : "r" (dest) : "memory");
#endif
#if 0
        /* Continuing libressl's implementation. The check here allows the
         * implementation to remain undefined and thus a buggy compiler
         * cannot see that it does nothing and elide it erroneously.
         */
        if (__clear_fn)
            __clear_fn(dest, len);
#endif
    }

    va_end(args);
}
