#include <include/wally-core.h>
#include "internal.h"
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

/* FIXME: Not threadsafe, not randomised, not cleaned up, etc etc*/
static secp256k1_context *global_ctx = NULL;

const secp256k1_context *secp_ctx(void)
{
    const uint32_t flags = SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN;

    if (!global_ctx)
        global_ctx = secp256k1_context_create(flags);

    /* FIXME: Error handling if null */

    return global_ctx;
}

void wally_free_string(char *str)
{
    if (str) {
        clear(str, strlen(str));
        free(str);
    }
}

void wally_bzero(void *bytes, size_t len)
{
    if (bytes)
        clear(bytes, len);
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
