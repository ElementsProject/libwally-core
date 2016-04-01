#include "internal.h"
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

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
    }

    va_end(args);
}
