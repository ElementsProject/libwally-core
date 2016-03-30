#include "internal.h"
#include <stdint.h>

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

