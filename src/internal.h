#ifndef LIBWALLY_INTERNAL_H
#define LIBWALLY_INTERNAL_H

#include "secp256k1/include/secp256k1.h"

/* Fetch an internal secp context */
const secp256k1_context *secp_ctx(void);

#define secp256k1_context_destroy(c) _do_not_destroy_shared_ctx_pointers(c)

/* Clear a set of memory areas passed as ptr1, len1, ptr2, len2 etc */
void clear_n(size_t count, ...);

inline static void clear(void *p, size_t len)
{
    clear_n(1, p, len);
}

#endif /* LIBWALLY_INTERNAL_H */

