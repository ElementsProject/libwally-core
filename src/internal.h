#ifndef LIBWALLY_INTERNAL_H
#define LIBWALLY_INTERNAL_H

#include "secp256k1/include/secp256k1.h"

/* Fetch an internal secp context */
const secp256k1_context *secp_ctx(void);

#define secp256k1_context_destroy(c) _do_not_destroy_shared_ctx_pointers(c)

#endif /* LIBWALLY_INTERNAL_H */

