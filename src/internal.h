#ifndef LIBWALLY_INTERNAL_H
#define LIBWALLY_INTERNAL_H

#include <include/wally_core.h>
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_recovery.h"
#include <config.h>
#include <string.h>

/* Fetch an internal secp context */
const secp256k1_context *secp_ctx(void);
#define secp256k1_context_destroy(c) _do_not_destroy_shared_ctx_pointers(c)

#define pubkey_combine    secp256k1_ec_pubkey_combine
#define pubkey_create     secp256k1_ec_pubkey_create
#define pubkey_parse      secp256k1_ec_pubkey_parse
#define pubkey_tweak_add  secp256k1_ec_pubkey_tweak_add
#define pubkey_serialize  secp256k1_ec_pubkey_serialize
#define privkey_tweak_add secp256k1_ec_privkey_tweak_add
#define pubkey_negate      secp256k1_ec_pubkey_negate

#define PUBKEY_COMPRESSED   SECP256K1_EC_COMPRESSED
#define PUBKEY_UNCOMPRESSED SECP256K1_EC_UNCOMPRESSED


void wally_clear(void *p, size_t len);
void wally_clear_2(void *p, size_t len, void *p2, size_t len2);
void wally_clear_3(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3);
void wally_clear_4(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3, void *p4, size_t len4);
void wally_clear_5(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3, void *p4, size_t len4,
                   void *p5, size_t len5);
void wally_clear_6(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3, void *p4, size_t len4,
                   void *p5, size_t len5, void *p6, size_t len6);

/* Fetch our internal operations function pointers */
const struct wally_operations *wally_ops(void);

void *wally_malloc(size_t size);
void wally_free(void *ptr);
char *wally_strdup(const char *str);

#define malloc(size) __use_wally_malloc_internally__
#define free(ptr) __use_wally_free_internally__
#ifdef strdup
#undef strdup
#endif
#define strdup(ptr) __use_wally_strdup_internally__

#endif /* LIBWALLY_INTERNAL_H */

