/* Config directives for ccan */
#include <stddef.h>

#ifdef WORDS_BIGENDIAN
# define HAVE_BIG_ENDIAN 1
# define HAVE_LITTLE_ENDIAN 0
#else
# define HAVE_BIG_ENDIAN 0
# define HAVE_LITTLE_ENDIAN 1
#endif

#ifdef __GNUC__
# define HAVE_ATTRIBUTE_COLD 1
# define HAVE_ATTRIBUTE_NORETURN 1
# define HAVE_ATTRIBUTE_PRINTF 1
# define HAVE_ATTRIBUTE_CONST 1
# define HAVE_ATTRIBUTE_PURE 1
# define HAVE_ATTRIBUTE_UNUSED 1
# define HAVE_ATTRIBUTE_USED 1
# define HAVE_BUILTIN_CONSTANT_P 1
# define HAVE_WARN_UNUSED_RESULT 1
#endif

#ifdef HAVE_BYTESWAP_H
#define HAVE_BSWAP_64 1
#else
#define HAVE_BYTESWAP_H 0
#define HAVE_BSWAP_64 0
#endif

#if defined(HAVE_UNALIGNED_ACCESS) && defined(__arm__)
/* arm unaligned access is incomplete, in that e.g. byte swap instructions
 * can fault on unaligned addresses where a normal load/store would be fine.
 * Since the compiler can optimise some of our accesses into operations like
 * byte swaps, treat this platform as though it doesn't have unaligned access.
 */
#undef HAVE_UNALIGNED_ACCESS
#define HAVE_UNALIGNED_ACCESS 0
#endif

#if HAVE_UNALIGNED_ACCESS
#define alignment_ok(p, n) 1
#else
#define alignment_ok(p, n) ((size_t)(p) % (n) == 0)
#endif

#ifdef HAVE_MBEDTLS_SHA256_H
#define CCAN_CRYPTO_SHA256_USE_MBEDTLS 1
#endif

#ifdef HAVE_MBEDTLS_SHA512_H
#define CCAN_CRYPTO_SHA512_USE_MBEDTLS 1
#endif

void wally_clear(void *p, size_t len);

#define CCAN_CLEAR_MEMORY(p, len) wally_clear(p, len)
