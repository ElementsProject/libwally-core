#ifndef WALLY_CORE_H
#define WALLY_CORE_H

#include <stdlib.h>

#ifndef WALLY_CORE_API
# if defined(_WIN32)
#  ifdef WALLY_CORE_BUILD
#   define WALLY_CORE_API __declspec(dllexport)
#  else
#   define WALLY_CORE_API
#  endif
# elif defined(__GNUC__) && defined(WALLY_CORE_BUILD)
#  define WALLY_CORE_API __attribute__ ((visibility ("default")))
# else
#  define WALLY_CORE_API
# endif
#endif

/** Return codes */
#define WALLY_OK      0 /** Success */
#define WALLY_ERROR  -1 /** General error */
#define WALLY_EINVAL -2 /** Invalid argument */
#define WALLY_ENOMEM -3 /** malloc() failed */

/**
 * Securely wipe memory.
 */
WALLY_CORE_API int wally_bzero(void *bytes, size_t len);

/**
 * Securely wipe and then free a string allocted by the library.
 */
WALLY_CORE_API int wally_free_string(char *str);

#endif /* WALLY_CORE_H */

