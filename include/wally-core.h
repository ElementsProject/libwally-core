#ifndef WALLY_CORE_H
#define WALLY_CORE_H

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


/**
 * Securely wipe and then free a string allocted by the library.
 */
WALLY_CORE_API void wally_free_string(char *str);

#endif /* WALLY_CORE_H */

