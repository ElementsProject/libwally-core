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
 *
 * @bytes_in Memory to wipe
 * @len_in Size of @bytes_in in bytes.
 */
WALLY_CORE_API int wally_bzero(
    void *bytes,
    size_t len_in);

/**
 * Securely wipe and then free a string allocted by the library.
 *
 * @str String to free (must be NUL terminated UTF-8).
 */
WALLY_CORE_API int wally_free_string(
    char *str);

/** Length of entropy required for @wally_randomize_context */
#define WALLY_SECP_RANDOMISE_LEN 32

/**
 * Provide entropy to randomize the libraries internal secp256k1 context.
 *
 * @bytes_in Entropy to use.
 * @len_in Size of @bytes_in in bytes. Must be @WALLY_SECP_RANDOMISE_LEN.
 *
 * Random data is used in libsecp256k1 to blind the data being processed, to
 * make side channel attacks more difficult. libwallycore uses a single
 * internal context for secp functions that is not randomized at run time.
 * The caller should call this function before using any functions that rely on
 * secp (anything using public/private keys).
 */
WALLY_CORE_API int wally_secp_randomize(
    const unsigned char *bytes_in,
    size_t len_in);

/**
 * Convert bytes to a (lower-case) hexadecimal string.
 *
 * @bytes_in Bytes to convert.
 * @len_in Size of @bytes_in in bytes.
 * @output Destination for the resulting hexadecimal string.
 *
 * The string returned should be freed using @wally_free_string.
 */
WALLY_CORE_API int wally_hex_from_bytes(
    const unsigned char *bytes_in,
    size_t len_in,
    char **output);

/**
 * Convert a hexadecimal string to bytes.
 *
 * @hex String to convert.
 * @bytes_out: Where to store the resulting bytes.
 * @len: The length of @bytes_out in bytes.
 * @written: Destination for the number of bytes written to @bytes_out.
 */
WALLY_CORE_API int wally_hex_to_bytes(
    const char *hex,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#ifndef SWIG
/** The type of an overridable function to allocate memory */
typedef void *(*wally_malloc_t)(
    size_t size);

/** The type of an overridable function to free memory */
typedef void (*wally_free_t)(
    void *ptr);

/** The type of an overridable function to generate an EC nonce */
typedef int (*wally_ec_nonce_t)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
    );

/** Structure holding function pointers for overridable wally operations */
struct wally_operations {
    wally_malloc_t malloc_fn;
    wally_free_t free_fn;
    wally_ec_nonce_t ec_nonce_fn;
};

/**
 * Fetch the current overridable operations used by wally.
 *
 * @output: Destination for the overridable operations.
 */
WALLY_CORE_API int wally_get_operations(
    struct wally_operations *output);

/**
 * Set the current overridable operations used by wally.
 *
 * @ops: The overridable operations to set.
 */
WALLY_CORE_API int wally_set_operations(
    const struct wally_operations *ops);

#endif /* SWIG */

#endif /* WALLY_CORE_H */
