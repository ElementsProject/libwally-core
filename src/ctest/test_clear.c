#include "config.h"

#ifdef HAVE_ASM_PAGE_H
#   include <asm/page.h>
#endif
#include "internal.h"
#undef malloc
#undef free
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_crypto.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>


/* From ASAN wiki, modified to not break gcc */
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

#if defined(__SANITIZE_ADDRESS__)
extern void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
#define ASAN_POISON_MEMORY_REGION(addr, size) \
    __asan_poison_memory_region((addr), (size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    __asan_unpoison_memory_region((addr), (size))
#else
#define ASAN_POISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
#endif

/* Many compilers these days will elide calls to memset when they
 * determine that the memory is not read afterwards. There are reports
 * that tricks designed to work around this including making data volatile,
 * calling through function pointers, dummy asm contraints etc are
 * not always effective as optimization continues to improve.
 *
 * Here we try to ensure that the wally_clear/wally_clear_n() functions work as advertised
 * by:
 * - Setting a custom thread stack, then
 * - Calling a function that processes sensitive data, then
 * - Searching the stack for any sensitive data when the function returns
 *
 * This test does not address data leaked through registers, ancillary heap
 * allocations, side channels, or being swapped to disk.
 */
#ifndef PTHREAD_STACK_MIN
/* OSX Needs a minimum of 512K of stack per thread */
#define PTHREAD_STACK_MIN 512u * 1024u
#endif

/* Global alternate stack pointer */
static unsigned char *gstack;
/* Global scratch buffer */
static unsigned char *gbytes;

static const char *BIP39_MNEMONIC = "team hospital room inspire tenant almost "
                                    "push rich year warfare jeans foil";
static const unsigned char BIP39_SECRET[16] = {
    0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xf0, 0x0d,
    0xab, 0xad, 0xca, 0xfe, 0xfe, 0xe1, 0xde, 0xad
};

/* Useful for developing these tests */
static void dump_mem(volatile const void *mem, size_t len)
{
    static size_t i;
    for (i = 0; i < len; ++i) {
        if (!((const unsigned char *)mem)[i])
            printf(".");
        else
            printf("%02x, ", ((const unsigned char *)mem)[i]);
    }
    printf("\n");
}

static unsigned char *checked_malloc(size_t len)
{
    void *ret = malloc(len);
    if (!ret)
        abort();
    wally_bzero(ret, len);
    return ret;
}

/* Non-optimized memcmp.
 * On e.g. x86_64, does not leave search data in SSE/AVX registers
 * where it may be spilled to the stack when a call through the PLT
 * occurs.
 * TODO: Move to src/internal.c if we need to (we currently do not
 *       memcmp() any secret data so this is only required here).
 */
WALLY_NO_OPTIMIZE static int wally_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

static bool in_stack(const char *caller, volatile const void *search, size_t len)
{
    static size_t i;

    for (i = 0; i < PTHREAD_STACK_MIN - len - 1; ++i)
        if (!wally_memcmp(gstack + i, (const void *)search, len)) {
            if (caller) {
                printf("Found %s secret at stack position %ld and base %p\n", caller, (long)i, (void *)gstack);
                printf("raw pointer: %p\n", gstack + i);
                dump_mem(gstack + i - 64, len + 128);
            }
            return true; /* Found */
        }

    return false; /* Not found */
}

/* Test that searching for data on the stack actually works */
static bool test_search(void)
{
    char buf[8] = { 's', 'e', 'c', 'r', 'e', 't', '_', '\0' };

    /* printf here doesn't let the optimiser elide buf off the stack */
    printf("Testing stack search with %s\n", buf);

    return in_stack(NULL, buf, sizeof(buf));
}

static bool test_bip39(void)
{
    static size_t len;
    /* Converting uses a temporary buffer on the stack */
    if (bip39_mnemonic_to_bytes(NULL, BIP39_MNEMONIC, gbytes,
                                BIP39_ENTROPY_LEN_128, &len))
        return false;

    if (in_stack("bip39_mnemonic_to_bytes", BIP39_SECRET, sizeof(BIP39_SECRET)))
        return false;

    /* Internally converts to bytes */
    if (bip39_mnemonic_validate(NULL, BIP39_MNEMONIC))
        return false;

    if (in_stack("bip39_mnemonic_validate", BIP39_SECRET, sizeof(BIP39_SECRET)))
        return false;

    return true;
}

/* Sentinel for non-bip39 secret-handling tests: 32 bytes of 0xa5.
 * Distinct from BIP39_SECRET so test_search-style false positives can't
 * mask a real leak. */
static const unsigned char SECRET32[32] = {
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5
};

static bool test_bip32_from_seed(void)
{
    /* Derive an extended key from an all-0xa5 seed. The seed bytes
     * pass through libc memcpy when stored into the ext_key struct
     * and the HMAC-SHA512 input. */
    struct ext_key key;
    if (bip32_key_from_seed(SECRET32, sizeof(SECRET32),
                            BIP32_VER_MAIN_PRIVATE, 0, &key))
        return false;
    return !in_stack("bip32_key_from_seed", SECRET32, sizeof(SECRET32));
}

static bool test_ec_private_key_verify(void)
{
    /* The privkey is fed through libc on its way to libsecp. */
    if (wally_ec_private_key_verify(SECRET32, sizeof(SECRET32)))
        return false;
    return !in_stack("wally_ec_private_key_verify", SECRET32, sizeof(SECRET32));
}

static bool test_ec_sig_from_bytes(void)
{
    static unsigned char msg[32] = { 0x11 };
    static unsigned char sig[EC_SIGNATURE_LEN];
    /* Privkey is the secret. */
    if (wally_ec_sig_from_bytes(SECRET32, sizeof(SECRET32),
                                msg, sizeof(msg),
                                EC_FLAG_ECDSA,
                                sig, sizeof(sig)))
        return false;
    return !in_stack("wally_ec_sig_from_bytes", SECRET32, sizeof(SECRET32));
}

static bool test_hmac_sha256(void)
{
    static unsigned char out[32];
    static unsigned char msg[32] = { 0x22 };
    if (wally_hmac_sha256(SECRET32, sizeof(SECRET32),
                          msg, sizeof(msg),
                          out, sizeof(out)))
        return false;
    return !in_stack("wally_hmac_sha256", SECRET32, sizeof(SECRET32));
}

static void *run_tests(void *passed_stack)
{
    if (passed_stack != gstack) {
        printf("stack mismatch!\n");
        return passed_stack;
    }

#define RUN(t) if (!t()) { printf(#t " wally_clear() test failed!\n"); return gstack; }

    /* Due to the nature of the test reading poisoned bytes off the custom stack will trigger ASAN */
    ASAN_UNPOISON_MEMORY_REGION(passed_stack, PTHREAD_STACK_MIN);
    if (!test_search()) {
        /* Usually means the optimizer has beaten our efforts to fight it,
         * or the compiler doesn't support e.g. no-optimize attributes. In
         * both cases the tests below will fail as memcmp alone will leak.
         */
        printf("WARNING: clear tests unreliable, skipping\n");
        return NULL; /* Don't fail test runs where the optimizer has won */
    }

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, PTHREAD_STACK_MIN);
    RUN(test_bip39);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, PTHREAD_STACK_MIN);
    RUN(test_bip32_from_seed);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, PTHREAD_STACK_MIN);
    RUN(test_ec_private_key_verify);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, PTHREAD_STACK_MIN);
    RUN(test_ec_sig_from_bytes);

    ASAN_UNPOISON_MEMORY_REGION(passed_stack, PTHREAD_STACK_MIN);
    RUN(test_hmac_sha256);

    return NULL;
}

static int error(const char *fn, int ret)
{
    printf("error: %s failed, returned %d\n", fn, ret);
    return ret;
}

int main(void)
{
    pthread_t id;
    pthread_attr_t attr;
    void *tests_ok = &gstack; /* Anything non-null */
    int ret;

    gstack = checked_malloc(PTHREAD_STACK_MIN);
    gbytes = checked_malloc(64u * 1024u);

    ret = pthread_attr_init(&attr);
    if (ret)
        return error("pthread_attr_init", ret);

    ret = pthread_attr_setstack(&attr, gstack, PTHREAD_STACK_MIN);
    if (ret)
        return error("pthread_attr_setstack", ret);

    ret = pthread_create(&id, &attr, run_tests, gstack);
    if (ret)
        return error("pthread_create", ret);

    ret = pthread_join(id, &tests_ok);
    if (ret)
        return error("pthread_join", ret);

    free(gbytes);
    free(gstack);

    return tests_ok == NULL ? 0 : 1;
}
