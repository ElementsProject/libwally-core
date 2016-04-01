#include <wally_bip32.h>
#include <wally_bip39.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Many compilers these days will elide calls to memset when they
 * determine that the memory is not read afterwards. There are reports
 * that tricks designed to work around this including making data volatile,
 * calling through function pointers, dummy asm contraints etc are
 * not always effective as optimisation continues to improve.
 *
 * Here we try to ensure that the clear/clear_n() functions work as advertised
 * by:
 * - Setting a custom thread stack, then
 * - Calling a function that processes sensitive data, then
 * - Searching the stack for any sensitive data when the function returns
 *
 * This test does not address data leaked through registers, ancillary heap
 * allocations, side channels, or being swapped to disk.
 */
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 16384u
#endif

/* Global alternate stack pointer */
static unsigned char *gstack;
/* Global scratch buffer */
static unsigned char *gbytes;

static const char *BIP39_MNEMONIC = "legal winner thank year wave sausage worth "
                                    "useful legal winner thank yellow";
static const unsigned char BIP39_SECRET[16] = {
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
};

/* Useful for developing these tests */
static void dump_mem(const void *mem, size_t len)
{
    const unsigned char *p = (const unsigned char *)mem;
    size_t i;
    for (i = 0; i < len; ++i) {
        if (!p[i])
            printf(".");
        else
            printf("%02x, ", p[i]);
    }
    printf("\n");
}

static unsigned char *checked_malloc(size_t len)
{
    void *ret = malloc(len);
    if (!ret)
        abort();
    memset(ret, 0, len);
    return ret;
}

static bool in_stack(const void *search, size_t len)
{
    size_t i;

    for (i = 0; i < PTHREAD_STACK_MIN - len - 1; ++i)
        if (!memcmp(gstack + i, search, len))
            return true; /* Found */

    return false; /* Not found */
}

/* Test that searching for data on the stack actually works */
static bool test_search(void)
{
    unsigned char buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    /* Don't let the optimiser elide buf off the stack */
    buf[7] ^= (((size_t)gstack) && 0xff);

    return in_stack(buf, sizeof(buf));
}

static bool test_bip39(void)
{
    /* Converting uses a temporary buffer on the stack */
    if (bip39_mnemonic_to_bytes(NULL, BIP39_MNEMONIC, gbytes,
                                BIP39_ENTROPY_LEN_128) != BIP39_ENTROPY_LEN_128)
        return false;

    if (in_stack(BIP39_SECRET, sizeof(BIP39_SECRET)))
        return false;

    /* Internally converts to bytes */
    if (!bip39_mnemonic_is_valid(NULL, BIP39_MNEMONIC))
        return false;

    if (in_stack(BIP39_SECRET, sizeof(BIP39_SECRET)))
        return false;

    return true;
}

static void *run_tests(void *passed_stack)
{
    if (passed_stack != gstack) {
        printf("stack mismatch!\n");
        return passed_stack;
    }

#define RUN(t) if (!t()) { printf(#t " failed!\n"); return gstack; }

    RUN(test_search);
    RUN(test_bip39);
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

    return tests_ok == NULL ? 0 : 1;
}
