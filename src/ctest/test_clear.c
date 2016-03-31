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
 * Here we try to ensure that the clear_all() function works as advertised by:
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

static const char *MNEMONIC = "legal winner thank year wave sausage worth "
                              "useful legal winner thank yellow";

/* Useful for developing these tests */
static void dump_mem(const void *mem, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        const unsigned char *p = ((const unsigned char *)mem) + i;
        if (!*p)
            printf(".");
        else
            printf("0x%02x, ", *p);
    }
    printf("\n");
}

static void *checked_malloc(size_t len)
{
    void *ret = malloc(len);
    if (!ret)
        abort();
    memset(ret, 0, len);
    return ret;
}

static bool search_mem(const void *mem, size_t mem_len,
                       const void *search, size_t search_len)
{
    size_t i;

    if (search_len >= mem_len)
        abort(); /* Bad call */

    for (i = 0; i < mem_len - search_len - 1; ++i)
        if (!memcmp(((const unsigned char *)mem) + i, search, search_len))
            return true; /* Found */

    return false; /* Not found */
}

/* Test that searching for data on the stack actually works */
static bool test_search(void *stack)
{
    unsigned char buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    /* Don't let the optimiser elide buf off the stack */
    buf[8] = ((size_t)stack) && 0xff;

    return search_mem(stack, PTHREAD_STACK_MIN, buf, sizeof(buf));
}

static bool test_bip39(void *stack)
{
    const size_t len = BIP39_ENTROPY_LEN_128;
    unsigned char *bytes = checked_malloc(len);

    /* Converting uses a temporary buffer on the stack */
    if (bip39_mnemonic_to_bytes(NULL, MNEMONIC, bytes, len) != len)
        return false;

    if (search_mem(stack, PTHREAD_STACK_MIN, bytes, len))
        return false;

    /* Internally converts to bytes */
    if (!bip39_mnemonic_is_valid(NULL, MNEMONIC))
        return false;

    if (search_mem(stack, PTHREAD_STACK_MIN, bytes, len))
        return false;

    return true;
}

static void *run_tests(void *stack)
{
#define RUN_TEST(t) if (!t(stack)) { printf(#t " failed!\n"); return stack; }

    RUN_TEST(test_search);
    RUN_TEST(test_bip39);
    return NULL;
}

int main(void)
{
    pthread_t id;
    pthread_attr_t attr;
    unsigned char *stack;
    void *tests_ok = NULL;

    stack = (unsigned char *)checked_malloc(PTHREAD_STACK_MIN);

    pthread_attr_init(&attr);
    if (pthread_attr_setstack(&attr, stack, PTHREAD_STACK_MIN) ||
        pthread_create(&id, &attr, run_tests, stack) ||
        pthread_join(id, &tests_ok))
        return -1; /* pthreads b0rked */

    return tests_ok == NULL ? 0 : 1;
}
