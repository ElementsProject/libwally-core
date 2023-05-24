/* This is a superset of test_psbt, but requires mmap */
#include "config.h"

#include <wally_psbt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if 0
#include <assert.h>
#endif
#include <errno.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <memoryapi.h>
#undef WIN32_LEAN_AND_MEAN
#else
#include <sys/mman.h>
#endif

#include "psbts.h"

/* Ignore test logging compiler warnings */
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif

static void fail(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    abort();
}

/* Create a cliff: any access past the end will SEGV */
static unsigned char *cliff(size_t *size)
{
    unsigned char *p;

#ifdef _WIN32
    SYSTEM_INFO info;
    DWORD tmp;

    GetSystemInfo(&info);
    *size = info.dwPageSize;

    p = (unsigned char *)VirtualAlloc(NULL, (*size) * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p)
        fail("VirtualAlloc failed, err %d", GetLastError());

    if (!VirtualProtect(p + *size, *size, PAGE_READWRITE | PAGE_GUARD, &tmp))
        fail("VirtualProtect failed, err %d", GetLastError());
#else
    /* One page is enough for our tests so far */
    *size = getpagesize();

    /* MAP_ANON isn't POSIX, but MacOS doesn't let us mmap /dev/zero */
    p = mmap(NULL, *size + getpagesize(),
             PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED)
        fail("Failed to mmap anon, errno %d", errno);

    /* Remove second page. */
    if (munmap(p + *size, getpagesize()) != 0)
        fail("Failed to munmap /dev/zero, errno %d", errno);
#endif
    return p;
}

/* Test that we don't read past end of buffer when unmarshalling */
static void test_psbt_read(const struct psbt_test *test,
                           unsigned char *p, size_t plen)
{
    unsigned char buff[8192];
    size_t written, i;

    /* It can fit, otherwise adjust buff and/or cliff() */
    if (wally_base64_to_bytes(test->base64, 0, buff, sizeof(buff), &written) != WALLY_OK ||
        written > sizeof(buff) || written > plen)
        abort();

    /* Unpack right next to the cliff */
    for (i = 0; i <= written; i++) {
        struct wally_psbt *psbt;
        size_t bit;

        memcpy(p + plen - i, buff, i);

        /* Try it raw: probably will fail. */
        if (wally_psbt_from_bytes(p + plen - i, i, 0, &psbt) == WALLY_OK)
            wally_psbt_free(psbt);

        /* Now try flipping each bit in last byte. */
        for (bit = 0; bit < 8; bit++) {
            p[plen - 1] ^= (1 << bit);
            if (wally_psbt_from_bytes(p + plen - i, i, 0, &psbt) == WALLY_OK)
                wally_psbt_free(psbt);
            p[plen - 1] ^= (1 << bit);
        }
    }
}

/* Test that we don't write past end of buffer when marshaling */
static void test_psbt_write(const struct psbt_test *test,
                            unsigned char *p, size_t plen)
{
    size_t i, psbt_len, written;
    struct wally_psbt *psbt;

#ifndef BUILD_ELEMENTS
    if (test->is_pset)
        return;
#endif

    if (wally_psbt_from_base64(test->base64, 0, &psbt) != WALLY_OK)
        abort();

    if (wally_psbt_get_length(psbt, 0, &psbt_len) != WALLY_OK)
        abort();

    for (i = 0; i <= psbt_len; i++) {
        /* A too short buffer should return OK and the required length */
        if (wally_psbt_to_bytes(psbt, 0, p + plen - i, i, &written) != WALLY_OK) {
            fail("wally_psbt_to_bytes %s should have succeeded", test->base64);
        }
        if (written != psbt_len)
            fail("wally_psbt_to_bytes %s wrote %zu in %zu bytes?",
                 test->base64, written, i);
    }
    wally_psbt_free(psbt);
}

int main(void)
{
    size_t i;
    size_t plen;
    unsigned char *p = cliff(&plen);

    for (i = 0; i < sizeof(invalid_psbts) / sizeof(invalid_psbts[0]); i++) {
        test_psbt_read(invalid_psbts + i, p, plen);
    }

    for (i = 0; i < sizeof(valid_psbts) / sizeof(valid_psbts[0]); i++) {
        test_psbt_read(valid_psbts + i, p, plen);
        test_psbt_write(valid_psbts + i, p, plen);
    }

    wally_cleanup(0);
    return 0;
}
