/* This is a superset of test_psbt, but requires mmap */
#include "config.h"

#include <wally_psbt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <err.h>
#include <ccan/str/hex/hex.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "psbts.h"

static size_t mallocs, frees;

static void *test_malloc(size_t size)
{
    mallocs++;
    return malloc(size);
}

static void test_free(void *ptr)
{
    if (ptr != NULL)
        frees++;
    free(ptr);
}

static const struct wally_operations test_ops = {
    test_malloc, test_free, NULL, NULL
};

/* Create a cliff: any access past the end will SEGV */
static unsigned char *cliff(size_t *size)
{
    unsigned char *p;

    /* One page is enough for our tests so far */
    *size = getpagesize();

    /* MAP_ANON isn't POSIX, but MacOS doesn't let us mmap /dev/zero */
    p = mmap(NULL, *size + getpagesize(),
             PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED)
        err(1, "Failed to mmap anon");

    /* Remove second page. */
    if (munmap(p + *size, getpagesize()) != 0)
        err(1, "Failed to munmap /dev/zero");
    return p;
}

/* Test that we don't read past end of buffer when unmarshalling */
static void test_psbt_read(const struct psbt_test *test,
                           unsigned char *p, size_t plen)
{
    size_t i;

    /* It can fit, otherwise adjust cliff() */
    assert(hex_data_size(strlen(test->hex)) <= plen);

    /* Unpack right next to the cliff */
    for (i = 0; i <= hex_data_size(strlen(test->hex)); i++) {
        struct wally_psbt *psbt;
        size_t bit;

        if (!hex_decode(test->hex, i * 2, p + plen - i, i))
            abort();

        /* Try it raw: probably will fail. */
        mallocs = frees = 0;
        if (wally_psbt_from_bytes(p + plen - i, i, &psbt) == WALLY_OK)
            wally_psbt_free(psbt);
        if (mallocs != frees) {
            errx(1, "psbt %s length %zu: mallocs = %zu, frees = %zu",
                 test->base64, i, mallocs, frees);
        }

        /* Now try flipping each bit in last byte. */
        for (bit = 0; bit < 8; bit++) {
            p[plen - 1] ^= (1 << bit);
            mallocs = frees = 0;
            if (wally_psbt_from_bytes(p + plen - i, i, &psbt) == WALLY_OK)
                wally_psbt_free(psbt);
            if (mallocs != frees) {
                errx(1, "psbt %s length %zu bitfplip %zu: mallocs = %zu, frees = %zu",
                     test->base64, i, bit, mallocs, frees);
            }
            p[plen - 1] ^= (1 << bit);
        }
    }
}

/* Test that we don't write past end of buffer when marshaling */
static void test_psbt_write(const struct psbt_test *test,
                            unsigned char *p, size_t plen)
{
    size_t i, written;
    struct wally_psbt *psbt;

    mallocs = frees = 0;
    if (wally_psbt_from_base64(test->base64, &psbt) != WALLY_OK)
        abort();

    for (i = 0;; i++) {
        if (wally_psbt_to_bytes(psbt, p + plen - i, i, &written) == WALLY_OK)
            break;
    }
    /* Should have fit exactly */
    if (written != i)
        errx(1, "wally_psbt_to_bytes %s wrote %zu in %zu bytes?",
             test->base64, written, i);
    wally_psbt_free(psbt);
    if (mallocs != frees) {
        errx(1, "psbt write %s: mallocs = %zu, frees = %zu",
             test->base64, mallocs, frees);
    }
}

int main(void)
{
    size_t i;
    size_t plen;
    unsigned char *p = cliff(&plen);

    wally_set_operations(&test_ops);

    for (i = 0; i < sizeof(invalid_psbts) / sizeof(invalid_psbts[0]); i++) {
        test_psbt_read(invalid_psbts + i, p, plen);
    }

    for (i = 0; i < sizeof(valid_psbts) / sizeof(valid_psbts[0]); i++) {
        test_psbt_read(valid_psbts + i, p, plen);
        test_psbt_write(valid_psbts + i, p, plen);
    }

    return 0;
}
