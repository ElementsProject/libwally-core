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

static void test_psbt(const struct psbt_test *test,
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
        if (wally_psbt_from_bytes(p + plen - i, i, &psbt) == WALLY_OK)
            wally_psbt_free(psbt);

        /* Now try flipping each bit in last byte. */
        for (bit = 0; bit < 8; bit++) {
            p[plen - 1] ^= (1 << bit);
            if (wally_psbt_from_bytes(p + plen - i, i, &psbt) == WALLY_OK)
                wally_psbt_free(psbt);
            p[plen - 1] ^= (1 << bit);
        }
    }
}

int main(void)
{
    size_t i;
    size_t plen;
    unsigned char *p = cliff(&plen);

    for (i = 0; i < sizeof(invalid_psbts) / sizeof(invalid_psbts[0]); i++) {
        test_psbt(invalid_psbts + i, p, plen);
    }

    for (i = 0; i < sizeof(valid_psbts) / sizeof(valid_psbts[0]); i++) {
        test_psbt(valid_psbts + i, p, plen);
    }

    return 0;
}
