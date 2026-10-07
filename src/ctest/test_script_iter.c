#include "config.h"

#include <wally_core.h>
#include <wally_script.h>
#include <stdio.h>
#include <string.h>
#include "../script_iter.h"

#define NUM_ELEMS(a) (sizeof(a) / sizeof(a[0]))

static bool check(bool ok, const char *what)
{
    if (!ok)
        printf("FAIL: %s\n", what);
    return ok;
}

/* Iterate a script, returning the number of opcodes or -1 if malformed */
static int count_opcodes(const unsigned char *script, size_t script_len)
{
    script_iter si;
    int n = 0;

    si_init(&si, script, script_len);
    while (si_next(&si))
        ++n;
    return si_is_error(&si) ? -1 : n;
}

static bool test_iterate(void)
{
    static const unsigned char script[] = {
        OP_DUP, OP_HASH160, 0x02, 0xaa, 0xbb, OP_EQUALVERIFY,
        OP_PUSHDATA1, 0x01, 0xcc, OP_PUSHDATA2, 0x01, 0x00, 0xdd,
        OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0xee, OP_0, OP_16
    };
    static const struct {
        unsigned char opcode;
        size_t data_len;
        unsigned char data;
    } expected[] = {
        { OP_DUP, 0, 0 }, { OP_HASH160, 0, 0 }, { 0x02, 2, 0xaa },
        { OP_EQUALVERIFY, 0, 0 }, { OP_PUSHDATA1, 1, 0xcc },
        { OP_PUSHDATA2, 1, 0xdd }, { OP_PUSHDATA4, 1, 0xee },
        { OP_0, 0, 0 }, { OP_16, 0, 0 }
    };
    /* Truncated push lengths and push data */
    static const unsigned char bad[][3] = {
        { 0x02, 0xaa, 0 }, { OP_PUSHDATA1, 0, 0 }, { OP_PUSHDATA2, 0x01, 0 },
        { OP_PUSHDATA1, 0x02, 0xaa }
    };
    static const size_t bad_len[] = { 2, 1, 2, 3 };
    script_iter si;
    size_t i;
    bool ok = true;

    si_init(&si, script, sizeof(script));
    for (i = 0; i < NUM_ELEMS(expected); ++i) {
        ok &= check(si_next(&si), "iterate: next");
        ok &= check(si.opcode == expected[i].opcode, "iterate: opcode");
        ok &= check(si.data_len == expected[i].data_len, "iterate: data_len");
        if (expected[i].data_len)
            ok &= check(si.data[0] == expected[i].data, "iterate: data");
    }
    ok &= check(!si_next(&si) && !si_is_error(&si), "iterate: end");

    ok &= check(count_opcodes(NULL, 0) == 0, "iterate: empty");
    for (i = 0; i < NUM_ELEMS(bad); ++i)
        ok &= check(count_opcodes(bad[i], bad_len[i]) == -1, "iterate: truncated");
    si_init(&si, NULL, 1);
    ok &= check(!si_next(&si) && si_is_error(&si), "iterate: NULL script");
    return ok;
}

static bool is_minimal(const unsigned char *script, size_t script_len)
{
    script_iter si;
    si_init(&si, script, script_len);
    return si_next(&si) && si_is_minimal_push(&si);
}

static bool test_minimal_push(void)
{
    unsigned char buf[300];
    bool ok = true;

    memset(buf, 0x11, sizeof(buf));
    buf[0] = OP_0;
    ok &= check(is_minimal(buf, 1), "minimal: OP_0");
    buf[0] = OP_PUSHDATA1; buf[1] = 0;
    ok &= check(!is_minimal(buf, 2), "minimal: empty PUSHDATA1");
    buf[0] = 0x01; buf[1] = 0x05;
    ok &= check(!is_minimal(buf, 2), "minimal: push of 5");
    buf[1] = 0x81;
    ok &= check(!is_minimal(buf, 2), "minimal: push of -1");
    buf[1] = 0x11;
    ok &= check(is_minimal(buf, 2), "minimal: push of 17");
    buf[0] = 0x20;
    ok &= check(is_minimal(buf, 33), "minimal: 32 byte push");
    buf[0] = OP_PUSHDATA1; buf[1] = 0x20;
    ok &= check(!is_minimal(buf, 34), "minimal: 32 byte PUSHDATA1");
    buf[1] = 0x4c;
    ok &= check(is_minimal(buf, 2 + 0x4c), "minimal: 76 byte PUSHDATA1");
    buf[0] = OP_PUSHDATA2; buf[1] = 0x4c; buf[2] = 0;
    ok &= check(!is_minimal(buf, 3 + 0x4c), "minimal: 76 byte PUSHDATA2");
    buf[1] = 0x00; buf[2] = 0x01;
    ok &= check(is_minimal(buf, 3 + 0x100), "minimal: 256 byte PUSHDATA2");
    buf[0] = OP_DUP;
    ok &= check(!is_minimal(buf, 1), "minimal: not a push");
    return ok;
}

static bool get_number(const unsigned char *script, size_t script_len, int64_t *v)
{
    script_iter si;
    si_init(&si, script, script_len);
    return si_next(&si) && si_get_number(&si, v);
}

static bool test_number(void)
{
    static const struct {
        unsigned char script[6];
        size_t len;
        bool valid;
        int64_t value;
    } cases[] = {
        { { OP_0 }, 1, true, 0 },
        { { OP_1NEGATE }, 1, true, -1 },
        { { OP_1 }, 1, true, 1 },
        { { OP_16 }, 1, true, 16 },
        { { 0x01, 0x11 }, 2, true, 17 },
        { { 0x01, 0x91 }, 2, true, -17 },
        { { 0x02, 0x80, 0x00 }, 3, true, 128 },
        { { 0x02, 0x80, 0x80 }, 3, true, -128 },
        { { 0x04, 0xff, 0xff, 0xff, 0x7f }, 5, true, 0x7fffffff },
        { { 0x01, 0x10 }, 2, false, 0 },              /* Should be OP_16 */
        { { 0x01, 0x00 }, 2, false, 0 },              /* Should be OP_0 */
        { { 0x01, 0x80 }, 2, false, 0 },              /* Negative zero */
        { { 0x02, 0x11, 0x00 }, 3, false, 0 },        /* Non-minimal */
        { { 0x05, 1, 2, 3, 4, 5 }, 6, false, 0 },     /* Too long */
        { { OP_PUSHDATA1, 0x01, 0x11 }, 3, false, 0 }, /* Non-minimal push */
        { { OP_DUP }, 1, false, 0 }                   /* Not a number */
    };
    size_t i;
    bool ok = true;

    for (i = 0; i < NUM_ELEMS(cases); ++i) {
        int64_t v = 1234;
        bool ret = get_number(cases[i].script, cases[i].len, &v);
        ok &= check(ret == cases[i].valid, "number: validity");
        ok &= check(v == cases[i].value, "number: value");
    }
    return ok;
}

static bool si_equal(const script_iter *a, const script_iter *b)
{
    return a->script == b->script && a->script_len == b->script_len &&
           a->next == b->next && a->data == b->data &&
           a->data_len == b->data_len && a->opcode == b->opcode;
}

static bool test_match(void)
{
    /* DUP HASH160 <20 bytes> EQUALVERIFY CHECKSIG 144 CSV */
    unsigned char script[29] = { OP_DUP, OP_HASH160, 0x14 };
    const uint32_t pkh[] = {
        OP_DUP, OP_HASH160, SI_PUSH, 20, OP_EQUALVERIFY, OP_CHECKSIG
    };
    const uint32_t older[] = { SI_NUMBER, 1, 0x7fffffff, OP_CHECKSEQUENCEVERIFY };
    const uint32_t older_range[] = { SI_NUMBER, 145, 200, OP_CHECKSEQUENCEVERIFY };
    const uint32_t wrong_len[] = { OP_DUP, OP_HASH160, SI_PUSH, 32 };
    const uint32_t too_long[] = { SI_NUMBER, 1, 1000, OP_CHECKSEQUENCEVERIFY, OP_DROP };
    const uint32_t bad_pattern[] = { OP_DUP, SI_PUSH };
    script_iter si, start, matched[6];
    int64_t v;
    bool ok = true;

    memset(script + 3, 0xab, 20);
    script[23] = OP_EQUALVERIFY;
    script[24] = OP_CHECKSIG;
    script[25] = 0x02;
    script[26] = 0x90;
    script[27] = 0x00;
    script[28] = OP_CHECKSEQUENCEVERIFY;

    si_init(&si, script, sizeof(script));
    ok &= check(!si_match(&si, pkh, NUM_ELEMS(pkh), NULL), "match: before first opcode");
    si_next(&si);
    start = si;
    ok &= check(!si_match(&si, wrong_len, NUM_ELEMS(wrong_len), NULL) &&
                si_equal(&si, &start), "match: failure leaves iterator unchanged");
    ok &= check(!si_match(&si, bad_pattern, NUM_ELEMS(bad_pattern), NULL),
                "match: truncated pattern");
    ok &= check(si_match(&si, pkh, NUM_ELEMS(pkh), matched), "match: pkh");
    ok &= check(si.opcode == OP_CHECKSIG, "match: left at last opcode");
    ok &= check(matched[2].data_len == 20 && matched[2].data == script + 3,
                "match: matched push");
    ok &= check(si_next(&si), "match: next");
    start = si;
    ok &= check(!si_match(&si, older_range, NUM_ELEMS(older_range), NULL),
                "match: number out of range");
    ok &= check(!si_match(&si, too_long, NUM_ELEMS(too_long), NULL),
                "match: script ends before pattern");
    ok &= check(si_match(&si, older, NUM_ELEMS(older), matched), "match: older");
    ok &= check(si_get_number(&matched[0], &v) && v == 144, "match: matched number");
    ok &= check(!si_next(&si) && !si_is_error(&si), "match: end");
    return ok;
}

int main(void)
{
    bool ok = test_iterate();
    ok &= test_minimal_push();
    ok &= test_number();
    ok &= test_match();
    return ok ? 0 : 1;
}
