#include "config.h"
#include "miniscript_decode.h"
#include <wally_core.h>
#include <wally_address.h>
#include <wally_descriptor.h>
#include <wally_script.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define MAX_TOKENS 64

#define CHECK(expr) do { if (!(expr)) { printf("FAIL: %s\n", #expr); ok = false; } } while(0)

static bool test_tokenize_script(void)
{
    bool ok = true;
    token_t tokens[MAX_TOKENS];
    size_t count;
    int ret;

    /* Empty script */
    ret = ms_tokenize_script(NULL, 0, tokens, MAX_TOKENS, &count);
    CHECK(ret == WALLY_OK);
    CHECK(count == 0);

    /* OP_0 */
    {
        unsigned char script[] = { OP_0 };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].num == 0);
    }

    /* OP_1 */
    {
        unsigned char script[] = { OP_1 };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].num == 1);
    }

    /* OP_16 */
    {
        unsigned char script[] = { OP_16 };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].num == 16);
    }

    /* OP_1NEGATE */
    {
        unsigned char script[] = { OP_1NEGATE };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Push data — 20-byte (TK_HASH20) */
    {
        unsigned char script[21];
        script[0] = 0x14; /* push 20 bytes */
        memset(script + 1, 0xab, 20);
        ret = ms_tokenize_script(script, 21, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_HASH20);
        CHECK(memcmp(tokens[0].bytes, script + 1, 20) == 0);
    }

    /* Push data — 32-byte (TK_BYTES32) */
    {
        unsigned char script[33];
        script[0] = 0x20; /* push 32 bytes */
        memset(script + 1, 0xcd, 32);
        ret = ms_tokenize_script(script, 33, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_BYTES32);
        CHECK(memcmp(tokens[0].bytes, script + 1, 32) == 0);
    }

    /* Push data — 33-byte (TK_BYTES33) */
    {
        unsigned char script[34];
        script[0] = 0x21; /* push 33 bytes */
        script[1] = 0x02; /* valid compressed key prefix */
        memset(script + 2, 0xef, 32);
        ret = ms_tokenize_script(script, 34, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_BYTES33);
        CHECK(memcmp(tokens[0].bytes, script + 1, 33) == 0);
    }

    /* Push data — 65 bytes (uncompressed key): not a size miniscript pushes */
    {
        unsigned char script[66];
        script[0] = 0x41; /* push 65 bytes */
        memset(script + 1, 0xab, 65);
        ret = ms_tokenize_script(script, 66, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Push data — CScriptNum: a minimally-encoded value (17, which has no
     * dedicated push opcode) tokenizes to TK_NUM. */
    {
        unsigned char script[] = { 0x01, 0x11 };
        ret = ms_tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].num == 17);
    }

    /* Non-minimal numeric pushes must be rejected (anti-malleability): a value
     * 0..16 must use OP_0/OP_1..OP_16, and redundant trailing bytes are invalid. */
    {
        unsigned char small[] = { 0x01, 0x05 };          /* 5 must be OP_5 */
        unsigned char trailing[] = { 0x02, 0x11, 0x00 }; /* non-minimal 17 */
        ret = ms_tokenize_script(small, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
        ret = ms_tokenize_script(trailing, 3, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Push data — unsupported length (5 bytes) */
    {
        unsigned char script[] = { 0x05, 0, 0, 0, 0, 0 };
        ret = ms_tokenize_script(script, 6, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Push data — truncated (push-N but script too short) */
    {
        unsigned char script[] = { 0x14 }; /* says push 20, but nothing follows */
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* OP_PUSHDATA1 with a 20-byte payload: a valid Script push, but not the
     * minimal encoding (direct push 0x14), so the tokenizer must reject it */
    {
        unsigned char script[22];
        script[0] = OP_PUSHDATA1;
        script[1] = 20;
        memset(script + 2, 0x11, 20);
        ret = ms_tokenize_script(script, 22, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* OP_PUSHDATA1 — truncated (missing length byte) */
    {
        unsigned char script[] = { OP_PUSHDATA1 };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* OP_PUSHDATA2 with a 20-byte payload: likewise non-minimal */
    {
        unsigned char script[23];
        script[0] = OP_PUSHDATA2;
        script[1] = 20;
        script[2] = 0;
        memset(script + 3, 0x22, 20);
        ret = ms_tokenize_script(script, 23, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* OP_PUSHDATA4 is never minimal either */
    {
        unsigned char script[] = { OP_PUSHDATA4, 1, 0, 0, 0, 0x64 };
        ret = ms_tokenize_script(script, sizeof(script), tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* OP_PUSHDATA2 — truncated (only one length byte) */
    {
        unsigned char script[] = { OP_PUSHDATA2, 20 };
        ret = ms_tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Opcode-only tokens */
    {
        unsigned char s[1];
        s[0] = OP_BOOLAND;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_BOOL_AND);

        s[0] = OP_BOOLOR;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_BOOL_OR);

        s[0] = OP_ADD;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_ADD);

        s[0] = OP_EQUAL;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_EQUAL);

        s[0] = OP_NUMEQUAL;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_NUM_EQUAL);

        s[0] = OP_CHECKSIG;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_SIG);

        s[0] = OP_CHECKSIGADD;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_SIG_ADD);

        s[0] = OP_CHECKMULTISIG;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_MULTI_SIG);

        s[0] = OP_CHECKSEQUENCEVERIFY;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_SEQUENCE_VERIFY);

        s[0] = OP_CHECKLOCKTIMEVERIFY;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_LOCK_TIME_VERIFY);

        s[0] = OP_FROMALTSTACK;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_FROM_ALT_STACK);

        s[0] = OP_TOALTSTACK;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_TO_ALT_STACK);

        s[0] = OP_DROP;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_DROP);

        s[0] = OP_DUP;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_DUP);

        s[0] = OP_IF;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_IF);

        s[0] = OP_IFDUP;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_IF_DUP);

        s[0] = OP_NOTIF;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_NOT_IF);

        s[0] = OP_ELSE;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_ELSE);

        s[0] = OP_ENDIF;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_END_IF);

        s[0] = OP_0NOTEQUAL;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_ZERO_NOT_EQUAL);

        s[0] = OP_SIZE;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_SIZE);

        s[0] = OP_SWAP;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_SWAP);

        s[0] = OP_RIPEMD160;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_RIPEMD160);

        s[0] = OP_HASH160;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_HASH160);

        s[0] = OP_SHA256;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_SHA256);

        s[0] = OP_HASH256;
        ret = ms_tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_HASH256);
    }

    /* OP_EQUALVERIFY → TK_EQUAL, TK_VERIFY */
    {
        unsigned char script[] = { OP_EQUALVERIFY };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_EQUAL);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* OP_NUMEQUALVERIFY → TK_NUM_EQUAL, TK_VERIFY */
    {
        unsigned char script[] = { OP_NUMEQUALVERIFY };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_NUM_EQUAL);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* OP_CHECKSIGVERIFY → TK_CHECK_SIG, TK_VERIFY */
    {
        unsigned char script[] = { OP_CHECKSIGVERIFY };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_CHECK_SIG);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* OP_CHECKMULTISIGVERIFY → TK_CHECK_MULTI_SIG, TK_VERIFY */
    {
        unsigned char script[] = { OP_CHECKMULTISIGVERIFY };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_CHECK_MULTI_SIG);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* Standalone OP_VERIFY (n=0, no preceding token) */
    {
        unsigned char script[] = { OP_VERIFY };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_VERIFY);
    }

    /* OP_SIZE, OP_VERIFY → TK_SIZE, TK_VERIFY */
    {
        unsigned char script[] = { OP_SIZE, OP_VERIFY };
        ret = ms_tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_SIZE);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* NonMinimalVerify: OP_EQUAL, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_EQUAL, OP_VERIFY };
        ret = ms_tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* NonMinimalVerify: OP_NUMEQUAL, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_NUMEQUAL, OP_VERIFY };
        ret = ms_tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* A 33-byte push must be a syntactically valid compressed key (0x02/0x03) */
    {
        unsigned char script[34];
        script[0] = 0x21;
        memset(script + 1, 0x11, 33);
        ret = ms_tokenize_script(script, 34, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
        script[1] = 0x04; /* uncompressed prefix on a 33-byte push */
        ret = ms_tokenize_script(script, 34, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
        script[1] = 0x03;
        ret = ms_tokenize_script(script, 34, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_BYTES33);
    }

    /* NonMinimalVerify: OP_CHECKSIG, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_CHECKSIG, OP_VERIFY };
        ret = ms_tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* NonMinimalVerify: OP_CHECKMULTISIG, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_CHECKMULTISIG, OP_VERIFY };
        ret = ms_tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Unknown opcode (OP_RESERVED = 0x50) → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_RESERVED };
        ret = ms_tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Buffer overflow: OP_DUP with max_tokens = 0 */
    {
        unsigned char script[] = { OP_DUP };
        ret = ms_tokenize_script(script, 1, tokens, 0, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Buffer overflow: OP_EQUALVERIFY (emits 2 tokens) with max_tokens = 1 */
    {
        unsigned char script[] = { OP_EQUALVERIFY };
        ret = ms_tokenize_script(script, 1, tokens, 1, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Multi-token sequence: P2PKH-like script
     * OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
     * → TK_DUP, TK_HASH160, TK_HASH20, TK_EQUAL, TK_VERIFY, TK_CHECK_SIG */
    {
        unsigned char script[25];
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 0x14; /* push 20 bytes */
        memset(script + 3, 0x33, 20);
        script[23] = OP_EQUALVERIFY;
        script[24] = OP_CHECKSIG;
        ret = ms_tokenize_script(script, 25, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 6);
        CHECK(tokens[0].kind == TK_DUP);
        CHECK(tokens[1].kind == TK_HASH160);
        CHECK(tokens[2].kind == TK_HASH20);
        CHECK(memcmp(tokens[2].bytes, script + 3, 20) == 0);
        CHECK(tokens[3].kind == TK_EQUAL);
        CHECK(tokens[4].kind == TK_VERIFY);
        CHECK(tokens[5].kind == TK_CHECK_SIG);
    }

    return ok;
}


/* --- Script building helpers for the decoder tests --- */

typedef struct { unsigned char buf[512]; size_t len; } sb_t;

static void sb_op(sb_t *s, unsigned char op) { s->buf[s->len++] = op; }

static void sb_push(sb_t *s, const unsigned char *d, size_t n)
{
    s->buf[s->len++] = (unsigned char)n;
    memcpy(s->buf + s->len, d, n);
    s->len += n;
}

/* Push a number using its minimal script encoding */
static void sb_num(sb_t *s, uint32_t v)
{
    unsigned char le[5];
    size_t n = 0;
    if (v == 0) { sb_op(s, OP_0); return; }
    if (v <= 16) { sb_op(s, (unsigned char)(OP_1 + v - 1)); return; }
    while (v) { le[n++] = v & 0xff; v >>= 8; }
    if (le[n - 1] & 0x80) le[n++] = 0;
    sb_push(s, le, n);
}

/* Fill a fake 33-byte compressed key: a valid 0x02 prefix then `fill` bytes */
static void fill_key33(unsigned char *k, unsigned char fill)
{
    k[0] = 0x02;
    memset(k + 1, fill, 32);
}

/* Push a fake 33-byte compressed key made of `fill` bytes */
static void sb_key33(sb_t *s, unsigned char fill)
{
    unsigned char k[33];
    fill_key33(k, fill);
    sb_push(s, k, 33);
}

/* Push a fake 32-byte x-only key made of `fill` bytes */
static void sb_key32(sb_t *s, unsigned char fill)
{
    unsigned char k[32];
    memset(k, fill, 32);
    sb_push(s, k, 32);
}

/* c:pk_k(fill) = <key> OP_CHECKSIG */
static void sb_cpk(sb_t *s, unsigned char fill)
{
    sb_key33(s, fill);
    sb_op(s, OP_CHECKSIG);
}

/* older(n) = <n> OP_CHECKSEQUENCEVERIFY */
static void sb_older(sb_t *s, uint32_t n)
{
    sb_num(s, n);
    sb_op(s, OP_CHECKSEQUENCEVERIFY);
}

static int decode(const sb_t *s, uint32_t flags, ms_node **out)
{
    return ms_node_from_script(s->buf, s->len, flags, out);
}

static bool key_is(const ms_node *n, unsigned char fill, size_t len)
{
    unsigned char k[33];
    if (len == 33)
        fill_key33(k, fill);
    else
        memset(k, fill, sizeof(k));
    return n && n->kind == KIND_MINISCRIPT_PK_K && n->data_len == len &&
           memcmp(n->data, k, len) == 0;
}

static bool test_decode_pk(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* c:pk_k(A) with a 33-byte compressed pubkey: <A> OP_CHECKSIG */
    {
        sb_t s = { {0}, 0 };
        sb_cpk(&s, 0x02);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_CHECK);
        CHECK((output->type_properties & TYPE_MASK) == TYPE_B);
        CHECK(key_is(output->child, 0x02, 33));
        CHECK(output->child->type_properties == (TYPE_K | PROP_O | PROP_N | PROP_D | PROP_U));
        CHECK(!(output->child->flags & WALLY_MS_IS_X_ONLY));
        ms_node_free(output); output = NULL;
    }

    /* A bare pk_k(A) is of type K: a complete script must be type B */
    {
        sb_t s = { {0}, 0 };
        sb_key33(&s, 0x02);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* 65-byte uncompressed keys are rejected in both contexts (Core rejects
     * them everywhere in miniscript; they are non-standard in P2WSH) */
    {
        sb_t s = { {0}, 0 };
        unsigned char key[65];
        key[0] = 0x04;
        memset(key + 1, 0xab, 64);
        sb_push(&s, key, 65);
        sb_op(&s, OP_CHECKSIG);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* A 32-byte x-only key is only valid in tapscript context */
    {
        sb_t s = { {0}, 0 };
        sb_key32(&s, 0xcd);
        sb_op(&s, OP_CHECKSIG);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Conversely a 33-byte key is not valid in tapscript (BIP-342: x-only) */
    {
        sb_t s = { {0}, 0 };
        sb_cpk(&s, 0x02);
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* c:pk_h(H): OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG */
    {
        sb_t s = { {0}, 0 };
        unsigned char hash[20];
        memset(hash, 0x77, 20);
        sb_op(&s, OP_DUP);
        sb_op(&s, OP_HASH160);
        sb_push(&s, hash, 20);
        sb_op(&s, OP_EQUALVERIFY);
        sb_op(&s, OP_CHECKSIG);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_CHECK);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_PK_H);
        CHECK(output->child->data_len == 20);
        CHECK(memcmp(output->child->data, hash, 20) == 0);
        CHECK(output->child->type_properties == (TYPE_K | PROP_N | PROP_D | PROP_U));
        ms_node_free(output); output = NULL;
    }

    /* c:pk_k with a 32-byte x-only key in tapscript context: WALLY_MS_IS_X_ONLY must be set */
    {
        sb_t s = { {0}, 0 };
        sb_key32(&s, 0xef);
        sb_op(&s, OP_CHECKSIG);
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child, 0xef, 32));
        CHECK(output->child->flags & WALLY_MS_IS_X_ONLY);
        ms_node_free(output); output = NULL;
    }

    /* Error: truncated script (length byte claims 33 bytes but only 1 byte total) */
    {
        unsigned char script[1];
        script[0] = 0x21; /* push 33 bytes, but nothing follows */
        ret = ms_node_from_script(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Error: wrong pubkey length (34-byte push — not a valid key size) */
    {
        unsigned char script[36];
        script[0] = 0x22; /* push 34 bytes */
        memset(script + 1, 0xab, 34);
        script[35] = OP_CHECKSIG;
        ret = ms_node_from_script(script, 36, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    return ok;
}

static bool test_decode_hash(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* sha256: OP_SIZE 0x0120 OP_EQUALVERIFY OP_SHA256 0x20 <32 bytes> OP_EQUAL */
    {
        unsigned char hash32[32];
        unsigned char script[39];
        memset(hash32, 0xaa, 32);
        script[0] = 0x82; /* OP_SIZE */
        script[1] = 0x01; script[2] = 0x20; /* push 1 byte = 32 */
        script[3] = 0x88; /* OP_EQUALVERIFY */
        script[4] = 0xa8; /* OP_SHA256 */
        script[5] = 0x20; /* push 32 bytes */
        memcpy(script + 6, hash32, 32);
        script[38] = 0x87; /* OP_EQUAL */
        ret = ms_node_from_script(script, 39, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_SHA256);
        CHECK(output->data_len == 32);
        CHECK(memcmp(output->data, hash32, 32) == 0);
        ms_node_free(output); output = NULL;
    }

    /* hash256: same shape, opcode byte 0xaa at offset 4 */
    {
        unsigned char hash32[32];
        unsigned char script[39];
        memset(hash32, 0xaa, 32);
        script[0] = 0x82;
        script[1] = 0x01; script[2] = 0x20;
        script[3] = 0x88;
        script[4] = 0xaa; /* OP_HASH256 */
        script[5] = 0x20;
        memcpy(script + 6, hash32, 32);
        script[38] = 0x87;
        ret = ms_node_from_script(script, 39, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_HASH256);
        CHECK(output->data_len == 32);
        CHECK(memcmp(output->data, hash32, 32) == 0);
        ms_node_free(output); output = NULL;
    }

    /* ripemd160: OP_SIZE 0x0120 OP_EQUALVERIFY OP_RIPEMD160 0x14 <20 bytes> OP_EQUAL */
    {
        unsigned char hash20[20];
        unsigned char script[27];
        memset(hash20, 0xbb, 20);
        script[0] = 0x82;
        script[1] = 0x01; script[2] = 0x20;
        script[3] = 0x88;
        script[4] = 0xa6; /* OP_RIPEMD160 */
        script[5] = 0x14; /* push 20 bytes */
        memcpy(script + 6, hash20, 20);
        script[26] = 0x87;
        ret = ms_node_from_script(script, 27, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_RIPEMD160);
        CHECK(output->data_len == 20);
        CHECK(memcmp(output->data, hash20, 20) == 0);
        ms_node_free(output); output = NULL;
    }

    /* hash160: same shape, opcode byte 0xa9 at offset 4 */
    {
        unsigned char hash20[20];
        unsigned char script[27];
        memset(hash20, 0xbb, 20);
        script[0] = 0x82;
        script[1] = 0x01; script[2] = 0x20;
        script[3] = 0x88;
        script[4] = 0xa9; /* OP_HASH160 */
        script[5] = 0x14;
        memcpy(script + 6, hash20, 20);
        script[26] = 0x87;
        ret = ms_node_from_script(script, 27, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_HASH160);
        CHECK(output->data_len == 20);
        CHECK(memcmp(output->data, hash20, 20) == 0);
        ms_node_free(output); output = NULL;
    }

    /* Error: truncated sha256 (missing OP_EQUAL at end) */
    {
        unsigned char hash32[32];
        unsigned char script[38];
        memset(hash32, 0xaa, 32);
        script[0] = 0x82;
        script[1] = 0x01; script[2] = 0x20;
        script[3] = 0x88;
        script[4] = 0xa8;
        script[5] = 0x20;
        memcpy(script + 6, hash32, 32);
        /* deliberately omit the trailing 0x87 */
        ret = ms_node_from_script(script, 38, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Error: wrong hash length (31-byte push instead of 32) */
    {
        unsigned char script[39];
        script[0] = 0x82;
        script[1] = 0x01; script[2] = 0x20;
        script[3] = 0x88;
        script[4] = 0xa8; /* OP_SHA256 */
        script[5] = 0x1f; /* push 31 bytes (invalid) */
        memset(script + 6, 0xaa, 31);
        script[37] = 0x87;
        script[38] = 0x00; /* padding to keep length same */
        ret = ms_node_from_script(script, 38, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    return ok;
}

static bool test_decode_multi(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* multi(2, pk1, pk2, pk3): OP_2 push33(pk1) push33(pk2) push33(pk3) OP_3 OP_CHECKMULTISIG */
    {
        unsigned char pk1[33], pk2[33], pk3[33];
        unsigned char script[1 + 34 + 34 + 34 + 1 + 1];
        size_t off = 0;
        fill_key33(pk1, 0x02);
        fill_key33(pk2, 0x03);
        fill_key33(pk3, 0x04);
        script[off++] = OP_2;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk2, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk3, 33); off += 33;
        script[off++] = OP_3;
        script[off++] = OP_CHECKMULTISIG;
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_MULTI);
        CHECK(output->number == 2);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->data_len == 33);
        CHECK(memcmp(output->child->data, pk1, 33) == 0);
        CHECK(output->child->next != NULL);
        CHECK(memcmp(output->child->next->data, pk2, 33) == 0);
        CHECK(output->child->next->next != NULL);
        CHECK(memcmp(output->child->next->next->data, pk3, 33) == 0);
        CHECK(output->child->next->next->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* multi(1, pk1): single key, threshold 1 (boundary) */
    {
        unsigned char pk1[33];
        unsigned char script[1 + 34 + 1 + 1];
        size_t off = 0;
        fill_key33(pk1, 0xaa);
        script[off++] = OP_1;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = OP_1;
        script[off++] = OP_CHECKMULTISIG;
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_MULTI);
        CHECK(output->number == 1);
        CHECK(output->child != NULL);
        CHECK(output->child->data_len == 33);
        CHECK(memcmp(output->child->data, pk1, 33) == 0);
        CHECK(output->child->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* Error path: k > n (k=3, n=2) → WALLY_EINVAL */
    {
        unsigned char pk1[33], pk2[33];
        unsigned char script[1 + 34 + 34 + 1 + 1];
        size_t off = 0;
        fill_key33(pk1, 0x02);
        fill_key33(pk2, 0x03);
        script[off++] = OP_3;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk2, 33); off += 33;
        script[off++] = OP_2;
        script[off++] = OP_CHECKMULTISIG;
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    return ok;
}

static bool test_decode_multi_a(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* multi_a(2, K1, K2, K3): K1 OP_CHECKSIG K2 OP_CHECKSIGADD K3 OP_CHECKSIGADD OP_2 OP_NUMEQUAL */
    {
        sb_t s = { {0}, 0 };
        sb_key32(&s, 0x01); sb_op(&s, OP_CHECKSIG);
        sb_key32(&s, 0x02); sb_op(&s, OP_CHECKSIGADD);
        sb_key32(&s, 0x03); sb_op(&s, OP_CHECKSIGADD);
        sb_op(&s, OP_2);
        sb_op(&s, OP_NUMEQUAL);
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_MULTI_A);
        CHECK(output->number == 2);
        CHECK(output->type_properties == (TYPE_B | PROP_D | PROP_U));
        CHECK(key_is(output->child, 0x01, 32));
        CHECK(output->child->flags & WALLY_MS_IS_X_ONLY);
        CHECK(key_is(output->child->next, 0x02, 32));
        CHECK(output->child->next->flags & WALLY_MS_IS_X_ONLY);
        CHECK(key_is(output->child->next->next, 0x03, 32));
        CHECK(output->child->next->next->next == NULL);
        ms_node_free(output); output = NULL;

        /* OP_CHECKSIGADD does not exist outside tapscript */
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* multi_a(1, K1): minimum valid (k=1, n=1) */
    {
        sb_t s = { {0}, 0 };
        sb_key32(&s, 0xaa); sb_op(&s, OP_CHECKSIG);
        sb_op(&s, OP_1);
        sb_op(&s, OP_NUMEQUAL);
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_MULTI_A);
        CHECK(output->number == 1);
        CHECK(key_is(output->child, 0xaa, 32));
        CHECK(output->child->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* Error: k > n (k=3, n=2) */
    {
        sb_t s = { {0}, 0 };
        sb_key32(&s, 0x02); sb_op(&s, OP_CHECKSIG);
        sb_key32(&s, 0x03); sb_op(&s, OP_CHECKSIGADD);
        sb_op(&s, OP_3);
        sb_op(&s, OP_NUMEQUAL);
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Error: OP_CHECKMULTISIG is disabled in tapscript (BIP-342) */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_1);
        sb_key33(&s, 0x02);
        sb_op(&s, OP_1);
        sb_op(&s, OP_CHECKMULTISIG);
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    return ok;
}

static bool test_decode_and_v(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* and_v(v:older(100), c:pk_h(B)):
     * script: <100> OP_CSV OP_VERIFY OP_DUP OP_HASH160 <hash20> OP_EQUALVERIFY OP_CHECKSIG
     * Tree: AND_V( VERIFY(OLDER(100)), CHECK(PK_H) ) */
    {
        sb_t s = { {0}, 0 };
        unsigned char hash[20];
        memset(hash, 0xbb, 20);
        sb_older(&s, 100);
        sb_op(&s, OP_VERIFY);
        sb_op(&s, OP_DUP); sb_op(&s, OP_HASH160);
        sb_push(&s, hash, 20);
        sb_op(&s, OP_EQUALVERIFY);
        sb_op(&s, OP_CHECKSIG);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_AND_V);
        /* and_v(Vz, Bndu) = Bnu */
        CHECK(output->type_properties == (TYPE_B | PROP_N | PROP_U));
        /* left child = v:older(100) = VERIFY wrapping OLDER */
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_VERIFY);
        CHECK(output->child->type_properties == (TYPE_V | PROP_Z));
        CHECK(output->child->child != NULL);
        CHECK(output->child->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->child->number == 100);
        /* right child = c:pk_h */
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_CHECK);
        CHECK(output->child->next->child != NULL);
        CHECK(output->child->next->child->kind == KIND_MINISCRIPT_PK_H);
        CHECK(output->child->next->child->data_len == 20);
        CHECK(memcmp(output->child->next->child->data, hash, 20) == 0);
        CHECK(output->child->next->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* Chained and_v: script [v:after(500)] [v:older(100)] [c:pk_k(C)]
     * Decoder produces left-associative form (as Bitcoin Core does):
     *   AND_V( AND_V(VERIFY(AFTER(500)), VERIFY(OLDER(100))), CHECK(PK_K(C)) ) */
    {
        sb_t s = { {0}, 0 };
        sb_num(&s, 500);
        sb_op(&s, OP_CHECKLOCKTIMEVERIFY);
        sb_op(&s, OP_VERIFY);
        sb_older(&s, 100);
        sb_op(&s, OP_VERIFY);
        sb_cpk(&s, 0xcc);
        CHECK(s.buf[0] == 0x02 && s.buf[1] == 0xF4 && s.buf[2] == 0x01); /* 500 LE */
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        /* outer AND_V */
        CHECK(output->kind == KIND_MINISCRIPT_AND_V);
        /* outer left = inner AND_V( v:after(500), v:older(100) ), type Vz */
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_AND_V);
        CHECK(output->child->type_properties == (TYPE_V | PROP_Z));
        CHECK(output->child->child != NULL);
        CHECK(output->child->child->kind == KIND_MINISCRIPT_VERIFY);
        CHECK(output->child->child->child != NULL);
        CHECK(output->child->child->child->kind == KIND_MINISCRIPT_AFTER);
        CHECK(output->child->child->child->number == 500);
        CHECK(output->child->child->next != NULL);
        CHECK(output->child->child->next->kind == KIND_MINISCRIPT_VERIFY);
        CHECK(output->child->child->next->child != NULL);
        CHECK(output->child->child->next->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->child->next->child->number == 100);
        /* outer right = c:pk_k(C) */
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child->next->child, 0xcc, 33));
        ms_node_free(output); output = NULL;
    }

    return ok;
}

static bool test_decode_and_b(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* and_b(older(100), s:c:pk_k(A)):
     * script: <100> OP_CSV OP_SWAP <A> OP_CHECKSIG OP_BOOLAND
     * Tree: AND_B( OLDER(100), SWAP(CHECK(PK_K(A))) ) */
    {
        sb_t s = { {0}, 0 };
        sb_older(&s, 100);
        sb_op(&s, OP_SWAP);
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_BOOLAND);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_AND_B);
        CHECK(output->type_properties == (TYPE_B | PROP_U));
        /* left (B) = older(100) */
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->number == 100);
        /* right (W) = s:c:pk_k(A) = SWAP wrapping CHECK wrapping PK_K */
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_SWAP);
        CHECK(output->child->next->type_properties == (TYPE_W | PROP_D | PROP_U));
        CHECK(output->child->next->child != NULL);
        CHECK(output->child->next->child->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child->next->child->child, 0x02, 33));
        ms_node_free(output); output = NULL;
    }

    /* and_b(older(100), a:c:pk_k(A)):
     * script: <100> OP_CSV OP_TOALTSTACK <A> OP_CHECKSIG OP_FROMALTSTACK OP_BOOLAND
     * Tree: AND_B( OLDER(100), ALT(CHECK(PK_K(A))) ) */
    {
        sb_t s = { {0}, 0 };
        sb_older(&s, 100);
        sb_op(&s, OP_TOALTSTACK);
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_FROMALTSTACK);
        sb_op(&s, OP_BOOLAND);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_AND_B);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_ALT);
        CHECK(output->child->next->type_properties == (TYPE_W | PROP_D | PROP_U));
        CHECK(output->child->next->child != NULL);
        CHECK(output->child->next->child->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child->next->child->child, 0x02, 33));
        ms_node_free(output); output = NULL;
    }

    return ok;
}

static bool test_decode_or_b(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    sb_t s = { {0}, 0 };

    /* or_b(c:pk_k(A), s:c:pk_k(B)): <A> OP_CHECKSIG OP_SWAP <B> OP_CHECKSIG OP_BOOLOR */
    sb_cpk(&s, 0x02);
    sb_op(&s, OP_SWAP);
    sb_cpk(&s, 0x03);
    sb_op(&s, OP_BOOLOR);
    ret = decode(&s, 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_OR_B);
    CHECK(output->type_properties == (TYPE_B | PROP_D | PROP_U));
    /* left (B) = c:pk_k(A) */
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_CHECK);
    CHECK(key_is(output->child->child, 0x02, 33));
    /* right (W) = s:c:pk_k(B) */
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_SWAP);
    CHECK(output->child->next->child != NULL);
    CHECK(output->child->next->child->kind == KIND_MINISCRIPT_CHECK);
    CHECK(key_is(output->child->next->child->child, 0x03, 33));
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_or_c(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    sb_t s = { {0}, 0 };

    /* or_c is of type V so it can only appear under and_v; t:or_c(X,Z) is
     * and_v(or_c(X,Z),1):
     * t:or_c(c:pk_k(A), v:older(100)): <A> OP_CHECKSIG OP_NOTIF <100> OP_CSV OP_VERIFY OP_ENDIF OP_1 */
    sb_cpk(&s, 0x03);
    sb_op(&s, OP_NOTIF);
    sb_older(&s, 100);
    sb_op(&s, OP_VERIFY);
    sb_op(&s, OP_ENDIF);
    sb_op(&s, OP_1);
    ret = decode(&s, 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_AND_V);
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_OR_C);
    /* or_c(Bondu, Vz) = Vo */
    CHECK(output->child->type_properties == (TYPE_V | PROP_O));
    CHECK(output->child->child != NULL);
    CHECK(output->child->child->kind == KIND_MINISCRIPT_CHECK);
    CHECK(key_is(output->child->child->child, 0x03, 33));
    CHECK(output->child->child->next != NULL);
    CHECK(output->child->child->next->kind == KIND_MINISCRIPT_VERIFY);
    CHECK(output->child->child->next->child != NULL);
    CHECK(output->child->child->next->child->kind == KIND_MINISCRIPT_OLDER);
    CHECK(output->child->child->next->child->number == 100);
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_JUST_1);
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_or_d(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    sb_t s = { {0}, 0 };

    /* or_d(c:pk_k(A), older(100)): <A> OP_CHECKSIG OP_IFDUP OP_NOTIF <100> OP_CSV OP_ENDIF */
    sb_cpk(&s, 0x04);
    sb_op(&s, OP_IFDUP);
    sb_op(&s, OP_NOTIF);
    sb_older(&s, 100);
    sb_op(&s, OP_ENDIF);
    ret = decode(&s, 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_OR_D);
    /* or_d(Bondu, Bz) = Bo */
    CHECK(output->type_properties == (TYPE_B | PROP_O));
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_CHECK);
    CHECK(key_is(output->child->child, 0x04, 33));
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_OLDER);
    CHECK(output->child->next->number == 100);
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_or_i(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    sb_t s = { {0}, 0 };

    /* or_i(older(100), c:pk_k(A)): OP_IF <100> OP_CSV OP_ELSE <A> OP_CHECKSIG OP_ENDIF */
    sb_op(&s, OP_IF);
    sb_older(&s, 100);
    sb_op(&s, OP_ELSE);
    sb_cpk(&s, 0x05);
    sb_op(&s, OP_ENDIF);
    ret = decode(&s, 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_OR_I);
    /* or_i(Bz, Bondu) = Bd */
    CHECK(output->type_properties == (TYPE_B | PROP_D));
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
    CHECK(output->child->number == 100);
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_CHECK);
    CHECK(key_is(output->child->next->child, 0x05, 33));
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_andor(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    sb_t s = { {0}, 0 };

    /* andor(c:pk_k(A), older(100), c:pk_k(B)):
     * <A> OP_CHECKSIG OP_NOTIF <B> OP_CHECKSIG OP_ELSE <100> OP_CSV OP_ENDIF */
    sb_cpk(&s, 0x02);
    sb_op(&s, OP_NOTIF);
    sb_cpk(&s, 0x03);
    sb_op(&s, OP_ELSE);
    sb_older(&s, 100);
    sb_op(&s, OP_ENDIF);
    ret = decode(&s, 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_ANDOR);
    /* andor(Bondu, Bz, Bondu) = Bd */
    CHECK(output->type_properties == (TYPE_B | PROP_D));
    /* child X = c:pk_k(A) */
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_CHECK);
    CHECK(key_is(output->child->child, 0x02, 33));
    /* Y = older(100) (true branch) */
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_OLDER);
    CHECK(output->child->next->number == 100);
    /* Z = c:pk_k(B) (false branch) */
    CHECK(output->child->next->next != NULL);
    CHECK(output->child->next->next->kind == KIND_MINISCRIPT_CHECK);
    CHECK(key_is(output->child->next->next->child, 0x03, 33));
    CHECK(output->child->next->next->next == NULL);
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_thresh(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* thresh(2, c:pk_k(A), s:c:pk_k(B)):
     * script: <A> OP_CHECKSIG OP_SWAP <B> OP_CHECKSIG OP_ADD OP_2 OP_EQUAL
     * Tree: THRESH(2, CHECK(PK_K(A)), SWAP(CHECK(PK_K(B)))) */
    {
        sb_t s = { {0}, 0 };
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_SWAP);
        sb_cpk(&s, 0x03);
        sb_op(&s, OP_ADD);
        sb_op(&s, OP_2);
        sb_op(&s, OP_EQUAL);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_THRESH);
        CHECK(output->number == 2);
        CHECK(output->type_properties == (TYPE_B | PROP_D | PROP_U));
        /* first child = c:pk_k(A) (base expr) */
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child->child, 0x02, 33));
        /* second child = s:c:pk_k(B) (W expr) */
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_SWAP);
        CHECK(output->child->next->child != NULL);
        CHECK(output->child->next->child->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child->next->child->child, 0x03, 33));
        CHECK(output->child->next->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* thresh(3, c:pk_k(A), s:c:pk_k(B), s:c:pk_k(C)) */
    {
        sb_t s = { {0}, 0 };
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_SWAP);
        sb_cpk(&s, 0x03);
        sb_op(&s, OP_ADD);
        sb_op(&s, OP_SWAP);
        sb_cpk(&s, 0x04);
        sb_op(&s, OP_ADD);
        sb_op(&s, OP_3);
        sb_op(&s, OP_EQUAL);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_THRESH);
        CHECK(output->number == 3);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child->child, 0x02, 33));
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_SWAP);
        CHECK(key_is(output->child->next->child->child, 0x03, 33));
        CHECK(output->child->next->next != NULL);
        CHECK(output->child->next->next->kind == KIND_MINISCRIPT_SWAP);
        CHECK(key_is(output->child->next->next->child->child, 0x04, 33));
        CHECK(output->child->next->next->next == NULL);
        ms_node_free(output); output = NULL;
    }

    return ok;
}

static bool test_decode_wrappers(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* c:pk_k(A) = <A> OP_CHECKSIG */
    {
        sb_t s = { {0}, 0 };
        sb_cpk(&s, 0x02);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_CHECK);
        CHECK(output->type_properties == (TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U));
        CHECK(key_is(output->child, 0x02, 33));
        ms_node_free(output); output = NULL;
    }

    /* n:older(100) = <100> OP_CSV OP_0NOTEQUAL */
    {
        unsigned char script[] = { 0x01, 0x64, OP_CHECKSEQUENCEVERIFY, OP_0NOTEQUAL };
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_ZERO_NOT_EQUAL);
        CHECK(output->type_properties == (TYPE_B | PROP_Z | PROP_U));
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->number == 100);
        ms_node_free(output); output = NULL;
    }

    /* d:v:older(100) = OP_DUP OP_IF <100> OP_CSV OP_VERIFY OP_ENDIF */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_DUP);
        sb_op(&s, OP_IF);
        sb_older(&s, 100);
        sb_op(&s, OP_VERIFY);
        sb_op(&s, OP_ENDIF);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_DUP_IF);
        /* d: is Bond in segwit v0 ... */
        CHECK(output->type_properties == (TYPE_B | PROP_O | PROP_N | PROP_D));
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_VERIFY);
        CHECK(output->child->child != NULL);
        CHECK(output->child->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->child->number == 100);
        ms_node_free(output); output = NULL;
        /* ... and gains u under tapscript (MINIMALIF) */
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->type_properties == (TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U));
        ms_node_free(output); output = NULL;
    }

    /* j:c:pk_k(A) = OP_SIZE OP_0NOTEQUAL OP_IF <A> OP_CHECKSIG OP_ENDIF */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_SIZE);
        sb_op(&s, OP_0NOTEQUAL);
        sb_op(&s, OP_IF);
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_ENDIF);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_NON_ZERO);
        CHECK(output->type_properties == (TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U));
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child->child, 0x02, 33));
        ms_node_free(output); output = NULL;
    }

    /* t:v:older(100) = <100> OP_CSV OP_VERIFY OP_1 */
    {
        unsigned char script[] = { 0x01, 0x64, OP_CHECKSEQUENCEVERIFY, OP_VERIFY, OP_1 };
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_AND_V);
        CHECK(output->type_properties == (TYPE_B | PROP_Z | PROP_U));
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_VERIFY);
        CHECK(output->child->child != NULL);
        CHECK(output->child->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->child->number == 100);
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_JUST_1);
        CHECK(output->child->next->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* l:c:pk_k(A) = OP_IF OP_0 OP_ELSE <A> OP_CHECKSIG OP_ENDIF */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_IF);
        sb_op(&s, OP_0);
        sb_op(&s, OP_ELSE);
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_ENDIF);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_OR_I);
        CHECK(output->type_properties == (TYPE_B | PROP_D | PROP_U));
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_JUST_0);
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child->next->child, 0x02, 33));
        ms_node_free(output); output = NULL;
    }

    /* u:c:pk_k(A) = OP_IF <A> OP_CHECKSIG OP_ELSE OP_0 OP_ENDIF */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_IF);
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_ELSE);
        sb_op(&s, OP_0);
        sb_op(&s, OP_ENDIF);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_OR_I);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_CHECK);
        CHECK(key_is(output->child->child, 0x02, 33));
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_JUST_0);
        ms_node_free(output); output = NULL;
    }

    return ok;
}

static bool test_decode_negative(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* Tokenizer-level: OP_1NEGATE alone */
    {
        unsigned char script[] = { OP_1NEGATE };
        ret = ms_node_from_script(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Tokenizer-level: truncated push (0x21 claims 33 bytes but script ends) */
    {
        unsigned char script[] = { 0x21 };
        ret = ms_node_from_script(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Tokenizer-level: OP_RESERVED (0x50) — unknown opcode */
    {
        unsigned char script[] = { OP_RESERVED };
        ret = ms_node_from_script(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Tokenizer-level: a digest pushed with OP_PUSHDATA1 is a non-minimal push */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_SIZE); sb_num(&s, 32); sb_op(&s, OP_EQUALVERIFY);
        sb_op(&s, OP_SHA256);
        sb_op(&s, OP_PUSHDATA1); sb_op(&s, 32); memset(s.buf + s.len, 0x11, 32); s.len += 32;
        sb_op(&s, OP_EQUAL);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Decoder-level: single OP_CHECKSIG — no preceding expression to wrap */
    {
        unsigned char script[] = { OP_CHECKSIG };
        ret = ms_node_from_script(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Decoder-level: empty script — NT_EXPRESSION gets NULL from tk_cursor_peek */
    {
        ret = ms_node_from_script(NULL, 0, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Argument checks: NULL script with a length, NULL output */
    {
        unsigned char script[] = { OP_1 };
        ret = ms_node_from_script(NULL, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        ret = ms_node_from_script(script, 1, 0, NULL);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Script size limits follow Bitcoin Core: 3600 bytes for segwit v0 (P2WSH
     * standardness), 329482 for tapscript. The scripts are valid, key-free
     * and_v chains of v:older(100) (4 bytes each) ending in a B fragment. */
    {
        static unsigned char big[MS_DECODE_MAX_SCRIPT_LEN_TAPSCRIPT + 1];
        static const unsigned char v_older[4] = { 0x01, 0x64, OP_CHECKSEQUENCEVERIFY, OP_VERIFY };
        static const unsigned char after500[4] = { 0x02, 0xF4, 0x01, OP_CHECKLOCKTIMEVERIFY };
        static const unsigned char older16[2] = { OP_16, OP_CHECKSEQUENCEVERIFY };
        const size_t v0_max = MS_DECODE_MAX_SCRIPT_LEN_SEGWIT_V0;
        const size_t tap_max = MS_DECODE_MAX_SCRIPT_LEN_TAPSCRIPT;
        size_t i;

        for (i = 0; i < sizeof(big); ++i)
            big[i] = v_older[i % 4];

        /* Segwit v0: 3600 = 899 x v:older(100) + after(500): exactly the
         * limit is fine, one more byte is not */
        memcpy(big + v0_max - 4, after500, 4);
        ret = ms_node_from_script(big, v0_max, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output && output->kind == KIND_MINISCRIPT_AND_V);
        CHECK(output && output->type_properties == (TYPE_B | PROP_Z));
        ms_node_free(output); output = NULL;
        ret = ms_node_from_script(big, v0_max + 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);

        /* A 3604-byte chain is over the segwit v0 limit but fine in tapscript */
        memcpy(big + v0_max - 4, v_older, 4);
        memcpy(big + v0_max, after500, 4);
        ret = ms_node_from_script(big, v0_max + 4, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        ret = ms_node_from_script(big, v0_max + 4, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output && output->kind == KIND_MINISCRIPT_AND_V);
        ms_node_free(output); output = NULL;
        memcpy(big + v0_max, v_older, 4);

        /* Tapscript: 329482 = 82370 x v:older(100) + older(16): exactly the
         * limit is fine, one more byte is not */
        memcpy(big + tap_max - 2, older16, 2);
        ret = ms_node_from_script(big, tap_max, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output && output->kind == KIND_MINISCRIPT_AND_V);
        CHECK(output && output->type_properties == (TYPE_B | PROP_Z));
        ms_node_free(output); output = NULL;
        ret = ms_node_from_script(big, tap_max + 1, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Decoder-level: pk_k then stray OP_CHECKSIG — is_and_v triggers NT_EXPRESSION
     * which finds no further expression after consuming TK_CHECK_SIG */
    {
        unsigned char script[35];
        script[0] = OP_CHECKSIG;
        script[1] = 0x21;
        memset(script + 2, 0x02, 33);
        ret = ms_node_from_script(script, 35, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Semantic: multi(0, pk1) — k=0 rejected */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_0);
        sb_key33(&s, 0x02);
        sb_op(&s, OP_1);
        sb_op(&s, OP_CHECKMULTISIG);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Semantic: multi(3, pk1, pk2) — k > n rejected */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_3);
        sb_key33(&s, 0x02);
        sb_key33(&s, 0x03);
        sb_op(&s, OP_2);
        sb_op(&s, OP_CHECKMULTISIG);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Semantic: thresh(0, c:pk_k(A)) — k=0 rejected */
    {
        sb_t s = { {0}, 0 };
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_0);
        sb_op(&s, OP_EQUAL);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Semantic: thresh(3, c:pk_k(A), s:c:pk_k(B)) — k=3 > n=2 rejected */
    {
        sb_t s = { {0}, 0 };
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_SWAP);
        sb_cpk(&s, 0x03);
        sb_op(&s, OP_ADD);
        sb_op(&s, OP_3);
        sb_op(&s, OP_EQUAL);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Tokenizer-level: v:multi_a encoded as NUMEQUAL VERIFY instead of
     * NUMEQUALVERIFY is a non-minimal VERIFY sequence */
    {
        sb_t s = { {0}, 0 };
        sb_key32(&s, 0x01); sb_op(&s, OP_CHECKSIG);
        sb_op(&s, OP_1);
        sb_op(&s, OP_NUMEQUAL); sb_op(&s, OP_VERIFY);
        sb_op(&s, OP_1);
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
        /* The canonical encoding decodes as t:v:multi_a(1,K) */
        s.len -= 3;
        sb_op(&s, OP_NUMEQUALVERIFY); sb_op(&s, OP_1);
        ret = decode(&s, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output && output->kind == KIND_MINISCRIPT_AND_V);
        CHECK(output && output->child->kind == KIND_MINISCRIPT_VERIFY);
        CHECK(output && output->child->child->kind == KIND_MINISCRIPT_MULTI_A);
        ms_node_free(output); output = NULL;
    }

    /* Tokenizer-level: a 33-byte push that is not a syntactically valid
     * compressed key (prefix 0x11) is not a key */
    {
        unsigned char script[35];
        script[0] = 0x21;
        memset(script + 1, 0x11, 33);
        script[34] = OP_CHECKSIG;
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Semantic: older(0)/after(0) — BIP-379 requires 1 <= n < 2^31 */
    {
        unsigned char script[] = { OP_0, OP_CHECKSEQUENCEVERIFY };
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
        script[1] = OP_CHECKLOCKTIMEVERIFY;
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Unconsumed leading tokens: {OP_IF, OP_1} previously mis-decoded as `1` */
    {
        unsigned char script[] = { OP_IF, OP_1 };
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Unconsumed leading tokens: {OP_SWAP, OP_1} */
    {
        unsigned char script[] = { OP_SWAP, OP_1 };
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Positive control: a lone OP_1 still decodes to `1` */
    {
        unsigned char script[] = { OP_1 };
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output && output->kind == KIND_MINISCRIPT_JUST_1);
        CHECK(output->type_properties == (TYPE_B | PROP_Z | PROP_U));
        ms_node_free(output); output = NULL;
    }

    return ok;
}

/* Scripts that are grammatically decodable but violate the BIP-379 typing
 * rules. Each must be rejected by the post-decode type check. */
static bool test_typecheck_negative(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* or_b(after(1), s:after(2)): or_b needs X to be Bd, Z to be Wd; after is Bz */
    {
        sb_t s = { {0}, 0 };
        sb_num(&s, 1); sb_op(&s, OP_CHECKLOCKTIMEVERIFY);
        sb_op(&s, OP_SWAP);
        sb_num(&s, 2); sb_op(&s, OP_CHECKLOCKTIMEVERIFY);
        sb_op(&s, OP_BOOLOR);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* v:older(100) alone: type V at the top level */
    {
        unsigned char script[] = { 0x01, 0x64, OP_CHECKSEQUENCEVERIFY, OP_VERIFY };
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* and_v(older(1), 1): and_v needs X to be V */
    {
        unsigned char script[] = { OP_1, OP_CHECKSEQUENCEVERIFY, OP_1 };
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* or_i(c:pk_k(A), pk_k(B)): branches must have the same type (B vs K) */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_IF);
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_ELSE);
        sb_key33(&s, 0x03);
        sb_op(&s, OP_ENDIF);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* and_b(older(100), s:pk_k(A)): s: needs Bo, pk_k is K */
    {
        sb_t s = { {0}, 0 };
        sb_older(&s, 100);
        sb_op(&s, OP_SWAP);
        sb_key33(&s, 0x02);
        sb_op(&s, OP_BOOLAND);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* or_d(older(100), c:pk_k(A)): or_d needs X to be Bdu, older is Bz */
    {
        sb_t s = { {0}, 0 };
        sb_older(&s, 100);
        sb_op(&s, OP_IFDUP);
        sb_op(&s, OP_NOTIF);
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_ENDIF);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* or_c(c:pk_k(A), older(100)) under t:: or_c needs Z to be V */
    {
        sb_t s = { {0}, 0 };
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_NOTIF);
        sb_older(&s, 100);
        sb_op(&s, OP_ENDIF);
        sb_op(&s, OP_1);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* andor(older(100), c:pk_k(A), c:pk_k(B)): andor needs X to be Bdu */
    {
        sb_t s = { {0}, 0 };
        sb_older(&s, 100);
        sb_op(&s, OP_NOTIF);
        sb_cpk(&s, 0x03);
        sb_op(&s, OP_ELSE);
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_ENDIF);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* thresh(2, older(100), s:c:pk_k(A)): thresh needs X1 to be Bdu */
    {
        sb_t s = { {0}, 0 };
        sb_older(&s, 100);
        sb_op(&s, OP_SWAP);
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_ADD);
        sb_op(&s, OP_2);
        sb_op(&s, OP_EQUAL);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* d:pk_k(A): d: needs Vz */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_DUP);
        sb_op(&s, OP_IF);
        sb_key33(&s, 0x02);
        sb_op(&s, OP_ENDIF);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* j:older(100): j: needs Bn, older is Bz */
    {
        sb_t s = { {0}, 0 };
        sb_op(&s, OP_SIZE);
        sb_op(&s, OP_0NOTEQUAL);
        sb_op(&s, OP_IF);
        sb_older(&s, 100);
        sb_op(&s, OP_ENDIF);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* c:older(100): c: needs K */
    {
        unsigned char script[] = { 0x01, 0x64, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG };
        ret = ms_node_from_script(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* s:older(100) in and_b: s: needs Bo, older is Bz */
    {
        sb_t s = { {0}, 0 };
        sb_cpk(&s, 0x02);
        sb_op(&s, OP_SWAP);
        sb_older(&s, 100);
        sb_op(&s, OP_BOOLAND);
        ret = decode(&s, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    return ok;
}

/* Round-trip the BIP-379 reference vectors (from rust-miniscript, see
 * src/data/bip379/miniscript_vectors.json) through the string parser and
 * script generator, then decode the resulting script. Every vector must decode
 * to a B-typed tree: any false rejection by the type checker shows up here. */
static bool test_decode_vectors(void)
{
    /* H placeholders substituted as in test/test_bip379_vectors.py */
#define H32 "9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2"
#define H20 "d0721279e70d39fb4aa409b52839a0056454e3b5"
    static const char *const segwit_vectors[] = {
        "and_b(lltvln:after(1231488000),s:pk(03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
        "uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))",
        "or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))",
        "j:and_v(vdv:after(1567547623),older(16))",
        "t:and_v(vu:hash256(" H32 "),v:sha256(" H32 "))",
        "t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(" H32 "))",
        "or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))",
        "or_d(sha256(" H32 "),and_n(un:after(499999999),older(4194305)))",
        "and_v(or_i(v:multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb),v:multi(2,03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)),sha256(" H32 "))",
        "j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))",
        "and_b(older(16),s:or_d(sha256(" H32 "),n:after(1567547623)))",
        "j:and_v(v:ripemd160(" H20 "),or_d(sha256(" H32 "),older(16)))",
        "and_b(hash256(" H32 "),a:and_b(hash256(" H32 "),a:older(1)))",
        "thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))",
        "and_n(sha256(" H32 "),t:or_i(v:older(4252898),v:older(16)))",
        "or_d(nd:and_v(v:older(4252898),v:older(4252898)),sha256(" H32 "))",
        "c:and_v(or_c(sha256(" H32 "),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk_k(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
        "c:and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(" H20 ")),pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        "and_v(andor(hash256(" H32 "),v:hash256(" H32 "),v:older(50000)),after(1231488000))",
        "andor(hash256(" H32 "),j:and_v(v:ripemd160(" H20 "),older(4194305)),ripemd160(" H20 "))",
        "or_i(c:and_v(v:after(500000),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(" H32 "))",
        "thresh(2,c:pk_h(025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(" H32 "),a:ripemd160(" H20 "))",
        "and_n(sha256(" H32 "),uc:and_v(v:older(16),pk_k(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))",
        "and_n(c:pk_k(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(15),a:older(16)))",
        "c:or_i(and_v(v:older(16),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)),pk_h(026a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4))",
        "or_d(c:pk_h(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))",
        "c:andor(ripemd160(" H20 "),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e),and_v(v:hash256(" H32 "),pk_h(03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)))",
        "c:andor(u:ripemd160(" H20 "),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),or_i(pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)))",
        "c:or_i(andor(c:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))",
        "multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00)",
        "multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00)",
        "thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00))",
        "c:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)",
    };
    /* Tapscript leaves (x-only keys: the x coordinates of the keys above),
     * given as single-leaf tr() descriptors since multi_a() and x-only pkh()
     * are only valid inside a tapscript tree */
#define XA "d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"
#define XB "5601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc"
#define TR(leaf) "tr(" XA "," leaf ")"
    static const char *const tapscript_vectors[] = {
        TR("pk(" XA ")"),
        TR("multi_a(2," XA "," XB ")"),
        TR("and_v(v:pk(" XA "),older(144))"),
        TR("or_d(pk(" XA "),and_v(v:pkh(" XB "),after(500000)))"),
        TR("andor(pk(" XA "),multi_a(1," XB "),sha256(" H32 "))"),
        TR("thresh(2,pk(" XA "),s:pk(" XB "),sdv:older(10))"),
        TR("or_b(pk(" XA "),s:pk(" XB "))"),
        TR("j:and_v(v:hash160(" H20 "),multi_a(1," XA "," XB "))"),
    };
#undef TR
#undef XA
#undef XB
#undef H32
#undef H20
    bool ok = true;
    size_t i;

    for (i = 0; i < sizeof(segwit_vectors) / sizeof(segwit_vectors[0]) +
                    sizeof(tapscript_vectors) / sizeof(tapscript_vectors[0]); ++i) {
        const size_t n_segwit = sizeof(segwit_vectors) / sizeof(segwit_vectors[0]);
        const bool is_tapscript = i >= n_segwit;
        const char *ms = is_tapscript ? tapscript_vectors[i - n_segwit] : segwit_vectors[i];
        struct wally_descriptor *d = NULL;
        unsigned char script[1024];
        size_t written = 0;
        ms_node *output = NULL;
        int ret;

        if (is_tapscript)
            ret = wally_descriptor_parse(ms, NULL, WALLY_NETWORK_BITCOIN_MAINNET, 0, &d);
        else
            ret = wally_descriptor_parse(ms, NULL, WALLY_NETWORK_NONE, WALLY_MINISCRIPT_ONLY, &d);
        if (ret != WALLY_OK) {
            printf("FAIL: parse %s\n", ms);
            ok = false;
            continue;
        }
        if (is_tapscript)
            ret = wally_descriptor_get_taproot_leaf_script(d, 0, 0, 0, 0, script, sizeof(script), &written);
        else
            ret = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, script, sizeof(script), &written);
        wally_descriptor_free(d);
        if (ret != WALLY_OK || !written || written > sizeof(script)) {
            printf("FAIL: to_script %s\n", ms);
            ok = false;
            continue;
        }
        ret = ms_node_from_script(script, written, is_tapscript ? WALLY_MINISCRIPT_TAPSCRIPT : 0, &output);
        if (ret != WALLY_OK || !output) {
            printf("FAIL: decode %s\n", ms);
            ok = false;
            continue;
        }
        if ((output->type_properties & TYPE_MASK) != TYPE_B) {
            printf("FAIL: top level not B: %s\n", ms);
            ok = false;
        }
        ms_node_free(output);
        /* A script with a raw key never decodes in the other context: the key
         * sizes differ. (Key hashes, digests and timelocks are context-free.) */
        if (strstr(ms, "pk(") || strstr(ms, "pk_k(") || strstr(ms, "multi")) {
            ret = ms_node_from_script(script, written, is_tapscript ? 0 : WALLY_MINISCRIPT_TAPSCRIPT, &output);
            if (ret == WALLY_OK) {
                printf("FAIL: decoded in wrong context: %s\n", ms);
                ok = false;
                ms_node_free(output);
            }
        }
    }
    return ok;
}

int main(void)
{
    bool ok = true;
    if (!test_tokenize_script()) {
        printf("[test_tokenize_script] failed!\n");
        ok = false;
    }
    if (!test_decode_pk()) {
        printf("[test_decode_pk] failed!\n");
        ok = false;
    }
    if (!test_decode_hash()) {
        printf("[test_decode_hash] failed!\n");
        ok = false;
    }
    if (!test_decode_multi()) {
        printf("[test_decode_multi] failed!\n");
        ok = false;
    }
    if (!test_decode_multi_a()) {
        printf("[test_decode_multi_a] failed!\n");
        ok = false;
    }
    if (!test_decode_and_v()) {
        printf("[test_decode_and_v] failed!\n");
        ok = false;
    }
    if (!test_decode_and_b()) {
        printf("[test_decode_and_b] failed!\n");
        ok = false;
    }
    if (!test_decode_or_b()) {
        printf("[test_decode_or_b] failed!\n");
        ok = false;
    }
    if (!test_decode_or_c()) {
        printf("[test_decode_or_c] failed!\n");
        ok = false;
    }
    if (!test_decode_or_d()) {
        printf("[test_decode_or_d] failed!\n");
        ok = false;
    }
    if (!test_decode_or_i()) {
        printf("[test_decode_or_i] failed!\n");
        ok = false;
    }
    if (!test_decode_andor()) {
        printf("[test_decode_andor] failed!\n");
        ok = false;
    }
    if (!test_decode_thresh()) {
        printf("[test_decode_thresh] failed!\n");
        ok = false;
    }
    if (!test_decode_wrappers()) {
        printf("[test_decode_wrappers] failed!\n");
        ok = false;
    }
    if (!test_decode_negative()) {
        printf("[test_decode_negative] failed!\n");
        ok = false;
    }
    if (!test_typecheck_negative()) {
        printf("[test_typecheck_negative] failed!\n");
        ok = false;
    }
    if (!test_decode_vectors()) {
        printf("[test_decode_vectors] failed!\n");
        ok = false;
    }
    wally_cleanup(0);
    return ok ? 0 : 1;
}
