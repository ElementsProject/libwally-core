#include "config.h"
#include "miniscript_decode.h"
#include <wally_core.h>
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
    ret = tokenize_script(NULL, 0, tokens, MAX_TOKENS, &count);
    CHECK(ret == WALLY_OK);
    CHECK(count == 0);

    /* OP_0 */
    {
        unsigned char script[] = { OP_0 };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].data.num == 0);
    }

    /* OP_1 */
    {
        unsigned char script[] = { OP_1 };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].data.num == 1);
    }

    /* OP_16 */
    {
        unsigned char script[] = { OP_16 };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].data.num == 16);
    }

    /* OP_1NEGATE */
    {
        unsigned char script[] = { OP_1NEGATE };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Push data — 20-byte (TK_HASH20) */
    {
        unsigned char script[21];
        script[0] = 0x14; /* push 20 bytes */
        memset(script + 1, 0xab, 20);
        ret = tokenize_script(script, 21, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_HASH20);
        CHECK(memcmp(tokens[0].data.hash20, script + 1, 20) == 0);
    }

    /* Push data — 32-byte (TK_BYTES32) */
    {
        unsigned char script[33];
        script[0] = 0x20; /* push 32 bytes */
        memset(script + 1, 0xcd, 32);
        ret = tokenize_script(script, 33, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_BYTES32);
        CHECK(memcmp(tokens[0].data.bytes32, script + 1, 32) == 0);
    }

    /* Push data — 33-byte (TK_BYTES33) */
    {
        unsigned char script[34];
        script[0] = 0x21; /* push 33 bytes */
        memset(script + 1, 0xef, 33);
        ret = tokenize_script(script, 34, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_BYTES33);
        CHECK(memcmp(tokens[0].data.bytes33, script + 1, 33) == 0);
    }

    /* Push data — 65-byte (TK_BYTES65) */
    {
        unsigned char script[66];
        script[0] = 0x41; /* push 65 bytes */
        memset(script + 1, 0x04, 65);
        ret = tokenize_script(script, 66, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_BYTES65);
        CHECK(memcmp(tokens[0].data.bytes65, script + 1, 65) == 0);
    }

    /* Push data — CScriptNum: a minimally-encoded value (17, which has no
     * dedicated push opcode) tokenizes to TK_NUM. */
    {
        unsigned char script[] = { 0x01, 0x11 };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_NUM);
        CHECK(tokens[0].data.num == 17);
    }

    /* Non-minimal numeric pushes must be rejected (anti-malleability): a value
     * 0..16 must use OP_0/OP_1..OP_16, and redundant trailing bytes are invalid. */
    {
        unsigned char small[] = { 0x01, 0x05 };          /* 5 must be OP_5 */
        unsigned char trailing[] = { 0x02, 0x11, 0x00 }; /* non-minimal 17 */
        ret = tokenize_script(small, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
        ret = tokenize_script(trailing, 3, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Push data — unsupported length (5 bytes) */
    {
        unsigned char script[] = { 0x05, 0, 0, 0, 0, 0 };
        ret = tokenize_script(script, 6, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Push data — truncated (push-N but script too short) */
    {
        unsigned char script[] = { 0x14 }; /* says push 20, but nothing follows */
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* OP_PUSHDATA1 — valid (20 bytes) */
    {
        unsigned char script[22];
        script[0] = OP_PUSHDATA1;
        script[1] = 20;
        memset(script + 2, 0x11, 20);
        ret = tokenize_script(script, 22, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_HASH20);
        CHECK(memcmp(tokens[0].data.hash20, script + 2, 20) == 0);
    }

    /* OP_PUSHDATA1 — truncated (missing length byte) */
    {
        unsigned char script[] = { OP_PUSHDATA1 };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* OP_PUSHDATA2 — valid (20 bytes, little-endian length) */
    {
        unsigned char script[23];
        script[0] = OP_PUSHDATA2;
        script[1] = 20;
        script[2] = 0;
        memset(script + 3, 0x22, 20);
        ret = tokenize_script(script, 23, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_HASH20);
        CHECK(memcmp(tokens[0].data.hash20, script + 3, 20) == 0);
    }

    /* OP_PUSHDATA2 — truncated (only one length byte) */
    {
        unsigned char script[] = { OP_PUSHDATA2, 20 };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Opcode-only tokens */
    {
        unsigned char s[1];
        s[0] = OP_BOOLAND;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_BOOL_AND);

        s[0] = OP_BOOLOR;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_BOOL_OR);

        s[0] = OP_ADD;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_ADD);

        s[0] = OP_EQUAL;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_EQUAL);

        s[0] = OP_NUMEQUAL;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_NUM_EQUAL);

        s[0] = OP_CHECKSIG;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_SIG);

        s[0] = OP_CHECKSIGADD;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_SIG_ADD);

        s[0] = OP_CHECKMULTISIG;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_MULTI_SIG);

        s[0] = OP_CHECKSEQUENCEVERIFY;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_SEQUENCE_VERIFY);

        s[0] = OP_CHECKLOCKTIMEVERIFY;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_CHECK_LOCK_TIME_VERIFY);

        s[0] = OP_FROMALTSTACK;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_FROM_ALT_STACK);

        s[0] = OP_TOALTSTACK;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_TO_ALT_STACK);

        s[0] = OP_DROP;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_DROP);

        s[0] = OP_DUP;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_DUP);

        s[0] = OP_IF;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_IF);

        s[0] = OP_IFDUP;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_IF_DUP);

        s[0] = OP_NOTIF;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_NOT_IF);

        s[0] = OP_ELSE;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_ELSE);

        s[0] = OP_ENDIF;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_END_IF);

        s[0] = OP_0NOTEQUAL;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_ZERO_NOT_EQUAL);

        s[0] = OP_SIZE;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_SIZE);

        s[0] = OP_SWAP;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_SWAP);

        s[0] = OP_RIPEMD160;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_RIPEMD160);

        s[0] = OP_HASH160;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_HASH160);

        s[0] = OP_SHA256;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_SHA256);

        s[0] = OP_HASH256;
        ret = tokenize_script(s, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK && count == 1 && tokens[0].kind == TK_HASH256);
    }

    /* OP_EQUALVERIFY → TK_EQUAL, TK_VERIFY */
    {
        unsigned char script[] = { OP_EQUALVERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_EQUAL);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* OP_NUMEQUALVERIFY → TK_NUM_EQUAL, TK_VERIFY */
    {
        unsigned char script[] = { OP_NUMEQUALVERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_NUM_EQUAL);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* OP_CHECKSIGVERIFY → TK_CHECK_SIG, TK_VERIFY */
    {
        unsigned char script[] = { OP_CHECKSIGVERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_CHECK_SIG);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* OP_CHECKMULTISIGVERIFY → TK_CHECK_MULTI_SIG, TK_VERIFY */
    {
        unsigned char script[] = { OP_CHECKMULTISIGVERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_CHECK_MULTI_SIG);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* Standalone OP_VERIFY (n=0, no preceding token) */
    {
        unsigned char script[] = { OP_VERIFY };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 1);
        CHECK(tokens[0].kind == TK_VERIFY);
    }

    /* OP_SIZE, OP_VERIFY → TK_SIZE, TK_VERIFY */
    {
        unsigned char script[] = { OP_SIZE, OP_VERIFY };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 2);
        CHECK(tokens[0].kind == TK_SIZE);
        CHECK(tokens[1].kind == TK_VERIFY);
    }

    /* NonMinimalVerify: OP_EQUAL, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_EQUAL, OP_VERIFY };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* NonMinimalVerify: OP_CHECKSIG, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_CHECKSIG, OP_VERIFY };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* NonMinimalVerify: OP_CHECKMULTISIG, OP_VERIFY → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_CHECKMULTISIG, OP_VERIFY };
        ret = tokenize_script(script, 2, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Unknown opcode (OP_RESERVED = 0x50) → WALLY_EINVAL */
    {
        unsigned char script[] = { OP_RESERVED };
        ret = tokenize_script(script, 1, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Buffer overflow: OP_DUP with max_tokens = 0 */
    {
        unsigned char script[] = { OP_DUP };
        ret = tokenize_script(script, 1, tokens, 0, &count);
        CHECK(ret == WALLY_EINVAL);
    }

    /* Buffer overflow: OP_EQUALVERIFY (emits 2 tokens) with max_tokens = 1 */
    {
        unsigned char script[] = { OP_EQUALVERIFY };
        ret = tokenize_script(script, 1, tokens, 1, &count);
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
        ret = tokenize_script(script, 25, tokens, MAX_TOKENS, &count);
        CHECK(ret == WALLY_OK);
        CHECK(count == 6);
        CHECK(tokens[0].kind == TK_DUP);
        CHECK(tokens[1].kind == TK_HASH160);
        CHECK(tokens[2].kind == TK_HASH20);
        CHECK(memcmp(tokens[2].data.hash20, script + 3, 20) == 0);
        CHECK(tokens[3].kind == TK_EQUAL);
        CHECK(tokens[4].kind == TK_VERIFY);
        CHECK(tokens[5].kind == TK_CHECK_SIG);
    }

    return ok;
}

static bool test_decode_pk(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* pk_k with a 33-byte compressed pubkey: script = 0x21 <33 bytes> */
    {
        unsigned char script[34];
        unsigned char key[33];
        script[0] = 0x21;
        memset(key, 0x02, 33); /* fake compressed pubkey */
        memcpy(script + 1, key, 33);
        ret = decode_script_to_node(script, 34, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->data_len == 33);
        CHECK(memcmp(output->data, key, 33) == 0);
        ms_node_free(output); output = NULL;
    }

    /* pk_k with a 65-byte uncompressed pubkey: script = 0x41 <65 bytes> */
    {
        unsigned char script[66];
        unsigned char key[65];
        script[0] = 0x41;
        key[0] = 0x04;
        memset(key + 1, 0xab, 64);
        memcpy(script + 1, key, 65);
        ret = decode_script_to_node(script, 66, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->data_len == 65);
        CHECK(memcmp(output->data, key, 65) == 0);
        ms_node_free(output); output = NULL;
    }

    /* A bare 32-byte x-only key is NOT valid in segwit-v0 context (keys must be
     * 33-byte compressed or 65-byte uncompressed); it must be rejected. The valid
     * tapscript case is tested below. */
    {
        unsigned char script[33];
        unsigned char key[32];
        script[0] = 0x20;
        memset(key, 0xcd, 32);
        memcpy(script + 1, key, 32);
        ret = decode_script_to_node(script, 33, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* pk_h: DUP HASH160 <20-byte-hash> EQUALVERIFY
     * script = OP_DUP OP_HASH160 0x14 <20 bytes> OP_EQUALVERIFY */
    {
        unsigned char script[25];
        unsigned char hash[20];
        memset(hash, 0x77, 20);
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 0x14;
        memcpy(script + 3, hash, 20);
        script[23] = OP_EQUALVERIFY;
        ret = decode_script_to_node(script, 24, 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_PK_H);
        CHECK(output->data_len == 20);
        CHECK(memcmp(output->data, hash, 20) == 0);
        ms_node_free(output); output = NULL;
    }

    /* pk_k with a 32-byte x-only key in tapscript context: WALLY_MS_IS_X_ONLY must be set */
    {
        unsigned char script[33];
        unsigned char key[32];
        script[0] = 0x20;
        memset(key, 0xef, 32);
        memcpy(script + 1, key, 32);
        ret = decode_script_to_node(script, 33, WALLY_MINISCRIPT_TAPSCRIPT, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->data_len == 32);
        CHECK(memcmp(output->data, key, 32) == 0);
        CHECK(output->flags & WALLY_MS_IS_X_ONLY);
        ms_node_free(output); output = NULL;
    }

    /* Error: truncated script (length byte claims 33 bytes but only 1 byte total) */
    {
        unsigned char script[1];
        script[0] = 0x21; /* push 33 bytes, but nothing follows */
        ret = decode_script_to_node(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Error: wrong pubkey length (34-byte push — not a valid key size) */
    {
        unsigned char script[35];
        script[0] = 0x22; /* push 34 bytes */
        memset(script + 1, 0xab, 34);
        ret = decode_script_to_node(script, 35, 0, &output);
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
        ret = decode_script_to_node(script, 39, 0, &output);
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
        ret = decode_script_to_node(script, 39, 0, &output);
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
        ret = decode_script_to_node(script, 27, 0, &output);
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
        ret = decode_script_to_node(script, 27, 0, &output);
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
        ret = decode_script_to_node(script, 38, 0, &output);
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
        ret = decode_script_to_node(script, 38, 0, &output);
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
        memset(pk1, 0x02, 33);
        memset(pk2, 0x03, 33);
        memset(pk3, 0x04, 33);
        script[off++] = OP_2;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk2, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk3, 33); off += 33;
        script[off++] = OP_3;
        script[off++] = OP_CHECKMULTISIG;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
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
        memset(pk1, 0xaa, 33);
        script[off++] = OP_1;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = OP_1;
        script[off++] = OP_CHECKMULTISIG;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
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
        memset(pk1, 0x02, 33);
        memset(pk2, 0x03, 33);
        script[off++] = OP_3;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk2, 33); off += 33;
        script[off++] = OP_2;
        script[off++] = OP_CHECKMULTISIG;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
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
        unsigned char K1[32], K2[32], K3[32];
        unsigned char script[104];
        size_t off = 0;
        memset(K1, 0x01, 32);
        memset(K2, 0x02, 32);
        memset(K3, 0x03, 32);
        script[off++] = 0x20; memcpy(script + off, K1, 32); off += 32;
        script[off++] = OP_CHECKSIG;
        script[off++] = 0x20; memcpy(script + off, K2, 32); off += 32;
        script[off++] = OP_CHECKSIGADD;
        script[off++] = 0x20; memcpy(script + off, K3, 32); off += 32;
        script[off++] = OP_CHECKSIGADD;
        script[off++] = OP_2;
        script[off++] = OP_NUMEQUAL;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_MULTI_A);
        CHECK(output->number == 2);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->data_len == 32);
        CHECK(memcmp(output->child->data, K1, 32) == 0);
        CHECK(output->child->next != NULL);
        CHECK(memcmp(output->child->next->data, K2, 32) == 0);
        CHECK(output->child->next->next != NULL);
        CHECK(memcmp(output->child->next->next->data, K3, 32) == 0);
        CHECK(output->child->next->next->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* multi_a(1, K1): minimum valid (k=1, n=1) */
    {
        unsigned char K1[32];
        unsigned char script[36];
        size_t off = 0;
        memset(K1, 0xaa, 32);
        script[off++] = 0x20; memcpy(script + off, K1, 32); off += 32;
        script[off++] = OP_CHECKSIG;
        script[off++] = OP_1;
        script[off++] = OP_NUMEQUAL;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_MULTI_A);
        CHECK(output->number == 1);
        CHECK(output->child != NULL);
        CHECK(output->child->data_len == 32);
        CHECK(memcmp(output->child->data, K1, 32) == 0);
        CHECK(output->child->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* Error: k > n (k=3, n=2) */
    {
        unsigned char K1[32], K2[32];
        unsigned char script[70];
        size_t off = 0;
        memset(K1, 0x02, 32);
        memset(K2, 0x03, 32);
        script[off++] = 0x20; memcpy(script + off, K1, 32); off += 32;
        script[off++] = OP_CHECKSIG;
        script[off++] = 0x20; memcpy(script + off, K2, 32); off += 32;
        script[off++] = OP_CHECKSIGADD;
        script[off++] = OP_3;
        script[off++] = OP_NUMEQUAL;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
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

    /* and_v(v:older(100), pk_h(B)):
     * script: <100> OP_CSV OP_VERIFY OP_DUP OP_HASH160 <hash20> OP_EQUALVERIFY
     * Tree: AND_V( VERIFY(OLDER(100)), PK_H ) */
    {
        unsigned char hash[20];
        /* <100> = push 1 byte [0x64] */
        unsigned char script[] = {
            0x01, 0x64,                     /* push 1 byte: 100 */
            OP_CHECKSEQUENCEVERIFY,
            OP_VERIFY,
            OP_DUP, OP_HASH160,
            0x14,                           /* push 20 bytes */
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* hash20 */
            OP_EQUALVERIFY
        };
        memset(hash, 0xbb, 20);
        memcpy(script + 7, hash, 20);
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_AND_V);
        /* left child = v:older(100) = VERIFY wrapping OLDER */
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_VERIFY);
        CHECK(output->child->child != NULL);
        CHECK(output->child->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->child->number == 100);
        /* right child = pk_h */
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_PK_H);
        CHECK(output->child->next->data_len == 20);
        CHECK(memcmp(output->child->next->data, hash, 20) == 0);
        ms_node_free(output); output = NULL;
    }

    /* Chained and_v: script [v:after(500)] [v:older(100)] [pk_h(C)]
     * Decoder produces left-associative form:
     *   AND_V( AND_V(VERIFY(AFTER(500)), VERIFY(OLDER(100))), PK_H(C) ) */
    {
        unsigned char hash[20];
        /* <500> = push 2 bytes [0xF4, 0x01] (500 little-endian, no sign extension needed) */
        unsigned char script[] = {
            0x02, 0xF4, 0x01,               /* push 2 bytes: 500 */
            OP_CHECKLOCKTIMEVERIFY,
            OP_VERIFY,
            0x01, 0x64,                     /* push 1 byte: 100 */
            OP_CHECKSEQUENCEVERIFY,
            OP_VERIFY,
            OP_DUP, OP_HASH160,
            0x14,                           /* push 20 bytes */
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            OP_EQUALVERIFY
        };
        memset(hash, 0xcc, 20);
        memcpy(script + 12, hash, 20);
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        /* outer AND_V */
        CHECK(output->kind == KIND_MINISCRIPT_AND_V);
        /* outer left = inner AND_V( v:after(500), v:older(100) ) */
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_AND_V);
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
        /* outer right = pk_h */
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_PK_H);
        CHECK(output->child->next->data_len == 20);
        CHECK(memcmp(output->child->next->data, hash, 20) == 0);
        ms_node_free(output); output = NULL;
    }

    return ok;
}

static bool test_decode_and_b(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* and_b(older(100), s:pk_k(A)):
     * script: <100> OP_CSV OP_SWAP <A_33bytes> OP_BOOLAND
     * Tree: AND_B( OLDER(100), SWAP(PK_K(A)) ) */
    {
        unsigned char key[33];
        unsigned char script[2 + 1 + 1 + 1 + 33 + 1]; /* 39 bytes */
        size_t off = 0;
        memset(key, 0x02, 33);
        script[off++] = 0x01; script[off++] = 0x64; /* push 1 byte: 100 */
        script[off++] = OP_CHECKSEQUENCEVERIFY;
        script[off++] = OP_SWAP;
        script[off++] = 0x21; /* push 33 bytes */
        memcpy(script + off, key, 33); off += 33;
        script[off++] = OP_BOOLAND;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_AND_B);
        /* left (B) = older(100) */
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->number == 100);
        /* right (W) = s:pk_k(A) = SWAP wrapping PK_K */
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_SWAP);
        CHECK(output->child->next->child != NULL);
        CHECK(output->child->next->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->next->child->data_len == 33);
        CHECK(memcmp(output->child->next->child->data, key, 33) == 0);
        ms_node_free(output); output = NULL;
    }

    return ok;
}

static bool test_decode_or_b(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    unsigned char key[33];
    unsigned char script[2 + 1 + 1 + 1 + 33 + 1]; /* 39 bytes */
    size_t off = 0;
    memset(key, 0x02, 33);
    script[off++] = 0x01; script[off++] = 0x64; /* push 1 byte: 100 */
    script[off++] = OP_CHECKSEQUENCEVERIFY;
    script[off++] = OP_SWAP;
    script[off++] = 0x21; /* push 33 bytes */
    memcpy(script + off, key, 33); off += 33;
    script[off++] = OP_BOOLOR;
    ret = decode_script_to_node(script, sizeof(script), 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_OR_B);
    /* left (B) = older(100) */
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
    CHECK(output->child->number == 100);
    /* right (W) = s:pk_k(A) = SWAP wrapping PK_K */
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_SWAP);
    CHECK(output->child->next->child != NULL);
    CHECK(output->child->next->child->kind == KIND_MINISCRIPT_PK_K);
    CHECK(output->child->next->child->data_len == 33);
    CHECK(memcmp(output->child->next->child->data, key, 33) == 0);
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_or_c(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    unsigned char key[33];
    unsigned char script[2 + 1 + 1 + 1 + 33 + 1]; /* 39 bytes */
    size_t off = 0;
    memset(key, 0x03, 33);
    script[off++] = 0x01; script[off++] = 0x64;
    script[off++] = OP_CHECKSEQUENCEVERIFY;
    script[off++] = OP_NOTIF;
    script[off++] = 0x21;
    memcpy(script + off, key, 33); off += 33;
    script[off++] = OP_ENDIF;
    ret = decode_script_to_node(script, sizeof(script), 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_OR_C);
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
    CHECK(output->child->number == 100);
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_PK_K);
    CHECK(output->child->next->data_len == 33);
    CHECK(memcmp(output->child->next->data, key, 33) == 0);
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_or_d(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    unsigned char key[33];
    unsigned char script[2 + 1 + 1 + 1 + 1 + 33 + 1]; /* 40 bytes */
    size_t off = 0;
    memset(key, 0x04, 33);
    script[off++] = 0x01; script[off++] = 0x64;
    script[off++] = OP_CHECKSEQUENCEVERIFY;
    script[off++] = OP_IFDUP;
    script[off++] = OP_NOTIF;
    script[off++] = 0x21;
    memcpy(script + off, key, 33); off += 33;
    script[off++] = OP_ENDIF;
    ret = decode_script_to_node(script, sizeof(script), 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_OR_D);
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
    CHECK(output->child->number == 100);
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_PK_K);
    CHECK(output->child->next->data_len == 33);
    CHECK(memcmp(output->child->next->data, key, 33) == 0);
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_or_i(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    unsigned char key[33];
    unsigned char script[1 + 2 + 1 + 1 + 1 + 33 + 1]; /* 40 bytes */
    size_t off = 0;
    memset(key, 0x05, 33);
    script[off++] = OP_IF;
    script[off++] = 0x01; script[off++] = 0x64;
    script[off++] = OP_CHECKSEQUENCEVERIFY;
    script[off++] = OP_ELSE;
    script[off++] = 0x21;
    memcpy(script + off, key, 33); off += 33;
    script[off++] = OP_ENDIF;
    ret = decode_script_to_node(script, sizeof(script), 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_OR_I);
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
    CHECK(output->child->number == 100);
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_PK_K);
    CHECK(output->child->next->data_len == 33);
    CHECK(memcmp(output->child->next->data, key, 33) == 0);
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_andor(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;
    unsigned char keyA[33], keyB[33];
    unsigned char script[2 + 1 + 1 + 1 + 33 + 1 + 1 + 33 + 1]; /* 74 bytes */
    size_t off = 0;
    memset(keyA, 0x02, 33);
    memset(keyB, 0x03, 33);
    script[off++] = 0x01; script[off++] = 0x64;
    script[off++] = OP_CHECKSEQUENCEVERIFY;
    script[off++] = OP_NOTIF;
    script[off++] = 0x21;
    memcpy(script + off, keyB, 33); off += 33;
    script[off++] = OP_ELSE;
    script[off++] = 0x21;
    memcpy(script + off, keyA, 33); off += 33;
    script[off++] = OP_ENDIF;
    ret = decode_script_to_node(script, sizeof(script), 0, &output);
    CHECK(ret == WALLY_OK);
    CHECK(output != NULL);
    CHECK(output->kind == KIND_MINISCRIPT_ANDOR);
    /* child X = older(100) */
    CHECK(output->child != NULL);
    CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
    CHECK(output->child->number == 100);
    /* Y = pk_k(A) (true branch) */
    CHECK(output->child->next != NULL);
    CHECK(output->child->next->kind == KIND_MINISCRIPT_PK_K);
    CHECK(output->child->next->data_len == 33);
    CHECK(memcmp(output->child->next->data, keyA, 33) == 0);
    /* Z = pk_k(B) (false branch) */
    CHECK(output->child->next->next != NULL);
    CHECK(output->child->next->next->kind == KIND_MINISCRIPT_PK_K);
    CHECK(output->child->next->next->data_len == 33);
    CHECK(memcmp(output->child->next->next->data, keyB, 33) == 0);
    ms_node_free(output); output = NULL;
    return ok;
}

static bool test_decode_thresh(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* thresh(2, older(100), s:pk_k(A)):
     * script: <100> OP_CSV  OP_SWAP <A_33bytes> OP_ADD  OP_2 OP_EQUAL
     * Tree: THRESH(2, OLDER(100), SWAP(PK_K(A))) */
    {
        unsigned char keyA[33];
        unsigned char script[2 + 1 + 1 + 1 + 33 + 1 + 1 + 1]; /* 41 bytes */
        size_t off = 0;
        memset(keyA, 0x02, 33);
        script[off++] = 0x01; script[off++] = 0x64; /* push 1 byte: 100 */
        script[off++] = OP_CHECKSEQUENCEVERIFY;
        script[off++] = OP_SWAP;
        script[off++] = 0x21; memcpy(script + off, keyA, 33); off += 33;
        script[off++] = OP_ADD;
        script[off++] = OP_2;
        script[off++] = OP_EQUAL;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_THRESH);
        CHECK(output->number == 2);
        /* first child = older(100) (e, base expr) */
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->number == 100);
        /* second child = s:pk_k(A) (W expr) */
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_SWAP);
        CHECK(output->child->next->child != NULL);
        CHECK(output->child->next->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->next->child->data_len == 33);
        CHECK(memcmp(output->child->next->child->data, keyA, 33) == 0);
        CHECK(output->child->next->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* thresh(3, older(100), s:pk_k(A), s:pk_k(B)):
     * script: <100> OP_CSV  OP_SWAP <A> OP_ADD  OP_SWAP <B> OP_ADD  OP_3 OP_EQUAL
     * Tree: THRESH(3, OLDER(100), SWAP(PK_K(A)), SWAP(PK_K(B))) */
    {
        unsigned char keyA[33], keyB[33];
        unsigned char script[2 + 1 + 1 + 1 + 33 + 1 + 1 + 1 + 33 + 1 + 1 + 1]; /* 77 bytes */
        size_t off = 0;
        memset(keyA, 0x02, 33);
        memset(keyB, 0x03, 33);
        script[off++] = 0x01; script[off++] = 0x64;
        script[off++] = OP_CHECKSEQUENCEVERIFY;
        script[off++] = OP_SWAP;
        script[off++] = 0x21; memcpy(script + off, keyA, 33); off += 33;
        script[off++] = OP_ADD;
        script[off++] = OP_SWAP;
        script[off++] = 0x21; memcpy(script + off, keyB, 33); off += 33;
        script[off++] = OP_ADD;
        script[off++] = OP_3;
        script[off++] = OP_EQUAL;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_THRESH);
        CHECK(output->number == 3);
        /* first child = older(100) */
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->number == 100);
        /* second child = s:pk_k(A) */
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_SWAP);
        CHECK(output->child->next->child != NULL);
        CHECK(output->child->next->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(memcmp(output->child->next->child->data, keyA, 33) == 0);
        /* third child = s:pk_k(B) */
        CHECK(output->child->next->next != NULL);
        CHECK(output->child->next->next->kind == KIND_MINISCRIPT_SWAP);
        CHECK(output->child->next->next->child != NULL);
        CHECK(output->child->next->next->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(memcmp(output->child->next->next->child->data, keyB, 33) == 0);
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

    /* c:pk_k(A) = <A_33bytes> OP_CHECKSIG */
    {
        unsigned char key[33];
        unsigned char script[35];
        memset(key, 0x02, 33);
        script[0] = 0x21;
        memcpy(script + 1, key, 33);
        script[34] = OP_CHECKSIG;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_CHECK);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->data_len == 33);
        CHECK(memcmp(output->child->data, key, 33) == 0);
        ms_node_free(output); output = NULL;
    }

    /* n:older(100) = <100> OP_CSV OP_0NOTEQUAL */
    {
        unsigned char script[] = { 0x01, 0x64, OP_CHECKSEQUENCEVERIFY, OP_0NOTEQUAL };
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_ZERO_NOT_EQUAL);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->number == 100);
        ms_node_free(output); output = NULL;
    }

    /* d:pk_k(A) = OP_DUP OP_IF <A_33bytes> OP_ENDIF */
    {
        unsigned char key[33];
        unsigned char script[37];
        size_t off = 0;
        memset(key, 0x02, 33);
        script[off++] = OP_DUP;
        script[off++] = OP_IF;
        script[off++] = 0x21;
        memcpy(script + off, key, 33); off += 33;
        script[off++] = OP_ENDIF;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_DUP_IF);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->data_len == 33);
        CHECK(memcmp(output->child->data, key, 33) == 0);
        ms_node_free(output); output = NULL;
    }

    /* j:pk_k(A) = OP_SIZE OP_0NOTEQUAL OP_IF <A_33bytes> OP_ENDIF */
    {
        unsigned char key[33];
        unsigned char script[38];
        size_t off = 0;
        memset(key, 0x02, 33);
        script[off++] = OP_SIZE;
        script[off++] = OP_0NOTEQUAL;
        script[off++] = OP_IF;
        script[off++] = 0x21;
        memcpy(script + off, key, 33); off += 33;
        script[off++] = OP_ENDIF;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_NON_ZERO);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->data_len == 33);
        CHECK(memcmp(output->child->data, key, 33) == 0);
        ms_node_free(output); output = NULL;
    }

    /* t:older(100) = <100> OP_CSV OP_1 */
    {
        unsigned char script[] = { 0x01, 0x64, OP_CHECKSEQUENCEVERIFY, OP_1 };
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_AND_V);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_OLDER);
        CHECK(output->child->number == 100);
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_JUST_1);
        CHECK(output->child->next->next == NULL);
        ms_node_free(output); output = NULL;
    }

    /* l:pk_k(A) = OP_IF OP_0 OP_ELSE <A_33bytes> OP_ENDIF */
    {
        unsigned char key[33];
        unsigned char script[38];
        size_t off = 0;
        memset(key, 0x02, 33);
        script[off++] = OP_IF;
        script[off++] = OP_0;
        script[off++] = OP_ELSE;
        script[off++] = 0x21;
        memcpy(script + off, key, 33); off += 33;
        script[off++] = OP_ENDIF;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_OR_I);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_JUST_0);
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->next->data_len == 33);
        CHECK(memcmp(output->child->next->data, key, 33) == 0);
        ms_node_free(output); output = NULL;
    }

    /* u:pk_k(A) = OP_IF <A_33bytes> OP_ELSE OP_0 OP_ENDIF */
    {
        unsigned char key[33];
        unsigned char script[38];
        size_t off = 0;
        memset(key, 0x02, 33);
        script[off++] = OP_IF;
        script[off++] = 0x21;
        memcpy(script + off, key, 33); off += 33;
        script[off++] = OP_ELSE;
        script[off++] = OP_0;
        script[off++] = OP_ENDIF;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_OK);
        CHECK(output != NULL);
        CHECK(output->kind == KIND_MINISCRIPT_OR_I);
        CHECK(output->child != NULL);
        CHECK(output->child->kind == KIND_MINISCRIPT_PK_K);
        CHECK(output->child->data_len == 33);
        CHECK(memcmp(output->child->data, key, 33) == 0);
        CHECK(output->child->next != NULL);
        CHECK(output->child->next->kind == KIND_MINISCRIPT_JUST_0);
        ms_node_free(output); output = NULL;
    }

    return ok;
}

typedef struct {
    uint32_t max_relative;
    uint32_t max_absolute;
} tl_ctx_t;

typedef struct {
    const unsigned char *pk;
    unsigned char        sig[71];
    size_t               sig_len;
} sig_entry_t;

typedef struct {
    const sig_entry_t *entries;
    size_t             n;
} sig_ctx_t;

static void make_fake_sig(unsigned char *sig, unsigned char r_byte, unsigned char s_byte)
{
    sig[0] = 0x30; sig[1] = 0x44;
    sig[2] = 0x02; sig[3] = 0x20;
    memset(sig + 4, r_byte, 32);
    sig[36] = 0x02; sig[37] = 0x20;
    memset(sig + 38, s_byte, 32);
    sig[70] = 0x01;
}

static void make_fake_schnorr_sig(unsigned char *sig, unsigned char byte)
{
    memset(sig, byte, 64);
}

typedef struct {
    sig_ctx_t sig;
    tl_ctx_t  tl;
} thresh_sig_tl_ctx_t;

static bool test_decode_negative(void)
{
    bool ok = true;
    ms_node *output = NULL;
    int ret;

    /* Tokenizer-level: OP_1NEGATE alone */
    {
        unsigned char script[] = { OP_1NEGATE };
        ret = decode_script_to_node(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Tokenizer-level: truncated push (0x21 claims 33 bytes but script ends) */
    {
        unsigned char script[] = { 0x21 };
        ret = decode_script_to_node(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Tokenizer-level: OP_RESERVED (0x50) — unknown opcode */
    {
        unsigned char script[] = { OP_RESERVED };
        ret = decode_script_to_node(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Decoder-level: single OP_CHECKSIG — no preceding expression to wrap */
    {
        unsigned char script[] = { OP_CHECKSIG };
        ret = decode_script_to_node(script, 1, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Decoder-level: empty script — NT_EXPRESSION gets NULL from tk_cursor_peek */
    {
        ret = decode_script_to_node(NULL, 0, 0, &output);
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
        ret = decode_script_to_node(script, 35, 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Semantic: multi(0, pk1) — k=0 rejected */
    {
        unsigned char pk1[33];
        unsigned char script[1 + 34 + 1 + 1];
        size_t off = 0;
        memset(pk1, 0x02, 33);
        script[off++] = OP_0;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = OP_1;
        script[off++] = OP_CHECKMULTISIG;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Semantic: multi(3, pk1, pk2) — k > n rejected */
    {
        unsigned char pk1[33], pk2[33];
        unsigned char script[1 + 34 + 34 + 1 + 1];
        size_t off = 0;
        memset(pk1, 0x02, 33);
        memset(pk2, 0x03, 33);
        script[off++] = OP_3;
        script[off++] = 0x21; memcpy(script + off, pk1, 33); off += 33;
        script[off++] = 0x21; memcpy(script + off, pk2, 33); off += 33;
        script[off++] = OP_2;
        script[off++] = OP_CHECKMULTISIG;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Semantic: thresh(0, pk_k(A)) — k=0 rejected */
    {
        unsigned char keyA[33];
        unsigned char script[34 + 1 + 1];
        size_t off = 0;
        memset(keyA, 0x02, 33);
        script[off++] = 0x21; memcpy(script + off, keyA, 33); off += 33;
        script[off++] = OP_0;
        script[off++] = OP_EQUAL;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
    }

    /* Semantic: thresh(3, pk_k(A), s:pk_k(B)) — k=3 > n=2 rejected */
    {
        unsigned char keyA[33], keyB[33];
        unsigned char script[34 + 1 + 34 + 1 + 1 + 1];
        size_t off = 0;
        memset(keyA, 0x02, 33);
        memset(keyB, 0x03, 33);
        script[off++] = 0x21; memcpy(script + off, keyA, 33); off += 33;
        script[off++] = OP_SWAP;
        script[off++] = 0x21; memcpy(script + off, keyB, 33); off += 33;
        script[off++] = OP_ADD;
        script[off++] = OP_3;
        script[off++] = OP_EQUAL;
        ret = decode_script_to_node(script, sizeof(script), 0, &output);
        CHECK(ret == WALLY_EINVAL);
        CHECK(output == NULL);
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
    wally_cleanup(0);
    return ok ? 0 : 1;
}
