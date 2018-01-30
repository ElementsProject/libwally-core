#include "internal.h"

#include "ccan/ccan/endian/endian.h"
#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/crypto/sha256/sha256.h"

#include <include/wally_crypto.h>
#include <include/wally_script.h>

#include <limits.h>
#include <stdbool.h>
#include "script_int.h"

/* varint tags and limits */
#define VI_TAG_16 253
#define VI_TAG_32 254
#define VI_TAG_64 255

#define VI_MAX_8 252
#define VI_MAX_16 USHRT_MAX
#define VI_MAX_32 UINT_MAX

#define ALL_SCRIPT_HASH_FLAGS (WALLY_SCRIPT_HASH160 | WALLY_SCRIPT_SHA256)

static bool script_flags_ok(uint32_t flags)
{
    if ((flags & ~ALL_SCRIPT_HASH_FLAGS) ||
        ((flags & ALL_SCRIPT_HASH_FLAGS) == ALL_SCRIPT_HASH_FLAGS))
        return false;
    return true;
}

static bool is_op_n(unsigned char op, bool allow_zero, size_t *n) {
    if (allow_zero && op == OP_0) {
        if (n)
            *n = 0;
        return true;
    }
    if (op >= OP_1 && op <= OP_16) {
        if (n)
            *n = op - OP_1 + 1;
        return true;
    }
    return false;
}

/* Note: does no parameter checking, v must be between 0 and 16 */
static inline size_t v_to_op_n(uint64_t v)
{
    if (!v)
        return OP_0;
    return OP_1 + v - 1;
}

static bool is_pk_push(size_t len_in) {
    return len_in == EC_PUBLIC_KEY_LEN ||
           len_in == EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
}

/* Calculate the opcode size of a push of 'len_in' bytes */
static size_t script_calc_push_opcode_size(size_t len_in)
{
    if (len_in < 76)
        return 1;
    else if (len_in < 256)
        return 2;
    else if (len_in < 65536)
        return 3;
    return 5;
}

static int get_push_size(const unsigned char *bytes_in, size_t len_in,
                         bool get_opcode_size, size_t *size_out)
{
    size_t opcode_len;

    if (!bytes_in || !len_in || !size_out)
        return WALLY_EINVAL;

    if (bytes_in[0] < 76) {
        opcode_len = 1;
        *size_out = bytes_in[0];
    } else if (bytes_in[0] == OP_PUSHDATA1) {
        opcode_len = 2;
        if (len_in < opcode_len)
            return WALLY_EINVAL;
        *size_out = bytes_in[1];
    } else if (bytes_in[0] == OP_PUSHDATA2) {
        leint16_t data_len;
        opcode_len = 3;
        if (len_in < opcode_len)
            return WALLY_EINVAL;
        memcpy(&data_len, &bytes_in[1], sizeof(data_len));
        *size_out = le16_to_cpu(data_len);
    } else if (bytes_in[0] == OP_PUSHDATA4) {
        leint32_t data_len;
        opcode_len = 5;
        if (len_in < opcode_len)
            return WALLY_EINVAL;
        memcpy(&data_len, &bytes_in[1], sizeof(data_len));
        *size_out = le32_to_cpu(data_len);
    } else
        return WALLY_EINVAL; /* Not a push */
    if (len_in < opcode_len + *size_out)
        return WALLY_EINVAL; /* Push is longer than current script bytes */
    if (get_opcode_size)
        *size_out = opcode_len;
    return WALLY_OK;
}

size_t varint_get_length(uint64_t v)
{
    if (v <= VI_MAX_8)
        return sizeof(uint8_t);
    if (v <= VI_MAX_16)
        return sizeof(uint8_t) + sizeof(uint16_t);
    if (v <= VI_MAX_32)
        return sizeof(uint8_t) + sizeof(uint32_t);
    return sizeof(uint8_t) + sizeof(uint64_t);
}

size_t varint_to_bytes(uint64_t v, unsigned char *bytes_out)
{
    if (v <= VI_MAX_8)
        return uint8_to_le_bytes(v, bytes_out);
    else if (v <= VI_MAX_16) {
        *bytes_out++ = VI_TAG_16;
        return sizeof(uint8_t) + uint16_to_le_bytes(v, bytes_out);
    } else if (v <= VI_MAX_32) {
        *bytes_out++ = VI_TAG_32;
        return sizeof(uint8_t) + uint32_to_le_bytes(v, bytes_out);
    }
    *bytes_out++ = VI_TAG_64;
    return sizeof(uint8_t) + uint64_to_le_bytes(v, bytes_out);
}

size_t varint_length_from_bytes(const unsigned char *bytes_in)
{
    switch (*bytes_in) {
    case VI_TAG_16:
        return sizeof(uint8_t) + sizeof(uint16_t);
    case VI_TAG_32:
        return sizeof(uint8_t) + sizeof(uint32_t);
    case VI_TAG_64:
        return sizeof(uint8_t) + sizeof(uint64_t);
    }
    return sizeof(uint8_t);
}

size_t varint_from_bytes(const unsigned char *bytes_in, uint64_t *v)
{
#define b(n) ((uint64_t)bytes_in[n] << ((n - 1) * 8))
    switch (*bytes_in) {
    case VI_TAG_16:
        *v = b(2) | b(1);
        return sizeof(uint8_t) + sizeof(uint16_t);
    case VI_TAG_32:
        *v = b(4) | b(3) | b(2) | b(1);
        return sizeof(uint8_t) + sizeof(uint32_t);
    case VI_TAG_64:
        *v = b(8) | b(7) | b(6) | b(5) | b(4) | b(3) | b(2) | b(1);
        return sizeof(uint8_t) + sizeof(uint64_t);
    }
    *v = *bytes_in;
    return sizeof(uint8_t);
#undef b
}

size_t varbuff_to_bytes(const unsigned char *bytes_in, size_t len_in,
                        unsigned char *bytes_out)
{
    size_t n = varint_to_bytes(len_in, bytes_out);
    bytes_out += n;
    if (len_in)
        memcpy(bytes_out, bytes_in, len_in);
    return n + len_in;
}

static bool scriptpubkey_is_op_return(const unsigned char *bytes_in, size_t len_in)
{
    size_t n_op, n_push;

    return len_in && bytes_in[0] == OP_RETURN &&
           get_push_size(bytes_in + 1, len_in - 1, false, &n_op) == WALLY_OK &&
           get_push_size(bytes_in + 1, len_in - 1, true, &n_push) == WALLY_OK &&
           len_in == 1 + n_op + n_push;
}

static bool scriptpubkey_is_p2pkh(const unsigned char *bytes_in, size_t len_in)
{
    return len_in == WALLY_SCRIPTPUBKEY_P2PKH_LEN &&
           bytes_in[0] == OP_DUP && bytes_in[1] == OP_HASH160 &&
           bytes_in[2] == 20 && bytes_in[23] == OP_EQUALVERIFY &&
           bytes_in[24] == OP_CHECKSIG;
}

static bool scriptpubkey_is_p2sh(const unsigned char *bytes_in, size_t len_in)
{
    return len_in == WALLY_SCRIPTPUBKEY_P2SH_LEN &&
           bytes_in[0] == OP_HASH160 &&
           bytes_in[1] == 20 &&
           bytes_in[22] == OP_EQUAL;
}

static bool scriptpubkey_is_p2wpkh(const unsigned char *bytes_in, size_t len_in)
{
    return len_in == WALLY_SCRIPTPUBKEY_P2WPKH_LEN &&
           bytes_in[0] == OP_0 &&
           bytes_in[1] == 20;
}

static bool scriptpubkey_is_p2wsh(const unsigned char *bytes_in, size_t len_in)
{
    return len_in == WALLY_SCRIPTPUBKEY_P2WSH_LEN &&
           bytes_in[0] == OP_0 &&
           bytes_in[1] == 32;
}

static bool scriptpubkey_is_multisig(const unsigned char *bytes_in, size_t len_in)
{
    const size_t min_1of1_len = 1 + 1 + 33 + 1 + 1; /* OP_1 [pubkey] OP_1 OP_CHECKMULTISIG */
    size_t i, n_pushes;

    if (len_in < min_1of1_len || !is_op_n(bytes_in[0], false, &n_pushes) ||
        bytes_in[len_in - 1] != OP_CHECKMULTISIG ||
        !is_op_n(bytes_in[len_in - 2], false, NULL))
        return false;

    ++bytes_in;
    --len_in;
    for (i = 0; i < n_pushes; ++i) {
        size_t n_op, n_push;
        if (get_push_size(bytes_in, len_in, false, &n_op) != WALLY_OK ||
            get_push_size(bytes_in, len_in, true, &n_push) != WALLY_OK ||
            !is_pk_push(n_push) || len_in < n_op + n_push + 2)
            return false;
        bytes_in += n_op + n_push;
        len_in -= n_op + n_push;
    }
    return len_in == 2;
}

int wally_scriptpubkey_get_type(const unsigned char *bytes_in, size_t len_in,
                                size_t *written)
{
    if (written)
        *written = WALLY_SCRIPT_TYPE_UNKNOWN;

    if (!bytes_in || !len_in || !written)
        return WALLY_EINVAL;

    if (scriptpubkey_is_op_return(bytes_in, len_in)) {
        *written = WALLY_SCRIPT_TYPE_OP_RETURN;
        return WALLY_OK;
    }

    if (scriptpubkey_is_multisig(bytes_in, len_in)) {
        *written = WALLY_SCRIPT_TYPE_MULTISIG;
        return WALLY_OK;
    }

    switch (len_in) {
    case WALLY_SCRIPTPUBKEY_P2PKH_LEN:
        if (scriptpubkey_is_p2pkh(bytes_in, len_in)) {
            *written = WALLY_SCRIPT_TYPE_P2PKH;
            return WALLY_OK;
        }
        break;
    case WALLY_SCRIPTPUBKEY_P2SH_LEN:
        if (scriptpubkey_is_p2sh(bytes_in, len_in)) {
            *written = WALLY_SCRIPT_TYPE_P2SH;
            return WALLY_OK;
        }
        break;
    case WALLY_SCRIPTPUBKEY_P2WPKH_LEN:
        if (scriptpubkey_is_p2wpkh(bytes_in, len_in)) {
            *written = WALLY_SCRIPT_TYPE_P2WPKH;
            return WALLY_OK;
        }
        break;
    case WALLY_SCRIPTPUBKEY_P2WSH_LEN:
        if (scriptpubkey_is_p2wsh(bytes_in, len_in)) {
            *written = WALLY_SCRIPT_TYPE_P2WSH;
            return WALLY_OK;
        }
        break;
    }
    return WALLY_OK;
}

int wally_scriptpubkey_p2pkh_from_bytes(
    const unsigned char *bytes_in, size_t len_in,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    int ret;

    if (written)
        *written = 0;

    if (!bytes_in || !len_in || !script_flags_ok(flags) ||
        (flags & WALLY_SCRIPT_SHA256) || !bytes_out ||
        len < WALLY_SCRIPTPUBKEY_P2PKH_LEN || !written)
        return WALLY_EINVAL;

    if (flags & WALLY_SCRIPT_HASH160) {
        if (len_in != EC_PUBLIC_KEY_LEN && len_in != EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
            return WALLY_EINVAL;
    } else if (len_in != HASH160_LEN)
        return WALLY_EINVAL;

    bytes_out[0] = OP_DUP;
    bytes_out[1] = OP_HASH160;
    ret = wally_script_push_from_bytes(bytes_in, len_in, flags,
                                       bytes_out + 2, len - 4, written);
    if (ret == WALLY_OK) {
        bytes_out[WALLY_SCRIPTPUBKEY_P2PKH_LEN - 2] = OP_EQUALVERIFY;
        bytes_out[WALLY_SCRIPTPUBKEY_P2PKH_LEN - 1] = OP_CHECKSIG;
        *written = WALLY_SCRIPTPUBKEY_P2PKH_LEN;
    }
    return ret;
}

int wally_scriptpubkey_p2sh_from_bytes(
    const unsigned char *bytes_in, size_t len_in,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    int ret;

    if (written)
        *written = 0;

    if (!bytes_in || !len_in || !script_flags_ok(flags) ||
        (flags & WALLY_SCRIPT_SHA256) || !bytes_out ||
        len < WALLY_SCRIPTPUBKEY_P2SH_LEN || !written)
        return WALLY_EINVAL;

    bytes_out[0] = OP_HASH160;
    ret = wally_script_push_from_bytes(bytes_in, len_in, flags,
                                       bytes_out + 1, len - 2, written);
    if (ret == WALLY_OK) {
        bytes_out[WALLY_SCRIPTPUBKEY_P2SH_LEN - 1] = OP_EQUAL;
        *written = WALLY_SCRIPTPUBKEY_P2SH_LEN;
    }
    return ret;
}

int wally_scriptpubkey_multisig_from_bytes(
    const unsigned char *bytes_in, size_t len_in, uint32_t threshold,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t n_pubkeys = len_in / EC_PUBLIC_KEY_LEN;
    size_t script_len = 3 + (n_pubkeys * (EC_PUBLIC_KEY_LEN + 1));
    size_t i;

    if (written)
        *written = 0;

    if (!bytes_in || !len_in || len_in % EC_PUBLIC_KEY_LEN ||
        n_pubkeys < 1 || n_pubkeys > 16 || threshold < 1 || threshold > 16 ||
        threshold > n_pubkeys || flags || !bytes_out || !written)
        return WALLY_EINVAL;

    if (len < script_len) {
        *written = len;
        return WALLY_OK;
    }

    *bytes_out++ = v_to_op_n(threshold);
    for (i = 0; i < n_pubkeys; ++i) {
        *bytes_out++ = EC_PUBLIC_KEY_LEN;
        memcpy(bytes_out, bytes_in, EC_PUBLIC_KEY_LEN);
        bytes_out += EC_PUBLIC_KEY_LEN;
        bytes_in += EC_PUBLIC_KEY_LEN;
    }
    *bytes_out++ = v_to_op_n(n_pubkeys);
    *bytes_out = OP_CHECKMULTISIG;
    *written = script_len;
    return WALLY_OK;
}

int script_get_push_size_from_bytes(
    const unsigned char *bytes_in, size_t len_in, size_t *size_out)
{
    return get_push_size(bytes_in, len_in, false, size_out);
}

int script_get_push_opcode_size_from_bytes(
    const unsigned char *bytes_in, size_t len_in, size_t *size_out)
{
    return get_push_size(bytes_in, len_in, true, size_out);
}

int wally_script_push_from_bytes(const unsigned char *bytes_in, size_t len_in,
                                 uint32_t flags,
                                 unsigned char *bytes_out, size_t len,
                                 size_t *written)
{
    unsigned char buff[SHA256_LEN];
    size_t opcode_len;
    int ret = WALLY_OK;

    if (written)
        *written = 0;

    if ((len_in && !bytes_in) || !script_flags_ok(flags) ||
        !bytes_out || !len || !written)
        return WALLY_EINVAL;

    if (flags & WALLY_SCRIPT_HASH160) {
        ret = wally_hash160(bytes_in, len_in, buff, HASH160_LEN);
        bytes_in = buff;
        len_in = HASH160_LEN;
    } else if (flags & WALLY_SCRIPT_SHA256) {
        ret = wally_sha256(bytes_in, len_in, buff, SHA256_LEN);
        bytes_in = buff;
        len_in = SHA256_LEN;
    }
    if (ret != WALLY_OK)
        goto cleanup;

    opcode_len = script_calc_push_opcode_size(len_in);

    *written = len_in + opcode_len;
    if (len < *written)
        return WALLY_OK; /* Caller needs to pass a bigger buffer */

    if (len_in < 76)
        bytes_out[0] = len_in;
    else if (len_in < 256) {
        bytes_out[0] = OP_PUSHDATA1;
        bytes_out[1] = len_in;
    } else if (len_in < 65536) {
        leint16_t data_len = cpu_to_le16(len_in);
        bytes_out[0] = OP_PUSHDATA2;
        memcpy(bytes_out + 1, &data_len, sizeof(data_len));
    } else {
        leint32_t data_len = cpu_to_le32(len_in);
        bytes_out[0] = OP_PUSHDATA4;
        memcpy(bytes_out + 1, &data_len, sizeof(data_len));
    }
    if (len_in)
        memcpy(bytes_out + opcode_len, bytes_in, len_in);

cleanup:
    wally_clear(buff, sizeof(buff));
    return ret;
}

int wally_witness_program_from_bytes(const unsigned char *bytes_in, size_t len_in,
                                     uint32_t flags,
                                     unsigned char *bytes_out, size_t len, size_t *written)
{
    int ret;

    if (written)
        *written = 0;

    if ((len_in && !bytes_in) || !script_flags_ok(flags) ||
        !bytes_out || !len || !written)
        return WALLY_EINVAL;

    if (flags & ALL_SCRIPT_HASH_FLAGS) {
        if (!len_in)
            return WALLY_EINVAL;
    } else if (len_in != HASH160_LEN && len_in != SHA256_LEN) {
        /* Only v0 witness scripts are currently supported */
        return WALLY_EINVAL;
    }

    bytes_out[0] = 0; /* Witness version */
    ret = wally_script_push_from_bytes(bytes_in, len_in, flags,
                                       bytes_out + 1, len - 1, written);
    if (ret == WALLY_OK)
        *written += 1; /* For Witness version byte */
    return ret;
}
