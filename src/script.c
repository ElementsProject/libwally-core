#include "internal.h"

#include "ccan/ccan/endian/endian.h"
#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/crypto/sha256/sha256.h"

#include <include/wally_crypto.h>
#include <include/wally_script.h>

#include <limits.h>
#include <stdbool.h>

#if 0
inline static uint8_t script_encode_op_n(uint8_t v)
{
    return v == 0 ? OP_0 : OP_1 + v - 1;
}
#endif

static int script_get_size_from_script(
    const unsigned char *bytes_in,
    size_t len_in,
    bool get_opcode_size,
    size_t *size_out)
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
    } else {
        leint32_t data_len;
        opcode_len = 5;
        if (len_in < opcode_len)
            return WALLY_EINVAL;
        memcpy(&data_len, &bytes_in[1], sizeof(data_len));
        *size_out = le32_to_cpu(data_len);
    }
    if (len_in < opcode_len + *size_out)
        return WALLY_EINVAL; /* Push is longer than current script bytes */
    if (get_opcode_size)
        *size_out = opcode_len;
    return WALLY_OK;
}

int script_get_push_size_from_script(
    const unsigned char *bytes_in,
    size_t len_in,
    size_t *size_out)
{
    return script_get_size_from_script(bytes_in, len_in, false, size_out);
}

int script_get_push_opcode_size_from_script(
    const unsigned char *bytes_in,
    size_t len_in,
    size_t *size_out)
{
    return script_get_size_from_script(bytes_in, len_in, true, size_out);
}

/* Get the size of a script pushing 'len' bytes of data excluding the data iteself */
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

int wally_push_from_bytes(const unsigned char *bytes_in, size_t len_in,
                          unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t opcode_len;

    if (written)
        *written = 0;

    if (!bytes_out || !written || !len || (len_in && !bytes_in))
        return WALLY_EINVAL;

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

    return WALLY_OK;
}

#define WALLY_SCRIPT_HASH_FLAGS (WALLY_SCRIPT_HASH160 | WALLY_SCRIPT_SHA256)

int wally_witness_program_from_bytes(const unsigned char *bytes_in, size_t len_in,
                                     uint32_t flags,
                                     unsigned char *bytes_out, size_t len, size_t *written)
{
    struct sha256 sha;
    struct ripemd160 hash160;

    int ret;

    if (written)
        *written = 0;

    if (!bytes_out || !written || !len || (len_in && !bytes_in) ||
        (flags & ~WALLY_SCRIPT_HASH_FLAGS) ||
        ((flags & WALLY_SCRIPT_HASH_FLAGS) == WALLY_SCRIPT_HASH_FLAGS))
        return WALLY_EINVAL;

    if (flags & WALLY_SCRIPT_HASH160) {
        ripemd160(&hash160, bytes_in, len_in);
        bytes_in = (const unsigned char *)&hash160;
        len_in = HASH160_LEN;
    } else if (flags & WALLY_SCRIPT_SHA256) {
        sha256(&sha, bytes_in, len_in);
        bytes_in = (const unsigned char *)&sha;
        len_in = SHA256_LEN;
    } else if (len_in != HASH160_LEN && len_in != SHA256_LEN) {
        /* Only v0 witness scripts are currently supported */
        ret = WALLY_EINVAL;
        goto end;
    }

    *written = script_calc_push_opcode_size(len_in) + len_in + 1; /* 1 for version 0 */
    if (len < *written)
        return WALLY_OK; /* Caller needs to pass a bigger buffer */

    bytes_out[0] = 0; /* Witness version */
    ret = wally_push_from_bytes(bytes_in, len_in, bytes_out + 1, len - 1, written);
    if (ret == WALLY_OK)
        *written += 1; /* For version byte */
end:
    wally_clear_2(&sha, sizeof(sha), &hash160, sizeof(hash160));
    return ret;
}
