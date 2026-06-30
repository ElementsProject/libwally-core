#include <wally_psbt.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * MuSig2 per-input PSBT field types (BIP-370):
 *   0x1a = PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS  key: type(1) + agg_pubkey(33)
 *   0x1b = PSBT_IN_MUSIG2_PUB_NONCE            key: type(1) + part_pubkey(33) + agg_pubkey(33)
 *   0x1c = PSBT_IN_MUSIG2_PARTIAL_SIG          key: type(1) + xonly_part(32) + agg_pubkey(33)
 *
 * This fuzzer builds a minimal but structurally valid PSBT v0 frame and splices
 * fuzz bytes into key-value pairs with each MuSig2 field type, specifically
 * exercising the deserialization paths for types 0x1a, 0x1b, and 0x1c.
 */

/* Minimal serialized tx: version=2, 1 input (all-zero txid), 1 output (0-val) */
static const uint8_t s_minimal_tx[] = {
    0x02, 0x00, 0x00, 0x00,  /* version=2 */
    0x01,                    /* 1 input */
    /* txid (32 zero bytes) */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x00, 0x00, 0x00, 0x00,  /* vout=0 */
    0x00,                    /* scriptSig len=0 */
    0xff, 0xff, 0xff, 0xff,  /* sequence=0xffffffff */
    0x01,                    /* 1 output */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* 0 satoshis */
    0x00,                    /* scriptPubKey len=0 */
    0x00, 0x00, 0x00, 0x00   /* locktime=0 */
};

/* PSBT magic: 0x70736274ff */
static const uint8_t s_psbt_magic[] = {0x70, 0x73, 0x62, 0x74, 0xff};

/* Write a compact-size (varint) integer, return bytes written */
static size_t write_varint(uint8_t *buf, uint64_t v)
{
    if (v < 0xfd) {
        buf[0] = (uint8_t)v;
        return 1;
    } else if (v <= 0xffff) {
        buf[0] = 0xfd;
        buf[1] = (uint8_t)(v & 0xff);
        buf[2] = (uint8_t)((v >> 8) & 0xff);
        return 3;
    } else {
        buf[0] = 0xfe;
        buf[1] = (uint8_t)(v & 0xff);
        buf[2] = (uint8_t)((v >> 8) & 0xff);
        buf[3] = (uint8_t)((v >> 16) & 0xff);
        buf[4] = (uint8_t)((v >> 24) & 0xff);
        return 5;
    }
}

/* Append a key-value pair to the output buffer, return new offset */
static size_t append_kv(uint8_t *out, size_t off,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *val, size_t val_len)
{
    off += write_varint(out + off, key_len);
    memcpy(out + off, key, key_len);
    off += key_len;
    off += write_varint(out + off, val_len);
    if (val_len && val)
        memcpy(out + off, val, val_len);
    off += val_len;
    return off;
}

/*
 * Build a minimal PSBT frame and inject fuzz bytes as the value of a
 * per-input key-value pair with the given MuSig2 field type.
 * The key suffix (after the type byte) is filled from fuzz data or zeros.
 */
static void fuzz_musig2_field(const uint8_t *fuzz, size_t fuzz_size,
                               uint8_t field_type)
{
    /*
     * Key suffix lengths (bytes after the 1-byte type):
     *   0x1a: agg_pubkey(33)                          = 33
     *   0x1b: part_pubkey(33) + agg_pubkey(33)        = 66
     *   0x1c: xonly_part(32)  + agg_pubkey(33)        = 65
     */
    size_t key_suffix_len;
    switch (field_type) {
        case 0x1a: key_suffix_len = 33; break;
        case 0x1b: key_suffix_len = 66; break;
        case 0x1c: key_suffix_len = 65; break;
        default:   key_suffix_len = 33; break;
    }

    /* Build the key: type byte + key_suffix (from fuzz or zero-padded) */
    uint8_t key[68];
    key[0] = field_type;
    size_t from_fuzz = fuzz_size < key_suffix_len ? fuzz_size : key_suffix_len;
    if (from_fuzz)
        memcpy(key + 1, fuzz, from_fuzz);
    if (from_fuzz < key_suffix_len)
        memset(key + 1 + from_fuzz, 0, key_suffix_len - from_fuzz);

    /* Value: fuzz bytes beyond the key suffix (may be empty) */
    const uint8_t *val = fuzz_size > key_suffix_len ? fuzz + key_suffix_len : NULL;
    size_t val_len = fuzz_size > key_suffix_len ? fuzz_size - key_suffix_len : 0;

    /* Allocate output buffer: magic + global(~80) + input(keysize + valsize) + output + extra */
    size_t buf_cap = 5 + 5 + sizeof(s_minimal_tx) + 10 +
                     5 + (1 + key_suffix_len) + 5 + val_len + 16;
    uint8_t *buf = malloc(buf_cap);
    if (!buf)
        return;

    size_t off = 0;

    /* 1. Magic */
    memcpy(buf + off, s_psbt_magic, 5);
    off += 5;

    /* 2. Global map: UNSIGNED_TX (key type = 0x00) */
    static const uint8_t unsigned_tx_key[] = {0x00};
    off = append_kv(buf, off, unsigned_tx_key, 1,
                    s_minimal_tx, sizeof(s_minimal_tx));
    buf[off++] = 0x00; /* end of global map */

    /* 3. Input 0 map: inject MuSig2-typed key-value pair */
    off = append_kv(buf, off, key, 1 + key_suffix_len, val, val_len);
    buf[off++] = 0x00; /* end of input 0 map */

    /* 4. Output 0 map: empty */
    buf[off++] = 0x00;

    /* Feed to the parser */
    struct wally_psbt *psbt = NULL;
    wally_psbt_from_bytes(buf, off, 0, &psbt);
    if (psbt)
        wally_psbt_free(psbt);

    psbt = NULL;
    wally_psbt_from_bytes(buf, off, WALLY_PSBT_PARSE_FLAG_STRICT, &psbt);
    if (psbt)
        wally_psbt_free(psbt);

    free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Exercise all three MuSig2 per-input field type code paths */
    fuzz_musig2_field(data, size, 0x1a);  /* PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS */
    fuzz_musig2_field(data, size, 0x1b);  /* PSBT_IN_MUSIG2_PUB_NONCE */
    fuzz_musig2_field(data, size, 0x1c);  /* PSBT_IN_MUSIG2_PARTIAL_SIG */

    return 0;
}
