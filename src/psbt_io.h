#ifndef LIBWALLY_CORE_PSBT_IO_H
#define LIBWALLY_CORE_PSBT_IO_H 1

#include <stdint.h>

/* Constants for PSBT/PSET serialization */

/* We use bitsets to detect duplicate, mandatory and disallowed keys
 * with common code, to avoid having to check each one manually.
 * Because PSET uses extension keys with overlapping key constants, we
 * shift them by 32 bits to allow using a single uint64_t to hold
 * all key bits to check using a single uint64_t bitset (lower 32 bits
 * for PSBT, upper 32 bits for PSET). This allows for up to 31 key types
 * each for PSBT and PSET. PSBT currently maxes out at 25 keys for
 * inputs; if this increases to 31 the shift can be made greater as long
 * as PSET keys can be represented in the remaining bits (PSET currently
 * maxes out at 16 bits for inputs).
 */
#define PSBT_FT(k) (((uint64_t)1) << ((uint64_t)k))
#define PSET_FT(k) (PSBT_FT(k) << ((uint64_t)32))

#define PSBT_SEPARATOR 0x00

/* Shorthand PSBT version constants */
#define PSBT_0 WALLY_PSBT_VERSION_0
#define PSBT_2 WALLY_PSBT_VERSION_2

/* Globals: PSBT */
#define PSBT_GLOBAL_UNSIGNED_TX 0x00
#define PSBT_GLOBAL_XPUB 0x01
#define PSBT_GLOBAL_TX_VERSION 0x02
#define PSBT_GLOBAL_FALLBACK_LOCKTIME 0x03
#define PSBT_GLOBAL_INPUT_COUNT 0x04
#define PSBT_GLOBAL_OUTPUT_COUNT 0x05
#define PSBT_GLOBAL_TX_MODIFIABLE 0x06
/* VERSION and PROPRIETARY are treated specially, hence our max is the max
 * of the contiguous defined fields.
 */
#define PSBT_GLOBAL_MAX PSBT_GLOBAL_TX_MODIFIABLE

/* PSBT_GLOBAL_VERSION is not contiguous with the other keys, and is
 * out of range of the keys we can track in the lower 32 bits of a
 * bitset if shifted. Map it to the 31st bit to allow checking with
 * our bitsets.
 */
#define PSBT_GLOBAL_VERSION 0xfb
#define PSBT_GLOBAL_VERSION_BIT PSBT_FT(0x1f)

/* Globals: PSET */
#define PSET_GLOBAL_SCALAR 0x00
#define PSET_GLOBAL_TX_MODIFIABLE 0x01
#define PSET_GLOBAL_MAX PSET_GLOBAL_TX_MODIFIABLE

/* Global PSBT/PSET fields that can be repeated */
#define PSBT_GLOBAL_REPEATABLE (PSBT_FT(PSBT_GLOBAL_XPUB) | \
                                PSET_FT(PSET_GLOBAL_SCALAR))

/* Global PSBT/PSET fields that contain data in their keys */
#define PSBT_GLOBAL_HAVE_KEYDATA (PSBT_FT(PSBT_GLOBAL_XPUB) | \
                                  PSET_FT(PSET_GLOBAL_SCALAR))

/* Global PSBT/PSET fields that must be present in v0 */
#define PSBT_GLOBAL_MANDATORY_V0 PSBT_FT(PSBT_GLOBAL_UNSIGNED_TX)

/* Global PSBT/PSET fields that must be present in v2 */
#define PSBT_GLOBAL_MANDATORY_V2 (PSBT_FT(PSBT_GLOBAL_TX_VERSION) | \
                                  PSBT_FT(PSBT_GLOBAL_INPUT_COUNT) | \
                                  PSBT_FT(PSBT_GLOBAL_OUTPUT_COUNT))

/* Global PSBT/PSET fields that must *not* be present in v0 */
#define PSBT_GLOBAL_DISALLOWED_V0 (PSBT_FT(PSBT_GLOBAL_TX_VERSION) | \
                                   PSBT_FT(PSBT_GLOBAL_FALLBACK_LOCKTIME) | \
                                   PSBT_FT(PSBT_GLOBAL_INPUT_COUNT) | \
                                   PSBT_FT(PSBT_GLOBAL_OUTPUT_COUNT) | \
                                   PSBT_FT(PSBT_GLOBAL_TX_MODIFIABLE) | \
                                   PSET_FT(PSET_GLOBAL_SCALAR) | \
                                   PSET_FT(PSET_GLOBAL_TX_MODIFIABLE))

/* Global PSBT/PSET fields that must *not* be present in v2 */
#define PSBT_GLOBAL_DISALLOWED_V2 PSBT_FT(PSBT_GLOBAL_UNSIGNED_TX)

/* Allowable flag values for PSBT_GLOBAL_TX_MODIFIABLE/PSET_GLOBAL_TX_MODIFIABLE */
#define PSBT_TXMOD_ALL_FLAGS (WALLY_PSBT_TXMOD_INPUTS | \
                              WALLY_PSBT_TXMOD_OUTPUTS | \
                              WALLY_PSBT_TXMOD_SINGLE)
#define PSET_TXMOD_ALL_FLAGS (WALLY_PSET_TXMOD_UNBLINDED)


/* Inputs: PSBT */
#define PSBT_IN_NON_WITNESS_UTXO 0x00
#define PSBT_IN_WITNESS_UTXO 0x01
#define PSBT_IN_PARTIAL_SIG 0x02
#define PSBT_IN_SIGHASH_TYPE 0x03
#define PSBT_IN_REDEEM_SCRIPT 0x04
#define PSBT_IN_WITNESS_SCRIPT 0x05
#define PSBT_IN_BIP32_DERIVATION 0x06
#define PSBT_IN_FINAL_SCRIPTSIG 0x07
#define PSBT_IN_FINAL_SCRIPTWITNESS 0x08
#define PSBT_IN_POR_COMMITMENT 0x09
#define PSBT_IN_RIPEMD160 0x0a
#define PSBT_IN_SHA256 0x0b
#define PSBT_IN_HASH160 0x0c
#define PSBT_IN_HASH256 0x0d
#define PSBT_IN_PREVIOUS_TXID 0x0e
#define PSBT_IN_OUTPUT_INDEX 0x0f
#define PSBT_IN_SEQUENCE 0x10
#define PSBT_IN_REQUIRED_TIME_LOCKTIME 0x11
#define PSBT_IN_REQUIRED_HEIGHT_LOCKTIME 0x12
#define PSBT_IN_MAX PSBT_IN_REQUIRED_HEIGHT_LOCKTIME

/* Inputs: PSET */
#define PSET_IN_ISSUANCE_VALUE 0x00
#define PSET_IN_ISSUANCE_VALUE_COMMITMENT 0x01
#define PSET_IN_ISSUANCE_VALUE_RANGEPROOF 0x02
#define PSET_IN_ISSUANCE_KEYS_RANGEPROOF 0x03
#define PSET_IN_PEG_IN_TX 0x04
#define PSET_IN_PEG_IN_TXOUT_PROOF 0x05
#define PSET_IN_PEG_IN_GENESIS 0x06
#define PSET_IN_PEG_IN_CLAIM_SCRIPT 0x07
#define PSET_IN_PEG_IN_VALUE 0x08
#define PSET_IN_PEG_IN_WITNESS 0x09
#define PSET_IN_ISSUANCE_INFLATION_KEYS 0x0a
#define PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT 0x0b
#define PSET_IN_ISSUANCE_BLINDING_NONCE 0x0c
#define PSET_IN_ISSUANCE_ASSET_ENTROPY 0x0d
#define PSET_IN_UTXO_RANGEPROOF 0x0e
#define PSET_IN_ISSUANCE_BLIND_VALUE_PROOF 0x0f
#define PSET_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF 0x10
#define PSET_IN_MAX PSET_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF

/* Input PSBT/PSET fields that can be repeated */
#define PSBT_IN_REPEATABLE 0x44 /* keys which can appear more than once */
/* Input PSBT/PSET fields that contain data in their keys */
#define PSBT_IN_HAVE_KEYDATA 0x3c44 /* keys with keydata */
/* Input PSBT/PSET fields that must be present in v0 */
#define PSBT_IN_MANDATORY_V0 0x0 /* Required keys for v0 */
/* Input PSBT/PSET fields that must be present in v2 */
#define PSBT_IN_MANDATORY_V2 0xc000 /* Required keys for v2 */
/* Input PSBT/PSET fields that must *not* be present in v0 */
#define PSBT_IN_DISALLOWED_V0 0x7c000 /* Disallowed keys for v0 */
/* Input PSBT/PSET fields that must *not* be present in v2 */
#define PSBT_IN_DISALLOWED_V2 0x0 /* Disallowed keys for v2 */

/* The minimum allowed timestamp in PSBT_IN_REQUIRED_TIME_LOCKTIME */
#define PSBT_LOCKTIME_MIN_TIMESTAMP 500000000

/* Outputs: PSBT */
#define PSBT_OUT_REDEEM_SCRIPT 0x00
#define PSBT_OUT_WITNESS_SCRIPT 0x01
#define PSBT_OUT_BIP32_DERIVATION 0x02
#define PSBT_OUT_AMOUNT 0x03
#define PSBT_OUT_SCRIPT 0x04
#define PSBT_OUT_MAX PSBT_OUT_SCRIPT

/* Outputs: PSET */
#define PSET_OUT_VALUE_COMMITMENT 0x01
#define PSET_OUT_ASSET 0x02
#define PSET_OUT_ASSET_COMMITMENT 0x03
#define PSET_OUT_VALUE_RANGEPROOF 0x04
#define PSET_OUT_ASSET_SURJECTION_PROOF 0x05
#define PSET_OUT_BLINDING_PUBKEY 0x06
#define PSET_OUT_ECDH_PUBKEY 0x07
#define PSET_OUT_BLINDER_INDEX 0x08
#define PSET_OUT_BLIND_VALUE_PROOF 0x09
#define PSET_OUT_BLIND_ASSET_PROOF 0x0a
#define PSET_OUT_MAX PSET_OUT_BLIND_ASSET_PROOF

/* Output PSBT/PSET fields that can be repeated */
#define PSBT_OUT_REPEATABLE 0x4
/* Output PSBT/PSET fields that contain data in their keys */
#define PSBT_OUT_HAVE_KEYDATA 0x4
/* Output PSBT/PSET fields that must be present in v0 */
#define PSBT_OUT_MANDATORY_V0 0x0
/* Output PSBT/PSET fields that must be present in v2 */
#define PSBT_OUT_MANDATORY_V2 0x18
/* Output PSBT/PSET fields that must *not* be present in v0 */
#define PSBT_OUT_DISALLOWED_V0 0x18
/* Output PSBT/PSET fields that must *not* be present in v2 */
#define PSBT_OUT_DISALLOWED_V2 0x0

#endif /* LIBWALLY_CORE_PSBT_IO_H */
