#!/usr/bin/env python3
"""
2-of-2 MuSig2 PSBT signing example (BIP-327/373)

Demonstrates the full two-round MuSig2 signing workflow:
  1. Key aggregation (signer 1 and signer 2 combine pubkeys)
  2. PSBT creation with P2TR output locked to the aggregate key
  3. Round 1: nonce generation and injection into the PSBT
  4. Round 2: partial signing by each participant
  5. Finalization: partial sigs aggregated into a 64-byte Schnorr sig
  6. Final PSBT verification

Run with:
  LD_LIBRARY_PATH=src/.libs PYTHONPATH=src/swig_python python3 contrib/musig2_psbt_2of2.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'swig_python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'test'))

from ctypes import *
from util import *

# ── Constants ────────────────────────────────────────────────────────────────

EC_PUBLIC_KEY_LEN    = 33
EC_XONLY_PUBLIC_KEY_LEN = 32
EC_SIGNATURE_LEN     = 64
EC_FLAG_SCHNORR      = 0x2
WALLY_SIGHASH_DEFAULT = 0x00
BIP32_VER_MAIN_PUBLIC = 0x0488B21E

# Two participant secret keys (for example use only — never hardcode in production!)
SECKEY1 = bytes([0x01] * 32)
SECKEY2 = bytes([0x02] * 32)


def derive_pubkey(seckey):
    """Derive the compressed 33-byte pubkey from a 32-byte secret key."""
    pub, pub_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
    ret = wally_ec_public_key_from_private_key(seckey, len(seckey), pub, pub_len)
    assert ret == WALLY_OK, 'derive_pubkey failed'
    return bytes(pub)


def main():
    # ── Step 1: Key Aggregation ───────────────────────────────────────────────
    pk1 = derive_pubkey(SECKEY1)
    pk2 = derive_pubkey(SECKEY2)
    pub_keys_flat = pk1 + pk2        # concatenated compressed pubkeys

    agg_pk_xonly, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
    cache = c_void_p()
    ret = wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                 agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN, cache)
    assert ret == WALLY_OK, 'key aggregation failed'
    assert cache.value is not None
    print(f'Aggregate x-only pubkey: {bytes(agg_pk_xonly).hex()}')

    # The PSBT stores participant keys under the compressed (33-byte) agg pubkey
    agg_pubkey = bytes([0x02]) + bytes(agg_pk_xonly)
    agg_pubkey_buf, _ = make_cbuffer(agg_pubkey.hex())

    # ── Step 2: Build PSBT with a P2TR input ─────────────────────────────────
    # Build the P2TR scriptpubkey. Passing the 33-byte COMPRESSED aggregate
    # (internal) key makes wally apply the BIP-341 key-path output tweak, so the
    # coin is locked to the standard taproot output key Q = P + H_TapTweak(P)*G
    # (NOT the raw aggregate key P). The PSBT musig signing flow re-applies the
    # same tweak internally so the aggregated signature is valid under Q.
    p2tr_buf, _ = make_cbuffer('00' * 34)
    ret, p2tr_written = wally_scriptpubkey_p2tr_from_bytes(
        agg_pubkey, EC_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
    assert ret == WALLY_OK, 'P2TR scriptpubkey creation failed'
    p2tr_bytes = bytes(p2tr_buf[:p2tr_written])

    # Create PSBT v2 with 1 input and 1 output
    psbt = pointer(wally_psbt())
    assert wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt) == WALLY_OK

    # Add a dummy input (txid=0..0, vout=0)
    tx_in = pointer(wally_tx_input())
    assert wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in) == WALLY_OK

    # Add a dummy P2WPKH output (recipient)
    tx_output = pointer(wally_tx_output())
    assert wally_tx_output_init_alloc(
        1000, b'\x00\x14' + b'\xab' * 20, 22, tx_output) == WALLY_OK
    assert wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output) == WALLY_OK

    # Set the UTXO being spent (P2TR output, 200,000 sat)
    utxo = pointer(wally_tx_output())
    assert wally_tx_output_init_alloc(
        200000, p2tr_bytes, len(p2tr_bytes), utxo) == WALLY_OK
    assert wally_psbt_set_input_witness_utxo(psbt, 0, utxo) == WALLY_OK
    assert wally_psbt_set_input_amount(psbt, 0, 200000) == WALLY_OK

    # Record the taproot internal key (x-only) so sighash knows the script tree
    assert wally_psbt_set_input_taproot_internal_key(
        psbt, 0, agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN) == WALLY_OK

    # Register both participant pubkeys in the PSBT under the aggregate key.
    # This is the BIP-373 MUSIG2_PARTICIPANT_PUBKEYS field.
    participants_flat = pk1 + pk2
    ret = wally_psbt_input_add_musig2_participant_pubkeys(
        psbt.contents.inputs,
        agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
        participants_flat, len(participants_flat))
    assert ret == WALLY_OK, 'registering participant pubkeys failed'

    print('PSBT created with P2TR input')

    # ── Step 3: Round 1 — Nonce Generation ───────────────────────────────────
    # Each signer independently generates a (secnonce, pubnonce) pair using a
    # unique session random value.  wally_psbt_musig2_add_nonce stores the
    # pubnonce in the PSBT and returns the secnonce to the caller.
    # Each signer MUST use unique, cryptographically secure randomness here and
    # MUST NOT reuse it across signing sessions (MuSig2 nonce reuse leaks the key).
    secrand1, _ = make_cbuffer(os.urandom(32).hex())
    secrand2, _ = make_cbuffer(os.urandom(32).hex())
    sn1 = c_void_p()
    sn2 = c_void_p()

    ret = wally_psbt_musig2_add_nonce(
        psbt, 0,
        secrand1, 32,       # unique session random (32 bytes)
        None, 0,            # optional seckey for binding
        pk1, EC_PUBLIC_KEY_LEN,
        agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
        None, 0,            # no tapscript leaf hash (key-path spend)
        None, 0,            # no external keyagg_cache
        byref(sn1))
    assert ret == WALLY_OK, 'participant 1 nonce generation failed'

    ret = wally_psbt_musig2_add_nonce(
        psbt, 0,
        secrand2, 32,
        None, 0,
        pk2, EC_PUBLIC_KEY_LEN,
        agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
        None, 0, None, 0,
        byref(sn2))
    assert ret == WALLY_OK, 'participant 2 nonce generation failed'

    print('Round 1 complete: both pubnonces stored in PSBT')

    # ── Step 4: Round 2 — Partial Signing ────────────────────────────────────
    # Each signer produces a partial signature using their secnonce + seckey.
    # The keyagg_cache (from step 1) must be the same object for both signers.
    seckey1, _ = make_cbuffer(SECKEY1.hex())
    seckey2, _ = make_cbuffer(SECKEY2.hex())

    ret = wally_psbt_musig2_sign(
        psbt, 0,
        sn1.value,          # secnonce is consumed (zeroed) after this call
        seckey1, 32,
        pk1, EC_PUBLIC_KEY_LEN,
        agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
        None, 0,            # no tapscript leaf hash
        cache.value, 0,     # keyagg_cache from step 1
        None)               # partial_sig_out (stored in PSBT internally)
    assert ret == WALLY_OK, 'participant 1 partial sign failed'

    ret = wally_psbt_musig2_sign(
        psbt, 0,
        sn2.value,
        seckey2, 32,
        pk2, EC_PUBLIC_KEY_LEN,
        agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
        None, 0,
        cache.value, 0,
        None)
    assert ret == WALLY_OK, 'participant 2 partial sign failed'

    print('Round 2 complete: both partial signatures stored in PSBT')

    # ── Step 5: Finalization ──────────────────────────────────────────────────
    # wally_psbt_musig2_finalize_input aggregates the two partial signatures
    # into a single 64-byte BIP-340 Schnorr signature and writes it as the
    # PSBT TAP_KEY_SIG field.  The pubnonce and partial sig entries are then
    # cleared from the PSBT.
    ret = wally_psbt_musig2_finalize_input(
        psbt, 0,
        agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
        None, 0,            # no tapscript leaf hash
        cache.value, 0)
    assert ret == WALLY_OK, 'finalization failed'

    # Read back the aggregated Schnorr signature
    sig_buf, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
    ret, sig_written = wally_psbt_get_input_taproot_signature(
        psbt, 0, sig_buf, EC_SIGNATURE_LEN)
    assert ret == WALLY_OK and sig_written == EC_SIGNATURE_LEN
    print(f'Final Schnorr signature ({sig_written} bytes): {bytes(sig_buf).hex()}')

    # ── Step 6: Cryptographic Verification ───────────────────────────────────
    # Verify the signature against the P2TR output key.
    # The P2TR scriptpubkey is OP_1 <32-byte-tweaked-output-key>;
    # bytes [2:34] are the x-only output key the signature must verify against.
    output_xonly_key = p2tr_bytes[2:34]
    output_key_buf, _ = make_cbuffer(output_xonly_key.hex())

    # Build the transaction from PSBT data so we can compute the sighash
    tx_pp = POINTER(wally_tx)()
    assert wally_tx_init_alloc(2, 0, 1, 1, byref(tx_pp)) == WALLY_OK
    zero_txid, _ = make_cbuffer('00' * 32)
    assert wally_tx_add_raw_input(tx_pp, zero_txid, 32, 0, 0, None, 0, None, 0) == WALLY_OK
    out_script = b'\x00\x14' + b'\xab' * 20
    assert wally_tx_add_raw_output(tx_pp, 1000, out_script, len(out_script), 0) == WALLY_OK

    sighash_buf, _ = make_cbuffer('00' * 32)
    ret = wally_psbt_get_input_signature_hash(
        psbt, 0, tx_pp, None, 0, WALLY_SIGHASH_DEFAULT, sighash_buf, 32)
    assert ret == WALLY_OK, 'sighash computation failed'

    ret = wally_ec_sig_verify(
        output_key_buf, EC_XONLY_PUBLIC_KEY_LEN,
        sighash_buf, 32,
        EC_FLAG_SCHNORR,
        sig_buf, EC_SIGNATURE_LEN)
    assert ret == WALLY_OK, 'BIP-340 signature verification FAILED'
    print('BIP-340 Schnorr signature verified successfully')

    # ── Cleanup ───────────────────────────────────────────────────────────────
    wally_musig_secnonce_free(sn1.value)
    wally_musig_secnonce_free(sn2.value)
    wally_musig_keyagg_cache_free(cache.value)
    wally_tx_free(tx_pp)
    wally_psbt_free(psbt)

    print('MuSig2 2-of-2 example complete')


if __name__ == '__main__':
    main()
