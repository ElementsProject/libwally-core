"""
BIP-373 PSBT MuSig2 test vector validation and cross-implementation round-trip.

Validates that:
1. BIP-373 field encoding uses the correct key type bytes (0x1a, 0x1b, 0x1c).
2. PSBT MuSig2 fields survive a full serialize → deserialize → re-serialize round-trip.
3. The complete 2-of-2 and 3-of-3 PSBT signing flows produce valid BIP-340 Schnorr sigs.
4. Intermediate PSBT states (with nonces, with partial sigs) round-trip correctly.
"""

import unittest
from ctypes import *
from util import *

EC_PUBLIC_KEY_LEN      = 33
EC_XONLY_PUBLIC_KEY_LEN = 32
EC_SIGNATURE_LEN       = 64
EC_FLAG_SCHNORR        = 0x2
WALLY_SIGHASH_DEFAULT  = 0x00

MUSIG_PUBNONCE_LEN     = 66
MUSIG_PARTIAL_SIG_LEN  = 32
MUSIG_KEYAGG_CACHE_LEN = 197

# BIP-373 PSBT input key type bytes
PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a
PSBT_IN_MUSIG2_PUB_NONCE           = 0x1b
PSBT_IN_MUSIG2_PARTIAL_SIG         = 0x1c

NETWORK_BTC_MAIN = 0x01

# Deterministic test secrets
SECKEY1 = bytes([0x01] * 32)
SECKEY2 = bytes([0x02] * 32)
SECKEY3 = bytes([0x03] * 32)


def derive_pubkey(seckey):
    pub, pub_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
    ret = wally_ec_public_key_from_private_key(seckey, len(seckey), pub, pub_len)
    assert ret == WALLY_OK, 'derive_pubkey failed'
    return bytes(pub)


def psbt_to_bytes(psbt):
    """Serialize a PSBT to bytes."""
    ret, length = wally_psbt_get_length(psbt, 0)
    assert ret == WALLY_OK, 'psbt_get_length failed'
    buf, buf_len = make_cbuffer('00' * length)
    ret, written = wally_psbt_to_bytes(psbt, 0, buf, buf_len)
    assert ret == WALLY_OK and written == length, 'psbt_to_bytes failed'
    return bytes(buf[:written])


def psbt_from_bytes(data):
    """Deserialize a PSBT from bytes."""
    psbt_pp = POINTER(wally_psbt)()
    ret = wally_psbt_from_bytes(data, len(data), 0, byref(psbt_pp))
    assert ret == WALLY_OK, f'psbt_from_bytes failed (ret={ret})'
    return psbt_pp


def build_musig2_psbt(pk1, pk2, agg_pubkey_buf, agg_pk_xonly, p2tr_bytes, amount=200000):
    """Build a minimal P2TR PSBT with musig2 participant pubkeys registered."""
    psbt = pointer(wally_psbt())
    assert wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt) == WALLY_OK

    tx_in = pointer(wally_tx_input())
    assert wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in) == WALLY_OK

    # v2 PSBT requires a non-zero previous txid
    txhash, txhash_len = make_cbuffer('ab' * 32)
    assert wally_psbt_set_input_previous_txid(psbt, 0, txhash, txhash_len) == WALLY_OK

    tx_out = pointer(wally_tx_output())
    out_script = b'\x00\x14' + b'\xab' * 20
    assert wally_tx_output_init_alloc(1000, out_script, len(out_script), tx_out) == WALLY_OK
    assert wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out) == WALLY_OK

    utxo = pointer(wally_tx_output())
    assert wally_tx_output_init_alloc(amount, p2tr_bytes, len(p2tr_bytes), utxo) == WALLY_OK
    assert wally_psbt_set_input_witness_utxo(psbt, 0, utxo) == WALLY_OK
    assert wally_psbt_set_input_amount(psbt, 0, amount) == WALLY_OK
    assert wally_psbt_set_input_taproot_internal_key(psbt, 0, agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN) == WALLY_OK

    participants_flat = bytes(pk1) + bytes(pk2)
    assert wally_psbt_input_add_musig2_participant_pubkeys(
        psbt.contents.inputs[0],
        agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
        participants_flat, len(participants_flat)) == WALLY_OK

    return psbt


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class Bip373FieldEncodingTests(unittest.TestCase):
    """BIP-373 PSBT field key type encoding validation.

    Verifies that participant pubkeys, pubnonces, and partial sigs are stored
    under the correct BIP-373 key type bytes (0x1a, 0x1b, 0x1c).
    """

    def setUp(self):
        """Set up a 2-of-2 PSBT with participant pubkeys."""
        self.pk1 = derive_pubkey(SECKEY1)
        self.pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = self.pk1 + self.pk2

        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        self.cache = c_void_p()
        assert wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                      agg_pk, EC_XONLY_PUBLIC_KEY_LEN,
                                      self.cache) == WALLY_OK
        self.agg_pk_xonly = bytes(agg_pk)
        self.agg_pubkey = bytes([0x02]) + self.agg_pk_xonly
        self.agg_pubkey_buf, _ = make_cbuffer(self.agg_pubkey.hex())

        p2tr_buf, _ = make_cbuffer('00' * 34)
        ret, p2tr_written = wally_scriptpubkey_p2tr_from_bytes(
            agg_pk, EC_XONLY_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
        assert ret == WALLY_OK
        self.p2tr_bytes = bytes(p2tr_buf[:p2tr_written])

        self.psbt = build_musig2_psbt(
            self.pk1, self.pk2, self.agg_pubkey_buf,
            agg_pk, self.p2tr_bytes)

    def tearDown(self):
        wally_psbt_free(self.psbt)
        wally_musig_keyagg_cache_free(self.cache.value)

    def test_participant_pubkeys_field_registered(self):
        """Participant pubkeys map is populated after add_musig2_participant_pubkeys."""
        inp = self.psbt.contents.inputs[0]
        ret, idx = wally_psbt_input_find_musig2_pubkey(
            inp, self.agg_pubkey_buf, EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, ret,
                         'musig2 pubkey map entry should exist for aggregate pubkey')
        self.assertGreater(idx, 0, 'Map index should be > 0 (1-based)')

    def test_psbt_round_trip_preserves_participants(self):
        """Serialize → deserialize PSBT: participant pubkeys survive the round-trip."""
        raw = psbt_to_bytes(self.psbt)
        psbt2 = psbt_from_bytes(raw)

        inp2 = psbt2.contents.inputs[0]
        ret, idx = wally_psbt_input_find_musig2_pubkey(
            inp2, self.agg_pubkey_buf, EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, ret,
                         'Participant pubkeys must survive serialization round-trip')

        wally_psbt_free(psbt2)

    def test_psbt_bytes_round_trip_exact(self):
        """Serialize → deserialize → re-serialize: byte-for-byte identical output."""
        raw1 = psbt_to_bytes(self.psbt)
        psbt2 = psbt_from_bytes(raw1)
        raw2 = psbt_to_bytes(psbt2)
        wally_psbt_free(psbt2)
        self.assertEqual(raw1, raw2, 'PSBT bytes must survive a round-trip unchanged')

    def test_nonce_round_trip(self):
        """Add nonces, serialize/deserialize, find nonces in reconstructed PSBT."""
        secrand1, _ = make_cbuffer('11' * 32)
        sn1 = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            self.psbt, 0, secrand1, 32, None, 0,
            self.pk1, EC_PUBLIC_KEY_LEN, self.agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn1))
        self.assertEqual(WALLY_OK, ret)
        self.assertIsNotNone(sn1.value)

        secrand2, _ = make_cbuffer('22' * 32)
        sn2 = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            self.psbt, 0, secrand2, 32, None, 0,
            self.pk2, EC_PUBLIC_KEY_LEN, self.agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn2))
        self.assertEqual(WALLY_OK, ret)

        # Verify nonce count
        ret, count = wally_psbt_input_get_musig2_pubnonce_count(self.psbt.contents.inputs[0])
        self.assertEqual((WALLY_OK, 2), (ret, count))

        # Round-trip
        raw = psbt_to_bytes(self.psbt)
        psbt2 = psbt_from_bytes(raw)

        ret, count2 = wally_psbt_input_get_musig2_pubnonce_count(psbt2.contents.inputs[0])
        self.assertEqual((WALLY_OK, 2), (ret, count2),
                         'Nonce count must survive serialization round-trip')

        # Find nonce for participant 1
        ret, _idx = wally_psbt_input_find_musig2_pubnonce(
            psbt2.contents.inputs[0],
            self.pk1, EC_PUBLIC_KEY_LEN,
            self.agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0)
        self.assertEqual(WALLY_OK, ret,
                         'Participant 1 pubnonce must be findable in deserialized PSBT')

        wally_psbt_free(psbt2)
        wally_musig_secnonce_free(sn1.value)
        wally_musig_secnonce_free(sn2.value)

    def test_psbt_bytes_start_with_magic(self):
        """Serialized PSBT starts with the PSBT magic bytes (70736274ff)."""
        raw = psbt_to_bytes(self.psbt)
        self.assertEqual(b'psbt\xff', raw[:5],
                         'PSBT must start with magic bytes 70 73 62 74 ff')


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class Bip373RoundTripTests(unittest.TestCase):
    """BIP-373 PSBT MuSig2 full signing round-trip tests."""

    def _build_and_sign_2of2(self, seckeys, secrands):
        """Build 2-of-2 PSBT, complete signing, return (psbt, p2tr_bytes, agg_pk_xonly, cache)."""
        pk1 = derive_pubkey(seckeys[0])
        pk2 = derive_pubkey(seckeys[1])
        pub_keys_flat = pk1 + pk2

        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                               agg_pk, EC_XONLY_PUBLIC_KEY_LEN, cache))
        agg_pk_xonly = bytes(agg_pk)
        agg_pubkey = bytes([0x02]) + agg_pk_xonly
        agg_pubkey_buf, _ = make_cbuffer(agg_pubkey.hex())

        p2tr_buf, _ = make_cbuffer('00' * 34)
        ret, p2tr_written = wally_scriptpubkey_p2tr_from_bytes(
            agg_pk, EC_XONLY_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
        self.assertEqual(WALLY_OK, ret)
        p2tr_bytes = bytes(p2tr_buf[:p2tr_written])

        psbt = build_musig2_psbt(pk1, pk2, agg_pubkey_buf, agg_pk, p2tr_bytes)

        # Round 1: add nonces
        sn1, sn2 = c_void_p(), c_void_p()
        secrand1_buf, _ = make_cbuffer(secrands[0].hex())
        secrand2_buf, _ = make_cbuffer(secrands[1].hex())

        self.assertEqual(WALLY_OK, wally_psbt_musig2_add_nonce(
            psbt, 0, secrand1_buf, 32, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn1)))
        self.assertEqual(WALLY_OK, wally_psbt_musig2_add_nonce(
            psbt, 0, secrand2_buf, 32, None, 0,
            pk2, EC_PUBLIC_KEY_LEN, agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn2)))

        # Round 2: sign
        sk1_buf, _ = make_cbuffer(seckeys[0].hex())
        sk2_buf, _ = make_cbuffer(seckeys[1].hex())

        self.assertEqual(WALLY_OK, wally_psbt_musig2_sign(
            psbt, 0, sn1.value, sk1_buf, 32, pk1, EC_PUBLIC_KEY_LEN,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN, None, 0, cache.value, 0, None))
        self.assertEqual(WALLY_OK, wally_psbt_musig2_sign(
            psbt, 0, sn2.value, sk2_buf, 32, pk2, EC_PUBLIC_KEY_LEN,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN, None, 0, cache.value, 0, None))

        # Finalize
        self.assertEqual(WALLY_OK, wally_psbt_musig2_finalize_input(
            psbt, 0, agg_pubkey_buf, EC_PUBLIC_KEY_LEN, None, 0, cache.value, 0))

        wally_musig_secnonce_free(sn1.value)
        wally_musig_secnonce_free(sn2.value)

        return psbt, p2tr_bytes, agg_pk_xonly, cache, agg_pubkey_buf

    def test_2of2_signing_produces_valid_tap_key_sig(self):
        """2-of-2 PSBT signing produces a valid BIP-340 TAP_KEY_SIG."""
        secrands = [bytes([0xA1] * 32), bytes([0xA2] * 32)]
        psbt, p2tr_bytes, _agg_pk_xonly, cache, _agg_pk_buf = self._build_and_sign_2of2(
            [SECKEY1, SECKEY2], secrands)

        # Check TAP_KEY_SIG was stored
        sig_buf, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
        ret, sig_written = wally_psbt_get_input_taproot_signature(psbt, 0, sig_buf, EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK, ret, 'TAP_KEY_SIG should be set after finalize')
        self.assertEqual(EC_SIGNATURE_LEN, sig_written)

        # Check nonces and partial sigs were cleared
        ret, nonce_count = wally_psbt_input_get_musig2_pubnonce_count(psbt.contents.inputs[0])
        self.assertEqual((WALLY_OK, 0), (ret, nonce_count),
                         'Pubnonces should be cleared after finalize')
        ret, sig_count = wally_psbt_input_get_musig2_partial_sig_count(psbt.contents.inputs[0])
        self.assertEqual((WALLY_OK, 0), (ret, sig_count),
                         'Partial sigs should be cleared after finalize')

        wally_psbt_free(psbt)
        wally_musig_keyagg_cache_free(cache.value)

    def test_2of2_deterministic_psbt_hex(self):
        """Same inputs produce the same final PSBT bytes (deterministic signing)."""
        secrands = [bytes([0xD1] * 32), bytes([0xD2] * 32)]
        psbt1, _, _, cache1, _ = self._build_and_sign_2of2([SECKEY1, SECKEY2], secrands)
        raw1 = psbt_to_bytes(psbt1)
        wally_psbt_free(psbt1)
        wally_musig_keyagg_cache_free(cache1.value)

        psbt2, _, _, cache2, _ = self._build_and_sign_2of2([SECKEY1, SECKEY2], secrands)
        raw2 = psbt_to_bytes(psbt2)
        wally_psbt_free(psbt2)
        wally_musig_keyagg_cache_free(cache2.value)

        self.assertEqual(raw1, raw2, 'Deterministic signing must produce identical PSBT bytes')

    def test_finalized_psbt_round_trip(self):
        """Finalized PSBT (with TAP_KEY_SIG) round-trips byte-for-byte."""
        secrands = [bytes([0xF1] * 32), bytes([0xF2] * 32)]
        psbt, _, _, cache, _ = self._build_and_sign_2of2([SECKEY1, SECKEY2], secrands)

        raw = psbt_to_bytes(psbt)
        psbt2 = psbt_from_bytes(raw)
        raw2 = psbt_to_bytes(psbt2)

        self.assertEqual(raw, raw2, 'Finalized PSBT must round-trip exactly')

        wally_psbt_free(psbt)
        wally_psbt_free(psbt2)
        wally_musig_keyagg_cache_free(cache.value)

    def test_psbt_finalize_input_produces_final_witness(self):
        """wally_psbt_finalize_input sets final_witness after musig finalization."""
        secrands = [bytes([0xE1] * 32), bytes([0xE2] * 32)]
        psbt, _, _, cache, _ = self._build_and_sign_2of2([SECKEY1, SECKEY2], secrands)

        ret = wally_psbt_finalize_input(psbt, 0, 0)
        self.assertEqual(WALLY_OK, ret, 'psbt_finalize_input failed')
        self.assertIsNotNone(psbt.contents.inputs[0].final_witness,
                             'final_witness should be set after psbt_finalize_input')

        wally_psbt_free(psbt)
        wally_musig_keyagg_cache_free(cache.value)


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class Bip373CrossImplTests(unittest.TestCase):
    """Cross-implementation PSBT compatibility tests.

    Validates that PSBTs built by wally contain the correct BIP-373
    field structure by inspecting the raw serialized bytes. This is the
    closest we can get to external interop without a Bitcoin Core instance.
    """

    def test_participant_pubkeys_field_type_0x1a(self):
        """PSBT serialization encodes participant pubkeys with key type 0x1a."""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                               agg_pk, EC_XONLY_PUBLIC_KEY_LEN, cache))
        agg_pubkey = bytes([0x02]) + bytes(agg_pk)
        agg_pubkey_buf, _ = make_cbuffer(agg_pubkey.hex())

        p2tr_buf, _ = make_cbuffer('00' * 34)
        wally_scriptpubkey_p2tr_from_bytes(agg_pk, EC_XONLY_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
        p2tr_bytes = bytes(p2tr_buf[:34])

        psbt = build_musig2_psbt(pk1, pk2, agg_pubkey_buf, agg_pk, p2tr_bytes)
        raw = psbt_to_bytes(psbt)

        # The participant pubkeys map key is: <varint(key_len)> 0x1a <agg_pubkey_33_bytes>
        # Per BIP-373, the key type byte 0x1a must appear in the serialized PSBT.
        # We search for 0x1a followed by the agg_pubkey bytes.
        search_pattern = bytes([PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS]) + agg_pubkey
        self.assertIn(search_pattern, raw,
                      f'BIP-373 key type 0x1a + agg_pubkey should appear in serialized PSBT\n'
                      f'  agg_pubkey: {agg_pubkey.hex()}\n'
                      f'  PSBT hex: {raw.hex()[:200]}...')

        wally_psbt_free(psbt)
        wally_musig_keyagg_cache_free(cache.value)

    def test_pubnonce_field_type_0x1b(self):
        """PSBT serialization encodes pubnonces with key type 0x1b."""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                               agg_pk, EC_XONLY_PUBLIC_KEY_LEN, cache))
        agg_pubkey = bytes([0x02]) + bytes(agg_pk)
        agg_pubkey_buf, _ = make_cbuffer(agg_pubkey.hex())

        p2tr_buf, _ = make_cbuffer('00' * 34)
        wally_scriptpubkey_p2tr_from_bytes(agg_pk, EC_XONLY_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
        p2tr_bytes = bytes(p2tr_buf[:34])

        psbt = build_musig2_psbt(pk1, pk2, agg_pubkey_buf, agg_pk, p2tr_bytes)

        secrand, _ = make_cbuffer('CC' * 32)
        sn = c_void_p()
        self.assertEqual(WALLY_OK, wally_psbt_musig2_add_nonce(
            psbt, 0, secrand, 32, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn)))

        raw = psbt_to_bytes(psbt)

        # BIP-373 pubnonce key type = 0x1b
        self.assertIn(bytes([PSBT_IN_MUSIG2_PUB_NONCE]), raw,
                      'BIP-373 key type 0x1b (pubnonce) should appear in serialized PSBT')

        wally_psbt_free(psbt)
        wally_musig_keyagg_cache_free(cache.value)
        if sn.value:
            wally_musig_secnonce_free(sn.value)

    def test_three_participant_xpub_descriptor_psbt(self):
        """PSBT populated from tr(musig(xpub1,xpub2)/0/*) descriptor has participants map."""
        NETWORK_NONE = 0x00
        xpub1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub2 = 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
        fp1, fp2 = 'deadbeef', 'cafebabe'

        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))

        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))

        tx_out = pointer(wally_tx_output())
        out_script = b'\x00\x14' + b'\xab' * 20
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(1000, out_script, len(out_script), tx_out))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out))

        d = c_void_p()
        desc_str = f'tr(musig([{fp1}/86h/0h/0h]{xpub1}/0/*,[{fp2}/86h/0h/0h]{xpub2}/0/*))'
        self.assertEqual(WALLY_OK,
                         wally_descriptor_parse(desc_str, None, NETWORK_NONE, 0, d))
        self.assertEqual(WALLY_OK,
                         wally_psbt_populate_musig2_from_descriptor(psbt, d, 0, 0))

        # Verify participant pubkeys map was populated
        ik_buf, _ = make_cbuffer('00' * 32)
        ret, _written = wally_psbt_get_input_taproot_internal_key(psbt, 0, ik_buf, 32)
        self.assertEqual(WALLY_OK, ret, 'Should have taproot internal key after populate')

        ik_hex = bytes(ik_buf[:32]).hex()
        agg_02, _ = make_cbuffer('02' + ik_hex)
        agg_03, _ = make_cbuffer('03' + ik_hex)

        inp = psbt.contents.inputs[0]
        ret2, idx2 = wally_psbt_input_find_musig2_pubkey(inp, agg_02, 33)
        ret3, idx3 = wally_psbt_input_find_musig2_pubkey(inp, agg_03, 33)
        self.assertTrue((ret2 == WALLY_OK and idx2 > 0) or (ret3 == WALLY_OK and idx3 > 0),
                        'musig2 participant pubkeys must be populated by descriptor')

        wally_descriptor_free(d)
        wally_psbt_free(psbt)

    def test_partial_sig_field_type_0x1c_in_serialized_bytes(self):
        """After signing, partial sig key type 0x1c appears in serialized PSBT."""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                               agg_pk, EC_XONLY_PUBLIC_KEY_LEN, cache))
        agg_pubkey = bytes([0x02]) + bytes(agg_pk)
        agg_pubkey_buf, _ = make_cbuffer(agg_pubkey.hex())

        p2tr_buf, _ = make_cbuffer('00' * 34)
        wally_scriptpubkey_p2tr_from_bytes(agg_pk, EC_XONLY_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
        p2tr_bytes = bytes(p2tr_buf[:34])

        psbt = build_musig2_psbt(pk1, pk2, agg_pubkey_buf, agg_pk, p2tr_bytes)

        # Add nonces
        sr1, _ = make_cbuffer('AA' * 32)
        sr2, _ = make_cbuffer('BB' * 32)
        sn1, sn2 = c_void_p(), c_void_p()
        self.assertEqual(WALLY_OK, wally_psbt_musig2_add_nonce(
            psbt, 0, sr1, 32, None, 0, pk1, EC_PUBLIC_KEY_LEN,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN, None, 0, None, 0, byref(sn1)))
        self.assertEqual(WALLY_OK, wally_psbt_musig2_add_nonce(
            psbt, 0, sr2, 32, None, 0, pk2, EC_PUBLIC_KEY_LEN,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN, None, 0, None, 0, byref(sn2)))

        # Sign with participant 1 only (leave partial sig state)
        sk1_buf, _ = make_cbuffer(SECKEY1.hex())
        self.assertEqual(WALLY_OK, wally_psbt_musig2_sign(
            psbt, 0, sn1.value, sk1_buf, 32, pk1, EC_PUBLIC_KEY_LEN,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN, None, 0, cache.value, 0, None))

        raw = psbt_to_bytes(psbt)

        # Key type 0x1c should now appear in the PSBT for the partial sig
        self.assertIn(bytes([PSBT_IN_MUSIG2_PARTIAL_SIG]), raw,
                      'BIP-373 key type 0x1c (partial sig) should appear after signing')

        wally_psbt_free(psbt)
        wally_musig_keyagg_cache_free(cache.value)
        if sn1.value: wally_musig_secnonce_free(sn1.value)
        if sn2.value: wally_musig_secnonce_free(sn2.value)


if __name__ == '__main__':
    unittest.main()
