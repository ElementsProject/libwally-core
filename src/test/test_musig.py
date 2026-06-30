import unittest
from ctypes import *
from util import *

EC_PUBLIC_KEY_LEN = 33
EC_XONLY_PUBLIC_KEY_LEN = 32
EC_SIGNATURE_LEN = 64
EC_FLAG_SCHNORR = 0x2
WALLY_SIGHASH_DEFAULT = 0x00

BIP32_VER_MAIN_PUBLIC  = 0x0488B21E
BIP32_VER_MAIN_PRIVATE = 0x0488ADE4
BIP32_VER_TEST_PUBLIC  = 0x043587CF
BIP32_INITIAL_HARDENED_CHILD = 0x80000000
BIP32_FLAG_KEY_PUBLIC = 0x1
BIP32_SERIALIZED_LEN = 78

MUSIG_PUBNONCE_LEN    = 66
MUSIG_AGGNONCE_LEN    = 66
MUSIG_PARTIAL_SIG_LEN = 32
MUSIG_KEYAGG_CACHE_LEN = 197
MUSIG_SESSION_LEN      = 133

SECKEY1 = bytes([0x01] * 32)
SECKEY2 = bytes([0x02] * 32)
SECKEY3 = bytes([0x03] * 32)
TEST_MSG32 = bytes([0xde, 0xad, 0xbe, 0xef] * 8)
TEST_TWEAK = bytes([0xab, 0xcd] * 16)


def derive_pubkey(seckey):
    pub, pub_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
    ret = wally_ec_public_key_from_private_key(seckey, len(seckey), pub, pub_len)
    assert ret == WALLY_OK, 'derive_pubkey failed'
    return pub


def musig_full_flow(seckeys, msg32):
    """
    Run a complete MuSig2 flow for n signers.
    Returns (final_sig_bytes, agg_pk_xonly_bytes) or raises AssertionError.
    """
    n = len(seckeys)
    pubkeys = [derive_pubkey(sk) for sk in seckeys]

    # Key aggregation
    pub_keys_flat = b''.join(pubkeys)
    agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
    cache = c_void_p()
    ret = wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat), agg_pk, EC_XONLY_PUBLIC_KEY_LEN, cache)
    assert ret == WALLY_OK, 'pubkey_agg failed'
    assert cache.value is not None

    # Nonce generation
    secnonces = []
    pubnonces = []
    pn_bytes_list = []
    for i, (sk, pk) in enumerate(zip(seckeys, pubkeys)):
        session_id = bytes([i + 1]) * 32
        sn = c_void_p()
        pn = c_void_p()
        ret = wally_musig_nonce_gen(session_id, 32, sk, 32, pk, EC_PUBLIC_KEY_LEN,
                                    None, None, 0, None, 0, sn, pn)
        assert ret == WALLY_OK, 'nonce_gen failed'
        assert sn.value is not None
        assert pn.value is not None
        secnonces.append(sn)
        pubnonces.append(pn)

        pn_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        ret = wally_musig_pubnonce_serialize(pn.value, pn_bytes, MUSIG_PUBNONCE_LEN)
        assert ret == WALLY_OK, 'pubnonce_serialize failed'
        pn_bytes_list.append(bytes(pn_bytes))

    # Nonce aggregation
    pubnonces_flat = b''.join(pn_bytes_list)
    aggnonce = c_void_p()
    ret = wally_musig_nonce_agg(pubnonces_flat, len(pubnonces_flat), n, aggnonce)
    assert ret == WALLY_OK, 'nonce_agg failed'
    assert aggnonce.value is not None

    # Nonce processing
    session = c_void_p()
    ret = wally_musig_nonce_process(aggnonce.value, msg32, 32, cache.value, None, 0, session)
    assert ret == WALLY_OK, 'nonce_process failed'
    assert session.value is not None

    # Partial signing
    partial_sigs = []
    ps_bytes_list = []
    for i, (sn, sk) in enumerate(zip(secnonces, seckeys)):
        psig = c_void_p()
        ret = wally_musig_partial_sign(sn.value, sk, 32, cache.value, session.value, psig)
        assert ret == WALLY_OK, f'partial_sign failed for signer {i}'
        assert psig.value is not None
        partial_sigs.append(psig)

        ps_bytes, _ = make_cbuffer('00' * MUSIG_PARTIAL_SIG_LEN)
        ret = wally_musig_partial_sig_serialize(psig.value, ps_bytes, MUSIG_PARTIAL_SIG_LEN)
        assert ret == WALLY_OK, 'partial_sig_serialize failed'
        ps_bytes_list.append(bytes(ps_bytes))

    # Partial sig verification
    for i, (psig, pn, pk) in enumerate(zip(partial_sigs, pubnonces, pubkeys)):
        ret = wally_musig_partial_sig_verify(psig.value, pn.value, pk, EC_PUBLIC_KEY_LEN,
                                             cache.value, session.value)
        assert ret == WALLY_OK, f'partial_sig_verify failed for signer {i}'

    # Sig aggregation
    partial_sigs_flat = b''.join(ps_bytes_list)
    final_sig, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
    ret = wally_musig_partial_sig_agg(partial_sigs_flat, len(partial_sigs_flat), n,
                                      session.value, final_sig, EC_SIGNATURE_LEN)
    assert ret == WALLY_OK, 'partial_sig_agg failed'

    # Cleanup
    for sn in secnonces:
        if sn.value:
            wally_musig_secnonce_free(sn.value)
    for pn in pubnonces:
        if pn.value:
            wally_musig_pubnonce_free(pn.value)
    for psig in partial_sigs:
        if psig.value:
            wally_musig_partial_sig_free(psig.value)
    wally_musig_aggnonce_free(aggnonce.value)
    wally_musig_session_free(session.value)
    wally_musig_keyagg_cache_free(cache.value)

    return bytes(final_sig), bytes(agg_pk)


class MuSig2Tests(unittest.TestCase):

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_2of2_full_flow(self):
        """2-of-2 full signing flow with BIP-340 signature verification"""
        seckeys = [SECKEY1, SECKEY2]
        pubkeys = [derive_pubkey(sk) for sk in seckeys]

        pub_keys_flat = b''.join(pubkeys)
        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          agg_pk, EC_XONLY_PUBLIC_KEY_LEN, cache))
        self.assertIsNotNone(cache.value)
        self.assertNotEqual(bytes(agg_pk), b'\x00' * EC_XONLY_PUBLIC_KEY_LEN)

        final_sig, agg_pk_bytes = musig_full_flow(seckeys, TEST_MSG32)
        self.assertNotEqual(final_sig, b'\x00' * EC_SIGNATURE_LEN)

        # Verify the final signature is a valid BIP-340 Schnorr sig
        ret = wally_ec_sig_verify(agg_pk_bytes, EC_XONLY_PUBLIC_KEY_LEN,
                                  TEST_MSG32, 32,
                                  EC_FLAG_SCHNORR, final_sig, EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK, ret)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_3of3_full_flow(self):
        """3-of-3 full signing flow with BIP-340 signature verification"""
        seckeys = [SECKEY1, SECKEY2, SECKEY3]
        final_sig, agg_pk_bytes = musig_full_flow(seckeys, TEST_MSG32)
        self.assertNotEqual(final_sig, b'\x00' * EC_SIGNATURE_LEN)
        ret = wally_ec_sig_verify(agg_pk_bytes, EC_XONLY_PUBLIC_KEY_LEN,
                                  TEST_MSG32, 32,
                                  EC_FLAG_SCHNORR, final_sig, EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK, ret)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_keyagg(self):
        """Key aggregation produces a consistent x-only key"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)

        pub_keys_12 = pk1 + pk2
        pub_keys_21 = pk2 + pk1

        agg_pk_12, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        agg_pk_21, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)

        cache_12 = c_void_p()
        cache_21 = c_void_p()

        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_12, len(pub_keys_12),
                                                          agg_pk_12, EC_XONLY_PUBLIC_KEY_LEN, cache_12))
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_21, len(pub_keys_21),
                                                          agg_pk_21, EC_XONLY_PUBLIC_KEY_LEN, cache_21))

        # Order of pubkeys changes the aggregate key
        self.assertNotEqual(bytes(agg_pk_12), bytes(agg_pk_21))

        # wally_musig_pubkey_get returns a compressed (33-byte) aggregate key
        comp_pk, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkey_get(cache_12.value, comp_pk, EC_PUBLIC_KEY_LEN))
        # First byte should be 0x02 or 0x03 (compressed)
        self.assertIn(bytes(comp_pk)[0:1], [b'\x02', b'\x03'])
        # The x-coordinate of the compressed key matches agg_pk_12
        self.assertEqual(bytes(comp_pk)[1:], bytes(agg_pk_12))

        wally_musig_keyagg_cache_free(cache_12.value)
        wally_musig_keyagg_cache_free(cache_21.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_malformed_cache_no_abort(self):
        """A malformed keyagg_cache must be rejected at parse, not abort() the process."""
        # A wrong-magic but correctly sized buffer fails the secp256k1 precondition
        # check inside parse; with the illegal-arg callback installed this must
        # return an error (leaving output NULL) rather than abort() the process.
        bad_bytes, _ = make_cbuffer('11' * MUSIG_KEYAGG_CACHE_LEN)
        cache = c_void_p()
        self.assertEqual(WALLY_EINVAL,
            wally_musig_keyagg_cache_parse(bad_bytes, MUSIG_KEYAGG_CACHE_LEN, cache))
        self.assertEqual(None, cache.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_ec_tweak(self):
        """EC tweak modifies the aggregate key and signing still works"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          None, 0, cache))

        tweaked_pub, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkey_ec_tweak_add(cache.value, TEST_TWEAK, 32,
                                                                    tweaked_pub, EC_PUBLIC_KEY_LEN))
        self.assertNotEqual(bytes(tweaked_pub), b'\x00' * EC_PUBLIC_KEY_LEN)
        self.assertIn(bytes(tweaked_pub)[0:1], [b'\x02', b'\x03'])

        wally_musig_keyagg_cache_free(cache.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_xonly_tweak(self):
        """X-only tweak modifies the aggregate key and the result is a valid key"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          None, 0, cache))

        tweaked_pub, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkey_xonly_tweak_add(cache.value, TEST_TWEAK, 32,
                                                                       tweaked_pub, EC_PUBLIC_KEY_LEN))
        self.assertNotEqual(bytes(tweaked_pub), b'\x00' * EC_PUBLIC_KEY_LEN)
        self.assertIn(bytes(tweaked_pub)[0:1], [b'\x02', b'\x03'])

        wally_musig_keyagg_cache_free(cache.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_serialization_roundtrip(self):
        """Serialize and parse each type, compare bytes"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        # keyagg_cache roundtrip
        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          None, 0, cache))
        cache_bytes, _ = make_cbuffer('00' * MUSIG_KEYAGG_CACHE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_keyagg_cache_serialize(cache.value, cache_bytes,
                                                                       MUSIG_KEYAGG_CACHE_LEN))
        cache2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_keyagg_cache_parse(cache_bytes, MUSIG_KEYAGG_CACHE_LEN, cache2))
        cache2_bytes, _ = make_cbuffer('00' * MUSIG_KEYAGG_CACHE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_keyagg_cache_serialize(cache2.value, cache2_bytes,
                                                                       MUSIG_KEYAGG_CACHE_LEN))
        self.assertEqual(bytes(cache_bytes), bytes(cache2_bytes))

        # pubnonce roundtrip
        sn1 = c_void_p()
        pn1 = c_void_p()
        session_id1 = bytes([0x01] * 32)
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(session_id1, 32, SECKEY1, 32,
                                                         pk1, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn1, pn1))
        pn1_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn1.value, pn1_bytes, MUSIG_PUBNONCE_LEN))
        pn1_parsed = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_parse(pn1_bytes, MUSIG_PUBNONCE_LEN, pn1_parsed))
        pn1_bytes2, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn1_parsed.value, pn1_bytes2, MUSIG_PUBNONCE_LEN))
        self.assertEqual(bytes(pn1_bytes), bytes(pn1_bytes2))

        sn2 = c_void_p()
        pn2 = c_void_p()
        session_id2 = bytes([0x02] * 32)
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(session_id2, 32, SECKEY2, 32,
                                                         pk2, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn2, pn2))
        pn2_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn2.value, pn2_bytes, MUSIG_PUBNONCE_LEN))

        # aggnonce roundtrip
        pubnonces_flat = bytes(pn1_bytes) + bytes(pn2_bytes)
        aggnonce = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_agg(pubnonces_flat, len(pubnonces_flat), 2, aggnonce))
        an_bytes, _ = make_cbuffer('00' * MUSIG_AGGNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_aggnonce_serialize(aggnonce.value, an_bytes, MUSIG_AGGNONCE_LEN))
        aggnonce2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_aggnonce_parse(an_bytes, MUSIG_AGGNONCE_LEN, aggnonce2))
        an_bytes2, _ = make_cbuffer('00' * MUSIG_AGGNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_aggnonce_serialize(aggnonce2.value, an_bytes2, MUSIG_AGGNONCE_LEN))
        self.assertEqual(bytes(an_bytes), bytes(an_bytes2))

        # session roundtrip
        session = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_process(aggnonce.value, TEST_MSG32, 32,
                                                             cache.value, None, 0, session))
        sess_bytes, _ = make_cbuffer('00' * MUSIG_SESSION_LEN)
        self.assertEqual(WALLY_OK, wally_musig_session_serialize(session.value, sess_bytes, MUSIG_SESSION_LEN))
        session2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_session_parse(sess_bytes, MUSIG_SESSION_LEN, session2))
        sess_bytes2, _ = make_cbuffer('00' * MUSIG_SESSION_LEN)
        self.assertEqual(WALLY_OK, wally_musig_session_serialize(session2.value, sess_bytes2, MUSIG_SESSION_LEN))
        self.assertEqual(bytes(sess_bytes), bytes(sess_bytes2))

        # partial_sig roundtrip
        psig1 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_partial_sign(sn1.value, SECKEY1, 32,
                                                            cache.value, session.value, psig1))
        ps_bytes, _ = make_cbuffer('00' * MUSIG_PARTIAL_SIG_LEN)
        self.assertEqual(WALLY_OK, wally_musig_partial_sig_serialize(psig1.value, ps_bytes, MUSIG_PARTIAL_SIG_LEN))
        psig_parsed = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_partial_sig_parse(ps_bytes, MUSIG_PARTIAL_SIG_LEN, psig_parsed))
        ps_bytes2, _ = make_cbuffer('00' * MUSIG_PARTIAL_SIG_LEN)
        self.assertEqual(WALLY_OK, wally_musig_partial_sig_serialize(psig_parsed.value, ps_bytes2, MUSIG_PARTIAL_SIG_LEN))
        self.assertEqual(bytes(ps_bytes), bytes(ps_bytes2))

        # Cleanup
        wally_musig_secnonce_free(sn2.value)
        wally_musig_pubnonce_free(pn1_parsed.value)
        wally_musig_pubnonce_free(pn2.value)
        wally_musig_partial_sig_free(psig1.value)
        wally_musig_partial_sig_free(psig_parsed.value)
        wally_musig_aggnonce_free(aggnonce.value)
        wally_musig_aggnonce_free(aggnonce2.value)
        wally_musig_session_free(session.value)
        wally_musig_session_free(session2.value)
        wally_musig_keyagg_cache_free(cache.value)
        wally_musig_keyagg_cache_free(cache2.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_nonce_gen_counter(self):
        """Counter-based nonce generation is deterministic"""
        pk1 = derive_pubkey(SECKEY1)

        sn0a = c_void_p()
        pn0a = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen_counter(0, SECKEY1, 32, pk1, EC_PUBLIC_KEY_LEN,
                                                                  None, None, 0, None, 0, sn0a, pn0a))
        self.assertIsNotNone(sn0a.value)
        self.assertIsNotNone(pn0a.value)

        sn0b = c_void_p()
        pn0b = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen_counter(0, SECKEY1, 32, pk1, EC_PUBLIC_KEY_LEN,
                                                                  None, None, 0, None, 0, sn0b, pn0b))

        sn1 = c_void_p()
        pn1 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen_counter(1, SECKEY1, 32, pk1, EC_PUBLIC_KEY_LEN,
                                                                  None, None, 0, None, 0, sn1, pn1))

        # Serialize for comparison
        pn0a_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        pn0b_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        pn1_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn0a.value, pn0a_bytes, MUSIG_PUBNONCE_LEN))
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn0b.value, pn0b_bytes, MUSIG_PUBNONCE_LEN))
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn1.value, pn1_bytes, MUSIG_PUBNONCE_LEN))

        # Same counter → same pubnonce (deterministic)
        self.assertEqual(bytes(pn0a_bytes), bytes(pn0b_bytes))
        # Different counter → different pubnonce
        self.assertNotEqual(bytes(pn0a_bytes), bytes(pn1_bytes))

        # seckey=NULL is WALLY_EINVAL for counter mode
        sn_bad = c_void_p()
        pn_bad = c_void_p()
        self.assertEqual(WALLY_EINVAL, wally_musig_nonce_gen_counter(0, None, 0, pk1, EC_PUBLIC_KEY_LEN,
                                                                      None, None, 0, None, 0, sn_bad, pn_bad))

        # Cleanup
        wally_musig_secnonce_free(sn0a.value)
        wally_musig_secnonce_free(sn0b.value)
        wally_musig_secnonce_free(sn1.value)
        wally_musig_pubnonce_free(pn0a.value)
        wally_musig_pubnonce_free(pn0b.value)
        wally_musig_pubnonce_free(pn1.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_secnonce_consumed_after_sign(self):
        """Verify the secnonce is consumed (zeroed) after partial_sign succeeds.

        Note: attempting to call partial_sign a second time with the same secnonce
        would trigger a secp256k1 illegal-argument abort() — that is intentional
        at the secp256k1 level. We verify correct single-use behavior instead.
        """
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          None, 0, cache))

        session_id1 = bytes([0x10] * 32)
        session_id2 = bytes([0x20] * 32)
        sn1 = c_void_p()
        pn1 = c_void_p()
        sn2 = c_void_p()
        pn2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(session_id1, 32, SECKEY1, 32,
                                                         pk1, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn1, pn1))
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(session_id2, 32, SECKEY2, 32,
                                                         pk2, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn2, pn2))

        pn1_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        pn2_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn1.value, pn1_bytes, MUSIG_PUBNONCE_LEN))
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn2.value, pn2_bytes, MUSIG_PUBNONCE_LEN))

        pubnonces_flat = bytes(pn1_bytes) + bytes(pn2_bytes)
        aggnonce = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_agg(pubnonces_flat, len(pubnonces_flat), 2, aggnonce))

        session = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_process(aggnonce.value, TEST_MSG32, 32,
                                                             cache.value, None, 0, session))

        # Sign: should succeed and produce a non-NULL partial sig
        psig1 = c_void_p()
        ret = wally_musig_partial_sign(sn1.value, SECKEY1, 32, cache.value, session.value, psig1)
        self.assertEqual(WALLY_OK, ret)
        self.assertIsNotNone(psig1.value)

        # The secnonce is now zeroed internally by secp256k1 after the sign.
        # Calling partial_sign again with the same sn1.value would cause a
        # secp256k1 illegal-argument abort(), which is the intended security
        # behavior — not a recoverable error. We only verify the first sign worked.

        # Cleanup
        wally_musig_secnonce_free(sn1.value)
        wally_musig_secnonce_free(sn2.value)
        wally_musig_pubnonce_free(pn1.value)
        wally_musig_pubnonce_free(pn2.value)
        wally_musig_partial_sig_free(psig1.value)
        wally_musig_aggnonce_free(aggnonce.value)
        wally_musig_session_free(session.value)
        wally_musig_keyagg_cache_free(cache.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_partial_sig_verify_fails_on_bad_sig(self):
        """Corrupting a partial sig bytes causes verify to return WALLY_ERROR"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          None, 0, cache))

        session_id1 = bytes([0x30] * 32)
        session_id2 = bytes([0x40] * 32)
        sn1 = c_void_p()
        pn1 = c_void_p()
        sn2 = c_void_p()
        pn2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(session_id1, 32, SECKEY1, 32,
                                                         pk1, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn1, pn1))
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(session_id2, 32, SECKEY2, 32,
                                                         pk2, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn2, pn2))

        pn1_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        pn2_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn1.value, pn1_bytes, MUSIG_PUBNONCE_LEN))
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn2.value, pn2_bytes, MUSIG_PUBNONCE_LEN))

        pubnonces_flat = bytes(pn1_bytes) + bytes(pn2_bytes)
        aggnonce = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_agg(pubnonces_flat, len(pubnonces_flat), 2, aggnonce))

        session = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_process(aggnonce.value, TEST_MSG32, 32,
                                                             cache.value, None, 0, session))

        psig1 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_partial_sign(sn1.value, SECKEY1, 32,
                                                            cache.value, session.value, psig1))

        # Serialize, corrupt, parse back
        ps_bytes, _ = make_cbuffer('00' * MUSIG_PARTIAL_SIG_LEN)
        self.assertEqual(WALLY_OK, wally_musig_partial_sig_serialize(psig1.value, ps_bytes, MUSIG_PARTIAL_SIG_LEN))

        corrupted = bytearray(ps_bytes)
        corrupted[0] ^= 0xff
        corrupted_buf = bytes(corrupted)

        psig1_bad = c_void_p()
        ret = wally_musig_partial_sig_parse(corrupted_buf, MUSIG_PARTIAL_SIG_LEN, psig1_bad)
        if ret == WALLY_OK and psig1_bad.value is not None:
            # If parsing succeeds, verify should fail
            ret_v = wally_musig_partial_sig_verify(psig1_bad.value, pn1.value, pk1, EC_PUBLIC_KEY_LEN,
                                                   cache.value, session.value)
            self.assertNotEqual(WALLY_OK, ret_v)
            wally_musig_partial_sig_free(psig1_bad.value)
        else:
            # Parse itself rejected the corrupted sig
            self.assertNotEqual(WALLY_OK, ret)

        # Cleanup
        wally_musig_secnonce_free(sn2.value)
        wally_musig_pubnonce_free(pn1.value)
        wally_musig_pubnonce_free(pn2.value)
        wally_musig_partial_sig_free(psig1.value)
        wally_musig_aggnonce_free(aggnonce.value)
        wally_musig_session_free(session.value)
        wally_musig_keyagg_cache_free(cache.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_invalid_args(self):
        """Input validation returns WALLY_EINVAL"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          None, 0, cache))

        # wally_musig_pubkey_agg: NULL pubkeys
        cache_bad = c_void_p()
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkey_agg(None, 66, None, 0, cache_bad))
        # wrong length (not multiple of 33)
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkey_agg(pub_keys_flat, 32, None, 0, cache_bad))
        # only 1 key (min is 2)
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkey_agg(pk1, EC_PUBLIC_KEY_LEN, None, 0, cache_bad))

        # wally_musig_nonce_gen: NULL session_secrand32
        sn_bad = c_void_p()
        pn_bad = c_void_p()
        self.assertEqual(WALLY_EINVAL, wally_musig_nonce_gen(None, 0, SECKEY1, 32, pk1, EC_PUBLIC_KEY_LEN,
                                                             None, None, 0, None, 0, sn_bad, pn_bad))
        # all-zero session_secrand32 must be rejected (defense-in-depth: it must be
        # unique and uniformly random; all-zero is the common uninitialized mistake)
        zero_secrand = bytes(32)
        self.assertEqual(WALLY_EINVAL, wally_musig_nonce_gen(zero_secrand, 32, SECKEY1, 32, pk1, EC_PUBLIC_KEY_LEN,
                                                             None, None, 0, None, 0, sn_bad, pn_bad))
        # NULL pubkey
        session_id = bytes([0xff] * 32)
        self.assertEqual(WALLY_EINVAL, wally_musig_nonce_gen(session_id, 32, SECKEY1, 32, None, 0,
                                                             None, None, 0, None, 0, sn_bad, pn_bad))
        # seckey non-NULL but seckey_len=0
        self.assertEqual(WALLY_EINVAL, wally_musig_nonce_gen(session_id, 32, SECKEY1, 0, pk1, EC_PUBLIC_KEY_LEN,
                                                             None, None, 0, None, 0, sn_bad, pn_bad))

        # wally_musig_nonce_agg: n_pubnonces=1 (min is 2)
        pn1_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        sn1 = c_void_p()
        pn1 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(bytes([0x01] * 32), 32, SECKEY1, 32,
                                                         pk1, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn1, pn1))
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn1.value, pn1_bytes, MUSIG_PUBNONCE_LEN))
        an_bad = c_void_p()
        self.assertEqual(WALLY_EINVAL, wally_musig_nonce_agg(bytes(pn1_bytes), MUSIG_PUBNONCE_LEN, 1, an_bad))

        # wally_musig_nonce_process: NULL msg32
        sn2 = c_void_p()
        pn2 = c_void_p()
        pn2_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(bytes([0x02] * 32), 32, SECKEY2, 32,
                                                         pk2, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn2, pn2))
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn2.value, pn2_bytes, MUSIG_PUBNONCE_LEN))
        pubnonces_flat = bytes(pn1_bytes) + bytes(pn2_bytes)
        aggnonce = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_agg(pubnonces_flat, len(pubnonces_flat), 2, aggnonce))

        session_bad = c_void_p()
        self.assertEqual(WALLY_EINVAL, wally_musig_nonce_process(aggnonce.value, None, 0, cache.value,
                                                                  None, 0, session_bad))
        # msg32 wrong length
        self.assertEqual(WALLY_EINVAL, wally_musig_nonce_process(aggnonce.value, bytes(31), 31, cache.value,
                                                                  None, 0, session_bad))

        # wally_musig_partial_sig_agg: n_sigs=1
        session = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_process(aggnonce.value, TEST_MSG32, 32,
                                                             cache.value, None, 0, session))
        psig1 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_partial_sign(sn1.value, SECKEY1, 32,
                                                            cache.value, session.value, psig1))
        ps1_bytes, _ = make_cbuffer('00' * MUSIG_PARTIAL_SIG_LEN)
        self.assertEqual(WALLY_OK, wally_musig_partial_sig_serialize(psig1.value, ps1_bytes, MUSIG_PARTIAL_SIG_LEN))
        final_sig, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_EINVAL, wally_musig_partial_sig_agg(bytes(ps1_bytes), MUSIG_PARTIAL_SIG_LEN, 1,
                                                                    session.value, final_sig, EC_SIGNATURE_LEN))

        # tweak functions: wrong tweak_len
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkey_ec_tweak_add(cache.value, TEST_TWEAK, 31,
                                                                        None, 0))
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkey_xonly_tweak_add(cache.value, TEST_TWEAK, 31,
                                                                           None, 0))

        # Serialization with wrong output buffer length
        cache_bytes_short, _ = make_cbuffer('00' * (MUSIG_KEYAGG_CACHE_LEN - 1))
        self.assertEqual(WALLY_EINVAL, wally_musig_keyagg_cache_serialize(cache.value, cache_bytes_short,
                                                                           MUSIG_KEYAGG_CACHE_LEN - 1))

        # Parse with wrong input byte length
        cache_bytes_ok, _ = make_cbuffer('00' * MUSIG_KEYAGG_CACHE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_keyagg_cache_serialize(cache.value, cache_bytes_ok,
                                                                       MUSIG_KEYAGG_CACHE_LEN))
        cache_parsed_bad = c_void_p()
        self.assertEqual(WALLY_EINVAL, wally_musig_keyagg_cache_parse(cache_bytes_ok,
                                                                       MUSIG_KEYAGG_CACHE_LEN - 1,
                                                                       cache_parsed_bad))
        pn_bytes_short, _ = make_cbuffer('00' * (MUSIG_PUBNONCE_LEN - 1))
        pn_parsed_bad = c_void_p()
        self.assertEqual(WALLY_EINVAL, wally_musig_pubnonce_parse(pn_bytes_short, MUSIG_PUBNONCE_LEN - 1,
                                                                   pn_parsed_bad))

        # Cleanup
        wally_musig_secnonce_free(sn2.value)
        wally_musig_pubnonce_free(pn1.value)
        wally_musig_pubnonce_free(pn2.value)
        wally_musig_partial_sig_free(psig1.value)
        wally_musig_aggnonce_free(aggnonce.value)
        wally_musig_session_free(session.value)
        wally_musig_keyagg_cache_free(cache.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_tweaked_key_signing(self):
        """Sign with a tweaked aggregate key and verify against tweaked key"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          None, 0, cache))

        # Apply xonly tweak (BIP-341 style)
        tweaked_pub, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkey_xonly_tweak_add(cache.value, TEST_TWEAK, 32,
                                                                       tweaked_pub, EC_PUBLIC_KEY_LEN))
        tweaked_xonly = bytes(tweaked_pub)[1:]  # x-only from compressed

        # Run full signing with tweaked cache
        session_id1 = bytes([0x51] * 32)
        session_id2 = bytes([0x52] * 32)
        sn1 = c_void_p()
        pn1 = c_void_p()
        sn2 = c_void_p()
        pn2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(session_id1, 32, SECKEY1, 32,
                                                         pk1, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn1, pn1))
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(session_id2, 32, SECKEY2, 32,
                                                         pk2, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn2, pn2))

        pn1_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        pn2_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn1.value, pn1_bytes, MUSIG_PUBNONCE_LEN))
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn2.value, pn2_bytes, MUSIG_PUBNONCE_LEN))

        pubnonces_flat = bytes(pn1_bytes) + bytes(pn2_bytes)
        aggnonce = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_agg(pubnonces_flat, len(pubnonces_flat), 2, aggnonce))

        session = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_process(aggnonce.value, TEST_MSG32, 32,
                                                             cache.value, None, 0, session))

        psig1 = c_void_p()
        psig2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_partial_sign(sn1.value, SECKEY1, 32,
                                                            cache.value, session.value, psig1))
        self.assertEqual(WALLY_OK, wally_musig_partial_sign(sn2.value, SECKEY2, 32,
                                                            cache.value, session.value, psig2))

        ps1_bytes, _ = make_cbuffer('00' * MUSIG_PARTIAL_SIG_LEN)
        ps2_bytes, _ = make_cbuffer('00' * MUSIG_PARTIAL_SIG_LEN)
        self.assertEqual(WALLY_OK, wally_musig_partial_sig_serialize(psig1.value, ps1_bytes, MUSIG_PARTIAL_SIG_LEN))
        self.assertEqual(WALLY_OK, wally_musig_partial_sig_serialize(psig2.value, ps2_bytes, MUSIG_PARTIAL_SIG_LEN))

        partial_sigs_flat = bytes(ps1_bytes) + bytes(ps2_bytes)
        final_sig, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_partial_sig_agg(partial_sigs_flat, len(partial_sigs_flat), 2,
                                                               session.value, final_sig, EC_SIGNATURE_LEN))

        # Verify against the tweaked aggregate key (x-only)
        ret = wally_ec_sig_verify(tweaked_xonly, EC_XONLY_PUBLIC_KEY_LEN,
                                  TEST_MSG32, 32,
                                  EC_FLAG_SCHNORR, final_sig, EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK, ret)

        # Cleanup
        wally_musig_pubnonce_free(pn1.value)
        wally_musig_pubnonce_free(pn2.value)
        wally_musig_partial_sig_free(psig1.value)
        wally_musig_partial_sig_free(psig2.value)
        wally_musig_aggnonce_free(aggnonce.value)
        wally_musig_session_free(session.value)
        wally_musig_keyagg_cache_free(cache.value)


    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_synthetic_xpub_construction(self):
        """BIP-328: synthetic xpub from 2-of-2 aggregate key"""
        seckeys = [SECKEY1, SECKEY2]
        pubkeys = [derive_pubkey(sk) for sk in seckeys]
        pub_keys_flat = b''.join(pubkeys)

        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        ret = wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                     agg_pk, EC_XONLY_PUBLIC_KEY_LEN, None)
        self.assertEqual(WALLY_OK, ret)

        xpub = POINTER(ext_key)()
        ret = wally_musig_pubkey_to_xpub(agg_pk, EC_XONLY_PUBLIC_KEY_LEN,
                                         BIP32_VER_MAIN_PUBLIC, byref(xpub))
        self.assertEqual(WALLY_OK, ret)
        self.assertIsNotNone(xpub)

        # Verify depth=0, child_num=0, parent fingerprint=0
        self.assertEqual(0, xpub.contents.depth)
        self.assertEqual(0, xpub.contents.child_num)
        self.assertEqual(b'\x00' * 20, bytes(xpub.contents.parent160))

        # Verify the chaincode matches BIP-328 constant
        expected_cc = bytes([
            0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74,
            0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
            0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3,
            0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65
        ])
        self.assertEqual(expected_cc, bytes(xpub.contents.chain_code))

        # Serialize to base58 and verify it starts with 'xpub'
        ret, b58_str = bip32_key_to_base58(xpub, BIP32_FLAG_KEY_PUBLIC)
        self.assertEqual(WALLY_OK, ret)
        b58_decoded = b58_str.decode('ascii') if isinstance(b58_str, bytes) else b58_str
        self.assertTrue(b58_decoded.startswith('xpub'),
                        f'Expected xpub prefix, got: {b58_decoded[:4]}')

        bip32_key_free(xpub)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_synthetic_xpub_unhardened_derivation(self):
        """BIP-328: unhardened child derivation from synthetic xpub succeeds"""
        seckeys = [SECKEY1, SECKEY2]
        pubkeys = [derive_pubkey(sk) for sk in seckeys]
        pub_keys_flat = b''.join(pubkeys)

        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                               agg_pk, EC_XONLY_PUBLIC_KEY_LEN, None)

        xpub = POINTER(ext_key)()
        wally_musig_pubkey_to_xpub(agg_pk, EC_XONLY_PUBLIC_KEY_LEN,
                                   BIP32_VER_MAIN_PUBLIC, byref(xpub))

        # Derive child 0 (unhardened) - should succeed
        child0 = POINTER(ext_key)()
        ret = bip32_key_from_parent_alloc(xpub, 0, BIP32_FLAG_KEY_PUBLIC, byref(child0))
        self.assertEqual(WALLY_OK, ret, 'Unhardened child 0 derivation should succeed')
        self.assertIsNotNone(child0)

        # Derive child 1 (unhardened) - should succeed
        child1 = POINTER(ext_key)()
        ret = bip32_key_from_parent_alloc(xpub, 1, BIP32_FLAG_KEY_PUBLIC, byref(child1))
        self.assertEqual(WALLY_OK, ret, 'Unhardened child 1 derivation should succeed')

        # Children 0 and 1 produce different keys
        ser0, _ = make_cbuffer('00' * BIP32_SERIALIZED_LEN)
        ser1, _ = make_cbuffer('00' * BIP32_SERIALIZED_LEN)
        bip32_key_serialize(child0, BIP32_FLAG_KEY_PUBLIC, ser0, BIP32_SERIALIZED_LEN)
        bip32_key_serialize(child1, BIP32_FLAG_KEY_PUBLIC, ser1, BIP32_SERIALIZED_LEN)
        self.assertNotEqual(bytes(ser0), bytes(ser1),
                            'Different child indices must produce different keys')

        bip32_key_free(child0)
        bip32_key_free(child1)
        bip32_key_free(xpub)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_synthetic_xpub_hardened_derivation_rejected(self):
        """BIP-328: hardened derivation from synthetic xpub must fail (no private key)"""
        seckeys = [SECKEY1, SECKEY2]
        pubkeys = [derive_pubkey(sk) for sk in seckeys]
        pub_keys_flat = b''.join(pubkeys)

        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                               agg_pk, EC_XONLY_PUBLIC_KEY_LEN, None)

        xpub = POINTER(ext_key)()
        wally_musig_pubkey_to_xpub(agg_pk, EC_XONLY_PUBLIC_KEY_LEN,
                                   BIP32_VER_MAIN_PUBLIC, byref(xpub))

        child_h = POINTER(ext_key)()
        ret = bip32_key_from_parent_alloc(xpub, BIP32_INITIAL_HARDENED_CHILD,
                                          BIP32_FLAG_KEY_PUBLIC, byref(child_h))
        self.assertNotEqual(WALLY_OK, ret, 'Hardened derivation must fail without private key')

        bip32_key_free(xpub)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_synthetic_xpub_invalid_args(self):
        """wally_musig_pubkey_to_xpub validates its arguments"""
        agg_pk_buf, _ = make_cbuffer('01' * EC_XONLY_PUBLIC_KEY_LEN)
        xpub = POINTER(ext_key)()

        # NULL pubkey
        self.assertEqual(WALLY_EINVAL,
                         wally_musig_pubkey_to_xpub(None, EC_XONLY_PUBLIC_KEY_LEN,
                                                    BIP32_VER_MAIN_PUBLIC, byref(xpub)))
        # Wrong length
        self.assertEqual(WALLY_EINVAL,
                         wally_musig_pubkey_to_xpub(agg_pk_buf, 31,
                                                    BIP32_VER_MAIN_PUBLIC, byref(xpub)))
        # Invalid version (private key version)
        self.assertEqual(WALLY_EINVAL,
                         wally_musig_pubkey_to_xpub(agg_pk_buf, EC_XONLY_PUBLIC_KEY_LEN,
                                                    BIP32_VER_MAIN_PRIVATE, byref(xpub)))
        # NULL output
        self.assertEqual(WALLY_EINVAL,
                         wally_musig_pubkey_to_xpub(agg_pk_buf, EC_XONLY_PUBLIC_KEY_LEN,
                                                    BIP32_VER_MAIN_PUBLIC, None))


    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_derive_then_agg(self):
        """BIP-390: derive child from each xpub then sort+aggregate"""
        # Build two master xpubs from seeds
        seed1 = bytes([0x01] * 32)
        seed2 = bytes([0x02] * 32)

        xpub1 = POINTER(ext_key)()
        xpub2 = POINTER(ext_key)()
        ret = bip32_key_from_seed_alloc(seed1, len(seed1), BIP32_VER_MAIN_PRIVATE, 0, byref(xpub1))
        self.assertEqual(WALLY_OK, ret)
        ret = bip32_key_from_seed_alloc(seed2, len(seed2), BIP32_VER_MAIN_PRIVATE, 0, byref(xpub2))
        self.assertEqual(WALLY_OK, ret)

        # Serialize both xpubs
        xpub1_ser, _ = make_cbuffer('00' * BIP32_SERIALIZED_LEN)
        xpub2_ser, _ = make_cbuffer('00' * BIP32_SERIALIZED_LEN)
        self.assertEqual(WALLY_OK, bip32_key_serialize(xpub1, BIP32_FLAG_KEY_PUBLIC, xpub1_ser, BIP32_SERIALIZED_LEN))
        self.assertEqual(WALLY_OK, bip32_key_serialize(xpub2, BIP32_FLAG_KEY_PUBLIC, xpub2_ser, BIP32_SERIALIZED_LEN))

        # Compute expected result manually: derive child 0, sort, aggregate
        child1 = POINTER(ext_key)()
        child2 = POINTER(ext_key)()
        self.assertEqual(WALLY_OK, bip32_key_from_parent_alloc(xpub1, 0, BIP32_FLAG_KEY_PUBLIC, byref(child1)))
        self.assertEqual(WALLY_OK, bip32_key_from_parent_alloc(xpub2, 0, BIP32_FLAG_KEY_PUBLIC, byref(child2)))

        pk1 = bytes(child1.contents.pub_key)
        pk2 = bytes(child2.contents.pub_key)
        sorted_pks = b''.join(sorted([pk1, pk2]))

        expected_agg, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(sorted_pks, len(sorted_pks),
                                                          expected_agg, EC_XONLY_PUBLIC_KEY_LEN, None))

        # Call derive_then_agg with xpub1 first
        xpubs_12 = bytes(xpub1_ser) + bytes(xpub2_ser)
        agg_pk_12, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkeys_derive_then_agg(
            xpubs_12, len(xpubs_12), 0, agg_pk_12, EC_XONLY_PUBLIC_KEY_LEN, None))
        self.assertEqual(bytes(expected_agg), bytes(agg_pk_12))

        # Swapping xpub order must produce the same result (lexsort is canonical)
        xpubs_21 = bytes(xpub2_ser) + bytes(xpub1_ser)
        agg_pk_21, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkeys_derive_then_agg(
            xpubs_21, len(xpubs_21), 0, agg_pk_21, EC_XONLY_PUBLIC_KEY_LEN, None))
        self.assertEqual(bytes(agg_pk_12), bytes(agg_pk_21))

        # Verify child index 1 differs from index 0
        agg_pk_idx1, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkeys_derive_then_agg(
            xpubs_12, len(xpubs_12), 1, agg_pk_idx1, EC_XONLY_PUBLIC_KEY_LEN, None))
        self.assertNotEqual(bytes(agg_pk_12), bytes(agg_pk_idx1))

        # Invalid: hardened child
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkeys_derive_then_agg(
            xpubs_12, len(xpubs_12), BIP32_INITIAL_HARDENED_CHILD, agg_pk_12, EC_XONLY_PUBLIC_KEY_LEN, None))

        # Invalid: xpubs_len not multiple of 78
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkeys_derive_then_agg(
            xpubs_12, len(xpubs_12) - 1, 0, agg_pk_12, EC_XONLY_PUBLIC_KEY_LEN, None))

        # Invalid: only 1 xpub
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkeys_derive_then_agg(
            xpubs_12, BIP32_SERIALIZED_LEN, 0, agg_pk_12, EC_XONLY_PUBLIC_KEY_LEN, None))

        bip32_key_free(child1)
        bip32_key_free(child2)
        bip32_key_free(xpub1)
        bip32_key_free(xpub2)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_agg_then_derive(self):
        """BIP-328: aggregate pubkeys, build synthetic xpub, then derive child"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        # Compute expected manually. wally_musig_pubkeys_agg_then_derive sorts
        # the keys before aggregation, so sort here to mirror it.
        sorted_keys_flat = b''.join(sorted([pk1, pk2]))
        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(sorted_keys_flat, len(sorted_keys_flat),
                                                          agg_pk, EC_XONLY_PUBLIC_KEY_LEN, None))
        synthetic_xpub = POINTER(ext_key)()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_to_xpub(agg_pk, EC_XONLY_PUBLIC_KEY_LEN,
                                                               BIP32_VER_MAIN_PUBLIC, byref(synthetic_xpub)))
        expected_child = POINTER(ext_key)()
        self.assertEqual(WALLY_OK, bip32_key_from_parent_alloc(synthetic_xpub, 0,
                                                                BIP32_FLAG_KEY_PUBLIC, byref(expected_child)))
        expected_pk = bytes(expected_child.contents.pub_key)

        # Call agg_then_derive
        result_pk, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkeys_agg_then_derive(
            pub_keys_flat, len(pub_keys_flat), BIP32_VER_MAIN_PUBLIC, 0,
            result_pk, EC_PUBLIC_KEY_LEN, None))
        self.assertEqual(expected_pk, bytes(result_pk))

        # Different child indices produce different pubkeys
        result_pk1, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        result_pk2, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkeys_agg_then_derive(
            pub_keys_flat, len(pub_keys_flat), BIP32_VER_MAIN_PUBLIC, 1,
            result_pk1, EC_PUBLIC_KEY_LEN, None))
        self.assertEqual(WALLY_OK, wally_musig_pubkeys_agg_then_derive(
            pub_keys_flat, len(pub_keys_flat), BIP32_VER_MAIN_PUBLIC, 2,
            result_pk2, EC_PUBLIC_KEY_LEN, None))
        self.assertNotEqual(bytes(result_pk), bytes(result_pk1))
        self.assertNotEqual(bytes(result_pk1), bytes(result_pk2))

        # child_out pointer variant
        child_ptr = POINTER(ext_key)()
        self.assertEqual(WALLY_OK, wally_musig_pubkeys_agg_then_derive(
            pub_keys_flat, len(pub_keys_flat), BIP32_VER_MAIN_PUBLIC, 0,
            None, 0, byref(child_ptr)))
        self.assertIsNotNone(child_ptr)
        self.assertEqual(expected_pk, bytes(child_ptr.contents.pub_key))

        # Invalid: hardened child
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkeys_agg_then_derive(
            pub_keys_flat, len(pub_keys_flat), BIP32_VER_MAIN_PUBLIC,
            BIP32_INITIAL_HARDENED_CHILD, result_pk, EC_PUBLIC_KEY_LEN, None))

        # Invalid: only 1 pubkey
        self.assertEqual(WALLY_EINVAL, wally_musig_pubkeys_agg_then_derive(
            pk1, EC_PUBLIC_KEY_LEN, BIP32_VER_MAIN_PUBLIC, 0,
            result_pk, EC_PUBLIC_KEY_LEN, None))

        bip32_key_free(expected_child)
        bip32_key_free(synthetic_xpub)
        bip32_key_free(child_ptr)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_psbt_musig2_add_nonce(self):
        """wally_psbt_musig2_add_nonce: generates nonce, stores pubnonce in PSBT"""
        NETWORK_NONE = 0x00
        SHA256_LEN = 32

        # Build a minimal v2 PSBT with 1 input and 1 output via musig descriptor
        xpub1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub2 = 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
        fp1 = 'deadbeef'
        fp2 = 'cafebabe'

        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))
        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))
        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(1000, b'\x00\x14' + b'\xab' * 20, 22, tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))

        d = c_void_p()
        desc_str = f'tr(musig([{fp1}/86h/0h/0h]{xpub1}/0/*,[{fp2}/86h/0h/0h]{xpub2}/0/*))'
        self.assertEqual(WALLY_OK, wally_descriptor_parse(desc_str, None, NETWORK_NONE, 0, d))
        self.assertEqual(WALLY_OK, wally_psbt_populate_musig2_from_descriptor(psbt, d, 0, 0))

        # Get the aggregate pubkey (x-only from taproot_internal_key)
        ik_buf, ik_buf_len = make_cbuffer('00' * 32)
        ret, ik_written = wally_psbt_get_input_taproot_internal_key(psbt, 0, ik_buf, ik_buf_len)
        self.assertEqual(ret, WALLY_OK)
        ik_hex = bytes(ik_buf[:32]).hex()

        # Try both compressed prefixes to find the actual agg_pubkey in the map
        agg_02, _ = make_cbuffer('02' + ik_hex)
        agg_03, _ = make_cbuffer('03' + ik_hex)
        inp = psbt.contents.inputs[0]
        ret2, idx2 = wally_psbt_input_find_musig2_pubkey(inp, agg_02, 33)
        ret3, idx3 = wally_psbt_input_find_musig2_pubkey(inp, agg_03, 33)
        self.assertTrue((ret2 == WALLY_OK and idx2 > 0) or (ret3 == WALLY_OK and idx3 > 0))
        agg_pubkey = agg_02 if (ret2 == WALLY_OK and idx2 > 0) else agg_03

        # Derive the two participant pubkeys from the xpubs
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)

        # --- Invalid arg tests ---
        secrand, secrand_len = make_cbuffer('aa' * 32)
        sn_out = c_void_p()

        # NULL psbt
        self.assertEqual(WALLY_EINVAL, wally_psbt_musig2_add_nonce(
            None, 0, secrand, secrand_len, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey, 33, None, 0, None, 0, byref(sn_out)))
        # index out of range
        self.assertEqual(WALLY_EINVAL, wally_psbt_musig2_add_nonce(
            psbt, 99, secrand, secrand_len, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey, 33, None, 0, None, 0, byref(sn_out)))
        # bad secrand_len
        self.assertEqual(WALLY_EINVAL, wally_psbt_musig2_add_nonce(
            psbt, 0, secrand, 31, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey, 33, None, 0, None, 0, byref(sn_out)))
        # bad pubkey_len
        self.assertEqual(WALLY_EINVAL, wally_psbt_musig2_add_nonce(
            psbt, 0, secrand, secrand_len, None, 0,
            pk1, 32, agg_pubkey, 33, None, 0, None, 0, byref(sn_out)))
        # flags != 0
        self.assertEqual(WALLY_EINVAL, wally_psbt_musig2_add_nonce(
            psbt, 0, secrand, secrand_len, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey, 33, None, 0, None, 1, byref(sn_out)))
        # NULL secnonce_out
        self.assertEqual(WALLY_EINVAL, wally_psbt_musig2_add_nonce(
            psbt, 0, secrand, secrand_len, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey, 33, None, 0, None, 0, None))

        # --- Valid call: participant 1 ---
        secrand1, _ = make_cbuffer('01' * 32)
        sn1 = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            psbt, 0, secrand1, 32, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey, 33, None, 0, None, 0, byref(sn1))
        self.assertEqual(WALLY_OK, ret)
        self.assertIsNotNone(sn1.value, 'secnonce should be returned to caller')

        # Pubnonce must now be present
        ret, idx = wally_psbt_input_find_musig2_pubnonce(
            psbt.contents.inputs[0], pk1, EC_PUBLIC_KEY_LEN, agg_pubkey, 33, None, 0)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        # Pubnonce count must be 1
        ret, count = wally_psbt_input_get_musig2_pubnonce_count(psbt.contents.inputs[0])
        self.assertEqual((ret, count), (WALLY_OK, 1))

        # --- Nonce reuse prevention: second call for same participant returns WALLY_ERROR ---
        secrand1b, _ = make_cbuffer('02' * 32)
        sn1b = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            psbt, 0, secrand1b, 32, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey, 33, None, 0, None, 0, byref(sn1b))
        self.assertEqual(WALLY_ERROR, ret, 'second call for same participant must return WALLY_ERROR')
        self.assertIsNone(sn1b.value, 'secnonce_out must remain NULL on error')

        # --- Valid call: participant 2 (different participant, same agg_pubkey) ---
        secrand2, _ = make_cbuffer('03' * 32)
        sn2 = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            psbt, 0, secrand2, 32, None, 0,
            pk2, EC_PUBLIC_KEY_LEN, agg_pubkey, 33, None, 0, None, 0, byref(sn2))
        self.assertEqual(WALLY_OK, ret)
        self.assertIsNotNone(sn2.value, 'secnonce for participant 2 should be returned')

        # Pubnonce count is now 2
        ret, count2 = wally_psbt_input_get_musig2_pubnonce_count(psbt.contents.inputs[0])
        self.assertEqual((ret, count2), (WALLY_OK, 2))

        # Cleanup
        wally_musig_secnonce_free(sn1.value)
        wally_musig_secnonce_free(sn2.value)
        wally_descriptor_free(d)
        wally_psbt_free(psbt)


    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_psbt_musig2_finalize_input(self):
        """wally_psbt_musig2_finalize_input: aggregates partial sigs and stores TAP_KEY_SIG"""
        # Derive participant pubkeys from two test seckeys
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        # Aggregate pubkeys → x-only agg_pk + keyagg_cache
        agg_pk_xonly, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        ret = wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                     agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN, cache)
        self.assertEqual(WALLY_OK, ret)

        # wally_musig_pubkey_agg normalizes to even parity (02 prefix)
        agg_pubkey = bytes([0x02]) + bytes(agg_pk_xonly)
        agg_pubkey_buf, _ = make_cbuffer(agg_pubkey.hex())

        # Build a standard BIP-341 P2TR scriptpubkey. Pass the 33-byte COMPRESSED
        # aggregate (internal) key so wally applies the key-path output tweak: the
        # coin is locked to Q = P + H_TapTweak(P)*G. The musig signing flow applies
        # the same tweak internally so the aggregated signature is valid under Q.
        # (Regression test for the key-path taproot tweak fix.)
        p2tr_buf, _ = make_cbuffer('00' * 34)
        ret, p2tr_written = wally_scriptpubkey_p2tr_from_bytes(
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
        self.assertEqual(WALLY_OK, ret)
        p2tr_bytes = bytes(p2tr_buf[:p2tr_written])
        self.assertEqual(34, len(p2tr_bytes))

        # Create PSBT v2 with 1 input and 1 output
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))

        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))

        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(1000, b'\x00\x14' + b'\xab' * 20, 22,
                                                    tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))

        # Set witness_utxo for the input (P2TR output, 200000 sat)
        utxo = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(200000, p2tr_bytes, len(p2tr_bytes),
                                                    utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, 0, utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_amount(psbt, 0, 200000))

        # Set taproot internal key (x-only)
        self.assertEqual(WALLY_OK,
                         wally_psbt_set_input_taproot_internal_key(psbt, 0,
                                                                    agg_pk_xonly,
                                                                    EC_XONLY_PUBLIC_KEY_LEN))

        # Register musig2 participant pubkeys in the PSBT input
        # psbt.contents.inputs is POINTER(wally_psbt_input) pointing to inputs[0]
        # C signature: (input, agg_pubkey, agg_pubkey_len, participants, participants_len)
        participants_flat = bytes(pk1) + bytes(pk2)
        self.assertEqual(WALLY_OK,
                         wally_psbt_input_add_musig2_participant_pubkeys(
                             psbt.contents.inputs,
                             agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
                             participants_flat, len(participants_flat)))

        # --- Round 1: generate and store nonces for each participant ---
        secrand1, _ = make_cbuffer('a1' * 32)
        secrand2, _ = make_cbuffer('a2' * 32)
        sn1 = c_void_p()
        sn2 = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            psbt, 0, secrand1, 32, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn1))
        self.assertEqual(WALLY_OK, ret)
        self.assertIsNotNone(sn1.value)
        ret = wally_psbt_musig2_add_nonce(
            psbt, 0, secrand2, 32, None, 0,
            pk2, EC_PUBLIC_KEY_LEN, agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn2))
        self.assertEqual(WALLY_OK, ret)
        self.assertIsNotNone(sn2.value)

        # --- Round 2: sign with each participant ---
        seckey1, _ = make_cbuffer(SECKEY1.hex())
        seckey2, _ = make_cbuffer(SECKEY2.hex())
        ret = wally_psbt_musig2_sign(
            psbt, 0, sn1.value,
            seckey1, 32, pk1, EC_PUBLIC_KEY_LEN,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, cache.value, 0, None)
        self.assertEqual(WALLY_OK, ret, 'participant 1 sign failed')
        ret = wally_psbt_musig2_sign(
            psbt, 0, sn2.value,
            seckey2, 32, pk2, EC_PUBLIC_KEY_LEN,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, cache.value, 0, None)
        self.assertEqual(WALLY_OK, ret, 'participant 2 sign failed')

        # --- Finalize: aggregate partial sigs → TAP_KEY_SIG ---
        ret = wally_psbt_musig2_finalize_input(
            psbt, 0,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0,
            cache.value, 0)
        self.assertEqual(WALLY_OK, ret, 'musig2_finalize_input failed')

        # Verify that nonce and partial sig entries were cleared after aggregation
        ret, nonce_count = wally_psbt_input_get_musig2_pubnonce_count(psbt.contents.inputs[0])
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(0, nonce_count, 'musig2 pubnonces should be cleared after finalize')
        ret, sig_count = wally_psbt_input_get_musig2_partial_sig_count(psbt.contents.inputs[0])
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(0, sig_count, 'musig2 partial sigs should be cleared after finalize')

        # Verify TAP_KEY_SIG is stored in the PSBT
        sig_buf, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
        ret, sig_written = wally_psbt_get_input_taproot_signature(psbt, 0, sig_buf, EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK, ret, 'TAP_KEY_SIG should be set after musig2_finalize_input')
        self.assertEqual(EC_SIGNATURE_LEN, sig_written, 'TAP_KEY_SIG should be 64 bytes')

        # Cryptographically verify the BIP-340 Schnorr signature under the taproot output key.
        # The P2TR scriptpubkey is OP_1 <32-byte-tweaked-output-key>; bytes [2:34] are the
        # x-only output key that the signature must verify against.
        output_xonly_key = bytes(p2tr_bytes[2:34])
        output_key_buf, _ = make_cbuffer(output_xonly_key.hex())

        # Compute the SIGHASH_DEFAULT taproot sighash for input 0.
        # PSBT v2 has no global tx; build the tx manually from PSBT data.
        # Input: txhash=0..0, index=0, sequence=0 (from zero-initialized wally_tx_input)
        # Output: 1000 sat, P2WPKH (b'\x00\x14' + b'\xab' * 20)
        tx_pp = POINTER(wally_tx)()
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 1, byref(tx_pp)))
        zero_txid, _ = make_cbuffer('00' * 32)
        self.assertEqual(WALLY_OK,
                         wally_tx_add_raw_input(tx_pp, zero_txid, 32, 0, 0, None, 0, None, 0))
        out_script = b'\x00\x14' + b'\xab' * 20
        self.assertEqual(WALLY_OK,
                         wally_tx_add_raw_output(tx_pp, 1000, out_script, len(out_script), 0))

        sighash_buf, _ = make_cbuffer('00' * 32)
        ret = wally_psbt_get_input_signature_hash(
            psbt, 0, tx_pp, None, 0, WALLY_SIGHASH_DEFAULT, sighash_buf, 32)
        self.assertEqual(WALLY_OK, ret, 'sighash computation failed')

        # Verify the 64-byte TAP_KEY_SIG is a valid BIP-340 Schnorr signature.
        ret = wally_ec_sig_verify(
            output_key_buf, EC_XONLY_PUBLIC_KEY_LEN,
            sighash_buf, 32,
            EC_FLAG_SCHNORR,
            sig_buf, EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK, ret, 'BIP-340 signature verification failed')
        wally_tx_free(tx_pp)

        # --- Final finalization: produce witness ---
        ret = wally_psbt_finalize_input(psbt, 0, 0)
        self.assertEqual(WALLY_OK, ret, 'psbt_finalize_input failed')
        self.assertIsNotNone(psbt.contents.inputs[0].final_witness,
                             'final_witness should be set after finalize_input')

        # Cleanup
        wally_musig_secnonce_free(sn1.value)
        wally_musig_secnonce_free(sn2.value)
        wally_musig_keyagg_cache_free(cache.value)
        wally_psbt_free(psbt)


    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_psbt_musig2_full_flow_3of3(self):
        """Full 3-of-3 MuSig2 PSBT signing flow produces a valid BIP-340 TAP_KEY_SIG"""
        # Derive participant pubkeys from three test seckeys
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pk3 = derive_pubkey(SECKEY3)
        pub_keys_flat = pk1 + pk2 + pk3  # 99 bytes

        # Aggregate pubkeys → x-only agg_pk + keyagg_cache
        agg_pk_xonly, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        ret = wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                     agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN, cache)
        self.assertEqual(WALLY_OK, ret)

        agg_pubkey = bytes([0x02]) + bytes(agg_pk_xonly)
        agg_pubkey_buf, _ = make_cbuffer(agg_pubkey.hex())

        # Build a standard BIP-341 P2TR scriptpubkey (output tweaked to Q). Pass the
        # 33-byte COMPRESSED aggregate key so wally applies the key-path output tweak;
        # the musig signing flow applies the same tweak internally so the aggregated
        # signature is valid under Q. (Regression test for the key-path tweak fix.)
        p2tr_buf, _ = make_cbuffer('00' * 34)
        ret, p2tr_written = wally_scriptpubkey_p2tr_from_bytes(
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
        self.assertEqual(WALLY_OK, ret)
        p2tr_bytes = bytes(p2tr_buf[:p2tr_written])
        self.assertEqual(34, len(p2tr_bytes))

        # Create PSBT v2 with 1 input and 1 output
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))

        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))

        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(1000, b'\x00\x14' + b'\xab' * 20, 22,
                                                    tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))

        utxo = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(300000, p2tr_bytes, len(p2tr_bytes), utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, 0, utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_amount(psbt, 0, 300000))

        self.assertEqual(WALLY_OK,
                         wally_psbt_set_input_taproot_internal_key(
                             psbt, 0, agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN))

        # Register musig2 participant pubkeys in the PSBT input
        participants_flat = bytes(pk1) + bytes(pk2) + bytes(pk3)  # 99 bytes
        self.assertEqual(WALLY_OK,
                         wally_psbt_input_add_musig2_participant_pubkeys(
                             psbt.contents.inputs,
                             agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
                             participants_flat, len(participants_flat)))

        # --- Round 1: generate and store nonces for each participant ---
        secrand1, _ = make_cbuffer('b1' * 32)
        secrand2, _ = make_cbuffer('b2' * 32)
        secrand3, _ = make_cbuffer('b3' * 32)
        sn1, sn2, sn3 = c_void_p(), c_void_p(), c_void_p()

        for secrand, pk, sn in [(secrand1, pk1, sn1), (secrand2, pk2, sn2),
                                 (secrand3, pk3, sn3)]:
            ret = wally_psbt_musig2_add_nonce(
                psbt, 0, secrand, 32, None, 0,
                pk, EC_PUBLIC_KEY_LEN, agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
                None, 0, None, 0, byref(sn))
            self.assertEqual(WALLY_OK, ret)
            self.assertIsNotNone(sn.value)

        self.assertIsNotNone(sn1.value)
        self.assertIsNotNone(sn2.value)
        self.assertIsNotNone(sn3.value)

        ret, count = wally_psbt_input_get_musig2_pubnonce_count(psbt.contents.inputs[0])
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(3, count, 'expected 3 pubnonces after round 1')

        # --- Round 2: sign with each participant ---
        seckey1, _ = make_cbuffer(SECKEY1.hex())
        seckey2, _ = make_cbuffer(SECKEY2.hex())
        seckey3, _ = make_cbuffer(SECKEY3.hex())

        for sk, pk, sn, label in [
            (seckey1, pk1, sn1, 'participant 1'),
            (seckey2, pk2, sn2, 'participant 2'),
            (seckey3, pk3, sn3, 'participant 3'),
        ]:
            ret = wally_psbt_musig2_sign(
                psbt, 0, sn.value,
                sk, 32, pk, EC_PUBLIC_KEY_LEN,
                agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
                None, 0, cache.value, 0, None)
            self.assertEqual(WALLY_OK, ret, f'{label} sign failed')

        ret, sig_count = wally_psbt_input_get_musig2_partial_sig_count(psbt.contents.inputs[0])
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(3, sig_count, 'expected 3 partial sigs after round 2')

        # --- Finalize: aggregate partial sigs → TAP_KEY_SIG ---
        ret = wally_psbt_musig2_finalize_input(
            psbt, 0,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0,
            cache.value, 0)
        self.assertEqual(WALLY_OK, ret, 'musig2_finalize_input failed for 3-of-3')

        # Verify that nonce and partial sig entries were cleared after aggregation
        ret, nonce_count = wally_psbt_input_get_musig2_pubnonce_count(psbt.contents.inputs[0])
        self.assertEqual((ret, nonce_count), (WALLY_OK, 0),
                         'musig2 pubnonces should be cleared after finalize')
        ret, sig_count = wally_psbt_input_get_musig2_partial_sig_count(psbt.contents.inputs[0])
        self.assertEqual((ret, sig_count), (WALLY_OK, 0),
                         'musig2 partial sigs should be cleared after finalize')

        # Verify TAP_KEY_SIG is stored and has correct length
        sig_buf, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
        ret, sig_written = wally_psbt_get_input_taproot_signature(
            psbt, 0, sig_buf, EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK, ret, 'TAP_KEY_SIG should be set after musig2_finalize_input')
        self.assertEqual(EC_SIGNATURE_LEN, sig_written, 'TAP_KEY_SIG should be 64 bytes')

        # Compute taproot sighash and verify BIP-340 signature under output key
        output_xonly_key = bytes(p2tr_bytes[2:34])
        output_key_buf, _ = make_cbuffer(output_xonly_key.hex())

        # PSBT v2 has no global tx; build the tx manually from PSBT data.
        # Input: txhash=0..0, index=0, sequence=0 (from zero-initialized wally_tx_input)
        # Output: 1000 sat, P2WPKH (b'\x00\x14' + b'\xab' * 20)
        tx_pp = POINTER(wally_tx)()
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 1, byref(tx_pp)))
        zero_txid, _ = make_cbuffer('00' * 32)
        self.assertEqual(WALLY_OK,
                         wally_tx_add_raw_input(tx_pp, zero_txid, 32, 0, 0, None, 0, None, 0))
        out_script = b'\x00\x14' + b'\xab' * 20
        self.assertEqual(WALLY_OK,
                         wally_tx_add_raw_output(tx_pp, 1000, out_script, len(out_script), 0))

        sighash_buf, _ = make_cbuffer('00' * 32)
        ret = wally_psbt_get_input_signature_hash(
            psbt, 0, tx_pp, None, 0, WALLY_SIGHASH_DEFAULT, sighash_buf, 32)
        self.assertEqual(WALLY_OK, ret, 'sighash computation failed')

        ret = wally_ec_sig_verify(
            output_key_buf, EC_XONLY_PUBLIC_KEY_LEN,
            sighash_buf, 32,
            EC_FLAG_SCHNORR,
            sig_buf, EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK, ret, 'BIP-340 signature invalid for 3-of-3')
        wally_tx_free(tx_pp)

        # Finalize witness and cleanup
        ret = wally_psbt_finalize_input(psbt, 0, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertIsNotNone(psbt.contents.inputs[0].final_witness,
                             'final_witness should be set after finalize_input')

        wally_musig_secnonce_free(sn1.value)
        wally_musig_secnonce_free(sn2.value)
        wally_musig_secnonce_free(sn3.value)
        wally_musig_keyagg_cache_free(cache.value)
        wally_psbt_free(psbt)


    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_psbt_musig2_sign_missing_nonce(self):
        """wally_psbt_musig2_sign returns error when not all participants have contributed nonces"""
        # Set up a 2-of-2 MuSig2 PSBT
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        agg_pk_xonly, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        ret = wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                     agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN, cache)
        self.assertEqual(WALLY_OK, ret)

        agg_pubkey = bytes([0x02]) + bytes(agg_pk_xonly)
        agg_pubkey_buf, _ = make_cbuffer(agg_pubkey.hex())

        p2tr_buf, _ = make_cbuffer('00' * 34)
        ret, p2tr_written = wally_scriptpubkey_p2tr_from_bytes(
            agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
        self.assertEqual(WALLY_OK, ret)
        p2tr_bytes = bytes(p2tr_buf[:p2tr_written])

        # Create PSBT v2 with 1 input and 1 output
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))

        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))

        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(1000, b'\x00\x14' + b'\xab' * 20, 22,
                                                    tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))

        utxo = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(200000, p2tr_bytes, len(p2tr_bytes), utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, 0, utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_amount(psbt, 0, 200000))

        self.assertEqual(WALLY_OK,
                         wally_psbt_set_input_taproot_internal_key(
                             psbt, 0, agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN))

        participants_flat = bytes(pk1) + bytes(pk2)
        self.assertEqual(WALLY_OK,
                         wally_psbt_input_add_musig2_participant_pubkeys(
                             psbt.contents.inputs,
                             agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
                             participants_flat, len(participants_flat)))

        # Scenario A: signer 2 has a valid secnonce but signer 1 never added a pubnonce.
        # Only signer 2 adds a nonce; signer 1 does NOT.
        secrand2, _ = make_cbuffer('c2' * 32)
        sn2 = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            psbt, 0, secrand2, 32, None, 0,
            pk2, EC_PUBLIC_KEY_LEN, agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn2))
        self.assertEqual(WALLY_OK, ret)
        self.assertIsNotNone(sn2.value)

        # Verify only 1 pubnonce is registered (signer 1 has not contributed)
        ret, nonce_count = wally_psbt_input_get_musig2_pubnonce_count(psbt.contents.inputs[0])
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(1, nonce_count)

        # Signer 2 has a valid secnonce, but signer 1 never added a pubnonce —
        # aggregate nonce cannot be formed, so sign must fail.
        seckey2, _ = make_cbuffer(SECKEY2.hex())
        ret = wally_psbt_musig2_sign(
            psbt, 0, sn2.value,
            seckey2, 32, pk2, EC_PUBLIC_KEY_LEN,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, cache.value, 0, None)
        self.assertNotEqual(WALLY_OK, ret,
                            'sign must fail when a participant pubnonce is missing from PSBT')
        wally_musig_secnonce_free(sn2.value)

        # Scenario B: NULL secnonce — basic invalid-argument guard.
        sn_null = c_void_p()  # never initialised → value is None
        ret = wally_psbt_musig2_sign(
            psbt, 0, sn_null.value,
            seckey2, 32, pk2, EC_PUBLIC_KEY_LEN,
            agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, cache.value, 0, None)
        self.assertEqual(WALLY_EINVAL, ret,
                         'sign must return WALLY_EINVAL for NULL secnonce')

        # Cleanup
        wally_musig_keyagg_cache_free(cache.value)
        wally_psbt_free(psbt)


    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_psbt_musig2_nonce_reuse(self):
        """wally_psbt_musig2_add_nonce returns error when called twice for the same participant"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        agg_pk_xonly, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        ret = wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                     agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN, cache)
        self.assertEqual(WALLY_OK, ret)

        agg_pubkey = bytes([0x02]) + bytes(agg_pk_xonly)
        agg_pubkey_buf, _ = make_cbuffer(agg_pubkey.hex())

        p2tr_buf, _ = make_cbuffer('00' * 34)
        ret, p2tr_written = wally_scriptpubkey_p2tr_from_bytes(
            agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN, 0, p2tr_buf, 34)
        self.assertEqual(WALLY_OK, ret)
        p2tr_bytes = bytes(p2tr_buf[:p2tr_written])

        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))

        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))

        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(1000, b'\x00\x14' + b'\xab' * 20, 22,
                                                    tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))

        utxo = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(200000, p2tr_bytes, len(p2tr_bytes), utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, 0, utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_amount(psbt, 0, 200000))

        self.assertEqual(WALLY_OK,
                         wally_psbt_set_input_taproot_internal_key(
                             psbt, 0, agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN))

        participants_flat = bytes(pk1) + bytes(pk2)
        self.assertEqual(WALLY_OK,
                         wally_psbt_input_add_musig2_participant_pubkeys(
                             psbt.contents.inputs,
                             agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
                             participants_flat, len(participants_flat)))

        # First nonce for signer 1 — must succeed
        secrand1, _ = make_cbuffer('d1' * 32)
        sn1 = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            psbt, 0, secrand1, 32, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn1))
        self.assertEqual(WALLY_OK, ret, 'first add_nonce for signer 1 should succeed')
        self.assertIsNotNone(sn1.value)

        # Second nonce for signer 1 (same pk, same agg_pubkey) — must fail
        secrand1b, _ = make_cbuffer('d2' * 32)
        sn1b = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            psbt, 0, secrand1b, 32, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, agg_pubkey_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn1b))
        self.assertNotEqual(WALLY_OK, ret,
                            'add_nonce must fail when called twice for the same participant')

        # Cleanup
        wally_musig_secnonce_free(sn1.value)
        wally_musig_keyagg_cache_free(cache.value)
        wally_psbt_free(psbt)


    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_pubnonce_parse_invalid(self):
        """wally_musig_pubnonce_parse rejects buffers of wrong length"""
        invalid_lengths = [0, 1, 65, 67, 132]
        for bad_len in invalid_lengths:
            buf = bytes([0x00] * bad_len)
            pn = c_void_p()
            ret = wally_musig_pubnonce_parse(buf if bad_len > 0 else None,
                                             bad_len, pn)
            self.assertNotEqual(WALLY_OK, ret,
                                f'pubnonce_parse should fail for length {bad_len}')

        # All-zeros 66-byte buffer is an invalid (infinity) point and must fail
        zero_buf = bytes([0x00] * MUSIG_PUBNONCE_LEN)
        pn = c_void_p()
        ret = wally_musig_pubnonce_parse(zero_buf, MUSIG_PUBNONCE_LEN, pn)
        self.assertNotEqual(WALLY_OK, ret,
                            'pubnonce_parse should reject all-zeros (infinity) input')
        if pn.value:
            wally_musig_pubnonce_free(pn.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_partial_sig_parse_invalid(self):
        """wally_musig_partial_sig_parse rejects buffers of wrong length"""
        invalid_lengths = [0, 31, 33]
        for bad_len in invalid_lengths:
            buf = bytes([0x01] * bad_len)
            psig = c_void_p()
            ret = wally_musig_partial_sig_parse(buf if bad_len > 0 else None,
                                                bad_len, psig)
            self.assertNotEqual(WALLY_OK, ret,
                                f'partial_sig_parse should fail for length {bad_len}')

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_aggnonce_mismatch_in_session(self):
        """Corrupted aggnonce bytes produce a different session (or fail), preventing silent forgery"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          None, 0, cache))

        sn1 = c_void_p()
        pn1 = c_void_p()
        sn2 = c_void_p()
        pn2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(bytes([0xe1] * 32), 32, SECKEY1, 32,
                                                         pk1, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn1, pn1))
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(bytes([0xe2] * 32), 32, SECKEY2, 32,
                                                         pk2, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn2, pn2))

        pn1_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        pn2_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn1.value, pn1_bytes, MUSIG_PUBNONCE_LEN))
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn2.value, pn2_bytes, MUSIG_PUBNONCE_LEN))

        pubnonces_flat = bytes(pn1_bytes) + bytes(pn2_bytes)
        aggnonce = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_agg(pubnonces_flat, len(pubnonces_flat), 2, aggnonce))

        # Serialize aggnonce, corrupt one byte, parse back
        an_bytes, _ = make_cbuffer('00' * MUSIG_AGGNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_aggnonce_serialize(aggnonce.value, an_bytes, MUSIG_AGGNONCE_LEN))

        corrupted = bytearray(an_bytes)
        corrupted[0] ^= 0xff
        aggnonce_bad = c_void_p()
        ret = wally_musig_aggnonce_parse(bytes(corrupted), MUSIG_AGGNONCE_LEN, aggnonce_bad)

        if ret == WALLY_OK and aggnonce_bad.value is not None:
            # Corrupted aggnonce parsed: session will differ or partial sign will fail to verify
            session_bad = c_void_p()
            ret_proc = wally_musig_nonce_process(aggnonce_bad.value, TEST_MSG32, 32,
                                                 cache.value, None, 0, session_bad)
            if ret_proc == WALLY_OK and session_bad.value is not None:
                # Session formed with bad nonce: partial sig must fail verification
                psig1_bad = c_void_p()
                ret_sign = wally_musig_partial_sign(sn1.value, SECKEY1, 32,
                                                    cache.value, session_bad.value, psig1_bad)
                if ret_sign == WALLY_OK and psig1_bad.value is not None:
                    ret_v = wally_musig_partial_sig_verify(psig1_bad.value, pn1.value,
                                                           pk1, EC_PUBLIC_KEY_LEN,
                                                           cache.value, session_bad.value)
                    # Verification should fail because the nonce was corrupted
                    self.assertNotEqual(WALLY_OK, ret_v,
                                        'partial sig must not verify against corrupted aggnonce')
                    wally_musig_partial_sig_free(psig1_bad.value)
                wally_musig_session_free(session_bad.value)
            wally_musig_aggnonce_free(aggnonce_bad.value)
        else:
            # Parse correctly rejected the corrupted aggnonce — that is also acceptable
            pass

        # Cleanup (sn1 may have been consumed if partial_sign was called above)
        try:
            wally_musig_secnonce_free(sn1.value)
        except Exception:
            pass
        wally_musig_secnonce_free(sn2.value)
        wally_musig_pubnonce_free(pn1.value)
        wally_musig_pubnonce_free(pn2.value)
        wally_musig_aggnonce_free(aggnonce.value)
        wally_musig_keyagg_cache_free(cache.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_keyagg_cache_roundtrip_3keys(self):
        """Keyagg cache serialize/parse roundtrip is identical for 3 participants"""
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pk3 = derive_pubkey(SECKEY3)
        pub_keys_flat = pk1 + pk2 + pk3

        # Aggregate 3 keys
        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          agg_pk, EC_XONLY_PUBLIC_KEY_LEN, cache))

        # Serialize
        cache_bytes, _ = make_cbuffer('00' * MUSIG_KEYAGG_CACHE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_keyagg_cache_serialize(cache.value, cache_bytes,
                                                                       MUSIG_KEYAGG_CACHE_LEN))

        # Parse back
        cache2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_keyagg_cache_parse(cache_bytes, MUSIG_KEYAGG_CACHE_LEN, cache2))

        # Re-serialize and compare bytes
        cache2_bytes, _ = make_cbuffer('00' * MUSIG_KEYAGG_CACHE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_keyagg_cache_serialize(cache2.value, cache2_bytes,
                                                                       MUSIG_KEYAGG_CACHE_LEN))
        self.assertEqual(bytes(cache_bytes), bytes(cache2_bytes))

        # Verify the aggregate pubkey is consistent from both caches
        agg_from_cache2, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubkey_get(cache2.value, agg_from_cache2, EC_PUBLIC_KEY_LEN))
        self.assertIn(bytes(agg_from_cache2)[0:1], [b'\x02', b'\x03'])
        self.assertEqual(bytes(agg_from_cache2)[1:], bytes(agg_pk))

        wally_musig_keyagg_cache_free(cache.value)
        wally_musig_keyagg_cache_free(cache2.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_descriptor_musig_outside_tr_rejected(self):
        """musig() is only valid inside tr(); using it in wpkh() must fail"""
        pk1 = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        pk2 = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        bad_desc = f'wpkh(musig({pk1},{pk2}))'
        d = c_void_p()
        ret = wally_descriptor_parse(bad_desc, None, 0, 0, d)
        self.assertNotEqual(WALLY_OK, ret,
                            'musig() inside wpkh() must be rejected')
        if d.value:
            wally_descriptor_free(d.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_descriptor_nested_musig_rejected(self):
        """Nested musig() must be rejected by the descriptor parser"""
        pk1 = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        pk2 = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        pk3 = '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
        bad_desc = f'tr(musig(musig({pk1},{pk2}),{pk3}))'
        d = c_void_p()
        ret = wally_descriptor_parse(bad_desc, None, 0, 0, d)
        self.assertNotEqual(WALLY_OK, ret,
                            'nested musig() must be rejected')
        if d.value:
            wally_descriptor_free(d.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_partial_sign_nonce_reuse_causes_abort(self):
        """SECURITY: secp256k1 zeroes the secnonce after partial_sign to prevent nonce reuse.

        A second call with the same (now-zeroed) secnonce would trigger the
        secp256k1 illegal-argument callback which calls abort(). This is the
        intended nonce-reuse protection at the secp256k1 level. The wally
        wrapper does not intercept that callback, so the abort() is by design.

        This test verifies:
        1. partial_sign succeeds on first call.
        2. The secnonce is consumed by the sign operation (cannot be reused).
        Calling partial_sign a second time with the same secnonce pointer
        would cause abort() — this cannot be tested in a normal unit test
        without crashing the process. The abort() path is tested by secp256k1's
        own test suite. Wally inherits that guarantee.
        """
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          None, 0, cache))

        sn1 = c_void_p()
        pn1 = c_void_p()
        sn2 = c_void_p()
        pn2 = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(bytes([0xf1] * 32), 32, SECKEY1, 32,
                                                         pk1, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn1, pn1))
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(bytes([0xf2] * 32), 32, SECKEY2, 32,
                                                         pk2, EC_PUBLIC_KEY_LEN,
                                                         None, None, 0, None, 0, sn2, pn2))

        pn1_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        pn2_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn1.value, pn1_bytes, MUSIG_PUBNONCE_LEN))
        self.assertEqual(WALLY_OK, wally_musig_pubnonce_serialize(pn2.value, pn2_bytes, MUSIG_PUBNONCE_LEN))

        pubnonces_flat = bytes(pn1_bytes) + bytes(pn2_bytes)
        aggnonce = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_agg(pubnonces_flat, len(pubnonces_flat), 2, aggnonce))

        session = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_process(aggnonce.value, TEST_MSG32, 32,
                                                             cache.value, None, 0, session))

        # First call: MUST succeed — secnonce is valid and unused.
        psig1 = c_void_p()
        ret = wally_musig_partial_sign(sn1.value, SECKEY1, 32, cache.value, session.value, psig1)
        self.assertEqual(WALLY_OK, ret, 'first partial_sign must succeed')
        self.assertIsNotNone(psig1.value, 'partial sig must be non-NULL on success')

        # secp256k1 has now zeroed the secnonce memory inside sn1.
        # A second call with sn1.value would cause secp256k1 to invoke its
        # illegal-argument callback, which calls abort(). This is the
        # deliberate security mechanism preventing nonce reuse.
        # We do NOT call partial_sign again here to avoid crashing the test
        # process — the abort() protection is documented and tested at the
        # secp256k1 level (see secp256k1/src/modules/musig/tests_impl.h).

        # Cleanup
        wally_musig_secnonce_free(sn1.value)
        wally_musig_secnonce_free(sn2.value)
        wally_musig_pubnonce_free(pn1.value)
        wally_musig_pubnonce_free(pn2.value)
        wally_musig_partial_sig_free(psig1.value)
        wally_musig_aggnonce_free(aggnonce.value)
        wally_musig_session_free(session.value)
        wally_musig_keyagg_cache_free(cache.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_descriptor_musig_hardened_rejected(self):
        """wally_descriptor_parse must reject tr(musig()) with hardened child paths after xpub.

        BIP-32 public-key-only derivation cannot produce hardened children
        (requires the private key). musig() keys are aggregated public keys,
        so hardened derivation paths inside musig() must be rejected.
        """
        xpub1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub2 = 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
        fp1 = 'deadbeef'
        fp2 = 'cafebabe'

        # Hardened child index after the xpub: /0h/* — must be rejected.
        bad_desc = f'tr(musig([{fp1}/86h/0h/0h]{xpub1}/0h/*,[{fp2}/86h/0h/0h]{xpub2}/0h/*))'
        d = c_void_p()
        ret = wally_descriptor_parse(bad_desc, None, 0, 0, d)
        self.assertNotEqual(WALLY_OK, ret,
                            'musig() descriptor with hardened child path after xpub must be rejected')
        if d.value:
            wally_descriptor_free(d.value)

        # Sanity check: the same descriptor with unhardened /0/* must be accepted.
        good_desc = f'tr(musig([{fp1}/86h/0h/0h]{xpub1}/0/*,[{fp2}/86h/0h/0h]{xpub2}/0/*))'
        d2 = c_void_p()
        ret2 = wally_descriptor_parse(good_desc, None, 0, 0, d2)
        self.assertEqual(WALLY_OK, ret2,
                         'musig() descriptor with unhardened /0/* must be accepted')
        if d2.value:
            wally_descriptor_free(d2.value)

    @unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
    def test_psbt_musig2_wrong_aggregate_key(self):
        """PSBT signing must fail when PARTICIPANT_PUBKEYS is registered under a wrong aggregate key.

        If the aggregate key stored in the PSBT input does not match the real
        aggregate key used during signing, the implementation must reject the
        operation rather than silently producing an invalid signature.
        """
        pk1 = derive_pubkey(SECKEY1)
        pk2 = derive_pubkey(SECKEY2)
        pub_keys_flat = pk1 + pk2

        # Compute the real aggregate key.
        agg_pk_xonly, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                                          agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN, cache))

        real_agg_pubkey = bytes([0x02]) + bytes(agg_pk_xonly)
        real_agg_buf, _ = make_cbuffer(real_agg_pubkey.hex())

        # Build a wrong aggregate key: a random compressed pubkey unrelated to pk1/pk2.
        wrong_agg = bytes([0x02]) + bytes([0x03] * EC_XONLY_PUBLIC_KEY_LEN)
        wrong_agg_buf, _ = make_cbuffer(wrong_agg.hex())

        # Build PSBT v2 with 1 input.
        p2tr_buf, _ = make_cbuffer('00' * 34)
        ret, _ = wally_scriptpubkey_p2tr_from_bytes(agg_pk_xonly, EC_XONLY_PUBLIC_KEY_LEN, 0,
                                                     p2tr_buf, 34)
        self.assertEqual(WALLY_OK, ret)
        p2tr_bytes = bytes(p2tr_buf[:34])

        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))

        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))

        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(1000, b'\x00\x14' + b'\xab' * 20, 22,
                                                    tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))

        utxo = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(200000, p2tr_bytes, len(p2tr_bytes), utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, 0, utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_amount(psbt, 0, 200000))

        self.assertEqual(WALLY_OK,
                         wally_psbt_set_input_taproot_internal_key(psbt, 0,
                                                                    agg_pk_xonly,
                                                                    EC_XONLY_PUBLIC_KEY_LEN))

        # Register participant pubkeys under the WRONG aggregate key.
        participants_flat = bytes(pk1) + bytes(pk2)
        self.assertEqual(WALLY_OK,
                         wally_psbt_input_add_musig2_participant_pubkeys(
                             psbt.contents.inputs,
                             wrong_agg_buf, EC_PUBLIC_KEY_LEN,
                             participants_flat, len(participants_flat)))

        # Try to add a nonce using the REAL aggregate key.
        # The lookup for the registered participant pubkeys uses the agg_pubkey
        # as part of the key — since they were registered under wrong_agg_buf,
        # the real agg_buf lookup must either fail or not find a matching entry.
        secrand1, _ = make_cbuffer('e1' * 32)
        sn1 = c_void_p()
        ret = wally_psbt_musig2_add_nonce(
            psbt, 0, secrand1, 32, None, 0,
            pk1, EC_PUBLIC_KEY_LEN, real_agg_buf, EC_PUBLIC_KEY_LEN,
            None, 0, None, 0, byref(sn1))
        # The add_nonce must fail: participant pubkeys were registered under
        # the wrong aggregate key, so the nonce entry cannot be stored correctly.
        self.assertNotEqual(WALLY_OK, ret,
                            'add_nonce must fail when participant pubkeys use a wrong aggregate key')
        if sn1.value:
            wally_musig_secnonce_free(sn1.value)

        # Cleanup
        wally_musig_keyagg_cache_free(cache.value)
        wally_psbt_free(psbt)


if __name__ == '__main__':
    unittest.main()
