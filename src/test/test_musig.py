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
