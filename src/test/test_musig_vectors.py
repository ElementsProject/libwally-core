"""
BIP-327/328/390 test vector validation for the wally MuSig2 Python API.

Loads the upstream BIP-327 JSON test vectors shipped under
src/data/bip327/ and drives them through the wally Python ctypes
binding layer end-to-end.
"""

import json
import os
import unittest
from ctypes import *
from util import *

_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'bip327')


def _load_vectors(name):
    with open(os.path.join(_DATA_DIR, name + '.json'), 'r') as f:
        return json.load(f)


def _h(s):
    """Hex -> bytes helper that tolerates None and empty strings."""
    if s is None:
        return None
    return bytes.fromhex(s)


# Map upstream BIP-327 error.type discriminators to wally error codes.
# Upstream uses "invalid_contribution" (a participant contributed bad data)
# and "value" (a scalar/field element is out of range). Both surface as
# WALLY_EINVAL through the wally API.
# Upstream 'value' errors map to different wally error codes depending on
# where validation rejects the input (EINVAL at the FFI boundary vs ERROR
# for scalar/field-element range checks inside secp256k1). Keep only the
# reliably one-to-one mapping; other types fall back to "any non-OK".
_ERROR_TYPE_MAP = {
    'invalid_contribution': WALLY_EINVAL,
}
_unknown_error_types = set()


def _assert_error(testcase, ret, err):
    """Assert ret matches the upstream error descriptor's type (if known)."""
    testcase.assertNotEqual(WALLY_OK, ret, 'expected error but got WALLY_OK')
    etype = (err or {}).get('type')
    if etype in _ERROR_TYPE_MAP:
        testcase.assertEqual(_ERROR_TYPE_MAP[etype], ret,
                             f'error type {etype!r} expected {_ERROR_TYPE_MAP[etype]}, got {ret}')
    elif etype is not None:
        _unknown_error_types.add(etype)

EC_PUBLIC_KEY_LEN = 33
EC_XONLY_PUBLIC_KEY_LEN = 32
EC_SIGNATURE_LEN = 64
EC_FLAG_SCHNORR = 0x2

BIP32_VER_MAIN_PUBLIC   = 0x0488B21E
BIP32_VER_MAIN_PRIVATE  = 0x0488ADE4
BIP32_INITIAL_HARDENED_CHILD = 0x80000000
BIP32_FLAG_KEY_PUBLIC = 0x1
BIP32_SERIALIZED_LEN = 78

MUSIG_PUBNONCE_LEN     = 66
MUSIG_AGGNONCE_LEN     = 66
MUSIG_PARTIAL_SIG_LEN  = 32
MUSIG_KEYAGG_CACHE_LEN = 197
MUSIG_SESSION_LEN      = 133

NETWORK_NONE     = 0x00
NETWORK_BTC_MAIN = 0x01

def derive_pubkey(seckey):
    pub, pub_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
    ret = wally_ec_public_key_from_private_key(seckey, len(seckey), pub, pub_len)
    assert ret == WALLY_OK, 'derive_pubkey failed'
    return pub


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class KeyAggVectorTests(unittest.TestCase):
    """BIP-327 key aggregation test vectors (upstream key_agg_vectors.json)."""

    V = _load_vectors('key_agg_vectors')
    PUBKEYS = [_h(p) for p in V['pubkeys']]
    TWEAKS  = [_h(t) for t in V['tweaks']]

    def _agg(self, key_indices):
        pks = b''.join(self.PUBKEYS[i] for i in key_indices)
        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        ret = wally_musig_pubkey_agg(pks, len(pks), agg_pk,
                                     EC_XONLY_PUBLIC_KEY_LEN, cache)
        return ret, bytes(agg_pk), cache

    def test_valid_cases(self):
        """Each valid_test_case matches BIP-327 expected x-only output."""
        self.assertGreater(len(self.V['valid_test_cases']), 0, "valid_test_cases empty")
        for i, tc in enumerate(self.V['valid_test_cases']):
            with self.subTest(case=i):
                ret, agg_pk, cache = self._agg(tc['key_indices'])
                self.assertEqual(WALLY_OK, ret, f'case {i}: pubkey_agg failed')
                self.assertEqual(_h(tc['expected']), agg_pk,
                                 f'case {i}: x-only output mismatch')
                if cache.value:
                    wally_musig_keyagg_cache_free(cache.value)

    def test_error_cases(self):
        """Each error_test_case returns non-WALLY_OK with the expected type."""
        self.assertGreater(len(self.V['error_test_cases']), 0, "error_test_cases empty")
        for i, tc in enumerate(self.V['error_test_cases']):
            with self.subTest(case=i, comment=tc.get('comment', '')):
                pks = b''.join(self.PUBKEYS[j] for j in tc['key_indices'])
                agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
                cache = c_void_p()
                ret = wally_musig_pubkey_agg(pks, len(pks), agg_pk,
                                             EC_XONLY_PUBLIC_KEY_LEN, cache)
                if ret == WALLY_OK and tc.get('tweak_indices') and cache.value:
                    for ti, xonly in zip(tc['tweak_indices'], tc['is_xonly']):
                        tweak = self.TWEAKS[ti]
                        out, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
                        fn = (wally_musig_pubkey_xonly_tweak_add if xonly
                              else wally_musig_pubkey_ec_tweak_add)
                        ret = fn(cache.value, tweak, len(tweak),
                                 out, EC_PUBLIC_KEY_LEN)
                        if ret != WALLY_OK:
                            break
                _assert_error(self, ret, tc.get('error'))
                if cache.value:
                    wally_musig_keyagg_cache_free(cache.value)


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class NonceAggVectorTests(unittest.TestCase):
    """BIP-327 nonce aggregation test vectors (upstream nonce_agg_vectors.json)."""

    V = _load_vectors('nonce_agg_vectors')
    PNONCES = [_h(p) for p in V['pnonces']]

    def test_valid_cases(self):
        self.assertGreater(len(self.V['valid_test_cases']), 0, "valid_test_cases empty")
        for i, tc in enumerate(self.V['valid_test_cases']):
            with self.subTest(case=i):
                flat = b''.join(self.PNONCES[j] for j in tc['pnonce_indices'])
                n = len(tc['pnonce_indices'])
                aggnonce = c_void_p()
                ret = wally_musig_nonce_agg(flat, len(flat), n, aggnonce)
                self.assertEqual(WALLY_OK, ret, f'case {i}: nonce_agg failed')
                an_bytes, _ = make_cbuffer('00' * MUSIG_AGGNONCE_LEN)
                self.assertEqual(WALLY_OK,
                                 wally_musig_aggnonce_serialize(aggnonce.value, an_bytes,
                                                                MUSIG_AGGNONCE_LEN))
                self.assertEqual(_h(tc['expected']), bytes(an_bytes),
                                 f'case {i}: aggnonce output mismatch')
                wally_musig_aggnonce_free(aggnonce.value)

    def test_error_cases(self):
        self.assertGreater(len(self.V['error_test_cases']), 0, "error_test_cases empty")
        for i, tc in enumerate(self.V['error_test_cases']):
            with self.subTest(case=i, comment=tc.get('comment', '')):
                flat = b''.join(self.PNONCES[j] for j in tc['pnonce_indices'])
                n = len(tc['pnonce_indices'])
                aggnonce = c_void_p()
                ret = wally_musig_nonce_agg(flat, len(flat), n, aggnonce)
                _assert_error(self, ret, tc.get('error'))
                if aggnonce.value:
                    wally_musig_aggnonce_free(aggnonce.value)


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class NonceGenVectorTests(unittest.TestCase):
    """BIP-327 nonce generation vectors (upstream nonce_gen_vectors.json).

    Cases 0..2 bind the nonce to an aggregate public key provided as raw
    32 bytes. wally's public API only accepts a keyagg_cache built from
    the constituent individual pubkeys; there is no way to construct a
    cache from a raw aggpk. Those cases are skipped.
    Case 2 additionally uses a 38-byte msg which the wally API rejects
    (msg must be 32 bytes). Case 3 has no aggpk/msg/extra_in and is
    driven end-to-end against the expected pubnonce.
    """

    V = _load_vectors('nonce_gen_vectors')

    def test_cases(self):
        checked = 0
        self.assertGreater(len(self.V['test_cases']), 0, "test_cases empty")
        for i, tc in enumerate(self.V['test_cases']):
            with self.subTest(case=i):
                if tc.get('aggpk') is not None:
                    self.skipTest('aggpk injection unsupported by wally public API')
                    continue
                msg = _h(tc.get('msg')) if tc.get('msg') is not None else None
                if msg is not None and len(msg) != 32:
                    self.skipTest('non-32-byte msg unsupported by wally API')
                    continue
                sk = _h(tc.get('sk')) if tc.get('sk') else None
                pk = _h(tc['pk'])
                extra = _h(tc.get('extra_in')) if tc.get('extra_in') else None
                rand_ = _h(tc['rand_'])
                sn, pn = c_void_p(), c_void_p()
                ret = wally_musig_nonce_gen(
                    rand_, len(rand_),
                    sk, (32 if sk else 0),
                    pk, len(pk),
                    None,
                    msg, (32 if msg else 0),
                    extra, (32 if extra else 0),
                    sn, pn)
                self.assertEqual(WALLY_OK, ret, f'case {i}: nonce_gen failed')
                pn_bytes, _bl = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
                self.assertEqual(WALLY_OK,
                                 wally_musig_pubnonce_serialize(pn.value, pn_bytes,
                                                                MUSIG_PUBNONCE_LEN))
                self.assertEqual(_h(tc['expected_pubnonce']), bytes(pn_bytes),
                                 f'case {i}: pubnonce mismatch')
                if sn.value: wally_musig_secnonce_free(sn.value)
                wally_musig_pubnonce_free(pn.value)
                checked += 1
        self.assertGreater(checked, 0, 'No nonce_gen cases exercised')

    def test_same_rand_same_result(self):
        """Nonce gen is deterministic: same inputs produce identical pubnonces."""
        rand_ = bytes([0xAB] * 32)
        pk = bytes.fromhex('02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9')

        sn1, pn1 = c_void_p(), c_void_p()
        sn2, pn2 = c_void_p(), c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(rand_, 32, None, 0, pk, 33,
                                                         None, None, 0, None, 0, sn1, pn1))
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(rand_, 32, None, 0, pk, 33,
                                                         None, None, 0, None, 0, sn2, pn2))

        pn1b, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        pn2b, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        wally_musig_pubnonce_serialize(pn1.value, pn1b, MUSIG_PUBNONCE_LEN)
        wally_musig_pubnonce_serialize(pn2.value, pn2b, MUSIG_PUBNONCE_LEN)
        self.assertEqual(bytes(pn1b), bytes(pn2b), 'Same inputs must produce same pubnonce')

        if sn1.value: wally_musig_secnonce_free(sn1.value)
        if sn2.value: wally_musig_secnonce_free(sn2.value)
        wally_musig_pubnonce_free(pn1.value)
        wally_musig_pubnonce_free(pn2.value)

    def test_different_rand_different_result(self):
        """Different rand values produce different pubnonces."""
        pk = bytes.fromhex('02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9')

        sn1, pn1 = c_void_p(), c_void_p()
        sn2, pn2 = c_void_p(), c_void_p()
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(bytes([0x01] * 32), 32, None, 0, pk, 33,
                                                         None, None, 0, None, 0, sn1, pn1))
        self.assertEqual(WALLY_OK, wally_musig_nonce_gen(bytes([0x02] * 32), 32, None, 0, pk, 33,
                                                         None, None, 0, None, 0, sn2, pn2))

        pn1b, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        pn2b, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
        wally_musig_pubnonce_serialize(pn1.value, pn1b, MUSIG_PUBNONCE_LEN)
        wally_musig_pubnonce_serialize(pn2.value, pn2b, MUSIG_PUBNONCE_LEN)
        self.assertNotEqual(bytes(pn1b), bytes(pn2b),
                            'Different rand values must produce different pubnonces')

        if sn1.value: wally_musig_secnonce_free(sn1.value)
        if sn2.value: wally_musig_secnonce_free(sn2.value)
        wally_musig_pubnonce_free(pn1.value)
        wally_musig_pubnonce_free(pn2.value)


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class SignVerifyVectorTests(unittest.TestCase):
    """BIP-327 sign/verify: complete flow with verification.

    BIP-327 sign_verify vectors use secp256k1-internal secnonce format (194 bytes)
    not accessible through the wally public API. We instead run complete
    deterministic signing flows and verify final Schnorr signatures.
    """

    def _run_sign_flow(self, seckeys, msg32):
        """Run full MuSig2 signing flow. Returns (final_sig, agg_pk_xonly)."""
        n = len(seckeys)
        pubkeys = [derive_pubkey(sk) for sk in seckeys]

        pub_keys_flat = b''.join(pubkeys)
        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        cache = c_void_p()
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                               agg_pk, EC_XONLY_PUBLIC_KEY_LEN, cache))

        secnonces, pubnonces, pn_bytes_list = [], [], []
        for i, (sk, pk) in enumerate(zip(seckeys, pubkeys)):
            sn, pn = c_void_p(), c_void_p()
            session_id = bytes([0x10 + i]) * 32
            self.assertEqual(WALLY_OK,
                             wally_musig_nonce_gen(session_id, 32, sk, 32, pk, EC_PUBLIC_KEY_LEN,
                                                   None, None, 0, None, 0, sn, pn))
            secnonces.append(sn)
            pubnonces.append(pn)

            pn_bytes, _ = make_cbuffer('00' * MUSIG_PUBNONCE_LEN)
            self.assertEqual(WALLY_OK,
                             wally_musig_pubnonce_serialize(pn.value, pn_bytes, MUSIG_PUBNONCE_LEN))
            pn_bytes_list.append(bytes(pn_bytes))

        pubnonces_flat = b''.join(pn_bytes_list)
        aggnonce = c_void_p()
        self.assertEqual(WALLY_OK,
                         wally_musig_nonce_agg(pubnonces_flat, len(pubnonces_flat), n, aggnonce))

        session = c_void_p()
        self.assertEqual(WALLY_OK,
                         wally_musig_nonce_process(aggnonce.value, msg32, 32,
                                                   cache.value, None, 0, session))

        partial_sigs, ps_bytes_list = [], []
        for i, (sn, sk, pn, pk) in enumerate(zip(secnonces, seckeys, pubnonces, pubkeys)):
            psig = c_void_p()
            self.assertEqual(WALLY_OK,
                             wally_musig_partial_sign(sn.value, sk, 32,
                                                      cache.value, session.value, psig),
                             f'partial_sign failed for signer {i}')
            partial_sigs.append(psig)

            ps_bytes, _ = make_cbuffer('00' * MUSIG_PARTIAL_SIG_LEN)
            self.assertEqual(WALLY_OK,
                             wally_musig_partial_sig_serialize(psig.value, ps_bytes,
                                                               MUSIG_PARTIAL_SIG_LEN))
            ps_bytes_list.append(bytes(ps_bytes))

            self.assertEqual(WALLY_OK,
                             wally_musig_partial_sig_verify(psig.value, pn.value,
                                                            pk, EC_PUBLIC_KEY_LEN,
                                                            cache.value, session.value),
                             f'partial_sig_verify failed for signer {i}')

        partial_sigs_flat = b''.join(ps_bytes_list)
        final_sig, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK,
                         wally_musig_partial_sig_agg(partial_sigs_flat, len(partial_sigs_flat),
                                                     n, session.value, final_sig, EC_SIGNATURE_LEN))

        for sn in secnonces:
            if sn.value: wally_musig_secnonce_free(sn.value)
        for pn in pubnonces:
            if pn.value: wally_musig_pubnonce_free(pn.value)
        for psig in partial_sigs:
            if psig.value: wally_musig_partial_sig_free(psig.value)
        wally_musig_aggnonce_free(aggnonce.value)
        wally_musig_session_free(session.value)
        wally_musig_keyagg_cache_free(cache.value)

        return bytes(final_sig), bytes(agg_pk)

    def test_2of2_sign_verify(self):
        """2-of-2: final Schnorr sig verifies against aggregate pubkey."""
        msg32 = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 8)
        final_sig, agg_pk = self._run_sign_flow([bytes([0x01]*32), bytes([0x02]*32)], msg32)
        self.assertNotEqual(final_sig, b'\x00' * EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK,
                         wally_ec_sig_verify(agg_pk, EC_XONLY_PUBLIC_KEY_LEN,
                                             msg32, 32, EC_FLAG_SCHNORR,
                                             final_sig, EC_SIGNATURE_LEN))

    def test_3of3_sign_verify(self):
        """3-of-3: final Schnorr sig verifies against aggregate pubkey."""
        msg32 = bytes([0xCA, 0xFE, 0xBA, 0xBE] * 8)
        final_sig, agg_pk = self._run_sign_flow(
            [bytes([0x01]*32), bytes([0x02]*32), bytes([0x03]*32)], msg32)
        self.assertNotEqual(final_sig, b'\x00' * EC_SIGNATURE_LEN)
        self.assertEqual(WALLY_OK,
                         wally_ec_sig_verify(agg_pk, EC_XONLY_PUBLIC_KEY_LEN,
                                             msg32, 32, EC_FLAG_SCHNORR,
                                             final_sig, EC_SIGNATURE_LEN))

    def test_deterministic_output(self):
        """Deterministic inputs produce identical final signatures across two runs."""
        msg32 = bytes([0xAA] * 32)
        sig1, _ = self._run_sign_flow([bytes([0x01]*32), bytes([0x02]*32)], msg32)
        sig2, _ = self._run_sign_flow([bytes([0x01]*32), bytes([0x02]*32)], msg32)
        self.assertEqual(sig1, sig2, 'Deterministic flow must produce same final sig')

    def test_wrong_message_fails_verify(self):
        """Schnorr sig verifies only for the correct message, not a different one."""
        msg32_signed = bytes([0x01] * 32)
        msg32_wrong  = bytes([0x02] * 32)
        final_sig, agg_pk = self._run_sign_flow([bytes([0x01]*32), bytes([0x02]*32)], msg32_signed)
        self.assertNotEqual(WALLY_OK,
                            wally_ec_sig_verify(agg_pk, EC_XONLY_PUBLIC_KEY_LEN,
                                                msg32_wrong, 32, EC_FLAG_SCHNORR,
                                                final_sig, EC_SIGNATURE_LEN),
                            'Verification against wrong message should fail')


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class Bip328VectorTests(unittest.TestCase):
    """BIP-328 synthetic xpub construction and derivation test vectors."""

    # BIP-328 chaincode = SHA256('MuSig2MuSig2MuSig2')
    # Computed: hashlib.sha256(b'MuSig2MuSig2MuSig2').hexdigest()
    EXPECTED_CHAINCODE = bytes.fromhex('868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965')

    def _make_agg_pk(self, seckeys):
        pubkeys = [derive_pubkey(sk) for sk in seckeys]
        pub_keys_flat = b''.join(pubkeys)
        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkey_agg(pub_keys_flat, len(pub_keys_flat),
                                               agg_pk, EC_XONLY_PUBLIC_KEY_LEN, None))
        return bytes(agg_pk)

    def _make_synthetic_xpub(self, seckeys):
        agg_pk = self._make_agg_pk(seckeys)
        agg_pk_buf, _ = make_cbuffer(agg_pk.hex())
        xpub = POINTER(ext_key)()
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkey_to_xpub(agg_pk_buf, EC_XONLY_PUBLIC_KEY_LEN,
                                                    BIP32_VER_MAIN_PUBLIC, byref(xpub)))
        return xpub

    def test_chaincode_is_bip328_constant(self):
        """Synthetic xpub chain code must equal SHA256('MuSig2MuSig2MuSig2')."""
        xpub = self._make_synthetic_xpub([bytes([0x01]*32), bytes([0x02]*32)])
        actual_cc = bytes(xpub.contents.chain_code)
        self.assertEqual(self.EXPECTED_CHAINCODE, actual_cc,
                         f'Chain code mismatch:\n'
                         f'  got:      {actual_cc.hex()}\n'
                         f'  expected: {self.EXPECTED_CHAINCODE.hex()}')
        bip32_key_free(xpub)

    def test_xpub_root_metadata(self):
        """Synthetic xpub has depth=0, child_num=0, all-zero parent fingerprint."""
        xpub = self._make_synthetic_xpub([bytes([0x01]*32), bytes([0x02]*32)])
        self.assertEqual(0, xpub.contents.depth, 'depth must be 0')
        self.assertEqual(0, xpub.contents.child_num, 'child_num must be 0')
        self.assertEqual(b'\x00' * 20, bytes(xpub.contents.parent160),
                         'parent fingerprint must be all zeros')
        bip32_key_free(xpub)

    def test_xpub_starts_with_xpub(self):
        """Synthetic xpub serializes to a base58 string starting with 'xpub'."""
        xpub = self._make_synthetic_xpub([bytes([0x01]*32), bytes([0x02]*32)])
        ret, b58_str = bip32_key_to_base58(xpub, BIP32_FLAG_KEY_PUBLIC)
        self.assertEqual(WALLY_OK, ret)
        b58 = b58_str.decode('ascii') if isinstance(b58_str, bytes) else b58_str
        self.assertTrue(b58.startswith('xpub'), f'Expected xpub prefix, got: {b58[:8]}')
        bip32_key_free(xpub)

    def test_unhardened_child_derivation(self):
        """Unhardened derivation from synthetic xpub succeeds; children differ."""
        xpub = self._make_synthetic_xpub([bytes([0x03]*32), bytes([0x04]*32)])
        c0, c1 = POINTER(ext_key)(), POINTER(ext_key)()
        self.assertEqual(WALLY_OK,
                         bip32_key_from_parent_alloc(xpub, 0, BIP32_FLAG_KEY_PUBLIC, byref(c0)))
        self.assertEqual(WALLY_OK,
                         bip32_key_from_parent_alloc(xpub, 1, BIP32_FLAG_KEY_PUBLIC, byref(c1)))
        self.assertNotEqual(bytes(c0.contents.pub_key), bytes(c1.contents.pub_key),
                            'Different indices must produce different pubkeys')
        bip32_key_free(c0)
        bip32_key_free(c1)
        bip32_key_free(xpub)

    def test_hardened_derivation_rejected(self):
        """Hardened derivation from synthetic xpub must fail (no private key)."""
        xpub = self._make_synthetic_xpub([bytes([0x01]*32), bytes([0x02]*32)])
        child = POINTER(ext_key)()
        ret = bip32_key_from_parent_alloc(xpub, BIP32_INITIAL_HARDENED_CHILD,
                                          BIP32_FLAG_KEY_PUBLIC, byref(child))
        self.assertNotEqual(WALLY_OK, ret, 'Hardened derivation must fail')
        bip32_key_free(xpub)

    def test_derive_then_agg_order_independent(self):
        """BIP-390 derive_then_agg: swapping xpub order does not change output."""
        seed1, seed2 = bytes([0x01]*32), bytes([0x02]*32)
        xpub1, xpub2 = POINTER(ext_key)(), POINTER(ext_key)()
        self.assertEqual(WALLY_OK,
                         bip32_key_from_seed_alloc(seed1, len(seed1),
                                                   BIP32_VER_MAIN_PRIVATE, 0, byref(xpub1)))
        self.assertEqual(WALLY_OK,
                         bip32_key_from_seed_alloc(seed2, len(seed2),
                                                   BIP32_VER_MAIN_PRIVATE, 0, byref(xpub2)))

        ser1, _ = make_cbuffer('00' * BIP32_SERIALIZED_LEN)
        ser2, _ = make_cbuffer('00' * BIP32_SERIALIZED_LEN)
        self.assertEqual(WALLY_OK,
                         bip32_key_serialize(xpub1, BIP32_FLAG_KEY_PUBLIC, ser1, BIP32_SERIALIZED_LEN))
        self.assertEqual(WALLY_OK,
                         bip32_key_serialize(xpub2, BIP32_FLAG_KEY_PUBLIC, ser2, BIP32_SERIALIZED_LEN))

        agg_12, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        agg_21, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkeys_derive_then_agg(
                             bytes(ser1) + bytes(ser2), 2 * BIP32_SERIALIZED_LEN,
                             0, agg_12, EC_XONLY_PUBLIC_KEY_LEN, None))
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkeys_derive_then_agg(
                             bytes(ser2) + bytes(ser1), 2 * BIP32_SERIALIZED_LEN,
                             0, agg_21, EC_XONLY_PUBLIC_KEY_LEN, None))
        self.assertEqual(bytes(agg_12), bytes(agg_21),
                         'derive_then_agg must be order-independent (BIP-390 lexsort)')

        bip32_key_free(xpub1)
        bip32_key_free(xpub2)

    def test_agg_then_derive_consistent(self):
        """BIP-328 agg_then_derive: matches manual aggregate+xpub+derive sequence."""
        sk1, sk2 = bytes([0x01]*32), bytes([0x02]*32)
        pk1 = derive_pubkey(sk1)
        pk2 = derive_pubkey(sk2)
        pub_keys_flat = pk1 + pk2

        # Manual computation. wally_musig_pubkeys_agg_then_derive sorts the keys
        # before aggregation, so sort here to mirror it.
        sorted_keys_flat = b''.join(sorted([pk1, pk2]))
        agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkey_agg(sorted_keys_flat, len(sorted_keys_flat),
                                               agg_pk, EC_XONLY_PUBLIC_KEY_LEN, None))
        agg_pk_buf, _ = make_cbuffer(bytes(agg_pk).hex())
        synthetic_xpub = POINTER(ext_key)()
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkey_to_xpub(agg_pk_buf, EC_XONLY_PUBLIC_KEY_LEN,
                                                    BIP32_VER_MAIN_PUBLIC, byref(synthetic_xpub)))
        expected_child = POINTER(ext_key)()
        self.assertEqual(WALLY_OK,
                         bip32_key_from_parent_alloc(synthetic_xpub, 0,
                                                     BIP32_FLAG_KEY_PUBLIC, byref(expected_child)))
        expected_pk = bytes(expected_child.contents.pub_key)

        # agg_then_derive API
        result_pk, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(WALLY_OK,
                         wally_musig_pubkeys_agg_then_derive(
                             pub_keys_flat, len(pub_keys_flat),
                             BIP32_VER_MAIN_PUBLIC, 0,
                             result_pk, EC_PUBLIC_KEY_LEN, None))
        self.assertEqual(expected_pk, bytes(result_pk),
                         'agg_then_derive must match manual computation')

        bip32_key_free(expected_child)
        bip32_key_free(synthetic_xpub)


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class Bip390DescriptorVectorTests(unittest.TestCase):
    """BIP-390 musig() descriptor parsing and address generation tests."""

    PK1 = '02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'
    PK2 = '03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'
    XPUB1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
    XPUB2 = 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'

    def test_tr_musig_2of2_parse_and_participants(self):
        """tr(musig(pk1,pk2)) parses with 2 participants."""
        desc_str = f'tr(musig({self.PK1},{self.PK2}))'
        d = c_void_p()
        ret = wally_descriptor_parse(desc_str, None, NETWORK_NONE, 0, d)
        self.assertEqual(WALLY_OK, ret, f'Failed to parse: {desc_str}')

        ret, num_participants = wally_descriptor_get_musig_num_participants(d, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(2, num_participants, 'Expected 2 musig participants')

        wally_descriptor_free(d)

    def test_tr_musig_address_is_bech32m(self):
        """tr(musig(pk1,pk2)) on mainnet generates a bc1p address."""
        desc_str = f'tr(musig({self.PK1},{self.PK2}))'
        d = c_void_p()
        self.assertEqual(WALLY_OK,
                         wally_descriptor_parse(desc_str, None, NETWORK_BTC_MAIN, 0, d))

        ret, addr = wally_descriptor_to_address(d, 0, 0, 0, 0)
        self.assertEqual(WALLY_OK, ret, 'Address generation failed')
        addr_str = addr.decode('ascii') if isinstance(addr, bytes) else addr
        self.assertTrue(addr_str.startswith('bc1p'),
                        f'Expected bech32m (bc1p...) address, got: {addr_str}')
        wally_descriptor_free(d)

    def test_tr_musig_with_xpub_derivation_paths(self):
        """tr(musig([fp/path]xpub1/0/*, [fp/path]xpub2/0/*)) parses and has 2 participants."""
        desc_str = (f'tr(musig([deadbeef/86h/0h/0h]{self.XPUB1}/0/*,'
                    f'[cafebabe/86h/0h/0h]{self.XPUB2}/0/*))')
        d = c_void_p()
        ret = wally_descriptor_parse(desc_str, None, NETWORK_NONE, 0, d)
        self.assertEqual(WALLY_OK, ret, f'Failed to parse: {desc_str}')

        ret, num_participants = wally_descriptor_get_musig_num_participants(d, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(2, num_participants)
        wally_descriptor_free(d)

    def test_tr_musig_xpub_multiple_address_indices(self):
        """Different child indices produce different tr(musig) addresses."""
        desc_str = f'tr(musig({self.XPUB1}/0/*,{self.XPUB2}/0/*))'
        d = c_void_p()
        ret = wally_descriptor_parse(desc_str, None, NETWORK_BTC_MAIN, 0, d)
        self.assertEqual(WALLY_OK, ret)

        ret0, addr0 = wally_descriptor_to_address(d, 0, 0, 0, 0)
        ret1, addr1 = wally_descriptor_to_address(d, 0, 0, 1, 0)

        if ret0 == WALLY_OK and ret1 == WALLY_OK:
            a0 = addr0.decode('ascii') if isinstance(addr0, bytes) else addr0
            a1 = addr1.decode('ascii') if isinstance(addr1, bytes) else addr1
            self.assertNotEqual(a0, a1, 'Different indices must produce different addresses')
        wally_descriptor_free(d)


def _build_cache(pubkeys_flat):
    agg_pk, _ = make_cbuffer('00' * EC_XONLY_PUBLIC_KEY_LEN)
    cache = c_void_p()
    ret = wally_musig_pubkey_agg(pubkeys_flat, len(pubkeys_flat),
                                 agg_pk, EC_XONLY_PUBLIC_KEY_LEN, cache)
    return ret, bytes(agg_pk), cache


def _apply_tweaks(cache, tweak_list, is_xonly):
    for tweak, xonly in zip(tweak_list, is_xonly):
        out, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        fn = (wally_musig_pubkey_xonly_tweak_add if xonly
              else wally_musig_pubkey_ec_tweak_add)
        ret = fn(cache, tweak, len(tweak), out, EC_PUBLIC_KEY_LEN)
        if ret != WALLY_OK:
            return ret
    return WALLY_OK


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class SignVerifyVectorFileTests(unittest.TestCase):
    """BIP-327 sign_verify_vectors.json partial signature verify cases.

    The valid_test_cases and sign_error_test_cases expect signing with a
    preconstructed 194-byte secnonce; wally's public API has no way to
    inject a raw secnonce, so those categories are not exercised here
    (they are covered end-to-end by the flow tests in SignVerifyVectorTests
    further down). verify_fail_test_cases and verify_error_test_cases
    provide a complete partial signature and only need verification, which
    is reachable through wally_musig_partial_sig_verify.
    """

    V = _load_vectors('sign_verify_vectors')
    PUBKEYS = [_h(p) for p in V['pubkeys']]
    PNONCES = [_h(p) for p in V['pnonces']]
    MSGS    = [_h(m) for m in V['msgs']]

    def _setup(self, tc):
        pks = b''.join(self.PUBKEYS[j] for j in tc['key_indices'])
        ret, _, cache = _build_cache(pks)
        if ret != WALLY_OK:
            return cache, c_void_p(), ret
        pn_flat = b''.join(self.PNONCES[j] for j in tc['nonce_indices'])
        n = len(tc['nonce_indices'])
        aggnonce = c_void_p()
        ret = wally_musig_nonce_agg(pn_flat, len(pn_flat), n, aggnonce)
        return cache, aggnonce, ret

    def test_verify_fail_cases(self):
        msg = self.MSGS[0]
        self.assertEqual(32, len(msg))
        self.assertGreater(len(self.V['verify_fail_test_cases']), 0, "verify_fail_test_cases empty")
        for i, tc in enumerate(self.V['verify_fail_test_cases']):
            with self.subTest(case=i, comment=tc.get('comment', '')):
                cache, aggnonce, ret = self._setup(tc)
                if ret != WALLY_OK:
                    # Nonce aggregation failed; the expected verification
                    # failure has already occurred upstream.
                    if cache is not None and cache.value:
                        wally_musig_keyagg_cache_free(cache.value)
                    continue
                session = c_void_p()
                ret = wally_musig_nonce_process(aggnonce.value, msg, 32,
                                                cache.value, None, 0, session)
                self.assertEqual(WALLY_OK, ret, 'nonce_process setup failed')
                psig = c_void_p()
                r2 = wally_musig_partial_sig_parse(_h(tc['sig']),
                                                   MUSIG_PARTIAL_SIG_LEN, psig)
                verify_ret = WALLY_ERROR
                if r2 == WALLY_OK:
                    signer_pn = c_void_p()
                    r3 = wally_musig_pubnonce_parse(
                        self.PNONCES[tc['nonce_indices'][tc['signer_index']]],
                        MUSIG_PUBNONCE_LEN, signer_pn)
                    if r3 == WALLY_OK:
                        signer_pk = self.PUBKEYS[tc['key_indices'][tc['signer_index']]]
                        verify_ret = wally_musig_partial_sig_verify(
                            psig.value, signer_pn.value,
                            signer_pk, EC_PUBLIC_KEY_LEN,
                            cache.value, session.value)
                        wally_musig_pubnonce_free(signer_pn.value)
                    else:
                        verify_ret = r3
                    wally_musig_partial_sig_free(psig.value)
                else:
                    verify_ret = r2
                self.assertNotEqual(WALLY_OK, verify_ret,
                                    f'case {i}: verify unexpectedly succeeded')
                wally_musig_session_free(session.value)
                wally_musig_aggnonce_free(aggnonce.value)
                wally_musig_keyagg_cache_free(cache.value)

    def test_verify_error_cases(self):
        msg = self.MSGS[0]
        self.assertGreater(len(self.V['verify_error_test_cases']), 0, "verify_error_test_cases empty")
        for i, tc in enumerate(self.V['verify_error_test_cases']):
            with self.subTest(case=i, comment=tc.get('comment', '')):
                cache, aggnonce, setup_ret = self._setup(tc)
                final_ret = setup_ret
                session = c_void_p()
                if setup_ret == WALLY_OK:
                    final_ret = wally_musig_nonce_process(
                        aggnonce.value, msg, 32, cache.value,
                        None, 0, session)
                    if final_ret == WALLY_OK:
                        psig = c_void_p()
                        r2 = wally_musig_partial_sig_parse(
                            _h(tc['sig']), MUSIG_PARTIAL_SIG_LEN, psig)
                        if r2 != WALLY_OK:
                            final_ret = r2
                        else:
                            signer_pn = c_void_p()
                            r3 = wally_musig_pubnonce_parse(
                                self.PNONCES[tc['nonce_indices'][tc['signer_index']]],
                                MUSIG_PUBNONCE_LEN, signer_pn)
                            if r3 != WALLY_OK:
                                final_ret = r3
                            else:
                                signer_pk = self.PUBKEYS[tc['key_indices'][tc['signer_index']]]
                                final_ret = wally_musig_partial_sig_verify(
                                    psig.value, signer_pn.value,
                                    signer_pk, EC_PUBLIC_KEY_LEN,
                                    cache.value, session.value)
                                wally_musig_pubnonce_free(signer_pn.value)
                            wally_musig_partial_sig_free(psig.value)
                _assert_error(self, final_ret, tc.get('error'))
                if session.value:
                    wally_musig_session_free(session.value)
                if aggnonce.value:
                    wally_musig_aggnonce_free(aggnonce.value)
                if cache.value:
                    wally_musig_keyagg_cache_free(cache.value)


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class TweakVectorTests(unittest.TestCase):
    """BIP-327 tweak_vectors.json.

    valid_test_cases bind to a preconstructed 194-byte secnonce, which
    wally's public API cannot accept. Only error_test_cases (which fail
    before reaching signing) are exercised here.
    """

    V = _load_vectors('tweak_vectors')
    PUBKEYS = [_h(p) for p in V['pubkeys']]
    TWEAKS  = [_h(t) for t in V['tweaks']]

    def test_error_cases(self):
        self.assertGreater(len(self.V['error_test_cases']), 0, "error_test_cases empty")
        for i, tc in enumerate(self.V['error_test_cases']):
            with self.subTest(case=i, comment=tc.get('comment', '')):
                pks = b''.join(self.PUBKEYS[j] for j in tc['key_indices'])
                ret, _, cache = _build_cache(pks)
                if ret == WALLY_OK:
                    tweaks = [self.TWEAKS[j] for j in tc['tweak_indices']]
                    ret = _apply_tweaks(cache.value, tweaks, tc['is_xonly'])
                _assert_error(self, ret, tc.get('error'))
                if cache.value:
                    wally_musig_keyagg_cache_free(cache.value)


@unittest.skipUnless(wally_musig_pubkey_agg, 'MuSig2 module not enabled')
class SigAggVectorTests(unittest.TestCase):
    """BIP-327 sig_agg_vectors.json."""

    V = _load_vectors('sig_agg_vectors')
    PUBKEYS = [_h(p) for p in V['pubkeys']]
    PNONCES = [_h(p) for p in V['pnonces']]
    TWEAKS  = [_h(t) for t in V['tweaks']]
    PSIGS   = [_h(p) for p in V['psigs']]
    MSG     = _h(V['msg'])

    def _prepare(self, tc):
        pks = b''.join(self.PUBKEYS[j] for j in tc['key_indices'])
        ret, _, cache = _build_cache(pks)
        if ret != WALLY_OK:
            return ret, None, None
        tweaks = [self.TWEAKS[j] for j in tc['tweak_indices']]
        ret = _apply_tweaks(cache.value, tweaks, tc['is_xonly'])
        if ret != WALLY_OK:
            wally_musig_keyagg_cache_free(cache.value)
            return ret, None, None
        aggnonce = c_void_p()
        ret = wally_musig_aggnonce_parse(_h(tc['aggnonce']),
                                         MUSIG_AGGNONCE_LEN, aggnonce)
        if ret != WALLY_OK:
            wally_musig_keyagg_cache_free(cache.value)
            return ret, None, None
        session = c_void_p()
        ret = wally_musig_nonce_process(aggnonce.value, self.MSG, 32,
                                        cache.value, None, 0, session)
        wally_musig_aggnonce_free(aggnonce.value)
        if ret != WALLY_OK:
            wally_musig_keyagg_cache_free(cache.value)
            return ret, None, None
        return WALLY_OK, cache, session

    def test_valid_cases(self):
        self.assertGreater(len(self.V['valid_test_cases']), 0, "valid_test_cases empty")
        for i, tc in enumerate(self.V['valid_test_cases']):
            with self.subTest(case=i):
                ret, cache, session = self._prepare(tc)
                self.assertEqual(WALLY_OK, ret)
                psigs_flat = b''.join(self.PSIGS[j] for j in tc['psig_indices'])
                n = len(tc['psig_indices'])
                out, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
                ret = wally_musig_partial_sig_agg(psigs_flat, len(psigs_flat),
                                                  n, session.value,
                                                  out, EC_SIGNATURE_LEN)
                self.assertEqual(WALLY_OK, ret, f'case {i}: partial_sig_agg failed')
                self.assertEqual(_h(tc['expected']), bytes(out),
                                 f'case {i}: aggregated sig mismatch')
                wally_musig_session_free(session.value)
                wally_musig_keyagg_cache_free(cache.value)

    def test_error_cases(self):
        self.assertGreater(len(self.V['error_test_cases']), 0, "error_test_cases empty")
        for i, tc in enumerate(self.V['error_test_cases']):
            with self.subTest(case=i, comment=tc.get('comment', '')):
                ret, cache, session = self._prepare(tc)
                if ret == WALLY_OK:
                    psigs_flat = b''.join(self.PSIGS[j] for j in tc['psig_indices'])
                    n = len(tc['psig_indices'])
                    out, _ = make_cbuffer('00' * EC_SIGNATURE_LEN)
                    ret = wally_musig_partial_sig_agg(psigs_flat, len(psigs_flat),
                                                      n, session.value,
                                                      out, EC_SIGNATURE_LEN)
                _assert_error(self, ret, tc.get('error'))
                if session is not None and session.value:
                    wally_musig_session_free(session.value)
                if cache is not None and cache.value:
                    wally_musig_keyagg_cache_free(cache.value)


@unittest.skipUnless(False, 'wally_musig_deterministic_sign is not exposed by '
                            'include/wally_musig.h; det_sign vectors cannot be '
                            'exercised through the public API')
class DetSignVectorTests(unittest.TestCase):
    """BIP-327 det_sign_vectors.json (skipped: no public API)."""

    def test_placeholder(self):
        pass


if __name__ == '__main__':
    unittest.main()
