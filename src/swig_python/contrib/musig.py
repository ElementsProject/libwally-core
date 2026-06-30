"""Tests for the MuSig2 SWIG wrappers.

Regression test for the opaque output-parameter typemaps: every MuSig2
function must return its opaque result (keyagg cache, nonces, session,
partial sig) as a capsule, and nonce generation must return a
(secnonce, pubnonce) tuple.
"""
import os
import unittest

import wallycore as wally

if not hasattr(wally, 'musig_pubkey_agg'):
    # Built against standard libsecp256k1 without the musig module
    raise SystemExit(0)


class MuSigTests(unittest.TestCase):

    def test_musig_2of2(self):
        """Aggregate, exchange nonces, sign and combine a 2-of-2 signature"""
        seckeys = [os.urandom(32), os.urandom(32)]
        pubkeys = [wally.ec_public_key_from_private_key(k) for k in seckeys]
        msg = os.urandom(32)

        agg_pk = bytearray(32)
        cache = wally.musig_pubkey_agg(b''.join(bytes(p) for p in pubkeys), agg_pk)
        self.assertIsNotNone(cache)

        # Nonce generation returns a (secnonce, pubnonce) tuple
        secnonces, pubnonces = [], []
        for seckey, pubkey in zip(seckeys, pubkeys):
            secnonce, pubnonce = wally.musig_nonce_gen(os.urandom(32), seckey,
                                                       pubkey, cache, msg, None)
            secnonces.append(secnonce)
            pubnonces.append(pubnonce)

        # Pubnonces serialize/parse round-trip
        serialized = [wally.musig_pubnonce_serialize(pn) for pn in pubnonces]
        for ser in serialized:
            self.assertIsNotNone(wally.musig_pubnonce_parse(ser))

        aggnonce = wally.musig_nonce_agg(b''.join(bytes(s) for s in serialized),
                                         len(serialized))
        session = wally.musig_nonce_process(aggnonce, msg, cache, None)

        partial_sigs = []
        for seckey, secnonce, pubnonce, pubkey in zip(seckeys, secnonces,
                                                      pubnonces, pubkeys):
            psig = wally.musig_partial_sign(secnonce, seckey, cache, session)
            wally.musig_partial_sig_verify(psig, pubnonce, pubkey, cache, session)
            partial_sigs.append(wally.musig_partial_sig_serialize(psig))

        sig = wally.musig_partial_sig_agg(b''.join(bytes(s) for s in partial_sigs),
                                          len(partial_sigs), session)
        self.assertEqual(len(sig), 64)


if __name__ == '__main__':
    unittest.main()
