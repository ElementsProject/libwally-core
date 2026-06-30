#!/usr/bin/env python
"""
BIP-379 miniscript test vectors imported from rust-miniscript.

Sources (commit 1834bc0635278b0fcdb6b6b2ebe3a7fef2b8154e):
  - bitcoind-tests/tests/data/random_ms.txt  (valid expressions)
  - src/miniscript/ms_tests.rs               (invalid type combinations)

H placeholders in valid_cases are substituted by _sub_h() before parsing:
  sha256(H) / hash256(H)   -> 32-byte hash hex
  ripemd160(H) / hash160(H) -> 20-byte hash hex
"""
import json
import os
import unittest
from util import *

NETWORK_NONE = 0x00
MS_ONLY = 0x2  # WALLY_MINISCRIPT_ONLY

_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'bip379')

# Hash values matching rust-miniscript test_util.rs:
#   sha256_pre   = [0x12; 32]  -> sha256::Hash::hash(&sha256_pre)
#   ripemd160_pre = [0x78; 32] -> ripemd160::Hash::hash(&ripemd160_pre)
# The sha256 value is also confirmed in libwally's own test_descriptor.py.
_SHA256_H  = '9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2'
_RIPEMD_H  = 'd0721279e70d39fb4aa409b52839a0056454e3b5'


def _load_vectors():
    with open(os.path.join(_DATA_DIR, 'miniscript_vectors.json'), 'r') as f:
        return json.load(f)


def _sub_h(ms):
    """Replace H placeholders with concrete hash hex values."""
    ms = ms.replace('hash256(H)', 'hash256(' + _SHA256_H + ')')
    ms = ms.replace('sha256(H)',  'sha256('  + _SHA256_H + ')')
    ms = ms.replace('hash160(H)', 'hash160(' + _RIPEMD_H + ')')
    ms = ms.replace('ripemd160(H)', 'ripemd160(' + _RIPEMD_H + ')')
    return ms


class Bip379ValidVectorTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cases = _load_vectors()['valid_cases']

    def test_valid_cases(self):
        for i, tc in enumerate(self.cases):
            ms = _sub_h(tc['miniscript'])
            comment = tc.get('comment', '')
            d = c_void_p()
            ret = wally_descriptor_parse(ms, None, NETWORK_NONE, MS_ONLY, d)
            if ret == WALLY_OK:
                wally_descriptor_free(d)
            self.assertEqual(ret, WALLY_OK,
                f'case {i} [{comment}]: parse failed for {ms!r}')


class Bip379InvalidVectorTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cases = _load_vectors()['invalid_cases']

    def test_invalid_cases(self):
        for i, tc in enumerate(self.cases):
            ms = tc['miniscript']
            comment = tc.get('comment', '')
            d = c_void_p()
            ret = wally_descriptor_parse(ms, None, NETWORK_NONE, MS_ONLY, d)
            if ret == WALLY_OK:
                wally_descriptor_free(d)
            self.assertNotEqual(ret, WALLY_OK,
                f'case {i} [{comment}]: expected parse failure for {ms!r}')


if __name__ == '__main__':
    unittest.main()
