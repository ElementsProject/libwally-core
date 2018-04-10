import unittest
from util import *

SCRIPT_TYPE_P2PKH = 0x2

SCRIPT_HASH160 = 0x1
SCRIPT_SHA256  = 0x2

SCRIPTPUBKEY_P2PKH_LEN = 25
HASH160_LEN = 20

PK, PK_LEN = make_cbuffer('11' * 33) # Fake compressed pubkey
PKU, PKU_LEN = make_cbuffer('11' * 65) # Fake uncompressed pubkey

class ScriptTests(unittest.TestCase):

    def test_scripttpubkey_get_type(self):
        """Tests for script analysis"""
        # Test invalid args, we test results with the functions that make scripts
        in_, in_len = make_cbuffer('00' * 16)
        for b, b_len in [(None, in_len), (in_, 0)]:
            ret, written = wally_scriptpubkey_get_type(b, b_len)
            self.assertEqual(ret, WALLY_EINVAL)
            self.assertEqual(written, 0)

    def test_scriptpubkey_p2pkh_from_bytes(self):
        """Tests for creating p2pkh scriptPubKeys"""
        # Invalid args
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2PKH_LEN)
        invalid_args = [
            (None, PK_LEN, SCRIPT_HASH160, out, out_len), # Null bytes
            (PK, 0, SCRIPT_HASH160, out, out_len), # Empty bytes
            (PK, PK_LEN, SCRIPT_SHA256, out, out_len), # Unsupported flags
            (PK, PK_LEN, SCRIPT_HASH160, None, out_len), # Null output
            (PK, PK_LEN, SCRIPT_HASH160, out, SCRIPTPUBKEY_P2PKH_LEN-1), # Short output len
            (PK, PK_LEN, 0, out, out_len), # Pubkey w/o SCRIPT_HASH160
            (PKU, PKU_LEN, 0, out, out_len), # Uncompressed pubkey w/o SCRIPT_HASH160
        ]
        for args in invalid_args:
            ret = wally_scriptpubkey_p2pkh_from_bytes(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))

        # Valid cases
        valid_args = [
            (PK, PK_LEN, SCRIPT_HASH160, out, out_len),
            (PKU, PKU_LEN, SCRIPT_HASH160, out, out_len),
            (PKU, HASH160_LEN, 0, out, out_len),
        ]
        for args in valid_args:
            ret = wally_scriptpubkey_p2pkh_from_bytes(*args)
            self.assertEqual(ret, (WALLY_OK, SCRIPTPUBKEY_P2PKH_LEN))
            ret = wally_scriptpubkey_get_type(out, SCRIPTPUBKEY_P2PKH_LEN)
            self.assertEqual(ret, (WALLY_OK, SCRIPT_TYPE_P2PKH))

    def test_script_push_from_bytes(self):
        """Tests for encoding script pushes"""
        out, out_len = make_cbuffer('00' * 165536)
        for data, prefix in {'00' * 75: '4b',
                             '00' * 76: '4c4c',
                             '00' * 255: '4cff',
                             '00' * 256: '4d0001'}.items():

            in_, in_len = make_cbuffer(data)
            ret, written = wally_script_push_from_bytes(in_, in_len, 0, out, out_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, len(data)/2 + len(prefix)/2)
            self.assertEqual(h(out[:written]), utf8(prefix + data))

            # Too short out_len returns the required number of bytes
            ret, written = wally_script_push_from_bytes(in_, in_len, 0, out, 20)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, len(data)/2 + len(prefix)/2)

    def test_wally_witness_program_from_bytes(self):
        valid_cases = [('00' * 20, 0),
                       ('00' * 32, 0),
                       ('00' * 50, SCRIPT_HASH160),
                       ('00' * 50, SCRIPT_SHA256)]

        out, out_len = make_cbuffer('00' * 100)
        for data, flags in valid_cases:
            in_, in_len = make_cbuffer(data)
            ret, written = wally_witness_program_from_bytes(in_, in_len, flags, out, out_len)
            self.assertEqual(ret, WALLY_OK)

        invalid_cases = [('00' * 50, 0), # Invalid unhashed length
                ]
        for data, flags in invalid_cases:
            in_, in_len = make_cbuffer(data)
            ret, written = wally_witness_program_from_bytes(in_, in_len, flags, out, out_len)
            self.assertEqual(ret, WALLY_EINVAL)


if __name__ == '__main__':
    unittest.main()
