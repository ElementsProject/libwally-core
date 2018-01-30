import unittest
from util import *

SCRIPT_HASH160 = 0x1
SCRIPT_SHA256  = 0x2

class ScriptTests(unittest.TestCase):

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
