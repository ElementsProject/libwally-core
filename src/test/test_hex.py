import unittest
from util import *

class HexTests(unittest.TestCase):

    def test_hex_to_bytes(self):
        LEN = 4
        buf, buf_len = make_cbuffer('00' * LEN)

        for i in range(256):
            for s in ("%02X" % i, "%02x" % i): # Upper/Lower
                ret, written = wally_hex_to_bytes(s * LEN, buf, buf_len)
                self.assertEqual((ret, written), (WALLY_OK, LEN))

        # Bad inputs
        for (s, b, l) in [(None,  buf,  buf_len),
                          ('00',  None, buf_len),
                          ('000', buf,  buf_len),
                          ('00',  buf,  0)]:
            ret, written = wally_hex_to_bytes(s, b, l)
            self.assertEqual((ret, written), (WALLY_EINVAL, 0))

        for l in (1,    # Too small, returns the required length
                  LEN): # Too large, returns length written
            ret, written = wally_hex_to_bytes('0000', buf, l)
            self.assertEqual((ret, written), (WALLY_OK, 2))


if __name__ == '__main__':
    unittest.main()
