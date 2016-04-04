import unittest
import util
from util import utf8
from binascii import hexlify
from ctypes import create_string_buffer

class AddressCase(object):
    def __init__(self, lines):
        # https://github.com/ThePiachu/Bitcoin-Unit-Tests/blob/master/Address
        self.ripemd_network = lines[4]
        self.checksummed = lines[8]
        self.base58 = lines[9]


class Base58Tests(unittest.TestCase):

    def setUp(self):
        if not hasattr(self, 'base58_string_from_bytes'):
            util.bind_all(self, util.bip38_funcs)

            # Test cases from https://github.com/ThePiachu/Bitcoin-Unit-Tests/
            self.cases = []
            cur = []
            with open(util.root_dir + 'src/data/address_vectors.txt', 'r') as f:
                for l in f.readlines():
                    if len(l.strip()):
                        cur.append(l.strip())
                    else:
                        self.cases.append(AddressCase(cur))
                        cur = []

    def encode(self, hex_in, flags):
        buf, buf_len = util.make_cbuffer(hex_in)
        return self.base58_string_from_bytes(buf, buf_len, flags)

    def test_address_vectors(self):

        for c in self.cases:
            # Checksummed should match directly
            base58 = self.encode(c.checksummed, 0)
            self.assertEqual(base58, c.base58)
            # FIXME: Call with flags to checksum and compare


if __name__ == '__main__':
    unittest.main()
