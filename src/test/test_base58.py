import unittest
from util import *
from binascii import hexlify

class AddressCase(object):
    def __init__(self, lines):
        # https://github.com/ThePiachu/Bitcoin-Unit-Tests/blob/master/Address
        self.ripemd_network = lines[4]
        self.checksummed = lines[8]
        self.base58 = lines[9]

class Base58Tests(unittest.TestCase):

    CHECKSUM = 1
    RESERVED = 2

    def setUp(self):
        if not hasattr(self, 'cases'):
            # Test cases from https://github.com/ThePiachu/Bitcoin-Unit-Tests/
            self.cases = []
            cur = []
            with open(root_dir + 'src/data/address_vectors.txt', 'r') as f:
                for l in f.readlines():
                    if len(l.strip()):
                        cur.append(l.strip())
                    else:
                        self.cases.append(AddressCase(cur))
                        cur = []

    def encode(self, hex_in, flags):
        if (flags == self.RESERVED):
            hex_in += '00000000' # Reserve checksum space
        buf, buf_len = make_cbuffer(hex_in)
        return base58_from_bytes(buf, buf_len, flags)

    def decode(self, str_in, flags):
        buf, buf_len = make_cbuffer('00' * 1024)
        buf_len = base58_to_bytes(utf8(str_in), flags, buf, buf_len)
        self.assertNotEqual(buf_len, 0)
        # Check that just computing the size returns us the actual size
        #print 'processing "%s"' % str_in
        bin_len = base58_get_length(str_in)
        if flags == self.CHECKSUM:
            bin_len -= 4 # Take off the 4 bytes of stripped checksum
        self.assertEqual(bin_len, buf_len)
        return hexlify(buf)[0:buf_len * 2].upper()


    def test_address_vectors(self):
        """Tests for encoding and decoding with and without checksums"""

        for c in self.cases:
            # Checksummed should match directly in base 58
            base58 = self.encode(c.checksummed, 0)
            self.assertEqual(base58, c.base58)
            # Decode it and make sure it matches checksummed again
            decoded = self.decode(c.base58, 0)
            self.assertEqual(decoded, utf8(c.checksummed))

            # Compute the checksum in the call, appended to a temp
            # buffer or in-place, depending on the flags
            for flags in [self.CHECKSUM, self.RESERVED]:
                base58 = self.encode(c.ripemd_network, flags)
                self.assertEqual(base58, c.base58)

                # Decode without checksum validation/stripping, should match
                # checksummed value
                decoded = self.decode(c.base58, 0)
                self.assertEqual(decoded, utf8(c.checksummed))

                # Decode with checksum validation/stripping and compare
                # to original ripemd + network
                decoded = self.decode(c.base58, self.CHECKSUM)
                self.assertEqual(decoded, utf8(c.ripemd_network))


    def test_to_bytes(self):
        buf, buf_len = make_cbuffer('00' * 1024)

        # Bad input base58 strings
        for bad in [ '',      # Empty string can't be represented
                     '0',     # Forbidden ASCII character
                     '\x80',  # High bit set
                   ]:
            ret = base58_to_bytes(utf8(bad), 0, buf, buf_len)
            self.assertEqual(ret, 0)

        # Bad checksummed base58 strings
        for bad in [ # libbase58: decode-b58c-fail
                    '19DXstMaV43WpYg4ceREiiTv2UntmoiA9a',
                    # libbase58: decode-b58c-toolong
                    '1119DXstMaV43WpYg4ceREiiTv2UntmoiA9a',
                    # libbase58: decode-b58c-tooshort
                    '111111111111111111114oLvT2'
                ]:
            ret = base58_to_bytes(utf8(bad), self.CHECKSUM, buf, buf_len)
            self.assertEqual(ret, 0)

        # Test output buffer too small
        valid = '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM' # decodes to 25 bytes
        self.assertEqual(base58_get_length(valid), 25)
        ret = base58_to_bytes(utf8(valid), 0, buf, 24)
        self.assertEqual(ret, 0)


    def test_from_bytes(self):

        # Leading zeros become ones
        self.assertEqual(self.encode('00', 0), '1')

        # Invalid flags
        self.assertEqual(self.encode('00', 0x7), None)

        buf, buf_len = make_cbuffer('00' * 8)

        # O length buffer, no checksum -> NULL
        self.assertEqual(base58_from_bytes(buf, 0, 0), None)

        # O length buffer, append checksum -> NULL
        self.assertEqual(base58_from_bytes(buf, 0, self.CHECKSUM), None)

        # 4 length buffer, checksum in place -> NULL
        self.assertEqual(base58_from_bytes(buf, 4, self.RESERVED), None)


if __name__ == '__main__':
    unittest.main()
