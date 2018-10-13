import unittest
from util import *

valid_cases = {
    'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4':
        ["bc", 0, '0014751e76e8199196d454941c45d1b3a323f1433bd6'],
    'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7':
        ["tb", 0, '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'],
    'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx':
        ["bc", 1, '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'],
    'BC1SW50QA3JX3S':
        ["bc", 16, '6002751e'],
    'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj':
        ["bc", 2, '5210751e76e8199196d454941c45d1b3a323'],
    'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy':
        ["tb", 0, '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433']
}

invalid_cases = [
    ["tb", 'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty'], # Invalid human-readable part
    ["bc", 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5'], # Invalid checksum
    ["bc", 'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2'], # Invalid witness version
    ["bc", 'bc1rw5uspcuh'], # Invalid program length
    ["bc", 'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90'], # Invalid program length
    ["bc", 'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P'], # Invalid program length for witness version 0 (per BIP141)
    ["tb", 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7'], # Mixed case
    ["bc", 'bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du'], # zero padding of more than 4 bits
    ["tb", 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv'], # Non-zero padding in 8-to-5 conversion
    ["bc", 'bc1gmk9yu'], # Empty data section
]

class Bech32Tests(unittest.TestCase):

    def decode(self, addr, family):
        out, out_len = make_cbuffer('00' * (32 + 2))
        ret, written = wally_addr_segwit_to_bytes(utf8(addr), utf8(family), 0, out, out_len)
        if ret != WALLY_OK:
            return ret, None
        return ret, h(out[:written])

    def test_segwit_address(self):
        """Tests for encoding and decoding segwit addresses"""
        # Valid cases
        for addr, data in valid_cases.items():
            # Decode the address
            family, script_ver, script_hex = data[0], data[1], data[2]

            ret, result_script_hex = self.decode(addr, family)
            if script_ver != 0:
                self.assertEqual(ret, WALLY_EINVAL)
            else:
                self.assertEqual(ret, WALLY_OK)
                self.assertEqual(result_script_hex, utf8(script_hex))

            # Encode the script and make sure the address matches
            script_buf, script_len = make_cbuffer(script_hex)
            ret, retstr = wally_addr_segwit_from_bytes(script_buf, script_len, utf8(family), 0)
            if script_ver != 0:
                self.assertEqual(ret, WALLY_EINVAL)
            else:
                self.assertEqual(ret, WALLY_OK)
                self.assertEqual(retstr.lower(), addr.lower())

        # Invalid cases
        for family, addr in invalid_cases:
            ret, result_script_hex = self.decode(addr, family)
            self.assertEqual(ret, WALLY_EINVAL)

        out, out_len = make_cbuffer('00' * (32 + 2))
        bad = 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefg'
        ret, written = wally_addr_segwit_to_bytes(utf8(bad), utf8('tb'), 0, out, out_len)
        self.assertEqual((ret, written), (WALLY_EINVAL, 0))


if __name__ == '__main__':
    unittest.main()
