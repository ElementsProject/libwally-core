import unittest
from util import *

CA_PREFIX_LIQUID = 0x0c
EC_PUBLIC_KEY_LEN = 33

class CATests(unittest.TestCase):

    def test_confidential_addr(self):
        """Tests for confidential addresses"""

        # The (Liquid) address that is to be blinded
        addr = 'Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6'
        # The blinding pubkey
        pubkey_hex = '02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623'
        # The resulting confidential address
        addr_c = utf8('VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK')

        # Test we can extract the original address
        ret, result = wally_confidential_addr_to_addr(addr_c, CA_PREFIX_LIQUID)
        self.assertEqual((ret, result), (WALLY_OK, addr))

        # Test we can extract the blinding pubkey
        out, out_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        ret = wally_confidential_addr_to_ec_public_key(addr_c, CA_PREFIX_LIQUID, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        _, out_hex = wally_hex_from_bytes(out, out_len)
        self.assertEqual(utf8(pubkey_hex), utf8(out_hex))

        # Test we can re-generate the confidential address from its inputs
        ret, new_addr_c = wally_confidential_addr_from_addr(utf8(addr), CA_PREFIX_LIQUID, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(utf8(new_addr_c), addr_c)


if __name__ == '__main__':
    unittest.main()
