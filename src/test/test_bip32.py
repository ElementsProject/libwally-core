import unittest
import util
from binascii import hexlify, unhexlify
from ctypes import byref

class BIP32Tests(unittest.TestCase):

    def setUp(self):
        if not hasattr(self, 'bip32_key_from_bytes'):
            util.bind_all(self, util.bip32_funcs)

    def test_bip32_vectors(self):

        # BIP32 Test vector 1, Chain m:
        seed, seed_len = util.make_cbuffer('000102030405060708090a0b0c0d0e0f')
        key_out = util.ext_key()
        ret = self.bip32_key_from_bytes(seed, seed_len, byref(key_out))
        self.assertEqual(ret, 0)
        ext_pub = '0488ADE4000000000000000000873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D50800E8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35E77E9D71'
        ext_pub = ext_pub.lower()
        encoded = hexlify(key_out.chain_code) + hexlify(key_out.key)
        self.assertTrue(encoded in ext_pub)


if __name__ == '__main__':
    unittest.main()
