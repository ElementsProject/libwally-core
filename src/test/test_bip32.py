import unittest
import util
from binascii import hexlify, unhexlify
from ctypes import byref

class BIP32Tests(unittest.TestCase):

    def setUp(self):
        if not hasattr(self, 'bip32_key_from_bytes'):
            util.bind_all(self, util.bip32_funcs)

    def test_from_seed(self):
        key_out = util.ext_key()
        seed, seed_len = util.make_cbuffer('000102030405060708090a0b0c0d0e0f')
        ret = self.bip32_key_from_bytes(seed, seed_len, byref(key_out))
        self.assertEqual(ret, 0)
        #print hexlify(key_out.key)


if __name__ == '__main__':
    unittest.main()
