import unittest
import util
from binascii import hexlify, unhexlify
from ctypes import byref

vector_1 = {
    'seed': '000102030405060708090a0b0c0d0e0f',
    'm': {
        'ext_pub': '0488ADE4000000000000000000873DFF'
                   '81C02F525623FD1FE5167EAC3A55A049'
                   'DE3D314BB42EE227FFED37D50800E8F3'
                   '2E723DECF4051AEFAC8E2C93C9C5B214'
                   '313817CDB01A1494B917C8436B35E77E'
                   '9D71',
    }
}

class BIP32Tests(unittest.TestCase):

    SERIALISED_LEN = 4 + 1 + 4 + 4 + 32 + 33;
    FULL_SERIALISED_LEN = 4 + 1 + 4 + 4 + 32 + 33 + 20 + 20;

    def setUp(self):
        if not hasattr(self, 'bip32_key_from_bytes'):
            util.bind_all(self, util.bip32_funcs)

    def unserialise(self, buf, buf_len):
        key_out = util.ext_key()
        ret = self.bip32_key_unserialise(buf, buf_len, byref(key_out))
        return ret, key_out

    def test_serialisation(self):
        buf, buf_len = util.make_cbuffer(vector_1['m']['ext_pub'])
        # Bad length, since buf_len includes the check bytes
        ret, _ = self.unserialise(buf, buf_len)
        self.assertEqual(ret, -1)
        # Should unserialise correctly with correct length given
        ret, _ = self.unserialise(buf, self.SERIALISED_LEN)
        self.assertEqual(ret, 0)


    def test_bip32_vectors(self):

        # BIP32 Test vector 1, Chain m:
        seed, seed_len = util.make_cbuffer(vector_1['seed'])
        key_out = util.ext_key()
        ret = self.bip32_key_from_bytes(seed, seed_len, byref(key_out))
        self.assertEqual(ret, 0)
        ext_pub = vector_1['m']['ext_pub'].lower()
        encoded = hexlify(key_out.chain_code) + hexlify(key_out.key)
        self.assertTrue(encoded in ext_pub)


if __name__ == '__main__':
    unittest.main()
