import unittest
import util
from binascii import hexlify, unhexlify
from ctypes import byref

def h(s):
    return hexlify(s)

vec_1 = {
    'seed':         '000102030405060708090a0b0c0d0e0f',
    'm': {
        'ext_priv': '0488ADE4000000000000000000873DFF'
                    '81C02F525623FD1FE5167EAC3A55A049'
                    'DE3D314BB42EE227FFED37D50800E8F3'
                    '2E723DECF4051AEFAC8E2C93C9C5B214'
                    '313817CDB01A1494B917C8436B35E77E'
                    '9D71'
    },
    'm/0h': {
        'ext_priv': '0488ADE4013442193E8000000047FDAC'
                    'BD0F1097043B78C63C20C34EF4ED9A11'
                    '1D980047AD16282C7AE623614100EDB2'
                    'E14F9EE77D26DD93B4ECEDE8D16ED408'
                    'CE149B6CD80B0715A2D911A0AFEA0A79'
                    '4DEC'
    },
}

class BIP32Tests(unittest.TestCase):

    SERIALISED_LEN = 4 + 1 + 4 + 4 + 32 + 33;
    FULL_SERIALISED_LEN = 4 + 1 + 4 + 4 + 32 + 33 + 20 + 20;

    def setUp(self):
        if not hasattr(self, 'bip32_key_from_bytes'):
            util.bind_all(self, util.bip32_funcs)

    def unserialise_key(self, buf, buf_len):
        key_out = util.ext_key()
        ret = self.bip32_key_unserialise(buf, buf_len, byref(key_out))
        return ret, key_out

    def get_test_key(self, vec, path, typ):
        buf, buf_len = util.make_cbuffer(vec[path][typ])
        ret, key_out = self.unserialise_key(buf, self.SERIALISED_LEN)
        self.assertEqual(ret, 0)
        return key_out

    def derive_key(self, parent, child_num):
        key_out = util.ext_key()
        ret = self.bip32_key_from_parent(byref(parent), child_num, byref(key_out))
        self.assertEqual(ret, 0)
        return key_out

    def compare_keys(self, key, expected):
        self.assertEqual(h(expected.chain_code), h(key.chain_code))
        self.assertEqual(h(expected.key), h(key.key))
        self.assertEqual(expected.depth, key.depth)
        self.assertEqual(expected.child_num, key.child_num)


    def test_serialisation(self):
        buf, buf_len = util.make_cbuffer(vec_1['m']['ext_priv'])
        # Bad length, since buf_len includes the check bytes
        ret, _ = self.unserialise_key(buf, buf_len)
        self.assertEqual(ret, -1)


    def test_bip32_vectors(self):

        # BIP32 Test vector 1
        seed, seed_len = util.make_cbuffer(vec_1['seed'])
        master = util.ext_key()
        ret = self.bip32_key_from_bytes(seed, seed_len, byref(master))
        self.assertEqual(ret, 0)

        # Chain m:
        key = self.get_test_key(vec_1, 'm', 'ext_priv')
        self.compare_keys(master, self.get_test_key(vec_1, 'm', 'ext_priv'))

        # Chain m/0h:
        m_0h = self.derive_key(master, 0x80000000)
        self.compare_keys(m_0h, self.get_test_key(vec_1, 'm/0h', 'ext_priv'))


if __name__ == '__main__':
    unittest.main()
