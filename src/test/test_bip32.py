import unittest
import util
from binascii import hexlify, unhexlify
from ctypes import byref

def h(s):
    return hexlify(s)

vec_1 = {
    'seed':     '000102030405060708090a0b0c0d0e0f',
    'm': {
        'pub':  '0488B21E000000000000000000873DFF'
                '81C02F525623FD1FE5167EAC3A55A049'
                'DE3D314BB42EE227FFED37D5080339A3'
                '6013301597DAEF41FBE593A02CC513D0'
                'B55527EC2DF1050E2E8FF49C85C2AB473B21',

        'priv': '0488ADE4000000000000000000873DFF'
                '81C02F525623FD1FE5167EAC3A55A049'
                'DE3D314BB42EE227FFED37D50800E8F3'
                '2E723DECF4051AEFAC8E2C93C9C5B214'
                '313817CDB01A1494B917C8436B35E77E9D71'
    },
    'm/0h': {
        'priv': '0488ADE4013442193E8000000047FDAC'
                'BD0F1097043B78C63C20C34EF4ED9A11'
                '1D980047AD16282C7AE623614100EDB2'
                'E14F9EE77D26DD93B4ECEDE8D16ED408'
                'CE149B6CD80B0715A2D911A0AFEA0A794DEC'
    },
}

class BIP32Tests(unittest.TestCase):

    SERIALISED_LEN = 4 + 1 + 4 + 4 + 32 + 33
    FULL_SERIALISED_LEN = 4 + 1 + 4 + 4 + 32 + 33 + 33 + 20 + 20

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

    def compare_keys(self, key, expected, typ):
        self.assertEqual(h(expected.chain_code), h(key.chain_code))
        expected_cmp = getattr(expected, typ + '_key')
        key_cmp = getattr(key, typ + '_key')
        self.assertEqual(h(expected_cmp), h(key_cmp))
        self.assertEqual(expected.depth, key.depth)
        self.assertEqual(expected.child_num, key.child_num)


    def test_serialisation(self):

        # Try short, correct, long lengths. Trimming 8 chars is the correct
        # length because the vector value contains 4 check bytes at the end.
        for trim, expected in [(0, -1), (8, 0), (16, -1)]:
            buf, buf_len = util.make_cbuffer(vec_1['m']['priv'][0:-trim])
            ret, _ = self.unserialise_key(buf, buf_len)
            self.assertEqual(ret, expected)


    def test_extended_serialisation(self):

        ext_buf = vec_1['m']['priv'][0:-8]
        ext_buf += '02' * 33 # Fake public key

        # ext_buf master key has a fingerprint of 0's, check that we
        # pass/fail unserialising if it matches/doesn't
        for fingerprint, expected in [('00', 0), ('11', -1)]:
            buf = ext_buf + fingerprint * 4 # fake hash160(parent)
            buf += '00' * 16
            buf += '00' * 20 # fake hash160(self)
            buf, buf_len = util.make_cbuffer(buf)
            self.assertEqual(buf_len, self.FULL_SERIALISED_LEN)
            ret, _ = self.unserialise_key(buf, buf_len)
            self.assertEqual(ret, expected)


    def test_bip32_vectors(self):

        # BIP32 Test vector 1
        seed, seed_len = util.make_cbuffer(vec_1['seed'])
        master = util.ext_key()
        ret = self.bip32_key_from_bytes(seed, seed_len, byref(master))
        self.assertEqual(ret, 0)

        # Chain m:
        for typ in ['pub', 'priv']:
            expected = self.get_test_key(vec_1, 'm', typ)
            self.compare_keys(master, expected, typ)

        # Chain m/0h:
        m_0h = self.get_test_key(vec_1, 'm/0h', 'priv')
        m_0h_priv = self.derive_key(master, 0x80000000)
        self.compare_keys(m_0h, m_0h_priv, 'priv')


if __name__ == '__main__':
    unittest.main()
