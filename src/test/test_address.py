#!/usr/bin/env python3
import unittest
from util import *

VER_MAIN_PUBLIC = 0x0488B21E
VER_TEST_PUBLIC = 0x043587CF

FLAG_KEY_PUBLIC = 0x1

ADDRESS_TYPE_P2PKH       = 0x01
ADDRESS_TYPE_P2SH_P2WPKH = 0x02
ADDRESS_TYPE_P2WPKH      = 0x04

VERSION_P2PKH = 0x00
VERSION_P2SH = 0x05

# Vector from test_bip32.py. We only need an xpub to derive addresses.
vec = {

    'm/0H/1': {
        # xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ
        FLAG_KEY_PUBLIC:  '0488B21E025C1BD648000000012A7857'
                          '631386BA23DACAC34180DD1983734E44'
                          '4FDBF774041578E9B6ADB37C1903501E'
                          '454BF00751F24B1B489AA925215D66AF'
                          '2234E3891C3B21A52BEDB3CD711C6F6E2AF7',

        "address_legacy": '1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj',

        "address_p2sh_segwit": '3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu',

        "address_segwit": 'bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt'
    }

}

class AddressTests(unittest.TestCase):

    SERIALIZED_LEN = 4 + 1 + 4 + 4 + 32 + 33

    def unserialize_key(self, buf, buf_len):
        key_out = ext_key()
        ret = bip32_key_unserialize(buf, buf_len, byref(key_out))
        return ret, key_out

    def get_test_key(self, vec, path):
        buf, buf_len = make_cbuffer(vec[path][FLAG_KEY_PUBLIC])
        ret, key_out = self.unserialize_key(buf, self.SERIALIZED_LEN)
        self.assertEqual(ret, WALLY_OK)

        return key_out

    def test_address_vectors(self):
        self.do_test_vector(vec, 'm/0H/1')

    def do_test_vector(self, vec, path):
        key = self.get_test_key(vec, path)

        # Address type flag is mandatory
        ret, out = wally_bip32_key_to_address(key, 0, VERSION_P2PKH)
        self.assertEqual(ret, WALLY_EINVAL)

        # Obtain legacy address (P2PKH)
        ret, out = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2PKH, VERSION_P2PKH)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(out, vec[path]['address_legacy'])

        # Obtain wrapped SegWit address (P2SH_P2WPKH)
        ret, out = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2SH_P2WPKH, VERSION_P2SH)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(out, vec[path]['address_p2sh_segwit'])

        # wally_bip32_key_to_address does not support bech32 native SegWit (P2WPKH)
        ret, out = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2WPKH, VERSION_P2SH)
        self.assertEqual(ret, WALLY_EINVAL)

        # Obtain native SegWit address (P2WPKH)
        ret, out = wally_bip32_key_to_addr_segwit(key, utf8('bc'), 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(out, vec[path]['address_segwit'])

if __name__ == '__main__':
    unittest.main()
