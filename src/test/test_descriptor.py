#!/usr/bin/env python
import unittest
from util import *

NETWORK_BTC_MAIN = 0x01
NETWORK_BTC_TEST = 0x02
NETWORK_BTC_REG = 0xff
NETWORK_LIQUID = 0x03
NETWORK_LIQUID_REG = 0x04

SCRIPTPUBKEY_P2WPKH_LEN = 22


def make_cbuffer_from_str(text):
    if text is None:
        return None, 0
    hex_len = len(text)
    return unhexlify(text.encode('utf-8').hex() + '00'), hex_len + 1


class DescriptorTests(unittest.TestCase):

    def test_parse_miniscript(self):
        script, script_len = make_cbuffer('00' * 256 * 2)
        key1, key1_len = make_cbuffer_from_str('key_local')
        key2, key2_len = make_cbuffer_from_str('key_remote')
        key3, key3_len = make_cbuffer_from_str('key_revocation')
        key4, key4_len = make_cbuffer_from_str('H')
        val1, val1_len = make_cbuffer_from_str('038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048')
        val2, val2_len = make_cbuffer_from_str('03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7')
        val3, val3_len = make_cbuffer_from_str('03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284')
        val4, val4_len = make_cbuffer_from_str('d0721279e70d39fb4aa409b52839a0056454e3b5') # HASH160(key_local)
        out, out_len = make_cbuffer('00'*128)
        s_arr_num = 4

        m = pointer(wally_map())
        ret = wally_map_init_alloc(s_arr_num, None, m)
        self.assertEqual(ret, WALLY_OK)
        self.assertNotEqual(m, None)

        # Add and find each key
        items = [(key1, key1_len, val1, val1_len),
                 (key2, key2_len, val2, val2_len),
                 (key3, key3_len, val3, val3_len),
                 (key4, key4_len, val4, val4_len)]
        for item in items:
            k, l, v, vl = item
            self.assertEqual(wally_map_add(m, k, l, v, vl), WALLY_OK)

        for miniscript, child_num, expect_script in [
            ('t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))', 0, '532102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975562102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1353ae6482012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2886703010040b2696851'),
            ('andor(c:pk_k(key_remote),or_i(and_v(vc:pk_h(key_local),hash160(H)),older(1008)),c:pk_k(key_revocation))', 0, '2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac676376a914d0721279e70d39fb4aa409b52839a0056454e3b588ad82012088a914d0721279e70d39fb4aa409b52839a0056454e3b5876702f003b26868'),
        ]:
            ret, written = wally_descriptor_parse_miniscript(miniscript, m, child_num, 0, script, script_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, len(expect_script) / 2)
            self.assertEqual(script[:written], unhexlify(expect_script))

        self.assertEqual(wally_map_free(m), WALLY_OK)

    def test_descriptor_to_scriptpubkey(self):
        script, script_len = make_cbuffer('00' * 64 * 2)

        for descriptor, child_num, network, expect_script in [
            ('wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)', 0, NETWORK_BTC_MAIN, '00147dd65592d0ab2fe0d0257d571abf032cd9db93dc'),
        ]:
            ret, written = wally_descriptor_to_scriptpubkey(descriptor, None, child_num, network, 0, 0, 0, script, script_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, SCRIPTPUBKEY_P2WPKH_LEN)
            self.assertEqual(script[:written], unhexlify(expect_script))

    def test_descriptor_to_address(self):
        # Valid args
        for descriptor, child_num, network, expect_addr in [
            ('wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)', 0, NETWORK_BTC_TEST, 'tb1q0ht9tyks4vh7p5p904t340cr9nvahy7um9zdem'),
        ]:
            ret, addr = wally_descriptor_to_address(descriptor, None, child_num, network, 0)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(addr, expect_addr)

    def test_descriptor_to_addresses(self):
        # Valid args
        for descriptor, start_num, end_num, network, expect_addr_list in [
            ('wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))', 0, 10, NETWORK_BTC_MAIN,
              [
                'bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c',
                'bc1qp6rfclasvmwys7w7j4svgc2mrujq9m73s5shpw4e799hwkdcqlcsj464fw',
                'bc1qsflxzyj2f2evshspl9n5n745swcvs5k7p5t8qdww5unxpjwdvw5qx53ms4',
                'bc1qmhmj2mswyvyj4az32mzujccvd4dgr8s0lfzaum4n4uazeqc7xxvsr7e28n',
                'bc1qjeu2wa5jwvs90tv9t9xz99njnv3we3ux04fn7glw3vqsk4ewuaaq9kdc9t',
                'bc1qc6626sa08a4ktk3nqjrr65qytt9k273u24mfy2ld004g76jzxmdqjgpm2c',
                'bc1qwlq7jjqcklrcqypvdndjx0fyrudgrymm67gcx3e09sekgs28u47smq0lx5',
                'bc1qx8qq9k2mtqarugg3ctcsm2um22ahmq5uttrecy5ufku0ukfgpwrs7epn38',
                'bc1qgrs4qzvw4aat2k38fvmrqf3ucaanqz2wxe5yy5cewwmqn06evxgq02wv43',
                'bc1qnkpr4y7fp7jwad3gfngczwsv9069rq96cl7lpq4h9j3eng9mwjzsssr520',
                'bc1q7yzadku3kxs855wgjxnyr2nk3e44ed75p07lzhnj53ynpczg78nq0leae5',
              ]),
        ]:
            addr_list_p = pointer(wally_map())
            ret = wally_descriptor_to_addresses_alloc(descriptor, None, start_num, end_num, network, 0, addr_list_p)
            self.assertEqual(ret, WALLY_OK)
            ret, num_items = wally_map_get_num_items(addr_list_p)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(len(expect_addr_list), num_items)
            for i in range(len(expect_addr_list)):
                ret, child_num = wally_map_get_item_integer_key(addr_list_p, i)
                self.assertEqual(ret, WALLY_OK)
                self.assertEqual(i, child_num)
                out, out_len = make_cbuffer('00'*128)
                ret, output_len = wally_map_get_item(addr_list_p, child_num, out, out_len)
                self.assertEqual(ret, WALLY_OK)
                self.assertEqual(expect_addr_list[i].encode('utf-8'), out[:output_len-1])
            self.assertEqual(wally_map_free(addr_list_p), WALLY_OK)

    def test_create_descriptor_checksum(self):
        # Valid args
        for descriptor, expect_checksum in [
            ('wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))', 't2zpj2eu'),
        ]:
            ret, checksum = wally_descriptor_create_checksum(descriptor, None, 0)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(checksum, expect_checksum)


if __name__ == '__main__':
    unittest.main()
