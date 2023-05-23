#!/usr/bin/env python
import unittest
from util import *


NETWORK_NONE       = 0x00
NETWORK_BTC_MAIN   = 0x01
NETWORK_BTC_TEST   = 0x02
NETWORK_BTC_REG    = 0xff
NETWORK_LIQUID     = 0x03
NETWORK_LIQUID_REG = 0x04

MS_TAP = 0x1  # WALLY_MINISCRIPT_TAPSCRIPT
MS_ONLY = 0x2 # WALLY_MINISCRIPT_ONLY

MS_IS_RANGED = 0x1
MS_IS_MULTIPATH = 0x2
MS_IS_PRIVATE = 0x4
MS_IS_UNCOMPRESSED = 0x08
MS_IS_RAW = 0x010
MS_IS_DESCRIPTOR = 0x20

NO_CHECKSUM = 0x1 # WALLY_MS_CANONICAL_NO_CHECKSUM

def wally_map_from_dict(d):
    m = pointer(wally_map())
    assert(wally_map_init_alloc(len(d.keys()), None, m) == WALLY_OK)
    for k,v in d.items():
        assert(wally_map_add(m, k, len(k), v, len(v)) == WALLY_OK)
    return m


class DescriptorTests(unittest.TestCase):

    def test_parse_and_to_script(self):
        """Test parsing and script generation"""
        keys = wally_map_from_dict({
            utf8('key_local'): utf8('038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048'),
            utf8('key_remote'): utf8('03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7'),
            utf8('key_revocation'): utf8('03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284'),
            utf8('H'): utf8('d0721279e70d39fb4aa409b52839a0056454e3b5'), # HASH160(key_local)
        })
        script, script_len = make_cbuffer('00' * 256 * 2)

        # Valid args
        args = [
            ('t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))', 0,
             '532102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975562102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1353ae6482012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2886703010040b2696851'),
            ('andor(c:pk_k(key_remote),or_i(and_v(vc:pk_h(key_local),hash160(H)),older(1008)),c:pk_k(key_revocation))', 0,
             '2103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ac642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac676376a914d0721279e70d39fb4aa409b52839a0056454e3b588ad82012088a914d0721279e70d39fb4aa409b52839a0056454e3b5876702f003b26868'),
        ]
        for miniscript, child_num, expected in args:
            d = c_void_p()
            ret = wally_descriptor_parse(miniscript, keys, NETWORK_NONE, MS_ONLY, d)
            self.assertEqual(ret, WALLY_OK)
            ret, written = wally_descriptor_to_script(d, 0, 0, 0, 0, child_num,
                                                      0, script, script_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, len(expected) / 2)
            self.assertEqual(script[:written], make_cbuffer(expected)[0])
            wally_descriptor_free(d)
        wally_map_free(keys)

        # Invalid args
        M, U = NETWORK_BTC_MAIN, 0x33 # Unknown network
        H = 0x80000000 # Hardened child
        bad_args = [
            (None,       M, 0, 0, 0, 0, 0, MS_ONLY, script, script_len), # NULL miniscript
            ('',         M, 0, 0, 0, 0, 0, MS_ONLY, script, script_len), # Empty miniscript
            (args[0][0], U, 0, 0, 0, 0, 0, MS_ONLY, script, script_len), # Unknown network
            (args[0][0], M, 4, 0, 0, 0, 0, MS_ONLY, script, script_len), # Invalid depth
            (args[0][0], M, 0, 4, 0, 0, 0, MS_ONLY, script, script_len), # Invalid idx
            (args[0][0], M, 0, 0, 1, 0, 0, MS_ONLY, script, script_len), # Invalid variant
            (args[0][0], M, 0, 0, 0, 1, 0, MS_ONLY, script, script_len), # Invalid range index
            (args[0][0], M, 0, 0, 0, 0, H, MS_ONLY, script, script_len), # Hardened child
            (args[0][0], M, 0, 0, 0, 0, 0, MS_ONLY, None,   script_len), # NULL output
            (args[0][0], M, 0, 0, 0, 0, 0, MS_ONLY, script, 0),          # Empty output
        ]
        for args in bad_args:
            (descriptor, network, depth, idx, variant, multi_index,
                child_num, flags, bytes_out, bytes_len) = args
            d = c_void_p()
            ret = wally_descriptor_parse(miniscript, None, network, flags, d)
            if ret == WALLY_OK:
                ret, written = wally_descriptor_to_script(d, depth, idx, variant,
                                                          multi_index, child_num,
                                                          0, bytes_out, bytes_len)
                self.assertEqual(written, 0)
                wally_descriptor_free(d)
            self.assertEqual(ret, WALLY_EINVAL)

    def test_network(self):
        addrs_len = 64
        addrs = (c_char_p * addrs_len)()

        # Start with a descriptor containing raw keys
        descriptor = 'sh(multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc))'
        d = c_void_p()
        ret = wally_descriptor_parse(descriptor, None, NETWORK_NONE, 0, d)
        self.assertEqual(ret, WALLY_OK)
        # Get the network from the descriptor
        ret, network = wally_descriptor_get_network(None)
        self.assertEqual((ret, network), (WALLY_EINVAL, NETWORK_NONE))
        ret, network = wally_descriptor_get_network(d)
        self.assertEqual((ret, network), (WALLY_OK, NETWORK_NONE))
        # We cannot generate an address for a descriptor without a network
        addrs = (c_char_p * 1)()
        ret = wally_descriptor_to_addresses(d, 0, 0, 0, 0, addrs, 1)
        self.assertEqual(ret, WALLY_EINVAL)
        # Set the network for the descriptor
        for args in [(None, NETWORK_BTC_MAIN), (d, 0xf0)]:
            ret = wally_descriptor_set_network(*args)
            self.assertEqual(ret, WALLY_EINVAL)
        ret = wally_descriptor_set_network(d, NETWORK_BTC_MAIN)
        self.assertEqual(ret, WALLY_OK)
        # Verify the network changed
        ret, network = wally_descriptor_get_network(d)
        self.assertEqual((ret, network), (WALLY_OK, NETWORK_BTC_MAIN))
        # We can now generate an address
        addrs = (c_char_p * 1)()
        ret = wally_descriptor_to_addresses(d, 0, 0, 0, 0, addrs, 1)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addrs[0], utf8('3ETTzkMnuA4PguZeWYtdCT6Rva3yTHATyP'))
        wally_descriptor_free(d)

    def test_descriptor_to_addresses(self):
        addrs_len = 64
        addrs = (c_char_p * addrs_len)()

        # Valid args
        args = [
            ('wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)',
              NETWORK_BTC_TEST, 0, 0, 0, [
                'tb1q0ht9tyks4vh7p5p904t340cr9nvahy7um9zdem'
              ]),
            ('wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))',
              NETWORK_BTC_MAIN, 0, 0, 0, [
                'bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c',
                'bc1qp6rfclasvmwys7w7j4svgc2mrujq9m73s5shpw4e799hwkdcqlcsj464fw',
                'bc1qsflxzyj2f2evshspl9n5n745swcvs5k7p5t8qdww5unxpjwdvw5qx53ms4',
                'bc1qmhmj2mswyvyj4az32mzujccvd4dgr8s0lfzaum4n4uazeqc7xxvsr7e28n',
                'bc1qjeu2wa5jwvs90tv9t9xz99njnv3we3ux04fn7glw3vqsk4ewuaaq9kdc9t',
              ]),
        ]
        for descriptor, network, variant, multi_index, child_num, expected in args:
            d = c_void_p()
            ret = wally_descriptor_parse(descriptor, None, network, 0, d)
            self.assertEqual(ret, WALLY_OK)
            ret = wally_descriptor_to_addresses(d, variant, multi_index,
                                                child_num, 0, addrs,
                                                len(expected))
            self.assertEqual(ret, WALLY_OK)
            for i in range(len(expected)):
                self.assertEqual(utf8(expected[i]), addrs[i])
            wally_descriptor_free(d)

        # Invalid args
        M, U = NETWORK_BTC_MAIN, 0x33 # Unknown network
        H = 0x80000000 # Hardened child
        bad_args = [
            (None,       M, 0, 0, 0, 0, addrs, addrs_len), # NULL miniscript
            (args[0][0], M, 0, 0, H, 0, addrs, addrs_len), # Hardened child
            (args[0][0], U, 0, 0, 0, 0, addrs, addrs_len), # Unknown network
            (args[0][0], M, 1, 0, 0, 0, addrs, addrs_len), # Unknown variant
            (args[0][0], M, 0, 1, 0, 0, addrs, addrs_len), # Unknown range index
            (args[0][0], M, 0, 0, 0, 2, addrs, addrs_len), # Invalid flags
            (args[0][0], M, 0, 0, 0, 0, None,  addrs_len), # NULL output
            (args[0][0], M, 0, 0, 0, 0, addrs, 0),         # Empty output
        ]
        for args in bad_args:
            (descriptor, network, variant, multi_index,
                child_num, flags, out, out_len) = args
            d = c_void_p()
            ret = wally_descriptor_parse(descriptor, None, network, flags, d)
            if ret == WALLY_OK:
                ret = wally_descriptor_to_addresses(d, variant, multi_index,
                                                    child_num, 0, out, out_len)
                wally_descriptor_free(d)
            self.assertEqual(ret, WALLY_EINVAL)

    def test_create_descriptor_checksum(self):
        # Valid args
        for descriptor, expected in [
            ('wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))', 't2zpj2eu'),
        ]:
            d = c_void_p()
            ret = wally_descriptor_parse(descriptor, None, NETWORK_NONE, 0, d)
            self.assertEqual(ret, WALLY_OK)
            ret, checksum = wally_descriptor_get_checksum(d, 0)
            self.assertEqual((ret, checksum), (WALLY_OK, expected))
            wally_descriptor_free(d)

    def test_canonicalize(self):
        """Test canonicalization """
        descriptor_str = 'wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)'
        for descriptor, flags, expected in [
            # 0: returns checksum
            (descriptor_str, 0, descriptor_str + '#8zl0zxma'),
            # WALLY_MS_CANONICAL_NO_CHECKSUM does not return checksum
            (descriptor_str, NO_CHECKSUM, descriptor_str),
        ]:
            d = c_void_p()
            ret = wally_descriptor_parse(descriptor, None, NETWORK_NONE, 0, d)
            self.assertEqual(ret, WALLY_OK)
            ret, canonical = wally_descriptor_canonicalize(d, flags)
            self.assertEqual((ret, canonical), (WALLY_OK, expected))
            wally_descriptor_free(d)

    def test_canonicalize_checksum_bad_args(self):
        """Test bad arguments to canonicalize and checksum functions"""
        descriptor = 'sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))'
        d = c_void_p()
        ret = wally_descriptor_parse(descriptor, None, NETWORK_NONE, 0, d)
        bad_args = [
            (None, 0),    # NULL descriptor
            (d,    0xff), # Bad flags
        ]

        for fn in (wally_descriptor_canonicalize, wally_descriptor_get_checksum):
            for descriptor, flags in bad_args:
               ret, out = fn(descriptor, flags)
               self.assertEqual((ret, out), (WALLY_EINVAL, None))

    def test_features_and_depth(self):
        """Test descriptor feature detection and depth"""
        k1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        k2 = 'xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU'
        # Valid args
        for descriptor, flags, expected, expected_depth in [
            # Bip32 xpub
            (f'pkh({k1})',
             0, MS_IS_DESCRIPTOR, 2),
            # Bip32 xpub with range
            (f'pkh({k1}/*)',
             0,  MS_IS_RANGED|MS_IS_DESCRIPTOR, 2),
            # BIP32 xprv
            (f'pkh({k2}/*)',
             0, MS_IS_PRIVATE|MS_IS_RANGED|MS_IS_DESCRIPTOR, 2),
            # WIF
            ('pkh(L1AAHuEC7XuDM7pJ7yHLEqYK1QspMo8n1kgxyZVdgvEpVC1rkUrM)',
             0, MS_IS_PRIVATE|MS_IS_RAW|MS_IS_DESCRIPTOR, 2),
            # Hex pubkey, compressed
            ('pk(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284)',
             0, MS_IS_RAW|MS_IS_DESCRIPTOR, 2),
            # Hex pubkey, uncompressed
            ('pk(0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf)',
             0, MS_IS_UNCOMPRESSED|MS_IS_RAW|MS_IS_DESCRIPTOR, 2),
            # Miniscript
            ('j:and_v(vdv:after(1567547623),older(2016))',
             MS_ONLY, 0, 3),
            # pk() is both descriptor and miniscript valid and should parse as each
            (f'or_d(thresh(1,pk({k1})),and_v(v:thresh(1,pk({k2}/)),older(30)))',
             0, MS_IS_PRIVATE, 5),
            (f'or_d(thresh(1,pk({k1})),and_v(v:thresh(1,pk({k2}/)),older(30)))',
             MS_ONLY, MS_IS_PRIVATE, 5),
        ]:
            d = c_void_p()
            ret = wally_descriptor_parse(descriptor, None, NETWORK_NONE, flags, d)
            ret, features = wally_descriptor_get_features(d)
            self.assertEqual((ret, features), (WALLY_OK, expected))
            ret, depth = wally_descriptor_get_depth(d)
            self.assertEqual((ret, depth), (WALLY_OK, expected_depth))
            wally_descriptor_free(d)
            # Check the maximum depth parsing limit
            for limit, expected in [(depth-1, WALLY_EINVAL), (depth, WALLY_OK)]:
                ret = wally_descriptor_parse(descriptor, None, NETWORK_NONE,
                                            flags | (limit << 16), d)
                self.assertEqual(ret, expected)
            wally_descriptor_free(d)

        # Invalid args
        ret, features = wally_descriptor_get_features(None) # NULL descriptor
        self.assertEqual((ret, features), (WALLY_EINVAL, 0))
        ret, depth = wally_descriptor_get_depth(None) # NULL descriptor
        self.assertEqual((ret, depth), (WALLY_EINVAL, 0))
        # Mismatched parens are caught early when checking maximum depth
        ret = wally_descriptor_parse('pk())', None, NETWORK_NONE,
                                     flags | (5 << 16), d)
        self.assertEqual(ret, WALLY_EINVAL)

if __name__ == '__main__':
    unittest.main()
