#!/usr/bin/env python
import unittest
from util import *


NETWORK_NONE       = 0x00
NETWORK_BTC_MAIN   = 0x01
NETWORK_BTC_TEST   = 0x02
NETWORK_BTC_REG    = 0xff
NETWORK_LIQUID     = 0x03
NETWORK_LIQUID_REG = 0x04

MS_TAP           = 0x1  # WALLY_MINISCRIPT_TAPSCRIPT
MS_ONLY          = 0x2  # WALLY_MINISCRIPT_ONLY
REQUIRE_CHECKSUM = 0x4  # WALLY_MINISCRIPT_REQUIRE_CHECKSUM
POLICY           = 0x08 # WALLY_MINISCRIPT_POLICY_TEMPLATE
UNIQUE_KEYPATHS  = 0x10 # WALLY_MINISCRIPT_UNIQUE_KEYPATHS
AS_ELEMENTS      = 0x20 # WALLY_MINISCRIPT_AS_ELEMENTS

MS_IS_RANGED       = 0x1
MS_IS_MULTIPATH    = 0x2
MS_IS_PRIVATE      = 0x4
MS_IS_UNCOMPRESSED = 0x08
MS_IS_RAW          = 0x010
MS_IS_DESCRIPTOR   = 0x20
MS_IS_X_ONLY       = 0x40
MS_IS_PARENTED     = 0x80
MS_IS_ELEMENTS     = 0x100
MS_IS_SLIP77       = 0x200
MS_IS_ELIP150      = 0x400
MS_IS_ELIP151      = 0x800
MS_IS_TAPSCRIPT    = 0x1000
MS_IS_MUSIG        = 0x2000

NO_CHECKSUM = 0x1 # WALLY_MS_CANONICAL_NO_CHECKSUM

BLINDING_KEY_INDEX = 0xffffffff

def wally_map_from_dict(d):
    m = pointer(wally_map())
    assert(wally_map_init_alloc(len(d.keys()), None, m) == WALLY_OK)
    for k,v in d.items():
        assert(wally_map_add(m, utf8(k), len(k), utf8(v), len(v)) == WALLY_OK)
    return m


class DescriptorTests(unittest.TestCase):

    def test_parse_and_to_script(self):
        """Test parsing and script generation"""
        keys = wally_map_from_dict({
            'key_local': '038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048',
            'key_remote': '03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7',
            'key_revocation': '03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284',
            'H': 'd0721279e70d39fb4aa409b52839a0056454e3b5', # HASH160(key_local)
            'x_only': 'b71aa79cab0ae2d83b82d44cbdc23f5dcca3797e8ba622c4e45a8f7dce28ba0e',
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

        # pk_k and pk_h fragment tests: (miniscript, flags, expected_hex)
        pk_args = [
            ('c:pk_k(key_local)', MS_ONLY,
             '21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac'),
            ('c:pk_h(key_local)', MS_ONLY,
             '76a914d0721279e70d39fb4aa409b52839a0056454e3b588ac'),
            ('c:pk_k(x_only)', MS_ONLY | MS_TAP,
             '20b71aa79cab0ae2d83b82d44cbdc23f5dcca3797e8ba622c4e45a8f7dce28ba0eac'),
        ]
        for miniscript, flags, expected in pk_args:
            d = c_void_p()
            ret = wally_descriptor_parse(miniscript, keys, NETWORK_NONE, flags, d)
            self.assertEqual(ret, WALLY_OK)
            ret, written = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, script, script_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, len(expected) // 2)
            self.assertEqual(script[:written], make_cbuffer(expected)[0])
            wally_descriptor_free(d)

        # hash fragment tests: (miniscript, flags, expected_hex)
        hash_args = [
            ('sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2)', MS_ONLY,
             '82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed287'),
            ('hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b)', MS_ONLY,
             '82012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b87'),
            ('ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba)', MS_ONLY,
             '82012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba87'),
            ('hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07)', MS_ONLY,
             '82012088a91420195b5a3d650c17f0f29f91c33f8f6335193d0787'),
        ]
        for hash_ms, flags, expected in hash_args:
            d = c_void_p()
            ret = wally_descriptor_parse(hash_ms, keys, NETWORK_NONE, flags, d)
            self.assertEqual(ret, WALLY_OK)
            ret, written = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, script, script_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, len(expected) // 2)
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
        _, is_elements_build = wally_is_elements_build()

        k1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        k2 = 'xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU'
        # Valid args
        # descriptor, flags, expected_features, expected_depth, expected keys
        cases = [
            # Bip32 xpub
            (f'pkh({k1})',
             0, MS_IS_DESCRIPTOR, 2, 1),
            # Bip32 xpub with range
            (f'pkh({k1}/*)',
             0,  MS_IS_RANGED|MS_IS_DESCRIPTOR, 2, 1),
            # BIP32 xprv
            (f'pkh({k2}/*)',
             0, MS_IS_PRIVATE|MS_IS_RANGED|MS_IS_DESCRIPTOR, 2, 1),
            # WIF
            ('pkh(L1AAHuEC7XuDM7pJ7yHLEqYK1QspMo8n1kgxyZVdgvEpVC1rkUrM)',
             0, MS_IS_PRIVATE|MS_IS_RAW|MS_IS_DESCRIPTOR, 2, 1),
            # Hex pubkey, compressed
            ('pk(03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284)',
             0, MS_IS_RAW|MS_IS_DESCRIPTOR, 2, 1),
            # Hex pubkey, uncompressed
            ('pk(0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf)',
             0, MS_IS_UNCOMPRESSED|MS_IS_RAW|MS_IS_DESCRIPTOR, 2, 1),
            # Miniscript
            ('j:and_v(vdv:after(1567547623),older(2016))',
             MS_ONLY, 0, 3, 0),
            # pk() is both descriptor and miniscript valid and should parse as each
            (f'or_d(thresh(1,pk({k1})),and_v(v:thresh(1,pk({k2}/)),older(30)))',
             0, MS_IS_PRIVATE, 5, 2),
            (f'or_d(thresh(1,pk({k1})),and_v(v:thresh(1,pk({k2}/)),older(30)))',
             MS_ONLY, MS_IS_PRIVATE, 5, 2),
            # tr() key-path only: MS_IS_TAPSCRIPT must NOT be set
            (f'tr({k1})',
             0, MS_IS_DESCRIPTOR, 2, 1),
        ]
        if is_elements_build:
            slip77 = 'ct(slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),elpkh(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH))'
            cases.extend([
                # Parsing a descriptor as elements returns elements in its features
                (f'tr({k1})',
                 AS_ELEMENTS, MS_IS_DESCRIPTOR|MS_IS_ELEMENTS, 2, 1),
                # el-prefixed builtins return elements in their features
                (f'eltr({k1})',
                 0, MS_IS_DESCRIPTOR|MS_IS_ELEMENTS, 2, 1),
                # Note that ct() blinding keys aren't returned in the key count.
                # slip77 builtins return elements and slip77 in their features,
                # and the ct() parent wrapper is included in their depth.
                (slip77,
                 0, MS_IS_DESCRIPTOR|MS_IS_ELEMENTS|MS_IS_SLIP77, 3, 1),
                # An xpub ELIP-150 key
                (f'ct({k1},elpkh({k1}))',
                 0, MS_IS_DESCRIPTOR|MS_IS_ELEMENTS|MS_IS_ELIP150, 3, 1),
                # A hex public ELIP-150 key.
                (f'ct(0286fc9a38e765d955e9b0bcc18fa9ae81b0c893e2dd1ef5542a9c73780a086b90,elpkh({k1}))',
                 0, MS_IS_DESCRIPTOR|MS_IS_ELEMENTS|MS_IS_ELIP150, 3, 1),
                # An xpriv ELIP-150 key. Note that MS_IS_PRIVATE is not
                # returned because the blinding key is not included in the
                # key count.
                (f'ct({k2},elpkh({k1}))',
                 0, MS_IS_DESCRIPTOR|MS_IS_ELEMENTS|MS_IS_ELIP150, 3, 1),
                # A hex private ELIP-150 key. As above MS_IS_PRIVATE is not
                # returned.
                (f'ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,elpkh({k1}))',
                 0, MS_IS_DESCRIPTOR|MS_IS_ELEMENTS|MS_IS_ELIP150, 3, 1),
                ])

        for descriptor, flags, expected_features, expected_depth, expected_keys in cases:
            d = c_void_p()
            ret = wally_descriptor_parse(descriptor, None, NETWORK_NONE, flags, d)
            ret, features = wally_descriptor_get_features(d)
            self.assertEqual((ret, features), (WALLY_OK, expected_features))
            ret, depth = wally_descriptor_get_depth(d)
            self.assertEqual((ret, depth), (WALLY_OK, expected_depth))
            ret, num_keys = wally_descriptor_get_num_keys(d)
            self.assertEqual((ret, num_keys), (WALLY_OK, expected_keys))
            ret, key_info = wally_descriptor_get_key(d, BLINDING_KEY_INDEX)
            if descriptor.startswith('ct'):
                self.assertEqual(ret, WALLY_OK)
                expected_key_info = descriptor.split(',')[0][3:]
                if expected_key_info.startswith('slip77'):
                    expected_key_info = expected_key_info[7:-1]
                self.assertEqual(key_info, expected_key_info)
            else:
                self.assertEqual(ret, WALLY_EINVAL)
            wally_descriptor_free(d)
            # Check the maximum depth parsing limit
            for limit, expected in [(depth-1, WALLY_EINVAL), (depth, WALLY_OK)]:
                ret = wally_descriptor_parse(descriptor, None, NETWORK_NONE,
                                            flags | (limit << 16), d)
                self.assertEqual(ret, expected)

        # Invalid args
        ret, features = wally_descriptor_get_features(None) # NULL descriptor
        self.assertEqual((ret, features), (WALLY_EINVAL, 0))
        ret, depth = wally_descriptor_get_depth(None) # NULL descriptor
        self.assertEqual((ret, depth), (WALLY_EINVAL, 0))
        # Mismatched parens are caught early when checking maximum depth
        ret = wally_descriptor_parse('pk())', None, NETWORK_NONE,
                                     flags | (5 << 16), d)
        self.assertEqual(ret, WALLY_EINVAL)

        # tr() with taptree: MS_IS_TAPSCRIPT must be set in features
        d = c_void_p()
        desc_tree = f'tr({k1},{{pk({k1}),pk({k1})}})'
        ret = wally_descriptor_parse(desc_tree, None, NETWORK_NONE, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret, features = wally_descriptor_get_features(d)
        self.assertEqual(ret, WALLY_OK)
        self.assertTrue(features & MS_IS_TAPSCRIPT, 'MS_IS_TAPSCRIPT not set for tr() with taptree')
        self.assertTrue(features & MS_IS_DESCRIPTOR)
        wally_descriptor_free(d)

    def test_policy(self):
        """Test policy parsing"""
        # Substitution variables
        slip77 = 'b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04'
        xpriv = 'xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU'
        xpub1 = 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL'
        xpub2 = 'xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU'

        def make_keys(xpubs):
            keys = {f'@{i}': xpub for i,xpub in enumerate(xpubs)}
            return wally_map_from_dict(keys)

        P, K = POLICY, UNIQUE_KEYPATHS
        bad_args = [
            # Raw pubkey
            [P, 'pkh(@0/*)', ['038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048']],
            # Bip32 private key
            [P, 'pkh(@0/*)', [xpriv]],
            # Keys must be in the form of @N
            [P, 'pkh(@0/*)', {'foo': xpub1}],
            # Keys must start from 0
            [P, 'pkh(@0/*)', {'@1': xpub1}],
            # Keys must be successive integers
            [P, 'pkh(@0/*)', [xpub1, xpub2]],
            # Keys must all be substituted
            [P, 'pkh(@0/*)', {'@0': xpub1, '@1': xpub2}],
            # Keys cannot have child paths
            [P, 'pkh(@0/*)', {'@0': f'{xpub1}/0'}],
            # Keys must be unique in the substitution list (always)
            [P, 'sh(multi(1, @0/*,@1/*))', [xpub1, xpub1]],
            # Keys must be unique in the final expression (with flag)
            [P|K, 'sh(multi(1,@0/*,@0/*))', [xpub1]],
            [P|K, 'sh(multi(1,@0/**,@0/**))', [xpub1]],
            # Key multi-paths must be disjoint sets
            [P|K, 'sh(multi(1,@0/<0;1>/*,@0/<1;2>/*))', [xpub1]],
            [P|K, 'sh(multi(1,@0/<1;0>/*,@0/<2;1>/*))', [xpub1]],
            # Keys must not be negative
            [P, 'pkh(@-1/*)', {'@-1': xpub1}],
            # Keys must not have leading space
            [P, 'pkh(@ 0/*)', {'@ 0': xpub1}],
            # Keys must not have leading zeros
            [P, 'pkh(@00/*)', {'@00': xpub1}],
            [P, 'sh(multi(1,@0/*,@01/*))', {'@0': xpub1, '@01': xpub2}],
        ]
        d = c_void_p()
        for flags, policy, key_items in bad_args:
            keys = wally_map_from_dict(key_items) if type(key_items) is dict else make_keys(key_items)
            ret = wally_descriptor_parse(policy, keys, NETWORK_BTC_MAIN, flags, d)
            self.assertEqual(ret, WALLY_EINVAL)
            wally_map_free(keys)

        # Elements confidential policy parsing"""
        if not wally_is_elements_build()[1]:
            return  # Not enabled

        P = POLICY
        cases = [
            # slip77 with a 64 byte hex slip77 blinding key
            [P, 'ct(slip77(@B),elpkh(@0/*))', {'@B': slip77, '@0': xpub1}],
            # elip150 with a 64 byte hex private blinding key
            [P, 'ct(@B,elpkh(@0/*))',         {'@B': slip77, '@0': xpub1}],
            # elip150 with an xpub blinding key
            [P, 'ct(@B,elpkh(@0/*))',         {'@B': xpub1,  '@0': xpub2}],
        ]
        d = c_void_p()
        for flags, policy, key_items in cases:
            keys = wally_map_from_dict(key_items)
            ret = wally_descriptor_parse(policy, keys, NETWORK_LIQUID, flags, d)
            self.assertEqual(ret, WALLY_OK)
            ret, num_keys = wally_descriptor_get_num_keys(d)
            self.assertEqual((ret, num_keys), (WALLY_OK, 1)) # Only non-blinding
            ret, key_str = wally_descriptor_get_key(d, 0)
            self.assertEqual((ret, key_str), (WALLY_OK, key_items['@0']))
            ret, key_info = wally_descriptor_get_key(d, BLINDING_KEY_INDEX)
            self.assertEqual((ret, key_info), (WALLY_OK, key_items['@B']))
            wally_map_free(keys)
            wally_descriptor_free(d)

    def test_key_iteration(self):
        """Test iterating descriptor keys"""
        origin_fp = 'd34db33f'
        origin_path = "44'/0'/0'"
        k1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        k2 = 'xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrvZQfvTcXXSAiFNQ6tTtU'
        wif = 'L1AAHuEC7XuDM7pJ7yHLEqYK1QspMo8n1kgxyZVdgvEpVC1rkUrM'
        pk = '03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284'
        pk_u = '0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf'
        policy_keys = wally_map_from_dict({f'@{i}': xpub for i,xpub in enumerate([k1])})
        origin = f'[{origin_fp}]' # Fingerprint only
        policy_keys_with_origins = wally_map_from_dict({f'@{i}': f'{origin}{xpub}' for i,xpub in enumerate([k1])})
        origin = f'[{origin_fp}/{origin_path}]' # Fingerprint with path
        policy_keys_with_origin_paths = wally_map_from_dict({f'@{i}': f'{origin}{xpub}' for i,xpub in enumerate([k1])})
        P = POLICY

        # Valid args
        for flags, descriptor, expected, child_path, expected_features in [
            # Bip32 xpub
            (0, f'pkh({k1})',         k1,   '',        0),
            (0, f'pkh({k1}/*)',       k1,   '*',       MS_IS_RANGED),
            (0, f'pkh({k1}/0/1/2/*)', k1,   '0/1/2/*', MS_IS_RANGED),
            (0, f'pkh({k1}/<0;1>/*)', k1,   '<0;1>/*', MS_IS_RANGED|MS_IS_MULTIPATH),
            # Bip32 xpub (as policy)
            (P, 'pkh(@0/*)',          k1,   '*',       MS_IS_RANGED),
            (P, 'pkh(@0/**)',         k1,   '<0;1>/*', MS_IS_RANGED|MS_IS_MULTIPATH),
            (P, 'pkh(@0/<0;1>/*)',    k1,   '<0;1>/*', MS_IS_RANGED|MS_IS_MULTIPATH),
            # BIP32 xprv
            (0, f'pkh({k2})',         k2,   '',        MS_IS_PRIVATE),
            # WIF
            (0, f'pkh({wif})',        wif,  '',        MS_IS_RAW|MS_IS_PRIVATE),
            # Hex pubkey, compressed
            (0, f'pk({pk})',          pk,   '',        MS_IS_RAW),
            # Hex pubkey, uncompressed
            (0, f'pk({pk_u})',        pk_u, '',        MS_IS_RAW|MS_IS_UNCOMPRESSED),
        ]:
            d = c_void_p()
            buf, buf_len = make_cbuffer('0' * 8)

            for with_origin in [False, True] if expected == k1 else [False]:
                keys = [None]
                if flags & P:
                    if with_origin:
                        # Check keys with a key origin with and without paths
                        keys = [policy_keys_with_origins, policy_keys_with_origin_paths]
                    else:
                        # Check keys with no key origin
                        keys = [policy_keys]
                elif with_origin:
                    continue
                for k in keys:
                    ret = wally_descriptor_parse(descriptor, k, NETWORK_BTC_MAIN, flags, d)
                    self.assertEqual(ret, WALLY_OK)
                    ret, num_keys = wally_descriptor_get_num_keys(d)
                    self.assertEqual((ret, num_keys), (WALLY_OK, 1))
                    ret, key_str = wally_descriptor_get_key(d, 0)
                    self.assertEqual((ret, key_str), (WALLY_OK, expected))
                    ret, path_len = wally_descriptor_get_key_child_path_str_len(d, 0)
                    self.assertEqual((ret, path_len), (WALLY_OK, len(child_path)))
                    ret, path_str = wally_descriptor_get_key_child_path_str(d, 0)
                    self.assertEqual((ret, path_str), (WALLY_OK, child_path))
                    ret, features = wally_descriptor_get_key_features(d, 0)
                    if with_origin:
                        expected_features |= MS_IS_PARENTED
                    self.assertEqual((ret, features), (WALLY_OK, expected_features))
                    ret = wally_descriptor_get_key_origin_fingerprint(d, 0, buf, buf_len)
                    # Ensure the key origin matches if present
                    if with_origin:
                        self.assertEqual(ret, WALLY_OK)
                        ret, fp = wally_hex_from_bytes(buf, buf_len)
                        self.assertEqual((ret, fp), (WALLY_OK, origin_fp))
                    else:
                        self.assertEqual(ret, WALLY_EINVAL)
                    ret, path_len = wally_descriptor_get_key_origin_path_str_len(d, 0)
                    expect_origin_path = with_origin and k == policy_keys_with_origin_paths
                    expected_len = len(origin_path) if expect_origin_path else 0
                    self.assertEqual((ret, path_len), (WALLY_OK, expected_len))
                    ret, path_str = wally_descriptor_get_key_origin_path_str(d, 0)
                    expected_path = origin_path if expect_origin_path else ''
                    self.assertEqual((ret, path_str), (WALLY_OK, expected_path))
                    wally_descriptor_free(d)


    def test_wrappers(self):
        """Test miniscript wrapper expressions (a:, s:, c:, d:, v:, j:, n:, l:, u:, t:)"""
        keys = wally_map_from_dict({
            'key_local': '038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048',
        })
        script, script_len = make_cbuffer('00' * 256 * 2)

        # pk_k push: 21 <33-byte compressed pubkey>
        pk_push = '21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048'

        # (miniscript, expected_script_hex)
        # In libwally, multiple wrappers use a single colon with all chars before it,
        # e.g. "ac:pk_k" applies c: first then a: (wrappers applied in reverse order).
        # c: [pk_k] CHECKSIG
        c_pk = pk_push + 'ac'
        # vc: pk_k CHECKSIGVERIFY (v: replaces trailing CHECKSIG with CHECKSIGVERIFY)
        vc_pk = pk_push + 'ad'

        wrapper_cases = [
            # c: wrapper — pk_k(K) -> [K] CHECKSIG
            ('c:pk_k(key_local)', c_pk),
            # a: wrapper — TOALTSTACK [X] FROMALTSTACK  (X = c:pk_k, type B)
            ('ac:pk_k(key_local)', '6b' + c_pk + '6c'),
            # s: wrapper — SWAP [X]  (X = c:pk_k, type Bo)
            ('sc:pk_k(key_local)', '7c' + c_pk),
            # v: wrapper — replaces trailing CHECKSIG with CHECKSIGVERIFY
            ('vc:pk_k(key_local)', vc_pk),
            # d: wrapper — DUP IF [X] ENDIF  (X = v:older(1), type Vz)
            # older(1) = OP_1(51) OP_CSV(b2); v: appends OP_VERIFY(69) since CSV not replaceable
            ('dv:older(1)', '7663' + '51b269' + '68'),
            # j: wrapper — SIZE 0NOTEQUAL IF [X] ENDIF  (X = c:pk_k, type Bn)
            ('jc:pk_k(key_local)', '829263' + c_pk + '68'),
            # n: wrapper — [X] 0NOTEQUAL  (X = c:pk_k, type B)
            ('nc:pk_k(key_local)', c_pk + '92'),
            # l: wrapper — or_i(0, X): IF 0 ELSE [X] ENDIF  (X = c:pk_k, type B)
            ('lc:pk_k(key_local)', '630067' + c_pk + '68'),
            # u: wrapper — or_i(X, 0): IF [X] ELSE 0 ENDIF  (X = c:pk_k, type B)
            ('uc:pk_k(key_local)', '63' + c_pk + '670068'),
            # t: wrapper — and_v(X, 1): [X] OP_1  (X = vc:pk_k, type V)
            ('tvc:pk_k(key_local)', vc_pk + '51'),
        ]

        for miniscript, expected in wrapper_cases:
            d = c_void_p()
            ret = wally_descriptor_parse(miniscript, keys, NETWORK_NONE, MS_ONLY, d)
            self.assertEqual(ret, WALLY_OK, f'parse failed for: {miniscript}')
            ret, written = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, script, script_len)
            self.assertEqual(ret, WALLY_OK, f'to_script failed for: {miniscript}')
            self.assertEqual(written, len(expected) // 2,
                             f'wrong length for: {miniscript}')
            self.assertEqual(script[:written], make_cbuffer(expected)[0],
                             f'wrong script for: {miniscript}')
            wally_descriptor_free(d)

        wally_map_free(keys)

    def test_composite_descriptors(self):
        """Test composite miniscript expressions (and_v, or_d, andor) including Liana-style templates"""
        keys = wally_map_from_dict({
            'key_local':      '038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048',
            'key_remote':     '03a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7',
            'key_revocation': '03b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284',
            'x_only':         'b71aa79cab0ae2d83b82d44cbdc23f5dcca3797e8ba622c4e45a8f7dce28ba0e',
        })
        script, script_len = make_cbuffer('00' * 512 * 2)

        cases = [
            # Case A: Liana-like recovery leaf — key + timelock
            # and_v(X,Y) -> [X][Y]
            # vc:pk_k -> push(K) OP_CHECKSIGVERIFY; older(52560=0xCD50) -> 03 50 CD 00 OP_CSV
            ('and_v(vc:pk_k(key_local),older(52560))', MS_ONLY,
             '21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048'
             'ad0350cd00b2'),
            # Case B: Primary key OR (recovery key + timelock)
            # or_d(X,Y) -> [X] OP_IFDUP(73) OP_NOTIF(64) [Y] OP_ENDIF(68)
            ('or_d(c:pk_k(key_local),and_v(vc:pk_k(key_remote),older(52560)))', MS_ONLY,
             '21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac'
             '73642103a22745365f673e658f0d25eb0afa9aaece858c6a48dfe37a67210c2e23da8ce7ad'
             '0350cd00b268'),
            # Case C: andor — if primary key succeeds use timelock, else use revocation key
            # andor(X,Y,Z) -> [X] OP_NOTIF(64) [Z] OP_ELSE(67) [Y] OP_ENDIF(68)
            ('andor(c:pk_k(key_local),older(52560),c:pk_k(key_revocation))', MS_ONLY,
             '21038bc7431d9285a064b0328b6333f3a20b86664437b6de8f4e26e6bbdee258f048ac'
             '642103b428da420cd337c7208ed42c5331ebb407bb59ffbe3dc27936a227c619804284ac'
             '670350cd00b268'),
            # Case D: Tapscript — x-only key uses 32-byte push (opcode 20)
            ('and_v(vc:pk_k(x_only),older(52560))', MS_ONLY | MS_TAP,
             '20b71aa79cab0ae2d83b82d44cbdc23f5dcca3797e8ba622c4e45a8f7dce28ba0e'
             'ad0350cd00b2'),
        ]

        for miniscript, flags, expected in cases:
            d = c_void_p()
            ret = wally_descriptor_parse(miniscript, keys, NETWORK_NONE, flags, d)
            self.assertEqual(ret, WALLY_OK, f'parse failed for: {miniscript}')
            ret, written = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, script, script_len)
            self.assertEqual(ret, WALLY_OK, f'to_script failed for: {miniscript}')
            self.assertEqual(written, len(expected) // 2, f'wrong length for: {miniscript}')
            self.assertEqual(script[:written], make_cbuffer(expected)[0], f'wrong script for: {miniscript}')
            wally_descriptor_free(d)

        wally_map_free(keys)

    def test_musig_parser(self):
        """Test musig() descriptor parsing (BIP-390)"""
        xpub1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub2 = 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
        xpub3 = 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL'

        # Valid: tr(musig(xpub1, xpub2)) — two-participant musig in taproot
        valid_cases = [
            f'tr(musig({xpub1},{xpub2}))',
            # With trailing ranged wildcard path
            f'tr(musig({xpub1},{xpub2})/<0;1>/*)',
            # With plain trailing derivation path
            f'tr(musig({xpub1},{xpub2})/0/*)',
            # Participant keys may carry their own derivation path
            f'tr(musig({xpub1}/0,{xpub2}/1))',
            # Three-participant musig (3-of-3)
            f'tr(musig({xpub1},{xpub2},{xpub3}))',
        ]
        for desc in valid_cases:
            d = c_void_p()
            ret = wally_descriptor_parse(desc, None, NETWORK_NONE, 0, d)
            self.assertEqual(ret, WALLY_OK, f'Expected WALLY_OK for: {desc}')

            # MS_IS_MUSIG feature flag must be set (whole-descriptor)
            ret, features = wally_descriptor_get_features(d)
            self.assertEqual(ret, WALLY_OK)
            self.assertTrue(features & MS_IS_MUSIG, f'MS_IS_MUSIG not set for: {desc}')
            # MS_IS_TAPSCRIPT must NOT be set (musig is the internal key, not in a leaf)
            self.assertFalse(features & MS_IS_TAPSCRIPT, f'MS_IS_TAPSCRIPT unexpectedly set for: {desc}')

            # MS_IS_MUSIG feature flag must also be set at the per-key level
            ret, kf = wally_descriptor_get_key_features(d, 0)
            self.assertEqual(ret, WALLY_OK)
            self.assertTrue(kf & MS_IS_MUSIG, f'Per-key MS_IS_MUSIG not set for: {desc}')

            wally_descriptor_free(d)

        # Participant count and key extraction for the basic two-participant case
        two_participant_cases = [
            f'tr(musig({xpub1},{xpub2}))',
            f'tr(musig({xpub1},{xpub2})/<0;1>/*)',
            f'tr(musig({xpub1},{xpub2})/0/*)',
        ]
        for desc in two_participant_cases:
            d = c_void_p()
            ret = wally_descriptor_parse(desc, None, NETWORK_NONE, 0, d)
            self.assertEqual(ret, WALLY_OK)
            # Participant count at key index 0
            ret, count = wally_descriptor_get_musig_num_participants(d, 0)
            self.assertEqual((ret, count), (WALLY_OK, 2), f'Count check failed for: {desc}')
            # Participant key extraction
            ret, key0 = wally_descriptor_get_musig_participant_key(d, 0, 0)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(key0, xpub1)
            ret, key1 = wally_descriptor_get_musig_participant_key(d, 0, 1)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(key1, xpub2)
            # Out-of-range participant index
            ret, _ = wally_descriptor_get_musig_participant_key(d, 0, 2)
            self.assertEqual(ret, WALLY_EINVAL)
            wally_descriptor_free(d)

        # Participant keys with per-participant paths
        d = c_void_p()
        desc_pp = f'tr(musig({xpub1}/0,{xpub2}/1))'
        ret = wally_descriptor_parse(desc_pp, None, NETWORK_NONE, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret, count = wally_descriptor_get_musig_num_participants(d, 0)
        self.assertEqual((ret, count), (WALLY_OK, 2))
        ret, key0 = wally_descriptor_get_musig_participant_key(d, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key0, f'{xpub1}/0')
        ret, key1 = wally_descriptor_get_musig_participant_key(d, 0, 1)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key1, f'{xpub2}/1')
        wally_descriptor_free(d)

        # Participant count and key extraction for the three-participant case
        d = c_void_p()
        desc3 = f'tr(musig({xpub1},{xpub2},{xpub3}))'
        ret = wally_descriptor_parse(desc3, None, NETWORK_NONE, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret, count = wally_descriptor_get_musig_num_participants(d, 0)
        self.assertEqual((ret, count), (WALLY_OK, 3), f'Count check failed for: {desc3}')
        ret, key0 = wally_descriptor_get_musig_participant_key(d, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key0, xpub1)
        ret, key1 = wally_descriptor_get_musig_participant_key(d, 0, 1)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key1, xpub2)
        ret, key2 = wally_descriptor_get_musig_participant_key(d, 0, 2)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key2, xpub3)
        # Out-of-range participant index for 3-participant case
        ret, _ = wally_descriptor_get_musig_participant_key(d, 0, 3)
        self.assertEqual(ret, WALLY_EINVAL)
        wally_descriptor_free(d)

        # Error: non-musig descriptor key at index 0
        d2 = c_void_p()
        ret = wally_descriptor_parse(f'tr({xpub1})', None, NETWORK_NONE, 0, d2)
        self.assertEqual(ret, WALLY_OK)
        ret, _ = wally_descriptor_get_musig_num_participants(d2, 0)
        self.assertEqual(ret, WALLY_EINVAL)
        ret, _ = wally_descriptor_get_musig_participant_key(d2, 0, 0)
        self.assertEqual(ret, WALLY_EINVAL)
        wally_descriptor_free(d2)

        # Error: NULL descriptor
        ret, _ = wally_descriptor_get_musig_num_participants(None, 0)
        self.assertEqual(ret, WALLY_EINVAL)
        ret, _ = wally_descriptor_get_musig_participant_key(None, 0, 0)
        self.assertEqual(ret, WALLY_EINVAL)

        # Invalid: musig() in non-taproot context or forbidden forms
        invalid_cases = [
            # wpkh does not accept musig()
            f'wpkh(musig({xpub1},{xpub2}))',
            # pk does not accept musig()
            f'pk(musig({xpub1},{xpub2}))',
            # pkh does not accept musig()
            f'pkh(musig({xpub1},{xpub2}))',
            # nested musig() is forbidden
            f'tr(musig(musig({xpub1},{xpub2}),{xpub2}))',
            # single participant is forbidden (BIP-390 requires >=2)
            f'tr(musig({xpub1}))',
            # hardened trailing derivation step is forbidden
            f'tr(musig({xpub1},{xpub2})/1h/*)',
        ]
        for desc in invalid_cases:
            d = c_void_p()
            ret = wally_descriptor_parse(desc, None, NETWORK_NONE, 0, d)
            self.assertEqual(ret, WALLY_EINVAL, f'Expected WALLY_EINVAL for: {desc}')
            if ret == WALLY_OK:
                wally_descriptor_free(d)

    def test_musig_descriptor_address_generation(self):
        """Test musig() descriptor address generation"""
        xpub1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub2 = 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'

        # 4a. Static musig() taproot address generation (mainnet)
        desc = f'tr(musig({xpub1},{xpub2}))'
        expected_addr_main = 'bc1p7y6m7r4u0035792q9dst9f32340nev5398dp9yvqw4mjkm3m4pdsqusq07'
        expected_addr_test = 'tb1p7y6m7r4u0035792q9dst9f32340nev5398dp9yvqw4mjkm3m4pdsh5x043'
        d = c_void_p()
        ret = wally_descriptor_parse(desc, None, NETWORK_BTC_MAIN, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret, addr_main = wally_descriptor_to_address(d, 0, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addr_main, expected_addr_main,
                         f'Expected known mainnet address, got: {addr_main}')
        wally_descriptor_free(d)

        # Static musig() taproot address generation (testnet)
        # Parse with NETWORK_NONE then set testnet (mainnet xpubs work with NONE)
        d = c_void_p()
        ret = wally_descriptor_parse(desc, None, NETWORK_NONE, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret = wally_descriptor_set_network(d, NETWORK_BTC_TEST)
        self.assertEqual(ret, WALLY_OK)
        ret, addr_test = wally_descriptor_to_address(d, 0, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addr_test, expected_addr_test,
                         f'Expected known testnet address, got: {addr_test}')
        wally_descriptor_free(d)

        # Main and test addresses must differ
        self.assertNotEqual(addr_main, addr_test)

        # 4b. Ranged musig() address derivation
        desc_ranged = f'tr(musig({xpub1},{xpub2})/*)'
        addrs = (c_char_p * 3)()
        d = c_void_p()
        ret = wally_descriptor_parse(desc_ranged, None, NETWORK_BTC_MAIN, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret = wally_descriptor_to_addresses(d, 0, 0, 0, 0, addrs, 3)
        self.assertEqual(ret, WALLY_OK)
        addr_strings = [a.decode() for a in addrs[:3]]
        for a in addr_strings:
            self.assertTrue(a.startswith('bc1p'), f'Expected bc1p prefix, got: {a}')
        self.assertEqual(len(set(addr_strings)), 3, 'All ranged addresses must be distinct')
        wally_descriptor_free(d)

        # 4c. Multipath ranged musig() descriptor
        desc_mp = f'tr(musig({xpub1},{xpub2})/<0;1>/*)'
        addrs_ext = (c_char_p * 1)()
        addrs_int = (c_char_p * 1)()
        d = c_void_p()
        ret = wally_descriptor_parse(desc_mp, None, NETWORK_BTC_MAIN, 0, d)
        self.assertEqual(ret, WALLY_OK)
        # External path (multi_index=0)
        ret = wally_descriptor_to_addresses(d, 0, 0, 0, 0, addrs_ext, 1)
        self.assertEqual(ret, WALLY_OK)
        self.assertTrue(addrs_ext[0].decode().startswith('bc1p'))
        # Internal path (multi_index=1)
        ret = wally_descriptor_to_addresses(d, 0, 1, 0, 0, addrs_int, 1)
        self.assertEqual(ret, WALLY_OK)
        self.assertTrue(addrs_int[0].decode().startswith('bc1p'))
        self.assertNotEqual(addrs_ext[0], addrs_int[0])
        wally_descriptor_free(d)

        # 4d. Per-participant derivation paths
        desc_pp = f'tr(musig({xpub1}/0,{xpub2}/1))'
        d = c_void_p()
        ret = wally_descriptor_parse(desc_pp, None, NETWORK_BTC_MAIN, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret, addr = wally_descriptor_to_address(d, 0, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertTrue(addr.startswith('bc1p'), f'Expected bc1p prefix, got: {addr}')
        wally_descriptor_free(d)

        # 4e. Address generation requires network set
        d = c_void_p()
        ret = wally_descriptor_parse(desc, None, NETWORK_NONE, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret, _ = wally_descriptor_to_address(d, 0, 0, 0, 0)
        self.assertEqual(ret, WALLY_EINVAL)
        wally_descriptor_free(d)

        # Key order independence: swapping keys must produce the same address
        desc_swapped = f'tr(musig({xpub2},{xpub1}))'
        d = c_void_p()
        ret = wally_descriptor_parse(desc_swapped, None, NETWORK_BTC_MAIN, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret, addr_swapped = wally_descriptor_to_address(d, 0, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addr_swapped, addr_main,
                         'Key order must not affect the aggregated taproot address')
        wally_descriptor_free(d)

        # Canonicalization: wally_descriptor_canonicalize works for musig() descriptors
        # and produces a deterministic output.
        # NOTE: libwally's wally_descriptor_canonicalize normalises the textual descriptor
        # (e.g. removes whitespace, normalises separators) but intentionally does NOT
        # re-sort participant keys inside musig().  Sorting happens at the cryptographic
        # aggregation stage (BIP-327 KeyAgg), not at the descriptor text level, which is
        # why two descriptors with swapped keys still produce the same address (tested
        # above).  The canonical form therefore preserves the input key order.
        d = c_void_p()
        ret = wally_descriptor_parse(desc_swapped, None, NETWORK_NONE, 0, d)
        self.assertEqual(ret, WALLY_OK)
        ret, canonical = wally_descriptor_canonicalize(d, NO_CHECKSUM)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(canonical, desc_swapped,
                         'Canonical form preserves input key order (sorting is done at '
                         'key-aggregation time, not descriptor-text level)')
        wally_descriptor_free(d)

        # musig() in a tapscript leaf is not yet supported (tr() FIXME for script paths).
        # Verify that the parser correctly rejects this form until implemented.
        desc_leaf = f'tr({xpub1},pk(musig({xpub1},{xpub2})))'
        d = c_void_p()
        ret = wally_descriptor_parse(desc_leaf, None, NETWORK_BTC_MAIN, 0, d)
        self.assertNotEqual(ret, WALLY_OK, 'Script-leaf musig() should be rejected until implemented')


if __name__ == '__main__':
    unittest.main()
