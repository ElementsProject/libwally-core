"""Tests for output descriptors"""
import unittest
from wallycore import *

class DescriptorTests(unittest.TestCase):

    def test_descriptor_to_addresses(self):
        """Test the SWIG string array mapping works for descriptor_to_addresses"""
        descriptor_str = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))#t2zpj2eu"
        variant = 0
        multi_index = 0
        child_num = 0
        flags = 0
        network = WALLY_NETWORK_BITCOIN_MAINNET
        expected = [
            'bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c',
            'bc1qp6rfclasvmwys7w7j4svgc2mrujq9m73s5shpw4e799hwkdcqlcsj464fw',
            'bc1qsflxzyj2f2evshspl9n5n745swcvs5k7p5t8qdww5unxpjwdvw5qx53ms4'
        ]
        descriptor = descriptor_parse(descriptor_str, None, network, flags)
        addrs = descriptor_to_addresses(descriptor, variant, multi_index,
                                        child_num, 0, len(expected))
        self.assertEqual(addrs, expected)


if __name__ == '__main__':
    unittest.main()
