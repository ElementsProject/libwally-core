"""Tests for addresses"""
import unittest
from wallycore import *


h2b = hex_to_bytes


class AddressTests(unittest.TestCase):

    def test_b58_address(self):
        for address, scriptpubkey, network in [
            ('mxvewdhKCenLkYgNa8irv1UM2omEWPMdEE', h2b('76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac'), 'testnet'),  # p2pkh
            ('2N5XyEfAXtVde7mv6idZDXp5NFwajYEj9TD', h2b('a91486cc442a97817c245ce90ed0d31d6dbcde3841f987'), 'testnet'),  # p2sh
            ('1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj', h2b('76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac'), 'mainnet'),  # p2pkh
            ('3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu', h2b('a91486cc442a97817c245ce90ed0d31d6dbcde3841f987'), 'mainnet'),  # p2sh
        ]:
            flags = {
                'mainnet': WALLY_NETWORK_BITCOIN_MAINNET,
                'testnet': WALLY_NETWORK_BITCOIN_TESTNET,
            }[network]
            self.assertEqual(address_to_scriptpubkey(address, flags), scriptpubkey)
