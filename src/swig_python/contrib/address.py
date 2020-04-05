"""Tests for addresses"""
import unittest
from wallycore import *


h2b = hex_to_bytes


class AddressTests(unittest.TestCase):

    def test_b58_address(self):
        for address, scriptpubkey, network in [
            ('mxvewdhKCenLkYgNa8irv1UM2omEWPMdEE', h2b('76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac'), WALLY_NETWORK_BITCOIN_TESTNET),  # p2pkh
            ('2N5XyEfAXtVde7mv6idZDXp5NFwajYEj9TD', h2b('a91486cc442a97817c245ce90ed0d31d6dbcde3841f987'), WALLY_NETWORK_BITCOIN_TESTNET),  # p2sh
            ('1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj', h2b('76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac'), WALLY_NETWORK_BITCOIN_MAINNET),  # p2pkh
            ('3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu', h2b('a91486cc442a97817c245ce90ed0d31d6dbcde3841f987'), WALLY_NETWORK_BITCOIN_MAINNET),  # p2sh
            ('XYtnYoGoSeE9ouMEVi6mfeujhjT2VnJncA', h2b('a914ec51ffb65120594389733bf8625f542446d97f7987'), WALLY_NETWORK_LIQUID_REGTEST),
            ('H5nswXhfo8AMt159sgA5FWT35De34hVR4o', h2b('a914f80278b2011573a2ac59c83fadf929b0fc57ad0187'), WALLY_NETWORK_LIQUID),
        ]:
            self.assertEqual(address_to_scriptpubkey(address, network), scriptpubkey)
            self.assertEqual(scriptpubkey_to_address(scriptpubkey, network), address)

if __name__ == '__main__':
    unittest.main()
