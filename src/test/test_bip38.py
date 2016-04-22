import unittest
from util import *

KEY_MAINNET, KEY_TESTNET, KEY_COMPRESSED, KEY_EC_MULT, KEY_RAW = 0, 7, 256, 512, 1024

# BIP38 Vectors from
# https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
cases = [
    [ 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5',
      'TestingOneTwoThree',
      KEY_MAINNET,
      '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg' ],
    [ '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE',
      'Satoshi',
      KEY_MAINNET,
      '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq' ],
    [ '64EEAB5F9BE2A01A8365A579511EB3373C87C40DA6D2A25F05BDA68FE077B66E',
      unhexlify('cf9300f0909080f09f92a9'),
      KEY_MAINNET,
      '6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn' ],
    [ 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5',
      'TestingOneTwoThree',
      KEY_MAINNET + KEY_COMPRESSED,
      '6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo' ],
    [ '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE',
      'Satoshi',
      KEY_MAINNET + KEY_COMPRESSED,
      '6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7' ],
    # Raw vectors
    [ '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE',
      'Satoshi',
      KEY_MAINNET + KEY_COMPRESSED + KEY_RAW,
      '0142E00B76EA60B62F66F0AF93D8B5380652AF51D1A3902EE00726CCEB70CA636B5B57CE6D3E2F' ],
]


class BIP38Tests(unittest.TestCase):

    def from_priv(self, priv_key, passwd, flags):
        priv, p_len = make_cbuffer(priv_key)
        if flags > KEY_RAW:
            out_buf, out_len = make_cbuffer('00' * 39)
            ret = bip38_raw_from_private_key(priv, p_len, passwd, len(passwd),
                                             flags, out_buf, out_len)
            return ret, h(out_buf).upper()
        else:
            return bip38_from_private_key(priv, p_len, passwd, len(passwd), flags)

    def to_priv(self, bip38, passwd, flags):
        priv, priv_len = make_cbuffer('00' * 32)
        if flags > KEY_RAW:
            raw, raw_len = make_cbuffer(bip38)
            ret = bip38_raw_to_private_key(raw, raw_len, passwd, len(passwd),
                                           flags, priv, priv_len)
        else:
            ret = bip38_to_private_key(bip38, passwd, len(passwd), flags,
                                       priv, priv_len)
        return ret, priv


    def test_bip38(self):

        for case in cases:
            priv_key, passwd, flags, expected = case
            ret, bip38 = self.from_priv(priv_key, passwd, flags)
            self.assertEqual(ret, 0)
            self.assertEqual(bip38, expected)

            ret, new_priv_key = self.to_priv(bip38, passwd, flags)
            self.assertEqual(ret, 0)
            self.assertEqual(h(new_priv_key).upper(), priv_key)


if __name__ == '__main__':
    unittest.main()
