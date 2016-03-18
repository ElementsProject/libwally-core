import unittest
from binascii import unhexlify
import json
import util
from ctypes import create_string_buffer


class BIP39Tests(unittest.TestCase):

    cases = None
    langs = { 'en': 'english',
              'es': 'spanish',
              'fr': 'french',
              'it': 'italian',
              'jp': 'japanese',
              'zhs': 'chinese_simplified',
              'zht': 'chinese_traditional' }


    def setUp(self):
        if self.cases is None:
            with open('data/wordlists/vectors.json', 'r') as f:
                self.cases = json.load(f)["english"]

            util.bind_all(self, util.bip39_funcs + util.wordlist_funcs)
            gwl = lambda lang: self.bip39_get_wordlist(lang)
            self.wordlists = {l: gwl(l) for l in self.langs.keys()}


    def test_all_langs(self):

        all_langs = self.bip39_get_languages().split()
        for lang in all_langs:
            self.assertTrue(lang in self.langs)

        self.assertEqual(len(all_langs), len(self.langs.keys()))

    def test_bip39_wordlists(self):

        for lang, wl in self.wordlists.iteritems():
            self.assertIsNotNone(wl)

        self.assertEqual(self.bip39_get_wordlist(None),
                         self.wordlists['en'])


    def test_all_lookups(self):

        for lang in self.langs.keys():
            wl = self.wordlists[lang]
            words_list, _ = util.load_words(self.langs[lang])
            for i in range(2048):
                word = self.wordlist_lookup_index(wl, i)
                self.assertEqual(word, words_list[i])
                idx = self.wordlist_lookup_word(wl, word)
                self.assertEqual(i, idx - 1)


    def test_bip39_vectors(self):
        """Test conversion to and from the BIP39 specification vectors"""
        wl = self.bip39_get_wordlist(None)

        for case in self.cases:
            hex_input, mnemonic = case[0], case[1]
            hex_len = len(hex_input) / 2

            buf = create_string_buffer(unhexlify(hex_input), hex_len)
            result = self.bip39_mnemonic_from_bytes(wl, buf, hex_len)
            self.assertEqual(result, mnemonic)
            self.assertEqual(self.bip39_mnemonic_is_valid(wl, mnemonic), 1)

            invalid_str = 'ff' * hex_len
            rbuf = create_string_buffer(unhexlify(invalid_str), hex_len)
            rlen = self.bip39_mnemonic_to_bytes(wl, result, rbuf, hex_len)
            self.assertEqual(rlen, hex_len)
            self.assertEqual(buf.raw, rbuf.raw)


if __name__ == '__main__':
    unittest.main()
