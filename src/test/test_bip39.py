import unittest
from binascii import hexlify
import json
import util
from util import utf8
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
            with open(util.root_dir + 'src/data/wordlists/vectors.json', 'r') as f:
                cases = json.load(f)['english']
                conv = lambda case: [utf8(x) for x in case]
                self.cases = [conv(case) for case in cases]

            util.bind_all(self, util.bip39_funcs + util.wordlist_funcs)
            gwl = lambda lang: self.bip39_get_wordlist(utf8(lang))
            self.wordlists = {l: gwl(l) for l in list(self.langs.keys())}


    def test_all_langs(self):

        all_langs = self.bip39_get_languages().split()

        for lang in all_langs:
            self.assertTrue(lang in self.langs)

        self.assertEqual(len(all_langs), len(list(self.langs.keys())))

    def test_bip39_wordlists(self):

        for lang, wl in self.wordlists.items():
            self.assertIsNotNone(wl)

        self.assertEqual(self.bip39_get_wordlist(None),
                         self.wordlists['en'])


    def test_all_lookups(self):

        if self.wordlist_lookup_index is None:
            return # No internal functions available

        for lang in list(self.langs.keys()):
            wl = self.wordlists[lang]
            words_list, _ = util.load_words(self.langs[lang])
            for i in range(2048):
                word = self.wordlist_lookup_index(wl, i)
                self.assertEqual(word, utf8(words_list[i]))
                idx = self.wordlist_lookup_word(wl, word)
                self.assertEqual(i, idx - 1)


    def test_bip39_vectors(self):
        """Test conversion to and from the BIP39 specification vectors"""
        wl = self.bip39_get_wordlist(None)

        for case in self.cases:
            hex_input, mnemonic = case[0], case[1]
            buf, buf_len = util.make_cbuffer(hex_input)

            result = utf8(self.bip39_mnemonic_from_bytes(wl, buf, buf_len))
            self.assertEqual(result, mnemonic)
            self.assertEqual(self.bip39_mnemonic_is_valid(wl, mnemonic), 1)

            out_buf = create_string_buffer(buf_len)
            rlen = self.bip39_mnemonic_to_bytes(wl, result, out_buf, buf_len)
            self.assertEqual(rlen, buf_len)
            self.assertEqual(buf, out_buf.raw)


    def test_mnemonic_to_seed(self):

        for case in self.cases:
            mnemonic, seed = case[1], case[2]

            buf = create_string_buffer(64)
            result = self.bip39_mnemonic_to_seed(mnemonic, b'TREZOR', buf, 64)
            self.assertEqual(result, 64)
            self.assertEqual(hexlify(buf), seed)


if __name__ == '__main__':
    unittest.main()
