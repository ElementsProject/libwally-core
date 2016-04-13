import unittest
from binascii import hexlify
import json
from util import *


class BIP39Tests(unittest.TestCase):

    cases = None
    langs = { 'en': 'english',
              'es': 'spanish',
              'fr': 'french',
              'it': 'italian',
              'jp': 'japanese',
              'zhs': 'chinese_simplified',
              'zht': 'chinese_traditional' }

    def get_wordlist(self, lang):
        out = c_void_p()
        bip39_get_wordlist(lang, byref(out))
        return out

    def setUp(self):
        if self.cases is None:
            with open(root_dir + 'src/data/wordlists/vectors.json', 'r') as f:
                cases = json.load(f)['english']
                conv = lambda case: [utf8(x) for x in case]
                self.cases = [conv(case) for case in cases]

            gwl = lambda lang: self.get_wordlist(utf8(lang))
            self.wordlists = {l: gwl(l) for l in list(self.langs.keys())}


    def test_all_langs(self):

        ret, all_langs = bip39_get_languages()
        self.assertEqual(ret, 0)
        all_langs = all_langs.split()

        for lang in all_langs:
            self.assertTrue(lang in self.langs)

        self.assertEqual(len(all_langs), len(list(self.langs.keys())))


    def test_bip39_wordlists(self):

        for lang, wl in self.wordlists.items():
            self.assertIsNotNone(wl)

        def_wl = self.get_wordlist(None)
        en_wl = self.wordlists['en']
        self.assertEqual(def_wl.value, en_wl.value)


    def test_all_lookups(self):

        if wordlist_lookup_index is None:
            return # No internal functions available

        for lang in list(self.langs.keys()):
            wl = self.wordlists[lang]
            words_list, _ = load_words(self.langs[lang])
            for i in range(2048):
                word = wordlist_lookup_index(wl, i)
                self.assertEqual(word, utf8(words_list[i]))
                idx = wordlist_lookup_word(wl, word)
                self.assertEqual(i, idx - 1)


    def test_bip39_vectors(self):
        """Test conversion to and from the BIP39 specification vectors"""
        wl = self.get_wordlist(None)

        for case in self.cases:
            hex_input, mnemonic = case[0], case[1]
            buf, buf_len = make_cbuffer(hex_input)

            ret, result = bip39_mnemonic_from_bytes(wl, buf, buf_len)
            self.assertEqual(ret, 0)
            result = utf8(result)
            self.assertEqual(result, mnemonic)
            bip39_mnemonic_validate(wl, mnemonic)

            out_buf = create_string_buffer(buf_len)
            rlen = c_ulong()
            bip39_mnemonic_to_bytes(wl, result, out_buf, buf_len, byref(rlen))
            self.assertEqual(rlen.value, buf_len)
            self.assertEqual(buf, out_buf.raw)


    def test_mnemonic_to_seed(self):

        for case in self.cases:
            mnemonic, seed = case[1], case[2]

            buf = create_string_buffer(64)
            count = c_ulong()
            bip39_mnemonic_to_seed(mnemonic, b'TREZOR', buf, 64, byref(count))
            self.assertEqual(count.value, 64)
            self.assertEqual(hexlify(buf), seed)


if __name__ == '__main__':
    unittest.main()
