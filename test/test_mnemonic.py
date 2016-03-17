import unittest
import util
from ctypes import create_string_buffer

class MnemonicTests(unittest.TestCase):

    words_list, wl = None, None

    def setUp(self):
        if self.wl is None:
            self.words_list, words = util.load_english_words()

            util.bind_all(self, util.wordlist_funcs + util.mnemonic_funcs)
            self.wl = self.wordlist_init(words, ' ')


    def test_mnemonic(self):

        LEN = 16
        PHRASES = LEN * 8 / 11 # 11 bits per phrase
        buff = create_string_buffer(LEN)

        # Test round tripping
        for i in range(len(self.words_list) - PHRASES):
            phrase = ' '.join(self.words_list[i : i + PHRASES])

            self.mnemonic_to_bytes(self.wl, phrase, buff, LEN)
            generated = self.mnemonic_from_bytes(self.wl, buff, LEN)
            self.assertEqual(phrase, generated)


if __name__ == '__main__':
    unittest.main()
