import unittest
import util
from ctypes import create_string_buffer

class MnemonicTests(unittest.TestCase):

    words_list, wl = None, None

    def setUp(self):
        if self.wl is None:
            self.words_list, words = util.load_words('english')

            util.bind_all(self, util.wordlist_funcs + util.mnemonic_funcs)
            self.wl = self.wordlist_init(words)


    def test_mnemonic(self):

        LEN = 16
        PHRASES = LEN * 8 / 11 # 11 bits per phrase
        PHRASES_BYTES = (PHRASES * 11 + 7) / 8 # Bytes needed to store
        self.assertEqual(LEN, PHRASES_BYTES)

        buff = create_string_buffer(LEN)

        # Test round tripping
        for i in range(len(self.words_list) - PHRASES):
            phrase = ' '.join(self.words_list[i : i + PHRASES])

            written = self.mnemonic_to_bytes(self.wl, phrase, buff, LEN)
            self.assertEqual(written, PHRASES_BYTES)
            generated = self.mnemonic_from_bytes(self.wl, buff, LEN)
            self.assertEqual(phrase, generated)


if __name__ == '__main__':
    unittest.main()
