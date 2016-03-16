import unittest
import util
from ctypes import *

class Mnemonic:
    def __init__(self, words, sep):
        util.bind_all(self, util.wordlist_funcs + util.mnemonic_funcs)


class MnemonicTests(unittest.TestCase):

    words_file = 'data/wordlists/english.txt'
    words_list = None
    words = None

    def setUp(self):
        if self.words is None:
            with open(self.words_file, 'r') as f:
                self.words_list = [l.strip() for l in f.readlines()]
            self.words = ' '.join(self.words_list)

    def test_mnemonic(self):
        pass

if __name__ == '__main__':
    unittest.main()
