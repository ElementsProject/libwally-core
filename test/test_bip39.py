import unittest
import json
import util
from ctypes import create_string_buffer

class BIP39Tests(unittest.TestCase):

    cases = None

    def setUp(self):
        if self.cases is None:
            with open('data/wordlists/vectors.json', 'r') as f:
                cases = json.load(f)["english"]

            util.bind_all(self, util.bip39_funcs)

    def test_bip39(self):

        pass

if __name__ == '__main__':
    unittest.main()
