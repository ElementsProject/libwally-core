import json
import os
import unittest
from util import *

class PSETTests(unittest.TestCase):

    def test_serialization(self):
        """Testing serialization and deserialization"""
        self.maxDiff = None
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/pset.json')) as f:
            d = json.load(f)
            valids = d['valid']

        for valid in valids:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(valid['pset'].encode('utf-8'), psbt))
            ret, reser = wally_psbt_to_base64(psbt)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(valid['pset'], reser)
            ret, length = wally_psbt_get_length(psbt)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(length, valid['len'])


if __name__ == '__main__':
    _, val = wally_is_elements_build()
    if val != 0:
        unittest.main()
    else:
        self.fail("Attempting to run Elements test without Elements enabled")
