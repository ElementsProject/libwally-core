import base64
import json
import os
import unittest
from util import *

class PSBTTests(unittest.TestCase):

    def test_serialization(self):
        """Testing serialization and deserialization"""
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/psbt.json')) as f:
            d = json.load(f)
            invalids = d['invalid']
            valids = d['valid']
            creators = d['creator']
            signers = d['signer']
            combiners = d['combiner']
            finalizers = d['finalizer']
            extractors = d['extractor']

        for invalid in invalids:
            self.assertEqual(WALLY_EINVAL, wally_psbt_from_base64(invalid.encode('utf-8'), pointer(wally_psbt())))

        for valid in valids:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(valid.encode('utf-8'), psbt))
            ret, reser = wally_psbt_to_base64(psbt)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(valid, reser)

if __name__ == '__main__':
    unittest.main()

