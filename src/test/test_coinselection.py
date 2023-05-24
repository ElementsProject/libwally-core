#!/usr/bin/env python
import unittest
from util import *


class CoinSelectionTests(unittest.TestCase):

    def test_invalid(self):
        """Test invalid arguments"""
        if not wally_is_elements_build()[1]:
            return # # No Elements support, skip this test case
        values = (c_uint64 * 4)(4, 3, 2, 1)
        values_len = len(values)
        out, out_len = (c_uint32 * values_len)(), values_len
        attempts, target, ratio = 0xffffffff, 1, 5
        bad_args = [
            (None,   values_len, target, attempts,   ratio, out,  out_len),   # Null values
            (values, 0,          target, attempts,   ratio, out,  out_len),   # Empty values
            (values, values_len, 0,      attempts,   ratio, out,  out_len),   # Zero target
            (values, values_len, target, values_len, ratio, out,  out_len),   # Too few attempts
            (values, values_len, target, attempts,   0,     out,  out_len),   # Zero ratio
            (values, values_len, target, attempts,   ratio, None, out_len),   # Null output
            (values, values_len, target, attempts,   ratio, out,  out_len-1), # Output too small
        ]
        for args in bad_args:
            ret = wally_coinselect_assets(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))


if __name__ == '__main__':
    unittest.main()
