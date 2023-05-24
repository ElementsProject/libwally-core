import unittest
from wallycore import *

# Simple test cases; we only want to check that the Python binding is OK
ASSET_CASES = [
    (
        'Cores hard_test_case(12) io_ratio=4',
        [2049, 2048, 1026, 1024, 516, 512, 264, 256, 144, 128, 96, 64],
        2048 + 1024 + 512 + 256 + 128 + 64, 0xffffffff, 4,
        [1, 3, 5, 7, 9, 11]
    )
]


class CoinSelectionTests(unittest.TestCase):
    """Tests for coin selection functions"""

    def test_coinselect_assets(self):
        if not is_elements_build():
            self.skipTest('No asset coinselection for non-elements builds')

        for case in ASSET_CASES:
            comment, values, target, attempts, io_ratio, expected = case
            ret = coinselect_assets(values, target, attempts, io_ratio)
            self.assertEqual(expected, ret)


if __name__ == '__main__':
    unittest.main()
