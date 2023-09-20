import unittest
from wallycore import init, cleanup, sha256, sha256d, sha512


class SHATests(unittest.TestCase):

    def test_sha_functions(self):
        """Test python wrappers for SHA hash functions"""
        # Ensure empty and valid buffers work correctly
        msg1 = 'This is a test message to hash'.encode()
        msg2 = bytes.fromhex('3e8379862d658e168c71f083bc05169b3b58ca3212e11c838b08629c5ca48a42')
        cases = [
            (sha256,  None, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
            (sha256,  msg1, '726ca2c10e9d8b76e5b79f2961c3069a09fdd0a3b9bf8650e091e39b3c6c35be'),
            (sha256,  msg2, '2f7d292595788655c5288b6e1dc698440d9c12559e3bc1e3cc38005a4add132f'),
            (sha256d, None, '5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456'),
            (sha256d, msg1, '29e04e90a1075caaa06573ea701913148d99fb0b7d6928e33f1aabe6032761a0'),
            (sha256d, msg2, '26e30f19dc2b29d8c220766fd5835d8256c87c32804d19b8307e21d6685c9d3e'),
            (sha512,  None, 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
                            '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'),
            (sha512,  msg1, '2ed34644ddfcf76ca4de13e4632aa61376fbce813fecc5a043a479daaab17b2f'
                            '8c3f376468d4637cb2e7c9e2b99ad08b8cb56fe6e724e476826f2aa210872c32'),
            (sha512,  msg2, 'd51342efcb114c11045c12f7fede6f9a5fdb11051032bd520a99d79023423f4a'
                            'c3ab706ce5fa88c0aac46bbbf15bde720cf49eae5be0def3b39e6d3abb29a67b'),
         ]
        for sha_fn, src, expected in cases:
            result = sha_fn(src)
            self.assertEqual(result.hex(), expected)

        # Ensure passing an incorrect type (a) throws and (b) doesn't crash
        for sha_fn in [sha256, sha256d, sha512]:
            with self.assertRaises(TypeError):
                sha_fn('not bytes')


if __name__ == '__main__':
    init(0)
    unittest.main()
    cleanup(0)
