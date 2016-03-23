import unittest
import util
from binascii import hexlify, unhexlify
from ctypes import create_string_buffer

# NIST cases from http://www.di-mgt.com.au/sha_testvectors.html
sha_512_cases = {
    'abc':
        'ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a' +
        '2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f',

    '':
        'cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce' +
        '47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e',

    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq':
        '204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335' +
        '96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445',

    'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn' +
    'hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu':
        '8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018' +
        '501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909',

    'a' * 1000000:
        'e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb' +
        'de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b',
}


class SHA2Tests(unittest.TestCase):

    SHA256_LEN, SHA512_LEN = 32, 64

    def setUp(self):
        if not hasattr(self, 'sha256'):
            util.bind_all(self, util.sha2_funcs)

    def doSHA(self, sha_fn, hex_in):
        buf_len = self.SHA256_LEN if sha_fn == self.sha256 else self.SHA512_LEN
        buf = create_string_buffer(buf_len)
        in_bytes_len = len(hex_in) / 2
        in_bytes = create_string_buffer(unhexlify(hex_in), in_bytes_len)
        sha_fn(buf, in_bytes, in_bytes_len)
        return hexlify(buf)


    def test_vectors(self):

        for k,v in sha_512_cases.iteritems():
            result = self.doSHA(self.sha512, hexlify(k))
            self.assertEqual(result, v.replace(' ', ''))


#    def test_rfc4231(self):
#        # TODO: HMAC vectors from https://tools.ietf.org/html/rfc4231
#        pass


if __name__ == '__main__':
    unittest.main()
