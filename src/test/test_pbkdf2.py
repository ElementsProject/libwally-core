import unittest
import util
from util import utf8
from binascii import hexlify
from ctypes import create_string_buffer

class PBKDF2Tests(unittest.TestCase):

    PBKDF2_HMAC_SHA256_LEN, PBKDF2_HMAC_SHA512_LEN = 32, 64
    SALT_EXTRA = '1234' # 4 chars to overwrite

    def setUp(self):
        if not hasattr(self, 'pbkdf2_hmac_sha512'):
            util.bind_all(self, util.pbkdf2_funcs)

    def test_pbkdf2_hmac_sha512(self):

        # First test case from
        # https://github.com/Anti-weakpasswords/PBKDF2-Test-Vectors/releases
        # FIXME: Import the file and test them all
        passwd = 'passDATAb00AB7YxDTT'
        salt = 'saltKEYbcTcXHCBxtjD' + self.SALT_EXTRA
        salt = create_string_buffer(salt)
        salt_len = len(salt) - 1 # Ignore trailing NUL from ctypes
        cost = 1
        out_len = 64
        out, _ = util.make_cbuffer('00' * out_len)
        ret = self.pbkdf2_hmac_sha512(passwd, len(passwd),
                                      salt, salt_len,
                                      cost, out, out_len)
        expected = 'CBE6088AD4359AF42E603C2A33760EF9' \
                   'D4017A7B2AAD10AF46F992C660A0B461' \
                   'ECB0DC2A79C2570941BEA6A08D15D688' \
                   '7E79F32B132E1C134E9525EEDDD744FA'
        self.assertEqual(hexlify(out).upper(), expected)


if __name__ == '__main__':
    unittest.main()
