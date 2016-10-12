import unittest
from util import *

FLAG_ECDSA, FLAG_SCHNORR = 1, 2
EC_SIGNATURE_LEN = 64

class SignTests(unittest.TestCase):

    def get_sign_cases(self):
        lines = []
        with open(root_dir + 'src/data/ecdsa_secp256k1_vectors.txt', 'r') as f:
            for l in f.readlines():
                if len(l.strip()) and not l.startswith('#'):
                    lines.append(self.cbufferize(l.strip().split(',')))
        return lines

    def cbufferize(self, values):
        conv = lambda v: make_cbuffer(v)[0] if type(v) is str else v
        return [conv(v) for v in values]

    def sign(self, priv_key, msg, flags, out_buf, out_len=None):
        blen = lambda b: 0 if b is None else len(b)
        if out_len is None:
            out_len = blen(out_buf)
        return wally_ec_sign_hash(priv_key, blen(priv_key), msg, blen(msg),
                                  flags, out_buf, out_len)


    def test_sign_hash(self):
        out_buf, out_len = make_cbuffer('00' * EC_SIGNATURE_LEN)

        for case in self.get_sign_cases():
            priv_key, msg, nonce, r, s = case

            if wally_ec_private_key_verify(priv_key, len(priv_key)) != WALLY_OK:
                # Some test vectors have invalid private keys which other
                # libraries allow. secp fails these keys so don't test them.
                continue

            set_fake_ec_nonce(nonce)
            ret = self.sign(priv_key, msg, FLAG_ECDSA, out_buf)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(h(r), h(out_buf[0:32]))
            self.assertEqual(h(s), h(out_buf[32:64]))

        set_fake_ec_nonce(None)


    def test_sign_hash_invalid_inputs(self):
        out_buf, out_len = make_cbuffer('00' * EC_SIGNATURE_LEN)

        priv_ok, msg_ok = self.cbufferize(['11' * 32, '22' * 32])
        FLAGS_BOTH = FLAG_ECDSA | FLAG_SCHNORR
        bad_priv, _ = make_cbuffer('FF' * 32)

        cases = [(None,        msg_ok,      FLAG_ECDSA),   # Null priv_key
                 (('11' * 33), msg_ok,      FLAG_ECDSA),   # Wrong priv_key len
                 (bad_priv,    msg_ok,      FLAG_ECDSA),   # Bad private key
                 (priv_ok,     None,        FLAG_ECDSA),   # Null message
                 (priv_ok,     ('11' * 33), FLAG_ECDSA),   # Wrong message len
                 (priv_ok,     msg_ok,      0),            # No flags set
                 (priv_ok,     msg_ok,      FLAG_SCHNORR), # Not implemented
                 (priv_ok,     msg_ok,      FLAGS_BOTH),   # Mutually exclusive
                 (priv_ok,     msg_ok,      0x4)]          # Unknown flag

        for case in cases:
            priv_key, msg, flags = case
            ret = self.sign(priv_key, msg, flags, out_buf)
            self.assertEqual(ret, WALLY_EINVAL)

        for o, l in [(None, 32), (out_buf, -1)]: # Invalid out/out length
            ret = self.sign(priv_ok, msg_ok, FLAG_ECDSA, o, l)
            self.assertEqual(ret, WALLY_EINVAL)


if __name__ == '__main__':
    unittest.main()
