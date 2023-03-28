import json
import unittest
from util import *

FLAG_ECDSA, FLAG_SCHNORR, FLAG_GRIND_R, FLAG_RECOVERABLE = 1, 2, 4, 8
EC_PRIV_KEY_LEN, EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_UNCOMPRESSED_LEN = 32, 33, 65
EC_SIGNATURE_LEN, EC_SIGNATURE_RECOVERABLE_LEN, EC_SIGNATURE_DER_MAX_LEN = 64, 65, 72
EC_SCALAR_LEN = 32
BITCOIN_MESSAGE_HASH_FLAG = 1

class SignTests(unittest.TestCase):

    def get_sign_cases(self):
        lines = []
        with open(root_dir + 'src/data/ecdsa_secp256k1_vectors.txt', 'r') as f:
            for l in f.readlines():
                if len(l.strip()) and not l.startswith('#'):
                    lines.append(self.cbufferize(l.strip().split(',')))
        return lines

    def get_bip340_sign_cases(self):
        with open(root_dir + 'src/data/schnorr_secp256k1_vectors.json', 'r') as f:
            return json.load(f)

    def cbufferize(self, values):
        conv = lambda v: make_cbuffer(v)[0] if type(v) is str else v
        return [conv(v) for v in values]

    def sign(self, priv_key, msg, flags, out_buf, out_len=None, aux=None, aux_len=None):
        blen = lambda b: 0 if b is None else len(b)
        out_len = blen(out_buf) if out_len is None else out_len
        aux_len = blen(aux) if aux_len is None else aux_len
        if aux or aux_len:
            return wally_ec_sig_from_bytes_aux(priv_key, blen(priv_key),
                                               msg, blen(msg), aux, aux_len,
                                               flags, out_buf, out_len)
        return wally_ec_sig_from_bytes(priv_key, blen(priv_key),
                                       msg, blen(msg), flags, out_buf, out_len)

    def test_sign_and_verify(self):
        sig, sig2, sig_low_r = self.cbufferize(['00' * EC_SIGNATURE_LEN] * 3)
        der, der_len = make_cbuffer('00' * EC_SIGNATURE_DER_MAX_LEN)

        for case in self.get_sign_cases():
            priv_key, msg, nonce, r, s = case

            if wally_ec_private_key_verify(priv_key, len(priv_key)) != WALLY_OK:
                # Some test vectors have invalid private keys which other
                # libraries allow. secp fails these keys so don't test them.
                continue

            # Sign
            set_fake_ec_nonce(nonce)
            ret = self.sign(priv_key, msg, FLAG_ECDSA, sig)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(h(r), h(sig[0:32]))
            self.assertEqual(h(s), h(sig[32:64]))
            ret = wally_ec_sig_from_bytes_len(priv_key, len(priv_key),
                                              msg, len(msg), FLAG_ECDSA)
            self.assertEqual(ret, (WALLY_OK, EC_SIGNATURE_LEN))


            # Also sign with low-R grinding
            set_fake_ec_nonce(None)
            ret = self.sign(priv_key, msg, FLAG_ECDSA|FLAG_GRIND_R, sig_low_r)
            self.assertEqual(ret, WALLY_OK)

            # Check signature conversions
            ret, written = wally_ec_sig_to_der(sig, len(sig), der, der_len)
            self.assertEqual(ret, WALLY_OK)
            ret = wally_ec_sig_from_der(der, written, sig2, len(sig2))
            self.assertEqual((ret, h(sig)), (WALLY_OK, h(sig2)))
            ret = wally_ec_sig_normalize(sig2, len(sig2), sig, len(sig))
            self.assertEqual((ret, h(sig)), (WALLY_OK, h(sig2))) # All sigs low-s

            # Verify
            pub_key, _ = make_cbuffer('00' * 33)
            ret = wally_ec_public_key_from_private_key(priv_key, len(priv_key),
                                                       pub_key, len(pub_key))
            self.assertEqual(ret, WALLY_OK)
            for s in [sig, sig_low_r]:
                ret = wally_ec_sig_verify(pub_key, len(pub_key), msg, len(msg),
                                          FLAG_ECDSA, s, len(s))
                self.assertEqual(ret, WALLY_OK)

            # Validate public key
            pub_unc, _ = make_cbuffer('00' * 65)
            ret = wally_ec_public_key_decompress(pub_key, len(pub_key), pub_unc, len(pub_unc))
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(wally_ec_public_key_verify(pub_key, len(pub_key)), WALLY_OK)
            self.assertEqual(wally_ec_public_key_verify(pub_unc, len(pub_unc)), WALLY_OK)

        set_fake_ec_nonce(None)


    def test_invalid_inputs(self):
        out_buf, out_len = make_cbuffer('00' * EC_SIGNATURE_LEN)

        priv_key, msg = self.cbufferize(['11' * 32, '22' * 32])
        priv_bad, msg_bad = self.cbufferize(['FF' * 32, '22' * 33])
        FLAGS_BOTH, FLAGS_BAD = FLAG_ECDSA | FLAG_SCHNORR, FLAG_ECDSA | 0x20
        FLAGS_R = FLAG_ECDSA | FLAG_RECOVERABLE
        FLAGS_G = FLAG_ECDSA | FLAG_GRIND_R
        FLAGS_SR = FLAG_SCHNORR | FLAG_RECOVERABLE
        FLAGS_SG = FLAG_SCHNORR | FLAG_GRIND_R

        # Signing
        aux, aux_len = make_cbuffer('00' * 32)
        for args in [
            (None,         msg,     FLAG_ECDSA,  out_buf),     # Null priv_key
            (('11' * 33),  msg,     FLAG_ECDSA,  out_buf),     # Wrong priv_key len
            (priv_bad,     msg,     FLAG_ECDSA,  out_buf),     # Bad private key
            (priv_key,     None,    FLAG_ECDSA,  out_buf),     # Null message
            (priv_key,     msg_bad, FLAG_ECDSA,  out_buf),     # Wrong message len
            (priv_key,     msg,     0,           out_buf),     # No flags set
            (priv_key,     msg,     FLAGS_BOTH,  out_buf),     # Mutually exclusive
            (priv_key,     msg,     FLAGS_SR,    out_buf),     # Mutually exclusive
            (priv_key,     msg,     FLAGS_SG,    out_buf),     # Mutually exclusive
            (priv_key,     msg,     FLAGS_BAD,   out_buf),     # Unknown flag
            (priv_key,     msg,     FLAG_ECDSA,  out_buf, 65), # Bad output len
            (priv_key,     msg,     FLAGS_R,     out_buf, 64), # Bad recoverable output len
            (priv_key,     msg,     FLAG_ECDSA,  out_buf, 64, None, 32), # NULL aux
            (priv_key,     msg,     FLAG_ECDSA,  out_buf, 64, aux,  16),  # Bad aux len
            (priv_key,     msg,     FLAGS_G,     out_buf, 64, aux,  32),  # Can't grind w/aux
            ]:
            self.assertEqual(self.sign(*args), WALLY_EINVAL)

        for o, o_len in [(None, 32), (out_buf, -1)]: # Null out, Wrong out len
            ret = self.sign(priv_key, msg, FLAG_ECDSA, o, o_len)
            self.assertEqual(ret, WALLY_EINVAL)

        # wally_ec_private_key_verify
        for pk, pk_len in  [(None,     len(priv_key)),  # Null priv_key
                            (priv_key, 10),             # Wrong priv_key len
                            (priv_bad, len(priv_key))]: # Bad private key
            self.assertEqual(wally_ec_private_key_verify(pk, pk_len), WALLY_EINVAL)

        # wally_ec_public_key_verify
        pub_key, _ = make_cbuffer('02' + '22' * 32)
        pub_bad, _ = make_cbuffer('02' + '00' * 32)
        for pub, pub_len in [(None, len(pub_key)),     # Null pub_key
                             (pub_key, 32),            # Wrong pub_key len
                             (pub_bad, len(pub_key))]: # Bad public key
            self.assertEqual(wally_ec_public_key_verify(pub, pub_len), WALLY_EINVAL)

        # wally_ec_public_key_decompress
        pub, _ = make_cbuffer('02' + '22' * 32)
        out_buf, out_len = make_cbuffer('00' * EC_PUBLIC_KEY_UNCOMPRESSED_LEN)

        cases = [(None, len(pub), out_buf, out_len), # Null pub
                 (pub,  32,       out_buf, out_len), # Wrong pub len
                 (pub,  len(pub), None, out_len),    # Null out
                 (pub,  len(pub), out_buf, 64)]      # Wrong out len

        for p, p_len, o, o_len in cases:
            ret = wally_ec_public_key_decompress(p, p_len, o, o_len)
            self.assertEqual(ret, WALLY_EINVAL)

        # wally_ec_xonly_public_key_verify
        pub_key = pub_key[1:]
        pub_bad, pub_bad[1:]
        for pub, pub_len in [(None, len(pub_key)),     # Null pub_key
                             (pub_key, 31),            # Wrong pub_key len
                             (pub_bad, len(pub_key))]: # Bad public key
            self.assertEqual(wally_ec_xonly_public_key_verify(pub, pub_len), WALLY_EINVAL)
        self.assertEqual(wally_ec_xonly_public_key_verify(pub_key, len(pub_key)), WALLY_OK)


        # wally_ec_sig_to_der
        sig, _ = make_cbuffer('13' * EC_SIGNATURE_LEN)
        out_buf, out_len = make_cbuffer('00' * EC_SIGNATURE_DER_MAX_LEN)

        cases = [(None, len(sig), out_buf, out_len), # Null sig
                 (sig,  15,       out_buf, out_len), # Wrong sig len
                 (sig,  len(sig), None, out_len),    # Null out
                 (sig,  len(sig), out_buf, 15)]      # Wrong out len

        for s, s_len, o, o_len in cases:
            ret, written = wally_ec_sig_to_der(s, s_len, o, o_len)
            self.assertEqual((ret, written), (WALLY_EINVAL, 0))

        # wally_ec_public_key_from_private_key
        out_buf, out_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        cases = [(None,     len(priv_key),   out_buf, len(out_buf)), # Null priv_key
                 (priv_key, 10,              out_buf, len(out_buf)), # Wrong priv_key len
                 (priv_bad, len(priv_key),   out_buf, len(out_buf)), # Bad private key
                 (priv_key, len(priv_key),   None,    len(out_buf)), # Null out
                 (priv_key, len(priv_key),   out_buf, 10)]           # Wrong out len

        for pk, pk_len, o, o_len in cases:
            ret = wally_ec_public_key_from_private_key(pk, pk_len, o, o_len);
            self.assertEqual(ret, WALLY_EINVAL)


    def test_format_message(self):
        PREFIX, MAX_LEN = b'\x18Bitcoin Signed Message:\n', 64 * 1024 - 64
        out_buf, out_len = make_cbuffer('00' * 64 * 1024)
        cases = [(b'a',           b'\x01'),
                 (b'aaa',         b'\x03'),
                 (b'a' * 252,     b'\xfc'),
                 (b'a' * 253,     b'\xfd\xfd\x00'),
                 (b'a' * 254,     b'\xfd\xfe\x00'),
                 (b'a' * 255,     b'\xfd\xff\x00'),
                 (b'a' * 256,     b'\xfd\x00\x01'),
                 (b'a' * 257,     b'\xfd\x01\x01'),
                 (b'a' * MAX_LEN, b'\xfd\xc0\xff')]
        for msg, varint, in cases:
            fn = lambda flags, ol: wally_format_bitcoin_message(msg, len(msg), flags,
                                                            out_buf, ol)
            for flags in (0, BITCOIN_MESSAGE_HASH_FLAG):
                expected = PREFIX + varint + msg
                if flags:
                    buf, buf_len = make_cbuffer('00'*32)
                    self.assertEqual(WALLY_OK, wally_sha256d(expected, len(expected), buf, buf_len))
                    expected = buf

                ret, written = fn(flags, out_len)
                self.assertEqual((ret, written), (WALLY_OK, len(expected)))
                self.assertEqual(out_buf[:written], expected)

                ret, written = fn(flags, 1) # Short length
                self.assertEqual((ret, written), (WALLY_OK, len(expected)))


        # Invalid cases
        msg = 'a'
        cases = [(None, len(msg),    0, out_buf, out_len), # Null message
                 (msg,  0,           0, out_buf, out_len), # Zero length message
                 (msg,  MAX_LEN + 1, 0, out_buf, out_len), # Message too large
                 (msg,  len(msg),    2, out_buf, out_len), # Bad flags
                 (msg,  len(msg),    0, None,    out_len)] # Null output
        for msg, msg_len, flags, o, o_len in cases:
            ret, written = wally_format_bitcoin_message(msg, msg_len, flags, o, o_len)
            self.assertEqual(ret, WALLY_EINVAL)


    def test_recoverable_sig(self):
        priv_key, msg, out1, out2, pub_key, pub_key_rec = self.cbufferize(
            ['11' * 32, '22' * 32, '00' * 65, '00' * 64, '00' * 32, '00' * 32])

        flags = FLAG_ECDSA | FLAG_RECOVERABLE
        self.assertEqual(WALLY_OK, self.sign(priv_key, msg, flags, out1))
        ret = wally_ec_sig_from_bytes_len(priv_key, len(priv_key),
                                          msg, len(msg), flags)
        self.assertEqual(ret, (WALLY_OK, EC_SIGNATURE_RECOVERABLE_LEN))


        self.assertEqual(WALLY_OK, wally_ec_public_key_from_private_key(
            priv_key, 32, pub_key, 33))
        i = 1 if h(pub_key[:1]) == '02' else 0
        self.assertEqual(27 + i + 4, int(h(out1[:1]), 16))

        flags = FLAG_ECDSA
        self.assertEqual(WALLY_OK, self.sign(priv_key, msg, flags, out2))

        self.assertEqual(out1[1:], out2)

        self.assertEqual(WALLY_OK, wally_ec_sig_to_public_key(msg, 32, out1, 65, pub_key_rec, 33))
        self.assertEqual(pub_key, pub_key_rec)

        self.assertEqual(WALLY_OK, wally_ec_sig_verify(pub_key, 33, msg, 32, FLAG_ECDSA, out2, 64))
        self.assertEqual(WALLY_EINVAL, wally_ec_sig_verify(pub_key, 33, msg, 32, FLAG_ECDSA, out1, 65))
        self.assertEqual(WALLY_OK, wally_ec_sig_verify(pub_key, 33, msg, 32, FLAG_ECDSA, out1[1:], 64))

        # Invalid cases
        aux, aux_len = make_cbuffer('00' * 32)
        flags = FLAG_ECDSA | FLAG_RECOVERABLE
        for args in [
            (priv_key, msg, FLAG_RECOVERABLE, out1, 65, None),                # No singing algorithm
            (priv_key, msg, FLAG_ECDSA, out1, 65, None),                      # Incorrect output len
            (priv_key, msg, flags, out1, 64, None),                           # Incorrect output len
            (priv_key, msg, FLAG_SCHNORR | FLAG_RECOVERABLE, out1, 65, None), # Mutually exclusive
            (priv_key, msg, FLAG_SCHNORR | FLAG_GRIND_R, out1, 65, None),     # Mutually exclusive
            (priv_key, msg, flags, out1, 65, None, 32),                       # NULL aux
            (priv_key, msg, flags, out1, 65, aux, 33),                        # Bad aux len
            (priv_key, msg, flags | FLAG_GRIND_R, out1, 65, aux, 32),         # Can't grind w/aux
            ]:
            self.assertEqual(WALLY_EINVAL, self.sign(*args))

        for args in [
            (None, 32, out1, 65, pub_key, 33),      # Missing message
            (msg, 31, out1, 65, pub_key, 33),       # Incorrect messsage length
            (msg, 32, None, 65, pub_key, 33),       # Missing signature
            (msg, 32, out1, 64, pub_key, 33),       # Incorrect signature length
            (msg, 32, out1, 65, None, 33),          # Missing pubkey
            (msg, 32, out1, 65, pub_key, 32),       # Incorrect pubkey length
            (priv_key, 32, out1, 65, pub_key, 32),  # Incorrect signature
            ]:
            self.assertEqual(WALLY_EINVAL, wally_ec_sig_to_public_key(*args))

    @unittest.skipUnless(wally_s2c_sig_from_bytes, "s2c module not enabled")
    def test_s2c(self):
        priv_key, pub_key, msg, s2c_data, sig_out, s2c_opening_out = self.cbufferize(
            ['11' * 32, '00' * 32, '22' * 32, '33' * 32, '00' * 64, '00' * 33])

        flags = FLAG_ECDSA

        self.assertEqual(WALLY_OK, wally_s2c_sig_from_bytes(priv_key, 32, msg, 32, s2c_data, 32, flags, s2c_opening_out, 33, sig_out, 64))

        self.assertEqual(WALLY_OK, wally_ec_public_key_from_private_key(priv_key, 32, pub_key, 33))
        self.assertEqual(WALLY_OK, wally_ec_sig_verify(pub_key, 33, msg, 32, flags, sig_out, 64))

        self.assertEqual(WALLY_OK, wally_s2c_commitment_verify(sig_out, 64, s2c_data, 32, s2c_opening_out, 33, flags))

        # Invalid cases
        for args in [
            (None,     32, msg,  32, s2c_data, 32, flags, s2c_opening_out, 33, sig_out, 64), # Missing privkey
            (priv_key, 31, msg,  32, s2c_data, 32, flags, s2c_opening_out, 33, sig_out, 64), # Incorrect privkey length
            (priv_key, 32, None, 32, s2c_data, 32, flags, s2c_opening_out, 33, sig_out, 64), # Missing message
            (priv_key, 32, msg,  31, s2c_data, 32, flags, s2c_opening_out, 33, sig_out, 64), # Incorrect message length
            (priv_key, 32, msg,  32, None,     32, flags, s2c_opening_out, 33, sig_out, 64), # Missing s2c data
            (priv_key, 32, msg,  32, s2c_data, 31, flags, s2c_opening_out, 33, sig_out, 64), # Incorrect s2c data length
            (priv_key, 32, msg,  32, s2c_data, 32, 0,     s2c_opening_out, 33, sig_out, 64), # Unsupported flags
            (priv_key, 32, msg,  32, s2c_data, 32, flags, None,            33, sig_out, 64), # Missing s2c opening
            (priv_key, 32, msg,  32, s2c_data, 32, flags, s2c_opening_out, 32, sig_out, 64), # Incorrect s2c opening length
            (priv_key, 32, msg,  32, s2c_data, 32, flags, s2c_opening_out, 33, None,    64), # Missing sig
            (priv_key, 32, msg,  32, s2c_data, 32, flags, s2c_opening_out, 33, sig_out, 63), # Incorrect sig length
            ]:
            self.assertEqual(WALLY_EINVAL, wally_s2c_sig_from_bytes(*args))

        inv_sig, inv_s2c_data, inv_s2c_opening = self.cbufferize(
            ['ff' * 64, 'ff' * 32, 'ff' * 33])

        for args in [
            (None,    64, s2c_data,     32, s2c_opening_out, 33, flags), # Missing signature
            (sig_out, 63, s2c_data,     32, s2c_opening_out, 33, flags), # Incorrect signature length
            (inv_sig, 64, s2c_data,     32, s2c_opening_out, 33, flags), # Invalid signature
            (sig_out, 64, None,         32, s2c_opening_out, 33, flags), # Missing s2c data
            (sig_out, 64, s2c_data,     31, s2c_opening_out, 33, flags), # Incorrect s2c data length
            (sig_out, 64, inv_s2c_data, 32, s2c_opening_out, 33, flags), # Invalid s2c data
            (sig_out, 64, s2c_data,     32, None,            33, flags), # Missing s2c opening
            (sig_out, 64, s2c_data,     32, s2c_opening_out, 32, flags), # Incorrect s2c opening length
            (sig_out, 64, s2c_data,     32, inv_s2c_opening, 33, flags), # Invalid s2c opening
            (sig_out, 64, s2c_data,     32, s2c_opening_out, 33, 0),     # Unsupported flags
            ]:
            self.assertEqual(WALLY_EINVAL, wally_s2c_commitment_verify(*args))

    def test_scalar(self):
        _, is_elements_build = wally_is_elements_build()

        zero_hex = '00' * EC_SCALAR_LEN
        scalar_hex = '3d41893225bf4c2ba903d157cd97dd2f6d330272e08a120f497f0dc0618d3fd1'
        zero, scalar, bad = self.cbufferize([zero_hex, scalar_hex, 'FF' * EC_SCALAR_LEN])
        out, out_len = make_cbuffer(zero_hex)

        def add(x, y):
            ret = wally_ec_scalar_add(x, EC_SCALAR_LEN, y, EC_SCALAR_LEN, out, out_len)
            return ret, wally_hex_from_bytes(out, out_len)[1]

        def sub(x, y):
            ret = wally_ec_scalar_subtract(x, EC_SCALAR_LEN, y, EC_SCALAR_LEN, out, out_len)
            return ret, wally_hex_from_bytes(out, out_len)[1]

        def mul(x, y):
            ret = wally_ec_scalar_multiply(x, EC_SCALAR_LEN, y, EC_SCALAR_LEN, out, out_len)
            return ret, wally_hex_from_bytes(out, out_len)[1]

        for fn in [add, sub]:
            self.assertEqual(fn(None, zero), (WALLY_EINVAL, zero_hex))
            self.assertEqual(fn(zero, None), (WALLY_EINVAL, zero_hex))

        _, negative_hex = sub(zero, scalar)
        negative = unhexlify(negative_hex)

        self.assertEqual(add(None, zero), (WALLY_EINVAL, zero_hex))
        self.assertEqual(add(zero, None), (WALLY_EINVAL, zero_hex))
        self.assertEqual(add(zero, bad), (WALLY_ERROR, zero_hex)) # WALLY_ERROR = scalar not in n
        self.assertEqual(add(bad, zero), (WALLY_ERROR, zero_hex))
        self.assertEqual(add(zero, zero), (WALLY_OK, zero_hex))
        self.assertEqual(add(zero, scalar), (WALLY_OK, scalar_hex))
        self.assertEqual(add(zero, negative), (WALLY_OK, negative_hex))
        self.assertEqual(add(negative, zero), (WALLY_OK, negative_hex))
        self.assertEqual(add(negative, scalar), (WALLY_OK, zero_hex))
        self.assertEqual(add(scalar, zero), (WALLY_OK, scalar_hex))
        self.assertEqual(add(scalar, negative), (WALLY_OK, zero_hex))

        # Test scalar addition identity to asset_final_vbf
        def add_by_final_vbf(a_hex, b_hex):
            values = (c_uint64 * 3)(1, 2, 3)
            abfs, abfs_len = make_cbuffer('00' * 32 * 3)
            vbfs, vbfs_len = make_cbuffer(a_hex + b_hex)
            ret = wally_asset_final_vbf(values, 3, 2, abfs, abfs_len, vbfs, vbfs_len, out, out_len)
            return ret, wally_hex_from_bytes(out, out_len)[1]
        if is_elements_build:
            self.assertEqual(add(scalar, scalar), add_by_final_vbf(scalar_hex, scalar_hex))

        self.assertEqual(sub(None, zero), (WALLY_EINVAL, zero_hex))
        self.assertEqual(sub(zero, None), (WALLY_EINVAL, zero_hex))
        self.assertEqual(add(zero, bad), (WALLY_ERROR, zero_hex))
        self.assertEqual(add(bad, zero), (WALLY_ERROR, zero_hex))
        self.assertEqual(sub(zero, zero), (WALLY_OK, zero_hex))
        self.assertEqual(sub(zero, scalar), (WALLY_OK, negative_hex))
        self.assertEqual(sub(zero, negative), (WALLY_OK, scalar_hex))
        self.assertEqual(sub(negative, zero), (WALLY_OK, negative_hex))
        self.assertEqual(sub(scalar, zero), (WALLY_OK, scalar_hex))
        self.assertEqual(sub(scalar, scalar), (WALLY_OK, zero_hex))

        self.assertEqual(mul(None, zero), (WALLY_EINVAL, zero_hex))
        self.assertEqual(mul(zero, None), (WALLY_EINVAL, zero_hex))
        self.assertEqual(mul(zero, bad), (WALLY_ERROR, zero_hex))
        self.assertEqual(mul(bad, zero), (WALLY_ERROR, zero_hex))
        self.assertEqual(mul(zero, zero), (WALLY_OK, zero_hex))
        self.assertEqual(mul(zero, scalar), (WALLY_OK, zero_hex))
        self.assertEqual(mul(zero, negative), (WALLY_OK, zero_hex))

    def test_bip340_sigs(self):

        num_tests_run = 0
        sig_out, sig_out_len = make_cbuffer('00' * EC_SIGNATURE_LEN)

        for case in self.get_bip340_sign_cases():
            priv_key, priv_key_len = make_cbuffer(case['priv_key'])
            pub_key, pub_key_len = make_cbuffer(case['pub_key'])
            aux_rand, aux_rand_len = make_cbuffer(case['aux_rand'])
            msg, msg_len = make_cbuffer(case['msg'])
            sig, sig_len = make_cbuffer(case['sig'])
            is_valid = case['is_valid']


            if priv_key_len == EC_PRIV_KEY_LEN:
                num_tests_run += 1
                flags = FLAG_SCHNORR
                ret = self.sign(priv_key, msg, flags, sig_out, None, aux_rand)
                self.assertEqual(ret, WALLY_OK)
                self.assertEqual(sig, sig_out)

                ret = wally_ec_sig_from_bytes_len(priv_key, priv_key_len,
                                                  msg, msg_len, FLAG_SCHNORR)
                self.assertEqual(ret, (WALLY_OK, EC_SIGNATURE_LEN))

                # Wrong size privkey
                ret = wally_ec_sig_from_bytes_len(priv_key, priv_key_len - 1,
                                                  msg, msg_len, FLAG_SCHNORR)
                self.assertEqual(ret, (WALLY_EINVAL, 0))

                # TODO support wally_ec_public_key_from_private_key with bip340 keys to check priv_key -> pub_key

            ret = wally_ec_sig_verify(pub_key, pub_key_len, msg, msg_len, FLAG_SCHNORR, sig, sig_len)
            self.assertEqual(ret == WALLY_OK, is_valid)

            # Wrong signature type
            ret = wally_ec_sig_verify(pub_key, pub_key_len, msg, msg_len, FLAG_ECDSA, sig, sig_len)
            self.assertEqual(ret, WALLY_EINVAL)

            # Wrong size pubkey
            ret = wally_ec_sig_verify(pub_key, pub_key_len - 1, msg, msg_len, FLAG_SCHNORR, sig, sig_len)
            self.assertEqual(ret, WALLY_EINVAL)

        self.assertGreater(num_tests_run, 0)


if __name__ == '__main__':
    unittest.main()
