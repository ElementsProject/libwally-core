import unittest
from util import *

HMAC_SHA512_LEN = 64
BIP39_ENTROPY_LEN_128 = 16
BIP39_ENTROPY_LEN_192 = 24
BIP39_ENTROPY_LEN_256 = 32

# BIP85/BIP39 Vectors from
# https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#bip39
master_xpriv = 'xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb'
cases = [
    ('en', 12, 0, '6250b68daf746d12a24d58b4787a714b',
     'girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose'),
    ('en', 18, 0, '938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc',
     'near account window bike charge season chef number sketch tomorrow excuse '
     'sniff circle vital hockey outdoor supply token'),
    ('en', 24, 0, 'ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f',
     'puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget '
     'divorce twin tonight reason outdoor destroy simple truth cigar social volcano')
]

# Additional test vectors
extra_xpriv = 'xprv9s21ZrQH143K3pHDnUsnBxePpiB3pbhu3owZem9cVUPVQLknjYAhzDXGppVipPsLSnx8UM6cmSqh3nG6vUaPxn1EDNNqtF1eqi7XmdLt1v6'
extra_cases = [
    ('en', 12, 0, '47dc1ab842553d94010a46a1f3a8ac91',
     'elephant this puppy lucky fatigue skate aerobic emotion peanut outer clinic casino'),
    ('en', 12, 12, 'aa510a2ccece5dc8aac2acdc45a6ab5f',
     'prevent marriage menu outside total tone prison few sword coffee print salad'),
    ('en', 12, 100, '8407f990218dd148bfdefdd5510881f1',
     'lottery divert goat drink tackle picture youth text stem marriage call tip'),
    ('en', 12, 65535, '3621194f64b7622f0f12e492da0f279b',
     'curtain angle fatigue siren involve bleak detail frame name spare size cycle'),

    ('en', 24, 0, '25a04e7c88fa6dc10ffad42b0d1ba8ba9285a4d97e05285a4793f59079e455f6',
     'certain act palace ball plug they divide fold climb hand tuition inside choose '
     'sponsor grass scheme choose split top twenty always vendor fit thank'),
    ('en', 24, 24, '591141467e96886394df2903a4345811080411d4b30240e9f68459d97ada6ddb',
     'flip meat face wood hammer crack fat topple admit canvas bid capital leopard '
     'angry fan gate domain exile patient recipe nut honey resist inner'),
    ('en', 24, 1024, 'a38c83e876c83512efcda1c11355a6e8ff887c02700fad6e555ff5f115ae34d2',
     'phone goat wheel unique local maximum sand reflect scissors one have spin weasel '
     'dignity antenna acid pulp increase fitness typical bacon strike spy festival'),
    ('en', 24, 65535, '6ef235952bffe1f6d753c0af7dd2e532e5f46f05c99be6d7b79aa2c60e33613d',
     'humble museum grab fitness wrap window front job quarter update rich grape gap '
     'daring blame cricket traffic sad trade easily genius boost lumber rhythm')
]

class BIP85Tests(unittest.TestCase):

    langs = [ 'en', 'jp', 'kr', 'es', 'zhs', 'zht', 'fr', 'it', 'cz' ]
    words_entropy_len = { 12: BIP39_ENTROPY_LEN_128, 18: BIP39_ENTROPY_LEN_192, 24: BIP39_ENTROPY_LEN_256 }

    def setUp(self):
        key_out = ext_key()
        ret = bip32_key_from_base58(utf8(master_xpriv), byref(key_out))
        self.assertEqual(ret, WALLY_OK)
        self.master_key = key_out

    def test_get_langs(self):
        ret, fetched_langs = bip85_get_languages()
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(fetched_langs, ' '.join(self.langs))

    def test_langs(self):
        buf = create_string_buffer(HMAC_SHA512_LEN)
        for lang in self.langs:
            for nwords, expected_len in self.words_entropy_len.items():
                for index in range(0, 8):
                    ret = bip85_get_bip39_entropy(self.master_key, lang, nwords, index, buf, HMAC_SHA512_LEN)
                    self.assertEqual(ret, (WALLY_OK, expected_len))

    def test_default_lang(self):
        en_buf = create_string_buffer(HMAC_SHA512_LEN)
        default_buf = create_string_buffer(HMAC_SHA512_LEN)
        for index in range(0,8):
            for nwords, expected_len in self.words_entropy_len.items():
                for lang, buf in [('en', en_buf), (None, default_buf)]:
                    ret = bip85_get_bip39_entropy(self.master_key, lang, nwords, index, buf, HMAC_SHA512_LEN)
                    self.assertEqual(ret, (WALLY_OK, expected_len))

                self.assertEqual(h(default_buf[:expected_len]), h(en_buf[:expected_len]))

    def test_invalid(self):
        buf, buf_len = make_cbuffer('00' * HMAC_SHA512_LEN)
        bad_i = 0x80000000
        cases = [
            (None,            'en',  12, 0,     buf,  buf_len),   # Null key
            (self.master_key, 'bad', 12, 0,     buf,  buf_len),   # Unknown lang
            (self.master_key, 'en',  0,  0,     buf,  buf_len),   # Zero word len
            (self.master_key, 'en',  16, 0,     buf,  buf_len),   # Unknown word len
            (self.master_key, 'en',  12, bad_i, buf,  buf_len),   # Invalid index
            (self.master_key, 'en',  12, 0,     None, buf_len),   # Null output
            (self.master_key, 'en',  12, 0,     buf,  buf_len-1), # Bad output len
        ]
        for args in cases:
            ret, _ = bip85_get_bip39_entropy(*args)
            self.assertEqual(ret, WALLY_EINVAL)

    def run_test_cases(self, master_key, cases):
        ret, all_langs = bip39_get_languages()
        all_langs = all_langs.split()

        buf = create_string_buffer(HMAC_SHA512_LEN)
        for lang, nwords, index, expected, mnemonic in cases:
            ret = bip85_get_bip39_entropy(master_key, lang, nwords, index, buf, HMAC_SHA512_LEN)
            expected_len = self.words_entropy_len[nwords]
            self.assertEqual(ret, (WALLY_OK, expected_len))
            self.assertEqual(h(buf[:expected_len]), utf8(expected))

            # Check the resulting mnemonic
            if lang not in all_langs:
                continue # Minimal build only has English support
            words = c_void_p()
            ret = bip39_get_wordlist(lang, byref(words))
            self.assertEqual(ret, WALLY_OK)
            ret = bip39_mnemonic_from_bytes(words, buf, expected_len)
            self.assertEqual(ret, (WALLY_OK, mnemonic))

    def test_bip85_cases(self):
        self.run_test_cases(self.master_key, cases)

    def test_additional_cases(self):
        extra_key = ext_key()
        ret = bip32_key_from_base58(utf8(extra_xpriv), byref(extra_key))
        self.assertEqual(ret, WALLY_OK)
        self.run_test_cases(extra_key, extra_cases)

if __name__ == '__main__':
    unittest.main()
