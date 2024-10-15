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

# BIP85/RSA Vectors generated using https://github.com/akarve/bipsea/blob/main/tests/test_bip85.py#L127
rsa_cases = [
        ('b3415a819ba8175a7f11b949d75133725594ee3dcf6284dbec8fe6a625d0e0df757c148e576369f9405b19aec9356a848897de64202df8da4880a5f769aac297', 1024, 0),
        ('ca1e93031427e4f086538f89b19f5f224719332c8a7b8c87db7eb81e4be935db24dcbc71873d0607ddd3876777cd158a2f061a5a5153413307df08fe5911a857', 1024, 1),
        ('e3ff02b1f0b934357cc0952225bb0e90081005b0cc992c5ed22f6fb8e9c628a3a0f138f9324e33ed4ba7250e43dd66d725a4e4c683dcf5a3b4015b82bcf71934', 2048, 0),
        ('b1b4d03eb9826aeb2fabc4529dc37da5eaaa9072d3e2b7e69da79862e2b9cd8131dbb5a9001612239cd96310f6be0417bd39c39500bf8a99ba5df32571866fe6', 2048, 1),
        ('9bd8cb61fea01892ffd981b4da7aae22f32c9641e49c48104682e249a98f7911ed55035a52e085938291d64e34537e9cc0b730f42ae9183b5ddaac33a55764ea', 3072, 0),
        ('fc49330db1352558f615651ae8d7840b083cce5c9e731e349847569d3813a3f7f605b5d66b178bf19fdd04bd7f48d2ddb07e16793703d17ee06c86e49e19a896', 3072, 1),
        ('12a499947a142ee3ede9c0960061383f2564b5cc569327d0dd22f7887094676f2e5d5785cd4eb683990d12209ebf6f39a5c1b5e217ea66710260e99fbe4b2be3', 4096, 0),
        ('a6fdf91d4f4a0cadaf3d20d638744b574306725aababa0ab7136f8f8b88c5a4c5ca6104646d695cd95a72ad15e6e6912e263762eab951bfcea8e9939ed7c03f4', 4096, 1),
        ('b3a0baa54a6fa75363e2bc0809dafd20eacea8b4d0fba9ef26f9ea9c471e135c53c1f787fd6a7a02bf736bed620d44e5b4465856fae6c2ef2d620b730098f8e9', 8192, 0),
        ('1b5f1ae261e9e36039cd7d55d25e71934a4f0a2fdd2d93b2f73fbd272d04257d6eba8f6ff6bc1ffe1d58f68b707b794e54e983e2f573991bb776b48b8ed9a1ca', 8192, 1),
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

    def run_bip39_test_cases(self, master_key, cases):
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

    def run_rsa_test_cases(self, master_key, rsa_cases):
        buf = create_string_buffer(HMAC_SHA512_LEN)
        for expected, key_bits, index in rsa_cases:
            ret = bip85_get_rsa_entropy(master_key, key_bits, index, buf, HMAC_SHA512_LEN)
            self.assertEqual(ret, (WALLY_OK, HMAC_SHA512_LEN))
            self.assertEqual(h(buf[:HMAC_SHA512_LEN]), utf8(expected))

    def test_bip85_cases(self):
        self.run_bip39_test_cases(self.master_key, cases)
        self.run_rsa_test_cases(self.master_key, rsa_cases)

    def test_additional_cases(self):
        extra_key = ext_key()
        ret = bip32_key_from_base58(utf8(extra_xpriv), byref(extra_key))
        self.assertEqual(ret, WALLY_OK)
        self.run_bip39_test_cases(extra_key, extra_cases)

if __name__ == '__main__':
    unittest.main()
