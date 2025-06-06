"""A wallycore version of https://github.com/trezor/python-mnemonic"""
import wallycore

BIP39_ENTROPY_LEN_128 = wallycore.BIP39_ENTROPY_LEN_128
BIP39_ENTROPY_LEN_160 = wallycore.BIP39_ENTROPY_LEN_160
BIP39_ENTROPY_LEN_192 = wallycore.BIP39_ENTROPY_LEN_192
BIP39_ENTROPY_LEN_224 = wallycore.BIP39_ENTROPY_LEN_224
BIP39_ENTROPY_LEN_256 = wallycore.BIP39_ENTROPY_LEN_256

class Mnemonic(object):

    def __init__(self, language):
        self.wordlist = wallycore.bip39_get_wordlist(language)


    @staticmethod
    def list_languages():
        return wallycore.bip39_get_languages().split()


    def generate(self, strength = wallycore.BIP39_ENTROPY_LEN_128):
        from os import urandom
        return self.to_mnemonic(bytearray(urandom(strength)))


    def to_entropy(self, words):
        if isinstance(words, list):
            words = ' '.join(words)
        return wallycore.bip39_mnemonic_to_bytes(self.wordlist, words)


    def to_mnemonic(self, data):
        return wallycore.bip39_mnemonic_from_bytes(self.wordlist, data)


    def check(self, mnemonic):
        wallycore.bip39_mnemonic_validate(self.wordlist, mnemonic)


    def to_seed(self, mnemonic, passphrase = ''):
        return wallycore.bip39_mnemonic_to_seed512(mnemonic, passphrase)


if __name__ == "__main__":
    # Just make sure the basics work
    for lang in Mnemonic.list_languages():
        m = Mnemonic(lang)
        phrase = m.generate()
        m.check(phrase)
        try:
            m.generate(BIP39_ENTROPY_LEN_256 - 1)
            assert False
        except Exception as _:
            pass
        try:
            m.check(phrase + ' foo')
            assert False
        except Exception as _:
            pass
        assert m.to_entropy(phrase) == m.to_entropy(phrase.split())
        assert m.to_mnemonic(m.to_entropy(phrase)) == phrase
        assert m.to_seed(phrase, 'foo') != m.to_seed(phrase, 'bar')

