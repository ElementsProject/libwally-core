from ctypes import *

libwally = CDLL('bld/libwally.so')

wordlist_funcs = [('wordlist_init', c_void_p, [c_char_p, c_char]),
                  ('wordlist_lookup_word', c_ulong, [c_void_p, c_char_p]),
                  ('wordlist_lookup_index', c_char_p, [c_void_p, c_ulong]),
                  ('wordlist_free', None, [c_void_p])]

mnemonic_funcs = [('mnemonic_from_bytes', c_char_p, [c_void_p, c_void_p, c_ulong]),
                  ('mnemonic_to_bytes', c_int, [c_void_p, c_char_p, c_void_p, c_ulong])]

bip39_funcs = [('bip39_default_wordlist', c_void_p, []),
               ('bip39_get_wordlist', c_void_p, [c_char_p]),
               ('bip39_mnemonic_from_bytes', c_char_p, [c_void_p, c_void_p, c_ulong])]


def bind_fn(name, res, args):
    fn = getattr(libwally, name)
    fn.restype, fn.argtypes = res, args
    return fn


def bind_all(dest, funcs):
    for f in funcs:
        name, restype, argtypes = f
        setattr(dest, name, bind_fn(name, restype, argtypes))


def load_words(lang):
    with open('data/wordlists/%s.txt' % lang, 'r') as f:
        words_list = [l.strip() for l in f.readlines()]
        return words_list, ' '.join(words_list)

