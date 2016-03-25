from ctypes import *
import platform

root_dir = '../../'
SO_EXT = 'dylib' if platform.system() == 'Darwin' else 'so'

try:
    # Assume 'make test' is running a from the src/test/ directory
    libwally = CDLL(root_dir + 'src/.libs/libwallycore.' + SO_EXT)
except OSError:
    # Perhaps we are manually running a test from the root dir using
    # the full path
    libwally = CDLL('src/.libs/libwallycore.' + SO_EXT)
    root_dir = ''

wordlist_funcs = [('wordlist_init', c_void_p, [c_char_p]),
                  ('wordlist_lookup_word', c_ulong, [c_void_p, c_char_p]),
                  ('wordlist_lookup_index', c_char_p, [c_void_p, c_ulong]),
                  ('wordlist_free', None, [c_void_p])]

mnemonic_funcs = [('mnemonic_from_bytes', c_char_p, [c_void_p, c_void_p, c_ulong]),
                  ('mnemonic_to_bytes', c_ulong, [c_void_p, c_char_p, c_void_p, c_ulong])]

bip39_funcs = [('bip39_get_languages', c_char_p, []),
               ('bip39_get_wordlist', c_void_p, [c_char_p]),
               ('bip39_mnemonic_from_bytes', c_char_p, [c_void_p, c_void_p, c_ulong]),
               ('bip39_mnemonic_to_bytes', c_ulong, [c_void_p, c_char_p, c_void_p, c_ulong]),
               ('bip39_mnemonic_is_valid', c_ulong, [c_void_p, c_char_p]),
               ('bip39_mnemonic_to_seed', c_ulong, [c_char_p, c_char_p, c_void_p, c_ulong])]

sha2_funcs = [('sha256', None, [c_void_p, c_void_p, c_ulong]),
              ('sha512', None, [c_void_p, c_void_p, c_ulong]),
              ('hmac_sha512', None, [c_void_p, c_void_p, c_ulong, c_void_p, c_ulong])]

def bind_fn(name, res, args):
    try:
        fn = getattr(libwally, name)
        fn.restype, fn.argtypes = res, args
    except AttributeError:
        # Internal function and --enable-export-all was not
        # passed to configure.
        fn = None
    return fn

def bind_all(dest, funcs):
    for f in funcs:
        name, restype, argtypes = f
        setattr(dest, name, bind_fn(name, restype, argtypes))


def load_words(lang):
    with open(root_dir + 'src/data/wordlists/%s.txt' % lang, 'r') as f:
        words_list = [l.strip() for l in f.readlines()]
        return words_list, ' '.join(words_list)

