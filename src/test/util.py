from ctypes import *
from binascii import unhexlify
from os.path import isfile
import platform
import sys

is_python3 = int(sys.version[0]) >= 3
utf8 = lambda s: s
if is_python3:
    utf8 = lambda s: s.encode('utf-8')

# Allow to run from any sub dir
SO_EXT = 'dylib' if platform.system() == 'Darwin' else 'so'
for depth in [0, 1, 2]:
    root_dir = '../' * depth
    if isfile(root_dir + 'src/.libs/libwallycore.' + SO_EXT):
        break

libwally = CDLL(root_dir + 'src/.libs/libwallycore.' + SO_EXT)

wordlist_funcs = [('wordlist_init', c_void_p, [c_char_p]),
                  ('wordlist_lookup_word', c_ulong, [c_void_p, c_char_p]),
                  ('wordlist_lookup_index', c_char_p, [c_void_p, c_ulong]),
                  ('wordlist_free', None, [c_void_p])]

mnemonic_funcs = [('mnemonic_from_bytes', c_char_p, [c_void_p, c_void_p, c_ulong]),
                  ('mnemonic_to_bytes', c_ulong, [c_void_p, c_char_p, c_void_p, c_ulong])]

class ext_key(Structure):
    _fields_ = [("chain_code", c_ubyte * 32),
                ("parent160", c_ubyte * 20),
                ("depth", c_ubyte),
                ("pad1", c_ubyte * 10),
                ("priv_key", c_ubyte * 33),
                ("child_num", c_uint),
                ("hash160", c_ubyte * 20),
                ("version", c_uint),
                ("pad2", c_ubyte * 3),
                ("pub_key", c_ubyte * 33)]

bip38_funcs = [('base58_string_from_bytes', None, [c_void_p, c_ulong, c_uint, POINTER(c_char_p)]),
               ('base58_string_to_bytes', c_ulong, [c_char_p, c_void_p, c_ulong])]

bip32_funcs = [('bip32_key_from_bytes', c_int, [c_void_p, c_ulong, c_uint, POINTER(ext_key)]),
               ('bip32_key_serialise', c_int, [POINTER(ext_key), c_uint, c_void_p, c_ulong]),
               ('bip32_key_unserialise', c_int, [c_void_p, c_uint, POINTER(ext_key)]),
               ('bip32_key_from_parent', c_int, [c_void_p, c_uint, c_uint, POINTER(ext_key)])]

bip39_funcs = [('bip39_get_languages', None, [POINTER(c_char_p)]),
               ('bip39_get_wordlist', c_void_p, [c_char_p]),
               ('bip39_mnemonic_from_bytes', None, [c_void_p, c_void_p, c_ulong, POINTER(c_char_p)]),
               ('bip39_mnemonic_to_bytes', c_ulong, [c_void_p, c_char_p, c_void_p, c_ulong]),
               ('bip39_mnemonic_is_valid', c_bool, [c_void_p, c_char_p]),
               ('bip39_mnemonic_to_seed', c_ulong, [c_char_p, c_char_p, c_void_p, c_ulong])]

sha2_funcs = [('sha256', None, [c_void_p, c_void_p, c_ulong]),
              ('sha512', None, [c_void_p, c_void_p, c_ulong]),
              ('hmac_sha512', None, [c_void_p, c_void_p, c_ulong, c_void_p, c_ulong])]

# ctypes represents all types of pointer-to-pointer-of-X with the same type,
# So we have to use explicit lists here to find functions to wrap
# FIXME: Use a sentinel class in the arg list instead
string_funcs = ['base58_string_from_bytes', 'bip39_get_languages',
                'bip39_mnemonic_from_bytes']

def bind_fn(name, res, args):
    try:
        fn = getattr(libwally, name)
        fn.restype, fn.argtypes = res, args
        return fn
    except AttributeError:
        # Internal function and 'configure --enable-export-all' not used
        return None

wally_free_string = libwally.wally_free_string
wally_free_string.restype, wally_free_string.argtypes = None, [c_char_p]

def string_fn_wrapper(fn, *args):
    # Return output string parameters directly without leaking
    p = c_char_p()
    new_args = [a for a in args] + [byref(p)]
    ret = fn(*new_args)
    ret_str = p.value.decode('utf-8')
    wally_free_string(p)
    return [ret_str, (ret, ret_str)][fn.restype is not None]


def bind_all(dest, funcs):
    for f in funcs:
        name, restype, argtypes = f
        fn = bind_fn(name, restype, argtypes)
        def mkstr(f): return lambda *args: string_fn_wrapper(f, *args)
        if name in string_funcs:
            fn = mkstr(fn)
        setattr(dest, name, fn)


def load_words(lang):
    with open(root_dir + 'src/data/wordlists/%s.txt' % lang, 'r') as f:
        words_list = [l.strip() for l in f.readlines()]
        return words_list, ' '.join(words_list)


def make_cbuffer(hex_in):
    hex_len = len(hex_in) // 2
    return unhexlify(hex_in), hex_len

