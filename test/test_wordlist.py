#!/bin/env python
import unittest
from ctypes import *

lib = CDLL('bld/libwally.so')

class Wordlist:

    def __init__(self, words, sep):
        def bind(name, res, args):
            fn = getattr(lib, name)
            fn.restype, fn.argtypes = res, args
            return fn

        self._init = bind('wordlist_init', c_void_p, [c_char_p, c_char])
        self.wl = self._init(words, sep)

        self._word = bind('wordlist_lookup_word', c_ulong, [c_void_p, c_char_p])
        self.lookup_word = lambda word: self._word(self.wl, word)

        self._index = bind('wordlist_lookup_index', c_char_p, [c_void_p, c_ulong])
        self.lookup_index = lambda index: self._index(self.wl, index)

        self._free = bind('wordlist_free', None, [c_void_p])

    def free(self):
        if self.is_valid():
            self._free(self.wl)
            self.wl = None

    def is_valid(self):
        return self.wl is not None


class WordlistTests(unittest.TestCase):

    words_file = 'data/wordlists/english.txt'
    words_list = None
    words = None

    def setUp(self):
        if self.words is None:
            with open(self.words_file, 'r') as f:
                self.words_list = [l.strip() for l in f.readlines()]
            self.words = ' '.join(self.words_list)

    def test_wordlist(self):
        valid_lengths = [2, 4, 8, 16]

        for n in xrange(17):
            test_list = self.words_list[0 : n]

            wl = Wordlist(' '.join(test_list), ' ')
            self.assertEqual(wl.is_valid(), n in valid_lengths)

            if wl.is_valid():
                for idx, word in enumerate(test_list):
                    self.assertEqual(idx + 1, wl.lookup_word(word))
                    self.assertEqual(wl.lookup_word(self.words_list[n + 1]), 0)
                    self.assertEqual(wl.lookup_index(idx), word)
                    self.assertIsNone(wl.lookup_index(n + 1))

            wl.free()

if __name__ == '__main__':
    unittest.main()
