#!/bin/env python
from __future__ import print_function
import sys

if __name__ == "__main__":

    bits = { 2 ** x : x for x in range(12) } # Up to 4k words
    wordlist = sys.argv[1]
    struct_name = '%s_words' % sys.argv[2]
    string_name = '%s' % sys.argv[2]

    with open(wordlist, 'r') as f:

        words = [l.strip() for l in f.readlines()]
        assert len(words) >= 2
        assert len(words) in bits

        lengths = [ 0 ];
        for w in words:
            lengths.append(lengths[-1] + len(w) + 1)
        idxs = ['{0}+{1}'.format(string_name, n) for n in lengths]

        print('/* Generated file - do not edit! */')
        print('#include <wordlist.h>')
        print()

        print('static const char %s[] =' % string_name)
        grouped = [words[i : i + 6] for i in range(0, len(words), 6)]
        for g in grouped:
            print('    "%s\\0"' % ('\\0'.join(g)))
        print('   ;')

        print('static const char *%s_i[] = {' % (string_name))
        grouped = [idxs[i : i + 6] for i in range(0, len(idxs), 6)]
        for g in grouped:
            print('    %s,' % (', '.join(g)))
        print('   };')

        print()
        print('static const struct words %s = {' % struct_name)
        print('    {0},'.format(len(words)))
        print('    {0},'.format(bits[len(words)]))
        print('    %s,' % string_name)
        print('    %s_i' % string_name)
        print('};')
