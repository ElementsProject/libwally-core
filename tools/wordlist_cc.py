#!/bin/env python
from __future__ import print_function
import sys

if __name__ == "__main__":

    wordlist = sys.argv[1]
    struct_name = sys.argv[2]
    string_name = '%s_str' % struct_name

    with open(wordlist, 'r') as f:

        words = [l.strip() for l in f.readlines()]
        lengths = [ 0 ];
        for w in words:
            lengths.append(lengths[-1] + len(w) + 1)
        idxs = ', '.join(['{0}+{1}'.format(string_name, n) for n in lengths])

        print('/* Generated file - do not edit! */')
        print('#include <wordlist.h>')
        print()
        print('   static const char %s[] = "%s";' % (string_name, '\\0'.join(words)))
        print('   static const char *%s_idx[] = {%s};' % (string_name, idxs))
        print()
        print('const struct words %s = {' % struct_name)
        print('    {0},'.format(len(words)))
        print('    %s,' % string_name)
        print('    %s_idx' % string_name)
        print('};')
