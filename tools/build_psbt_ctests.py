#!/usr/bin/env python3
# Generate the PSBT c-test header file src/ctest/psbts.h
import json

def dump(cases):
    for case in cases:
        if case.get('is_pset'):
            print('#ifdef BUILD_ELEMENTS')
        print('    /* {} */'.format(case['comment']))
        print('    {{"{}"}},'.format(case['psbt']))
        if case.get('is_pset'):
            print('#endif /* BUILD_ELEMENTS */')
        if case != cases[-1]:
            print()

with open('src/data/psbt.json', 'r') as f:
    JSON = json.load(f)

print('''/* Generated file - do not edit! */
struct psbt_test {
    const char *base64;
};

static const struct psbt_test invalid_psbts[] =
{''')
dump(JSON['invalid'])
print('''};

static const struct psbt_test valid_psbts[] =
{''')
dump(JSON['valid'])
print('};\n')
