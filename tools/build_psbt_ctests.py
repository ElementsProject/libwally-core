#!/usr/bin/env python3
# Generate the PSBT c-test header file src/ctest/psbts.h
import json

def dump(cases):
    for case in cases:
        print('    /* {} */'.format(case['comment']))
        round_trip = 'true' if case.get('can_round_trip', True) else 'false'
        is_pset = 'true' if case.get('is_pset', False) else 'false'
        print('    {{"{}", {}, {}}},'.format(case['psbt'], is_pset, round_trip))
        if case != cases[-1]:
            print()

with open('src/data/psbt.json', 'r') as f:
    JSON = json.load(f)

print('''/* Generated file - do not edit! */
struct psbt_test {
    const char *base64;
    const bool is_pset;
    const bool can_round_trip;
};

static const struct psbt_test invalid_psbts[] =
{''')
dump(JSON['invalid'])
print('''};

static const struct psbt_test valid_psbts[] =
{''')
dump(JSON['valid'])
print('};\n')
