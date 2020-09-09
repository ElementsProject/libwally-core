#!/bin/bash
# Generate the CFFI function list used in src/tests/util.py
# Run to print the updated list and update util.py as needed.
# Only generates entries for documented functions, and requires
# that the user has sphinx documentation tool installed (package
# sphinx-doc on debian).

# FIXME: 'int' is used only by wally_asset_rangeproof/wally_asset_rangeproof_with_nonce

# This expression just replaces the various argument types with their
# CFFI type. struct 'words' is special cases as it is an opaque type
# and no struct definition is exposed to library users.
WALLY_DOC_DUMP_FUNCS="1" sphinx-build -b html -a -c docs/source docs/source docs/build/html 2>&1 | \
    grep '^int ' | \
    sed -e "s/(/',c_int,[/g" \
        -e "s/^int /    ('/g" \
        -e 's/, /,/g' -e 's/const //g' | \
    perl -pe 's/int .*?[,)]/c_int,/g' | \
    perl -pe 's/size_t \*.*?[,)]/c_ulong_p,/g' | \
    perl -pe 's/size_t .*?[,)]/c_ulong,/g' | \
    perl -pe 's/uint32_t \*.*?[,)]/c_uint_p,/g' | \
    perl -pe 's/uint32_t .*?[,)]/c_uint,/g' | \
    perl -pe 's/uint64_t \*.*?,/POINTER(c_uint64),/g' | \
    perl -pe 's/uint64_t \*.*?\)/c_uint64_p,/g' | \
    perl -pe 's/uint64_t .*?[,)]/c_uint64,/g' | \
    perl -pe 's/unsigned char \*.*?[,)]/c_void_p,/g' | \
    perl -pe 's/char \*\*.*?[,)]/c_char_p_p,/g' | \
    perl -pe 's/char \*.*?[,)]/c_char_p,/g' | \
    perl -pe 's/void \*.*?[,)]/c_void_p,/g' | \
    perl -pe 's/struct ([a-z0-9_]*?) \*\*(.*?)[,)]/POINTER(POINTER(\1)),/g' | \
    perl -pe 's/struct ([a-z0-9_]*?) \*(.*?)[,)]/POINTER(\1),/g' | \
    sed -e 's/POINTER(words)/c_void_p/g' \
        -e 's/,/, /g' \
        -e 's/, $/]),/g' | sort

