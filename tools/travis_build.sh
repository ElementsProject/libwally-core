#! /usr/bin/env bash

function show_err()
{
    if [ -f $1 ]; then
        cat $1
    fi
}

function show_test_err()
{
    tests="test_bech32 test_clear test_tx test_elements_tx test_blech32"
    for i in $tests; do
        show_err src/$i.log
    done
}

trap "show_test_err" ERR

ENABLE_SWIG_PYTHON="--enable-swig-python"
ENABLE_SWIG_JAVA="--enable-swig-java"

if [ -n "$HOST" ]; then
   USE_HOST="--host=$HOST"
   if [ "$HOST" = "i686-linux-gnu" ]; then
       export CC="$CC -m32"
       ENABLE_SWIG_PYTHON=""
       # We only disable Java because the 64 bit jvm won't run the
       # tests given a 32 bit libwally.so. It compiles fine.
       export ENABLE_SWIG_JAVA=""
   fi
fi

./configure --disable-dependency-tracking --enable-export-all $ENABLE_SWIG_PYTHON $ENABLE_SWIG_JAVA $USE_HOST $DEBUG_WALLY $ENABLE_ELEMENTS $ENABLE_BUILTIN_MEMSET && make && make check
