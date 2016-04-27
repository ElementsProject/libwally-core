#!/bin/sh

ENABLE_SWIG_PYTHON="--enable-swig-python"

if [ -n "$HOST" ]; then
   USE_HOST="--host=$HOST"
   if [ "$HOST" = "i686-linux-gnu" ]; then
       export CC="$CC -m32"
       export ENABLE_SWIG_PYTHON=""
   fi
fi

./configure --disable-dependency-tracking --enable-export-all $ENABLE_SWIG_PYTHON --enable-swig-java $USE_HOST && make && make check

