#! /usr/bin/env bash

set -e

tools/cleanup.sh
tools/autogen.sh
./configure --enable-js-wrappers --disable-swig-python --disable-swig-java --enable-ecmult-static-precomputation --enable-elements $DEBUG_WALLY
num_jobs=4
if [ -f /proc/cpuinfo ]; then
    num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
fi
make -o configure clean
make -o configure -j $num_jobs
make -o configure check

./tools/cleanup.sh
