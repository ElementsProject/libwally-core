#! /usr/bin/env bash

set -e

num_jobs=4
if [ -f /proc/cpuinfo ]; then
    num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
fi
$PWD/tools/cleanup.sh && $PWD/tools/autogen.sh
export CFLAGS="-fno-stack-protector"
emconfigure ./configure --build=$HOST_OS ac_cv_c_bigendian=no --disable-swig-python --disable-swig-java --enable-elements --disable-ecmult-static-precomputation --disable-tests
emmake make -j $num_jobs

: ${OPTIMIZATION_LEVEL:=3}
: ${EXTRA_EXPORTED_RUNTIME_METHODS:="['getValue', 'UTF8ToString', 'ccall']"}
: ${EXPORTED_FUNCTIONS:="['_malloc','_free','_wally_init','_wally_get_secp_context','_wally_secp_randomize', '_wally_free_string', '_bip39_get_wordlist', '_bip39_mnemonic_from_bytes', '_bip39_mnemonic_to_seed']"}

mkdir -p wally_dist
emcc -O$OPTIMIZATION_LEVEL \
    -s "EXTRA_EXPORTED_RUNTIME_METHODS=$EXTRA_EXPORTED_RUNTIME_METHODS" \
    -s "EXPORTED_FUNCTIONS=$EXPORTED_FUNCTIONS" \
    -s FILESYSTEM=0 \
    $EMCC_OPTIONS \
    ./src/.libs/*.o src/secp256k1/src/*.o src/ccan/ccan/crypto/*/.libs/*.o ./src/ccan/ccan/str/hex/.libs/*.o \
    -o wally_dist/wallycore.html \
    --shell-file contrib/shell_minimal.html
