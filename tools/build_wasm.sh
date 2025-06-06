#! /usr/bin/env bash

set -e

DISABLE_ELEMENTS=""
if [ "$1" = "--disable-elements" ]; then
    DISABLE_ELEMENTS="--disable-elements --disable-elements-abi"
    shift
fi

num_jobs=4
if [ -f /proc/cpuinfo ]; then
    num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
fi

if ! type -P emcc > /dev/null; then
    # Setup the emsdk environment if it isn't already
    source /opt/emsdk/emsdk_env.sh
fi

$PWD/tools/cleanup.sh && $PWD/tools/autogen.sh

# Note: This doesn't work yet, see https://github.com/emscripten-core/emscripten/issues/6233
# we pass --enable-export-all to prevent library symbols from being hidden,
# the wasm build then makes visible only the functions marked EMSCRIPTEN_KEEPALIVE.
#trap "sed -i 's/EMSCRIPTEN_KEEPALIVE/WALLY_CORE_API/g' include/*.h src/*.h" ERR EXIT
#sed -i 's/WALLY_CORE_API/EMSCRIPTEN_KEEPALIVE/g' include/*.h src/*.h

export CFLAGS="-fno-stack-protector"
emconfigure ./configure --build=$HOST_OS ac_cv_c_bigendian=no --disable-swig-python --disable-swig-java $DISABLE_ELEMENTS --disable-tests --enable-export-all --enable-wasm-interface
emmake make -j $num_jobs

: ${EMCC_OPTIONS:="-s EXPORT_ES6=1 -s WASM_BIGINT"}
: ${OPTIMIZATION_LEVEL:=3}
: ${EXPORTED_RUNTIME_METHODS:='cwrap,ccall,getValue,UTF8ToString'}
# Get the list of functions to export
source ./tools/wasm_exports.sh

mkdir -p dist

emcc -O$OPTIMIZATION_LEVEL \
    -s "EXPORTED_RUNTIME_METHODS=$EXPORTED_RUNTIME_METHODS" \
    -s "EXPORTED_FUNCTIONS=$EXPORTED_FUNCTIONS" \
    -s FILESYSTEM=0 \
    $EMCC_OPTIONS \
    ./src/.libs/*.o src/secp256k1/src/*.o src/ccan/ccan/*/.libs/*.o src/ccan/ccan/*/*/.libs/*.o \
    -o dist/wallycore.js
