#! /usr/bin/env bash
set -xeo pipefail

# Update function list in wasm_exports.sh and run codegen for the public API in functions.js
(cd ../.. && ./tools/build_wrappers.py)

# Update WASM package constants and version to match libwally
(cd ../.. && ./tools/update_wasm_package.sh)

# Build WASM (Elements is always enabled)
(cd ../.. && ./tools/build_wasm.sh --enable-elements)
mkdir -p libwally_wasm && cp ../../wally_dist/wallycore.{js,wasm} libwally_wasm/
# Rename to force commonjs mode. See https://github.com/emscripten-core/emscripten/pull/17451
mv libwally_wasm/wallycore.js libwally_wasm/wallycore.cjs
