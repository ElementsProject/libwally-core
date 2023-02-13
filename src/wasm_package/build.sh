#! /usr/bin/env bash
set -xeo pipefail

# Update function list in wasm_exports.sh and run codegen for the public API in functions.js
(cd ../.. && ./tools/build_wrappers.py)

# Update WASM package constants and version to match libwally
(cd ../.. && ./tools/update_wasm_package.sh)

# Build WASM (Elements is always enabled)
(cd ../.. && ./tools/build_wasm.sh --enable-elements)
mkdir -p libwally_wasm && cp ../../wally_dist/wallycore.{js,wasm} libwally_wasm/
touch libwally_wasm/index # necessary for webpack to work (fixes "Can't resolve './' in 'wasm_package/libwally_wasm'")

# Build browser bundle (to dist/wallycore.bundle.js, see webpack.config.js)
webpack --mode production
