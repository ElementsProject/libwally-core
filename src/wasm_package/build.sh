#! /usr/bin/env bash
set -xeo pipefail

# Build WASM (Note Elements is always enabled)
(cd ../.. && ./tools/build_wasm.sh)
mkdir -p libwally_wasm && cp ../../dist/wallycore.{js,wasm} libwally_wasm/
touch libwally_wasm/index # necessary for webpack to work (fixes "Can't resolve './' in 'wasm_package/libwally_wasm'")

# Build browser bundle (to dist/wallycore.bundle.js, see webpack.config.js)
webpack --mode production
