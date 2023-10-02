#! /usr/bin/env bash
# Update the library version in dependent source files.

# The master source of the version numbers is the wally_core.h header
MAJOR=$(grep '#define WALLY_MAJOR_VER ' include/wally_core.h | cut -d' ' -f 3)
MINOR=$(grep '#define WALLY_MINOR_VER ' include/wally_core.h | cut -d' ' -f 3)
PATCH=$(grep '#define WALLY_PATCH_VER ' include/wally_core.h | cut -d' ' -f 3)
# Compute the build version from the sub versions
BUILD=$(($MAJOR * 256 * 256 + $MINOR * 256 + $PATCH));
BUILD=$(printf '0x%x' $BUILD)
sed -i "s/BUILD_VER .*$/BUILD_VER $BUILD/g" include/wally_core.h

DOTTED="$MAJOR.$MINOR.$PATCH"
sed -i "s/^AC_INIT.*$/AC_INIT\(\[libwallycore],\[$DOTTED\]\)/g" configure.ac
sed -i "s/wallycore==.*$/wallycore==$DOTTED/g" README.md
sed -i "s/^  VERSION .*$/  VERSION $DOTTED/g" _CMakeLists.txt
sed -i "s/^version = .*$/version = u'$DOTTED'/g" docs/source/conf.py
sed -i "s/^    'version': .*$/    'version': '$DOTTED',/g" setup.py
sed -i "s/^  \"version\": .*$/  \"version\": \"$DOTTED\",/g" src/wasm_package/package.json src/wasm_package/package-lock.json
jq --arg dotted "$DOTTED" '(.packages."".version) = $dotted' src/wasm_package/package-lock.json > src/wasm_package/package-lock.json.tmp
mv src/wasm_package/package-lock.json.tmp src/wasm_package/package-lock.json
./tools/update_generated.sh
