#!/bin/bash

APPDIR=$(pwd)
APPNAME="$( (cat config.xml 2>/dev/null || cat www/config.xml) | grep "<name>" | cut -d">" -f2 | cut -d"<" -f1 )"
if which greadlink; then
    READLINK=greadlink
else
    if [ "$(uname -s)" == "Darwin" ]; then
        echo "greadlink missing! Try brew install coreutils."
        exit 1
    fi
    READLINK=readlink
fi
PLUGINDIR="$($READLINK -f "$(dirname "$(test -L "$0" && $READLINK "$0" || echo "$0")")")"
SWIGJSDIR=$PLUGINDIR/..  # libwally-core/src/swig_js/
SRCDIR=$SWIGJSDIR/..  # libwally-core/src/
LIBWALLYDIR=$SRCDIR/..  # libwally-core/

set -e
if [ -z "$JAVA_HOME" ]; then
    export JAVA_HOME=$JAVA7_HOME
fi
if [ "$(uname -s)" != "Darwin" ]; then
    # Require JAVA_HOME and ANDROID_NDK on Linux only, where we can't build for iOS
    echo ${JAVA_HOME:?}
    echo ${ANDROID_NDK:?}
fi
echo ${APPNAME:?}

NUM_JOBS=4
if [ -f /proc/cpuinfo ]; then
    NUM_JOBS=$(cat /proc/cpuinfo | grep ^processor | wc -l)
fi

if [ "$(uname -s)" == "Darwin" ]; then
    export HOST_OS="x86_64-apple-darwin"  # FIXME: Verify
else
    export HOST_OS="i686-linux-gnu"
fi

function build() {
    unset CFLAGS
    unset CPPFLAGS
    unset LDFLAGS
    configure_opts="--enable-silent-rules --disable-dependency-tracking --enable-swig-java --enable-endomorphism"

    case $1 in
        armeabi)
            arch=arm
            configure_opts="$configure_opts"
            export CFLAGS="-march=armv5te -mtune=xscale -msoft-float -mthumb"
            ;;
        armeabi-v7a)
            arch=arm
            configure_opts="$configure_opts" # FIXME: Fails to compile: --with-asm=arm
            export CFLAGS="-march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb"
            export LDFLAGS="-Wl,--fix-cortex-a8"
            ;;
        arm64-v8a)
            arch=arm64
            configure_opts="$configure_opts" # FIXME: Fails to compile: --with-asm=arm
            export CFLAGS="-flax-vector-conversions"
            ;;
        mips)
            arch=mips
            # FIXME: Only needed until mips32r2 is not the default in clang
            export CFLAGS="-mips32"
            export LDLAGS="-mips32"
            ;;
        *)
            arch=$1
    esac

    export CFLAGS="$CFLAGS -O3" # Must  add optimisation flags for secp
    export CPPFLAGS="$CFLAGS"

    if [[ $arch == *"64"* ]]; then
        export ANDROID_VERSION="21"
    else
        export ANDROID_VERSION="14"
    fi

    rm -rf ./toolchain >/dev/null 2>&1
    $ANDROID_NDK/build/tools/make_standalone_toolchain.py --arch $arch --api $ANDROID_VERSION --install-dir=./toolchain

    echo '============================================================'
    echo Building $1
    echo '============================================================'
    ./configure --host=$HOST_OS --target=$arch $configure_opts >/dev/null
    make -o configure clean -j$NUM_JOBS >/dev/null 2>&1
    make -o configure -j$NUM_JOBS V=1

    mkdir -p $PLUGINDIR/jniLibs/$1
    toolchain/bin/*-strip -o $PLUGINDIR/jniLibs/$1/libwallycore.so src/.libs/libwallycore.so
}

if [ -n "$1" ]; then
    all_android_archs="$1"
else
    all_android_archs="armeabi armeabi-v7a arm64-v8a mips mips64 x86 x86_64"
fi

cd $LIBWALLYDIR  #  cd from src/swig_js/cordovaplugin to wallycore root

./tools/cleanup.sh
./tools/autogen.sh

if [ "$ANDROID_NDK" != "" ]; then
    OLDPATH=$PATH
    export PATH=`pwd`/toolchain/bin:$PATH
    export CC=clang

    echo '============================================================'
    echo 'Initialising Android build for architecture(s):'
    echo $all_android_archs
    echo '============================================================'

    for a in $all_android_archs; do
        build $a || if [ "$(uname -s)" == "Darwin" ]; then
            echo "Android build failed - ignoring, still trying iOS."
            unset CFLAGS
            unset CPPFLAGS
            unset LDFLAGS
            break
        else
            echo "Android build failed and not on macOS, so cannot do iOS - exiting."
            exit 1
        fi
    done

    # Note we can't do a full clean here since we need the generated Java files
    export PATH=$OLDPATH
    rm -rf src/.libs ./toolchain
fi

./configure && make clean && make -j$NUM_JOBS  # generate files for iOS in case Android build failed

cd $PLUGINDIR
python $SWIGJSDIR/makewrappers/wrap.py
cp $SRCDIR/swig_java/src/com/blockstream/libwally/Wally.java . || true

cd $APPDIR

if [ "$(uname -s)" == "Darwin" ]; then
    cordova prepare ios
    # FIXME plugin add doesn't work before prepare for iOS
    sed s/HelloCordova/$APPNAME/ $PLUGINDIR/scripts/add_swift_support.js.HelloCordova > $PLUGINDIR/scripts/add_swift_support.js
    cordova plugin add $PLUGINDIR --nosave
    sed s/HelloCordova/$APPNAME/ $PLUGINDIR/patch_pbxproj_with_wally.js > patch_pbxproj_with_wally.js
    NODE_PATH=`pwd`/platforms/ios/cordova/node_modules node patch_pbxproj_with_wally.js > pbxproj.new
    cp -r $SRCDIR/* platforms/ios/$APPNAME
    cp -r $LIBWALLYDIR/include platforms/ios/$APPNAME
    cp -r $SRCDIR/secp256k1/include/* platforms/ios/$APPNAME/include/
    mv pbxproj.new platforms/ios/$APPNAME.xcodeproj/project.pbxproj
else
    cordova plugin add $PLUGINDIR --nosave
fi

# Put files required by GA webfiles into place:
cd $APPDIR/plugins/cordova-plugin-wally
mkdir -p build/Release
echo '' > build/Release/wallycore.js  # mock wallycore which is nodejs-only
npm i base64-js
