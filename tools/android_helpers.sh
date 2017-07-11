# Source this file from your build scripts to use the functions provided

# List the android architectures supported by wally
function android_get_arch_list() {
    echo "armeabi armeabi-v7a arm64-v8a mips mips64 x86 x86_64"
}

# Create an NDK toolchain directory to build wally for an architecture
# Requires:
# ANDROID_HOME: Android SDK install directory
# ANDROID_NDK: Android NDK directory (default: $ANDROID_HOME/ndk-bundle)
# Parameters:
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# api:      The Android API level to build for (e.g. 21)
function android_create_toolchain() {
    local arch=$1 toolsdir=$2 api=$3
    if [[ ! -d $toolsdir ]]; then
        case $arch in
            armeabi*) arch=arm;;
            arm64-v8a) arch=arm64;;
        esac
        if [[ -z "$ANDROID_NDK" ]]; then
            ANDROID_NDK="$ANDROID_HOME/ndk-bundle"
        fi
        local cmd=$ANDROID_NDK/build/tools/make_standalone_toolchain.py
        $cmd --arch $arch --api $api --install-dir=$toolsdir
        case $arch in
            mips64)
                # Work around a bug in the install
                if [[ ! -e $toolsdir/sysroot/usr/lib ]]; then
                   ln -s $toolsdir/sysroot/usr/lib64 $toolsdir/sysroot/usr/lib
                fi
        esac
    fi
}

# Get the compiler flags needed to build for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# api:      The Android API level to build for (e.g. 21)
function android_get_cflags() {
    local arch=$1 toolsdir=$2 api=$3
    local cflags=""
    if [[ -n "$WALLY_USE_GCC" ]]; then
        cflags="$cflags --sysroot=$toolsdir/sysroot -D__ANDROID_API__=$api"
    fi
    cflags="$cflags -isystem $toolsdir/sysroot/usr/include"
    case $arch in
       armeabi) cflags="$cflags -march=armv5te -mtune=xscale -msoft-float -mthumb";;
       armeabi-v7a) cflags="$cflags -march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb";;
       arm64-v8a) cflags="$cflags -flax-vector-conversions";;
       mips) cflags="$cflags -mips32";;
    esac
    echo $cflags
}

# Get the linker flags needed to build for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# api:      The Android API level to build for (e.g. 21)
function android_get_ldflags() {
    local arch=$1 toolsdir=$2 api=$3
    case $arch in
       armeabi-v7a) echo "-Wl,--fix-cortex-a8";;
       mips) echo "-mips32";;
    esac
}

# Get the configure flags needed to build for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# api:      The Android API level to build for (e.g. 21)
# useropts: The users configure options e.g. --enable-swig-java
function android_get_configure_flags() {
    local arch=$1 toolsdir=$2 api=$3
    shift 3
    local useropts=$*
    local host=$(basename $toolsdir/bin/*-strip | sed 's/-strip$//')
    local args="--host=$host $useropts --enable-endomorph"
    case $arch in
       arm*) args="$args --with-asm=auto";;
       x86_64) args="$args --with-asm=x86_64";;
    esac
    echo $args
}

# Create a toolchain configure and build wally for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# api:      The Android API level to build for (e.g. 21)
# useropts: The users configure options e.g. --enable-swig-java
function android_build_wally() {
    local arch=$1 toolsdir=$2 api=$3
    shift 3
    local useropts=$*
    # Create an NDK installation to build with
    android_create_toolchain $arch $toolsdir $api

    # Set cross compilation options for configure
    # TODO: Support NDK > 14 and clang when they work
    if [[ -z "$WALLY_USE_GCC" ]]; then
        export CC="$toolsdir/bin/clang"
    fi

    export CFLAGS=$(android_get_cflags $arch $toolsdir $api)
    export LDFLAGS=$(android_get_ldflags $arch $toolsdir $api)

    PATH="$toolsdir/bin:$PATH" ./configure $(android_get_configure_flags $arch $toolsdir $api $useropts)
    local num_jobs=4
    if [ -f /proc/cpuinfo ]; then
        num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
    fi
    PATH="$toolsdir/bin:$PATH" make -o configure clean
    PATH="$toolsdir/bin:$PATH" make -o configure -j $num_jobs
    unset CC CFLAGS LDFLAGS
}
