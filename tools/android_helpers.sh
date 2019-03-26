# Source this file from your build scripts to use the functions provided

# List the android architectures supported by wally
function android_get_arch_list() {
    echo "armeabi-v7a arm64-v8a x86 x86_64"
}

# Get the compiler flags needed to build for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
function android_get_cflags() {
    local arch=$1 toolsdir=$2
    local cflags="$CFLAGS -isystem $toolsdir/sysroot/include"
    case $arch in
       armeabi-v7a) cflags="$cflags -march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb";;
       arm64-v8a) cflags="$cflags -flax-vector-conversions";;
    esac
    echo $cflags
}

# Get the configure flags needed to build for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# useropts: The users configure options e.g. --enable-swig-java
function android_get_configure_flags() {
    local arch=$1 toolsdir=$2 archfilename=$1
    shift 2
    local useropts=$*
    case $arch in
        armeabi-v7a) archfilename=arm;;
        arm64-v8a) archfilename=aarch64;;
    esac

    local host=$(basename $toolsdir/bin/$archfilename-linux-android*-strip | sed 's/-strip$//')
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
    local arch=$1 toolsdir=$2 api=$3 clangarchname=$1
    shift 3
    local useropts=$*

    # Set cross compilation options for configure
    case $arch in
        armeabi-v7a) clangarchname=armv7a;;
        arm64-v8a) clangarchname=aarch64;;
    esac

    export CC=$(ls $toolsdir/bin/$clangarchname-linux-android*$api-clang)

    export CFLAGS=$(android_get_cflags $arch $toolsdir)

    PATH="$toolsdir/bin:$PATH" ./configure $(android_get_configure_flags $arch $toolsdir $useropts)
    local num_jobs=4
    if [ -f /proc/cpuinfo ]; then
        num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
    fi
    PATH="$toolsdir/bin:$PATH" make -o configure clean
    PATH="$toolsdir/bin:$PATH" make -o configure -j $num_jobs
    unset CC CFLAGS LDFLAGS
}
