# Source this file from your build scripts to use the functions provided

# List the android architectures supported by wally
function android_get_arch_list() {
    echo "armeabi-v7a arm64-v8a x86 x86_64"
}


# Get the location of the android NDK build tools to build with
function android_get_build_tools_dir() {
    if [ "$(uname)" == "Darwin" ]; then
        echo $ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64
    else
        echo $ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64
    fi
}


# Get the cross compile target for a given android architecture,
# used to determine the build tools to use.
# arch: An architecture from android_get_arch_list()
function android_get_cross_compile_target() {
    local arch=$1
    case $arch in
        armeabi-v7a) echo "armv7a-linux-androideabi";;
        arm64-v8a) echo "aarch64-linux-android";;
        x86) echo "i686-linux-android";;
        x86_64) echo "x86_64-linux-android";;
        *)
            echo "ERROR: Unknown arch $arch" >&2
            exit 1
            ;;
    esac
}


# Get the cross compile triplet for a given android architecture,
# passed as --host to configure
# arch: An architecture from android_get_arch_list()
# api:      The minimum Android API level to build for (e.g. 21)
function android_get_cross_compile_triplet() {
    local arch=$1 api=$3
    case $arch in
        armeabi-v7a) echo "armv7-none-linux-androideabi$api";;
        arm64-v8a) echo "aarch64-none-linux-android$api";;
        x86) echo "i686-none-linux-android$api";;
        x86_64) echo "x86_64-none-linux-android$api";;
        *)
            echo "ERROR: Unknown arch $arch" >&2
            exit 1
            ;;
    esac
}


# Create a toolchain configure and build wally for Android
# arch:     An architecture from android_get_arch_list()
# toolsdir: The directory for the NDK toolchain
# api:      The minimum Android API level to build for (e.g. 21)
# useropts: The users configure options e.g. --enable-swig-java
function android_build_wally() {
    local arch=$1 toolsdir=$2 api=$3
    shift 3
    local useropts=$*
    local target=$(android_get_cross_compile_target $arch)

    AR=$toolsdir/bin/llvm-ar \
    CC=$toolsdir/bin/$target$api-clang \
    AS=$toolsdir/bin/$target$api-clang \
    LD=$toolsdir/bin/ld \
    RANLIB=$toolsdir/bin/llvm-ranlib \
    STRIP=$toolsdir/bin/llvm-strip \
    ./configure --host=$(android_get_cross_compile_triplet $arch $api) \
      --enable-swig-java --disable-swig-python --enable-elements $useropts
    local num_jobs=4
    if [ -f /proc/cpuinfo ]; then
        num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
    fi
    PATH="$toolsdir/bin:$PATH" make -o configure clean
    PATH="$toolsdir/bin:$PATH" make -o configure -j $num_jobs
}
