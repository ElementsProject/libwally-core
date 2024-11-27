#! /usr/bin/env bash
# Install required dependencies for building wally
# Options:
# -e : Don't install emsdk (used for JS builds)
# -j : Don't install Java SDK (used for Java builds)
# -n : Don't install Android NDK (used for Android builds)
# -w : Don't install MinGW (used for Windows cross compiles)
set -e

skip_emsdk=
skip_ndk=
skip_java=
skip_windows=
while getopts enjw name
do
    case $name in
    e)   skip_emsdk=1;;
    n)   skip_ndk=1;;
    j)   skip_java=1;;
    w)   skip_windows=1;;
    *)   echo "Invalid flag"; exit 1;;
    esac
done
shift $(($OPTIND - 1))

apt update -qq
apt upgrade -yqq

java_packages=
if [ -z "$skip_java" ]; then
    java_packages="openjdk-17-jdk openjdk-17-jre"
fi
windows_packages=
if [ -z "$skip_windows" ]; then
    windows_packages="g++-mingw-w64-x86-64"
fi
apt install --no-install-recommends unzip autoconf automake autotools-dev pkg-config build-essential libtool python3{,-dev,-pip,-virtualenv} python{,-dev}-is-python3 clang{,-format,-tidy} git swig curl cmake libssl-dev libtool-bin $java_packages curl $windows_packages valgrind jq -yqq

if [ -z "$skip_java" ]; then
    update-java-alternatives -s $(basename ${JAVA_HOME})
fi

# Note --break-system-packages to allow installing our requirements system-wide
pip install valgrind-codequality -r contrib/requirements.txt --break-system-packages

pushd /opt

if [ -z "$skip_ndk" ]; then
    curl -L -o ndk.zip https://dl.google.com/android/repository/android-ndk-r26b-linux.zip
    echo "ad73c0370f0b0a87d1671ed2fd5a9ac9acfd1eb5c43a7fbfbd330f85d19dd632  ndk.zip" | shasum -a 256 -c
    unzip ndk.zip
    rm ndk.zip
fi

if [ -z "$skip_emsdk" ]; then
    # Install node 20
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt install nodejs -yqq
    # Install emsdk
    git clone https://github.com/emscripten-core/emsdk
    cd emsdk
    EMSDK_VERSION=3.1.52
    if [ "${TARGETARCH}" = "arm64" ]; then
        # very few versions of emsdk are available for linux-arm64
        # https://github.com/emscripten-core/emsdk/issues/547
        EMSDK_VERSION=3.1.33
    fi
    ./emsdk install ${EMSDK_VERSION}
    ./emsdk activate ${EMSDK_VERSION}
    # Force emsdk to use the installed node version instead of its own
    sed -i "s/^NODE_JS = .*$/NODE_JS = 'node'/g" /opt/emsdk/.emscripten
    # Make emsdk commands available
    source ./emsdk_env.sh
fi

if [ -f /.dockerenv ]; then
    # Installing dependencies into a docker image.
    # Purge uneeded files to keep the image as small as possible.
    apt remove --purge curl unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi

popd
