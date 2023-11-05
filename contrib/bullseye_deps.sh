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
    java_packages="openjdk-11-jdk openjdk-11-jre"
fi
windows_packages=
if [ -z "$skip_windows" ]; then
    windows_packages="g++-mingw-w64-x86-64"
fi
apt install --no-install-recommends unzip autoconf automake autotools-dev pkg-config build-essential libtool python3{,-dev,-pip,-virtualenv} python{,-dev}-is-python3 clang{,-format,-tidy} git swig curl cmake libssl-dev libtool-bin $java_packages curl $windows_packages -yqq

if [ -z "$skip_java" ]; then
    update-java-alternatives -s java-1.11.0-openjdk-amd64
fi

pip3 install -r contrib/requirements.txt

pushd /opt

if [ -z "$skip_ndk" ]; then
    curl -L -o ndk.zip https://dl.google.com/android/repository/android-ndk-r23b-linux.zip
    echo "c6e97f9c8cfe5b7be0a9e6c15af8e7a179475b7ded23e2d1c1fa0945d6fb4382 ndk.zip" | sha256sum --check
    unzip ndk.zip
    rm ndk.zip
fi

if [ -z "$skip_emsdk" ]; then
    git clone https://github.com/emscripten-core/emsdk
    cd emsdk
    ./emsdk install 3.1.27
    ./emsdk activate 3.1.27
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
