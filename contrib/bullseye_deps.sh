#! /usr/bin/env bash
set -e

apt update -qq
apt upgrade -yqq

apt install --no-install-recommends unzip autoconf automake autotools-dev pkg-config build-essential libtool python3{,-dev,-pip,-virtualenv} python{,-dev}-is-python3 clang{,-format,-tidy} git swig g++-mingw-w64-x86-64 curl cmake libssl-dev libtool-bin openjdk-11-jdk openjdk-11-jre curl -yqq

update-java-alternatives -s java-1.11.0-openjdk-amd64

pip3 install -r contrib/requirements.txt

cd /opt
curl -L -o ndk.zip https://dl.google.com/android/repository/android-ndk-r23b-linux.zip
echo "c6e97f9c8cfe5b7be0a9e6c15af8e7a179475b7ded23e2d1c1fa0945d6fb4382 ndk.zip" | sha256sum --check
unzip ndk.zip
rm ndk.zip

git clone https://github.com/emscripten-core/emsdk
cd emsdk
./emsdk install 3.1.27
./emsdk activate 3.1.27
source ./emsdk_env.sh

if [ -f /.dockerenv ]; then
    apt remove --purge curl unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
