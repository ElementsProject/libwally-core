#! /usr/bin/env bash
set -e

export NDK_FILENAME=android-ndk-r23b-linux.zip

dpkg --add-architecture i386

curl -sL https://deb.nodesource.com/setup_16.x | bash -
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list

apt-get update -qq -o="APT::Acquire::Retries=3"
apt-get upgrade -yqq -o="APT::Acquire::Retries=3"
apt-get install -yqq --no-install-recommends -o="APT::Acquire::Retries=3" unzip autoconf automake autotools-dev pkg-config build-essential libtool python3{,-dev,-pip,-virtualenv,-distutils,-sphinx} python{,-dev}-is-python3 clang{,-format,-tidy} git swig openjdk-11-jdk g++-mingw-w64-x86-64 curl nodejs yarn
update-java-alternatives -s java-1.11.0-openjdk-amd64

cd /opt && curl -sSO https://dl.google.com/android/repository/${NDK_FILENAME}
unzip -qq ${NDK_FILENAME}
rm ${NDK_FILENAME}
git clone https://github.com/emscripten-core/emsdk
cd emsdk
./emsdk install 3.1.27
./emsdk activate 3.1.27
source ./emsdk_env.sh

apt-get remove --purge curl unzip -yqq
apt-get -yqq autoremove
apt-get -yqq clean
rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6*
