#! /usr/bin/env bash
set -e

export NDK_FILENAME=android-ndk-r20-linux-x86_64.zip

dpkg --add-architecture i386

apt-get update -qq
apt-get upgrade -yqq
apt-get install git uncrustify python{,3}-distutils-extra python{,3}-dev build-essential libffi-dev swig autoconf libtool pkg-config lib32z1 openjdk-11-jdk ca-certificates-java unzip curl libc6:i386 libc6-dev:i386 libncurses5:i386 libstdc++6:i386 lib32z1 virtualenv python{,3}-setuptools apt-transport-https -yqq
update-java-alternatives -s java-1.11.0-openjdk-amd64

curl -sL https://deb.nodesource.com/setup_8.x | bash -
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
apt-get -yqq update
apt-get -yqq upgrade
apt-get -yqq install nodejs yarn

cd /opt && curl -sSO https://dl.google.com/android/repository/${NDK_FILENAME} && unzip -qq ${NDK_FILENAME} && rm ${NDK_FILENAME}

apt-get remove --purge curl -yqq
apt-get -yqq autoremove
apt-get -yqq clean
rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6*
