#! /usr/bin/env bash
set -e

export NDK_FILENAME=android-ndk-r14b-linux-x86_64.zip

dpkg --add-architecture i386
sed -i 's/deb.debian.org/httpredir.debian.org/g' /etc/apt/sources.list

apt-get update -qq
apt-get upgrade -yqq
apt-get install python{,3}-distutils-extra python{,3}-dev build-essential libffi-dev swig autoconf libtool pkg-config lib32z1 openjdk-8-jdk ca-certificates-java unzip curl libc6:i386 libc6-dev:i386 libncurses5:i386 libstdc++6:i386 lib32z1 virtualenv python{,3}-setuptools -yqq
update-java-alternatives -s java-1.8.0-openjdk-amd64

cd /opt && curl -sSO https://dl.google.com/android/repository/${NDK_FILENAME} && unzip -qq ${NDK_FILENAME} && rm ${NDK_FILENAME}

apt-get remove --purge curl -yqq
apt-get -yqq autoremove
apt-get -yqq clean
rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6*
