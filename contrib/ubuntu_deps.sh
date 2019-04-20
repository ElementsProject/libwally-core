#! /usr/bin/env bash
set -e

apt-get update -qq
apt-get upgrade -yqq
apt-get install python3-distutils-extra python3-dev build-essential libffi-dev swig autoconf libtool pkg-config lib32z1 unzip lib32z1 virtualenv python3-setuptools apt-transport-https -yqq

apt-get -yqq autoremove
apt-get -yqq clean
rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6*

