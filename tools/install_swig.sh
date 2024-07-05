#! /usr/bin/env bash
set -e

if [ $(command -v swig) ]; then
    # Already installed
    exit 0
fi

if [ $(command -v apt) ]; then
    # Debian/Ubuntu
    apt install swig
    exit 0
fi

if [ -d /etc/yum.repos.d ]; then
    # Redhat/Fedora
    if grep -- mirror.centos.org /etc/yum.repos.d/*.repo >/dev/null 2>&1; then
        # mirror.centos.org has been nuked. Attempt to update the repo spec
        # for older manylinux docker builds
        sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
        sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
        sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo
    fi
    yum install -y swig
    exit 0
fi

if [ $(command -v brew) ]; then
    # MacOS
    brew install swig
    exit 0
fi

if [ $(command -v apk) ]; then
    # Alpine
    apk add swig
    exit 0
fi

# Unknown - install from source
SWIG_URL='https://downloads.sourceforge.net/project/swig/swig/swig-3.0.12/swig-3.0.12.tar.gz?use_mirror=autoselect'
curl -sSL ${SWIG_URL} | tar xz
pushd swig-3.0.12 >/dev/null
./configure
make -j4
make install
popd >/dev/null
rm -rf swig-3.0.12
exit 0
