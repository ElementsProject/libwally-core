#! /usr/bin/env bash

# Creates manylinux compatible python wheels.
#
# Like all tools/ scripts, this should be run from the project root.

set -e

if [ ! -d "/opt/python" ]; then
    echo "No python binaries found under /opt/python/. Exiting..."
    exit 0
fi

source ./tools/build_python_wheels.sh " "

# Remember the unmodified PATH so we can reset inbetween builds
PPATH=$PATH
for PYBIN in /opt/python/*/bin/; do
    PATH=$PYBIN:$PPATH
    build_wheel python
    PATH=$PPATH
done

./tools/cleanup.sh
