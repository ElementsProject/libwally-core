#! /usr/bin/env bash

# Creates wheel files
#
# The wheel file can be installed with
# pip install wallycore*.whl
#
# Like all tools/ scripts, this should be run from the project root.

set -e

function build_wheel {
    ./tools/cleanup.sh

    virtualenv -p $1 .venv
    source .venv/bin/activate

    pip install wheel
    pip wheel .

    deactivate
}

build_wheel python2
build_wheel python3

./tools/cleanup.sh
