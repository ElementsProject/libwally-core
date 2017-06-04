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

    # Create a new virtualenv and use it to build the wheel using pip wheel
    virtualenv -p $1 .venv
    source .venv/bin/activate

    pip install wheel
    pip wheel --wheel-dir=.venv .

    deactivate

    # Smoke test the built wheel by installing it into a new virtualenv
    virtualenv -p $1 .venv/.smoketest
    source .venv/.smoketest/bin/activate

    pip install --upgrade pip
    pip install .venv/*.whl
    python -c "import wallycore as wally; assert wally.hex_from_bytes(wally.hex_to_bytes('ff')) == 'ff'"

    deactivate

    # Copy the wheel into the root directory and remove the virtualenvs
    cp .venv/*.whl .
    rm -rf .venv
}

build_wheel python2
build_wheel python3

./tools/cleanup.sh
