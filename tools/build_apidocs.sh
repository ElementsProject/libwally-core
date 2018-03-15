#! /usr/bin/env bash

# Creates apidocs.tar.gz containing the generated API HTML docs.

set -e

./tools/cleanup.sh
virtualenv -p python2 .venv
source .venv/bin/activate
pip install sphinx sphinx_rtd_theme
cd docs && make html && cd build && tar czf ../../apidocs.tar.gz html/ && cd ../..
deactivate
./tools/cleanup.sh
