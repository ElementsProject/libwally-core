#! /usr/bin/env bash

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    brew update
    brew install gnu-sed
    brew install swig@3.0.4 yarn
    brew link --overwrite swig@3.0.4
fi
