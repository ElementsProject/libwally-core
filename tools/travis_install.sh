#! /usr/bin/env bash

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    brew update
    brew install gnu-sed
    brew install swig@3 yarn
    brew link --overwrite --force swig@3
fi
