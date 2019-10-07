#! /usr/bin/env bash

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    brew update
    brew install gnu-sed
    brew install swig yarn
elif [ "$TRAVIS_OS_NAME" = "windows" ]; then
    SWIG_VERSION="4.0.1"
    choco install swig --version $SWIG_VERSION
    choco install python --version 3.7.4
    ln -sf /c/ProgramData/chocolatey/lib/swig/tools/install/swigwin-$SWIG_VERSION /c/swig
fi
