# libwally-core

Wally is a cross-platform, cross-language collection of useful primitives
for cryptocurrency wallets.

Read the API documentation at https://wally.readthedocs.io.

Note that library interfaces may change slightly while the library design matures. Please see the [CHANGES](./CHANGES.md) file to determine if the API has changed when upgrading.

Please report bugs and submit patches to https://github.com/ElementsProject/libwally-core.

[![Build Status](https://travis-ci.org/ElementsProject/libwally-core.svg?branch=master)](https://travis-ci.org/ElementsProject/libwally-core)

## Platforms

Wally can currently be built for:
- Linux
- Android
- OS X
- iOS
- Windows

And can be used from:
- C and compatible languages which can call C interfaces
- C++ (see include/wally.hpp for C++ container support)
- Python 2.7+ or 3.x
- Java
- Javascript via node.js or Cordova

## Building

```
$ ./tools/autogen.sh
$ ./configure <options - see below>
$ make
$ make check
```

### configure options

- `--enable-debug`. Enables debugging information and disables compiler
   optimisations (default: no).
- `--enable-export-all`. Export all functions from the wally shared library.
   Ordinarily only API functions are exported. (default: no). Enable this
   if you want to test the internal functions of the library or are planning
   to submit patches.
- `--enable-swig-python`. Enable the [SWIG](http://www.swig.org/) Python
   interface. The resulting shared library can be imported from Python using
   the generated interface file `src/swig_python/wallycore/__init__.py`. (default: no).
- `--enable-swig-java`. Enable the [SWIG](http://www.swig.org/) Java (JNI)
   interface. After building, see `src/swig_java/src/com/blockstream/libwally/Wally.java`
   for the Java interface definition (default: no).
- `--enable-elements`. Enables support for [Elements](https://elementsproject.org/)
   features, including [Liquid](https://blockstream.com/liquid/) support.
- `--enable-js-wrappers`. Enable the Node.js and Cordova Javascript wrappers.
   This currently requires python to be available at build time (default: no).
- `--enable-coverage`. Enables code coverage (default: no) Note that you will
   need [lcov](http://ltp.sourceforge.net/coverage/lcov.php) installed to
   build with this option enabled and generate coverage reports.
- `--disable-shared`. Disables building a shared library and builds a static
  library instead.

### Recommended development configure options

```
$ ./configure --enable-debug --enable-export-all --enable-swig-python --enable-swig-java --enable-coverage
```

### Compiler options

Set `CC=clang` to use clang for building instead of gcc, when both are
installed.

### Python

For python development, you can build and install wally using:

```
$ pip install .
```

It is suggested you only install this way into a virtualenv while the library
is under heavy development.

If you wish to explicitly choose the python version to use, set the
`PYTHON_VERSION` environment variable (to e.g. `2`, `2.7`, `3` etc) before
running `setup.py` or (when compiling manually) `./configure`.

Before running pip.

You can also install the binary wally releases using the released
wheel files without having to compile the library, e.g.:

```
pip install wallycore-0.7.7-cp37-cp37m-linux_x86_64.whl
```

The script `tools/build_python_wheels.sh` builds the release files and can be
used as an example for your own python projects.

### Android

Android builds are currently supported for all Android binary targets using
the Android NDK. The script `tools/android_helpers.sh` can be sourced from
the shell or scripts to make it easier to produce builds:

```
$ export ANDROID_HOME=/opt/android-sdk
$ . ./tools/android_helpers.sh

$ android_get_arch_list
armeabi-v7a arm64-v8a x86 x86_64

# Prepare to build
$ ./tools/cleanup.sh
$ ./tools/autogen.sh

# See the comments in tools/android_helpers.sh for arguments
$ android_build_wally armeabi-v7a $ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64 19 "--enable-swig-java"
```

The script `tools/build_android_libraries.sh` builds the Android release files and
can be used as an example for your own Android projects.

## Cleaning

```
$ ./tools/cleanup.sh
```

## Submitting patches

Please use pull requests on github to submit. Before producing your patch you
should format your changes using [uncrustify](https://github.com/uncrustify/uncrustify.git)
version 0.60 or later. The script `./tools/uncrustify` will reformat all C
sources in the library as needed, with the currently chosen uncrustify options.

You should also make sure the existing tests pass and if possible write tests
covering any new functionality, following the existing style.

## Generating a coverage report

To generate an HTML coverage report, install `lcov` and use:

```
$ ./tools/cleanup.sh
$ ./tools/autogen.sh
$ ./configure --enable-debug --enable-export-all --enable-swig-python --enable-swig-java --enable-coverage
$ make
$ ./tools/coverage.sh clean
$ make check
$ ./tools/coverage.sh
```

The coverage report can then be viewed at `src/lcov/index.html`. Patches to
increase the test coverage are welcome.

## Users of libwally-core

Projects and products that are known to depend on or use `libwally`:
* [Blockstream Green Command Line Wallet](https://github.com/Blockstream/green_cli)
* [Blockstream Green Development Kit](https://github.com/Blockstream/gdk)
* [Blockstream Green Wallet for Android](https://github.com/Blockstream/green_android)
* [Blockstream Green Wallet for iOS](https://github.com/Blockstream/green_ios)
* [Blockstream/liquid-melt](https://github.com/Blockstream/liquid-melt)
* [Blockstream/liquid_multisig_issuance](https://github.com/Blockstream/liquid_multisig_issuance)
* [c-lightning](https://github.com/ElementsProject/lightning)
* [gdk_rpc for bitcoind/liquidd](https://github.com/Blockstream/gdk_rpc)
* [GreenAddress Recovery Tool](https://github.com/greenaddress/garecovery)
* [GreenAddress Wallet for Windows/Mac/Linux](https://github.com/greenaddress/WalletElectron)
* [GreenAddress Web Files](https://github.com/greenaddress/GreenAddressWebFiles)
* [LibWally Swift](https://github.com/blockchain/libwally-swift)
* [Multy-Core](https://github.com/Multy-io/Multy-Core)

Please note that some of listed projects may be experimental or superseded.
