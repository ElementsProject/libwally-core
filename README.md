# libwally-core

Wally is a cross-platform, cross-language collection of useful primitives
for cryptocurrency wallets.

Note that the library is currently pre-release and so the API may change
without notice.

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
- C/C++ (and compatible languages)
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
   the generated interface file `src/swig_python/wallycore/wallycore.py`. (default: no).
- `--enable-swig-java`. Enable the [SWIG](http://www.swig.org/) Java (JNI)
   interface. After building, see `src/swig_java/src/com/blockstream/libwally/Wally.java`
   for the Java interface definition (default: no).
- `--enable-js-wrappers`. Enable the Node.js and Cordova Javascript wrappers.
   This currently requires python to be available at build time (default: no).
- `--enable-coverage`. Enables code coverage (default: no) Note that you will
   need [lcov](http://ltp.sourceforge.net/coverage/lcov.php) installed to
   build with this option enabled and generate coverage reports.
- `--disable-shared`. Disables building a shared library and builds a static
  library instead.

### Recommended development configure options

```
$ ./configure --enable-debug --enable-export-all --enable-swig-python --enable-coverage
```

### Compiler options

Set `CC=clang` to use clang for building instead of gcc, when both are
installed.

### Python

For python development, you can build and install wally using:

```
$ python setup.py install
```

It is suggested you only install this way into a virtualenv while the library
is under heavy development.

If you wish to explicitly choose the python version to use, set the
`PYTHON_VERSION` environment variable (to e.g. `2`, `2.7`, `3` etc) before
running `./configure`.

### Android

Android builds are currently supported for all Android binary targets using
a toolchain directory created with the Android SDK tool
`make_standalone_toolchain.py`. The script `tools/android_helpers.sh` can be
sourced from the shell or scripts to make it easier to produce builds:

```
$ export ANDROID_HOME=/opt/android-sdk
$ . ./tools/android_helpers.sh

$ android_get_arch_list
armeabi armeabi-v7a arm64-v8a mips mips64 x86 x86_64

# Optional, uses gcc instead of clang (needed e.g. for NDK r15 with mips64)
$ export WALLY_USE_GCC=1

# See the comments in tools/android_helpers.sh for arguments
$ android_build_wally armeabi-v7a $PWD/toolchain-armeabi-v7a 14 "--enable-swig-java"
```

## Cleaning

```
$ ./tools/cleanup.sh
```

## Submitting patches

Please use pull requests on github to submit. Before producing your patch you
should format your changes using [uncrustify](https://github.com/uncrustify/uncrustify.git)
version 0.60 or later. The script `./tools/uncrustify` will reformat all C
sources in the library as needed, with the currently chosen uncrustify options.

The version of uncrustify in Debian is unfortunately out of date and buggy. If
you are using Debian this means you will need to download and build uncrustify
from source using something like:

```
$ git clone --depth 1 https://github.com/uncrustify/uncrustify.git
$ cd uncrustify
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

You should also make sure the existing tests pass and if possible write tests
covering any new functionality, following the existing style.

## Generating a coverage report

To generate an HTML coverage report, use:

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
