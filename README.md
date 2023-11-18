# libwally-core

Wally is a cross-platform, cross-language collection of useful primitives
for cryptocurrency wallets.

Read the API documentation at https://wally.readthedocs.io.

Please see the [CHANGES](./CHANGES.md) for change details (including ABI changes) when upgrading.

Please report bugs and submit patches to [Our github repository](https://github.com/ElementsProject/libwally-core). If you wish to report a security issue, please read [Our security reporting guidelines](./SECURITY.md).

[![Documentation Status](https://readthedocs.org/projects/wally/badge/?version=latest)](https://wally.readthedocs.io/en/latest/?badge=latest)

## Platforms

Wally can currently be built for:
- Linux
- Android
- macOS
- iOS
- Windows
- Embedded (e.g ESP-32)
- WebAssembly

And can be used from:
- C and compatible languages which can call C interfaces
- C++ (see include/wally.hpp for C++ container support)
- Python 3.x
- Java
- Javascript via node.js or web browser.

## Building

```
# Initialise the libsecp sources (Needs to be run only once)
$ git submodule init
$ git submodule sync --recursive
$ git submodule update --init --recursive

# Build
$ ./tools/autogen.sh
$ ./configure <options - see below>
$ make
$ make check
```

### Building on macOS

Using homebrew,
```
$ brew install gnu-sed
```

If you wish to enable the SWIG interface, you
will need install the Java JDK 8 or newer, and install SWIG:

```
$ brew install swig
```

### configure options

- `--enable-debug`. Enables debugging information and disables compiler
   optimizations (default: no).
- `--enable-minimal`. Minimises library size and memory requirements to target
   embedded or resource-constrained environments (default: no).
- `--enable-asm`. Enables fast assembly language implementations where available.
   (default: enabled for non-debug builds).
- `--enable-export-all`. Export all functions from the wally shared library.
   Ordinarily only API functions are exported. (default: no). Enable this
   if you want to test the internal functions of the library or are planning
   to submit patches.
- `--enable-swig-python`. Enable the [SWIG](http://www.swig.org/) Python
   interface. The resulting shared library can be imported from Python using
   the generated interface file `src/swig_python/wallycore/__init__.py`. (default: no).
- `--enable-python-manylinux`. Enable [manylinux](https://github.com/pypa/manylinux)
   support for building [PyPI](https://pypi.org/) compatible python wheels. Using
   the resulting library in non-python programs requires linking with `libpython.so`.
- `--enable-swig-java`. Enable the [SWIG](http://www.swig.org/) Java (JNI)
   interface. After building, see `src/swig_java/src/com/blockstream/libwally/Wally.java`
   for the Java interface definition (default: no).
- `--disable-elements`. Disables support for [Elements](https://elementsproject.org/)
   features, including [Liquid](https://blockstream.com/liquid/) support. Elements
   functions exported by the library will always return WALLY_ERROR (default: no).
- `--disable-elements-abi`. Changes the exposed library ABI to completely remove Elements
   structure members and exported functions. When configured, elements support must be
   disabled and the user must define `WALLY_ABI_NO_ELEMENTS` before including all wally
   header files. This option *must not be given if wally is being installed as a system/shared library*. (default: no).
- `--enabled-standard-secp`. Excludes support for features that are unavailable in
   the standard [libsecp256k1 library](https://github.com/bitcoin-core/secp256k1).
- `--with-system-secp256k1=<package_name>`. Compile and link against a system-wide
   install of libsecp256k1 instead of the in-tree submodule. (default: not enabled).
- `--enable-mbed-tls`. Use mbed-tls hashing functions if available. This typically
   results in faster hashing via hardware on embedded platforms such as ESP32.
   Note that the caller must ensure that ``sdkconfig.h`` and ``soc/soc_caps.h``
   are available when compiling, e.g. by setting the `CFLAGS` environment variable
   before calling configure. (default: no)
- `--enable-coverage`. Enables code coverage (default: no) Note that you will
   need [lcov](http://ltp.sourceforge.net/coverage/lcov.php) installed to
   build with this option enabled and generate coverage reports.
- `--disable-shared`. Disables building a shared library and builds a static
  library instead. (default: no)
- `--disable-tests`. Disables building library tests. (default: no)
- `--disable-clear-tests`. Disables just the test_clear test (required to pass
  the test suite with some compilers). (default: no)

### Recommended development configure options

```
$ ./configure --enable-debug --enable-export-all --enable-swig-python --enable-swig-java --enable-coverage
```

### Compiler options

Set `CC=clang` to use clang for building instead of gcc, when both are
installed.

### Python

For non-development use, you can install wally from PyPI with `pip` as follows:

```
pip install wallycore==1.0.0
```

For development, you can build and install wally using:

```
$ pip install .
```

If you wish to explicitly choose the python version to use, set the
`PYTHON_VERSION` environment variable (to e.g. `3.9`, `3.10` etc) before
running `pip` or (when compiling manually) `./configure`.

You can also install the binary [wally releases](https://github.com/ElementsProject/libwally-core/releases)
using the released wheel files, for example if you don't wish to install from PyPI over the network:

```
pip install wallycore-<version_and_architecture>.whl
```

Each wally release includes a signed `requirements.txt` file. It is strongly
suggested that you verify and use this file when installing, with:

```
pip install --require-hashes -r requirements.txt
```

Doing so ensures that the wheel you install is the version you expect and an
official build. This will detect, for example, if PyPI is hacked and a
malicious wallycore package uploaded.

### Android

Android builds are currently supported for all Android binary targets using
the Android NDK. The script `tools/android_helpers.sh` can be sourced from
the shell or scripts to make it easier to produce builds:

```
$ export ANDROID_NDK=/opt/android-ndk-r23b # r22 is the minimum supported version
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

### WebAssembly

WebAssembly is available as a preview feature. Users may want to avoid using wally compiled for
wasm for signing or encryption/decryption as the transpiled code may not remain constant time.

Building wally as wasm requires following emsdk instructions for
your [platform](https://webassembly.org/getting-started/developers-guide/) and sourcing
the `emsdk_env.sh` file:

```
# Set up the environment variables for the toolchain
$ source $HOME/emsdk/emsdk_env.sh

# Optionally set the list of wally functions to export to wasm (default: all)
$ export EXPORTED_FUNCTIONS="['_malloc','_free','_wally_init','_wally_cleanup',...]"

# Build
$ ./tools/build_wasm.sh [--disable-elements]
```

Note that emsdk v3.1.27 or later is required.

The script `tools/build_wasm.sh` builds the `wallycore.html` example as well
as the required `wallycore.js` and `wallycore.wasm` files, which can be used
as an example for your own WebAssembly projects.

Open `wallycore.html` in a browser via a webserver like [nginx](https://www.nginx.com/)
or `python2 -m SimpleHTTPServer 8000` to run the example.

## Cleaning

```
$ ./tools/cleanup.sh
```

## Submitting patches

Please use pull requests on [github](https://github.com/ElementsProject/libwally-core) to
submit. Before producing your patch you should format your changes
using [uncrustify](https://github.com/uncrustify/uncrustify.git) version 0.60 or
later. The script `./tools/uncrustify` will reformat all C sources in the library
as needed, with the currently chosen uncrustify options.

To reformat a single source file, use e.g.:
```
$ ./tools/uncrustify src/transaction.c
```

Or to reformat all source files, pass no arguments:
```
$ ./tools/uncrustify
```

If you have added new API functions in your patch, run `tools/update_generated.sh`
to update the auto-generated support code for various platforms. This requires
Python and the `jq` binary.

You should also make sure the existing tests pass and if possible write tests
covering any new functionality, following the existing style. You can run the
tests via:
```
$ make check
```

Python ctypes tests (in `./src/test/`) are strongly preferred, but you can add
to the other test suites if your changes target a specific language or your
tests need to be written at a higher level of abstraction.

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

For coverage with `clang`, you need to install `llvm-cov`, typically via the
`llvm-<version>` package that corresponds to your `clang` version. Once
installed, set the `GCOV` environment variable to the versioned `llvm-cov`
binary name before running `./tools/coverage.sh`, e.g:

```
$ GCOV=llvm-cov-11 ./tools/coverage.sh clean
$ make check
$ GCOV=llvm-cov-11 ./tools/coverage.sh
```

The coverage report can be viewed at `./src/lcov/src/index.html`. Patches
to increase the test coverage are welcome.

## Users of libwally-core

Projects and products that are known to depend on or use `libwally`:
* [Blockstream Green Command Line Wallet](https://github.com/Blockstream/green_cli)
* [Blockstream Green Development Kit](https://github.com/Blockstream/gdk)
* [Blockstream Green Wallet for Android](https://github.com/Blockstream/green_android)
* [Blockstream Green Wallet for iOS](https://github.com/Blockstream/green_ios)
* [Blockstream Green Wallet for Desktops](https://github.com/Blockstream/green_qt)
* [Blockstream Jade Hardware Wallet](https://github.com/Blockstream/Jade)
* [BitBox02 Hardware Wallet](https://github.com/digitalbitbox/bitbox02-firmware)
* [Blockstream Blind PIN Server](https://github.com/Blockstream/blind_pin_server)
* [Blockstream/liquid-melt](https://github.com/Blockstream/liquid-melt)
* [Blockstream/liquid_multisig_issuance](https://github.com/Blockstream/liquid_multisig_issuance)
* [c-lightning](https://github.com/ElementsProject/lightning)
* [gdk_rpc for bitcoind/liquidd](https://github.com/Blockstream/gdk_rpc)
* [GreenAddress Recovery Tool](https://github.com/greenaddress/garecovery)
* [GreenAddress Wallet for Windows/Mac/Linux](https://github.com/greenaddress/WalletElectron)
* [GreenAddress Web Files](https://github.com/greenaddress/GreenAddressWebFiles)
* [LibWally Swift](https://github.com/blockchain/libwally-swift)
* [Multy-Core](https://github.com/Multy-io/Multy-Core)

Please note that some of the listed projects may be experimental or superseded.
