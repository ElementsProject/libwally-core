# libwally-core
Useful primitives for wallets.

Please report bugs and submit patches to https://github.com/jgriffiths/libwally-core.

[![Build Status](https://travis-ci.org/jgriffiths/libwally-core.svg?branch=master)](https://travis-ci.org/jgriffiths/libwally-core)

## Building

```
$ ./tools/autogen.sh
$ ./configure
$ make
```

### configure options

- `--enable-debug`. Enables debugging information and disables compiler
   optimisations (default: no).
- `--enable-coverage`. Enables code coverage. See tools/coverage.sh for
   instructions on generating a coverage report (default: no).
- `--enable-export-all`. Export all functions from the wally shared library.
   Ordinarily only API functions are exported. (default: no).
- `--enable-swig-python`. Enable the SWIG python interface. The resulting
   shared library can be directly imported from Python. (default: no).
- `--enable-swig-java`. Enable the SWIG java (JNI) interface. After building,
   see `src/swig_java/src/com/blockstream/libwally/Wally.java` for the Java
   interface definition (default: no).

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
