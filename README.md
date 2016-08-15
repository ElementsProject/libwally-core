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


