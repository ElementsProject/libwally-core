#!/bin/sh

# Clean up all generated files
make distclean >/dev/null 2>&1

rm -f */*~
rm -f *~
rm -f Makefile.in
rm -f aclocal.m4
rm -f config.h.in
rm -f configure
rm -f src/*pyc
rm -f src/test/*pyc
rm -f src/wallycore.py
rm -f src/swig_python_wrap.c
rm -f src/Makefile.in
rm -f src/config.h.in
rm -f src/test_clear*
rm -f src/test-suite.log
rm -rf src/.libs
rm -f tools/build-aux/compile
rm -f tools/build-aux/config.guess
rm -f tools/build-aux/config.sub
rm -f tools/build-aux/depcomp
rm -f tools/build-aux/install-sh
rm -f tools/build-aux/ltmain.sh
rm -f tools/build-aux/missing
rm -f tools/build-aux/m4/l*.m4
rm -f tools/build-aux/test-driver
rm -rf autom4te.cache/
rm -rf bld/
