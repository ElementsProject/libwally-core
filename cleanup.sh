#!/bin/sh

# Clean up all generated files

make distclean

rm -rf bld/
rm -rf autom4te.cache/
rm -f Makefile.in
rm -f aclocal.m4
rm -f compile
rm -f config.guess
rm -f config.h.in
rm -f config.sub
rm -f configure
rm -f depcomp
rm -f install-sh
rm -f ltmain.sh
rm -f missing
rm -f src/Makefile.in
rm -f src/config.h.in
rm -f *~
rm -f */*~
