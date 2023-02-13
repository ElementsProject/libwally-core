#!/bin/bash
# Set GCOV to e.g. llvm-gov, llvm-gov-11 etc for clang,
# leave it unset for gcc
exec $GCOV gcov "$@"
