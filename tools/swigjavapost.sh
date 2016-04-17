#!/bin/sh

sed_exe=$1

mkdir -p swig_java/src/com/blockstream/libwally
result="swig_java/src/com/blockstream/libwally/wallycore.java"

# Merge the constants and JNI interface into wallycore.java
grep -v '^}$' swig_java/wallycoreJNI.java | $sed_exe 's/wallycoreJNI/wallycore/g' >$result
grep 'public final static' swig_java/wallycoreConstants.java >>$result
echo '}' >>$result

# Clean up
rm -f swig_java/*.java
