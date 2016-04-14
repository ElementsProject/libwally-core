#!/bin/sh

# Clean up after swig java generation
rm -f swig_java/SWIGTYPE_p_words.java swig_java/wallycore.java

# Merge the constants and JNI interface into wallycore.java
grep -v '^}$' swig_java/wallycoreJNI.java | sed 's/wallycoreJNI/wallycore/g' >swig_java/wallycore.java
grep 'public final static' swig_java/wallycoreConstants.java >>swig_java/wallycore.java
echo '}' >>swig_java/wallycore.java
rm -f swig_java/wallycoreJNI.java swig_java/wallycoreConstants.java
