AC_PREREQ([2.69])
AC_INIT([libwallycore],[0.1])
AC_CONFIG_AUX_DIR([tools/build-aux])
AC_CONFIG_MACRO_DIR([tools/build-aux/m4])
AC_CONFIG_SRCDIR([src/mnemonic.h])
AC_CONFIG_HEADERS([src/config.h])
AH_TOP([#ifndef LIBWALLYCORE_CONFIG_H])
AH_TOP([#define LIBWALLYCORE_CONFIG_H])
AH_BOTTOM([#include "ccan_config.h"
#endif /*LIBWALLYCORE_CONFIG_H*/])

AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_INIT([disable-static])

AC_PROG_CC

# Prefer gccs ar/ranlib as they handle flto files properly
AC_CHECK_PROG(HAVE_GCC_AR,gcc-ar,yes,no)
if test "x$HAVE_GCC_AR" == "xyes"; then
    AR=gcc-ar
    AC_SUBST([AR])
fi

AC_CHECK_PROG(HAVE_GCC_RANLIB,gcc-ranlib,yes,no)
if test "x$HAVE_GCC_RANLIB" == "xyes"; then
    RANLIB=gcc-ranlib
    AC_SUBST([RANLIB])
fi

GNU_SED=sed
AC_CHECK_PROG(HAVE_GSED,gsed,yes,no)
if test "x$HAVE_GSED" == "xyes"; then
  GNU_SED=gsed
else
    case $host_os in
    *darwin*)
        AC_MSG_ERROR([gsed must be available to build this library])
        ;;
    esac
fi
AC_SUBST([GNU_SED])

#
# C facilities
#
AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[enable debugging (default: no)]),
    [debug=$enableval], [debug=no])

CFLAGS=""
if test "x$debug" == "xyes"; then
    # Make debugging easier, leave assertions in
    AX_CHECK_COMPILE_FLAG([-Og], [CFLAGS="$CFLAGS -Og"])
    AX_CHECK_COMPILE_FLAG([-ggdb], [CFLAGS="$CFLAGS -ggdb"])
    LDFLAGS="-Og -ggdb"
else
    # Optimise and harden
    AX_CHECK_COMPILE_FLAG([-O3], [CFLAGS="$CFLAGS -O3"])
    AX_CHECK_COMPILE_FLAG([-flto], [CFLAGS="$CFLAGS -flto"])
    AX_CHECK_COMPILE_FLAG([-DNDEBUG=1], [CFLAGS="$CFLAGS -DNDEBUG=1"])
    AX_CHECK_COMPILE_FLAG([-D_FORTIFY_SOURCE=1], [CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=1"])
    AX_CHECK_COMPILE_FLAG([-fstack-protector-strong], [CFLAGS="$CFLAGS -fstack-protector-strong"])
    LDFLAGS="-O3 -flto -Wl,-z,relro"
fi


AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"])
AX_CHECK_COMPILE_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"])
AX_CHECK_COMPILE_FLAG([-Wpedantic], [CFLAGS="$CFLAGS -Wpedantic"])
AX_CHECK_COMPILE_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"])
AX_CHECK_COMPILE_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"])
AX_CHECK_COMPILE_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"])
AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes], [CFLAGS="$CFLAGS -Wstrict-prototypes"])
AX_CHECK_COMPILE_FLAG([-Wno-unused-function], [CFLAGS="$CFLAGS -Wno-unused-function"])
AX_CHECK_COMPILE_FLAG([-Wno-long-long], [CFLAGS="$CFLAGS -Wno-long-long"])
AX_CHECK_COMPILE_FLAG([-Wno-overlength-strings], [CFLAGS="$CFLAGS -Wno-overlength-strings"])
AX_CHECK_COMPILE_FLAG([-Wformat], [CFLAGS="$CFLAGS -Wformat"])
AX_CHECK_COMPILE_FLAG([-Wformat-security], [CFLAGS="$CFLAGS -Wformat-security"])

AC_ARG_ENABLE(export-all,
    AS_HELP_STRING([--enable-export-all],[export all functions (for testing, default: no)]),
    [export_all=$enableval], [export_all=no])
AM_CONDITIONAL([EXPORT_ALL], [test x"$export_all" = "xyes"])

if test "x$export_all" != "xyes"; then
    AX_CHECK_COMPILE_FLAG([-fvisibility=hidden], [CFLAGS="$CFLAGS -fvisibility=hidden"])
fi

AC_C_BIGENDIAN()
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

AC_DEFUN([AC_HAVE_UNALIGNED_ACCESS],
    # Assume we have no unaligned access if cross-compiling
    [AC_RUN_IFELSE([AC_LANG_SOURCE([int main(void){static int a[2];return *((int*)(((char*)a)+1)) != 0;}])],
        [ac_have_unaligned_access=yes], [ac_have_unaligned_access=no], [ac_have_unaligned_access=no])]
if test "x$ac_have_unaligned_access" = "xyes"; then
    AC_DEFINE([HAVE_UNALIGNED_ACCESS], [1], [Define if we have unaligned access])
fi
)
AC_HAVE_UNALIGNED_ACCESS

AC_DEFUN([AC_HAVE_ATTRIBUTE_WEAK],
    # Assume we are using gcc (i.e. have this attribute) if cross-compiling
    [AC_COMPILE_IFELSE([AC_LANG_SOURCE([extern int foo(int) __attribute__((weak)); int main(void){return 0;}])],
        [ac_have_attribute_weak=yes], [ac_have_attribute_weak=no], [ac_have_attribute_weak=yes])]
if test "x$ac_have_attribute_weak" = "xyes"; then
    AC_DEFINE([HAVE_ATTRIBUTE_WEAK], [1], [Define if we have __attribute__((weak)) support])
fi
)
AC_HAVE_ATTRIBUTE_WEAK

AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sys/mman.h>]],[[mmap(0,0,0,0,0,0)]])],
               [AC_DEFINE(HAVE_MMAP, 1, [Define if we have mmap])])

AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stdlib.h>]],[[return posix_memalign(NULL,0,0)]])],
               [AC_DEFINE(HAVE_POSIX_MEMALIGN, 1, [Define if we have posix_memalign])])

AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <string.h>]],[[int x[1]; memset_s(x, 1, 0, 1)]])],
               [AC_DEFINE(HAVE_MEMSET_S, 1, [Define if we have memset_s])])

AC_CHECK_HEADERS([byteswap.h])

AX_PTHREAD([ac_have_pthread=yes], [ac_have_pthread=no])
AM_CONDITIONAL([USE_PTHREAD], [test x"$ac_have_pthread" = "xyes"])
if test "x$ac_have_pthread" = "xyes"; then
    AC_DEFINE([HAVE_PTHREAD], [1], [Define if we have pthread support])
fi

#
# Python facilities
#
AX_PYTHON_DEVEL([>= '2.7.0'])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != ""])

#
# SWIG
#
AC_ARG_ENABLE(swig-python,
    AS_HELP_STRING([--enable-swig-python],[enable the SWIG python interface (default: no)]),
    [swig_python=$enableval], [swig_python=no])
AM_CONDITIONAL([USE_SWIG_PYTHON], [test x"$swig_python" = "xyes"])

if test "x$swig_python" == "xyes"; then
    AC_PROG_SWIG
    SWIG_PYTHON
fi

AC_ARG_ENABLE(swig-java,
    AS_HELP_STRING([--enable-swig-java],[enable the SWIG java (JNI) interface (default: no)]),
    [swig_java=$enableval], [swig_java=no])
AM_CONDITIONAL([USE_SWIG_JAVA], [test x"$swig_java" = "xyes"])

if test "x$swig_python" == "xyes"; then
    AC_PROG_SWIG
    AX_JNI_INCLUDE_DIR
    for JNI_DIR in $JNI_INCLUDE_DIRS; do
        SWIG_JAVA_CPPFLAGS="$SWIG_JAVA_CPPFLAGS -I$JNI_DIR"
    done
    SWIG_JAVA_OPT="-java"
    AC_SUBST([SWIG_JAVA_CPPFLAGS])
    AC_SUBST([SWIG_JAVA_OPT])
fi

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])

ac_configure_args="${ac_configure_args} --disable-shared --disable-jni --with-pic --with-bignum=no"
AC_CONFIG_SUBDIRS([src/secp256k1])


AC_OUTPUT
