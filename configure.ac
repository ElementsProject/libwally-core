AC_PREREQ([2.69])
AC_INIT(libwallycore, 0.1)
AC_CONFIG_AUX_DIR([tools/build-aux])
AC_CONFIG_MACRO_DIR([tools/build-aux/m4])
AC_CONFIG_SRCDIR([src/mnemonic.h])
AC_CONFIG_HEADERS([src/config.h])
AH_TOP([#ifndef LIBWALLYCORE_CONFIG_H])
AH_TOP([#define LIBWALLYCORE_CONFIG_H])
AH_BOTTOM([#include "ccan_config.h"
#endif /*LIBWALLYCORE_CONFIG_H*/])

AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_INIT

AC_PROG_CC

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
AC_ARG_ENABLE(export-all,
    AS_HELP_STRING([--enable-export-all],[export all functions (for testing, default: no)]),
    [export_all=$enableval], [export_all=no])
AM_CONDITIONAL([EXPORT_ALL], [test x"$export_all" = "xyes"])

if test "x$CFLAGS" = "x"; then
  CFLAGS="-O3 -g"
fi

warn_CFLAGS="--pedantic -Wall -W -Wextra -Wcast-align -Wnested-externs -Wshadow -Wstrict-prototypes -Wno-unused-function -Wno-long-long -Wno-overlength-strings"
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS $warn_CFLAGS"
AC_MSG_CHECKING([if ${CC} supports ${warn_CFLAGS}])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[char foo;]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
        CFLAGS="$saved_CFLAGS"
    ])

if test "x$export_all" != "xyes"; then
    saved_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS -fvisibility=hidden"
    AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[char foo;]])],
        [ AC_MSG_RESULT([yes]) ],
        [ AC_MSG_RESULT([no])
            CFLAGS="$saved_CFLAGS"
        ])
fi

AC_C_BIGENDIAN()
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

AC_DEFUN([AC_HAVE_UNALIGNED_ACCESS],
    [AC_TRY_RUN([int main(){static int a[2];return *((int*)(((char*)a)+1)) != 0;}],
        [ac_have_unaligned_access=yes], [ac_have_unaligned_access=no])]
if test "x$ac_have_unaligned_access" = "xyes"; then
    AC_DEFINE([HAVE_UNALIGNED_ACCESS], [1], [Define if we have unaligned access])
fi
)
AC_HAVE_UNALIGNED_ACCESS

AC_DEFUN([AC_HAVE_ATTRIBUTE_WEAK],
    [AC_TRY_RUN([extern int foo(int) __attribute__((weak)); int main(){return 0;}],
        [ac_have_attribute_weak=yes], [ac_have_attribute_weak=no])]
if test "x$ac_have_attribute_weak" = "xyes"; then
    AC_DEFINE([HAVE_ATTRIBUTE_WEAK], [1], [Define if we have __attribute__((weak)) support])
fi
)
AC_HAVE_ATTRIBUTE_WEAK

AC_CHECK_HEADERS([byteswap.h])

#
# Python facilities
#
AC_PYTHON_DEVEL
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

AC_CONFIG_FILES([
 Makefile
 src/Makefile
 src/test/Makefile
])

ac_configure_args="${ac_configure_args} --disable-shared --disable-jni --with-pic --with-bignum=no"
AC_CONFIG_SUBDIRS([src/secp256k1])


AC_OUTPUT
