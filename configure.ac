AC_PREREQ([2.69])
AC_INIT(libwallycore, 0.1)
AC_CONFIG_SRCDIR([src/mnemonic.h])
AC_CONFIG_HEADERS([src/config.h])
AH_TOP([#ifndef LIBWALLYCORE_CONFIG_H])
AH_TOP([#define LIBWALLYCORE_CONFIG_H])
AH_BOTTOM([#include "ccan_config.h"
#endif /*LIBWALLYCORE_CONFIG_H*/])

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_PATH_PYTHON([2.7],, [:])
LT_INIT

AC_PROG_CC

#
# C facilities
#
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

saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden"
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[char foo;]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      CFLAGS="$saved_CFLAGS"
    ])

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
if test x"$ac_have_unaligned_access" = xyes ; then
    AC_DEFINE([HAVE_UNALIGNED_ACCESS], [1], [Define if we have unaligned access])
fi
)
AC_HAVE_UNALIGNED_ACCESS

AC_CHECK_HEADERS([byteswap.h])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])

AC_OUTPUT
