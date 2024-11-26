#ifndef LIBWALLYCORE_CONFIG_H
#define LIBWALLYCORE_CONFIG_H

/* config.h for Windows. Assumes a little-endian intel-ish target */
#include <stddef.h>

#ifndef _WIN32
#error windows_config/config.h is only intended for windows builds
#endif

#define HAVE_UNALIGNED_ACCESS 1

#if defined (_WIN32) && !defined(_SSIZE_T_DECLARED) && !defined(_ssize_t) && !defined(ssize_t)
#if defined(_WIN64)
typedef __int64 ssize_t;
#else
typedef long ssize_t;
#endif
#endif

#include "ccan_config.h"

#endif /* LIBWALLYCORE_CONFIG_H */
