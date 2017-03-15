#ifndef LIBWALLYCORE_CONFIG_H
#define LIBWALLYCORE_CONFIG_H

#define HAVE_ATTRIBUTE_WEAK 1
#define HAVE_DLFCN_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_MEMORY_H 1
#define HAVE_MMAP 1
#define HAVE_PTHREAD 1
#define HAVE_PTHREAD_PRIO_INHERIT 1
#define HAVE_PYTHON "2.7"
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define STDC_HEADERS 1
#define VERSION "0.1"

#define HAVE_LITTLE_ENDIAN 1
/* Clear a set of memory areas passed as ptr1, len1, ptr2, len2 etc */
void clear_n(unsigned int count, ...);
#define alignment_ok(p, n) ((size_t)(p) % (n) == 0)
#define CCAN_CLEAR_MEMORY(p, len) clear_n(1, p, len)

#endif /*LIBWALLYCORE_CONFIG_H*/
