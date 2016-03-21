/* Config directives for ccan */

#ifdef WORDS_BIGENDIAN
# define HAVE_BIG_ENDIAN 1
# ifdef HAVE_LITTLE_ENDIAN
#  undef HAVE_LITTLE_ENDIAN
# endif
#else
# define HAVE_LITTLE_ENDIAN 1
# ifdef HAVE_BIG_ENDIAN
#  undef HAVE_BIG_ENDIAN
# endif
#endif
