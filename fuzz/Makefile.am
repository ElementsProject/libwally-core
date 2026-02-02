noinst_PROGRAMS = fuzz_psbt

fuzz_psbt_SOURCES = fuzz_psbt.c
fuzz_psbt_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
fuzz_psbt_LDFLAGS = -fsanitize=fuzzer
fuzz_psbt_LDADD = $(top_builddir)/src/libwallycore.la
