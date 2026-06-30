noinst_PROGRAMS = fuzz_psbt_from_bytes fuzz_tx_from_bytes fuzz_descriptor fuzz_psbt_musig2

fuzz_psbt_from_bytes_SOURCES = fuzz_psbt_from_bytes.c
fuzz_psbt_from_bytes_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
fuzz_psbt_from_bytes_LDFLAGS = -fsanitize=fuzzer
fuzz_psbt_from_bytes_LDADD = $(top_builddir)/src/libwallycore.la

fuzz_tx_from_bytes_SOURCES = fuzz_tx_from_bytes.c
fuzz_tx_from_bytes_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
fuzz_tx_from_bytes_LDFLAGS = -fsanitize=fuzzer
fuzz_tx_from_bytes_LDADD = $(top_builddir)/src/libwallycore.la

fuzz_descriptor_SOURCES = fuzz_descriptor.c
fuzz_descriptor_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
fuzz_descriptor_LDFLAGS = -fsanitize=fuzzer
fuzz_descriptor_LDADD = $(top_builddir)/src/libwallycore.la

fuzz_psbt_musig2_SOURCES = fuzz_psbt_musig2.c
fuzz_psbt_musig2_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
fuzz_psbt_musig2_LDFLAGS = -fsanitize=fuzzer
fuzz_psbt_musig2_LDADD = $(top_builddir)/src/libwallycore.la
