lib_LTLIBRARIES = libwallycore.la

libwallycore_la_SOURCES = \
    bip39.c \
    mnemonic.c \
    wordlist.c \
    ccan/ccan/crypto/sha256/sha256.c

libwallycore_la_INCLUDES = mnemonic.h wordlist.h
libwallycore_la_CFLAGS = -I$(top_srcdir) -Iccan

#SUBDIRS = test
