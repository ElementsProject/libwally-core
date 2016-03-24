lib_LTLIBRARIES = libwallycore.la

libwallycore_la_SOURCES = \
    bip39.c \
    hmac.c \
    mnemonic.c \
    wordlist.c \
    ccan/ccan/crypto/sha256/sha256.c \
    ccan/ccan/crypto/sha512/sha512.c

libwallycore_la_INCLUDES = mnemonic.h wordlist.h
libwallycore_la_CFLAGS = -I$(top_srcdir) -Iccan -DWALLY_CORE_BUILD=1

SUBDIRS = test
