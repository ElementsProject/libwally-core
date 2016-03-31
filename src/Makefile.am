LIBSECP256K1=secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

libwallycore_la_CFLAGS =

if USE_SWIG_PYTHON
SWIG_SRCS = swig_python_wrap.c swig_python_weak.c

libwallycore_la_CFLAGS += $(SWIG_PYTHON_CPPFLAGS)

# We must sed the wrapper to workaround SWIGs odd library naming conventions
swig_python_wrap.c : swig.i
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ $< && $(GNU_SED) -i 's/_wallycore/libwallycore/g' wallycore.py $@

# FIXME: Add SWIG python tests, e.g.
# PYTHONPATH=".libs" python mnemonic.py
endif

lib_LTLIBRARIES = libwallycore.la

libwallycore_la_SOURCES = \
    $(SWIG_SRCS) \
    bip32.c \
    bip39.c \
    hmac.c \
    internal.c \
    mnemonic.c \
    wordlist.c \
    ccan/ccan/crypto/ripemd160/ripemd160.c \
    ccan/ccan/crypto/sha256/sha256.c \
    ccan/ccan/crypto/sha512/sha512.c

libwallycore_la_INCLUDES = config.h hmac.h internal.h mnemonic.h wordlist.h
libwallycore_la_CFLAGS += -I$(top_srcdir) -Iccan -DWALLY_CORE_BUILD=1
libwallycore_la_LIBADD = $(LIBSECP256K1)

SUBDIRS = secp256k1 test

TESTS = test_clear
noinst_PROGRAMS = test_clear
test_clear_SOURCES = ctest/test_clear.c
test_clear_CFLAGS = -I$(top_srcdir)/include
test_clear_LDADD = $(lib_LTLIBRARIES)
