LIBSECP256K1=secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

noinst_LTLIBRARIES =

if USE_SWIG_PYTHON
noinst_LTLIBRARIES += libswig_python.la
libswig_python_la_SOURCES = \
    swig_python/swig_python_wrap.c \
    swig_python/swig_python_weak.c

libswig_python_la_CFLAGS = -I$(top_srcdir) $(SWIG_PYTHON_CPPFLAGS) -fno-strict-aliasing

# We must sed the wrapper to workaround SWIGs odd library naming conventions
swig_python/swig_python_wrap.c : swig_python/swig.i
	$(SWIG) $(SWIG_PYTHON_OPT) -outdir swig_python -o $@ $< && $(GNU_SED) -i 's/_wallycore/libwallycore/g' swig_python/wallycore.py $@

PYTHON_TEST = PYTHONDONTWRITEBYTECODE=1 $(PYTHON)
PYTHON_SWIGTEST = PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.libs:swig_python $(PYTHON)
endif

if USE_SWIG_JAVA
noinst_LTLIBRARIES += libswig_java.la
libswig_java_la_SOURCES = \
    swig_java/swig_java_wrap.c

libswig_java_la_CFLAGS = -I$(top_srcdir) $(SWIG_JAVA_CPPFLAGS) -fno-strict-aliasing

swig_java/swig_java_wrap.c : swig_java/swig.i
	$(SWIG) $(SWIG_JAVA_OPT) -outdir swig_java -o $@ $<
endif


lib_LTLIBRARIES = libwallycore.la

libwallycore_la_SOURCES = \
    base58.c \
    bip32.c \
    bip38.c \
    bip39.c \
    hmac.c \
    internal.c \
    mnemonic.c \
    pbkdf2.c \
    scrypt.c \
    wordlist.c \
    ccan/ccan/crypto/ripemd160/ripemd160.c \
    ccan/ccan/crypto/sha256/sha256.c \
    ccan/ccan/crypto/sha512/sha512.c


libwallycore_la_INCLUDES = \
    include/wally_bip32.h \
    include/wally_bip38.h \
    include/wally_bip39.h \
    include/wally-core.h

libwallycore_la_CFLAGS = -I$(top_srcdir) -Iccan -DWALLY_CORE_BUILD=1
libwallycore_la_LIBADD = $(LIBSECP256K1) $(noinst_LTLIBRARIES)

SUBDIRS = secp256k1

TESTS =
if USE_PTHREAD
TESTS += test_clear
noinst_PROGRAMS = test_clear
test_clear_SOURCES = ctest/test_clear.c
test_clear_CFLAGS = -I$(top_srcdir)/include $(PTHREAD_CFLAGS)
test_clear_LIBS = $(PTHREAD_LIBS)
test_clear_LDADD = $(lib_LTLIBRARIES)
endif

check-local:
if HAVE_PYTHON
	$(PYTHON_TEST) test/test_bip32.py
	$(PYTHON_TEST) test/test_bip38.py
	$(PYTHON_TEST) test/test_bip39.py
if EXPORT_ALL
	$(PYTHON_TEST) test/test_base58.py
	$(PYTHON_TEST) test/test_hmac.py
	$(PYTHON_TEST) test/test_mnemonic.py
	$(PYTHON_TEST) test/test_pbkdf2.py
	$(PYTHON_TEST) test/test_scrypt.py
	$(PYTHON_TEST) test/test_sha2.py
	$(PYTHON_TEST) test/test_wordlist.py
endif
if USE_SWIG_PYTHON
	$(PYTHON_SWIGTEST) swig_python/contrib/mnemonic.py
endif
endif
