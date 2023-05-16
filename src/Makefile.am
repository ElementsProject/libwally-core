LIBSECP256K1=secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

noinst_LTLIBRARIES =

include_HEADERS =
include_HEADERS += $(top_srcdir)/include/wally.hpp
include_HEADERS += $(top_srcdir)/include/wally_address.h
include_HEADERS += $(top_srcdir)/include/wally_anti_exfil.h
include_HEADERS += $(top_srcdir)/include/wally_bip32.h
include_HEADERS += $(top_srcdir)/include/wally_bip38.h
include_HEADERS += $(top_srcdir)/include/wally_bip39.h
include_HEADERS += $(top_srcdir)/include/wally_bip85.h
include_HEADERS += $(top_srcdir)/include/wally_coinselection.h
include_HEADERS += $(top_srcdir)/include/wally_core.h
include_HEADERS += $(top_srcdir)/include/wally_crypto.h
include_HEADERS += $(top_srcdir)/include/wally_descriptor.h
include_HEADERS += $(top_srcdir)/include/wally_elements.h
include_HEADERS += $(top_srcdir)/include/wally_map.h
include_HEADERS += $(top_srcdir)/include/wally_psbt.h
include_HEADERS += $(top_srcdir)/include/wally_psbt_members.h
include_HEADERS += $(top_srcdir)/include/wally_script.h
include_HEADERS += $(top_srcdir)/include/wally_symmetric.h
include_HEADERS += $(top_srcdir)/include/wally_transaction.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = wallycore.pc

if BUILD_ELEMENTS
SWIG_GEN_FLAGS := -DBUILD_ELEMENTS=1
TOOLS_EXTRA_ARGS := "elements"
else
SWIG_GEN_FLAGS :=
TOOLS_EXTRA_ARGS :=
endif

if USE_SWIG_PYTHON
noinst_LTLIBRARIES += libswig_python.la
libswig_python_la_SOURCES = swig_python/swig_python_wrap.c

libswig_python_la_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(SWIG_WARN_CFLAGS) $(NOALIAS_CFLAGS)
if PYTHON_MANYLINUX
else
libswig_python_la_LIBADD = $(PYTHON_LIBS)
endif # PYTHON_MANYLINUX

# Append our extra wrapper code to the package
swig_python/swig_python_wrap.c : swig_python/swig.i swig_python/python_extra.py_in
	$(AM_V_at)$(SWIG) $(SWIG_PYTHON_OPT) $(SWIG_GEN_FLAGS) -outdir swig_python -o $@ $< && \
    $(GNU_SED) -i 's/(unsigned long long const \*)/(uint64_t const \*)/g' $@ && \
    cat swig_python/wallycore.py swig_python/python_extra.py_in > swig_python/wallycore/__init__.py && \
    rm swig_python/wallycore.py

PYTHON_SWIGTEST = PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.libs:swig_python $(PYTHON)

clean-swig-python:
	$(AM_V_at)rm -f swig_python/swig_python_wrap.c swig_python/wallycore/__init__.py
clean-local: clean-swig-python
endif # USE_SWIG_PYTHON

if RUN_PYTHON_TESTS
# Python requires the shared library to be named _wallycore.so
# for 'import' to work.
if IS_OSX
platform_dso_ext = dylib
else
if IS_MINGW
platform_dso_ext = dll
else
platform_dso_ext = so
endif # IS_MINGW
endif # IS_OSX
.libs/_wallycore.so: .libs/libwallycore.$(platform_dso_ext)
	$(AM_V_at)ln -sfn libwallycore.$(platform_dso_ext) $@
PYTHON_TEST_DEPS = .libs/_wallycore.so
PYTHON_TEST = PYTHONDONTWRITEBYTECODE=1 $(PYTHON)
endif

if USE_SWIG_JAVA
noinst_LTLIBRARIES += libswig_java.la
libswig_java_la_SOURCES = \
    swig_java/swig_java_wrap.c

libswig_java_la_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS) $(SWIG_JAVA_CPPFLAGS) $(SWIG_WARN_CFLAGS)

SWIG_JOPT = $(SWIG_JAVA_OPT) -outdir swig_java -noproxy -package com.blockstream.libwally

swig_java/swig_java_wrap.c: swig_java/swig.i swig_java/jni_extra.java_in
	$(AM_V_at)$(SWIG) $(SWIG_JOPT) $(SWIG_GEN_FLAGS) -o $@ $< && \
    $(GNU_SED) -i 's/wallycoreJNI/Wally/g' $@ && \
    $(GNU_SED) -i 's/ = (char \*) (\*jenv)->Get/ = (unsigned char \*) (\*jenv)->Get/g' $@

cblw=com/blockstream/libwally
cbt=com/blockstream/test
sjs=swig_java/src
$(sjs)/$(cblw)/Wally.java: swig_java/swig_java_wrap.c
	$(AM_V_at)$(top_srcdir)/tools/swigjavapost.sh @GNU_SED@ $(TOOLS_EXTRA_ARGS)

$(sjs)/$(cblw)/Wally.class: $(sjs)/$(cblw)/Wally.java
	$(AM_V_at)$(JAVAC) -implicit:none -source $(JAVAC_TARGET) -target $(JAVAC_TARGET) -sourcepath $(sjs)/$(cblw)/ $(sjs)/$(cblw)/Wally.java

swig_java/wallycore.jar: $(sjs)/$(cblw)/Wally.class
	$(AM_V_at)$(JAR) cf swig_java/wallycore.jar -C $(sjs) '$(cblw)/Wally$$Obj.class' -C $(sjs) '$(cblw)/Wally.class'

$(sjs)/$(cbt)/%.class: $(sjs)/$(cbt)/%.java swig_java/wallycore.jar
	$(AM_V_at)$(JAVAC) -implicit:none -source $(JAVAC_TARGET) -target $(JAVAC_TARGET) -sourcepath $(sjs) $(filter %.java,$^)

if HAVE_JAVAC
all: swig_java/wallycore.jar

SWIG_JAVA_TEST_DEPS = \
    $(sjs)/$(cbt)/test_bip32.class \
    $(sjs)/$(cbt)/test_descriptor.class \
    $(sjs)/$(cbt)/test_tx.class \
    $(sjs)/$(cbt)/test_scripts.class \
    $(sjs)/$(cbt)/test_mnemonic.class

if BUILD_ELEMENTS
SWIG_JAVA_TEST_DEPS += $(sjs)/$(cbt)/test_assets.class \
    $(sjs)/$(cbt)/test_pegs.class
endif

all: $(SWIG_JAVA_TEST_DEPS)

JAVA_TEST = @LDPATH_VAR@=.libs $(JAVA) -Djava.library.path=.libs -classpath $(sjs) com.blockstream.test.

endif # HAVE_JAVAC

clean-swig-java:
	$(AM_V_at)rm -rf swig_java/swig_java_wrap.c $(sjs)/$(cblw) $(sjs)/$(cbt)/*.class swig_java/*.java swig_java/*.jar
clean-local: clean-swig-java
endif # USE_SWIG_JAVA

lib_LTLIBRARIES = libwallycore.la

libwallycore_la_SOURCES = \
    address.c \
    anti_exfil.c \
    aes.c \
    base58.c \
    base64.c \
    bip32.c \
    bip38.c \
    bip39.c \
    bip85.c \
    bech32.c \
    coins.c \
    descriptor.c \
    ecdh.c \
    elements.c \
    blech32.c \
    hex.c \
    hmac.c \
    internal.c \
    map.c \
    mnemonic.c \
    pbkdf2.c \
    psbt.c \
    pullpush.c \
    script.c \
    scrypt.c \
    sign.c \
    symmetric.c \
    transaction.c \
    wif.c \
    wordlist.c \
    ccan/ccan/base64/base64.c \
    ccan/ccan/crypto/ripemd160/ripemd160.c \
    ccan/ccan/crypto/sha256/sha256.c \
    ccan/ccan/crypto/sha512/sha512.c \
    ccan/ccan/str/hex/hex.c

libwallycore_la_INCLUDES = \
    include/wally.hpp \
    include/wally_address.h \
    include/wally_bip32.h \
    include/wally_bip38.h \
    include/wally_bip39.h \
    include/wally_bip85.h \
    include/wally_coinselection.h \
    include/wally_core.h \
    include/wally_crypto.h \
    include/wally_descriptor.h \
    include/wally_elements.h \
    include/wally_map.h \
    include/wally_psbt.h \
    include/wally_script.h \
    include/wally_symmetric.h \
    include/wally_transaction.h

if SHARED_BUILD_ENABLED
if IS_MINGW
libwallycore_la_LDFLAGS = -no-undefined
else
libwallycore_la_LDFLAGS = 
endif
endif # SHARED_BUILD_ENABLED

libwallycore_la_CFLAGS = -I$(top_srcdir) -I$(srcdir)/ccan -DWALLY_CORE_BUILD=1 $(AM_CFLAGS)
libwallycore_la_LIBADD = $(LIBADD_SECP256K1) $(noinst_LTLIBRARIES)

SUBDIRS = secp256k1

TESTS =
noinst_PROGRAMS =
if RUN_TESTS
TESTS += test_bech32
noinst_PROGRAMS += test_bech32
test_bech32_SOURCES = ctest/test_bech32.c
test_bech32_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
test_bech32_LDADD = $(lib_LTLIBRARIES) @CTEST_EXTRA_STATIC@
if PYTHON_MANYLINUX
test_bech32_LDADD += $(PYTHON_LIBS)
endif
TESTS += test_psbt
noinst_PROGRAMS += test_psbt
test_psbt_SOURCES = ctest/test_psbt.c ccan/ccan/str/hex/hex.c
test_psbt_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS) -I$(srcdir)/ccan
test_psbt_LDADD = $(lib_LTLIBRARIES) @CTEST_EXTRA_STATIC@
if PYTHON_MANYLINUX
test_psbt_LDADD += $(PYTHON_LIBS)
endif
TESTS += test_psbt_limits
noinst_PROGRAMS += test_psbt_limits
test_psbt_limits_SOURCES = ctest/test_psbt_limits.c ccan/ccan/str/hex/hex.c
test_psbt_limits_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS) -I$(srcdir)/ccan
test_psbt_limits_LDADD = $(lib_LTLIBRARIES) @CTEST_EXTRA_STATIC@
if PYTHON_MANYLINUX
test_psbt_limits_LDADD += $(PYTHON_LIBS)
endif
if USE_PTHREAD
TESTS += test_clear
noinst_PROGRAMS += test_clear
test_clear_SOURCES = ctest/test_clear.c
test_clear_CFLAGS = -I$(top_srcdir)/include $(PTHREAD_CFLAGS) $(AM_CFLAGS) $(NOOPT_CFLAGS) $(NOBUILTIN_CFLAGS)
test_clear_LIBS = $(PTHREAD_LIBS)
test_clear_LDADD = $(lib_LTLIBRARIES) @CTEST_EXTRA_STATIC@
if PYTHON_MANYLINUX
test_clear_LDADD += $(PYTHON_LIBS)
endif
endif
TESTS += test_coinselection
noinst_PROGRAMS += test_coinselection
test_coinselection_SOURCES = ctest/test_coinselection.c
test_coinselection_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
test_coinselection_LDADD = $(lib_LTLIBRARIES) @CTEST_EXTRA_STATIC@
if PYTHON_MANYLINUX
test_coinselection_LDADD += $(PYTHON_LIBS)
endif
TESTS += test_tx
noinst_PROGRAMS += test_tx
test_tx_SOURCES = ctest/test_tx.c
test_tx_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
test_tx_LDADD = $(lib_LTLIBRARIES) @CTEST_EXTRA_STATIC@
if PYTHON_MANYLINUX
test_tx_LDADD += $(PYTHON_LIBS)
endif
TESTS += test_descriptor
noinst_PROGRAMS += test_descriptor
test_descriptor_SOURCES = ctest/test_descriptor.c
test_descriptor_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
test_descriptor_LDADD = $(lib_LTLIBRARIES) @CTEST_EXTRA_STATIC@
if PYTHON_MANYLINUX
test_descriptor_LDADD += $(PYTHON_LIBS)
endif
if BUILD_ELEMENTS
TESTS += test_elements_tx
noinst_PROGRAMS += test_elements_tx
test_elements_tx_SOURCES = ctest/test_elements_tx.c
test_elements_tx_CFLAGS = -I$(top_srcdir)/include $(AM_CFLAGS)
test_elements_tx_LDADD = $(lib_LTLIBRARIES) @CTEST_EXTRA_STATIC@
if PYTHON_MANYLINUX
test_elements_tx_LDADD += $(PYTHON_LIBS)
endif
endif

check-local: check-libwallycore check-swig-python check-swig-java
	$(AM_V_at)! grep '^int ' $(top_srcdir)/include/*.h # Missing WALLY_CORE_API

if SHARED_BUILD_ENABLED
if RUN_PYTHON_TESTS
check-libwallycore: $(PYTHON_TEST_DEPS)
	$(AM_V_at)$(PYTHON_TEST) test/test_address.py
	$(AM_V_at)$(PYTHON_TEST) test/test_aes.py
	$(AM_V_at)$(PYTHON_TEST) test/test_anti_exfil.py
	$(AM_V_at)$(PYTHON_TEST) test/test_base58.py
	$(AM_V_at)$(PYTHON_TEST) test/test_base64.py
	$(AM_V_at)$(PYTHON_TEST) test/test_bech32.py
	$(AM_V_at)$(PYTHON_TEST) test/test_bip32.py
	$(AM_V_at)$(PYTHON_TEST) test/test_bip38.py
	$(AM_V_at)$(PYTHON_TEST) test/test_bip39.py
	$(AM_V_at)$(PYTHON_TEST) test/test_bip85.py
	$(AM_V_at)$(PYTHON_TEST) test/test_coinselection.py
	$(AM_V_at)$(PYTHON_TEST) test/test_descriptor.py
	$(AM_V_at)$(PYTHON_TEST) test/test_ecdh.py
	$(AM_V_at)$(PYTHON_TEST) test/test_hash.py
	$(AM_V_at)$(PYTHON_TEST) test/test_hex.py
	$(AM_V_at)$(PYTHON_TEST) test/test_hmac.py
	$(AM_V_at)$(PYTHON_TEST) test/test_internal.py
	$(AM_V_at)$(PYTHON_TEST) test/test_map.py
	$(AM_V_at)$(PYTHON_TEST) test/test_mnemonic.py
	$(AM_V_at)$(PYTHON_TEST) test/test_psbt.py
	$(AM_V_at)$(PYTHON_TEST) test/test_pbkdf2.py
	$(AM_V_at)$(PYTHON_TEST) test/test_script.py
	$(AM_V_at)$(PYTHON_TEST) test/test_scrypt.py
	$(AM_V_at)$(PYTHON_TEST) test/test_sign.py
	$(AM_V_at)$(PYTHON_TEST) test/test_symmetric.py
	$(AM_V_at)$(PYTHON_TEST) test/test_transaction.py
	$(AM_V_at)$(PYTHON_TEST) test/test_wif.py
	$(AM_V_at)$(PYTHON_TEST) test/test_wordlist.py
if BUILD_ELEMENTS
	$(AM_V_at)$(PYTHON_TEST) test/test_confidential_addr.py
	$(AM_V_at)$(PYTHON_TEST) test/test_pegin.py
	$(AM_V_at)$(PYTHON_TEST) test/test_pegout.py
	$(AM_V_at)$(PYTHON_TEST) test/test_elements.py
endif

if USE_SWIG_PYTHON
check-swig-python: $(SWIG_PYTHON_TEST_DEPS)
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/bip32.py
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/coinselection.py
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/descriptor.py
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/mnemonic.py
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/psbt.py
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/sha.py
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/signmessage.py
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/tx.py
	$(AM_V_at)$(PYTHON_SWIGTEST) pyexample/anti-exfil.py
if BUILD_ELEMENTS
	$(AM_V_at)$(PYTHON_SWIGTEST) swig_python/contrib/elements_tx.py
	$(AM_V_at)$(PYTHON_SWIGTEST) pyexample/liquid/receive-send.py
endif
else # USE_SWIG_PYTHON
check-swig-python: ;
endif # USE_SWIG_PYTHON
else # RUN_PYTHON_TESTS
check-libwallycore: ;
endif # RUN_PYTHON_TESTS

if RUN_JAVA_TESTS
check-swig-java: $(SWIG_JAVA_TEST_DEPS)
	$(AM_V_at)! grep 'native int wally_' $(sjs)/$(cblw)/Wally.java # Unwrapped Java calls
	$(AM_V_at)! grep 'native Object wally_' $(sjs)/$(cblw)/Wally.java # Unwrapped Java calls
if BUILD_ELEMENTS
	$(AM_V_at)$(JAVA_TEST)test_assets
	$(AM_V_at)$(JAVA_TEST)test_pegs
endif
	$(AM_V_at)$(JAVA_TEST)test_bip32
	$(AM_V_at)$(JAVA_TEST)test_descriptor
	$(AM_V_at)$(JAVA_TEST)test_mnemonic
	$(AM_V_at)$(JAVA_TEST)test_scripts
	$(AM_V_at)$(JAVA_TEST)test_tx
else # RUN_JAVA_TESTS
check-swig-java: ;
endif # RUN_JAVA_TESTS

endif # SHARED_BUILD_ENABLED
.PHONY: check-libwallycore check-swig-python check-swig-java clean-swig-python clean-swig-java
else # RUN_TESTS
.PHONY: clean-swig-python clean-swig-java
endif # RUN_TESTS

