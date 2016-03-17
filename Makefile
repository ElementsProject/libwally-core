libname := wally

src := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

bld := $(src)bld/

ccan_srcs := \
    ccan/ccan/crypto/ripemd160/ripemd160.c \
    ccan/ccan/crypto/sha256/sha256.c

lib_srcs := \
    bip39.c \
    mnemonic.c \
    wordlist.c

srcs := $(ccan_srcs) $(lib_srcs)

objs := $(srcs:%.c=$(bld)%.o)

pytests := $(wildcard test/test_*.py)

override CFLAGS ?= -g -Wall -W -Wno-missing-field-initializers
override CFLAGS += -fPIC -I $(bld) -I ccan/ -I .

.PHONY: all clean
all::;

clean:
	-rm -rf $(bld)

$(bld)config.h: $(bld)ccan/tools/configurator/configurator
	$< > $@

$(bld)%.ok: %.py
	@-mkdir -p $(@D)
	python $< && touch $@

$(bld)%: %.c
	@-mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $<

$(bld)%.o: %.c $(bld)config.h
	@-mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

shared_lib := $(bld)lib$(libname).so
$(shared_lib): $(objs)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $(objs) $(LDLIBS)

tests := $(pytests:%.py=$(bld)%.ok)
test: $(shared_lib) $(tests)

all:: $(shared_lib);
