libname := libwally

src := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

bld := $(src)bld/

srcs := \
    ccan/ccan/crypto/ripemd160/ripemd160.c \
    ccan/ccan/crypto/sha256/sha256.c

objs := $(srcs:%.c=$(bld)%.o)

CFLAGS ?= -O2 -g -Wall
CFLAGS += -fPIC -I $(bld) -I ccan/

.PHONY: all clean
all::;

clean:
	-rm -r $(bld)

$(bld)config.h: $(bld)ccan/tools/configurator/configurator
	$< > $@

$(bld)%: %.c
	@-mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $<

$(bld)%.o: %.c $(bld)config.h
	@-mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

shared_lib := $(bld)$(libname).so
$(shared_lib): $(objs)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $(objs) $(LDLIBS)

all:: $(shared_lib);
