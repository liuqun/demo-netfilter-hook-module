objfiles += xdp-example.o xdp-example.S
host_cpu := $(shell uname --machine)
CC := clang
CFLAGS := -O2 -target bpf
CPPFLAGS += -I/usr/include/$(host_cpu)-linux-gnu

.PHONY: all
all: $(objfiles)

%.o: %.c
	$(COMPILE.c) $< -o $@
%.S: %.c
	$(CC) -S $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# vi: set noexpandtab ts=4 sw=4 :
