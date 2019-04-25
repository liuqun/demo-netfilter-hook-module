objfiles += $(patsubst %.c,%.o,$(wildcard *.c))
asmfiles += $(patsubst %.c,%.asm,$(wildcard *.c))
host_cpu := $(shell uname --machine)
LLC ?= llc-8
CLANG ?= clang-8
CFLAGS := -O2 -target bpf
CPPFLAGS += -I/usr/include/$(host_cpu)-linux-gnu
CPPFLAGS += -I./include

.PHONY: all
all: $(objfiles)

.PHONY: asm
asm: $(asmfiles)

.PHONY: clean
clean:
	$(RM) $(objfiles) $(asmfiles)

%.o: %.c
	$(CLANG) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<
%.asm: %.c
	$(CLANG) $(CPPFLAGS) $(CFLAGS) -S -o $@ -c $<

# vi: set noexpandtab ts=4 sw=4 :
