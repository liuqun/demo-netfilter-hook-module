project_rootdir = $(CURDIR)
srcdir = $(project_rootdir)/src
incdir = $(project_rootdir)/include
vpath %.c $(srcdir)
vpath %.h $(srcdir) $(incdir)
srcfiles = $(notdir $(wildcard $(srcdir)/*.c))
objfiles = $(patsubst %.c,%.o,$(srcfiles))
asmfiles = $(patsubst %.c,%.ll,$(srcfiles))
host_cpu := $(shell uname --machine)
LLC ?= llc-8
CLANG ?= clang-8
CFLAGS := -O2 -target bpf
CPPFLAGS += -I$(incdir)
CPPFLAGS += -I/usr/include/$(host_cpu)-linux-gnu
RM := rm -rf

.PHONY: all
all: $(objfiles) $(asmfiles)

.PHONY: clean
clean:
	$(RM) $(objfiles) $(asmfiles)

%.o: %.c
	$(CLANG) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

# LLVM assembly language format (.ll)
%.ll: %.c
	$(CLANG) $(CPPFLAGS) $(CFLAGS) -S -o $@ -c $<

# vi: set noexpandtab ts=4 sw=4 :
