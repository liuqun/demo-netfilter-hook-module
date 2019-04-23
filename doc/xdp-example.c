// Original documents:
// https://cilium.readthedocs.io/en/latest/bpf/#llvm

#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
    return XDP_DROP;
}

__section("license")
char __license[] = "GPL";

// 以下为vim排版选项:
// vi: set expandtab tabstop=4 shiftwidth=4 :
