// Original documents:
// https://cilium.readthedocs.io/en/latest/bpf/#llvm

#include <linux/bpf.h>
#include "bpf/api.h"

__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
    return XDP_DROP;
}

__section("license")
char __license[] = "GPL";

// 以下为vim排版选项:
// vi: set expandtab tabstop=4 shiftwidth=4 :
