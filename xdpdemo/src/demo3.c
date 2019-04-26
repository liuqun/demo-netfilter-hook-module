#include <linux/stddef.h>
//#include <linux/bpf.h>
//#include <linux/in.h>
//#include <linux/if_ether.h>
//#include <linux/ip.h>
//#include <linux/ipv6.h>
//#include <linux/if_packet.h>
//#include <linux/icmpv6.h>
//#include "bpf_helpers.h"
//#include "bpf_endian.h"
//#include "xdp_stats_kern_user.h"
//#include "xdp_stats_kern.h"

__always_inline
int foobar(int a, int b)
{
	return a+b;
}

int main()
{
	return foobar(1, 2);
}
