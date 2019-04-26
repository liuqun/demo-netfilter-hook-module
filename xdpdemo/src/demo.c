#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <linux/stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
//#include <linux/if_packet.h>
//#include <linux/icmpv6.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "xdp_stats_kern_user.h"
#include "xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct cursor {
    void *pos;
};

/* 函数原型声明 */
__always_inline static int cursor_find_next_header_ethernet(struct cursor *p, const void *data_end, struct ethhdr **ethernet_hdr_out);
__always_inline static int cursor_find_next_header_ipv6(struct cursor *p, const void *data_end, struct ipv6hdr **ipv6_hdr_out);
__always_inline static int cursor_find_next_header_ipv4(struct cursor *p, const void *data_end, struct iphdr **ipv4_hdr_out);

/* 指定生成可执行代码的section分区 */
#ifndef __section
# define __section(s) __attribute__((section(s), used))
#endif

SEC("prog")
int packet_parser_prog(struct xdp_md *ctx)
{
    void *data_start = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth;
    struct cursor pos;
    /* Default action XDP_PASS, imply everything we couldn't parse, or that
     * we don't want to deal with, we just pass up the stack and let the
     * kernel deal with it.
     */
    __u32 action = XDP_PASS; /* Default action */
    /* These keep track of the next header type and iterator pointer */
    int nh_type;

    /* Start next header cursor position at data_start */
    pos.pos = data_start;
    if (!cursor_find_next_header_ethernet(&pos, data_end, &eth)) {
        goto out;
    }
    switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IPV6:
        return XDP_DROP;
        break;
    case ETH_P_IP:
        return XDP_DROP;
        break;
    default:
        goto out;
    }

out:
    return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

/**
 * 以太网报头(MAC地址头)提取函数 cursor_find_next_header_ethernet()
 *
 * 说明: 返回值为int整数, 失败时返回0, 成功时返回以太网报头字节数
 */
__always_inline
static int cursor_find_next_header_ethernet(
    struct cursor *p,
    const void *data_end,
    struct ethhdr **next_hdr_out)
{
    struct ethhdr *eth_hdr = p->pos;

    if ((void *)(eth_hdr + 1) > data_end) {
        return -1;
    }

    p->pos += sizeof(struct ethhdr);
    *next_hdr_out = eth_hdr;

    return sizeof(struct ethhdr);
}

/**
 * IPv6报头提取函数 cursor_find_next_header_ipv6()
 * 
 * 说明: 返回值为int整数, 失败时返回0, 成功时返回IPv6报头字节数
 */
__always_inline
static int cursor_find_next_header_ipv6(
    struct cursor *p,
    const void *data_end,
    struct ipv6hdr **next_hdr_out)
{
    struct ipv6hdr *ipv6_hdr = p->pos;

    if ((void *) (ipv6_hdr + 1) > data_end) {
        return 0;
    }

    p->pos = (void *) (ipv6_hdr + 1);
    *next_hdr_out = ipv6_hdr;

    return sizeof(struct ipv6hdr);
}

/**
 * IPv4报头提取函数 cursor_find_next_header_ipv4()
 * 
 * 说明: 返回值为int整数, 失败时返回0, 成功时返回IPv4报头字节数
 */
static __always_inline int cursor_find_next_header_ipv4(
    struct cursor *p,
    const void *data_end,
    struct iphdr **next_hdr_out)
{
    struct iphdr *ipv4_hdr = p->pos;
    int hdrsize;

    if ((void *) (ipv4_hdr + 1) > data_end) {
        return 0;
    }

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    hdrsize = ipv4_hdr->ihl * 4;
    if (p->pos + hdrsize > data_end) {
        return 0;
    }

    p->pos += hdrsize;
    *next_hdr_out = ipv4_hdr;

    return hdrsize;
}

SEC("license")
char _license[] = "GPL";

// vi: set expandtab tabstop=4 shiftwidth=4 :
