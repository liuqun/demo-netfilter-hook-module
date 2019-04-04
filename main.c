#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>

MODULE_AUTHOR("Yanchuan Nian");
MODULE_LICENSE("GPL");

static char target[4] = {0, 0, 0, 0};

static unsigned int output_filter(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
    )
{
    int res;
    u8 saddr[4];
    int offset;

    offset = skb_network_offset(skb);
    offset += 12;
    res = skb_copy_bits(skb, offset, saddr, 4);
    if (res < 0) {
        return NF_ACCEPT;
    }

    //{
    //    u8 selfsaddr[4] = {192, 168, 1, 16};
    //    if (memcmp(saddr, selfsaddr, 4) == 0) {
    //        pr_info("Allow:OUTPUT: IP packet src ip=%u.%u.%u.%u\n",
    //                saddr[0], saddr[1], saddr[2], saddr[3]);
    //        return NF_ACCEPT;
    //    }
    //}
    offset += 4;
    {
        u8 dst_addr[4];

        res = skb_copy_bits(skb, offset, dst_addr, 4);
        if (res < 0) {
            return NF_ACCEPT;
        }

        pr_info("Drop:OUTPUT: src ip=%u.%u.%u.%u, dst ip=%u.%u.%u.%u\n",
            saddr[0], saddr[1], saddr[2], saddr[3],
            dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]
            );
    }
    return NF_DROP;
}

static struct nf_hook_ops pkt_input_hook_ops = {
    .hook=output_filter,
    .pf=NFPROTO_IPV4,
    .hooknum=NF_INET_POST_ROUTING,
    .priority=0,
    #if (LINUX_VERSION_CODE <= KERNEL_VERSION(4,3,6))
        .owner=THIS_MODULE,
    #endif // LINUX_VERSION_CODE
};

static unsigned int input_filter(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
    )
{
    int res;
    u8 saddr[4];
    int offset;

    offset = skb_network_offset(skb);
    offset += 12;
    res = skb_copy_bits(skb, offset, saddr, 4);
    if (res < 0) {
        return NF_ACCEPT;
    }

    if (memcmp(saddr, target, 4) == 0) {
        pr_info("Allow:INPUT: src ip=%u.%u.%u.%u\n",
                saddr[0], saddr[1], saddr[2], saddr[3]);
        return NF_ACCEPT;
    }
    pr_info("Drop:INPUT: src ip=%u.%u.%u.%u\n",
            saddr[0], saddr[1], saddr[2], saddr[3]);
    return NF_DROP;
}

static struct nf_hook_ops pkt_output_hook_ops = {
    .hook=input_filter,
    .pf=NFPROTO_IPV4,
    .hooknum=NF_INET_PRE_ROUTING,
    .priority=0,
    #if (LINUX_VERSION_CODE <= KERNEL_VERSION(4,3,6))
        .owner=THIS_MODULE,
    #endif // LINUX_VERSION_CODE
};

static int __init nftest_init(void)
{
    int res;
    int res2;

    target[0] = 192;
    target[1] = 168;
    target[2] = 1;
    target[3] = 14;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
    res = nf_register_net_hook(&init_net, &pkt_input_hook_ops);
    res2 = nf_register_net_hook(&init_net, &pkt_output_hook_ops);
#else // LINUX_VERSION_CODE<=4.2.8 did not have nf_register_net_hook(), fallback to use the old API function nf_register_hook()
    res = nf_register_hook(&pkt_input_hook_ops);
    res2 = nf_register_hook(&pkt_output_hook_ops);
#endif

    if (res < 0 || res2 < 0) {
        printk(KERN_INFO"failed to register hook\n");
    } else {
        printk(KERN_INFO"hello nftest\n");
    }
    return res;
}

static void __exit nftest_exit(void)
{
    printk(KERN_INFO"bye nftest\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
    nf_unregister_net_hook(&init_net, &pkt_input_hook_ops);
    nf_unregister_net_hook(&init_net, &pkt_output_hook_ops);
#else
    nf_unregister_hook(&pkt_input_hook_ops);
    nf_unregister_hook(&pkt_output_hook_ops);
#endif
}

module_init(nftest_init);
module_exit(nftest_exit);
