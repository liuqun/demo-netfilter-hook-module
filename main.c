#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>

MODULE_AUTHOR("Yanchuan Nian");
MODULE_LICENSE("GPL");

static char target[4] = {0, 0, 0, 0};

static unsigned int nftest_fn(
    #if (LINUX_VERSION_CODE == KERNEL_VERSION(3,10,0)) && !defined(__GENKSYMS__)
        // CentOS 7.6 with Linux kernel version == 3.10.0
        const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        const struct nf_hook_state *state
    #elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0))
        // 4.0 <= Linux <= 4.0.9
        const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *)
    #elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
        // 4.1 <= Linux <= 4.3.6
        const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state
    #elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
        void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state
    #else
    #error "No support for current Linux kernel version..."
    #endif // LINUX_VERSION_CODE
    )
{
    int res;
    char saddr[4];
    int offset;

    offset = skb_network_offset(skb);
    offset += 12;
    res = skb_copy_bits(skb, offset, saddr, 4);
    if (res < 0) {
        return NF_ACCEPT;
    }
    res =memcmp(saddr, target, 4);
    if (!res) {
        printk(KERN_INFO"receive message from 192.168.7.121\n");
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops nf_test_ops = {
    .hook=nftest_fn,
    .pf=NFPROTO_IPV4,
    .hooknum=NF_INET_LOCAL_IN,
    .priority=0,
    #if (LINUX_VERSION_CODE <= KERNEL_VERSION(4,3,6))
        .owner=THIS_MODULE,
    #endif // LINUX_VERSION_CODE
};

static int __init nftest_init(void)
{
    int res;

    target[0] = 192;
    target[1] = 168;
    target[2] = 7;
    target[3] = 121;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
    res = nf_register_net_hook(&init_net, &nf_test_ops);
#else // LINUX_VERSION_CODE<=4.2.8 did not have nf_register_net_hook(), fallback to use the old API function nf_register_hook()
    res = nf_register_hook(&nf_test_ops);
#endif

    if (res < 0) {
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
    nf_unregister_net_hook(&init_net, &nf_test_ops);
#else
    nf_unregister_hook(&nf_test_ops);
#endif
}

module_init(nftest_init);
module_exit(nftest_exit);
