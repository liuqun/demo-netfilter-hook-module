#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include "my_genlmsg_handler.h"

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

    offset += 4;
    {
        const u8 white_dst_addr[4] = {192, 168, 1, 14};
        u8 dst_addr[4];

        res = skb_copy_bits(skb, offset, dst_addr, 4);
        if (res < 0) {
            return NF_ACCEPT;
        }
        if (memcmp(dst_addr, white_dst_addr, 4) == 0) {
            pr_info("Allow:OUTPUT: from src ip=%u.%u.%u.%u, to dst ip=%u.%u.%u.%u\n",
                saddr[0], saddr[1], saddr[2], saddr[3],
                dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]
                );
            return NF_ACCEPT;
        }
        pr_info("Drop:OUTPUT: from src ip=%u.%u.%u.%u, to dst ip=%u.%u.%u.%u\n",
            saddr[0], saddr[1], saddr[2], saddr[3],
            dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]
            );
    }
    return NF_DROP;
}

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
        pr_info("Allow:INPUT: from src ip=%u.%u.%u.%u\n",
                saddr[0], saddr[1], saddr[2], saddr[3]);
        return NF_ACCEPT;
    }
    pr_info("Drop:INPUT: from src ip=%u.%u.%u.%u\n",
            saddr[0], saddr[1], saddr[2], saddr[3]);
    return NF_DROP;
}

static struct nf_hook_ops all_my_hooks[] = {
    {
        .hook = input_filter,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = 0,// 优先级=0, 即NF_IP_PRI_FILTER
        // 备注: 枚举值 NF_IP_PRI_FILTER 定义于头文件"uapi/linux/netfilter_ipv4.h"中
    },
    {
        .hook = output_filter,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = 0,
    },
};
const unsigned int TOTAL_HOOKS = sizeof(all_my_hooks) / sizeof(all_my_hooks[0]);

/* 手动声明 API 函数原型 nf_register_net_hooks() 和 nf_unregister_net_hooks() */
int nf_register_net_hooks(struct net *net, const struct nf_hook_ops *hooks_to_reg, unsigned int n);
void nf_unregister_net_hooks(struct net *net, const struct nf_hook_ops *hooks_to_unreg, unsigned int n);

static int __init nftest_init(void)
{
    int res;
    int errcode3;

    errcode3 = my_genlmsg_handler_register();
    if (errcode3 < 0) {
        pr_info("nftest:Error: Failed to register genlmsg handler, error code = %d\n", errcode3);
        return errcode3;
    }

    target[0] = 192;
    target[1] = 168;
    target[2] = 1;
    target[3] = 14;

    res = nf_register_net_hooks(&init_net, all_my_hooks, TOTAL_HOOKS);
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
    nf_unregister_net_hooks(&init_net, all_my_hooks, TOTAL_HOOKS);
    my_genlmsg_handler_unregister();
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)) // code for old linux kernel
/// v4.2.8 及更低版本的 Linux 内核没有定义接口函数 nf_register_net_hook() 和 nf_unregister_net_hook()
/// 为了兼容旧版内核, 此处手动定义新版API函数名
int nf_register_net_hooks(struct net *net, const struct nf_hook_ops *hooks_to_reg, unsigned int n)
{
    return nf_register_hooks(hooks_to_reg, n);
}
void nf_unregister_net_hooks(struct net *net, const struct nf_hook_ops *hooks_to_unreg, unsigned int n)
{
    nf_unregister_hooks(hooks_to_unreg, n);
}
#endif // code for old linux kernel

module_init(nftest_init);
module_exit(nftest_exit);
