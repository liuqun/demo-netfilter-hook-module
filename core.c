#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include "my_genlmsg_handler.h"

MODULE_AUTHOR("Yanchuan Nian");
MODULE_LICENSE("GPL");

enum layer_num {
    //LAYER_LINK = 2, // MAC头,也称链路层头
    LAYER_NETWORK = 3, // IP头,也称network头
    LAYER_TRANSPORT = 4, // 传输层头,也称UDP/TCP/ICMP头
};

struct filter_comparator {
    //int uuid;
    enum layer_num orig_layer;// 若从IP头开始计算则=3; 若从TCP头开始计算则=4; 等于其他值一律判无效
    int orig_len;//必须大于0否则会导致无法预测的结果
    int orig_offset;
    int orig_mask_n_bits;// IP地址子网掩码位数取值一般为32位、24位、16位、8位或0位；端口号掩码则无意义
    int target_idx;// 对应到database[idx下标]
};

struct filter_table {
    struct filter_comparator *list;
    int *outcodelist;//
    int n_items;
    int default_policy_code;
};

static struct filter_table local_in;
static struct filter_table local_out;
static struct filter_table forwarding;

/* 手动声明内部函数原型 filter_match_packet() */
static const void *filter_match_packet(const struct filter_comparator *fc, struct sk_buff *pkt_skb); // 备注: 返回值NULL表示不匹配, 其他值表示匹配
/* 手动声明内部函数原型 filter_policystr_from_policycode() */
static const char *filter_policystr_from_policycode(int code);

static unsigned int input_filter(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
    )
{
    struct filter_comparator *fc;
    int i;

    for (i=0; i<local_in.n_items; i++)
    {
        fc = &(local_in.list[i]);
        if (filter_match_packet(fc, skb)) {
            pr_info("input_filter(): packet match filter index=%d\n", i);
            return local_in.outcodelist[i];
        }
    }
    return local_in.default_policy_code;
}

static unsigned int output_filter(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
    )
{
    struct filter_comparator *fc;
    int i;

    for (i=0; i<local_out.n_items; i++)
    {
        fc = &(local_out.list[i]);
        if (filter_match_packet(fc, skb)) {
            return local_out.outcodelist[i];
        }
    }
    return local_out.default_policy_code;
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

/* 手动声明内部函数原型 init_my_database_and_filter_tables() */
static void init_my_database_and_filter_tables(void);

static int __init nftest_init(void)
{
    int res;
    int errcode3;

    errcode3 = my_genlmsg_handler_register();
    if (errcode3 < 0) {
        pr_info("nftest:Error: Failed to register genlmsg handler, error code = %d\n", errcode3);
        return errcode3;
    }

    init_my_database_and_filter_tables();

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

/////////////////////////
enum filter_policy_code {
    MY_DROP = 0, // NF_DROP=0
    MY_ACCEPT = 1, // NF_ACCEPT=1
    MY_STOLEN = 2, // NF_STOLEN=2
    MY_QUEUE = 3, // NF_QUEUE=3
    MY_REPEAT = 4, // NF_REPEAT=4
};

static const char *filter_policystr_from_policycode(int code)
{
    const char *strlist[]={
        [MY_DROP] = "Drop",
        [MY_ACCEPT] = "Accept",
        [MY_STOLEN] = "STOLEN_debug",
        [MY_QUEUE] = "QUEUE_debug",
        [MY_REPEAT] = "REPEAT_debug",
        [15] = "CODE_15_debug",
    };
    const size_t MAX_CODE = ARRAY_SIZE(strlist)- 1;
    if (code > MAX_CODE || code < 0){
        code = MAX_CODE;
    }
    return strlist[code];
}

/////////////////////////////////////////////////////////
static void *write_ipv4_netmask(u32 *mask, int n_bits) // 备注: n_bits必须取0~32以内的值
{
    u32 cpu32;
    cpu32 = (~0);
    cpu32 <<= (32 - n_bits);
    *mask = __cpu_to_be32(cpu32);
    return (void *)mask;
}

//////////////////////////////////////////////////
static void AND(void *val, void *mask, size_t len)
{
    u8 *p1;
    u8 *p2;
    p1 = (u8 *)val;
    p2 = (u8 *)mask;
    while (len--) {
        *p1++ &= *p2++;
    }
}

///////////////////////////
static u8 database[4096];// 备注: 单独存储各种IP地址、端口号以及报文中其他特殊字段的码值

//////////////////////////////////////////////////////////////////////////////////////////////////////
static const void *filter_match_packet(const struct filter_comparator *fc, struct sk_buff *pkt_skb) // 返回值NULL表示不匹配, 其他值表示匹配
{
    u32 mask;
    int offset;
    u8 buf[64];
    u8 *origval=NULL;
    const size_t MAX_LOCAL_BUFFFER_SIZE=ARRAY_SIZE(buf);
    const struct filter_comparator *out = NULL;

    switch (fc->orig_layer) {
        case LAYER_NETWORK:
            offset = skb_network_offset(pkt_skb);
            break;
        case LAYER_TRANSPORT:
            offset = skb_transport_offset(pkt_skb);
            break;
        default:
            goto unknown_layer_expection;
    }
    origval = buf;
    if (fc->orig_len > MAX_LOCAL_BUFFFER_SIZE) {
        origval = kmalloc(fc->orig_len, GFP_KERNEL);
        if (!origval) {
            goto lack_of_memory_expection;
        }
    }
    offset += fc->orig_offset;
    if (skb_copy_bits(pkt_skb, offset, origval, fc->orig_len) < 0) {
        out = NULL;
        goto normal_cleanups;
    }
    if (LAYER_NETWORK == fc->orig_layer) { // 只有 layer 3 IP 层才支持子网掩码设置
        AND(origval, write_ipv4_netmask(&mask, fc->orig_mask_n_bits), 4);
    }
    if (memcmp(origval, database + fc->target_idx, fc->orig_len) == 0) {
        out = fc;
    }
normal_cleanups:
    if (origval != buf) {
        kfree(origval);
    }
    return (void *)out;
unknown_layer_expection:
    return NULL;
lack_of_memory_expection:
    return NULL;
}

//--------------------------------------------------
static struct filter_comparator my_list1[10];
const size_t LIST1_MAX_ITEMS = ARRAY_SIZE(my_list1);
enum filter_policy_code my_outlist1[10];
//--------------------------------------------------
static struct filter_comparator my_list2[10];
const size_t LIST2_MAX_ITEMS = ARRAY_SIZE(my_list2);
enum filter_policy_code my_outlist2[10];

////////////////////////////////////////////////
static void init_my_database_and_filter_tables()
{
    struct filter_comparator *item;
    const int debug = 1; // 调试阶段允许收发特定网段的数据包

    memset(database, 0x0, sizeof(database));
    if (debug) {
        database[0] = 192;
        database[1] = 168;
        database[2] = 1;
        database[3] = 0;
    }
    // ------------------------------------
    local_in.default_policy_code = NF_DROP;
    local_in.list = my_list1;
    local_in.outcodelist = my_outlist1;
    local_in.n_items = 0;
    item = &(local_in.list[0]);
    if (debug) {
        // 从layer2即IP层取4字节地址
        item->orig_layer = 2;
        item->orig_len = 4;
        item->orig_offset = 12; // 注意: 来源地址偏移12字节 / 目标地址偏移16字节
        item->orig_mask_n_bits = 24;
        item->target_idx = 0;
        local_in.outcodelist[0] = NF_ACCEPT;
        local_in.n_items += 1;
    }
    // -------------------------------------
    local_out.default_policy_code = NF_DROP;
    local_out.list = my_list2;
    local_out.outcodelist = my_outlist2;
    local_out.n_items = 0;
    item = &(local_out.list[0]);
    if (debug) {
        // 从layer2即IP层取4字节地址
        item->orig_layer = 2;
        item->orig_len = 4;
        item->orig_offset = 16; // 注意: 来源地址偏移12字节 / 目标地址偏移16字节
        item->orig_mask_n_bits = 24;
        item->target_idx = 0;
        local_out.outcodelist[0] = NF_ACCEPT;
        local_out.n_items += 1;
    }
    // --------------------
    forwarding.list = NULL;
    forwarding.outcodelist = NULL;
    forwarding.n_items = 0;
    forwarding.default_policy_code = NF_ACCEPT;
}

module_init(nftest_init);
module_exit(nftest_exit);
