#include <linux/version.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>
#include <net/sock.h>

#include "my_genlmsg_handler.h"
#include "uapi/nftest.h"

static u32 myvar;

static int genl_get_myvar(struct sk_buff *skb, struct genl_info *info);
static int genl_upd_myvar(struct sk_buff *skb, struct genl_info *info);

static const struct nla_policy my_poliy_upd_something[NLE_MAX+1] = {
    [NLE_MYVAR] = { .type = NLA_U32 },
};

static struct genl_ops genl_example_ops[] = {
    {
        .cmd = NLEX_CMD_GET,
        .flags = 0,
        .policy = NULL,
        .doit = genl_get_myvar,
        .dumpit = NULL,
    },
    {
        .cmd = NLEX_CMD_UPD,
        .flags = 0,
        .policy = my_poliy_upd_something,
        .doit = genl_upd_myvar,
        .dumpit = NULL,
    },
};

static struct genl_family my_genl_family = {
    .module = THIS_MODULE,
    //////////////////////
    .ops = genl_example_ops,
    .mcgrps = NULL,
    .n_ops = ARRAY_SIZE(genl_example_ops),
    .n_mcgrps = 0,
    //////////////////////
    .name = "nftest",
    .hdrsize = 0,
    .version = 1,
    .maxattr = NLE_MAX,
};

int my_genlmsg_handler_register(void)
{
    pr_info("nftest: registering netlink handler...\n");

    myvar = 1;
    pr_info("nftest: init myvar=%u\n", (unsigned)myvar);

    return genl_register_family(&my_genl_family);
}

void my_genlmsg_handler_unregister(void)
{
    genl_unregister_family(&my_genl_family);
    pr_info("nftest: unregistered netlink handler\n");
}

static int
genl_get_myvar(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    void *hdr;

    pr_info("nftest: begin get myvar\n");
    msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq, &my_genl_family, 0, NLEX_CMD_GET);
    if (hdr == NULL) {
        goto nlmsg_failure;
    }

    if (nla_put_u32(msg, NLE_MYVAR, myvar)) {
        goto nla_put_failure;
    }

    genlmsg_end(msg, hdr);

    genlmsg_unicast(sock_net(skb->sk), msg, info->snd_portid);

    pr_info("nftest: end get myvar\n");
    return 0;

nlmsg_failure:
nla_put_failure:
    genlmsg_cancel(msg, hdr);
    nlmsg_free(msg);
    return -ENOBUFS;
}

static int
genl_upd_myvar(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    void *hdr;

    pr_info("nftest:genl_upd_myvar():%d:begin update myvar\n", __LINE__);
    if (!info->attrs[NLE_MYVAR]) {
        return -EINVAL;
    }

    pr_info("nftest:genl_upd_myvar():%d: old myvar = %d\n", __LINE__, myvar);
    myvar = nla_get_u32(info->attrs[NLE_MYVAR]);
    pr_info("nftest:genl_upd_myvar():%d: new myvar = %d\n", __LINE__, myvar);

    msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    hdr = genlmsg_put(msg, 0, 0, &my_genl_family, 0, NLEX_CMD_UPD);
    if (hdr == NULL) {
        goto nlmsg_failure;
    }

    if (nla_put_u32(msg, NLE_MYVAR, myvar)) {
        goto nla_put_failure;
    }

    genlmsg_end(msg, hdr);

    pr_info("nftest:%s:%d:end update myvar\n", __FILE__, __LINE__);
    return 0;

nlmsg_failure:
nla_put_failure:
    genlmsg_cancel(msg, hdr);
    nlmsg_free(msg);
    return -ENOBUFS;
}
