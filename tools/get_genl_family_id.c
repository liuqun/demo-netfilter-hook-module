// Copyright 2019, Qingdao Xin-Fan-Shi Information Technology Co. Ltd.
/* Demo code based on examples from https://netfilter.org
 * See: https://git.netfilter.org/libmnl/tree/examples/genl/genl-family-get.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTRL_ATTR_FAMILY_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTRL_ATTR_FAMILY_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTRL_ATTR_VERSION:
	case CTRL_ATTR_HDRSIZE:
	case CTRL_ATTR_MAXATTR:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTRL_ATTR_OPS:
	case CTRL_ATTR_MCAST_GROUPS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

#include <stdint.h>
typedef uint16_t u16;
typedef uint32_t u32;
#define MAX_FAMILY_NAME_CHARS 15 //bytes
struct data_record {
	char familyname[MAX_FAMILY_NAME_CHARS+1];
	size_t familynamelen;
	u16 familyid;
	u32 version;
	u32 hdrsize;
	u32 maxattr;
};

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct data_record *record = NULL;
	struct nlattr *tb[CTRL_ATTR_MAX+1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), data_attr_cb, tb);
	record = (struct data_record *) data;
	if (tb[CTRL_ATTR_FAMILY_NAME]) {
		const char *str = mnl_attr_get_str(tb[CTRL_ATTR_FAMILY_NAME]);
		size_t i;
		for (i=0; i<MAX_FAMILY_NAME_CHARS && str[i]; i++) {
			record->familyname[i] = str[i];
		}
		record->familynamelen = i;
		record->familyname[i] = '\0';
	}
	if (tb[CTRL_ATTR_FAMILY_ID]) {
		record->familyid = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
	}
	if (tb[CTRL_ATTR_VERSION]) {
		record->version = mnl_attr_get_u16(tb[CTRL_ATTR_VERSION]);
	}
	if (tb[CTRL_ATTR_HDRSIZE]) {
		record->hdrsize = mnl_attr_get_u32(tb[CTRL_ATTR_HDRSIZE]);
	}
	if (tb[CTRL_ATTR_MAXATTR]) {
		record->maxattr = mnl_attr_get_u32(tb[CTRL_ATTR_MAXATTR]);
	}
	if (tb[CTRL_ATTR_OPS]) {
		//TODO: parse_genl_family_ops(tb[CTRL_ATTR_OPS]);
	}
	if (tb[CTRL_ATTR_MCAST_GROUPS]) {
		//TODO: parse_genl_mc_grps(tb[CTRL_ATTR_MCAST_GROUPS]);
	}
	return MNL_CB_OK;
}

static int fetch_family_id_by_family_name(struct mnl_socket *nl_ctx, const char *family_name_strz, int *id)
{
	char sendbuf[MNL_SOCKET_BUFFER_SIZE];
	char recvbuf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *header;
	struct genlmsghdr *extra;
	unsigned int seq;
	unsigned int portid;
	int ret;
	struct data_record my_record;
	const int ENABLE_MY_DEBUG = 0;

	if (ENABLE_MY_DEBUG) {
		header = NULL;
		extra = NULL;
	}
	header = mnl_nlmsg_put_header(sendbuf);
	header->nlmsg_type = GENL_ID_CTRL;
	header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	header->nlmsg_seq = seq = time(NULL);
	extra = mnl_nlmsg_put_extra_header(header, sizeof(*extra));
	extra->cmd = CTRL_CMD_GETFAMILY;
	extra->version = 1;

	mnl_attr_put_strz(header, CTRL_ATTR_FAMILY_NAME, family_name_strz);

	if (mnl_socket_bind(nl_ctx, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return(-1);
	}
	portid = mnl_socket_get_portid(nl_ctx);

	if (mnl_socket_sendto(nl_ctx, header, header->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		return(-1);
	}

	memset(&my_record, 0x00, sizeof(struct data_record));
	while ((ret = mnl_socket_recvfrom(nl_ctx, recvbuf, sizeof(recvbuf))) > 0) {
		ret = mnl_cb_run(recvbuf, ret, seq, portid, data_cb, &my_record);
		if (ret <= 0) {
			break;
		}
	}
	if (ret == -1) {
		fprintf(stderr, "Warning: mnl_socket_recvfrom() OR mnl_cb_run() failed\n");
		return(-1);
	}

	*id = my_record.familyid;
	if (ENABLE_MY_DEBUG) {
		fprintf(stderr, "Debug: family id=%d\n", *id);
	}
	return(0);
}

#include "my_functions.h"
int get_genl_family_id_by_name(const char *family_name_strz)
{
	int err;
	struct mnl_socket *ctx;
	int family_id;

	ctx = mnl_socket_open(NETLINK_GENERIC);
	if (!ctx) {
		perror("mnl_socket_open");
		return(-1);
	}
	err = fetch_family_id_by_family_name(ctx, family_name_strz, &family_id);
	mnl_socket_close(ctx);

	if (err) {
		family_id = -1;
	}
	return(family_id);
}
