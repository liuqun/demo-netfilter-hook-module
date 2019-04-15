#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/genetlink.h>
#include <time.h>
#include <libmnl/libmnl.h>
#include "my_functions.h"
#include "../uapi/nftest.h"

static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);
	if (mnl_attr_type_valid(attr, NLE_MAX) < 0) {
		return MNL_CB_OK;
	}
	switch(type) {
	case NLE_MYVAR:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	default:
		fprintf(stderr, "DEBUG: Unknown attribute type=%d", (int)type);
		return MNL_CB_ERROR;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int my_upd_response_parser_cb(const struct nlmsghdr *nlh, void *data)//内核应答报文中会携带当前myvar值
{
	struct nlattr *tb[CTRL_ATTR_MAX+1] = {};
//	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), data_attr_cb, tb);
	if (tb[NLE_MYVAR]) {
		printf("my value=%u\n", (unsigned)mnl_attr_get_u32(tb[NLE_MYVAR]));
	}
	(void) data; // disable gcc warning of un-used parameter(s)
	return MNL_CB_OK;
}

static int do_update_myvar(struct mnl_socket *nl_ctx, int id)
{
	uint8_t sendbuf[MNL_SOCKET_BUFFER_SIZE];
	uint8_t recvbuf[MNL_SOCKET_BUFFER_SIZE];
//	const size_t MY_SENDBUF_SIZE = sizeof(sendbuf);
	const size_t MY_RECVBUF_SIZE = sizeof(recvbuf);
	struct nlmsghdr *header;
	struct genlmsghdr *extra;
	unsigned int seq;
	unsigned int portid;
	int recvlen;
	int cbret;

//	memset(sendbuf, 0x00, MY_SENDBUF_SIZE);
	header = mnl_nlmsg_put_header(sendbuf);
	header->nlmsg_type = id;
	header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	header->nlmsg_seq = seq = time(NULL);

	extra = mnl_nlmsg_put_extra_header(header, sizeof(*extra));
	extra->version = 1;
	extra->cmd = NLEX_CMD_UPD;
	mnl_attr_put_u32(header, NLE_MYVAR, 2);

	if (mnl_socket_bind(nl_ctx, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl_ctx);

	if (mnl_socket_sendto(nl_ctx, header, header->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		return(EXIT_FAILURE);
	}

	cbret = -1;
//	memset(recvbuf, 0x00, MY_RECVBUF_SIZE);
	recvlen = mnl_socket_recvfrom(nl_ctx, recvbuf, MY_RECVBUF_SIZE);
//	fprintf(stderr, "DEBUG: recvlen = %d\n", recvlen);
	if (recvlen > 0) {
		cbret = mnl_cb_run(recvbuf, recvlen, seq, portid, my_upd_response_parser_cb, NULL);
//		fprintf(stderr, "DEBUG: mnl_cb_run() returns cbret=%d\n", cbret);
	}
	if (cbret < 0) {
		fprintf(stderr, "WARNING: mnl_cb_run() failed\n");
		return(EXIT_FAILURE);
	}
	return(0);
}

void run_test1_update_myvar(int genl_family_id)
{
	struct mnl_socket *nl_ctx;

	nl_ctx = mnl_socket_open(NETLINK_GENERIC);
	if (!nl_ctx) {
		perror("mnl_socket_open");
		return;
	}

	do_update_myvar(nl_ctx, genl_family_id);

	mnl_socket_close(nl_ctx);
}

struct my_data {
	unsigned long uldata;
};

static int my_getdata_response_parser_cb(const struct nlmsghdr *nlh, void *result)
{
	uint32_t data;
	struct nlattr *tb[CTRL_ATTR_MAX+1] = {};
//	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), data_attr_cb, tb);
	if (!tb[NLE_MYVAR]) {
		return MNL_CB_ERROR;
	}
	data = mnl_attr_get_u32(tb[NLE_MYVAR]);
	printf("DEBUG: in Test2 my data=%u\n", (unsigned)data);
	((struct my_data *)result)->uldata = (unsigned long) data;
	return MNL_CB_OK;
}

static int do_fetch_data(struct mnl_socket *nl_ctx, int id, struct my_data *result)
{
	uint8_t sendbuf[MNL_SOCKET_BUFFER_SIZE];
	uint8_t recvbuf[MNL_SOCKET_BUFFER_SIZE];
	const size_t MY_RECVBUF_SIZE = sizeof(recvbuf);
	struct nlmsghdr *header;
	struct genlmsghdr *extra;
	unsigned int seq;
	unsigned int portid;
	int recvlen;
	int cbret;

	header = mnl_nlmsg_put_header(sendbuf);
	header->nlmsg_type = id;
	header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	header->nlmsg_seq = seq = time(NULL);

	extra = mnl_nlmsg_put_extra_header(header, sizeof(*extra));
	extra->version = 1;
	extra->cmd = NLEX_CMD_GET;

	if (mnl_socket_bind(nl_ctx, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return(-1);
	}
	portid = mnl_socket_get_portid(nl_ctx);

	if (mnl_socket_sendto(nl_ctx, header, header->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		return(-1);
	}

	cbret = -1;
//	memset(recvbuf, 0x00, MY_RECVBUF_SIZE);
	recvlen = mnl_socket_recvfrom(nl_ctx, recvbuf, MY_RECVBUF_SIZE);
//	fprintf(stderr, "DEBUG: recvlen = %d\n", recvlen);
	if (recvlen > 0) {
		cbret = mnl_cb_run(recvbuf, recvlen, seq, portid, my_getdata_response_parser_cb, result);
//		fprintf(stderr, "DEBUG: mnl_cb_run() returns cbret=%d\n", cbret);
	}
	if (cbret < 0) {
		fprintf(stderr, "WARNING: mnl_cb_run() failed\n");
		return(-1);
	}
	return(0);
}

void run_test2_ipc_fetch_data(int genl_family_id)
{
	struct my_data result;
	struct mnl_socket *nl_ctx;

	nl_ctx = mnl_socket_open(NETLINK_GENERIC);
	if (!nl_ctx) {
		perror("mnl_socket_open");
		return;
	}

	do_fetch_data(nl_ctx, genl_family_id, &result);

	mnl_socket_close(nl_ctx);
}

int main(int argc, char *argv[])
{
	const int DEBUG_ENABLED = 0;
	const char name[] = "nftest";
	int id;

	id = get_genl_family_id_by_name(name);
	if (id < 0) {
		fprintf(stderr, "Error: family name does NOT exist\n");
		fprintf(stderr, "(please load demo2.ko kernel module first...)\n");
		return(255);
	}
	printf("Demo genl family name[] = \"%s\", id=%d\n", name, id);
	if (DEBUG_ENABLED) {
		print_genl_family_info_by_family_name_strz(name);
	}

	printf("==== Test1: Update my var start ====\n");
	run_test1_update_myvar(id);
	printf("==== Test1 finish ====\n");

	// printf("==== Test2 fetch my var from kernel start ====\n");
	// run_test2_ipc_fetch_data(id);
	// printf("==== Test2 finish ====\n");
	return(0);
}
