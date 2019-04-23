/*
Copyright 2019, Qingdao Xin-Fan-Shi Information and Technology Co. Ltd.
*/
#pragma once

enum layer_num {
    //LAYER_LINK = 2, // MAC头,也称链路层头
    LAYER_NETWORK = 3, // IP头,也称network头
    LAYER_TRANSPORT = 4, // 传输层头,也称UDP/TCP/ICMP头
};

struct ipv4addr_comparator {
    //int uuid;
    int orig_len;//必须大于0否则会导致无法预测的结果
    int orig_offset;
    int orig_mask_n_bits;// IP地址子网掩码位数取值一般为32位、24位、16位、8位或0位；端口号掩码则无意义
    int target_idx;// 对应到database[idx下标]
};

struct ipv4addr_filter_table {
    struct ipv4addr_comparator *list;
    unsigned int *outcodelist;
    int n_items;
    int max_items;
    unsigned int default_policy_code;
};

/**
 * 在过滤表的末尾追加一条新规则.
 * 返回值表示规则所在行序号.
 */
int append_filter_table(struct ipv4addr_filter_table *table, const struct ipv4addr_comparator *fc, unsigned int code);

/**
 * 在过滤表的中间位置插入一条新规则.
 * 返回值表示规则所在行序号.
 */
int insert_to_filter_table(struct ipv4addr_filter_table *table, int where, const struct ipv4addr_comparator *fc, unsigned int code);

/**
 * 判定过滤表是否已满, 能否继续添加新规则.
 * 返回值为布尔量.
 */
int table_is_full(const struct ipv4addr_filter_table *table);

/**
 * 清空整个过滤表.
 */
void flush_filter_table(struct ipv4addr_filter_table *table);

/**
 * 修改过滤表的默认规则.
 * 输入值0表示丢弃DROP, 或1表示接受ACCEPT.
 */
void modify_filter_table_default_policy_code(struct ipv4addr_filter_table *table, unsigned int default_policy_code);
