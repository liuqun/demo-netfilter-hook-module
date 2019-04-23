/*
Copyright 2019, Qingdao Xin-Fan-Shi Information and Technology Co. Ltd.
*/
#include "my_filter_table.h" /// (下列函数的原型声明及使用方法均请查阅此头文件)

//////////////////////////////////////////////////////////////////////////////////////////////////////////
void modify_filter_table_default_policy_code(struct ipv4addr_filter_table *table, unsigned int default_policy_code)
{
    table->default_policy_code = default_policy_code;
}

///////////////////////////////////////////////////
void flush_filter_table(struct ipv4addr_filter_table *table)
{
    table->n_items = 0;
}

////////////////////////////////////////////////////
int table_is_full(const struct ipv4addr_filter_table *table)
{
    return table->n_items >= table->max_items;
}
