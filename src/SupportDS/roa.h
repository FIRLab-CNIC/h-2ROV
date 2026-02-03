#ifndef ROA_H
#define ROA_H

#include<stdint.h>
#include"patricia.h"
#include"rtrlib/rtrlib.h"
#include"../utils/coding.h"
#include"../SupportDS/decoder.h"
#include"common.h"

typedef struct{
    uint8_t maxlen;
    uint32_t asn;
}ROA;

typedef struct {
	unsigned int len;
	ROA *ary;
}node_data_t;

typedef struct{
    patricia_tree_t *roa_table_ipv4;
    patricia_tree_t *roa_table_ipv6;
}pt_table;

void pt_init(pt_table *table);
int pt_insert(pt_table *table, void *pdu);
int pt_remove(pt_table *table, void *pdu);
int pt_validate(pt_table *table, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
size_t pt_memory_statistic(pt_table *table);
patricia_node_t* getParent(patricia_node_t * node);
int append_elem(node_data_t *data, const ROA *record);
int delete_elem(node_data_t *data, const unsigned int index);
#endif