#ifndef BGP_H
#define BGP_H
#include"route.h"
#include"../utils/coding.h"
#include"../SupportDS/decoder.h"
#include"common.h"

struct bgp_rov {
    rtable *roa_table_ip4;		/* Table for ROA IPv4 */
    rtable *roa_table_ip6;		/* Table for ROA IPv6 */
};

void bgp_rov_init(struct bgp_rov *br);
int bgp_rov_insert(struct bgp_rov *br, void *pdu);
int bgp_rov_remove(struct bgp_rov *br,void *pdu);
int bgp_rov_validate(struct bgp_rov *br, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
size_t bgp_rov_memory_statistic(struct bgp_rov *br);

int bgp_rov_trie_insert(struct bgp_rov *br, void *pdu);
int bgp_rov_trie_remove(struct bgp_rov *br,void *pdu);
int bgp_rov_trie_validate(struct bgp_rov *br, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
size_t bgp_rov_trie_memory_statistic(struct bgp_rov *br);
void bgp_rov_show_trie(struct bgp_rov *br);

#endif