#ifndef CODING_H
#define CODING_H

#include<stdio.h>
#include<string.h>
#include"rtrlib/rtrlib.h"
#include"../pfx/ipv4.h"
#include"../pfx/ipv6.h"
#include"utils.h"
#define HROV_IPV4 11
#define HROV_IPV6 12
#define TROA_IPV4 4
#define TROA_IPV6 6

struct updates_message
{
	struct lrtr_ip_addr addr;
	uint32_t asn;
	uint8_t masklen;
	enum pfxv_state res;
};

struct pdu_ipv4 {
	uint8_t ver;
	uint8_t type;
	uint16_t reserved;
	uint32_t len;   //A 32-bit unsigned integer which has as its value the count of the bytes in the entire PDU
	uint8_t flags; 	//1 for an announcement and 0 for a withdrawal
	uint8_t prefix_len;
	uint8_t max_prefix_len;
	uint8_t zero;
	uint32_t prefix;
	uint32_t asn;
};

struct pdu_ipv6 {
	uint8_t ver;
	uint8_t type;
	uint16_t reserved;
	uint32_t len;
	uint8_t flags;
	uint8_t prefix_len;
	uint8_t max_prefix_len;
	uint8_t zero;
	uint32_t prefix[4];
	uint32_t asn;
};

struct hpdu_ipv4{
	uint8_t ver;
	uint8_t type;
	uint16_t reserved;
	uint32_t len;
	uint32_t sub_tree_identifier;
	uint32_t Encoded_sub_tree;
	uint32_t asn;
};

struct hpdu_ipv6 {
	uint8_t ver;
	uint8_t type;
	uint16_t reserved;
	uint32_t len;
	uint32_t sub_tree_identifier[4];
	uint32_t Encoded_sub_tree;
	uint32_t asn;
};

#define set_hpdu_v4(_p, _identifier, _bitmap, _asn)       \
{                                                         \
    _p->ver = 1;                                          \
    _p->type = HROV_IPV4;                                 \
    _p->reserved = 0;                                     \
    _p->len = 20;                                         \
    _p->sub_tree_identifier = _identifier;                \
    _p->Encoded_sub_tree = _bitmap;                       \
    _p->asn = _asn;                                       \
}

#define set_hpdu_v6(_p, _identifier, _bitmap, _asn)       \
{                                                         \
    _p->ver = 1;                                          \
    _p->type = HROV_IPV4;                                 \
    _p->reserved = 0;                                     \
    _p->len = 20;                                         \
    memcpy(_p->sub_tree_identifier,_identifier,sizeof(uint32_t)*4);                \
    _p->Encoded_sub_tree = _bitmap;                       \
    _p->asn = _asn;                                       \
}

char* msubstring(char *destination, const char *source, int beg, int n);

void pdu_v4(struct pdu_ipv4 * p, int ip_version, ipv4 prefix, uint8_t len, uint8_t maxlen, uint32_t asn);
void pdu_v6(struct pdu_ipv6 * p, int ip_version, struct ip6_t prefix, uint8_t len, uint8_t maxlen, uint32_t asn);

void init_pdu_v4(struct pdu_ipv4 * p, int ip_version, char * prefix, uint8_t len, uint8_t maxlen, uint32_t asn);
void init_pdu_v6(struct pdu_ipv6 * p, int ip_version, char * prefix, uint8_t len, uint8_t maxlen, uint32_t asn);

void init_hpdu_v4(struct hpdu_ipv4 * p, char * identifier, uint32_t bitmap, uint32_t asn);
void init_hpdu_v6(struct hpdu_ipv6 * p, char * identifier, uint32_t bitmap, uint32_t asn);

void * hrov_style_coding(char * raw_data, int * counter);
void * trov_style_coding(char * raw_data);
void * mrov_style_coding(char * raw_data);

void * mrov_style_coding_it(char * raw_data);
void * trov_style_coding_it(char * raw_data);
void * hrov_style_coding_it(char * raw_data);

void * mrov_coding_rd(char * raw_data);
void * hrov_coding_rd(char * raw_data);

void print_bgp_update_record(struct updates_message record);
void bgp_coding(char * raw_data, void * record);
void bgp_tmp_coding(char * raw_data, void * record);
void bgp_update_coding(char * raw_data, void * record);
void bgp_update_coding_htonl(char * raw_data, void * record);
#endif