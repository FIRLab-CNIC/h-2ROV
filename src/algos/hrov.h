#ifndef HROV_H
#define HROV_H

#include<assert.h>
#include<stdint.h>
#include<math.h>
#include<time.h>
#include"algos.h"
#include"../pfx/ipv6.h"
#include"../pfx/ipv4.h"
#include"../utils/coding.h"
#include"../utils/mprint.h"
#include"../utils/utils.h"
// #include"../SupportDS/common.h"
#include"../SupportDS/hash.h"
#include"../SupportDS/hashmap.h"
#include"../SupportDS/announce_cnt.h"
#include"../SupportDS/wideArray.h"
#include"../SupportDS/wideArray_extra.h"
#include"../SupportDS/level_bitmap.h"
#include"../SupportDS/path_bitmap.h"
#include "../SupportDS/roa.h"

struct hrov_table_basic
{
    struct hashmap * sot_v4; //ASN+Identifier, bitmap
    struct hashmap * sot_v6; //ASN+Identifier, bitmap
    struct hashmap * stt_v4; //Identifier, offset+num+bitmap+flag
    struct hashmap * stt_v6; //Identifier, offset+num+bitmap+flag
    int widelen_v4;
    int widelen_v6;
    rc_sot4 *rc_sot_v4;
    rc_sot6 *rc_sot_v6;
    rc_stt4 *rc_stt_v4;
    rc_stt6 *rc_stt_v6;
    wideASN *wide_array_v4_extra;
    wideASN *wide_array_v6_extra;
    patricia_tree_t *wide_tree_v4;
    patricia_tree_t *wide_tree_v6;
};

void hrov_pfxt_init_basic(struct hrov_table_basic *ht);
int hrov_pfx_rm_basic(struct hrov_table_basic * pfxt, void *pdu);
int hrov_pfx_add_basic(struct hrov_table_basic * pfxt, void * pdu);
int hrov_pfx_validate_basic(struct hrov_table_basic *ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void hrov_memory_release_basic(struct hrov_table_basic *ht);

struct hrov_table_binary
{
    struct hashmap * sot_v4; //ASN+Identifier, bitmap + withdrawn flag
    struct hashmap * sot_v6; //ASN+Identifier, bitmap + withdrawn flag 
    struct hashmap * stt_v4; //Identifier, wideROA flag+withdrawn flag+bitmap+flag
    struct hashmap * stt_v6; //Identifier, wideROA flag+withdrawn flag+bitmap+flag
    rc_sot4 *rc_sot_v4;
    rc_sot6 *rc_sot_v6;
    rc_stt4 *rc_stt_v4;
    rc_stt6 *rc_stt_v6;
    wideArray4 * wide_array_v4;
    wideArray6 * wide_array_v6;
    struct hashmap * child_bitmap_v4;
    struct hashmap * child_bitmap_v6;
    int backtracking;
    double backtrack_time;
};

void hrov_pfxt_init_binary(struct hrov_table_binary *ht);
int hrov_pfx_add_binary(struct hrov_table_binary * pfxt, void * pdu);
int hrov_pfx_rm_binary(struct hrov_table_binary * pfxt, void *pdu);
int hrov_pfx_validate_binary(struct hrov_table_binary *ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void hrov_memory_release_binary(struct hrov_table_binary *ht);


struct hrov_table_nlbs
{
    struct hashmap * sot_v4; //ASN+Identifier, bitmap
    // ipv4asn_uint32_map sot_v4; //ASN+Identifier, bitmap
    struct hashmap * sot_v6; //ASN+Identifier, bitmap
    struct hashmap * stt_v4; //Identifier, bitmap + withdrawn flag
    // ipv4_complex_map stt_v4; //Identifier, bitmap + withdrawn flag
    struct hashmap * stt_v6; //Identifier, offset+num+bitmap+flag
    struct hashmap * leaflevel_v6; //hanging-level >= 40
    struct hashmap * midlevel_v6; //20 <= hanging-level < 40
    int lessthan15_cnt;
    double hashtime;
    int sot_check;
    int patricia_check;
    int patricia_check_success;
    int widelen_v4;
    int widelen_v6;
    rc_sot4 *rc_sot_v4;
    rc_sot6 *rc_sot_v6;
    rc_stt4 *rc_stt_v4;
    rc_stt6 *rc_stt_v6;
    struct hashmap * child_bitmap_v6;
    wideASN *wide_array_v4_extra;
    wideASN *wide_array_v6_extra;
    patricia_tree_t *wide_tree_v4;
    patricia_tree_t *wide_tree_v6;
    level_bitmap *lb;
    level_bitmap *lb_v6;
};

void hrov_pfxt_init_nlbs(struct hrov_table_nlbs *ht);
int hrov_pfx_add_nlbs(struct hrov_table_nlbs * pfxt, void * pdu);
int hrov_pfx_rm_nlbs(struct hrov_table_nlbs * pfxt, void *pdu);
int hrov_pfx_validate_nlbs(struct hrov_table_nlbs *ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void hrov_memory_release_nlbs(struct hrov_table_nlbs *ht);

extern int widelen_v4;
extern int widelen_v6;

#define extract_bits_c(p, start, end)((p >> start) & ((1 << (end - start)) - 1))

#define get_subtree_pos_v4_c(prefix, hanging_level, len, res){       \
    int from = 32-len, to = 32-hanging_level;                        \
    uint32_t tmp = extract_bits_c(prefix,from, to);                  \
    int bits = len - hanging_level;                                  \
    tmp = tmp | (1<<bits);                                           \
    *res = tmp;                                                      \
}

int get_position_v6_c(uint32_t src[4], int total_len, int from);
// void bitmap_to_pfx_v6(uint32_t identifier[], uint32_t bitmap);
uint32_t calculate_bitmap(uint32_t identifier,int masklen,int maxlen);
uint32_t calculate_bitmap_v6(uint32_t prefix[],int masklen,int maxlen);
#endif