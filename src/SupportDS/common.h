/**
 * general definitions for hashmap
*/
#ifndef COMMON_H
#define COMMON_H

#include"hashmap.h"
#include"hash.h"
#include"sc-vector.h"
#include"../pfx/ipv6.h"
#include"../pfx/ipv4.h"
#include<xxhash.h>
#include"mum_hash.h"

#define SUCCESS 1
#define ERROR -1
#define HANGING_LEVEL 5
#define SUCCESS_IPV4 4
#define SUCCESS_IPV6 6
#define WIDE_LEN_v4 10
#define WIDE_LEN_v6 4
#define V4PATH 6
#define V6PATH 25
#define UINT32_BITS 32

static const long MASK[] = {1, 3, 7, 11, 23, 39, 75, 139, 279, 535, 1063, 2087, 4171, 8267, 16523, 32907, 65815, 131351, 262679, 524823,
        1049639, 2098215, 4196391, 8390695, 16781387, 33558603, 67117131, 134225995, 268451979, 536887435, 1073774731,
        2147516555};

static const long MASK_BASIC[] = {0, 2, 6, 10, 22, 38, 74, 138, 278, 534, 1062, 2086, 4170, 8266, 16522, 32906, 65814, 131350, 262678, 524822,
        1049638, 2098214, 4196390, 8390694, 16781386, 33558602, 67117130, 134225994, 268451978, 536887434, 1073774730,
        2147516554};

struct bmb{
    uint32_t bitmap;
    uint8_t withdrawn_flag:1;
    uint8_t wideROA_flag:1;
};

#define set_bmb(bmb_ptr,b,w,l){      \
    bmb_ptr.bitmap =  b;              \
    bmb_ptr.withdrawn_flag = w;       \
    bmb_ptr.wideROA_flag = l;        \
}

struct ipv4_asn
{
    ipv4 addr;
    uint32_t asn;
};

struct ipv4_asn_info
{
    struct ipv4_asn key;
    uint32_t bitmap;
};

struct ipv4_complex_info{
    ipv4 key;
    struct bmb bm;
};

struct ipv4_info
{
    ipv4 key;
    uint32_t bm;
};

#define insert_ipv4_info(ht, k, v)(hashmap_set(ht, &(struct ipv4_info){.key=k, .bm=v}))
#define insert_ipv4_complex_info(ht, k, v)(hashmap_set(ht, &(struct ipv4_complex_info){.key=k, .bm=v}))
#define insert_ipv4_asn_info(ht, k, v)(hashmap_set(ht, &(struct ipv4_asn_info){.key=k, .bitmap=v}))

#define find_ipv4_info(ht, k)(hashmap_get(ht, &(struct ipv4_info){.key=k}))
#define find_ipv4_complex_info(ht, k)(hashmap_get(ht, &(struct ipv4_complex_info){.key=k}))
#define find_ipv4_asn_info(ht, k)(hashmap_get(ht, &(struct ipv4_asn_info){.key=k}))

#define delete_ipv4_info(ht, k)(hashmap_delete(ht, &(struct ipv4_info){.key=k}))
#define delete_ipv4_complex_info(ht, k)(hashmap_delete(ht, &(struct ipv4_complex_info){.key=k}))
#define delete_ipv4_asn_info(ht, k)(hashmap_delete(ht, &(struct ipv4_asn_info){.key=k}))

uint64_t hash_ipv4_info(const void *item, uint64_t seed0, uint64_t seed1);
uint64_t hash_ipv4_complex_info(const void *item, uint64_t seed0, uint64_t seed1);
uint64_t hash_ipv4_asn_info(const void *item, uint64_t seed0, uint64_t seed1);

int ipv4_asn_equal(const void *a, const void *b, void *udata);
int ipv4_equal(const void *a, const void *b, void *udata);
int ipv4_cmp(const void *a, const void *b);


//verstable patch

/*********************************
 * 
 * ipv4_info
 * 
 *********************************/
#define NAME ipv4_uint32_map
#define KEY_TY ipv4
#define VAL_TY uint32_t
static uint64_t hash_ip4(KEY_TY item){
    return XXH3_64bits(&item,sizeof(ipv4));
}
static bool ip4_equal_vt(KEY_TY a, KEY_TY b){
    return a == b ? true : false;
}
#define HASH_FN hash_ip4
#define CMPR_FN ip4_equal_vt
#include "verstable.h"

/*********************************
 * 
 * ipv4_asn_info
 * 
 *********************************/
#define NAME ipv4asn_uint32_map
#define KEY_TY struct ipv4_asn
#define VAL_TY uint32_t
static uint64_t hash_ipv4asn(KEY_TY item){
    return XXH3_64bits(&item,sizeof(struct ipv4_asn));
}
static bool ipv4asn_equal(KEY_TY a, KEY_TY b){
    return a.addr == b.addr && a.asn==b.asn ? true : false;
}
#define HASH_FN hash_ipv4asn
#define CMPR_FN ipv4asn_equal
#include "verstable.h"

/*********************************
 * 
 * ipv4_complex_info
 * 
 *********************************/
#define NAME ipv4_complex_map
#define KEY_TY ipv4
#define VAL_TY struct bmb
static uint64_t hash_ipv4_complex(KEY_TY item){
    return XXH3_64bits(&item,sizeof(ipv4));
}
static bool ipv4_complex_equal(KEY_TY a, KEY_TY b){
    return a == b ? true : false;
}
#define HASH_FN hash_ipv4_complex
#define CMPR_FN ipv4_complex_equal
#include "verstable.h"

/*********************************
 * 
 * ipv6
 * 
 *********************************/
struct ip6_t_asn
{
    struct ip6_t addr;
    uint32_t asn;
};

struct ip6_t_asn_info
{
    struct ip6_t_asn key;
    uint32_t bitmap;
};


struct ip6_t_complex_info{
    struct ip6_t key;
    struct bmb bm;
};

struct ip6_t_info
{
    struct ip6_t key;
    uint32_t bm;
};

struct ip6_t_leafnode_level{
    uint32_t key;
    // FrequencyArray levels;
    struct sc_array_int levels;
};

#define insert_ip6_t_info(ht, k, v)(hashmap_set(ht, &(struct ip6_t_info){.key=k, .bm=v}))
#define insert_ip6_t_complex_info(ht, k, v)(hashmap_set(ht, &(struct ip6_t_complex_info){.key=k, .bm=v}))
#define insert_ip6_t_asn_info(ht, k, v)(hashmap_set(ht, &(struct ip6_t_asn_info){.key=k, .bitmap=v}))
#define insert_ip6_t_leafnode_level(ht, k, v)(hashmap_set(ht, &(struct ip6_t_leafnode_level){.key=k, .levels=v}))

#define find_ip6_t_info(ht, k)(hashmap_get(ht, &(struct ip6_t_info){.key=k}))
#define find_ip6_t_complex_info(ht, k)(hashmap_get(ht, &(struct ip6_t_complex_info){.key=k}))
#define find_ip6_t_asn_info(ht, k)(hashmap_get(ht, &(struct ip6_t_asn_info){.key=k}))
#define find_ip6_t_leafnode_level(ht, k)(hashmap_get(ht, &(struct ip6_t_leafnode_level){.key=k}))

#define delete_ip6_t_info(ht, k)(hashmap_delete(ht, &(struct ip6_t_info){.key=k}))
#define delete_ip6_t_complex_info(ht, k)(hashmap_delete(ht, &(struct ip6_t_complex_info){.key=k}))
#define delete_ip6_t_asn_info(ht, k)(hashmap_delete(ht, &(struct ip6_t_asn_info){.key=k}))
#define delete_ip6_t_leafnode_level(ht, k)(hashmap_delete(ht, &(struct ip6_t_leafnode_level){.key=k}))

uint64_t hash_ip6_t_info(const void *item, uint64_t seed0, uint64_t seed1);
uint64_t hash_ip6_t_complex_info(const void *item, uint64_t seed0, uint64_t seed1);
uint64_t hash_ip6_t_asn_info(const void *item, uint64_t seed0, uint64_t seed1);
uint64_t hash_ip6_t_leafnode_level(const void *item, uint64_t seed0, uint64_t seed1);

int ip6_t_asn_equal(const void *a, const void *b, void *udata);
int ip6_t_equal(const void *a, const void *b, void *udata);
int ip6_midlevel_equal(const void *a, const void *b, void *udata);
int ip6_t_cmp(const void *a, const void *b, void *udata);

#endif
