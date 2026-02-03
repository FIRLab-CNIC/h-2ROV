#ifndef WIDEARRAY_H
#define WIDEARRAY_H
#include"hashmap.h"
#include"rtrlib/rtrlib.h"
#include"sc-vector.h"
#include"hash.h"
#include"common.h"
#include"../utils/utils.h"
#include"../utils/mprint.h"
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#define DIVIDER 3
#define WA_NULL 0
#define WA_NOTNULL 1

typedef struct{
    uint32_t pfx;
    int masklen;
    int maxlen;
    uint32_t asn;
}w4;

typedef struct{
    struct ip6_t pfx;
    int masklen;
    int maxlen;
    uint32_t asn;
}w6;

#define w4_cmp(org,des)(org.pfx==des.pfx&&org.masklen==des.masklen&&org.maxlen==des.maxlen&&org.asn==des.asn)
#define w6_cmp(org,des)(org.pfx.u_ip6.u_ip6_addr64[1] == org.pfx.u_ip6.u_ip6_addr64[1] && org.pfx.u_ip6.u_ip6_addr64[0]==org.pfx.u_ip6.u_ip6_addr64[0]&&org.masklen==des.masklen&&org.maxlen==des.maxlen&&org.asn==des.asn)

sc_array_def(w4,w4);

typedef struct{
    uint32_t header;
    struct sc_array_w4 body; 
} wideBlock4;
 
typedef struct{
    struct hashmap *dyheader;
} wideArray4;


int hash_cmp_v4(const void *a, const void *b, void *udata);
uint64_t hash_block_v4(const void *item, uint64_t seed0, uint64_t seed1);

void wideArray_init_v4(wideArray4 *widearray);

/**
 * @brief insert wide ROA in IPv4
 * @param[in] widearray
 * @param[in] header identifier of the wideROA
 * @param[in] pfx_to_asn information about the wideROA being inserted
*/
int wideArray_insert_v4(wideArray4 *widearray,uint32_t header,uint32_t pfx, int masklen, int maxlen, uint32_t asn);

/**
 * @brief remove wide ROA in IPv4
 * @param[in] widearray
 * @param[in] header identifier of the wideROA
 * @param[in] pfx_to_asn information about the wideROA being removed
 * @param[in,out] flag if the number of wideROA under the header is zero,set flag to WA_NULL,else set to WA_NOTNULL
*/
int wideArray_remove_v4(wideArray4 *widearray,uint32_t header, uint32_t pfx, int masklen, int maxlen, uint32_t asn,int *flag);


void wideArray_validate_v4(wideArray4 *wide_array,uint32_t header,uint32_t pfx,int masklen,uint32_t asn,enum pfxv_state *res);

int wideArray_copy_v4(wideArray4 *widearray,ipv4 org,ipv4 dest);
void wideArray_print_v4(wideArray4 *widearray);
void wideArray_free_v4(wideArray4 *widearray);


/**
 * =================================================================
 *                           IPv6 part
 * =================================================================
 * 
 **/
sc_array_def(w6,w6);

typedef struct{
    struct ip6_t header;
    struct sc_array_w6 body; 
} wideBlock6;

typedef struct{
    struct hashmap *dyheader;
} wideArray6;

int hash_cmp_v6(const void *a, const void *b, void *udata);
uint64_t hash_block_v6(const void *item, uint64_t seed0, uint64_t seed1);

void wideArray_init_v6(wideArray6 *widearray);

/**
 * @brief insert wide ROA in IPv6
 * @param[in] widearray
 * @param[in] header identifier of the wideROA
 * @param[in] value information about the wideROA being inserted
*/
int wideArray_insert_v6(wideArray6 *widearray,struct ip6_t header,struct ip6_t prefix,int masklen,int maxlen,uint32_t asn);

/**
 * @brief remove wide ROA in IPv6
 * @param[in] widearray
 * @param[in] header identifier of the wideROA
 * @param[in] value information about the wideROA being removed
 * @param[in,out] flag if the number of wideROA under the header is zero,set flag to WA_NULL,else set to WA_NOTNULL
*/
int wideArray_remove_v6(wideArray6 *widearray,struct ip6_t header,struct ip6_t prefix,int masklen,int maxlen,uint32_t asn,int *flag);

int wideArray_copy_v6(wideArray6 *widearray,struct ip6_t org,struct ip6_t dest);

void wideArray_print_v6(wideArray6 *widearray);

/**
 * @brief validate result
 * @param[in] wide_array
 * @param[in] header header of the wideArray
 * @param[in] pfx
 * @param[in] masklen
 * @param[in] asn
 * @param[in,out] res result of the validation
*/
void wideArray_validate_v6(wideArray6 *wide_array,struct ip6_t header,struct ip6_t pfx,int masklen,uint32_t asn,enum pfxv_state *res);
void wideArray_free_v6(wideArray6 *wide_array);
#endif