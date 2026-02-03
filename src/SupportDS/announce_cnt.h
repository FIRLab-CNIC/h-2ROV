#ifndef ANNOUNCE_CNT_H
#define ANNOUNCE_CNT_H

/***
 * @brief data structure used to statistic reference count in STT
 * @details hashmap structure:
 *          +++++++++++++++++++++++++++++++++++++++
 *          +  sot/stt key  +  uint8_t array[32]  +
 *          +++++++++++++++++++++++++++++++++++++++
*/
#include "hash.h"
#include "hashmap.h"
#include "common.h"
#include"../utils/mprint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <xxhash.h>

#define ALLZERO 1

//basic reference cnt
typedef struct{
    uint8_t rc[32];
}reference_cnt;

//entry in hashmap
typedef struct{
    struct ipv4_asn key;
    reference_cnt cnt; 
} rcBlock_sot4;

typedef struct{
    struct ip6_t_asn key;
    reference_cnt cnt; 
} rcBlock_sot6;

typedef struct{
    ipv4 key;
    reference_cnt cnt; 
} rcBlock_stt4;

typedef struct{
    struct ip6_t key;
    reference_cnt cnt; 
} rcBlock_stt6;

//reference count with sot/stt
typedef struct{
    struct hashmap *map;
}rc_sot4;

typedef struct{
    struct hashmap *map;
}rc_stt4;

typedef struct{
    struct hashmap *map;
}rc_sot6;

typedef struct{
    struct hashmap *map;
}rc_stt6;

#define insert_rcBlock_sot4(ht, k, v)(hashmap_set(ht, &(rcBlock_sot4){.key=k, .cnt=v}))
#define find_rcBlock_sot4(ht, k)(hashmap_get(ht, &(rcBlock_sot4){.key=k}))
#define delete_rcBlock_sot4(ht, k)(hashmap_delete(ht, &(rcBlock_sot4){.key=k}))

#define insert_rcBlock_stt4(ht, k, v)(hashmap_set(ht, &(rcBlock_stt4){.key=k, .cnt=v}))
#define find_rcBlock_stt4(ht, k)(hashmap_get(ht, &(rcBlock_stt4){.key=k}))
#define delete_rcBlock_stt4(ht, k)(hashmap_delete(ht, &(rcBlock_stt4){.key=k}))

#define insert_rcBlock_sot6(ht, k, v)(hashmap_set(ht, &(rcBlock_sot6){.key=k, .cnt=v}))
#define find_rcBlock_sot6(ht, k)(hashmap_get(ht, &(rcBlock_sot6){.key=k}))
#define delete_rcBlock_sot6(ht, k)(hashmap_delete(ht, &(rcBlock_sot6){.key=k}))

#define insert_rcBlock_stt6(ht, k, v)(hashmap_set(ht, &(rcBlock_stt6){.key=k, .cnt=v}))
#define find_rcBlock_stt6(ht, k)(hashmap_get(ht, &(rcBlock_stt6){.key=k}))
#define delete_rcBlock_stt6(ht, k)(hashmap_delete(ht, &(rcBlock_stt6){.key=k}))

//hash functions
uint64_t hash_rc_sot4(const void *item, uint64_t seed0, uint64_t seed1);
uint64_t hash_rc_stt4(const void *item, uint64_t seed0, uint64_t seed1);
uint64_t hash_rc_sot6(const void *item, uint64_t seed0, uint64_t seed1);
uint64_t hash_rc_stt6(const void *item, uint64_t seed0, uint64_t seed1);

//reference count init
void rc_sot4_init(rc_sot4 *rc);
void rc_stt4_init(rc_stt4 *rc);
void rc_sot6_init(rc_sot6 *rc);
void rc_stt6_init(rc_stt6 *rc);

//reference count insert
int rc_sot4_insert_new(rc_sot4 *rc,struct ipv4_asn k,uint32_t bitmap,uint32_t bitmap_new);
int rc_sot4_insert(rc_sot4 *rc,struct ipv4_asn k,uint32_t bitmap);

int rc_stt4_insert_new(rc_stt4 *rc,ipv4 k,uint32_t bitmap,uint32_t bitmap_new);
int rc_stt4_insert(rc_stt4 *rc,ipv4 k,uint32_t bitmap);

int rc_sot6_insert_new(rc_sot6 *rc,struct ip6_t_asn k,uint32_t bitmap,uint32_t bitmap_new);
int rc_sot6_insert(rc_sot6 *rc,struct ip6_t_asn k,uint32_t bitmap);

int rc_stt6_insert_new(rc_stt6 *rc, struct ip6_t k, uint32_t bitmap, uint32_t bitmap_new);
int rc_stt6_insert(rc_stt6 *rc, struct ip6_t k, uint32_t bitmap);

//reference count remove
int rc_sot4_remove(rc_sot4 *rc,struct ipv4_asn k,uint32_t bitmap_new,uint32_t *bitmap);
int rc_stt4_remove(rc_stt4 *rc,ipv4 k, uint32_t bitmap_new,uint32_t *bitmap);
int rc_sot6_remove(rc_sot6 *rc,struct ip6_t_asn k,uint32_t bitmap_new,uint32_t *bitmap);
int rc_stt6_remove(rc_stt6 *rc, struct ip6_t k, uint32_t bitmap_new,uint32_t *bitmap);

//reference count print
int rc_sot4_print(rc_sot4 *rc);
int rc_stt4_print(rc_stt4 *rc);
int rc_sot6_print(rc_sot6 *rc);
int rc_stt6_print(rc_stt6 *rc);

void reference_cnt_init(reference_cnt *rc);

//reference cnt insert
void reference_cnt_insert(reference_cnt *rc,uint32_t bitmap);

//reference cnt delete
int reference_cnt_withdrawn(reference_cnt *rc, uint32_t bitmap, uint32_t *res);

int reference_cnt_print(reference_cnt *rc);

#endif