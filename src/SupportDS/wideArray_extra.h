#ifndef WIDEARRAY_EXTRA_H
#define WIDEARRAY_EXTRA_H

#include"wideArray.h"

typedef struct{
    uint32_t asn;
    int count;
} wideASN_block;

typedef struct{
    struct hashmap *dyheader;
} wideASN;

int hash_cmp_wideASN(const void *a, const void *b, void *udata);
uint64_t hash_block_wideASN(const void *item, uint64_t seed0, uint64_t seed1);

void wideASN_init(wideASN *widearray);
int wideASN_insert(wideASN *widearray,uint32_t header);
int wideASN_remove(wideASN *widearray,uint32_t header);
void wideASN_print(wideASN *widearray);
void wideASN_free(wideASN *wide_array);

#endif