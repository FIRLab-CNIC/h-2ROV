#include"wideArray_extra.h"

int hash_cmp_wideASN(const void *a, const void *b, void *udata) {
    const wideASN_block *ua = a;
    const wideASN_block *ub = b;
    return ua->asn==ub->asn?0:-1;
}

uint64_t hash_block_wideASN(const void *item, uint64_t seed0, uint64_t seed1) {
    const wideASN_block *user = item;
    // return hxgcum((unsigned int*)&user->asn,4,user->asn);
    return user->asn;
}

void wideASN_init(wideASN *widearray){
    widearray->dyheader = hashmap_new(sizeof(wideASN_block),0,0,0,hash_block_wideASN,hash_cmp_wideASN,NULL,NULL);
}

int wideASN_insert(wideASN *widearray,uint32_t header){
    w6 value;
    wideASN_block * wb = hashmap_get(widearray->dyheader,&(wideASN_block){.asn=header});
    if(!wb){
        hashmap_set(widearray->dyheader,&(wideASN_block){.asn=header,.count=1});
        if(hashmap_oom(widearray->dyheader)) return ERROR;
    }
    else{
        int count = wb->count;
        hashmap_set(widearray->dyheader,&(wideASN_block){.asn=header,.count=count+1});
    }
    return SUCCESS;
}

int wideASN_remove(wideASN *widearray,uint32_t header){
    wideASN_block * wb = hashmap_get(widearray->dyheader,&(wideASN_block){.asn=header});
    if(!wb){
        puts("DONT HAVE SUCH WIDE ROA(HEADER)!");
        return ERROR;
    }
    else{
        int count = wb->count;
        if(count==1){
            hashmap_delete(widearray->dyheader,&(wideASN_block){.asn=header});
        }
        else{
            hashmap_set(widearray->dyheader,&(wideASN_block){.asn=header,.count=count-1});
        }
    }
}


void wideASN_print(wideASN *widearray){
    size_t iter = 0;
    void *item;
    while (hashmap_iter(widearray->dyheader, &iter, &item)) {
        const wideASN_block *user = item;
        uint32_t header = user->asn;
        int count = user->count;
        printf("identifier: %u, count: %d\n",header,count);
    }
}


void wideASN_free(wideASN *widearray){
    hashmap_free(widearray->dyheader);
    free(widearray);
}