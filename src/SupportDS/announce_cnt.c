#include "announce_cnt.h"

uint64_t hash_rc_sot4(const void *item, uint64_t seed0, uint64_t seed1){
    const rcBlock_sot4 *p = (const rcBlock_sot4*)item;
    return hxgcum((unsigned int*)&p->key,8,p->key.asn);
}

uint64_t hash_rc_stt4(const void *item, uint64_t seed0, uint64_t seed1){
    const rcBlock_stt4 * p = (const rcBlock_stt4 *)item;
    return hxgcum((unsigned int*)&p->key,4,p->key); 
}

uint64_t hash_rc_sot6(const void *item, uint64_t seed0, uint64_t seed1){
    const rcBlock_sot6 * p = (const rcBlock_sot6 *)item;
    return XXH3_64bits_withSeed(&p->key,20,seed0);
    // return hashmap_murmur(&p->key, sizeof(struct ip6_t_asn), seed0, seed1);
}

uint64_t hash_rc_stt6(const void *item, uint64_t seed0, uint64_t seed1){
    const rcBlock_stt6 * p = (const rcBlock_stt6 *)item;
    return XXH3_64bits_withSeed(&p->key,sizeof(struct ip6_t),seed0);
    // return hashmap_murmur(&p->key, sizeof(ipv6), seed0, seed1);
}

void rc_sot4_init(rc_sot4 *rc){
    rc->map = hashmap_new(sizeof(rcBlock_sot4),0,0,0,hash_rc_sot4,ipv4_asn_equal,NULL,NULL);
}

void rc_stt4_init(rc_stt4 *rc){
    rc->map = hashmap_new(sizeof(rcBlock_stt4),0,0,0,hash_rc_stt4,ipv4_equal,NULL,NULL);
}

void rc_sot6_init(rc_sot6 *rc){
    rc->map = hashmap_new(sizeof(rcBlock_sot6),0,0,0,hash_rc_sot6,ip6_t_asn_equal,NULL,NULL);
}

void rc_stt6_init(rc_stt6 *rc){
    rc->map = hashmap_new(sizeof(rcBlock_stt6),0,0,0,hash_rc_stt6,ip6_t_equal,NULL,NULL);
}

int rc_sot4_insert_new(rc_sot4 *rc,struct ipv4_asn k,uint32_t bitmap,uint32_t bitmap_new){
    reference_cnt rc_arr;
    reference_cnt_init(&rc_arr);
    reference_cnt_insert(&rc_arr,bitmap);
    reference_cnt_insert(&rc_arr,bitmap_new);
    insert_rcBlock_sot4(rc->map,k,rc_arr);
    if(hashmap_oom(rc->map)) return ERROR;
    return SUCCESS;
}

int rc_sot4_insert(rc_sot4 *rc,struct ipv4_asn k,uint32_t bitmap){
    rcBlock_sot4 *offset = find_rcBlock_sot4(rc->map,k);
    if(!offset) return ERROR;
    reference_cnt rc_arr = offset->cnt;
    reference_cnt_insert(&rc_arr,bitmap);
    insert_rcBlock_sot4(rc->map,k,rc_arr);
    return SUCCESS;
}

int rc_stt4_insert_new(rc_stt4 *rc,ipv4 k,uint32_t bitmap,uint32_t bitmap_new){
    reference_cnt rc_arr;
    reference_cnt_init(&rc_arr);
    reference_cnt_insert(&rc_arr,bitmap);
    reference_cnt_insert(&rc_arr,bitmap_new);
    insert_rcBlock_stt4(rc->map,k,rc_arr);

    if(hashmap_oom(rc->map)) return ERROR;
    return SUCCESS;
}

int rc_stt4_insert(rc_stt4 *rc,ipv4 k,uint32_t bitmap){
    rcBlock_stt4 *offset = find_rcBlock_stt4(rc->map,k);
    if(!offset) return ERROR;
    reference_cnt rc_arr = offset->cnt;
    reference_cnt_insert(&rc_arr,bitmap);
    insert_rcBlock_stt4(rc->map,k,rc_arr);
    return SUCCESS;
}

int rc_sot6_insert_new(rc_sot6 *rc,struct ip6_t_asn k,uint32_t bitmap,uint32_t bitmap_new){
    reference_cnt rc_arr;
    reference_cnt_init(&rc_arr);
    reference_cnt_insert(&rc_arr,bitmap);
    reference_cnt_insert(&rc_arr,bitmap_new);
    insert_rcBlock_sot6(rc->map,k,rc_arr);
    if(hashmap_oom(rc->map)) return ERROR;
    return SUCCESS;
}

int rc_sot6_insert(rc_sot6 *rc,struct ip6_t_asn k,uint32_t bitmap){
    rcBlock_sot6 *offset = find_rcBlock_sot6(rc->map,k);
    if(!offset) return ERROR;
    reference_cnt rc_arr = offset->cnt;
    reference_cnt_insert(&rc_arr,bitmap);
    insert_rcBlock_sot6(rc->map,k,rc_arr);
    return SUCCESS;
}

int rc_stt6_insert_new(rc_stt6 *rc, struct ip6_t k, uint32_t bitmap, uint32_t bitmap_new){
    reference_cnt rc_arr;
    reference_cnt_init(&rc_arr);
    reference_cnt_insert(&rc_arr,bitmap);
    reference_cnt_insert(&rc_arr,bitmap_new);
    insert_rcBlock_stt6(rc->map,k,rc_arr);
    if(hashmap_oom(rc->map)) return ERROR;
    return SUCCESS;
}

int rc_stt6_insert(rc_stt6 *rc, struct ip6_t k, uint32_t bitmap){
    rcBlock_stt6 *offset = find_rcBlock_stt6(rc->map,k);
    if(!offset) return ERROR;
    reference_cnt rc_arr = offset->cnt;
    reference_cnt_insert(&rc_arr,bitmap);
    insert_rcBlock_stt6(rc->map,k,rc_arr);
    return SUCCESS;
}

int rc_sot4_remove(rc_sot4 *rc,struct ipv4_asn k,uint32_t bitmap_new,uint32_t *bitmap){
    rcBlock_sot4 *withdrawn_info = find_rcBlock_sot4(rc->map,k);
    if(!withdrawn_info) return ERROR;
    reference_cnt rc_arr = withdrawn_info->cnt;
    int flag = reference_cnt_withdrawn(&rc_arr,bitmap_new,bitmap);
    insert_rcBlock_sot4(rc->map,k,rc_arr);
    if(flag==ALLZERO){
        delete_rcBlock_sot4(rc->map,k);
    }
    return flag;
}

int rc_stt4_remove(rc_stt4 *rc,ipv4 k,uint32_t bitmap_new,uint32_t *bitmap){
    rcBlock_stt4 *withdrawn_info = find_rcBlock_stt4(rc->map,k);
    if(!withdrawn_info) return ERROR;
    reference_cnt rc_arr = withdrawn_info->cnt;
    int flag = reference_cnt_withdrawn(&rc_arr,bitmap_new,bitmap);
    insert_rcBlock_stt4(rc->map,k,rc_arr);
    if(flag){
        delete_rcBlock_stt4(rc->map,k);
    }
    return flag;
}

int rc_sot6_remove(rc_sot6 *rc,struct ip6_t_asn k,uint32_t bitmap_new,uint32_t *bitmap){
    rcBlock_sot6 *withdrawn_info = find_rcBlock_sot6(rc->map,k);
    if(!withdrawn_info) return ERROR;
    reference_cnt rc_arr = withdrawn_info->cnt;
    int flag = reference_cnt_withdrawn(&rc_arr,bitmap_new,bitmap);
    insert_rcBlock_sot6(rc->map,k,rc_arr);
    if(flag){
        delete_rcBlock_sot6(rc->map,k);
    }
    return flag;
}

int rc_stt6_remove(rc_stt6 *rc,struct ip6_t k,uint32_t bitmap_new,uint32_t *bitmap){
    rcBlock_stt6 *withdrawn_info = find_rcBlock_stt6(rc->map,k);
    if(!withdrawn_info) return ERROR;
    reference_cnt rc_arr = withdrawn_info->cnt;
    int flag = reference_cnt_withdrawn(&rc_arr,bitmap_new,bitmap);
    insert_rcBlock_stt6(rc->map,k,rc_arr);
    if(flag){
        delete_rcBlock_stt6(rc->map,k);
    }
    return flag;
}

int rc_sot4_print(rc_sot4 *rc){
    size_t iter = 0;
    void *item;
    while (hashmap_iter(rc->map, &iter, &item)) {
        const rcBlock_sot4 *user = item;
        struct ipv4_asn header = user->key;
        reference_cnt arr = user->cnt;
        printf("header Identifier: %x %u\n",header.addr,header.asn);
        reference_cnt_print(&arr);
    }
}

int rc_stt4_print(rc_stt4 *rc){
    size_t iter = 0;
    void *item;
    while (hashmap_iter(rc->map, &iter, &item)) {
        const rcBlock_stt4 *user = item;
        ipv4 header = user->key;
        reference_cnt arr = user->cnt;
        printf("header Identifier: %x\n",header);
        reference_cnt_print(&arr);
    }
}

int rc_sot6_print(rc_sot6 *rc){
    size_t iter = 0;
    void *item;
    while (hashmap_iter(rc->map, &iter, &item)) {
        const rcBlock_sot6 *user = item;
        struct ip6_t_asn header = user->key;
        reference_cnt arr = user->cnt;
        printf("identifier: ");
        SHOW_IPV6_oct(header.addr.u_ip6.u_ip6_addr32);
        printf("%u\n",header.asn);
        reference_cnt_print(&arr);
    }
}

int rc_stt6_print(rc_stt6 *rc){
    size_t iter = 0;
    void *item;
    while (hashmap_iter(rc->map, &iter, &item)) {
        const rcBlock_stt6 *user = item;
        struct ip6_t header = user->key;
        reference_cnt arr = user->cnt;
        printf("identifier: ");
        SHOW_IPV6_oct(header.u_ip6.u_ip6_addr32);
        reference_cnt_print(&arr);
    }
}


void reference_cnt_init(reference_cnt *rc){
    for(int i=0;i<32;i++){
        rc->rc[i] = 0;
    }
}

void reference_cnt_insert(reference_cnt *rc,uint32_t bitmap){
    bitmap = bitmap >> 1;
    for(int i=1;i<32;i++){
        if((bitmap & 1) == 1){
            rc->rc[i]+=1;
        }
        bitmap = bitmap >> 1;
    }
}

int reference_cnt_withdrawn(reference_cnt *rc, uint32_t bitmap, uint32_t *res){
    bitmap = bitmap >> 1;
    int flag=ALLZERO;
    for(int i=1;i<32;i++){
        if((bitmap & 1) ==1){
            rc->rc[i]-=1;
            if(rc->rc[i]==0){
                *res = *res & (~((uint32_t)1<<i));
            }
            else if(rc->rc[i]<0){
               rc->rc[i]=0;
            }
        }
        if(rc->rc[i]>1){
            flag=0;
        }
        bitmap = bitmap >> 1;
    }
    return flag;
}

int reference_cnt_print(reference_cnt *rc){
    for(int i=31;i>=0;i--){
        printf("%d",rc->rc[i]);
        if(i%4==0) printf(" ");
    }
    printf("\n");
}