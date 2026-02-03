#include"wideArray.h"

int hash_cmp_v4(const void *a, const void *b, void *udata) {
    const wideBlock4 *ua = a;
    const wideBlock4 *ub = b;
    return ua->header==ub->header?0:-1;
}

uint64_t hash_block_v4(const void *item, uint64_t seed0, uint64_t seed1) {
    const wideBlock4 *user = item;
    return hxgcum((unsigned int*)&user->header,4,user->header);
}

void wideArray_init_v4(wideArray4 *widearray){
    widearray->dyheader = hashmap_new(sizeof(wideBlock4),0,0,0,hash_block_v4,hash_cmp_v4,NULL,NULL);
}

int wideArray_insert_v4(wideArray4 *widearray,uint32_t header,uint32_t pfx, int masklen, int maxlen, uint32_t asn){
    w4 value;
    value.pfx = pfx;
    value.asn = asn;
    value.masklen = masklen;
    value.maxlen = maxlen;
    wideBlock4 * wb = hashmap_get(widearray->dyheader,&(wideBlock4){.header=header});
    if(!wb){
        struct sc_array_w4 arr; 
        sc_array_init(&arr);
        sc_array_add(&arr,value);
        hashmap_set(widearray->dyheader,&(wideBlock4){.header=header,.body=arr});
        if(hashmap_oom(widearray->dyheader)) return ERROR;
    }
    else{
        struct sc_array_w4 arr = wb->body;
        // printf("%ld\n",arr.size);
        sc_array_add(&arr,value);
        hashmap_set(widearray->dyheader,&(wideBlock4){.header=header,.body=arr});
    }
    return SUCCESS;
}

int wideArray_remove_v4(wideArray4 *widearray,uint32_t header,uint32_t pfx, int masklen, int maxlen, uint32_t asn,int *flag){
    w4 value;
    value.pfx = pfx;
    value.asn = asn;
    value.masklen = masklen;
    value.maxlen = maxlen;
    *flag=WA_NOTNULL;
    wideBlock4 * wb = hashmap_get(widearray->dyheader,&(wideBlock4){.header=header});
    if(!wb){
        puts("DONT HAVE SUCH WIDE ROA(HEADER)!");
        return ERROR;
    }
    else{
        int delIndex = -1;
        struct sc_array_w4 arr = wb->body;
        for (size_t i = 0; i < sc_array_size(&arr); i++) {
            if(w4_cmp(value,arr.elems[i])){
                delIndex = i;
                break;
            }
        }
        if(delIndex!=-1){
            sc_array_del(&arr,delIndex);
            if(sc_array_size(&arr)==0){
                *flag = WA_NULL;
                hashmap_delete(widearray->dyheader,&(wideBlock4){.header=header});
            }
            else{
                hashmap_set(widearray->dyheader,&(wideBlock4){.header=header,.body=arr});
            }
        }
        else{
            puts("DON HAVE SUCH WIDE ROA!");
            return ERROR;
        }
    }
}

void wideArray_print_v4(wideArray4 *widearray){
    size_t iter = 0;
    void *item;
    while (hashmap_iter(widearray->dyheader, &iter, &item)) {
        const wideBlock4 *user = item;
        uint32_t header = user->header;
        struct sc_array_w4 arr = user->body;
        printf("header Identifier: %x\n",header);
        for(int i=0;i<sc_array_size(&arr);i++){
            w4 tmp = arr.elems[i];
            printf("pfx: %x, masklen: %d, maxlen: %d, asn: %u\n",tmp.pfx,tmp.masklen,tmp.maxlen,tmp.asn);
        }
    }
}

int wideArray_copy_v4(wideArray4 *widearray,ipv4 org,ipv4 dest){
    wideBlock4 *wb = hashmap_get(widearray->dyheader,&(wideBlock4){.header=org});
    struct sc_array_w4 arr = wb->body;
    for(int i=0;i<sc_array_size(&arr);i++){
        w4 tmp = arr.elems[i];
        if(wideArray_insert_v4(widearray,dest,tmp.pfx,tmp.masklen,tmp.maxlen,tmp.asn)==ERROR) return ERROR;
    }
    return SUCCESS;
}

void wideArray_validate_v4(wideArray4 *wide_array,uint32_t header,uint32_t pfx,int masklen,uint32_t asn,enum pfxv_state *res){
    wideBlock4 *wb = hashmap_get(wide_array->dyheader,&(wideBlock4){.header=header});
    if(wb){
        struct sc_array_w4 arr = wb->body;
        for(int i=0;i<sc_array_size(&arr);i++){
            w4 winfo = arr.elems[i];
            if(masklen<winfo.masklen){
                ;
            }
            else if(((pfx>>(32-winfo.masklen))==(winfo.pfx>>(32-winfo.masklen)))){
                if(masklen<=winfo.maxlen && asn==winfo.asn){
                    *res = BGP_PFXV_STATE_VALID;
                    return;
                }
                else{
                    *res = BGP_PFXV_STATE_INVALID;
                }
            }
        }
    }
}

void wideArray_free_v4(wideArray4 *widearray){
    size_t iter = 0;
    void *item;
    while (hashmap_iter(widearray->dyheader, &iter, &item)) {
        const wideBlock4 *user = item;
        uint32_t header = user->header;
        struct sc_array_w4 arr = user->body;
        sc_array_term(&arr);
    }
    hashmap_free(widearray->dyheader);
    free(widearray);
}

int hash_cmp_v6(const void *a, const void *b, void *udata) {
    const struct ip6_t *ua = a;
    const struct ip6_t *ub = b;
    for(int i=0;i<2;i++){
        if(ua->u_ip6.u_ip6_addr64[i]<ub->u_ip6.u_ip6_addr64[i])
        {
            return -1;
        }
        else if(ua->u_ip6.u_ip6_addr64[i]>ub->u_ip6.u_ip6_addr64[i])
        {
            return 1;
        }
    }
    // const struct ip6_t * ua = a;
    // const struct ip6_t * ub = b;
    // return ua->u_ip6.u_ip6_addr64[1] == ub->u_ip6.u_ip6_addr64[1] && ua->u_ip6.u_ip6_addr64[0]==ub->u_ip6.u_ip6_addr64[0] ? 0 : 1;
    return 0;
}

uint64_t hash_block_v6(const void *item, uint64_t seed0, uint64_t seed1) {
    const wideBlock6 *user = item;
    // uint64_t hash = hashmap_murmur(&user->header, sizeof(uint32_t)*4, seed0, seed1);
    return XXH3_64bits_withSeed(&user->header,sizeof(uint32_t)*4,seed0);
    // return hash;
}

void wideArray_init_v6(wideArray6 *widearray){
    widearray->dyheader = hashmap_new(sizeof(wideBlock6),0,0,0,hash_block_v6,hash_cmp_v6,NULL,NULL);
}

int wideArray_insert_v6(wideArray6 *widearray,struct ip6_t header,struct ip6_t prefix,int masklen,int maxlen,uint32_t asn){
    w6 value;
    value.masklen=masklen;
    value.maxlen=maxlen;
    value.asn=asn;
    memcpy(&value.pfx.u_ip6.u_ip6_addr32,&prefix.u_ip6.u_ip6_addr32,sizeof(struct ip6_t));
    wideBlock6 * wb = hashmap_get(widearray->dyheader,&(wideBlock6){.header=header});
    if(!wb){
        struct sc_array_w6 arr; 
        sc_array_init(&arr);
        sc_array_add(&arr,value);
        hashmap_set(widearray->dyheader,&(wideBlock6){.header=header,.body=arr});
        if(hashmap_oom(widearray->dyheader)) return ERROR;
    }
    else{
        struct sc_array_w6 arr = wb->body;
        sc_array_add(&arr,value);
        hashmap_set(widearray->dyheader,&(wideBlock6){.header=header,.body=arr});
    }
    return SUCCESS;
}

int wideArray_remove_v6(wideArray6 *widearray,struct ip6_t header,struct ip6_t prefix,int masklen,int maxlen,uint32_t asn,int *flag){
    w6 value;
    memcpy(value.pfx.u_ip6.u_ip6_addr32,prefix.u_ip6.u_ip6_addr32,sizeof(uint32_t)*4);
    value.asn = asn;
    value.masklen = masklen;
    value.maxlen = maxlen;
    *flag = WA_NOTNULL;
    wideBlock6 * wb = hashmap_get(widearray->dyheader,&(wideBlock6){.header=header});
    if(!wb){
        puts("DONT HAVE SUCH WIDE ROA(HEADER)!");
        return ERROR;
    }
    else{
        int delIndex = -1;
        struct sc_array_w6 arr = wb->body;
        for (size_t i = 0; i < sc_array_size(&arr); i++) {
            if(w6_cmp(value,arr.elems[i])){
                delIndex = i;
                break;
            }
        }
        if(delIndex!=-1){
            sc_array_del(&arr,delIndex);
            if(sc_array_size(&arr)==0){
                *flag = WA_NULL;
                hashmap_delete(widearray->dyheader,&(wideBlock6){.header=header});
            }
            else{
                hashmap_set(widearray->dyheader,&(wideBlock6){.header=header,.body=arr});
            }
        }
        else{
            puts("DON HAVE SUCH WIDE ROA!");
            return ERROR;
        }
    }
}


void wideArray_print_v6(wideArray6 *widearray){
    puts("wideArray_v6");
    size_t iter = 0;
    void *item;
    while (hashmap_iter(widearray->dyheader, &iter, &item)) {
        const wideBlock6 *user = item;
        struct ip6_t header = user->header;
        struct sc_array_w6 arr = user->body;
        printf("identifier: ");
        SHOW_IPV6_oct(header.u_ip6.u_ip6_addr32);
        for(int i=0;i<sc_array_size(&arr);i++){
            w6 tmp = arr.elems[i];
            printf("prefix: ");
            SHOW_IPV6_oct(tmp.pfx.u_ip6.u_ip6_addr32);
            printf("masklen: %d, maxlen: %d, asn: %u\n",tmp.masklen,tmp.maxlen,tmp.asn);
        }
    }
}

int wideArray_copy_v6(wideArray6 *widearray,struct ip6_t org,struct ip6_t dest){
    struct ip6_t org_t;
    memcpy(&org_t.u_ip6.u_ip6_addr32,org.u_ip6.u_ip6_addr32,sizeof(struct ip6_t));
    wideBlock6 *wb = hashmap_get(widearray->dyheader,&(wideBlock6){.header=org_t});
    struct sc_array_w6 arr = wb->body;
    for(int i=0;i<sc_array_size(&arr);i++){
        w6 tmp = arr.elems[i];
        if(wideArray_insert_v6(widearray,dest,tmp.pfx,tmp.masklen,tmp.maxlen,tmp.asn)==ERROR) return ERROR;
    }
    return SUCCESS;
}

bool ip6_compare_with_masklen(uint32_t addr1[4],uint32_t addr2[4],int masklen){
    int full_blocks = masklen / 32;  // 完全比较的 32 位块数
    int remaining_bits = masklen % 32;  // 剩余的位数

    // 比较完整的 32 位块
    for (int i = 0; i < full_blocks; i++) {
        if (addr1[i] != addr2[i]) {
            return false;
        }
    }

    // 比较剩余的位数
    if (remaining_bits > 0) {
        uint32_t mask = ((1U << remaining_bits) - 1) << (32 - remaining_bits);
        if ((addr1[full_blocks] & mask) != (addr2[full_blocks] & mask)) {
            return false;
        }
    }

    return true;
}

void wideArray_validate_v6(wideArray6 *wide_array,struct ip6_t header,struct ip6_t pfx,int masklen,uint32_t asn,enum pfxv_state *res){
    wideBlock6 *wb = hashmap_get(wide_array->dyheader,&(wideBlock6){.header=header});
    if(wb){
        struct sc_array_w6 arr = wb->body;
        for(int i=0;i<sc_array_size(&arr);i++){
            w6 winfo = arr.elems[i];
            if(i<arr.size-1) __builtin_prefetch(&arr.elems[i+1],0,2);
            if(masklen<winfo.masklen){
                ;
            }
            else{
                uint32_t pfx_tmp[4],ptr_tmp[4];
                r_move_v6_fast(pfx.u_ip6.u_ip6_addr32,pfx_tmp,(128-winfo.masklen));
                r_move_v6_fast(winfo.pfx.u_ip6.u_ip6_addr32,ptr_tmp,(128-winfo.masklen));
                if(pfx_tmp[3]==ptr_tmp[3]&&pfx_tmp[2]==ptr_tmp[2]&&pfx_tmp[1]==ptr_tmp[1]&&pfx_tmp[0]==ptr_tmp[0]){
                // if(ip6_compare_with_masklen(pfx.u_ip6.u_ip6_addr32,winfo.pfx.u_ip6.u_ip6_addr32,winfo.masklen)){
                    if(masklen<=winfo.maxlen && asn==winfo.asn){
                        *res = BGP_PFXV_STATE_VALID;
                        break;
                    }
                    else{
                        *res = BGP_PFXV_STATE_INVALID;
                    }
                }
            }
        }
    }
}

void wideArray_free_v6(wideArray6 *widearray){
    size_t iter = 0;
    void *item;
    while (hashmap_iter(widearray->dyheader, &iter, &item)) {
        const wideBlock6 *user = item;
        struct ip6_t header = user->header;
        struct sc_array_w6 arr = user->body;
        sc_array_term(&arr);
    }
    hashmap_free(widearray->dyheader);
    free(widearray);
}