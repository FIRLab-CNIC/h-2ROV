#include"hrov.h"

int widelen_v4 = 8;
int widelen_v6 = 8;

void hrov_pfxt_init_basic(struct hrov_table_basic *ht){
    ht->sot_v4=hashmap_new(sizeof(struct ipv4_asn_info),0,0,0,hash_ipv4_asn_info,ipv4_asn_equal,NULL,NULL);
    ht->sot_v6=hashmap_new(sizeof(struct ip6_t_asn_info),0,0,0,hash_ip6_t_asn_info,ip6_t_asn_equal,NULL,NULL);
    ht->stt_v4=hashmap_new(sizeof(struct ipv4_complex_info),0,0,0,hash_ipv4_complex_info,ipv4_equal,NULL,NULL);
    ht->stt_v6=hashmap_new(sizeof(struct ip6_t_complex_info),0,0,0,hash_ip6_t_complex_info,ip6_t_equal,NULL,NULL);
    ht->rc_sot_v4 = (rc_sot4 *)malloc(sizeof(rc_sot4));
    rc_sot4_init(ht->rc_sot_v4);
    ht->rc_sot_v6 = (rc_sot6 *)malloc(sizeof(rc_sot6));
    rc_sot6_init(ht->rc_sot_v6);
    ht->rc_stt_v4 = (rc_stt4 *)malloc(sizeof(rc_stt4));
    rc_stt4_init(ht->rc_stt_v4);
    ht->rc_stt_v6 = (rc_stt6 *)malloc(sizeof(rc_stt6));
    rc_stt6_init(ht->rc_stt_v6);
    ht->wide_tree_v4 = New_Patricia(32);
    ht->wide_tree_v6 = New_Patricia(128);
    ht->wide_array_v4_extra = (wideASN *)malloc(sizeof(wideASN));
    ht->wide_array_v6_extra = (wideASN *)malloc(sizeof(wideASN));
    wideASN_init(ht->wide_array_v4_extra);
    wideASN_init(ht->wide_array_v6_extra);
}

//update withdrawn cnt for pfxt_v4
int insert_withdrawn_cnt_v4(struct hrov_table_basic * pfxt, const struct hpdu_ipv4 *pdu, struct ipv4_asn_info * info){
    struct ipv4_asn k;
    memcpy(&k,&info->key,sizeof(struct ipv4_asn));
    int pos=0;
    if((info->bitmap&1) == 0){
        if((info->bitmap & pdu->Encoded_sub_tree)>0){
            info->bitmap |= 1;
            return rc_sot4_insert_new(pfxt->rc_sot_v4,k,info->bitmap,pdu->Encoded_sub_tree);      
        }
    }
    else{
        return rc_sot4_insert(pfxt->rc_sot_v4,k,pdu->Encoded_sub_tree);
    }
    return SUCCESS;
}

int insert_SOT_v4(struct hrov_table_basic * pfxt, const struct hpdu_ipv4 *pdu){
    struct ipv4_asn k;
    k.addr = pdu->sub_tree_identifier;
    k.asn = pdu->asn;
    struct ipv4_asn_info * info = find_ipv4_asn_info(pfxt->sot_v4,k);
    //not in hashmap before
    if(!info){
        insert_ipv4_asn_info(pfxt->sot_v4, k, pdu->Encoded_sub_tree);
        if(hashmap_oom(pfxt->sot_v4)) return ERROR;
    }
    else{
        //handle withdrawn cnt part
        if(insert_withdrawn_cnt_v4(pfxt,pdu,info)==ERROR) return ERROR;
        info->bitmap = pdu->Encoded_sub_tree|info->bitmap;
    }  
    return SUCCESS;
}

int insert_withdrawn_cnt_v4_agg(struct hrov_table_basic * pfxt, const struct hpdu_ipv4 *pdu, struct ipv4_complex_info *info_agg){
    ipv4 k_agg;
    k_agg = pdu->sub_tree_identifier;
    if(info_agg->bm.withdrawn_flag == 0){
        if((info_agg->bm.bitmap & pdu->Encoded_sub_tree)>0){
            info_agg->bm.withdrawn_flag = 1;
            return rc_stt4_insert_new(pfxt->rc_stt_v4,k_agg,info_agg->bm.bitmap,pdu->Encoded_sub_tree);
        }
    }
    else{
        return rc_stt4_insert(pfxt->rc_stt_v4,k_agg,pdu->Encoded_sub_tree);
    }
    return SUCCESS;
}

int insert_STT_v4(struct hrov_table_basic * pfxt, const struct hpdu_ipv4 *pdu){
    ipv4 k_agg;
    k_agg = pdu->sub_tree_identifier;
    struct ipv4_complex_info *info_agg = find_ipv4_complex_info(pfxt->stt_v4,k_agg);
    if(!info_agg){
        struct bmb b;
        set_bmb(b,pdu->Encoded_sub_tree,0,0);
        insert_ipv4_complex_info(pfxt->stt_v4, k_agg, b);
        if(hashmap_oom(pfxt->stt_v4)) return ERROR;
    }
    else{
        //set withdrawn cnt
        if(insert_withdrawn_cnt_v4_agg(pfxt,pdu,info_agg)==ERROR) return ERROR;
        info_agg->bm.bitmap = info_agg->bm.bitmap | pdu->Encoded_sub_tree;
    }
}

int set_wide_flag_v4(struct hrov_table_basic * pfxt, uint32_t id){
    ipv4 k_agg;
    k_agg = id;
    struct ipv4_complex_info *info_agg = find_ipv4_complex_info(pfxt->stt_v4,k_agg);
    if(!info_agg){
        struct bmb b;
        set_bmb(b,0,0,1);
        insert_ipv4_complex_info(pfxt->stt_v4, k_agg, b);
        if(hashmap_oom(pfxt->stt_v4)) return ERROR;
    }
    else{
        info_agg->bm.wideROA_flag=1;
    }
    return SUCCESS;
}

int hrov_pfx_add_v4_basic(struct hrov_table_basic * pfxt, const struct hpdu_ipv4 *pdu){
    //asn 0 dont need to add in SOT
    if(pdu->asn>0){
        if(insert_SOT_v4(pfxt,pdu)==ERROR) return ERROR;
    }
    if(insert_STT_v4(pfxt,pdu)==ERROR) return ERROR;
    return SUCCESS;
}

int insert_withdrawn_cnt_v6(struct hrov_table_basic * pfxt, const struct hpdu_ipv6 *ipv6, struct ip6_t_asn_info * info){
    struct ip6_t_asn k;
    memcpy(&k,&info->key,sizeof(struct ip6_t_asn));
    int pos=0;
    if((info->bitmap&1) == 0){
        if((info->bitmap & ipv6->Encoded_sub_tree)>0){
            info->bitmap |= 1;
            return rc_sot6_insert_new(pfxt->rc_sot_v6,k,info->bitmap,ipv6->Encoded_sub_tree);
        }
    }
    else{
        return rc_sot6_insert(pfxt->rc_sot_v6,k,ipv6->Encoded_sub_tree);
    }
    return SUCCESS;
}

int insert_SOT_v6(struct hrov_table_basic * pfxt, const struct hpdu_ipv6 *pdu){
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(uint32_t)*4);
    k.asn = pdu->asn;

    struct ip6_t_asn_info * info = find_ip6_t_asn_info(pfxt->sot_v6, k);
    if(!info){
        insert_ip6_t_asn_info(pfxt->sot_v6, k, pdu->Encoded_sub_tree);
        if(hashmap_oom(pfxt->sot_v6)) return ERROR;
    }
    else{
        //handle withdrawn cnt part
        if(insert_withdrawn_cnt_v6(pfxt,pdu,info)==ERROR) return ERROR;
        info->bitmap = pdu->Encoded_sub_tree|info->bitmap;
    }
    return SUCCESS;
}

int insert_withdrawn_cnt_v6_agg(struct hrov_table_basic * pfxt, const struct hpdu_ipv6 *pdu, struct ip6_t_complex_info *info_agg){
    struct ip6_t k_agg;
    memcpy(k_agg.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(uint32_t)*4);
    if(info_agg->bm.withdrawn_flag == 0){
        if((info_agg->bm.bitmap & pdu->Encoded_sub_tree)>0){
            info_agg->bm.withdrawn_flag = 1;
            return rc_stt6_insert_new(pfxt->rc_stt_v6,k_agg,info_agg->bm.bitmap,pdu->Encoded_sub_tree);
        }
    }
    else{
        return rc_stt6_insert(pfxt->rc_stt_v6,k_agg,pdu->Encoded_sub_tree);
    }
    return SUCCESS;
}

int insert_STT_v6(struct hrov_table_basic * pfxt, const struct hpdu_ipv6 *pdu){
    struct ip6_t identifier;
    memcpy(identifier.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(uint32_t)*4);
    struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(pfxt->stt_v6, identifier);
    if(!info_agg){
        struct bmb b;
        set_bmb(b,pdu->Encoded_sub_tree,0,0);
        insert_ip6_t_complex_info(pfxt->stt_v6, identifier, b);
        if(hashmap_oom(pfxt->stt_v6)) return ERROR;
    }
    else{
        //set withdrawn cnt
        if(insert_withdrawn_cnt_v6_agg(pfxt,pdu,info_agg)==ERROR) return ERROR;
        info_agg->bm.bitmap = info_agg->bm.bitmap | pdu->Encoded_sub_tree;
    }
}

int hrov_pfx_add_v6_basic(struct hrov_table_basic * pfxt, const struct hpdu_ipv6 *ipv6){
    if(ipv6->asn>0){
        if(insert_SOT_v6(pfxt,ipv6)==ERROR) return ERROR;
    }
    if(insert_STT_v6(pfxt,ipv6)==ERROR) return ERROR;
    return SUCCESS;
}


int bitmap_individer_v4_basic(struct hrov_table_basic *pfxt, uint32_t prefix, int masklen, int maxlen, uint32_t asn,int (*pfx_update)(struct hrov_table_basic *, const struct hpdu_ipv4 *)){
    if(masklen<=maxlen){
        //handle sub-tree header
        // puts("?");
        int hanging_level = get_hanging_level(masklen);
        int next_hanging_level = hanging_level + HANGING_LEVEL;
        uint32_t bitmap=calculate_bitmap(prefix,masklen,maxlen);
        uint32_t id = hanging_level==0?1:get_subtree_identifier_v4(prefix,hanging_level);
        // printf("%x\n",bitmap);
        struct hpdu_ipv4 pdu;
        set_hpdu_v4((&pdu),id,bitmap,asn);
        if(pfx_update(pfxt,&pdu)==ERROR) return ERROR;
        //handle sub-tree stub
        if(next_hanging_level<=maxlen){
            int total = (int)pow(2,(next_hanging_level-masklen));
            for(int i=0;i<total;i++){
                uint32_t tmp_prefix = prefix + (i<<(32-next_hanging_level));
                if(bitmap_individer_v4_basic(pfxt,tmp_prefix,next_hanging_level,maxlen,asn,pfx_update)==ERROR) return ERROR;
            }
        }
        return SUCCESS;
    }
    else{
        return ERROR;
    }
}


int bitmap_wide_v4_basic_add(struct hrov_table_basic *pfxt, uint32_t identifier, int masklen, int maxlen, uint32_t asn){
    bitmap_individer_v4_basic(pfxt,identifier,masklen,masklen,0,hrov_pfx_add_v4_basic);
    // puts("1");
    prefix_t lookupPrefix;
    lookupPrefix.family = AF_INET;
    lookupPrefix.bitlen = masklen;
    lookupPrefix.add.sin.s_addr = htonl(identifier);
    lookupPrefix.ref_count = 0;
    patricia_node_t* treeNode = NULL;
    treeNode = patricia_lookup(pfxt->wide_tree_v4,&lookupPrefix);
    if(treeNode == NULL){
        return ERROR;
    }
    if(!treeNode->data){
        node_data_t *nd = malloc(sizeof(node_data_t));
        nd->ary = NULL;
        nd->len = 0;
        treeNode->data = nd;
    }
    ROA *roa = malloc(sizeof(ROA));
    roa->asn = asn;
    roa->maxlen = maxlen;
    if(!append_elem((node_data_t *)treeNode->data,roa)) return ERROR;
    wideASN_insert(pfxt->wide_array_v4_extra,asn);
    return SUCCESS;
}


int bitmap_individer_v6_basic(struct hrov_table_basic *pfxt, uint32_t prefix[], int masklen, int maxlen, uint32_t asn,int (*pfx_update)(struct hrov_table_basic *, const struct hpdu_ipv6 *)){
    if(masklen<=maxlen){
        //handle identifier from masklen to next_hanging_level first
        int hanging_level = get_hanging_level(masklen);
        int next_hanging_level = hanging_level + HANGING_LEVEL;
        uint32_t identifier[4];
        get_subtree_identifier_v6(identifier, prefix, hanging_level);
        uint32_t bitmap = calculate_bitmap_v6(prefix,masklen,maxlen);
        struct hpdu_ipv6 pdu;
        set_hpdu_v6((&pdu),identifier,bitmap,asn);
        if(pfx_update(pfxt,&pdu)==ERROR) return ERROR;

        //handle sub-identifier in bitmap_individer
        if(next_hanging_level<=maxlen){
            int total = (int)pow(2,(next_hanging_level-masklen));
            int left_move_total = 128 - next_hanging_level;
            int index = 3 - left_move_total/UINT32_BITS;
            int left_move = left_move_total%UINT32_BITS;
            int threshold = (int)pow(2,(UINT32_BITS-left_move));
            for(int i=0;i<total;i++){
                uint32_t sub_prefix[4];
                memcpy(sub_prefix,prefix,sizeof(uint32_t)*4);
                sub_prefix[index] = sub_prefix[index] | (i << left_move);
                if(i>=threshold){
                    int top_i = i>>(UINT32_BITS-left_move);
                    sub_prefix[index-1] = sub_prefix[index-1]|top_i;
                }
                if(bitmap_individer_v6_basic(pfxt,sub_prefix,next_hanging_level,maxlen,asn,pfx_update)==ERROR) return ERROR;
            }
        }
    }
    return SUCCESS;
}


int set_wide_flag_v6(struct hrov_table_basic * pfxt, uint32_t id[]){
    struct ip6_t identifier;
    memcpy(identifier.u_ip6.u_ip6_addr32, id, sizeof(uint32_t)*4);
    struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(pfxt->stt_v6, identifier);
    if(!info_agg){
        struct bmb b;
        set_bmb(b,0,0,1);
        insert_ip6_t_complex_info(pfxt->stt_v6, identifier, b);
        if(hashmap_oom(pfxt->stt_v6)) return ERROR;
    }
    else{
        info_agg->bm.wideROA_flag=1;
    }
    return SUCCESS;
}


int bitmap_wide_v6_basic_add(struct hrov_table_basic *pfxt, uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    bitmap_individer_v6_basic(pfxt,pfx,masklen,masklen,0,hrov_pfx_add_v6_basic);
    prefix_t lookupPrefix;
    lookupPrefix.family = AF_INET6;
    lookupPrefix.bitlen = masklen;
    for(int i=0;i<4;i++){
        lookupPrefix.add.sin6.__in6_u.__u6_addr32[i] = htonl(pfx[i]);
    }
    lookupPrefix.ref_count = 0;
    patricia_node_t* treeNode = NULL;
    treeNode = patricia_lookup(pfxt->wide_tree_v6,&lookupPrefix);
    if(treeNode == NULL){
        return ERROR;
    }
    if(!treeNode->data){
        node_data_t *nd = malloc(sizeof(node_data_t));
        nd->ary = NULL;
        nd->len = 0;
        treeNode->data = nd;
    }
    ROA *roa = malloc(sizeof(ROA));
    roa->asn = asn;
    roa->maxlen = maxlen;
    if(!append_elem((node_data_t *)treeNode->data,roa)) return ERROR;
    wideASN_insert(pfxt->wide_array_v6_extra,asn);
    return SUCCESS;
}

int remove_entry_in_SOT_v4(struct hrov_table_basic * pfxt, const struct hpdu_ipv4 *ipv4){
    struct ipv4_asn k;
    k.addr = ipv4->sub_tree_identifier;
    k.asn = ipv4->asn;
    struct ipv4_asn_info * info = find_ipv4_asn_info(pfxt->sot_v4,k);
    if(info){
        if((info->bitmap&1)==0){
            info->bitmap = info->bitmap & (~ipv4->Encoded_sub_tree);
        }
        else{
            uint32_t tmp = info->bitmap;
            int flag = rc_sot4_remove(pfxt->rc_sot_v4,k,ipv4->Encoded_sub_tree,&tmp);
            if(flag==ERROR) return ERROR;
            info->bitmap=tmp;
            if(flag==ALLZERO){
                info->bitmap &= 0xfffffffe;
            }
        }
        if(info->bitmap==0){
            delete_ipv4_asn_info(pfxt->sot_v4,k);
        }
        return SUCCESS;
    }
    return ERROR;
}

int remove_with_withdrawn_cnt_v4_agg_basic(struct hrov_table_basic * pfxt, const struct hpdu_ipv4 *pdu){
    ipv4 k_agg;
    k_agg = pdu->sub_tree_identifier;
    struct ipv4_complex_info *info_agg = find_ipv4_complex_info(pfxt->stt_v4,k_agg);
    if(info_agg){
        if(info_agg->bm.withdrawn_flag){
            uint32_t tmp = info_agg->bm.bitmap;
            int flag = rc_stt4_remove(pfxt->rc_stt_v4,k_agg,pdu->Encoded_sub_tree,&tmp); 
            if(flag==ERROR) return ERROR;
            info_agg->bm.bitmap=tmp;
            if(flag==ALLZERO){
                info_agg->bm.withdrawn_flag=0;  
            }
        }
        else{
            info_agg->bm.bitmap = info_agg->bm.bitmap & (~pdu->Encoded_sub_tree);
        }
        if(info_agg->bm.bitmap==0&&info_agg->bm.wideROA_flag==0){
            delete_ipv4_complex_info(pfxt->stt_v4,k_agg);
        }
        return SUCCESS;
    }
    else{
        return ERROR;
    }
}

int hrov_pfx_rm_v4_basic(struct hrov_table_basic * pfxt, const struct hpdu_ipv4 *ipv4){
    if(ipv4->asn>0){
        if(remove_entry_in_SOT_v4(pfxt,ipv4)==ERROR) return ERROR;
    }
    if(remove_with_withdrawn_cnt_v4_agg_basic(pfxt,ipv4)==ERROR) return ERROR;
    return SUCCESS;
}

int remove_entry_in_SOT_v6(struct hrov_table_basic * pfxt, const struct hpdu_ipv6 *ipv6){
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32, ipv6->sub_tree_identifier, sizeof(k.addr));
    k.asn = ipv6->asn;
    struct ip6_t_asn_info * info = find_ip6_t_asn_info(pfxt->sot_v6,k);
    if(info){
        if((info->bitmap&1)==0){
            info->bitmap = info->bitmap & (~ipv6->Encoded_sub_tree);
        }
        else{
            uint32_t tmp = info->bitmap;
            int flag = rc_sot6_remove(pfxt->rc_sot_v6,k,ipv6->Encoded_sub_tree,&tmp);
            if(flag==ERROR) return ERROR;
            info->bitmap = tmp;
            if(flag==ALLZERO){
                info->bitmap &= 0xfffffffe;
            }
        }
        if(info->bitmap==0){
            delete_ip6_t_asn_info(pfxt->sot_v6,k);
        }
        return SUCCESS;
    }
    return ERROR;
}

int remove_with_withdrawn_cnt_v6_agg_basic(struct hrov_table_basic * pfxt, const struct hpdu_ipv6 *pdu){
    struct ip6_t identifier;
    memcpy(identifier.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(uint32_t)*4);
    struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(pfxt->stt_v6, identifier);
    if(info_agg){
        if(info_agg->bm.withdrawn_flag){
            uint32_t tmp = info_agg->bm.bitmap;
            int flag = rc_stt6_remove(pfxt->rc_stt_v6,identifier,pdu->Encoded_sub_tree,&tmp);
            if(flag==ERROR) return ERROR;
            info_agg->bm.bitmap=tmp;
            if(flag==ALLZERO){
                info_agg->bm.withdrawn_flag=0;
            }
        }
        else{
            info_agg->bm.bitmap = info_agg->bm.bitmap & (~pdu->Encoded_sub_tree);
        }
        if(info_agg->bm.bitmap==0&&info_agg->bm.wideROA_flag==0){
            delete_ip6_t_complex_info(pfxt->stt_v6,identifier);
        }
        return SUCCESS;
    }
    else{
        return ERROR;
    }
}

int hrov_pfx_rm_v6_basic(struct hrov_table_basic * pfxt, const struct hpdu_ipv6 *ipv6){
    if(ipv6->asn>0){
        if(remove_entry_in_SOT_v6(pfxt,ipv6)==ERROR) return ERROR;
    }
    if(remove_with_withdrawn_cnt_v6_agg_basic(pfxt,ipv6)==ERROR) return ERROR;
    return SUCCESS;
}


int bitmap_wide_v4_basic_rm(struct hrov_table_basic *pfxt, uint32_t identifier, int masklen, int maxlen, uint32_t asn){
    //rm to wide roa part
    int hanging_level = get_hanging_level(masklen);
    uint32_t id = get_subtree_identifier_v4(identifier,hanging_level);
    int flag;
    if(flag==WA_NULL){
        ipv4 wid;
        wid=id;
        struct ipv4_complex_info *info_agg = find_ipv4_complex_info(pfxt->stt_v4,wid);
        if(!info_agg) return ERROR;
        info_agg->bm.wideROA_flag=0;
        if(info_agg->bm.bitmap==0){
            delete_ipv4_complex_info(pfxt->stt_v4,wid);
        }
    }
    return SUCCESS;
}

int bitmap_wide_v6_basic_rm(struct hrov_table_basic *pfxt, uint32_t pfx[4], int masklen, int maxlen, uint32_t asn){
    //rm to wide roa part
    int hanging_level = get_hanging_level(masklen);
    uint32_t id[4];
    get_subtree_identifier_v6(id,pfx,hanging_level);
    int flag;
    struct ip6_t header;
    memcpy(header.u_ip6.u_ip6_addr32,id,sizeof(uint32_t)*4);
    struct ip6_t prefix;
    memcpy(prefix.u_ip6.u_ip6_addr32,pfx,sizeof(uint32_t)*4);
    if(flag==WA_NULL){
        struct ip6_t wideROA_identifier;
        memcpy(wideROA_identifier.u_ip6.u_ip6_addr32,id,sizeof(uint32_t)*4);
        struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(pfxt->stt_v6, wideROA_identifier);
        if(!info_agg) return ERROR;
        info_agg->bm.wideROA_flag=0;
        if(info_agg->bm.bitmap==0){
            delete_ip6_t_complex_info(pfxt->stt_v6,wideROA_identifier);
        }
    }
    return SUCCESS;
}

int hrov_pfx_add_basic(struct hrov_table_basic * pfxt, void * pdu)
{
    const int type = *((char *)pdu + 1);
    if(type == HROV_IPV4){
        const struct hpdu_ipv4 *ipv4 = (const struct hpdu_ipv4 *)pdu;
        return hrov_pfx_add_v4_basic(pfxt,ipv4);
    }
    else if (type == HROV_IPV6)
    {
        const struct hpdu_ipv6 *ipv6 = (const struct hpdu_ipv6 *)pdu;
        return hrov_pfx_add_v6_basic(pfxt,ipv6);
    }
    else if(type == TROA_IPV4)
    {
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        if(ipv4->asn==0){
            // puts("0");
            return bitmap_individer_v4_basic(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->prefix_len,ipv4->asn,hrov_pfx_add_v4_basic);
        }
        else if(ipv4->max_prefix_len - ipv4->prefix_len < pfxt->widelen_v4){
            // puts("1");
            return bitmap_individer_v4_basic(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn,hrov_pfx_add_v4_basic);
        }   
        else{
            // puts("2");
            return bitmap_wide_v4_basic_add(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn);
        }
    }
    else if(type == TROA_IPV6){
        struct pdu_ipv6 *ipv6 = (struct pdu_ipv6 *)pdu;
        if(ipv6->asn==0){
            return bitmap_individer_v6_basic(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->prefix_len,ipv6->asn,hrov_pfx_add_v6_basic);
        }
        else if(ipv6->max_prefix_len - ipv6->prefix_len < pfxt->widelen_v6){
            return bitmap_individer_v6_basic(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn,hrov_pfx_add_v6_basic);
        }
        else{
            return bitmap_wide_v6_basic_add(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn);
        }
    }
    else{
        return ERROR;
    }
    return SUCCESS;
}

int hrov_pfx_rm_basic(struct hrov_table_basic * pfxt, void *pdu){
    const int type = *((char *)pdu + 1);
    if(type==HROV_IPV4){
        const struct hpdu_ipv4 *ipv4 = (const struct hpdu_ipv4 *)pdu;
        return hrov_pfx_rm_v4_basic(pfxt,ipv4);
    }
    else if(type==HROV_IPV6){
        const struct hpdu_ipv6 *ipv6 = (const struct hpdu_ipv6 *)pdu;
        return hrov_pfx_rm_v6_basic(pfxt,ipv6);
    }
    else if(type==TROA_IPV4){
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        if(ipv4->asn==0){
            return bitmap_individer_v4_basic(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->prefix_len,ipv4->asn,hrov_pfx_rm_v4_basic);
        }else if(ipv4->max_prefix_len - ipv4->prefix_len < pfxt->widelen_v4){
            return bitmap_individer_v4_basic(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn,hrov_pfx_rm_v4_basic);
        }else{
            return bitmap_wide_v4_basic_rm(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn);
        }
    }   
    else if(type==TROA_IPV6){
        struct pdu_ipv6 *ipv6 = (struct pdu_ipv6 *)pdu;
        if(ipv6->asn==0){
            return bitmap_individer_v6_basic(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->prefix_len,ipv6->asn,hrov_pfx_rm_v6_basic);
        }
        else if(ipv6->max_prefix_len - ipv6->prefix_len < pfxt->widelen_v6){
            return bitmap_individer_v6_basic(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn,hrov_pfx_rm_v6_basic);
        }
        else{
            return bitmap_wide_v6_basic_rm(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn);
        }
    }
    else{
        return ERROR;
    }
    return SUCCESS;
}

void check_point_v4(struct hrov_table_basic * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, struct ipv4_complex_info *it_agg, int index, enum pfxv_state * res){
    enum pfxv_state res_sot=BGP_PFXV_STATE_NOT_FOUND,res_wide=BGP_PFXV_STATE_NOT_FOUND;
    if((it_agg->bm.bitmap&MASK_BASIC[index])>0){
        res_sot = BGP_PFXV_STATE_INVALID;
    }
    if(res_wide==BGP_PFXV_STATE_VALID){
        *res=BGP_PFXV_STATE_VALID;
    }
    else if((res_sot==BGP_PFXV_STATE_INVALID)||(res_wide==BGP_PFXV_STATE_INVALID)){
        *res=BGP_PFXV_STATE_INVALID;
    }
    return;
}

int hrov_pfx_validate_v4_wide_basic(struct hrov_table_basic * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id = hanging_level==0?1:get_subtree_identifier_v4(pfx->u.addr4.addr, hanging_level);
    struct ipv4_asn k;
    k.addr = sub_tree_id;
    k.asn = asn;

    ipv4 k_agg;
    k_agg = sub_tree_id;
    uint32_t index = 0;
    get_subtree_pos_v4_c(pfx->u.addr4.addr,hanging_level,masklen,&index);
    uint32_t mask = 1<<index; 

    struct ipv4_asn_info * it = find_ipv4_asn_info(ht->sot_v4,k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
    }
    else{
        struct ipv4_complex_info * it_agg; 
        while(hanging_level>=0){
            it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);
            if(it_agg){
                check_point_v4(ht,asn,pfx,masklen,it_agg,index,res);
                if(*res==BGP_PFXV_STATE_VALID) return SUCCESS;
            }
            hanging_level-=HANGING_LEVEL;
            r_move_v4(k_agg,k_agg,HANGING_LEVEL);
            get_subtree_pos_v4_c(pfx->u.addr4.addr, hanging_level, (hanging_level+HANGING_LEVEL-1), &index);
        }
    }
    return SUCCESS;
}

void check_point_v6(struct hrov_table_basic * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, struct ip6_t_complex_info *it_agg, int index, enum pfxv_state * res){
    enum pfxv_state res_sot=BGP_PFXV_STATE_NOT_FOUND,res_wide=BGP_PFXV_STATE_NOT_FOUND;
    if((it_agg->bm.bitmap&MASK[index])>0){
        res_sot = BGP_PFXV_STATE_INVALID;
    }
    if(res_wide==BGP_PFXV_STATE_VALID){
        *res=BGP_PFXV_STATE_VALID;
    }
    else if((res_sot==BGP_PFXV_STATE_INVALID)||(res_wide==BGP_PFXV_STATE_INVALID)){
        *res=BGP_PFXV_STATE_INVALID;
    }
    return;
}

int hrov_pfx_validate_v6_wide_basic(struct hrov_table_basic *ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id[4];
    get_subtree_identifier_v6(sub_tree_id, pfx->u.addr6.addr, hanging_level);
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    k.asn = asn;

    struct ip6_t k_agg;
    memcpy(k_agg.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    uint32_t index = 0;
    get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,masklen,index);
    uint32_t mask = 1<<index; 

    struct ip6_t_asn_info * it = find_ip6_t_asn_info(ht->sot_v6, k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
    }
    else{
        struct ip6_t_complex_info * it_agg; 
        while(hanging_level>=0){
            it_agg = find_ip6_t_complex_info(ht->stt_v6, k_agg);
            if(it_agg){
                check_point_v6(ht,asn,pfx,masklen,it_agg,index,res);
                if(*res==BGP_PFXV_STATE_VALID) return SUCCESS;
            }
            hanging_level-=HANGING_LEVEL;
            r_move_v6(k_agg.u_ip6.u_ip6_addr32,k_agg.u_ip6.u_ip6_addr32,HANGING_LEVEL);
            get_subtree_pos_v6(pfx->u.addr6.addr, hanging_level, (hanging_level+HANGING_LEVEL-1),index);
        }
    }
    return SUCCESS;
}

int hrov_pfx_validate_v4_basic(struct hrov_table_basic * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id = hanging_level==0?1:get_subtree_identifier_v4(pfx->u.addr4.addr, hanging_level);
    struct ipv4_asn k;
    k.addr = sub_tree_id;
    k.asn = asn;

    ipv4 k_agg;
    k_agg = sub_tree_id;
    uint32_t index = 0;
    get_subtree_pos_v4_c(pfx->u.addr4.addr,hanging_level,masklen,&index);
    uint32_t mask = 1<<index; 
    struct ipv4_asn_info * it = find_ipv4_asn_info(ht->sot_v4,k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
    if(hashmap_get(ht->wide_array_v4_extra->dyheader,&(wideASN_block){.asn=asn})!=NULL){
        patricia_node_t *treeNode = NULL;
        prefix_t lookupPrefix;
        lookupPrefix.family = AF_INET;
        lookupPrefix.bitlen = masklen;
        lookupPrefix.add.sin.s_addr = htonl(pfx->u.addr4.addr);
        lookupPrefix.ref_count = 0;
        treeNode = patricia_search_best(ht->wide_tree_v4,&lookupPrefix);
        if(treeNode){  
            while(treeNode){
                // printf("prefix %x\n",treeNode->prefix->add.sin.s_addr);
                node_data_t *roaListNode = (node_data_t *)treeNode->data;
                for(int i=0;i<roaListNode->len;i++){
                    ROA roa = roaListNode->ary[i];
                    // printf("%u\n",roa.asn);
                    if(asn==roa.asn&&lookupPrefix.bitlen<=roa.maxlen){
                        *res = BGP_PFXV_STATE_VALID;
                        return SUCCESS;
                    }
                }
                treeNode = getParent(treeNode);
            }
            *res = BGP_PFXV_STATE_INVALID;
            return SUCCESS;
        }
    }
    struct ipv4_complex_info * it_agg;  
    while(hanging_level>=0){
        it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);
        // if(it_agg) puts("1");
        if(it_agg&&((it_agg->bm.bitmap&MASK_BASIC[index])>0)){
            *res = BGP_PFXV_STATE_INVALID;
            return SUCCESS;
        }
        hanging_level-=HANGING_LEVEL;
        r_move_v4(k_agg,k_agg,HANGING_LEVEL);
        get_subtree_pos_v4_c(pfx->u.addr4.addr, hanging_level, (hanging_level+HANGING_LEVEL-1), &index);
    }     
    
    return SUCCESS;
}

int hrov_pfx_validate_v6_basic(struct hrov_table_basic *ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
   *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id[4];
    get_subtree_identifier_v6(sub_tree_id, pfx->u.addr6.addr, hanging_level);
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    k.asn = asn;

    struct ip6_t k_agg;
    memcpy(k_agg.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    uint32_t index = 0;
    get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,masklen,index);
    uint32_t mask = 1<<index; 

    struct ip6_t_asn_info * it = find_ip6_t_asn_info(ht->sot_v6, k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
    if(hashmap_get(ht->wide_array_v6_extra->dyheader,&(wideASN_block){.asn=asn})!=NULL){
        patricia_node_t *treeNode = NULL;
        prefix_t lookupPrefix;
        lookupPrefix.family = AF_INET6;
        lookupPrefix.bitlen = masklen;
        for(int i=0;i<4;i++){
            lookupPrefix.add.sin6.__in6_u.__u6_addr32[i] = htonl(pfx->u.addr6.addr[i]);
        }
        lookupPrefix.ref_count = 0;
        treeNode = patricia_search_best(ht->wide_tree_v6,&lookupPrefix);
        if(treeNode){  
            while(treeNode){
                node_data_t *roaListNode = (node_data_t *)treeNode->data;
                for(int i=0;i<roaListNode->len;i++){
                    ROA roa = roaListNode->ary[i];
                    if(asn==roa.asn&&lookupPrefix.bitlen<=roa.maxlen){
                        *res = BGP_PFXV_STATE_VALID;
                        return SUCCESS;
                    }
                }
                treeNode = getParent(treeNode);
            }
            *res = BGP_PFXV_STATE_INVALID;
            return SUCCESS;
        }
    }

    struct ip6_t_complex_info * it_agg;  
    while(hanging_level>=0){
        it_agg = find_ip6_t_complex_info(ht->stt_v6, k_agg);
        if(it_agg&&((it_agg->bm.bitmap&MASK_BASIC[index])>0)){
            *res = BGP_PFXV_STATE_INVALID;
            return SUCCESS;
        }
        hanging_level-=HANGING_LEVEL;
        r_move_v6(k_agg.u_ip6.u_ip6_addr32,k_agg.u_ip6.u_ip6_addr32,HANGING_LEVEL);
        get_subtree_pos_v6(pfx->u.addr6.addr, hanging_level, (hanging_level+HANGING_LEVEL-1),index);
    }     
   
    return SUCCESS;
}

int hrov_pfx_validate_basic(struct hrov_table_basic *ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    if(pfx->ver == LRTR_IPV4){ 
        return hrov_pfx_validate_v4_basic(ht,asn,pfx,masklen,res);
    }
    else{
        return hrov_pfx_validate_v6_basic(ht,asn,pfx,masklen,res);
    }
}

void hrov_memory_release_basic(struct hrov_table_basic *ht){
    hashmap_free(ht->stt_v4);
    hashmap_free(ht->stt_v6);
    hashmap_free(ht->sot_v4);
    hashmap_free(ht->sot_v6);
    hashmap_free(ht->rc_sot_v4->map);
    hashmap_free(ht->rc_sot_v6->map);
    hashmap_free(ht->rc_stt_v4->map);
    hashmap_free(ht->rc_stt_v6->map);
    
    // free(ht);
}



