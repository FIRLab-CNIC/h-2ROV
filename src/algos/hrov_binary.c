#include"hrov.h"
/**
 * | bitmap | authorization flag | wideROA flag | withdrawn flag |
 * | 31   1 |         0          | ..
 * 
*/

int set_child_flag_v4_binary(struct hrov_table_binary * ht, ipv4 p){
    struct ipv4_complex_info *info_agg = find_ipv4_complex_info(ht->stt_v4,p);
    if(!info_agg) return ERROR;
    struct ipv4_info *pchild = find_ipv4_info(ht->child_bitmap_v4,p);
    if(!pchild) return ERROR;
    uint32_t bm = pchild->bm;
    while(bm>0){
        int index = __builtin_ctz(bm);
        ipv4 k_agg;
        k_agg = (p << HANGING_LEVEL) + index;
        struct ipv4_complex_info *tmp = find_ipv4_complex_info(ht->stt_v4,k_agg);
        if(!tmp) return ERROR;

        int flag = tmp->bm.bitmap & 1;
        if((info_agg->bm.bitmap&1)==1){
            tmp->bm.bitmap = tmp->bm.bitmap|1;
        }
        else{
            int pos = 0;
            int bits = count_Bits_v4_c(tmp->key);
            int parent_hanging_level = bits - 1 - HANGING_LEVEL;
            get_position_v4_c(tmp->key, bits, parent_hanging_level-1, &pos);
            pos = pos |(1<<(HANGING_LEVEL-1));
            if((info_agg->bm.bitmap & MASK[pos])>0){
                tmp->bm.bitmap = tmp->bm.bitmap|1;
            }
            else{
                tmp->bm.bitmap = tmp->bm.bitmap&0xfffffffe;
            }
        }
        if((tmp->bm.bitmap & 1)!=flag){
            if(set_child_flag_v4_binary(ht,k_agg)==ERROR) return ERROR;
        }
        bm = bm &(~(1<<index));
    }
    return SUCCESS;
}

int set_child_wide_info_v4_binary(struct hrov_table_binary * ht, ipv4 p, uint32_t pfx, int masklen, int maxlen, uint32_t asn){
    struct ipv4_info *cinfo = find_ipv4_info(ht->child_bitmap_v4,p);
    if(!cinfo) return ERROR;
    uint32_t bm = cinfo->bm;
    while(bm>0){
        int index = __builtin_ctz(bm);
        ipv4 c_agg;
        c_agg = (p << HANGING_LEVEL) + index;
        struct ipv4_complex_info *tmp = find_ipv4_complex_info(ht->stt_v4,c_agg);
        if(!tmp) return ERROR;
        tmp->bm.wideROA_flag=1;
        if(wideArray_insert_v4(ht->wide_array_v4,c_agg,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
        if(set_child_wide_info_v4_binary(ht,c_agg,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
        bm = bm &(~(1<<index));
    }
    return SUCCESS;
}

int rm_child_wide_info_v4_binary(struct hrov_table_binary * ht, ipv4 p, uint32_t pfx, int masklen, int maxlen, uint32_t asn){;
    struct ipv4_info *cinfo = find_ipv4_info(ht->child_bitmap_v4,p);
    if(!cinfo) return ERROR;
    uint32_t bm = cinfo->bm;
    while(bm>0){
        int index = __builtin_ctz(bm);
        ipv4 c_agg;
        c_agg = (p<<HANGING_LEVEL)+index;
        if(rm_child_wide_info_v4_binary(ht,c_agg,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
        //delete its children's information
        int flag;
        if(wideArray_remove_v4(ht->wide_array_v4,c_agg,pfx,masklen,maxlen,asn,&flag)==ERROR) return ERROR;
        if(flag==WA_NULL){
            struct ipv4_complex_info *info_agg = find_ipv4_complex_info(ht->stt_v4,c_agg);
            if(!info_agg) return ERROR;
            info_agg->bm.wideROA_flag=0;
            cinfo = hashmap_get(ht->child_bitmap_v4, &(struct ipv4_info){.key = c_agg});
            if(!cinfo) return ERROR;
            if((info_agg->bm.bitmap==0||info_agg->bm.bitmap==1)&&(cinfo->bm==0)){
                delete_ipv4_complex_info(ht->stt_v4,c_agg);
                delete_ipv4_info(ht->child_bitmap_v4,c_agg);
                struct ipv4_info * pinfo_agg = find_ipv4_info(ht->child_bitmap_v4,p);
                if(pinfo_agg){
                    uint32_t mask = 0xffffffff - (1<<index);
                    pinfo_agg->bm=pinfo_agg->bm&mask;
                }
            }
        }   
        bm = bm &(~(1<<index));
    }
    return SUCCESS;
}

int rm_child_wide_info_v6_binary(struct hrov_table_binary * ht, struct ip6_t self_identifier, const uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    struct ip6_t prefix;
    memcpy(prefix.u_ip6.u_ip6_addr32,pfx,sizeof(uint32_t)*4);
    struct ip6_t_info *child_info = find_ip6_t_info(ht->child_bitmap_v6,self_identifier);
    if(!child_info) return ERROR;
    uint32_t bm = child_info->bm;
    while(bm>0){
        int index = __builtin_ctz(bm);
        struct ip6_t child_identifier;
        l_move_v6(self_identifier.u_ip6.u_ip6_addr32,child_identifier.u_ip6.u_ip6_addr32,HANGING_LEVEL);
        child_identifier.u_ip6.u_ip6_addr32[3] = child_identifier.u_ip6.u_ip6_addr32[3]+index;
        if(rm_child_wide_info_v6_binary(ht,child_identifier,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
        //delete its children's information
        int flag;
        if(wideArray_remove_v6(ht->wide_array_v6,child_identifier,prefix,masklen,maxlen,asn,&flag)==ERROR) return ERROR;
        if(flag==WA_NULL){
            struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(ht->stt_v6, child_identifier);
            if(!info_agg) return ERROR;
            info_agg->bm.wideROA_flag=0;
            child_info = find_ip6_t_info(ht->child_bitmap_v6, child_identifier);
            if(!child_info) return ERROR;
            if((info_agg->bm.bitmap==0||info_agg->bm.bitmap==1)&&(child_info->bm==0)){
                hashmap_delete(ht->stt_v6,&(struct ip6_t_complex_info){.key = child_identifier});
                hashmap_delete(ht->child_bitmap_v6,&(struct ip6_t_info){.key = child_identifier});
                struct ip6_t_info * pinfo_agg = find_ip6_t_info(ht->child_bitmap_v6, self_identifier);
                if(pinfo_agg){
                    uint32_t mask = 0xffffffff - (1<<index);
                    pinfo_agg->bm=pinfo_agg->bm&mask;
                }
            }
        }   
        bm = bm &(~(1<<index));
    }
    return SUCCESS;
}


int set_child_wide_info_v6_binary(struct hrov_table_binary * ht, struct ip6_t self_identifier, uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    struct ip6_t_info *child_info = find_ip6_t_info(ht->child_bitmap_v6,self_identifier);
    if(!child_info) return ERROR;
    uint32_t bm = child_info->bm;
    while(bm>0){
        int index = __builtin_ctz(bm);
        struct ip6_t child_identifier;
        l_move_v6(self_identifier.u_ip6.u_ip6_addr32,child_identifier.u_ip6.u_ip6_addr32,HANGING_LEVEL);
        child_identifier.u_ip6.u_ip6_addr32[3] = child_identifier.u_ip6.u_ip6_addr32[3]+index;  
        struct ip6_t_complex_info *tmp = find_ip6_t_complex_info(ht->stt_v6, child_identifier);
        if(!tmp) return ERROR;
        tmp->bm.wideROA_flag=1;
        // wide_table_v6_binary_add(ht,c_agg.addr,pfx,masklen,maxlen,asn);
        struct ip6_t prefix;
        memcpy(prefix.u_ip6.u_ip6_addr32,pfx,sizeof(uint32_t)*4);
        if(wideArray_insert_v6(ht->wide_array_v6,child_identifier,prefix,masklen,maxlen,asn)==ERROR) return ERROR;
        if(set_child_wide_info_v6_binary(ht,child_identifier,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
        bm = bm &(~(1<<index));
    }
    return SUCCESS;
}

int set_child_flag_v6_binary(struct hrov_table_binary * ht, struct ip6_t self_identifier){
    struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(ht->stt_v6, self_identifier);
    if(!info_agg) return ERROR;
    struct ip6_t_info * child_info;
    child_info = hashmap_get(ht->child_bitmap_v6, &(struct ip6_t_info){.key = self_identifier});
    if(!child_info) return ERROR;
    uint32_t bm = child_info->bm;
    while(bm>0){
        int index = __builtin_ctz(bm);
        struct ip6_t child_identifier;
        l_move_v6(self_identifier.u_ip6.u_ip6_addr32,child_identifier.u_ip6.u_ip6_addr32,HANGING_LEVEL);
        child_identifier.u_ip6.u_ip6_addr32[3] =  child_identifier.u_ip6.u_ip6_addr32[3] + index;
        struct ip6_t_complex_info *tmpx = find_ip6_t_complex_info(ht->stt_v6, child_identifier);
        if(!tmpx) return ERROR;
        int flag = tmpx->bm.bitmap & 1;
        if((info_agg->bm.bitmap&1)==1){
            tmpx->bm.bitmap = tmpx->bm.bitmap|1;
        }
        else{
            int bits = 0;
            count_Bits_v6_c(tmpx->key.u_ip6.u_ip6_addr32, &bits);
            int parent_hanging_level = bits - 1 - HANGING_LEVEL;
            int pos = get_position_v6_c(tmpx->key.u_ip6.u_ip6_addr32, bits, parent_hanging_level-1);
            pos = pos |(1<<(HANGING_LEVEL-1));
            if((info_agg->bm.bitmap & MASK[pos])>0){
                tmpx->bm.bitmap = tmpx->bm.bitmap|1;
            }
            else{
                tmpx->bm.bitmap = tmpx->bm.bitmap&0xfffffffe;
            }
        }
        if((tmpx->bm.bitmap & 1)!=flag){
            if(set_child_flag_v6_binary(ht,child_identifier)==ERROR) return ERROR;
        } 
        bm = bm &(~(1<<index));
    }
    return SUCCESS;
}

void hrov_pfxt_init_binary(struct hrov_table_binary *ht){
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
    ht->child_bitmap_v4=hashmap_new(sizeof(struct ipv4_info),0,0,0,hash_ipv4_info,ipv4_equal,NULL,NULL);
    ht->child_bitmap_v6=hashmap_new(sizeof(struct ip6_t_info),0,0,0, hash_ip6_t_info,ip6_t_equal,NULL,NULL);
    ht->wide_array_v6=(wideArray6 *)malloc(sizeof(wideArray6));
    wideArray_init_v6(ht->wide_array_v6);
    ht->wide_array_v4=(wideArray4 *)malloc(sizeof(wideArray4));
    wideArray_init_v4(ht->wide_array_v4);
    ht->backtracking=0;
    ht->backtrack_time=0;
}

//update withdrawn cnt for pfxt_v4
int insert_withdrawn_cnt_v4_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv4 *ipv4, struct ipv4_asn_info * info){
    struct ipv4_asn k;
    memcpy(&k,&info->key,sizeof(struct ipv4_asn));
    int pos=0;
    if((info->bitmap&1) == 0){
        if((info->bitmap & ipv4->Encoded_sub_tree)>0){
            info->bitmap |= 1;
            return rc_sot4_insert_new(pfxt->rc_sot_v4,k,info->bitmap,ipv4->Encoded_sub_tree);  
        }
    }
    else{
        return rc_sot4_insert(pfxt->rc_sot_v4,k,ipv4->Encoded_sub_tree);
    }
    return SUCCESS;
}

//insert ipv4 pdu into SOT with withdrawn cnt
int insert_SOT_v4_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv4 *ipv4){
    struct ipv4_asn k;
    k.addr = ipv4->sub_tree_identifier;
    k.asn = ipv4->asn;
    struct ipv4_asn_info * info = find_ipv4_asn_info(pfxt->sot_v4,k);
    if(!info){
        insert_ipv4_asn_info(pfxt->sot_v4, k, ipv4->Encoded_sub_tree);
        if(hashmap_oom(pfxt->sot_v4)) return ERROR;
    }
    else{
        //handle withdrawn cnt part
        if(insert_withdrawn_cnt_v4_binary(pfxt,ipv4,info)==ERROR) return ERROR;
        info->bitmap = ipv4->Encoded_sub_tree|info->bitmap;
    }
    return SUCCESS;
}

int handle_parent_v4(struct hrov_table_binary *pfxt,struct ipv4_complex_info pinfo_list[V4PATH],int pl_index,ipv4 identifier){
    ipv4 k_agg;
    k_agg = identifier;
    ipv4 tmp_agg;
    tmp_agg = identifier;
    ipv4 parent_k_agg;
    r_move_v4(identifier, parent_k_agg, HANGING_LEVEL);
    int bits = count_Bits_v4_c(k_agg);
    int parent_hanging_level = bits - 1 - HANGING_LEVEL;

    while(parent_hanging_level>=0){
        struct ipv4_complex_info * pinfo = find_ipv4_complex_info(pfxt->stt_v4,parent_k_agg);
        if(pinfo){ 
            int pos = 0;
            get_position_v4_c(k_agg, bits, parent_hanging_level-1, &pos);
            pos = pos |(1<<(HANGING_LEVEL-1));
            if((pinfo->bm.bitmap & MASK[pos])>0){
                for(int i=0;i<pl_index;i++){
                    pinfo_list[i].bm.bitmap |= 1;
                }
            }
            
            if(pinfo->bm.wideROA_flag){
                ipv4 parent_header;
                parent_header = parent_k_agg;
                for(int i=0;i<pl_index;i++){
                    ipv4 child_header;
                    child_header = pinfo_list[i].key;
                    if(wideArray_copy_v4(pfxt->wide_array_v4,parent_header,child_header)==ERROR) return ERROR;
                    pinfo_list[i].bm.wideROA_flag=1;
                }
            }              
            int index = tmp_agg & ((1 << HANGING_LEVEL) - 1);
            uint32_t child_bitmap = 1<<index;
            struct ipv4_info *pinfo;
            pinfo = hashmap_get(pfxt->child_bitmap_v4,&(struct ipv4_info){.key=parent_k_agg});
            if(pinfo){
                pinfo->bm = pinfo->bm | child_bitmap;
            }
            else{
                insert_ipv4_info(pfxt->child_bitmap_v4,parent_k_agg,child_bitmap);
                if(hashmap_oom(pfxt->child_bitmap_v4)) return ERROR;
            }
            break;
        }
        //insert parent_addr to STT, add parent_k_agg to ip_addr_agg_v4_info list
        struct ipv4_complex_info ptmp;
        ptmp.key = parent_k_agg;
        set_bmb(ptmp.bm,0,0,0);
        pinfo_list[pl_index++]=ptmp;

        int index = tmp_agg & ((1 << HANGING_LEVEL) - 1);
        uint32_t child_bitmap = 1<<index;
        insert_ipv4_info(pfxt->child_bitmap_v4,parent_k_agg,child_bitmap);
        if(hashmap_oom(pfxt->child_bitmap_v4)) return ERROR;
        r_move_v4(tmp_agg,tmp_agg,HANGING_LEVEL);

        r_move_v4(parent_k_agg,parent_k_agg,HANGING_LEVEL);
        parent_hanging_level-=HANGING_LEVEL;
    }     

    for(int i = 0;i<pl_index;i++){
        insert_ipv4_complex_info(pfxt->stt_v4,pinfo_list[i].key,pinfo_list[i].bm);
        if(hashmap_oom(pfxt->stt_v4)) return ERROR;
    }            
    return SUCCESS;
}

int insert_STT_with_parent_v4_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv4 *pdu){
    ipv4 k_agg;
    k_agg = pdu->sub_tree_identifier;
    //pinfo_list中存放的是STT中不存在的identifier
    int len = V4PATH;
    struct ipv4_complex_info pinfo_list[len];
    int pl_index=0;
    pinfo_list[0].key = k_agg;
    set_bmb(pinfo_list[0].bm,pdu->Encoded_sub_tree,0,0);
    pl_index++;
    //把自己先插入到child bitmap中
    insert_ipv4_info(pfxt->child_bitmap_v4,k_agg,0);
    if(hashmap_oom(pfxt->child_bitmap_v4)) return ERROR;
    //向上寻找祖先
    ipv4 identifier;
    identifier = pdu->sub_tree_identifier;
    if(handle_parent_v4(pfxt,pinfo_list,pl_index,identifier)==ERROR) return ERROR;
    return SUCCESS;
}


int insert_withdrawn_cnt_v4_agg_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv4 *pdu, struct ipv4_complex_info * info_agg){
    ipv4 k_agg;
    k_agg = pdu->sub_tree_identifier;
    int pos=0;
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

int insert_STT_v4_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv4 *pdu){
    ipv4 k_agg;
    k_agg = pdu->sub_tree_identifier;
    struct ipv4_complex_info * info_agg = find_ipv4_complex_info(pfxt->stt_v4,k_agg);
    if(!info_agg){
        if(insert_STT_with_parent_v4_binary(pfxt,pdu)==ERROR) return ERROR;     
    }
    else{
        if(insert_withdrawn_cnt_v4_agg_binary(pfxt,pdu,info_agg)==ERROR) return ERROR;
        info_agg->bm.bitmap = pdu->Encoded_sub_tree|info_agg->bm.bitmap; 
        if(set_child_flag_v4_binary(pfxt,k_agg)==ERROR) return ERROR;
    }
    return SUCCESS;
}


int hrov_pfx_add_v4_normal_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv4 *ipv4){
    if(ipv4->asn>0){
        if(insert_SOT_v4_binary(pfxt,ipv4)==ERROR) return ERROR;
    }
    if(insert_STT_v4_binary(pfxt,ipv4)==ERROR) return ERROR;
}

int insert_STT_with_wide_n_parent_v4_binary(struct hrov_table_binary *pfxt,uint32_t pfx, int masklen, int maxlen, uint32_t asn){
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id = get_subtree_identifier_v4(pfx, hanging_level);
    ipv4 k_agg = sub_tree_id;
    
    //pinfo_list中存放的是STT中不存在的identifier
    int len = V4PATH;
    struct ipv4_complex_info pinfo_list[len];
    int pl_index=0;
    //设置自己的wideROA flag为1
    pinfo_list[0].key=k_agg;
    set_bmb(pinfo_list[0].bm,0,0,1);
    pl_index++;
    insert_ipv4_info(pfxt->child_bitmap_v4,k_agg,0);
    if(hashmap_oom(pfxt->child_bitmap_v4)) return ERROR;
    //向上寻找祖先
    ipv4 identifier;
    identifier=sub_tree_id;
    if(handle_parent_v4(pfxt,pinfo_list,pl_index,identifier)==ERROR) return ERROR;
    return SUCCESS;
}

int hrov_pfx_add_v4_wide_binary(struct hrov_table_binary *pfxt, uint32_t pfx, int masklen, int maxlen, uint32_t asn){
    int hanging_level = get_hanging_level(masklen);
    uint32_t id =get_subtree_identifier_v4(pfx,hanging_level);
    ipv4 k_agg = id;

    if(wideArray_insert_v4(pfxt->wide_array_v4,id,pfx,masklen,maxlen,asn)==ERROR) return ERROR;

    struct ipv4_complex_info * info_agg = find_ipv4_complex_info(pfxt->stt_v4,k_agg);
    if(!info_agg){
        if(insert_STT_with_wide_n_parent_v4_binary(pfxt,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
    }
    else{
        info_agg->bm.wideROA_flag = 1;
        if(set_child_wide_info_v4_binary(pfxt,k_agg,pfx,masklen,maxlen,asn)==ERROR) return ERROR;     
    }
    return SUCCESS;
}

int insert_withdrawn_cnt_v6_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv6 *ipv6, struct ip6_t_asn_info * info){
    struct ip6_t_asn k;
    memcpy(&k, &info->key, sizeof(struct ip6_t_asn));
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

int insert_SOT_v6_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv6 *ipv6){
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32, ipv6->sub_tree_identifier, sizeof(k.addr));
    k.asn = ipv6->asn;
    struct ip6_t_asn_info * info = find_ip6_t_asn_info(pfxt->sot_v6, k);
    if(!info){
        insert_ip6_t_asn_info(pfxt->sot_v6, k, ipv6->Encoded_sub_tree);
        if(hashmap_oom(pfxt->sot_v6)) return ERROR;
    }
    else{
        if(insert_withdrawn_cnt_v6_binary(pfxt,ipv6,info)==ERROR) return ERROR;
        info->bitmap = ipv6->Encoded_sub_tree|info->bitmap;
    }
    return SUCCESS;
}

int insert_withdrawn_cnt_v6_agg_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv6 *pdu, struct ip6_t_complex_info * info_agg){
    struct ip6_t identifier;
    memcpy(identifier.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(struct ip6_t));
    int pos=0;
    if(info_agg->bm.withdrawn_flag == 0){
        if((info_agg->bm.bitmap & pdu->Encoded_sub_tree)>0){
            info_agg->bm.withdrawn_flag = 1;
            return rc_stt6_insert_new(pfxt->rc_stt_v6,identifier,info_agg->bm.bitmap,pdu->Encoded_sub_tree);
        }
    }
    else{
        return rc_stt6_insert(pfxt->rc_stt_v6,identifier,pdu->Encoded_sub_tree);
    }
    return SUCCESS;
}

int handle_parent_v6(struct hrov_table_binary *pfxt,struct ip6_t_complex_info pinfo_list[V6PATH],int pl_index,struct ip6_t identifier){
    struct ip6_t tmp_identifier;
    memcpy(tmp_identifier.u_ip6.u_ip6_addr32, identifier.u_ip6.u_ip6_addr32, sizeof(uint32_t)*4);
    struct ip6_t parent_identifier;
    r_move_v6(identifier.u_ip6.u_ip6_addr32,parent_identifier.u_ip6.u_ip6_addr32,HANGING_LEVEL);
    int bits = 0;
    count_Bits_v6_c(identifier.u_ip6.u_ip6_addr32,&bits);
    int parent_hanging_level = bits - 1 - HANGING_LEVEL;

    while(parent_hanging_level>=0){          
        struct ip6_t_complex_info * pinfo = find_ip6_t_complex_info(pfxt->stt_v6, parent_identifier);
        if(pinfo){ 
            int pos = get_position_v6_c(identifier.u_ip6.u_ip6_addr32, bits, parent_hanging_level-1);
            pos = pos |(1<<(HANGING_LEVEL-1));
            if((pinfo->bm.bitmap & MASK[pos])>0){
                for(int i=0;i<pl_index;i++){
                    pinfo_list[i].bm.bitmap |= 1;
                }
            }  
            if(pinfo->bm.wideROA_flag){
                struct ip6_t parent_header;
                memcpy(parent_header.u_ip6.u_ip6_addr32,parent_identifier.u_ip6.u_ip6_addr32,sizeof(uint32_t)*4);
                for(int i=0;i<pl_index;i++){
                    struct ip6_t child_header;
                    memcpy(child_header.u_ip6.u_ip6_addr32,pinfo_list[i].key.u_ip6.u_ip6_addr32,sizeof(uint32_t)*4);
                    if(wideArray_copy_v6(pfxt->wide_array_v6,parent_header,child_header)==ERROR) return ERROR;
                    pinfo_list[i].bm.wideROA_flag=1;
                }
               
            } 
            int index = tmp_identifier.u_ip6.u_ip6_addr32[3] & ((1 << HANGING_LEVEL) - 1);
            uint32_t child_bitmap = 1<<index;
            struct ip6_t_info * pinfo;
            pinfo = hashmap_get(pfxt->child_bitmap_v6, &(struct ip6_t_info){.key = parent_identifier});
            if(pinfo){
                pinfo->bm = child_bitmap | pinfo->bm;
            }
            else{
                insert_ip6_t_info(pfxt->child_bitmap_v6,parent_identifier,child_bitmap);
                if(hashmap_oom(pfxt->child_bitmap_v6)) return ERROR;
            }
            break;
        }
        struct ip6_t_complex_info ptmp;
        memcpy(ptmp.key.u_ip6.u_ip6_addr32,parent_identifier.u_ip6.u_ip6_addr32,sizeof(uint32_t)*4);
        set_bmb(ptmp.bm,0,0,0);
        pinfo_list[pl_index++]=ptmp;

        int index = tmp_identifier.u_ip6.u_ip6_addr32[3] & ((1 << HANGING_LEVEL) - 1);
        uint32_t child_bitmap = 1<<index;
        insert_ip6_t_info(pfxt->child_bitmap_v6,parent_identifier,child_bitmap);
        if(hashmap_oom(pfxt->child_bitmap_v6)) return ERROR;
        r_move_v6(tmp_identifier.u_ip6.u_ip6_addr32,tmp_identifier.u_ip6.u_ip6_addr32,HANGING_LEVEL);

        r_move_v6(parent_identifier.u_ip6.u_ip6_addr32,parent_identifier.u_ip6.u_ip6_addr32,HANGING_LEVEL);
        parent_hanging_level-=HANGING_LEVEL;
    }
    
    //将不在STT中的祖先插入到STT中
    for(int i=0;i<pl_index;i++){
        insert_ip6_t_complex_info(pfxt->stt_v6,pinfo_list[i].key,pinfo_list[i].bm);
        if(hashmap_oom(pfxt->stt_v6)) return ERROR;
    }
    return SUCCESS;
}

int insert_STT_with_parent_v6_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv6 *pdu){
    struct ip6_t identifier;
    memcpy(identifier.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(uint32_t)*4); 
    //pinfo_list中存放的是STT中不存在的identifier
    int len = V6PATH;
    struct ip6_t_complex_info pinfo_list[len];
    int pl_index=0;
    memcpy(pinfo_list[0].key.u_ip6.u_ip6_addr32, identifier.u_ip6.u_ip6_addr32, sizeof(uint32_t)*4);
    set_bmb(pinfo_list[0].bm,pdu->Encoded_sub_tree,0,0);
    pl_index++;
    //把自己先插入到child bitmap中
    insert_ip6_t_info(pfxt->child_bitmap_v6,identifier,0);
    if(hashmap_oom(pfxt->child_bitmap_v6)) return ERROR;
    //向上寻找祖先
    if(handle_parent_v6(pfxt,pinfo_list,pl_index,identifier)==ERROR) return ERROR;
    return SUCCESS;
}

int insert_STT_v6_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv6 *pdu){
    struct ip6_t identifier;
    memcpy(identifier.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(uint32_t)*4);
    struct ip6_t_complex_info * info_agg = find_ip6_t_complex_info(pfxt->stt_v6, identifier);
    if(!info_agg){
        if(insert_STT_with_parent_v6_binary(pfxt,pdu)==ERROR) return ERROR;     
    }
    else{
        if(insert_withdrawn_cnt_v6_agg_binary(pfxt,pdu,info_agg)==ERROR) return ERROR;
        info_agg->bm.bitmap = pdu->Encoded_sub_tree|info_agg->bm.bitmap; 
        if(set_child_flag_v6_binary(pfxt,identifier)==ERROR) return ERROR;
    }
    return SUCCESS;
}

int hrov_pfx_add_v6_normal_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv6 *pdu){
    if(pdu->asn>0){
        if(insert_SOT_v6_binary(pfxt,pdu)==ERROR) return ERROR;
    }
    if(insert_STT_v6_binary(pfxt,pdu)==ERROR) return ERROR;
}

int bitmap_individer_v4_binary(struct hrov_table_binary *pfxt, uint32_t prefix, int masklen, int maxlen, uint32_t asn,int (*pfx_update)(struct hrov_table_binary *, const struct hpdu_ipv4 *)){
    if(masklen<=maxlen){
        //handle sub-tree header
        int hanging_level = get_hanging_level(masklen);
        int next_hanging_level = hanging_level + HANGING_LEVEL;
        uint32_t bitmap=calculate_bitmap(prefix,masklen,maxlen);
        uint32_t id = hanging_level==0?1:get_subtree_identifier_v4(prefix,hanging_level);
        struct hpdu_ipv4 pdu;
        set_hpdu_v4((&pdu),id,bitmap,asn);
        if(pfx_update(pfxt,&pdu)==ERROR) return ERROR;
        //handle sub-tree stub
        if(next_hanging_level<=maxlen){
            int total = (int)pow(2,(next_hanging_level-masklen));
            for(int i=0;i<total;i++){
                uint32_t tmp_prefix = prefix + (i<<(32-next_hanging_level));
                if(bitmap_individer_v4_binary(pfxt,tmp_prefix,next_hanging_level,maxlen,asn,pfx_update)==ERROR) return ERROR;
            }
        }
    
    }
    return SUCCESS;
}

int bitmap_individer_v6_binary(struct hrov_table_binary *pfxt, uint32_t prefix[], int masklen, int maxlen, uint32_t asn,int (*pfx_update)(struct hrov_table_binary *, const struct hpdu_ipv6 *)){
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
                if(bitmap_individer_v6_binary(pfxt,sub_prefix,next_hanging_level,maxlen,asn,pfx_update)==ERROR) return ERROR;
            }
        }
        }
    }
    return SUCCESS;
}

int insert_STT_with_wide_n_parent_v6_binary(struct hrov_table_binary *pfxt,uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id[4];
    get_subtree_identifier_v6(sub_tree_id, pfx, hanging_level);
    struct ip6_t identifier;
    memcpy(identifier.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    
    //pinfo_list中存放的是STT中不存在的identifier
    int len = V6PATH;
    struct ip6_t_complex_info pinfo_list[len];
    int pl_index=0;
    //设置自己的wideROA flag为1
    memcpy(pinfo_list[0].key.u_ip6.u_ip6_addr32, identifier.u_ip6.u_ip6_addr32, sizeof(uint32_t)*4);
    set_bmb(pinfo_list[0].bm,0,0,1);
    pl_index++;
    insert_ip6_t_info(pfxt->child_bitmap_v6,identifier,0);
    if(hashmap_oom(pfxt->child_bitmap_v6)) return ERROR;
    //向上寻找祖先
    if(handle_parent_v6(pfxt,pinfo_list,pl_index,identifier)==ERROR) return ERROR;
    return SUCCESS;
}

int bitmap_wide_v6_binary_add(struct hrov_table_binary *pfxt, uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    //STT
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id[4];
    get_subtree_identifier_v6(sub_tree_id, pfx, hanging_level);

    struct ip6_t header;
    memcpy(header.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    struct ip6_t prefix;
    memcpy(prefix.u_ip6.u_ip6_addr32,pfx,sizeof(uint32_t)*4);
    if(wideArray_insert_v6(pfxt->wide_array_v6,header,prefix,masklen,maxlen,asn)==ERROR) return ERROR;
    struct ip6_t_complex_info * info_agg = find_ip6_t_complex_info(pfxt->stt_v6, header);
    if(!info_agg){
        if(insert_STT_with_wide_n_parent_v6_binary(pfxt,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
    }
    else{
        info_agg->bm.wideROA_flag=1;
        if(set_child_wide_info_v6_binary(pfxt,header,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
    }    
    return SUCCESS;
}


int hrov_pfx_add_binary(struct hrov_table_binary * pfxt, void * pdu){
    const int type = *((char *)pdu + 1);
    if(type==HROV_IPV4){
        const struct hpdu_ipv4 *ipv4 = (const struct hpdu_ipv4 *)pdu;
        return hrov_pfx_add_v4_normal_binary(pfxt,ipv4);
    }
    else if (type==HROV_IPV6)
    {
        const struct hpdu_ipv6 *ipv6 = (const struct hpdu_ipv6 *)pdu;
        return hrov_pfx_add_v6_normal_binary(pfxt,ipv6);
    }
    else if(type == TROA_IPV4)
    {
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        if(ipv4->asn==0){
            // puts("0");
            return bitmap_individer_v4_binary(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->prefix_len,ipv4->asn,hrov_pfx_add_v4_normal_binary);
        }
        else if(ipv4->max_prefix_len - ipv4->prefix_len < WIDE_LEN_v4){
            // puts("1");
            return bitmap_individer_v4_binary(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn,hrov_pfx_add_v4_normal_binary);
        }   
        else{
            return hrov_pfx_add_v4_wide_binary(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn);
        }
    }
    else if(type == TROA_IPV6){
        struct pdu_ipv6 *ipv6 = (struct pdu_ipv6 *)pdu;
        if(ipv6->asn==0){
            return bitmap_individer_v6_binary(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->prefix_len,ipv6->asn,hrov_pfx_add_v6_normal_binary);
        }
        else if(ipv6->max_prefix_len - ipv6->prefix_len < WIDE_LEN_v6){
            return bitmap_individer_v6_binary(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn,hrov_pfx_add_v6_normal_binary);
        }
        else{
            return bitmap_wide_v6_binary_add(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn);
        }
    }
    else{
        return ERROR;
    }
    return SUCCESS;
}

int remove_entry_in_SOT_v4_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv4 *ipv4){
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
            hashmap_delete(pfxt->sot_v4,&(struct ipv4_asn_info){.key = k});
        }
        return SUCCESS;
    }
    return ERROR;
}

int remove_with_withdrawn_cnt_v4_agg_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv4 *pdu){
    ipv4 k_agg = pdu->sub_tree_identifier;
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
        return SUCCESS;
    }
    else{
        return ERROR;
    }
}

int remove_with_parent_v4_binary(struct hrov_table_binary * pfxt,ipv4 k_agg){
    struct ipv4_info * child_info;
    child_info = hashmap_get(pfxt->child_bitmap_v4, &(struct ipv4_info){.key = k_agg});
    if(!child_info) return ERROR;
    uint32_t bm = child_info->bm;
    if(bm==0){
        struct ipv4_complex_info *info_agg = find_ipv4_complex_info(pfxt->stt_v4,k_agg);
        if(!info_agg) return ERROR;
        uint32_t dest_bitmap = info_agg->bm.bitmap;
        int flag = info_agg->bm.wideROA_flag;
        if((dest_bitmap==0||dest_bitmap==1)&&flag==0){
            ipv4 parent_k_agg;
            r_move_v4(k_agg,parent_k_agg,HANGING_LEVEL);
            struct ipv4_info * pinfo_agg;
            pinfo_agg = hashmap_get(pfxt->child_bitmap_v4, &(struct ipv4_info){.key = parent_k_agg});
            if(pinfo_agg){
                int index = k_agg & ((1 << HANGING_LEVEL) - 1);
                uint32_t mask = 0xffffffff - (1<<index);
                pinfo_agg->bm=pinfo_agg->bm&mask;
                if(remove_with_parent_v4_binary(pfxt,parent_k_agg)==ERROR) return ERROR;        
            }
            hashmap_delete(pfxt->stt_v4,&(struct ipv4_complex_info){.key = k_agg});
            hashmap_delete(pfxt->child_bitmap_v4,&(struct ipv4_info){.key = k_agg}); 
        }
    }
    return SUCCESS;
}

int hrov_pfx_rm_v4_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv4 *pdu){
    //delete in SOT if asn != 0
    if(pdu->asn>0){
        if(remove_entry_in_SOT_v4_binary(pfxt,pdu)==ERROR) return ERROR;
    }
    ipv4 k_agg = pdu->sub_tree_identifier;
    //update STT value with withdrawn cnt
    if(remove_with_withdrawn_cnt_v4_agg_binary(pfxt,pdu)==ERROR) return ERROR;
    //update children's authorization-flag value
    if(set_child_flag_v4_binary(pfxt,k_agg)==ERROR) return ERROR;
    //delete with its parents when it should be deleted
    if(remove_with_parent_v4_binary(pfxt,k_agg)==ERROR) return ERROR; 
    return SUCCESS;
}

int remove_entry_in_SOT_v6_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv6 *ipv6){
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32, ipv6->sub_tree_identifier, sizeof(uint32_t)*4);
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
            info->bitmap=tmp;
            if(flag==ALLZERO){
                info->bitmap &= 0xfffffffe;
            }
        }
        if(info->bitmap==0){
            hashmap_delete(pfxt->sot_v6,&(struct ip6_t_asn_info){.key = k});
        }
        return SUCCESS;
    }
    return ERROR;
}

//handle withdrawn cnt for STT in removing function
int remove_with_withdrawn_cnt_v6_agg_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv6 *pdu){
    struct ip6_t identifier;
    memcpy(identifier.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(struct ip6_t));
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
        return SUCCESS;
    }
    else{
        return ERROR;
    }
}

int remove_with_parent_v6_binary(struct hrov_table_binary * pfxt,struct ip6_t identifier){
    struct ip6_t_info * child_info;
    child_info = hashmap_get(pfxt->child_bitmap_v6, &(struct ip6_t_info){.key = identifier});
    if(!child_info) return ERROR;
    uint32_t bm = child_info->bm;
    if(bm==0){
        struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(pfxt->stt_v6, identifier);
        if(!info_agg) return ERROR;
        uint32_t dest_bitmap = info_agg->bm.bitmap;
        int flag = info_agg->bm.wideROA_flag;
        if((dest_bitmap==0||dest_bitmap==1)&&flag==0){
            struct ip6_t parent_identifier;
            r_move_v6(identifier.u_ip6.u_ip6_addr32,parent_identifier.u_ip6.u_ip6_addr32,HANGING_LEVEL);
            struct ip6_t_info * pinfo_agg;
            pinfo_agg = hashmap_get(pfxt->child_bitmap_v6, &(struct ip6_t_info){.key = parent_identifier});
            if(pinfo_agg){
                int index = identifier.u_ip6.u_ip6_addr32[3] & ((1 << HANGING_LEVEL) - 1);
                uint32_t mask = 0xffffffff - (1<<index);
                pinfo_agg->bm=pinfo_agg->bm&mask;
                if(remove_with_parent_v6_binary(pfxt,parent_identifier)==ERROR) return ERROR;        
            }
            hashmap_delete(pfxt->stt_v6,&(struct ip6_t_complex_info){.key = identifier});
            hashmap_delete(pfxt->child_bitmap_v6,&(struct ip6_t_info){.key = identifier}); 
        }
    }
    return SUCCESS;
}

int hrov_pfx_rm_v6_binary(struct hrov_table_binary * pfxt, const struct hpdu_ipv6 *pdu){
    //delete in SOT if asn != 0
    if(pdu->asn>0){
       if(remove_entry_in_SOT_v6_binary(pfxt,pdu)==ERROR) return ERROR;
    }
    struct ip6_t identifier;
    memcpy(identifier.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(struct ip6_t));
    //update STT value with withdrawn cnt
    if(remove_with_withdrawn_cnt_v6_agg_binary(pfxt,pdu)==ERROR) return ERROR;
    //update children's authorization-flag value
    if(set_child_flag_v6_binary(pfxt,identifier)==ERROR) return ERROR;
    //delete with its parents when it should be deleted
    if(remove_with_parent_v6_binary(pfxt,identifier)==ERROR) return ERROR; 
    return SUCCESS;
}

int bitmap_wide_v4_binary_rm(struct hrov_table_binary *pfxt, uint32_t pfx, int masklen, int maxlen, uint32_t asn){
    ipv4 p;
    int hanging_level = get_hanging_level(masklen);
    p=get_subtree_identifier_v4(pfx, hanging_level);
    //delete for children
    if(rm_child_wide_info_v4_binary(pfxt,p,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
    //delete for itself
    int flag=0;
    if(wideArray_remove_v4(pfxt->wide_array_v4,p,pfx,masklen,maxlen,asn,&flag)==ERROR) return ERROR;
    if(flag==WA_NULL){
        struct ipv4_complex_info *info_agg = find_ipv4_complex_info(pfxt->stt_v4,p);
        info_agg->bm.wideROA_flag=0;
     }
    //delete its parents
    if(remove_with_parent_v4_binary(pfxt,p)==ERROR) return ERROR; 
    return SUCCESS;
}

int bitmap_wide_v6_binary_rm(struct hrov_table_binary *pfxt, uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    struct ip6_t identifier;
    int hanging_level = get_hanging_level(masklen);
    get_subtree_identifier_v6(identifier.u_ip6.u_ip6_addr32, pfx, hanging_level);
    //delete for children
    if(rm_child_wide_info_v6_binary(pfxt,identifier,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
    //delete for itself
    int flag=0;
    struct ip6_t prefix;
    memcpy(prefix.u_ip6.u_ip6_addr32,pfx,sizeof(uint32_t)*4);
    if(wideArray_remove_v6(pfxt->wide_array_v6,identifier,prefix,masklen,maxlen,asn,&flag)==ERROR) return ERROR;
    if(flag==WA_NULL){
        struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(pfxt->stt_v6, identifier);
        if(!info_agg) return ERROR;
        info_agg->bm.wideROA_flag=0;
     }
    //delete its parents
    if(remove_with_parent_v6_binary(pfxt,identifier)==ERROR) return ERROR; 
    return SUCCESS;
}

int hrov_pfx_rm_binary(struct hrov_table_binary * pfxt, void *pdu){
    const int type = *((char *)pdu + 1);
    if(type==HROV_IPV4){
        const struct hpdu_ipv4 *ipv4 = (const struct hpdu_ipv4 *)pdu;
        hrov_pfx_rm_v4_binary(pfxt,ipv4);
    }
    else if(type==HROV_IPV6){
        const struct hpdu_ipv6 *ipv6 = (const struct hpdu_ipv6 *)pdu;
        hrov_pfx_rm_v6_binary(pfxt,ipv6);
    }
    else if(type==TROA_IPV4){
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        if(ipv4->asn==0){
            bitmap_individer_v4_binary(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->prefix_len,ipv4->asn,hrov_pfx_rm_v4_binary);
        }else if(ipv4->max_prefix_len - ipv4->prefix_len < WIDE_LEN_v4){
            bitmap_individer_v4_binary(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn,hrov_pfx_rm_v4_binary);
        }else{
            bitmap_wide_v4_binary_rm(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn);
        }
    }   
    else if(type==TROA_IPV6){
        struct pdu_ipv6 *ipv6 = (struct pdu_ipv6 *)pdu;
        if(ipv6->asn==0){
            bitmap_individer_v6_binary(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->prefix_len,ipv6->asn,hrov_pfx_rm_v6_binary);
        }
        else if(ipv6->max_prefix_len - ipv6->prefix_len < WIDE_LEN_v6){
            bitmap_individer_v6_binary(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn,hrov_pfx_rm_v6_binary);
        }
        else{
            bitmap_wide_v6_binary_rm(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn);
        }
    }
    else{
        return ERROR;
    }
    return SUCCESS;
}

struct ipv4_complex_info* find_stt_cnt_v4(struct hrov_table_binary * ht,ipv4 k_agg){
    double f = 0;
    struct ipv4_complex_info *it_agg = hashmap_get_cnt(ht->stt_v4, &(struct ipv4_complex_info){.key=k_agg},&f);
    ht->backtrack_time += f;
    return it_agg;
}

int hrov_pfx_validate_v4_binary(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id = get_subtree_identifier_v4(pfx->u.addr4.addr,hanging_level);
    struct ipv4_asn k;
    k.addr = sub_tree_id;
    k.asn = asn;
    ipv4 k_agg = sub_tree_id;
    uint32_t index = 0;
    get_subtree_pos_v4_c(pfx->u.addr4.addr,hanging_level,masklen,&index);
    uint32_t mask = 1<<index; 
    struct ipv4_asn_info * it = find_ipv4_asn_info(ht->sot_v4,k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
    else{
        // struct ipv4_complex_info *it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);
        struct ipv4_complex_info *it_agg = find_stt_cnt_v4(ht,k_agg);
        ht->backtracking++;
        if(it_agg){
            if((it_agg->bm.bitmap&MASK[index])>0){
                *res = BGP_PFXV_STATE_INVALID;
            }    
            return SUCCESS;
        }
        else{
            int left=0, right=hanging_level;
            int mid = (left+right)/2;
            int hanging_level_mid = mid - mid%HANGING_LEVEL;
            ipv4 tmp_agg;
            int minilen = 0;
            while(left<=right){
                tmp_agg = k_agg>>(hanging_level - hanging_level_mid);
                // it_agg = find_ipv4_complex_info(ht->stt_v4,tmp_agg);
                it_agg = find_stt_cnt_v4(ht,tmp_agg);
                ht->backtracking++;
                minilen = min_t((hanging_level_mid+HANGING_LEVEL-1),masklen);
                get_subtree_pos_v4_c(pfx->u.addr4.addr, hanging_level_mid, minilen, &index);
                if(!it_agg){
                    right = hanging_level_mid - HANGING_LEVEL;
                }
                else if((it_agg->bm.bitmap&MASK[index])>0){
                    *res = BGP_PFXV_STATE_INVALID;
                    return SUCCESS;
                }
                else{
                    left = hanging_level_mid + HANGING_LEVEL; 
                }
                mid = (left+right)/2;
                hanging_level_mid = mid - mid%HANGING_LEVEL;   
            }
            return SUCCESS; 
        }
    }
    return SUCCESS;
}

int hrov_pfx_validate_v4_direct(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id = get_subtree_identifier_v4(pfx->u.addr4.addr,hanging_level);
    struct ipv4_asn k;
    k.addr = sub_tree_id;
    k.asn = asn;
    ipv4 k_agg = sub_tree_id;

    uint32_t index = 0;
    get_subtree_pos_v4_c(pfx->u.addr4.addr,hanging_level,masklen,&index);
    uint32_t mask = 1<<index; 
    struct ipv4_asn_info * it = find_ipv4_asn_info(ht->sot_v4,k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
   
    struct ipv4_complex_info * it_agg; 
    while(hanging_level>=0){
        it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);
        if(it_agg){
            if((it_agg->bm.bitmap&MASK[index])>0){
                *res = BGP_PFXV_STATE_INVALID;
            }
            return SUCCESS;
        }
        hanging_level-=HANGING_LEVEL;
        r_move_v4(k_agg,k_agg,HANGING_LEVEL);
        get_subtree_pos_v4_c(pfx->u.addr4.addr, hanging_level, (hanging_level+HANGING_LEVEL-1), &index);
    }
    return SUCCESS;
}

struct ip6_t_complex_info* find_stt_cnt_v6(struct hrov_table_binary * ht,struct ip6_t k_agg){
    double f = 0;
    struct ip6_t_complex_info *it_agg = hashmap_get_cnt(ht->stt_v6, &(struct ip6_t_complex_info){.key=k_agg},&f);
    ht->backtrack_time += f;
    return it_agg;
}

int hrov_pfx_validate_v6_binary(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id[4];
    get_subtree_identifier_v6(sub_tree_id, pfx->u.addr6.addr, hanging_level);
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    k.asn = asn;
    struct ip6_t k_agg;
    memcpy(&k_agg.u_ip6.u_ip6_addr32,&sub_tree_id,sizeof(uint32_t)*4);
    
    uint32_t index = 0;
    get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,masklen,index);
    uint32_t mask = 1<<index;
    struct ip6_t_asn_info * it = find_ip6_t_asn_info(ht->sot_v6, k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
    }
    else{  
        struct ip6_t_complex_info *it_agg = find_ip6_t_complex_info(ht->stt_v6, k_agg);
        // struct ipv6_complex_info *it_agg = find_stt_cnt_v6(ht,k_agg);
        ht->backtracking++;
        if(it_agg){
            if((it_agg->bm.bitmap & MASK[index])>0){
                *res = BGP_PFXV_STATE_INVALID;
            }
        } else{
            int left=0, right=hanging_level;
            int mid = (left+right)/2;
            int hanging_level_mid = mid-mid%HANGING_LEVEL;
            struct ip6_t tmp_agg;
            int minilen = 0;
            
            while(left<=right){
                r_move_v6(k_agg.u_ip6.u_ip6_addr32,tmp_agg.u_ip6.u_ip6_addr32,(hanging_level - hanging_level_mid));
                it_agg = find_ip6_t_complex_info(ht->stt_v6, tmp_agg);
                // it_agg = find_stt_cnt_v6(ht, tmp_agg);
                ht->backtracking++;
                minilen = min_t((hanging_level_mid+HANGING_LEVEL-1),masklen);
                get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level_mid,minilen,index);
                if(!it_agg){
                    right = hanging_level_mid - HANGING_LEVEL;
                }
                else if((it_agg->bm.bitmap&MASK[index])>0){
                    *res = BGP_PFXV_STATE_INVALID;
                    break;
                }
                else{
                    left = hanging_level_mid + HANGING_LEVEL; 
                }
                mid = (left+right)/2;
                hanging_level_mid = mid - mid%HANGING_LEVEL; 
            }
            // FILE *f = fopen("./backupv6_binary.txt","a");
            // fprintf(f,"%d %d %d\n",hanging_level_mid,hanging_level,times);
            // fclose(f);
        }
    }
    return SUCCESS;
}

int hrov_pfx_validate_v6_direct(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id[4];
    get_subtree_identifier_v6(sub_tree_id, pfx->u.addr6.addr, hanging_level);
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    k.asn = asn;
    struct ip6_t k_agg;
    memcpy(&k_agg.u_ip6.u_ip6_addr32,&sub_tree_id,sizeof(uint32_t)*4);
    
    uint32_t index = 0;
    get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,masklen,index);
    uint32_t mask = 1<<index;
    struct ip6_t_asn_info * it = find_ip6_t_asn_info(ht->sot_v6, k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
    }
    else{
        struct ip6_t_complex_info *it_agg;
        while(hanging_level>=0){
            it_agg = find_ip6_t_complex_info(ht->stt_v6, k_agg);
            ht->backtracking++;
            if(it_agg){
                if((it_agg->bm.bitmap&MASK[index])>0){
                    *res = BGP_PFXV_STATE_INVALID;
                }
                break;
            }
            hanging_level -= HANGING_LEVEL;
            r_move_v6(k_agg.u_ip6.u_ip6_addr32,k_agg.u_ip6.u_ip6_addr32,HANGING_LEVEL);
            get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,(hanging_level+4),index);
        }
    }
    return SUCCESS;
}

void check_point_v4_binary(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, struct ipv4_complex_info *it_agg, int index, enum pfxv_state * res){
    enum pfxv_state res_sot=BGP_PFXV_STATE_NOT_FOUND,res_wide=BGP_PFXV_STATE_NOT_FOUND;
    if((it_agg->bm.bitmap&MASK[index])>0){
        res_sot = BGP_PFXV_STATE_INVALID;
    }
    if(it_agg->bm.wideROA_flag){
        wideArray_validate_v4(ht->wide_array_v4,it_agg->key,pfx->u.addr4.addr,masklen,asn,&res_wide);
    }
    if(res_wide==BGP_PFXV_STATE_VALID){
        *res=BGP_PFXV_STATE_VALID;
    }
    else if((res_sot==BGP_PFXV_STATE_INVALID)||(res_wide==BGP_PFXV_STATE_INVALID)){
        *res=BGP_PFXV_STATE_INVALID;
    }
    else{
        *res=BGP_PFXV_STATE_NOT_FOUND;
    }
    return;
}

void check_point_v6_binary(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, struct ip6_t_complex_info *it_agg, int index, enum pfxv_state * res){
    enum pfxv_state res_sot=BGP_PFXV_STATE_NOT_FOUND,res_wide=BGP_PFXV_STATE_NOT_FOUND;
    if((it_agg->bm.bitmap&MASK[index])>0){
        res_sot = BGP_PFXV_STATE_INVALID;
    }
    if(it_agg->bm.wideROA_flag){
        struct ip6_t prefix;
        memcpy(prefix.u_ip6.u_ip6_addr32,pfx->u.addr6.addr,sizeof(uint32_t)*4);
        wideArray_validate_v6(ht->wide_array_v6,it_agg->key,prefix,masklen,asn,&res_wide);
    }
    if(res_wide==BGP_PFXV_STATE_VALID){
        *res=BGP_PFXV_STATE_VALID;
    }
    else if((res_sot==BGP_PFXV_STATE_INVALID)||(res_wide==BGP_PFXV_STATE_INVALID)){
        *res=BGP_PFXV_STATE_INVALID;
    }
    else{
        *res=BGP_PFXV_STATE_NOT_FOUND;
    }
    return;
}

int hrov_pfx_validate_v4_wide_binary(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id = get_subtree_identifier_v4(pfx->u.addr4.addr,hanging_level);
    struct ipv4_asn k;
    k.addr = sub_tree_id;
    k.asn = asn;
    ipv4 k_agg = sub_tree_id;

    uint32_t index = 0;
    get_subtree_pos_v4_c(pfx->u.addr4.addr,hanging_level,masklen,&index);
    uint32_t mask = 1<<index; 
    struct ipv4_asn_info * it = find_ipv4_asn_info(ht->sot_v4,k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
    struct ipv4_complex_info *it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);
    // it_agg = hashmap_get_with_hashvalue(ht->pfxt_v4_agg,&(struct ip_addr_agg_v4_info_bmb){.key = k_agg},&hash); 
    if(it_agg){
        check_point_v4_binary(ht,asn,pfx,masklen,it_agg,index,res);
    }
    else{
        int left=0, right=hanging_level;
        int mid = (left+right)/2;
        int hanging_level_mid = mid - mid%HANGING_LEVEL;
        ipv4 tmp_agg;
        int minilen = 0;
        *res = BGP_PFXV_STATE_NOT_FOUND;
        while(left<right){
            r_move_v4(k_agg,tmp_agg,(hanging_level - hanging_level_mid));
            it_agg = find_ipv4_complex_info(ht->stt_v4,tmp_agg);
            if(!it_agg){
                right = hanging_level_mid;
            }
            else{
                left = hanging_level_mid + HANGING_LEVEL;
            }
            mid = (left+right)/2;
            hanging_level_mid = mid - mid%HANGING_LEVEL;
        }
        if(right>0){
            r_move_v4(k_agg,tmp_agg,(hanging_level - hanging_level_mid + HANGING_LEVEL));
            it_agg = find_ipv4_complex_info(ht->stt_v4,tmp_agg);
            get_subtree_pos_v4_c(pfx->u.addr4.addr,(hanging_level_mid - HANGING_LEVEL),(hanging_level_mid- HANGING_LEVEL+4),&index);
            check_point_v4_binary(ht,asn,pfx,masklen,it_agg,index,res);
        }
    }
    return SUCCESS;
}

int hrov_pfx_validate_v4_wide_direct(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id = get_subtree_identifier_v4(pfx->u.addr4.addr, hanging_level);
    struct ipv4_asn k;
    k.addr = sub_tree_id;
    k.asn = asn;
    ipv4 k_agg = sub_tree_id;

    uint32_t index = 0;
    get_subtree_pos_v4_c(pfx->u.addr4.addr,hanging_level,masklen,&index);
    uint32_t mask = 1<<index; 
    struct ipv4_asn_info * it = find_ipv4_asn_info(ht->sot_v4,k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
   
    struct ipv4_complex_info * it_agg; 
    size_t map_i=0;
    while(hanging_level>=0){
        it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);
        if(it_agg){
            check_point_v4_binary(ht,asn,pfx,masklen,it_agg,index,res);
            return SUCCESS;
        }
        hanging_level-=HANGING_LEVEL;
        r_move_v4(k_agg,k_agg,HANGING_LEVEL);
        get_subtree_pos_v4_c(pfx->u.addr4.addr, hanging_level, (hanging_level+4), &index);
    }
    
    return SUCCESS;
}

int hrov_pfx_validate_v6_wide_binary(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id[4];
    get_subtree_identifier_v6(sub_tree_id, pfx->u.addr6.addr, hanging_level);
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    k.asn = asn;
    struct ip6_t k_agg;
    memcpy(&k_agg.u_ip6.u_ip6_addr32,&sub_tree_id,sizeof(uint32_t)*4);

    uint32_t index = 0;
    get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,masklen,index);
    uint32_t mask = 1<<index;
    struct ip6_t_asn_info * it = find_ip6_t_asn_info(ht->sot_v6, k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
    struct ip6_t_complex_info *it_agg = find_ip6_t_complex_info(ht->stt_v6, k_agg);
    // uint64_t hash = hashmap_murmur(&k_agg, sizeof(struct ip_addr_agg_v6), 0, 0)<< 16 >> 16;
    // it_agg = hashmap_get_with_hashvalue(ht->pfxt_v6_agg, &(struct ip_addr_agg_v6_info_bmb){.key = k_agg}, &hash);
    if(it_agg){
        check_point_v6_binary(ht,asn,pfx,masklen,it_agg,index,res);
    }
    else{
        int left=0, right=hanging_level;
        int mid = (left+right)/2;
        int hanging_level_mid = mid - mid%HANGING_LEVEL;
        struct ip6_t tmp_agg;
        int minilen = 0;
        *res = BGP_PFXV_STATE_NOT_FOUND;
        int times = 0;
        while(left<right){
            r_move_v6(k_agg.u_ip6.u_ip6_addr32,tmp_agg.u_ip6.u_ip6_addr32,(hanging_level - hanging_level_mid));
            it_agg = find_ip6_t_complex_info(ht->stt_v6, tmp_agg);
            times++;
            if(!it_agg){
                right = hanging_level_mid;
            }
            else{
                left = hanging_level_mid + HANGING_LEVEL;
            }
            mid = (left+right)/2;
            hanging_level_mid = mid - mid%HANGING_LEVEL;
        }
        if(right>0){
            r_move_v6(k_agg.u_ip6.u_ip6_addr32,tmp_agg.u_ip6.u_ip6_addr32,(hanging_level - hanging_level_mid + HANGING_LEVEL));
            it_agg = find_ip6_t_complex_info(ht->stt_v6, tmp_agg);
            times++;
            // it_agg = hashmap_get_with_hashvalue(ht->pfxt_v6_agg, &(struct ip_addr_agg_v6_info_bmb){.key = tmp_agg}, &hasht);  
            get_subtree_pos_v6(pfx->u.addr6.addr,(hanging_level_mid-HANGING_LEVEL),(hanging_level_mid- HANGING_LEVEL+4),index);
            check_point_v6_binary(ht,asn,pfx,masklen,it_agg,index,res);
        }
        if(*res==BGP_PFXV_STATE_NOT_FOUND){
            FILE *f = fopen("./backup.txt","a");
            fprintf(f,"%d %d %d\n",hanging_level_mid-HANGING_LEVEL,masklen,times);
            fclose(f);
        }
    }
    return SUCCESS;
}

int hrov_pfx_validate_v6_wide_direct(struct hrov_table_binary * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id[4];
    get_subtree_identifier_v6(sub_tree_id, pfx->u.addr6.addr, hanging_level);
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32,sub_tree_id,sizeof(uint32_t)*4);
    k.asn = asn;
    struct ip6_t k_agg;
    memcpy(&k_agg.u_ip6.u_ip6_addr32,&sub_tree_id,sizeof(uint32_t)*4);

    uint32_t index = 0;
    get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,masklen,index);
    uint32_t mask = 1<<index;
    struct ip6_t_asn_info * it = find_ip6_t_asn_info(ht->sot_v6, k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
    struct ip6_t_complex_info *it_agg;
    while(hanging_level>=0){
        it_agg = find_ip6_t_complex_info(ht->stt_v6, k_agg);
        if(it_agg){
            check_point_v6_binary(ht,asn,pfx,masklen,it_agg,index,res);
            return SUCCESS;
        }
        hanging_level-=HANGING_LEVEL;
        r_move_v6(k_agg.u_ip6.u_ip6_addr32,k_agg.u_ip6.u_ip6_addr32,HANGING_LEVEL);
        get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,(hanging_level+4),index);
    }
    return SUCCESS;
}

int hrov_pfx_validate_binary(struct hrov_table_binary *ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    if(pfx->ver == LRTR_IPV4){
        if(hashmap_count(ht->wide_array_v4->dyheader)>0){
            return hrov_pfx_validate_v4_wide_binary(ht,asn,pfx,masklen,res);
        }
        else{
            return hrov_pfx_validate_v4_binary(ht,asn,pfx,masklen,res);
        }
    }
    else{
        if(hashmap_count(ht->wide_array_v6->dyheader)>0){
            return hrov_pfx_validate_v6_wide_binary(ht,asn,pfx,masklen,res);
        }
        else{
            // if(masklen<35){
            //     return hrov_pfx_validate_v6_direct(ht,asn,pfx,masklen,res);
            // }
            // else{
            //     return hrov_pfx_validate_v6_binary(ht,asn,pfx,masklen,res);
            // }
            return hrov_pfx_validate_v6_binary(ht,asn,pfx,masklen,res);
        }
    }
}

void hrov_memory_release_binary(struct hrov_table_binary *ht){
    hashmap_free(ht->stt_v4);
    hashmap_free(ht->stt_v6);
    hashmap_free(ht->sot_v4);
    hashmap_free(ht->sot_v6);
    hashmap_free(ht->rc_sot_v4->map);
    hashmap_free(ht->rc_sot_v6->map);
    hashmap_free(ht->rc_stt_v4->map);
    hashmap_free(ht->rc_stt_v6->map);
    hashmap_free(ht->child_bitmap_v4);
    hashmap_free(ht->child_bitmap_v6);
    wideArray_free_v4(ht->wide_array_v4);
    wideArray_free_v6(ht->wide_array_v6);
    free(ht);
    return;
}
