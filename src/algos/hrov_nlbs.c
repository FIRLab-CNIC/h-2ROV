#include "hrov.h"
#define LEVEL 40
#define MIDLEVEL 25
#define BINARY 1
//todo : find faster ipv4 hash function; pre-computing some values

int set_child_flag_v6_nlbs(struct hrov_table_nlbs * ht, struct ip6_t p){
    struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(ht->stt_v6, p);
    if(!info_agg) return ERROR;
    struct ip6_t_info * pinfo;
    pinfo = hashmap_get(ht->child_bitmap_v6, &(struct ip6_t_info){.key = p});
    if(!pinfo) return ERROR;
    uint32_t bm = pinfo->bm;
    // printf("%x\n",bm);
    while(bm>0){
        int index = __builtin_ctz(bm);
        struct ip6_t k_agg;
        l_move_v6(p.u_ip6.u_ip6_addr32,k_agg.u_ip6.u_ip6_addr32,HANGING_LEVEL);
        k_agg.u_ip6.u_ip6_addr32[3] =  k_agg.u_ip6.u_ip6_addr32[3] + index;
        struct ip6_t_complex_info *tmpx = find_ip6_t_complex_info(ht->stt_v6, k_agg);
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
            if(set_child_flag_v6_nlbs(ht,k_agg)==ERROR) return ERROR;
        } 
        bm = bm &(~(1<<index));
    }
    return SUCCESS;
}


void hrov_pfxt_init_nlbs(struct hrov_table_nlbs *ht){
    ht->widelen_v4 = 8;
    ht->widelen_v6 = 7;
    ht->hashtime = 0;
    ht->sot_check = 0;
    ht->patricia_check = 0;
    ht->patricia_check_success = 0;
    ht->sot_v4=hashmap_new(sizeof(struct ipv4_asn_info),0,0,0,hash_ipv4_asn_info,ipv4_asn_equal,NULL,NULL);
    ht->sot_v6=hashmap_new(sizeof(struct ip6_t_asn_info),0,0,0,hash_ip6_t_asn_info,ip6_t_asn_equal,NULL,NULL);
    ht->stt_v4=hashmap_new(sizeof(struct ipv4_complex_info),0,0,0,hash_ipv4_complex_info,ipv4_equal,NULL,NULL);
    ht->stt_v6=hashmap_new(sizeof(struct ip6_t_complex_info),0,0,0,hash_ip6_t_complex_info,ip6_t_equal,NULL,NULL);
    ht->leaflevel_v6=hashmap_new(sizeof(struct ip6_t_leafnode_level),0,0,0,hash_ip6_t_leafnode_level,ip6_t_equal,NULL,NULL);
    ht->midlevel_v6=hashmap_new(sizeof(struct ip6_t_leafnode_level),0,0,0,hash_ip6_t_leafnode_level,ip6_midlevel_equal,NULL,NULL);
    ht->lessthan15_cnt=0;
    ht->rc_sot_v4 = (rc_sot4 *)malloc(sizeof(rc_sot4));
    rc_sot4_init(ht->rc_sot_v4);
    ht->rc_sot_v6 = (rc_sot6 *)malloc(sizeof(rc_sot6));
    rc_sot6_init(ht->rc_sot_v6);
    ht->rc_stt_v4 = (rc_stt4 *)malloc(sizeof(rc_stt4));
    rc_stt4_init(ht->rc_stt_v4);
    ht->rc_stt_v6 = (rc_stt6 *)malloc(sizeof(rc_stt6));
    rc_stt6_init(ht->rc_stt_v6);
    ht->lb = (level_bitmap *)malloc(sizeof(level_bitmap));
    lvl_bm_init(ht->lb);
    ht->lb_v6 = (level_bitmap *)malloc(sizeof(level_bitmap));
    lvl_bm_init(ht->lb_v6);
    ht->wide_tree_v4 = New_Patricia(32);
    ht->wide_array_v4_extra = (wideASN *)malloc(sizeof(wideASN));
    ht->wide_tree_v6 = New_Patricia(128);
    ht->wide_array_v6_extra = (wideASN *)malloc(sizeof(wideASN));
    wideASN_init(ht->wide_array_v4_extra);
    wideASN_init(ht->wide_array_v6_extra);
    ht->child_bitmap_v6=hashmap_new(sizeof(struct ip6_t_info),0,0,0,hash_ip6_t_info,ip6_t_equal,NULL,NULL);
}

//update withdrawn cnt for pfxt_v4
int insert_withdrawn_cnt_v4_nlb(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv4 *ipv4, struct ipv4_asn_info * info){
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

int insert_SOT_v4_nlb(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv4 *ipv4){
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
        if(insert_withdrawn_cnt_v4_nlb(pfxt,ipv4,info)==ERROR) return ERROR;
        info->bitmap = ipv4->Encoded_sub_tree|info->bitmap;
    }  
    // ipv4asn_uint32_map_itr itr = vt_get( &pfxt->sot_v4, k );
    // if( !vt_is_end( itr ) ){
    //     struct ipv4_asn_info info;
    //     info.key = itr.data->key;
    //     info.bitmap = itr.data->val;
    //     if(insert_withdrawn_cnt_v4_nlb(pfxt,ipv4,&info)==ERROR) return ERROR;
    //     vt_insert( &pfxt->sot_v4, k, (itr.data->val | ipv4->Encoded_sub_tree) );
    // }
    // else{
    //     ipv4asn_uint32_map_itr itr = vt_insert( &pfxt->sot_v4, k, ipv4->Encoded_sub_tree );
    //     if( vt_is_end( itr ) )
    //     {
    //         // Out of memory, so abort.
    //         return ERROR;
    //     }
    // }
    return SUCCESS;
}

int insert_withdrawn_cnt_v4_nlb_agg(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv4 *pdu, struct ipv4_complex_info *info_agg){
    ipv4 k_agg;
    k_agg = pdu->sub_tree_identifier;
    int pos=0;
    if(info_agg->bm.withdrawn_flag == 0){
        if(set_last_bit_zero(info_agg->bm.bitmap & pdu->Encoded_sub_tree)>0){
            info_agg->bm.withdrawn_flag = 1;
            return rc_stt4_insert_new(pfxt->rc_stt_v4,k_agg,info_agg->bm.bitmap,pdu->Encoded_sub_tree); 
        }
    }
    else{
        return rc_stt4_insert(pfxt->rc_stt_v4,k_agg,pdu->Encoded_sub_tree);
    }
    return SUCCESS;
}

int insert_STT_v4_nlb(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv4 *pdu){
    ipv4 k_agg = pdu->sub_tree_identifier;
    struct ipv4_complex_info *info_agg = find_ipv4_complex_info(pfxt->stt_v4,k_agg);
    if(!info_agg){
        //put in STT
        uint32_t bm = pdu->Encoded_sub_tree;
        bm = set_last_bit_zero(bm);
        struct bmb b;
        set_bmb(b,bm,0,0);
        insert_ipv4_complex_info(pfxt->stt_v4, k_agg, b);
        if(hashmap_oom(pfxt->stt_v4)) return ERROR;
    }
    else{
        if(insert_withdrawn_cnt_v4_nlb_agg(pfxt,pdu,info_agg)==ERROR) return ERROR;
        info_agg->bm.bitmap = info_agg->bm.bitmap | pdu->Encoded_sub_tree;
    }
    return SUCCESS;
    // ipv4_complex_map_itr itr = vt_get( &pfxt->stt_v4, k_agg );
    // if( !vt_is_end( itr ) ){
    //     struct ipv4_complex_info info;
    //     info.key = itr.data->key;
    //     info.bm = itr.data->val;
    //     if(insert_withdrawn_cnt_v4_nlb_agg(pfxt,pdu,&info)==ERROR) return ERROR;
    //     itr.data->val.bitmap = (itr.data->val.bitmap | pdu->Encoded_sub_tree);
    //     vt_insert( &pfxt->stt_v4, k_agg, itr.data->val );
    // }
    // else{
    //     uint32_t bm = pdu->Encoded_sub_tree;
    //     bm = set_last_bit_zero(bm);
    //     struct bmb b;
    //     set_bmb(b,bm,0,0);
    //     ipv4_complex_map_itr itr = vt_insert( &pfxt->stt_v4, k_agg, b );
    //     if( vt_is_end( itr ) )
    //     {
    //         // Out of memory, so abort.
    //         return ERROR;
    //     }
    // }
}

int hrov_pfx_add_v4_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv4 *pdu){
    if(pdu->asn>0){
        if(insert_SOT_v4_nlb(pfxt,pdu)==ERROR) return ERROR;
    }
    if(insert_STT_v4_nlb(pfxt,pdu)==ERROR) return ERROR;
    lvl_bm_insert(pfxt->lb, pdu->sub_tree_identifier, pdu->Encoded_sub_tree);
    return SUCCESS;
}

int insert_withdrawn_cnt_v6_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv6 *ipv6, struct ip6_t_asn_info * info){
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

int insert_SOT_v6_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv6 *ipv6){
    struct ip6_t_asn k;
    memcpy(k.addr.u_ip6.u_ip6_addr32, ipv6->sub_tree_identifier, sizeof(uint32_t)*4);
    k.asn = ipv6->asn;
   
    struct ip6_t_asn_info * info = find_ip6_t_asn_info(pfxt->sot_v6, k);
    if(!info){
        insert_ip6_t_asn_info(pfxt->sot_v6, k, ipv6->Encoded_sub_tree);
        if(hashmap_oom(pfxt->sot_v6)) return ERROR;
    }
    else{
        if(insert_withdrawn_cnt_v6_nlbs(pfxt,ipv6,info)==ERROR) return ERROR;
        info->bitmap = ipv6->Encoded_sub_tree|info->bitmap;
    }
    return SUCCESS;
}

int handle_parent_v6_nlbs(struct hrov_table_nlbs *pfxt,struct ip6_t_complex_info pinfo_list[V6PATH],int pl_index,struct ip6_t identifier){
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
            // if(pinfo->bm.wideROA_flag){
            //     struct ip6_t parent_header;
            //     memcpy(parent_header.u_ip6.u_ip6_addr32,parent_identifier.u_ip6.u_ip6_addr32,sizeof(uint32_t)*4);
            //     for(int i=0;i<pl_index;i++){
            //         struct ip6_t child_header;
            //         memcpy(child_header.u_ip6.u_ip6_addr32,pinfo_list[i].key.u_ip6.u_ip6_addr32,sizeof(uint32_t)*4);
            //         if(wideArray_copy_v6(pfxt->wide_array_v6,parent_header,child_header)==ERROR) return ERROR;
            //         pinfo_list[i].bm.wideROA_flag=1;
            //     }
               
            // } 
            int index = tmp_identifier.u_ip6.u_ip6_addr32[3] & ((1 << HANGING_LEVEL) - 1);
            uint32_t child_bitmap = 1<<index;
            struct ip6_t_info * pchild;
            pchild = hashmap_get(pfxt->child_bitmap_v6, &(struct ip6_t_info){.key = parent_identifier});
            if(pchild){
                pchild->bm = child_bitmap | pchild->bm;
                // pinfo->bm.childbitmap = child_bitmap | pinfo->bm.childbitmap;
            }
            else{
                insert_ip6_t_info(pfxt->child_bitmap_v6,parent_identifier,child_bitmap);
                // pinfo->bm.childbitmap = child_bitmap;
                if(hashmap_oom(pfxt->child_bitmap_v6)) return ERROR;
            }
            break;
        }
        struct ip6_t_complex_info ptmp;
        memcpy(ptmp.key.u_ip6.u_ip6_addr32,parent_identifier.u_ip6.u_ip6_addr32,sizeof(uint32_t)*4);
        set_bmb(ptmp.bm,0,0,0);
       

        int index = tmp_identifier.u_ip6.u_ip6_addr32[3] & ((1 << HANGING_LEVEL) - 1);
        uint32_t child_bitmap = 1<<index;
        insert_ip6_t_info(pfxt->child_bitmap_v6,parent_identifier,child_bitmap);
        // ptmp.bm.childbitmap = child_bitmap;
        pinfo_list[pl_index++]=ptmp;

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

int insert_STT_with_parent_v6_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv6 *pdu){
    struct ip6_t k_agg;
    memcpy(k_agg.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(uint32_t)*4); 
    //pinfo_list中存放的是STT中不存在的identifier
    int len = V6PATH;
    struct ip6_t_complex_info pinfo_list[len];
    int pl_index=0;
    memcpy(pinfo_list[0].key.u_ip6.u_ip6_addr32, k_agg.u_ip6.u_ip6_addr32, sizeof(uint32_t)*4);
    set_bmb(pinfo_list[0].bm,pdu->Encoded_sub_tree,0,0);
    // pinfo_list[0].bm.childbitmap = 0;
    pl_index++;
    //把自己先插入到child bitmap中
    insert_ip6_t_info(pfxt->child_bitmap_v6,k_agg,0);
    if(hashmap_oom(pfxt->child_bitmap_v6)) return ERROR;
    //向上寻找祖先
    if(handle_parent_v6_nlbs(pfxt,pinfo_list,pl_index,k_agg)==ERROR) return ERROR;
    return SUCCESS;
}

int insert_withdrawn_cnt_v6_agg_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv6 *pdu, struct ip6_t_complex_info * info_agg){
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

int insert_midlevel_v6(struct hrov_table_nlbs * pfxt,struct ip6_t id){
    int hanging_level = 0;
    count_Bits_v6_c(id.u_ip6.u_ip6_addr32,&hanging_level);
    hanging_level-=1;
    struct ip6_t subsubid; 
    if(hanging_level>=MIDLEVEL){
        r_move_v6(id.u_ip6.u_ip6_addr32,subsubid.u_ip6.u_ip6_addr32,(hanging_level-MIDLEVEL));
        uint32_t key = subsubid.u_ip6.u_ip6_addr32[3];
        struct ip6_t_leafnode_level *llevel = find_ip6_t_leafnode_level(pfxt->midlevel_v6,key);
        if(!llevel){
            struct sc_array_int arr; 
            sc_array_init(&arr);
            sc_array_add(&arr,hanging_level);
            insert_ip6_t_leafnode_level(pfxt->midlevel_v6,key,arr);
        }
        else{
            // sc_array_add(&llevel->levels,hanging_level);
            int exist = 0;
            for (size_t i = 0; i < sc_array_size(&llevel->levels); i++) {
                if(hanging_level==llevel->levels.elems[i]){
                    exist = 1;
                    break;
                }
                else if(hanging_level<llevel->levels.elems[i]){
                    exist = 1;
                    sc_array_insert(&llevel->levels,i,hanging_level);
                    break;
                }
            }
            if(exist==0) sc_array_add(&llevel->levels,hanging_level);
        }
    }
    return SUCCESS;
}

int insert_STT_v6_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv6 *pdu){
    struct ip6_t k_agg;
    memcpy(k_agg.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(uint32_t)*4);
    struct ip6_t_complex_info * info_agg = find_ip6_t_complex_info(pfxt->stt_v6, k_agg);
    if(!info_agg){
        if(insert_STT_with_parent_v6_nlbs(pfxt,pdu)==ERROR) return ERROR;     
    }
    else{
        if(insert_withdrawn_cnt_v6_agg_nlbs(pfxt,pdu,info_agg)==ERROR) return ERROR;
        info_agg->bm.bitmap = pdu->Encoded_sub_tree|info_agg->bm.bitmap; 
        if(set_child_flag_v6_nlbs(pfxt,k_agg)==ERROR) return ERROR;
    }
#ifndef BINARY
    int hanging_level = 0;
    count_Bits_v6_c(k_agg.u_ip6.u_ip6_addr32,&hanging_level);
    hanging_level-=1;
    if(hanging_level>=MIDLEVEL){
        insert_midlevel_v6(pfxt,k_agg);
    }
    else{
        lvl_bm_insert(pfxt->lb_v6, pdu->sub_tree_identifier[3], pdu->Encoded_sub_tree);
    }
#endif
    return SUCCESS;
}

int hrov_pfx_add_v6_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv6 *ipv6){
    if(ipv6->asn>0){
        if(insert_SOT_v6_nlbs(pfxt,ipv6)==ERROR) return ERROR;
    }
    if(insert_STT_v6_nlbs(pfxt,ipv6)==ERROR) return ERROR;
}

int bitmap_individer_v4_nlbs(struct hrov_table_nlbs *pfxt, uint32_t prefix, int masklen, int maxlen, uint32_t asn,int (*pfx_update)(struct hrov_table_nlbs *, const struct hpdu_ipv4 *)){
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
                if(bitmap_individer_v4_nlbs(pfxt,tmp_prefix,next_hanging_level,maxlen,asn,pfx_update)==ERROR) return ERROR;
            }
        }
    
    }
    return SUCCESS;
}

int set_wide_flag_v4_nlbs(struct hrov_table_nlbs * pfxt, uint32_t id){
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
    // ipv4_complex_map_itr itr = vt_get( &pfxt->stt_v4, k_agg );
    // if( !vt_is_end( itr ) ){
    //     itr.data->val.wideROA_flag=1;
    //     vt_insert( &pfxt->stt_v4, k_agg, itr.data->val );
    // }
    // else{
    //     struct bmb b;
    //     set_bmb(b,0,0,1);
    //     ipv4_complex_map_itr itr = vt_insert( &pfxt->stt_v4, k_agg, b );
    //     if( vt_is_end( itr ) )
    //     {
    //         return ERROR;
    //     }
    // }
    return SUCCESS;
}

int bitmap_wide_add_v4_nlbs(struct hrov_table_nlbs *pfxt, uint32_t prefix, int masklen, int maxlen, uint32_t asn){
    bitmap_individer_v4_nlbs(pfxt,prefix,masklen,masklen,0,hrov_pfx_add_v4_nlbs);
    prefix_t lookupPrefix;
    lookupPrefix.family = AF_INET;
    lookupPrefix.bitlen = masklen;
    lookupPrefix.add.sin.s_addr = htonl(prefix);
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

int bitmap_individer_v6_nlbs(struct hrov_table_nlbs *pfxt, uint32_t prefix[], int masklen, int maxlen, uint32_t asn,int (*pfx_update)(struct hrov_table_nlbs *, const struct hpdu_ipv6 *)){
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
                if(bitmap_individer_v6_nlbs(pfxt,sub_prefix,next_hanging_level,maxlen,asn,pfx_update)==ERROR) return ERROR;
            }
        }
        }
    }
    return SUCCESS;
}


int insert_STT_with_wide_n_parent_v6_nlbs(struct hrov_table_nlbs *pfxt,uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
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
    // pinfo_list[0].bm.childbitmap = 0;
    pl_index++;
    insert_ip6_t_info(pfxt->child_bitmap_v6,identifier,0);
    if(hashmap_oom(pfxt->child_bitmap_v6)) return ERROR;
    //向上寻找祖先
    if(handle_parent_v6_nlbs(pfxt,pinfo_list,pl_index,identifier)==ERROR) return ERROR;
    return SUCCESS;
}

int set_child_wide_info_v6_nlbs(struct hrov_table_nlbs * ht, struct ip6_t p, uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    struct ip6_t_info *cinfo;
    cinfo = hashmap_get(ht->child_bitmap_v6, &(struct ip6_t_info){.key = p});
    if(!cinfo) return ERROR;
    uint32_t bm = cinfo->bm;
    while(bm>0){
        int index = __builtin_ctz(bm);
        struct ip6_t c_agg;
        l_move_v6(p.u_ip6.u_ip6_addr32,c_agg.u_ip6.u_ip6_addr32,HANGING_LEVEL);
        c_agg.u_ip6.u_ip6_addr32[3] = c_agg.u_ip6.u_ip6_addr32[3]+index;  
        struct ip6_t_complex_info *tmp = find_ip6_t_complex_info(ht->stt_v6, c_agg);
        if(!tmp) return ERROR;
        tmp->bm.wideROA_flag=1;
        // wide_table_v6_nlbs_add(ht,c_agg.addr,pfx,masklen,maxlen,asn);
        struct ip6_t prefix;
        memcpy(prefix.u_ip6.u_ip6_addr32,pfx,sizeof(uint32_t)*4);
        // if(wideArray_insert_v6(ht->wide_array_v6,c_agg,prefix,masklen,maxlen,asn)==ERROR) return ERROR;
        if(set_child_wide_info_v6_nlbs(ht,c_agg,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
        bm = bm &(~(1<<index));
    }
    return SUCCESS;
}


int bitmap_wide_v6_nlbs_add(struct hrov_table_nlbs *pfxt, uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    //STT
    bitmap_individer_v6_nlbs(pfxt,pfx,masklen,masklen,0,hrov_pfx_add_v6_nlbs);
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


int hrov_pfx_add_nlbs(struct hrov_table_nlbs * pfxt, void * pdu){
    const int type = *((char *)pdu + 1);
    if(type==HROV_IPV4){
        const struct hpdu_ipv4 *ipv4 = (const struct hpdu_ipv4 *)pdu;
        hrov_pfx_add_v4_nlbs(pfxt,ipv4);
    }
    else if(type==HROV_IPV6){
        const struct hpdu_ipv6 *ipv6 = (const struct hpdu_ipv6 *)pdu;
        hrov_pfx_add_v6_nlbs(pfxt,ipv6);
    }
    else if(type==TROA_IPV4){
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        if(ipv4->asn==0){
            // puts("0");
            return bitmap_individer_v4_nlbs(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->prefix_len,ipv4->asn,hrov_pfx_add_v4_nlbs);
        }
        else if(ipv4->max_prefix_len - ipv4->prefix_len < pfxt->widelen_v4){
            // puts("1");
            return bitmap_individer_v4_nlbs(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn,hrov_pfx_add_v4_nlbs);
        }   
        else{
            // puts("2");
            return bitmap_wide_add_v4_nlbs(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn);
        }
    }
    else if(type==TROA_IPV6){
        struct pdu_ipv6 *ipv6 = (struct pdu_ipv6 *)pdu;
        if(ipv6->prefix_len<15) pfxt->lessthan15_cnt++;
        if(ipv6->asn==0){
            // puts("1");
            return bitmap_individer_v6_nlbs(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->prefix_len,ipv6->asn,hrov_pfx_add_v6_nlbs);
        }
        else if(ipv6->max_prefix_len - ipv6->prefix_len < pfxt->widelen_v6){
            // puts("2");
            return bitmap_individer_v6_nlbs(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn,hrov_pfx_add_v6_nlbs);
        }
        else{
            // puts("3");
            // return SUCCESS;
            return bitmap_wide_v6_nlbs_add(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn);
        }
    }
    else{
        return ERROR;
    }
    return SUCCESS;
}

int remove_entry_in_SOT_v4_nlb(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv4 *ipv4){
    struct ipv4_asn k;
    k.addr = ipv4->sub_tree_identifier;
    k.asn = ipv4->asn;
    struct ipv4_asn_info * info = find_ipv4_asn_info(pfxt->sot_v4,k);
    if(info){
        //if reference flag is set to 0
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
        if(info->bitmap==0||info->bitmap==1){
            hashmap_delete(pfxt->sot_v4,&(struct ipv4_asn_info){.key = k});
        }
        return SUCCESS;
    }
    return ERROR;
}

int remove_with_withdrawn_cnt_v4_nlb(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv4 *pdu){
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
        if(info_agg->bm.bitmap==0){
            delete_ipv4_complex_info(pfxt->stt_v4,k_agg);
        }
        return SUCCESS;
    }
    else{
        return ERROR;
    }
}


int hrov_pfx_rm_v4_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv4 *ipv4){
    if(ipv4->asn>0){
        if(remove_entry_in_SOT_v4_nlb(pfxt,ipv4)==ERROR) return ERROR;
    }
    if(remove_with_withdrawn_cnt_v4_nlb(pfxt,ipv4)==ERROR) return ERROR;
    lvl_bm_remove(pfxt->lb,ipv4->sub_tree_identifier,ipv4->Encoded_sub_tree);   
    return SUCCESS;   

}

int remove_entry_in_SOT_v6_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv6 *ipv6){
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
            info->bitmap = tmp;
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

int remove_with_withdrawn_cnt_v6_agg_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv6 *pdu){
    struct ip6_t k_agg;
    memcpy(k_agg.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(struct ip6_t));
    struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(pfxt->stt_v6, k_agg);
    if(info_agg){
        if(info_agg->bm.withdrawn_flag){
            uint32_t tmp = info_agg->bm.bitmap;
            int flag = rc_stt6_remove(pfxt->rc_stt_v6,k_agg,pdu->Encoded_sub_tree,&tmp);
            if(flag==ERROR) return ERROR;
            info_agg->bm.bitmap=tmp;
            if(flag==ALLZERO){
                info_agg->bm.withdrawn_flag=0;
            }
        }
        else{
            info_agg->bm.bitmap = info_agg->bm.bitmap & (~pdu->Encoded_sub_tree);
        }
        // printf("%u\n",info_agg->bm.bitmap);
        return SUCCESS;
    }
    else{
        return ERROR;
    }
}

int remove_with_parent_v6_nlbs(struct hrov_table_nlbs * pfxt,struct ip6_t k_agg){
    struct ip6_t_info * child_info;
    child_info = hashmap_get(pfxt->child_bitmap_v6, &(struct ip6_t_info){.key = k_agg});
    if(!child_info) return ERROR;
    uint32_t bm = child_info->bm;
    if(bm==0){
        struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(pfxt->stt_v6, k_agg);
        if(!info_agg) return ERROR;
        uint32_t dest_bitmap = info_agg->bm.bitmap;
        if(dest_bitmap==0||dest_bitmap==1){
            struct ip6_t parent_k_agg;
            r_move_v6(k_agg.u_ip6.u_ip6_addr32,parent_k_agg.u_ip6.u_ip6_addr32,HANGING_LEVEL);
            struct ip6_t_info * pinfo_agg;
            pinfo_agg = hashmap_get(pfxt->child_bitmap_v6, &(struct ip6_t_info){.key = parent_k_agg});
            if(pinfo_agg){
                int index = k_agg.u_ip6.u_ip6_addr32[3] & ((1 << HANGING_LEVEL) - 1);
                uint32_t mask = 0xffffffff - (1<<index);
                pinfo_agg->bm=pinfo_agg->bm&mask;
                if(remove_with_parent_v6_nlbs(pfxt,parent_k_agg)==ERROR) return ERROR;        
            }
            hashmap_delete(pfxt->stt_v6,&(struct ip6_t_complex_info){.key = k_agg});
            hashmap_delete(pfxt->child_bitmap_v6,&(struct ip6_t_info){.key = k_agg}); 
        }
    }
    return SUCCESS;
}

int hrov_pfx_rm_v6_nlbs(struct hrov_table_nlbs * pfxt, const struct hpdu_ipv6 *pdu){
    // delete in SOT if asn != 0
    if(pdu->asn>0){
       if(remove_entry_in_SOT_v6_nlbs(pfxt,pdu)==ERROR) return ERROR;
    }
    struct ip6_t k_agg;
    memcpy(k_agg.u_ip6.u_ip6_addr32, pdu->sub_tree_identifier, sizeof(struct ip6_t));
    //update STT value with withdrawn cnt
    if(remove_with_withdrawn_cnt_v6_agg_nlbs(pfxt,pdu)==ERROR) return ERROR;
    //update children's authorization-flag value
    if(set_child_flag_v6_nlbs(pfxt,k_agg)==ERROR) return ERROR;
    //delete with its parents when it should be deleted
    if(remove_with_parent_v6_nlbs(pfxt,k_agg)==ERROR) return ERROR; 
    return SUCCESS;
}

int bitmap_wide_rm_v4_nlbs(struct hrov_table_nlbs *pfxt, uint32_t prefix, int masklen, int maxlen, uint32_t asn){
    //STT remove
    bitmap_individer_v4_nlbs(pfxt,prefix,masklen,masklen,0,hrov_pfx_rm_v4_nlbs);
    //WRT remove
    prefix_t lookupPrefix;
    lookupPrefix.family = AF_INET;
    lookupPrefix.bitlen = masklen;
    lookupPrefix.add.sin.s_addr = htonl(prefix);
    lookupPrefix.ref_count = 0;
    patricia_node_t* treeNode = NULL;
    treeNode = patricia_lookup(pfxt->wide_tree_v4,&lookupPrefix);
    if(treeNode == NULL){
        return ERROR;
    }
    if(treeNode->data){
        node_data_t *roaListNode = (node_data_t *)treeNode->data;
        int index = -1;
        for(int i=0;i<roaListNode->len;i++){
            ROA roa = roaListNode->ary[i];
            if(asn==roa.asn&&maxlen==roa.maxlen){
                index = i;
                break;
            }
        }
        if(index==-1) return ERROR;
        delete_elem((node_data_t *)treeNode->data,index);
    }
    else{
        return ERROR;
    }
    wideASN_remove(pfxt->wide_array_v4_extra,asn);
    return SUCCESS;
}

int rm_child_wide_info_v6_nlbs(struct hrov_table_nlbs * ht, struct ip6_t p, const uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    struct ip6_t prefix;
    memcpy(prefix.u_ip6.u_ip6_addr32,pfx,sizeof(uint32_t)*4);
    struct ip6_t_info *cinfo;
    cinfo = hashmap_get(ht->child_bitmap_v6, &(struct ip6_t_info){.key = p});
    if(!cinfo) return ERROR;
    uint32_t bm = cinfo->bm;
    while(bm>0){
        int index = __builtin_ctz(bm);
        struct ip6_t c_agg;
        l_move_v6(p.u_ip6.u_ip6_addr32,c_agg.u_ip6.u_ip6_addr32,HANGING_LEVEL);
        c_agg.u_ip6.u_ip6_addr32[3] = c_agg.u_ip6.u_ip6_addr32[3]+index;
        if(rm_child_wide_info_v6_nlbs(ht,c_agg,pfx,masklen,maxlen,asn)==ERROR) return ERROR;
        //delete its children's information
        struct ip6_t header;
        memcpy(header.u_ip6.u_ip6_addr32,c_agg.u_ip6.u_ip6_addr32,sizeof(uint32_t)*4);
        int flag;
        // if(wideArray_remove_v6(ht->wide_array_v6,header,prefix,masklen,maxlen,asn,&flag)==ERROR) return ERROR;
        if(flag==WA_NULL){
            struct ip6_t_complex_info *info_agg = find_ip6_t_complex_info(ht->stt_v6, c_agg);
            if(!info_agg) return ERROR;
            info_agg->bm.wideROA_flag=0;
            cinfo = hashmap_get(ht->child_bitmap_v6, &(struct ip6_t_info){.key = c_agg});
            if(!cinfo) return ERROR;
            if((info_agg->bm.bitmap==0||info_agg->bm.bitmap==1)&&(cinfo->bm==0)){
                hashmap_delete(ht->stt_v6,&(struct ip6_t_complex_info){.key = c_agg});
                hashmap_delete(ht->child_bitmap_v6,&(struct ip6_t_info){.key = c_agg});
                struct ip6_t_info * pinfo_agg;
                pinfo_agg = hashmap_get(ht->child_bitmap_v6, &(struct ip6_t_info){.key = p});
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

int bitmap_wide_v6_nlbs_rm(struct hrov_table_nlbs *pfxt, uint32_t pfx[], int masklen, int maxlen, uint32_t asn){
    //STT remove
    bitmap_individer_v6_nlbs(pfxt,pfx,masklen,masklen,0,hrov_pfx_rm_v6_nlbs);
    //WRT remove
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
    if(treeNode->data){
        node_data_t *roaListNode = (node_data_t *)treeNode->data;
        int index = -1;
        for(int i=0;i<roaListNode->len;i++){
            ROA roa = roaListNode->ary[i];
            if(asn==roa.asn&&maxlen==roa.maxlen){
                index = i;
                break;
            }
        }
        if(index==-1) return ERROR;
        delete_elem((node_data_t *)treeNode->data,index);
    }
    else{
        return ERROR;
    }
    wideASN_remove(pfxt->wide_array_v6_extra,asn);
    return SUCCESS;
}

int hrov_pfx_rm_nlbs(struct hrov_table_nlbs * pfxt, void *pdu){
    const int type = *((char *)pdu + 1);
    if(type==HROV_IPV4){
        const struct hpdu_ipv4 *ipv4 = (const struct hpdu_ipv4 *)pdu;
        hrov_pfx_rm_v4_nlbs(pfxt, ipv4);
    }
    else if(type==HROV_IPV6){
        const struct hpdu_ipv6 *ipv6 = (const struct hpdu_ipv6 *)pdu;
        hrov_pfx_rm_v6_nlbs(pfxt, ipv6);
    }
    else if(type==TROA_IPV4){
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        if(ipv4->asn==0){
            bitmap_individer_v4_nlbs(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->prefix_len,ipv4->asn,hrov_pfx_rm_v4_nlbs);
        }
        else if(ipv4->max_prefix_len - ipv4->prefix_len < pfxt->widelen_v4){
            bitmap_individer_v4_nlbs(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn,hrov_pfx_rm_v4_nlbs);
        }
        else{
            return bitmap_wide_rm_v4_nlbs(pfxt,ipv4->prefix,ipv4->prefix_len,ipv4->max_prefix_len,ipv4->asn);
        }
    }
    else if(type==TROA_IPV6){
        struct pdu_ipv6 *ipv6 = (struct pdu_ipv6 *)pdu;
        if(ipv6->asn==0){
            bitmap_individer_v6_nlbs(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->prefix_len,ipv6->asn,hrov_pfx_rm_v6_nlbs);
        }
        else if(ipv6->max_prefix_len - ipv6->prefix_len < pfxt->widelen_v6){
            bitmap_individer_v6_nlbs(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn,hrov_pfx_rm_v6_nlbs);
        }
        else{
            bitmap_wide_v6_nlbs_rm(pfxt,ipv6->prefix,ipv6->prefix_len,ipv6->max_prefix_len,ipv6->asn);
        }
    }else{
        return ERROR;
    }
    return SUCCESS;
}

int hrov_pfx_validate_v4_nlbs(struct hrov_table_nlbs * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    uint32_t sub_tree_id = hanging_level==0?1:get_subtree_identifier_v4(pfx->u.addr4.addr, hanging_level);
    
    struct ipv4_asn k;
    k.addr = sub_tree_id;
    k.asn = asn;

    ipv4 k_agg = sub_tree_id;
   
    uint32_t index = 0;
    get_subtree_pos_v4_c(pfx->u.addr4.addr,hanging_level,masklen,&index);
    uint32_t mask = 1<<index; 
    // ipv4asn_uint32_map_itr itr = vt_get( &ht->sot_v4, k );
    // if(!vt_is_end( itr )&&(itr.data->val & mask)>0){
    struct ipv4_asn_info * it = find_ipv4_asn_info(ht->sot_v4,k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
    else{
        // ipv4_complex_map_itr it_agg = vt_get(&ht->stt_v4,k_agg);
        // if(!vt_is_end(it_agg)&&((it_agg.data->val.bitmap&MASK_BASIC[index])>0)){
        struct ipv4_complex_info * it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);  
        if(it_agg&&((it_agg->bm.bitmap&MASK_BASIC[index])>0)){
            *res = BGP_PFXV_STATE_INVALID;
            return SUCCESS;
        }    
        while(hanging_level>LVL_BM){
            hanging_level-=HANGING_LEVEL;
            k_agg = k_agg>>HANGING_LEVEL;
            get_subtree_pos_v4_c(pfx->u.addr4.addr, hanging_level, (hanging_level+HANGING_LEVEL-1), &index);
            // it_agg = vt_get(&ht->stt_v4,k_agg);
            // if(!vt_is_end(it_agg)&&(it_agg.data->val.bitmap&MASK_BASIC[index])>0){
            it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);  
            if(it_agg&&(it_agg->bm.bitmap&MASK_BASIC[index])>0){
                *res = BGP_PFXV_STATE_INVALID;
                return SUCCESS;
            }
            if(hanging_level==LVL_BM) break;
        }

        if(hanging_level>0){
            int offset = lvl_bm_get_position(k_agg, hanging_level);
            if(lvl_bm_judge_exact_bit(ht->lb,offset)){
                *res = BGP_PFXV_STATE_INVALID;
                return SUCCESS;
            }else{
                *res = BGP_PFXV_STATE_NOT_FOUND;
                return SUCCESS;
            }
        }
    }
    
    return SUCCESS;
}

void check_point_v4_nlbs(struct hrov_table_nlbs * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, struct ipv4_complex_info *it_agg, int index, enum pfxv_state * res){
    enum pfxv_state res_sot=BGP_PFXV_STATE_NOT_FOUND,res_wide=BGP_PFXV_STATE_NOT_FOUND;
    if((it_agg->bm.bitmap&MASK_BASIC[index])>0){
        *res = BGP_PFXV_STATE_INVALID;
    }
    // if(it_agg->bm.wideROA_flag){
    //     wideArray_validate_v4(ht->wide_array_v4,it_agg->key,pfx->u.addr4.addr,masklen,asn,&res_wide);
    // }
    // if(res_wide==BGP_PFXV_STATE_VALID){
    //     *res=BGP_PFXV_STATE_VALID;
    // }
    // else if((res_sot==BGP_PFXV_STATE_INVALID)||(res_wide==BGP_PFXV_STATE_INVALID)){
    //     *res=BGP_PFXV_STATE_INVALID;
    // }
    return;
}

int hrov_pfx_validate_v4_wide_nlbs(struct hrov_table_nlbs * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    enum pfxv_state basic_res = BGP_PFXV_STATE_NOT_FOUND, wide_res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    int basic_level = hanging_level, wide_level = hanging_level;
    uint32_t sub_tree_id = hanging_level==0?1:get_subtree_identifier_v4(pfx->u.addr4.addr, hanging_level);
    
    struct ipv4_asn k;
    k.addr = sub_tree_id;
    k.asn = asn;

    ipv4 k_agg = sub_tree_id;
    ipv4 wide_header = sub_tree_id;
    
    uint32_t index = 0;
    get_subtree_pos_v4_c(pfx->u.addr4.addr,hanging_level,masklen,&index);
    uint32_t mask = 1<<index; 
    // uint32_t mask = lmove_res[index]; 
    // ipv4asn_uint32_map_itr itr = vt_get( &ht->sot_v4, k );
    // if(!vt_is_end( itr )&&(itr.data->val & mask)>0){
    struct ipv4_asn_info * it = find_ipv4_asn_info(ht->sot_v4,k);
    // puts("0");
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
                    else{
                        *res = BGP_PFXV_STATE_INVALID;
                    }
                }
                treeNode = getParent(treeNode);
            }
            if(*res!=BGP_PFXV_STATE_NOT_FOUND) return SUCCESS;
        }
    }
    ipv4 lb_key = k_agg;
    int lb_level = basic_level;
    if(lb_level>20){
        lb_key=lb_key>>(lb_level-20);
        lb_level=20;
    }
    if(lb_level>0){
        int offset = lvl_bm_get_position(lb_key, lb_level);
        if(lvl_bm_judge_exact_bit(ht->lb,offset)){
            *res = BGP_PFXV_STATE_INVALID;
            return SUCCESS;
        }
    }

    struct ipv4_complex_info * it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);
    if(it_agg){
        // check_point_v4_nlbs(ht,asn,pfx,masklen,it_agg,index,res);
        if((it_agg->bm.bitmap&MASK_BASIC[index])>0){
            *res = BGP_PFXV_STATE_INVALID;
            return SUCCESS;
        }
    }
    while(basic_level>LVL_BM){
        basic_level-=HANGING_LEVEL;
        k_agg = k_agg>>HANGING_LEVEL;
        wide_level-=HANGING_LEVEL;
        wide_header = wide_header>>HANGING_LEVEL;
        get_subtree_pos_v4_c(pfx->u.addr4.addr, basic_level, (basic_level+HANGING_LEVEL-1), &index);
        it_agg = find_ipv4_complex_info(ht->stt_v4,k_agg);   
        if(it_agg){
        // it_agg = vt_get(&ht->stt_v4,k_agg);
        // if(!vt_is_end(it_agg)){
        //     struct ipv4_complex_info tmp;
        //     tmp.key = it_agg.data->key;
        //     tmp.bm = it_agg.data->val;
            if((it_agg->bm.bitmap&MASK_BASIC[index])>0){
                *res = BGP_PFXV_STATE_INVALID;
                return SUCCESS;
            }
        }
        if(basic_level==LVL_BM) break;
    }

    // if((*res==BGP_PFXV_STATE_NOT_FOUND)&&(basic_level>0)){
    //     int offset = lvl_bm_get_position(k_agg, basic_level);
    //     if(lvl_bm_judge_exact_bit(ht->lb,offset)){
    //         *res = BGP_PFXV_STATE_INVALID;
    //     }
    // }

    
    return SUCCESS;
}

int hrov_pfx_validate_v6_nlbs(struct hrov_table_nlbs * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
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
    else{       
        struct ip6_t_complex_info *it_agg = find_ip6_t_complex_info(ht->stt_v6, k_agg);
        if(it_agg){
            if((it_agg->bm.bitmap & MASK[index])>0){
                *res = BGP_PFXV_STATE_INVALID;
                return SUCCESS;
            }
            *res = BGP_PFXV_STATE_NOT_FOUND;
            return SUCCESS;
        }
        else{
            int left=0, right=hanging_level;
            int mid = (left+right)/2;
            int hanging_level_mid = mid-mid%HANGING_LEVEL;
            struct ip6_t tmp_agg;
            int minilen = 0;
            
            while(left<=right){
                r_move_v6(k_agg.u_ip6.u_ip6_addr32,tmp_agg.u_ip6.u_ip6_addr32,(hanging_level - hanging_level_mid));
                it_agg = find_ip6_t_complex_info(ht->stt_v6, tmp_agg);
                minilen = min_t((hanging_level_mid+HANGING_LEVEL-1),masklen);
                get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level_mid,minilen,index);
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
            *res = BGP_PFXV_STATE_NOT_FOUND;
            return SUCCESS; 
        }
    }
    return SUCCESS;
}

static inline void check_point_v6_nlbs(struct hrov_table_nlbs * ht, const uint32_t asn, struct ip6_t pfx, const uint8_t masklen, struct ip6_t_complex_info *it_agg, int index, enum pfxv_state * res){
    enum pfxv_state res_sot=BGP_PFXV_STATE_NOT_FOUND,res_wide=BGP_PFXV_STATE_NOT_FOUND;
    if((it_agg->bm.bitmap&MASK[index])>0){
        *res=BGP_PFXV_STATE_INVALID;
    }
    // if(it_agg->bm.wideROA_flag){
    //     wideArray_validate_v6(ht->wide_array_v6,it_agg->key,pfx,masklen,asn,&res_wide);
    // }
    // if(res_wide==BGP_PFXV_STATE_VALID){
    //     *res=BGP_PFXV_STATE_VALID;
    // }
    // else if((res_sot==BGP_PFXV_STATE_INVALID)||(res_wide==BGP_PFXV_STATE_INVALID)){
    //     *res=BGP_PFXV_STATE_INVALID;
    // }
    return;
}

int hrov_pfx_validate_v6_wide_nlbs(struct hrov_table_nlbs * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    struct ip6_t_asn k;
    get_subtree_identifier_v6(k.addr.u_ip6.u_ip6_addr32, pfx->u.addr6.addr, hanging_level);
    k.asn = asn;

    uint32_t index = 0;
    get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,masklen,index);
    uint32_t mask = 1<<index;
    struct ip6_t_asn_info * it = find_ip6_t_asn_info(ht->sot_v6, k);
    if(it&&(it->bitmap & mask)>0){
        *res = BGP_PFXV_STATE_VALID;
        return SUCCESS;
    }
    struct ip6_t prefix;
    memcpy(prefix.u_ip6.u_ip6_addr32,pfx->u.addr6.addr,sizeof(uint32_t)*4);
    struct ip6_t_complex_info *it_agg = find_ip6_t_complex_info(ht->stt_v6, k.addr);
    // uint64_t hash = hashmap_murmur(&k_agg, sizeof(struct ip_addr_agg_v6), 0, 0)<< 16 >> 16;
    // it_agg = hashmap_get_with_hashvalue(ht->pfxt_v6_agg, &(struct ip_addr_agg_v6_info_bmb){.key = k_agg}, &hash);
    int t  = 2;
    if(it_agg){
        check_point_v6_nlbs(ht,asn,prefix,masklen,it_agg,index,res);
    }
    else{
        int left=0, right=hanging_level;
        int mid = (left+right)/2;
        int hanging_level_mid = mid - mid%HANGING_LEVEL;
        struct ip6_t tmp_agg;
        *res = BGP_PFXV_STATE_NOT_FOUND;
        while(left<right){
            r_move_v6_fast(k.addr.u_ip6.u_ip6_addr32,tmp_agg.u_ip6.u_ip6_addr32,(hanging_level - hanging_level_mid));
            it_agg = find_ip6_t_complex_info(ht->stt_v6, tmp_agg);
            t++;
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
            r_move_v6_fast(k.addr.u_ip6.u_ip6_addr32,tmp_agg.u_ip6.u_ip6_addr32,(hanging_level - hanging_level_mid + HANGING_LEVEL));
            it_agg = find_ip6_t_complex_info(ht->stt_v6, tmp_agg);
            t++;
            
            // it_agg = hashmap_get_with_hashvalue(ht->pfxt_v6_agg, &(struct ip_addr_agg_v6_info_bmb){.key = tmp_agg}, &hasht);  
            get_subtree_pos_v6(pfx->u.addr6.addr,(hanging_level_mid-HANGING_LEVEL),(hanging_level_mid- HANGING_LEVEL+4),index);
            check_point_v6_nlbs(ht,asn,prefix,masklen,it_agg,index,res);
        }
    }
    // printf("%d\n",t);
    return SUCCESS;
}

uint32_t get_bits(const uint32_t addr[4], int i) {
    // 计算第 i 位所在的 uint32_t 数组的索引和位偏移
    int idx = i / 32;
    int bit_offset = i % 32;

    // 如果跨越了 32 位边界，需要特殊处理
    if (bit_offset < 28) {
        return (addr[idx] >> (32 - bit_offset - 5)) & 0x1F;
    } else {
        // 跨越了 32 位边界，分两部分处理
        int remaining_bits = 5 - (32 - bit_offset);
        uint32_t part1 = (addr[idx] & ((1U << (32 - bit_offset)) - 1)) << remaining_bits;
        uint32_t part2 = addr[idx + 1] >> (32 - remaining_bits);
        return part1 | part2;
    }
}

// int hrov_pfx_validate_v6_wide_nlbs_exp(struct hrov_table_nlbs * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
//     *res = BGP_PFXV_STATE_NOT_FOUND;
//     int hanging_level = get_hanging_level(masklen);
//     struct ip6_t_asn k;
//     get_subtree_identifier_v6(k.addr.u_ip6.u_ip6_addr32, pfx->u.addr6.addr, hanging_level);
//     k.asn = asn;
//     int t = 0;
//     struct timespec tstart={0,0}, tend={0,0};

//     int exist_flag = 0;
//     // clock_gettime(CLOCK_MONOTONIC, &tstart);
//     struct ip6_t_asn_info * it = find_ip6_t_asn_info(ht->sot_v6, k);
//     // clock_gettime(CLOCK_MONOTONIC, &tend);
//     // double f = ((double)tend.tv_sec*1e9 + tend.tv_nsec) - ((double)tstart.tv_sec*1e9 + tstart.tv_nsec);
//     // ht->hashtime += f/1e9;
//     uint32_t index = 0;
//     get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,masklen,index);
//     uint32_t mask = 1u<<index;
//     if(it&&(it->bitmap & mask)>0){
//         // ht->sot_check++;
//         *res = BGP_PFXV_STATE_VALID;
//         return SUCCESS;
//     }
    
//     if(hashmap_get(ht->wide_array_v6_extra->dyheader,&(wideASN_block){.asn=asn})!=NULL){
//         patricia_node_t *treeNode = NULL;
//         prefix_t lookupPrefix;
//         lookupPrefix.family = AF_INET6;
//         lookupPrefix.bitlen = masklen;
//         for(int i=0;i<4;i++){
//             lookupPrefix.add.sin6.__in6_u.__u6_addr32[i] = htonl(pfx->u.addr6.addr[i]);
//         }
//         lookupPrefix.ref_count = 0;

//         treeNode = patricia_search_best(ht->wide_tree_v6,&lookupPrefix);
//         // ht->patricia_check++;

//         if(treeNode){  
//             while(treeNode){
//                 // printf("prefix %x\n",treeNode->prefix->add.sin.s_addr);
//                 node_data_t *roaListNode = (node_data_t *)treeNode->data;
//                 for(int i=0;i<roaListNode->len;i++){
//                     ROA roa = roaListNode->ary[i];
//                     // printf("%u\n",roa.asn);
//                     if(asn==roa.asn&&lookupPrefix.bitlen<=roa.maxlen){
//                         ht->patricia_check_success++;
//                         *res = BGP_PFXV_STATE_VALID;
//                         return SUCCESS;
//                     }
//                 }
//                 treeNode = getParent(treeNode);
//             }
//             *res = BGP_PFXV_STATE_INVALID;
//             return SUCCESS;
//         }
        
//     }

//     struct ip6_t prefix;
//     int set_prefix = 0;

//     int level_flag = 0;
//     struct ip6_t tmp_agg = k.addr;
//     int current_hanging_level = hanging_level;
//     if(hanging_level>=MIDLEVEL){
//         struct ip6_t leaf_check;
//         r_move_v6_fast(k.addr.u_ip6.u_ip6_addr32,leaf_check.u_ip6.u_ip6_addr32,(hanging_level-MIDLEVEL));
//         uint32_t key = leaf_check.u_ip6.u_ip6_addr32[3];
//         struct ip6_t_leafnode_level *lc = find_ip6_t_leafnode_level(ht->midlevel_v6,key);
//         t++;

//         if(lc){
//             // for(int i=0;i<lc->levels.size;i++) printf("%d,",lc->levels.elems[i]);
//             // printf("-->");
//             struct ip6_t_complex_info *it_agg=NULL, *result=NULL;  
//             int result_hanging_level = -1;
//             int l=0,r=lc->levels.size-1;
//             while(l<=r){
//                 int mid = (l+r)>>1;
//                 // printf("%d,",lc->levels.elems[mid]);
//                 int dest_hanging_level = lc->levels.elems[mid];
//                 if(dest_hanging_level>hanging_level){
//                     r=mid-1;
//                 }
//                 else{
//                     struct ip6_t tmp;
//                     r_move_v6_fast(k.addr.u_ip6.u_ip6_addr32,tmp.u_ip6.u_ip6_addr32,(hanging_level-dest_hanging_level));
//                     it_agg = find_ip6_t_complex_info(ht->stt_v6,tmp);
//                     t++;
//                     if(it_agg){
    
//                         result = it_agg;
//                         result_hanging_level = lc->levels.elems[mid];
//                         l=mid+1;
//                         if(hanging_level==dest_hanging_level){
//                             break;
//                         }
//                         else if(hanging_level>dest_hanging_level){
//                             int index_t = get_bits(pfx->u.addr6.addr,dest_hanging_level);
//                             if((it_agg->bm.childbitmap & (1u<<index_t))==0) {
//                                 // printf("find leaf node %d, ",t);
//                                 break;
//                             }
//                         }
//                     }  
//                     else{
//                         r=mid-1;
//                     }
//                 }
//             }
            
//             if(result){
//                 int result_masklen = result_hanging_level+HANGING_LEVEL-1>masklen?masklen:result_hanging_level+HANGING_LEVEL-1;
//                 get_subtree_pos_v6(pfx->u.addr6.addr,result_hanging_level,result_masklen,index);
//                 if((result->bm.bitmap&MASK[index])>0){
//                     *res = BGP_PFXV_STATE_INVALID;
//                 }
//                 return SUCCESS;
//             }
            
//         }
        
//         if(hanging_level >= MIDLEVEL){
//             r_move_v6_fast(k.addr.u_ip6.u_ip6_addr32,tmp_agg.u_ip6.u_ip6_addr32,(hanging_level-LVL_BM));
//             hanging_level = LVL_BM;
//         }
//     }
//     if(hanging_level>=LVL_BM){
//         struct ip6_t_complex_info *it_agg = find_ip6_t_complex_info(ht->stt_v6, tmp_agg);
//         t++;
//         if(it_agg){
//             int result_masklen = hanging_level+HANGING_LEVEL-1>masklen?masklen:hanging_level+HANGING_LEVEL-1;
//             get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,result_masklen,index);
//             if((it_agg->bm.bitmap&MASK[index])>0){
//                 *res = BGP_PFXV_STATE_INVALID;
//             }
//             return SUCCESS;
//         }
//     }
//     int offset = lvl_bm_get_position(tmp_agg.u_ip6.u_ip6_addr32[3], hanging_level);
//     if(lvl_bm_judge_exact_bit(ht->lb_v6,offset)){
//         *res = BGP_PFXV_STATE_INVALID;
//     }
//     return SUCCESS;
// }

int hrov_pfx_validate_v6_wide_nlbs_binary(struct hrov_table_nlbs * ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    *res = BGP_PFXV_STATE_NOT_FOUND;
    int hanging_level = get_hanging_level(masklen);
    struct ip6_t_asn k;
    get_subtree_identifier_v6(k.addr.u_ip6.u_ip6_addr32, pfx->u.addr6.addr, hanging_level);
    k.asn = asn;
    // int t = 0;
    struct timespec tstart={0,0}, tend={0,0};

    int exist_flag = 0;
    struct ip6_t_asn_info * it = find_ip6_t_asn_info(ht->sot_v6, k);
    uint32_t index = 0;
    get_subtree_pos_v6(pfx->u.addr6.addr,hanging_level,masklen,index);
    uint32_t mask = 1u<<index;
    if(it&&(it->bitmap & mask)>0){
        // puts("sot,");
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
                        // printf("%x,%x,%x,%x\n",treeNode->prefix->add.sin6.__in6_u.__u6_addr32[0],treeNode->prefix->add.sin6.__in6_u.__u6_addr32[1],treeNode->prefix->add.sin6.__in6_u.__u6_addr32[2],treeNode->prefix->add.sin6.__in6_u.__u6_addr32[3]);
                        ht->patricia_check_success++;
                        // puts("wrt");

                        *res = BGP_PFXV_STATE_VALID;
                        return SUCCESS;
                    }
                    else{
                        *res = BGP_PFXV_STATE_INVALID;
                    }
                }
                treeNode = getParent(treeNode);
            }
            // puts("wrt,");
            if(*res!=BGP_PFXV_STATE_NOT_FOUND) return SUCCESS;
        }
    }
    struct ip6_t k_agg;
    memcpy(&k_agg.u_ip6.u_ip6_addr32,&k.addr.u_ip6.u_ip6_addr32,sizeof(uint32_t)*4);
    struct ip6_t_complex_info *it_agg = find_ip6_t_complex_info(ht->stt_v6, k_agg);
    // t += 1;
    if(it_agg){
        if((it_agg->bm.bitmap & MASK[index])>0){
            *res = BGP_PFXV_STATE_INVALID;
        }
    } else{
        int left=0, right=hanging_level;
        int mid = (left+right)/2;
        // printf("%d\n",mid);
        int hanging_level_mid = mid-mid%HANGING_LEVEL;
        struct ip6_t tmp_agg;
        int minilen = 0;
        
        while(left<=right){
            r_move_v6(k_agg.u_ip6.u_ip6_addr32,tmp_agg.u_ip6.u_ip6_addr32,(hanging_level - hanging_level_mid));
            it_agg = find_ip6_t_complex_info(ht->stt_v6, tmp_agg);
            // t+=1;
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
    }

    // printf("STT, %d\n",t);
    return SUCCESS;
}

int hrov_pfx_validate_nlbs(struct hrov_table_nlbs *ht, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    if(pfx->ver == LRTR_IPV4){
        return hrov_pfx_validate_v4_wide_nlbs(ht,asn,pfx,masklen,res);
    }
    else{
        return hrov_pfx_validate_v6_wide_nlbs_binary(ht,asn,pfx,masklen,res);
        // return hrov_pfx_validate_v6_wide_nlbs_exp(ht,asn,pfx,masklen,res);
    }
}

void hrov_memory_release_nlbs(struct hrov_table_nlbs *ht){
    // printf("%ld\n",hashmap_count(ht->wide_array_v6->dyheader));
    printf("%lf\n",ht->hashtime);
    printf("%d\n",ht->sot_check);
    printf("%d\n",ht->patricia_check);
    printf("%d\n",ht->patricia_check_success);
    // hashmap_free(ht->stt_v4);
    // hashmap_free(ht->stt_v6);
    // // hashmap_free(ht->sot_v4);
    // hashmap_free(ht->sot_v6);
    // hashmap_free(ht->rc_sot_v4->map);
    // hashmap_free(ht->rc_sot_v6->map);
    // hashmap_free(ht->rc_stt_v4->map);
    // hashmap_free(ht->rc_stt_v6->map);
    // hashmap_free(ht->child_bitmap_v6);
    // // wideArray_free_v4(ht->wide_array_v4);
    // // wideArray_free_v6(ht->wide_array_v6);
    // free(ht->lb);
    // // free(ht->pb);
    // free(ht->lb_v6);
    // // free(ht->pb_v6);
    // free(ht);
    return;
}
