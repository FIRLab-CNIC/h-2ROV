#include"hrov_process.h"

void h_pfxt_init_basic(struct rov_algo_t *algo){
    struct hrov_table_basic *pfxt = (struct hrov_table_basic *)malloc(sizeof(struct hrov_table_basic));
	hrov_pfxt_init_basic(pfxt);
    pfxt->widelen_v4 = algo->wide_threshold;
    pfxt->widelen_v6 = algo->wide_threshold;
	algo->ht = (void *)pfxt;
	return;
}

int h_pfx_add_basic(void *algo_ptr, void * record){
    return hrov_pfx_add_basic((struct hrov_table_basic *)algo_ptr, record);
}

int h_pfx_remove_basic(void *algo_ptr, void * pdu){
    return hrov_pfx_rm_basic((struct hrov_table_basic *)algo_ptr, pdu);
}

int h_pfx_validate_basic(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    return hrov_pfx_validate_basic((struct hrov_table_basic *)algo_ptr,asn,pfx,masklen,res);
}

void h_pfxt_release_basic(void *algo_ptr){
    hrov_memory_release_basic((struct hrov_table_basic *)algo_ptr);
}

void h_memory_check_basic(void *algo_ptr){
    struct hrov_table_basic *ht = (struct hrov_table_basic *)algo_ptr;
    size_t memory_size_v4 = 0;
    size_t memory_size_v6 = 0;
    size_t pfxt_v4 = hashmap_count(ht->sot_v4)*1.25;
    memory_size_v4 += pfxt_v4*sizeof(struct ipv4_asn_info);
    
    size_t pfxt_v6 = hashmap_count(ht->sot_v6)*1.25;
    memory_size_v6 += pfxt_v6*sizeof(struct ip6_t_asn_info);

    size_t pfxt_v4_agg = hashmap_count(ht->stt_v4)*1.25;
    memory_size_v4 += pfxt_v4_agg*sizeof(struct ipv4_complex_info);

    size_t pfxt_v6_agg = hashmap_count(ht->stt_v6)*1.25;
    memory_size_v6 += pfxt_v6_agg*sizeof(struct ip6_t_complex_info);

    size_t pfxt_v4_withdrawn = hashmap_count(ht->rc_sot_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn*sizeof(rcBlock_sot4);

    size_t pfxt_v4_withdrawn_agg = hashmap_count(ht->rc_stt_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn_agg*sizeof(rcBlock_stt4);

    size_t pfxt_v6_withdrawn = hashmap_count(ht->rc_sot_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn*sizeof(rcBlock_sot6);

    size_t pfxt_v6_withdrawn_agg = hashmap_count(ht->rc_stt_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn_agg*sizeof(rcBlock_stt6);

    uint64_t total_size_v4 = memory_size_v4/1024;
    uint64_t total_size_v6 = memory_size_v6/1024;
    puts("memory statistic");
    printf("SOT v4 entry count: %lu\n",pfxt_v4);
    printf("SOT v6 entry count: %lu\n",pfxt_v6);
    printf("STT v4 entry count: %lu\n",pfxt_v4_agg);
    printf("STT v6 entry count: %lu\n",pfxt_v6_agg);
	printf("ipv4 size: %lu KB\n",total_size_v4);
	printf("ipv6 size: %lu KB\n",total_size_v6);
    puts("technical statistics");
    int hroa_count = hashmap_count(ht->sot_v4);
    printf("hroa_count v4: %d\n",hroa_count);
    hroa_count = hashmap_count(ht->sot_v6);
    printf("hroa_count v6: %d\n",hroa_count);
    return;
}

size_t h_memory_check_mute_basic(void *algo_ptr){
    struct hrov_table_basic *ht = (struct hrov_table_basic *)algo_ptr;
    size_t memory_size_v4 = 0;
    size_t memory_size_v6 = 0;
    size_t pfxt_v4 = hashmap_count(ht->sot_v4)*1.25;
    memory_size_v4 += pfxt_v4*sizeof(struct ipv4_asn_info);
    
    size_t pfxt_v6 = hashmap_count(ht->sot_v6)*1.25;
    memory_size_v6 += pfxt_v6*sizeof(struct ip6_t_asn_info);

    size_t pfxt_v4_agg = hashmap_count(ht->stt_v4)*1.25;
    memory_size_v4 += pfxt_v4_agg*sizeof(struct ipv4_complex_info);

    size_t pfxt_v6_agg = hashmap_count(ht->stt_v6)*1.25;
    memory_size_v6 += pfxt_v6_agg*sizeof(struct ip6_t_complex_info);

    size_t pfxt_v4_withdrawn = hashmap_count(ht->rc_sot_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn*sizeof(rcBlock_sot4);

    size_t pfxt_v4_withdrawn_agg = hashmap_count(ht->rc_stt_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn_agg*sizeof(rcBlock_stt4);

    size_t pfxt_v6_withdrawn = hashmap_count(ht->rc_sot_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn*sizeof(rcBlock_sot6);

    size_t pfxt_v6_withdrawn_agg = hashmap_count(ht->rc_stt_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn_agg*sizeof(rcBlock_stt6);
    
    size_t wideasn_v4 = hashmap_count(ht->wide_array_v4_extra->dyheader)*1.25;
    memory_size_v4 += wideasn_v4*sizeof(wideASN_block);

    size_t wideasn_v6 = hashmap_count(ht->wide_array_v6_extra->dyheader)*1.25;
    memory_size_v6 += wideasn_v6*sizeof(wideASN_block);

    patricia_tree_t *tree = ht->wide_tree_v4;
    patricia_node_t *node;
    
    PATRICIA_WALK_ALL(tree->head, node) {
        memory_size_v4 += sizeof(patricia_node_t);
        if(node->prefix) memory_size_v4+=sizeof(prefix_t);
        if(node->data){
            node_data_t *nd = (node_data_t *)node->data;
            memory_size_v4 += sizeof(node_data_t);
            memory_size_v4 += sizeof(ROA)*nd->len;
            
        }
    } PATRICIA_WALK_END;

    tree = ht->wide_tree_v6;
    PATRICIA_WALK_ALL(tree->head, node) {
        memory_size_v6 += sizeof(patricia_node_t);
        if(node->prefix) memory_size_v6+=sizeof(prefix_t);
        if(node->data){
            node_data_t *nd = (node_data_t *)node->data;
            memory_size_v6 += sizeof(node_data_t);
            memory_size_v6 += sizeof(ROA)*nd->len;
            
        }
    } PATRICIA_WALK_END;
    size_t total_size= (memory_size_v4+memory_size_v6)/(1024);
    return total_size;
}

void h_pfxt_print_basic_v4(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_basic *ht = (struct hrov_table_basic *)algo->ht;
    puts("SOT v4");
    while (hashmap_iter(ht->sot_v4, &iter, &item)) {
        const struct ipv4_asn_info *user = item;
        printf("identifier: %x, asn: %u, (bitmap=%x)\n", user->key.addr, user->key.asn,user->bitmap);
    }
    puts("STT v4");
    iter=0;
    while (hashmap_iter(ht->stt_v4, &iter, &item)) {
        const struct ipv4_complex_info *user = item;
        printf("identifier: %x, bitmap=%x, wideROA flag: %d, withdrawn flag: %d\n", user->key, user->bm.bitmap, user->bm.wideROA_flag, user->bm.withdrawn_flag);
    }
    puts("-------------------");
}

void h_pfxt_print_basic_v6(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_basic *ht = (struct hrov_table_basic *)algo->ht;
    puts("SOT v6");
    while (hashmap_iter(ht->sot_v6, &iter, &item)) {
        const struct ip6_t_asn_info *user = item;
        printf("identifier: %x %x %x %x, asn: %u (bitmap=%x)\n", user->key.addr.u_ip6.u_ip6_addr32[0],  user->key.addr.u_ip6.u_ip6_addr32[1], user->key.addr.u_ip6.u_ip6_addr32[2], user->key.addr.u_ip6.u_ip6_addr32[3],user->key.asn,user->bitmap);
    }
    puts("STT v6");
    iter=0;
    while (hashmap_iter(ht->stt_v6, &iter, &item)) {
        const struct ip6_t_complex_info *user = item;
        printf("identifer: %x %x %x %x, bitmap=%x, withdrawn flag=%d, wideROA flag=%d\n", user->key.u_ip6.u_ip6_addr32[0],  user->key.u_ip6.u_ip6_addr32[1], user->key.u_ip6.u_ip6_addr32[2], user->key.u_ip6.u_ip6_addr32[3],user->bm.bitmap,user->bm.withdrawn_flag,user->bm.wideROA_flag);
    }
    puts("-------------------");
}

void h_pfxt_print_nl_v4(struct rov_algo_t *algo){
    struct hrov_table_basic *ht = (struct hrov_table_basic *)algo->ht;
    puts("wide table v4:");
}

void hrov_table_basic_print(void *algo){
    struct hrov_table_basic *ht = (struct hrov_table_basic*)algo;
    size_t iter = 0;
    void *item;
    // puts("SOT v4");
    // while (hashmap_iter(ht->pfxt_v4, &iter, &item)) {
    //     const ip_addr_v4_info *user = item;
    //     printf("identifier: %x, asn: %u, (bitmap=%x)\n", user->key.addr, user->key.asn,user->bitmap);
    // }
    // iter=0;
    // puts("STT v4");
    // while (hashmap_iter(ht->pfxt_v4_agg, &iter, &item)) {
    //     const struct ip_addr_agg_v4_info_bmb *user = item;
    //     printf("identifier: %x, bitmap=%x, wideROA flag: %d, withdrawn flag: %d\n", user->key.addr, user->bm.bitmap, user->bm.wideROA_flag, user->bm.withdrawn_flag);
    // }
    // puts("-------------------");
    // iter=0;
    // puts("widearray v4");
    // while (hashmap_iter(ht->wide_array_v4->dyheader, &iter, &item)) {
    //     const wideBlock4 *user = item;
    //     int header = user->header, position = user->body.index, num=user->body.num;
    //     printf("identifier: %x, position: %d, size: %d\n",user->header,user->body.index,user->body.num);
    //     // printf("%d\n",user->body.num);
    //     for(int i=0;i<num;i++){
    //         int hanging_level = ht->wide_array_v4->dyarray->data[position+i].masklen - ht->wide_array_v4->dyarray->data[position+i].masklen%5;
    //         w4 tmp = ht->wide_array_v4->dyarray->data[position+i];
    //         printf("pfx: %x, masklen: %d, maxlen: %d, asn: %u\n",tmp.pfx,tmp.masklen,tmp.maxlen,tmp.asn);
    //     }
    // }
    // iter = 0;
    // puts("SOT v6");
    // while (hashmap_iter(ht->pfxt_v6, &iter, &item)) {
    //     const ipv6_asn_info *user = item;
    //     printf("identifier: %x %x %x %x, asn: %u (bitmap=%x)\n", user->key.addr.addr[0],  user->key.addr.addr[1], user->key.addr.addr[2], user->key.addr.addr[3],user->key.asn,user->bitmap);
    // }
    // iter=0;
    // puts("STT v6");
    // while (hashmap_iter(ht->pfxt_v6_agg, &iter, &item)) {
    //     const struct ipv6_complex_info *user = item;
    //     printf("identifer: %x %x %x %x, bitmap=%x, withdrawn flag=%d, wideROA flag=%d\n", user->key.addr[0],  user->key.addr[1], user->key.addr[2], user->key.addr[3],user->bm.bitmap,user->bm.withdrawn_flag,user->bm.wideROA_flag);
    // }
    // puts("-------------------");
    // iter = 0;
    // puts("wideArray_v6");
    // while (hashmap_iter(ht->wide_array_v6->dyheader, &iter, &item)) {
    //     const wideBlock6 *user = item;
    //     ipv6 header = user->header;
    //     int position = user->body.index, num=user->body.num;
    //     printf("identifier: ");
    //     SHOW_IPV6_oct(header.addr);
    //     printf("position: %d, size: %d\n",user->body.index,user->body.num);
    //     // printf("%d\n",user->body.num);
    //     for(int i=0;i<num;i++){
    //         int hanging_level = ht->wide_array_v6->dyarray->data[position+i].masklen - ht->wide_array_v6->dyarray->data[position+i].masklen%5;
    //         w6 tmp = ht->wide_array_v6->dyarray->data[position+i];
    //         printf("prefix: ");
    //         SHOW_IPV6_oct(tmp.pfx.addr);
    //         printf("masklen: %d, maxlen: %d, asn: %u\n",tmp.masklen,tmp.maxlen,tmp.asn);
    //     }
    //     puts("------------");
    // }
}

void h_pfxt_print_basic(struct rov_algo_t *algo){
    struct hrov_table_basic *ht = (struct hrov_table_basic*)algo->ht;
    h_pfxt_print_basic_v4(algo);
    // h_pfxt_print_basic_v6(algo);
    // wideArray_print_v6(ht->wide_array_v6);
    // wc_print(ht->wc);
    // puts("------------------");
}

void h_pfxt_print_binary_v4(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_binary *ht = (struct hrov_table_binary *)algo->ht;
    puts("SOT");
    while (hashmap_iter(ht->sot_v4, &iter, &item)) {
        const struct ipv4_asn_info *user = item;
        printf("ipaddr: %x, asn: %u, bitmap: %x\n", user->key.addr, user->key.asn, user->bitmap);
    }
    puts("-------------------");
    puts("STT");
    iter = 0;
    while (hashmap_iter(ht->stt_v4, &iter, &item)) {
        const struct ipv4_complex_info *user = item;
        printf("ipaddr: %x, bitmap: %x, withdrawn_flag: %u, wide_flag: %u\n", user->key, user->bm.bitmap, user->bm.withdrawn_flag, user->bm.wideROA_flag);
    }
    puts("-------------------");
}

void h_pfxt_print_wide_v4(struct rov_algo_t *algo){
    struct hrov_table_binary *ht = (struct hrov_table_binary *)algo->ht;
    wideArray_print_v4(ht->wide_array_v4);
}

void h_pfxt_print_child_bitmap_v4(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_binary *ht = (struct hrov_table_binary *)algo->ht;
    puts("child info");
    while (hashmap_iter(ht->child_bitmap_v4, &iter, &item)) {
        const struct ipv4_info *user = item;
        SHOW_IPV4_oct(user->key);
        printf("child bitmap %x\n",user->bm);
    }
}

void h_pfxt_print_binary_v6(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_binary *ht = (struct hrov_table_binary *)algo->ht;
    puts("SOT");
    while (hashmap_iter(ht->sot_v6, &iter, &item)) {
        const struct ip6_t_asn_info *user = item;
        printf("ipaddr: %x %x %x %x, asn: %u, bitmap: %x\n", user->key.addr.u_ip6.u_ip6_addr32[0],user->key.addr.u_ip6.u_ip6_addr32[1],user->key.addr.u_ip6.u_ip6_addr32[2],user->key.addr.u_ip6.u_ip6_addr32[3], user->key.asn, user->bitmap);
    }
    puts("-------------------");
    puts("STT");
    iter = 0;
    while (hashmap_iter(ht->stt_v6, &iter, &item)) {
        const struct ip6_t_complex_info *user = item;
        printf("ipaddr: %x %x %x %x, bitmap: %x, withdrawn_flag: %u, wide_flag: %u\n", user->key.u_ip6.u_ip6_addr32[0],user->key.u_ip6.u_ip6_addr32[1],user->key.u_ip6.u_ip6_addr32[2],user->key.u_ip6.u_ip6_addr32[3], user->bm.bitmap, user->bm.withdrawn_flag, user->bm.wideROA_flag);
    }
    puts("-------------------");
}

void h_pfxt_print_wide_v6(struct rov_algo_t *algo){
    struct hrov_table_binary *ht = (struct hrov_table_binary *)algo->ht;
    wideArray_print_v6(ht->wide_array_v6);
}

void h_pfxt_print_child_bitmap_v6(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_binary *ht = (struct hrov_table_binary *)algo->ht;
    puts("child info");
    while (hashmap_iter(ht->child_bitmap_v6, &iter, &item)) {
        const struct ip6_t_info *user = item;
        SHOW_IPV6_oct(user->key.u_ip6.u_ip6_addr32);
        printf("child bitmap %x\n",user->bm);
    }
}

void h_pfxt_print_binary(struct rov_algo_t *algo){
    h_pfxt_print_binary_v4(algo);  
    h_pfxt_print_wide_v4(algo);
    h_pfxt_print_child_bitmap_v4(algo);
    h_pfxt_print_binary_v6(algo);
    h_pfxt_print_wide_v6(algo);
    h_pfxt_print_child_bitmap_v6(algo);
}

void h_pfxt_init_binary(struct rov_algo_t *algo){
    struct hrov_table_binary *pfxt = (struct hrov_table_binary *)malloc(sizeof(struct hrov_table_binary));
	hrov_pfxt_init_binary(pfxt);
	algo->ht = (void *)pfxt;
    return;
}

int h_pfx_add_binary(void *algo_ptr, void * record){
    return hrov_pfx_add_binary((struct hrov_table_binary *)algo_ptr,record);
}

int h_pfx_remove_binary(void *algo_ptr, void * pdu){
    return hrov_pfx_rm_binary((struct hrov_table_binary *)algo_ptr,pdu);
}
int h_pfx_validate_binary(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    return hrov_pfx_validate_binary((struct hrov_table_binary *)algo_ptr,asn,pfx,masklen,res);
}
void h_pfxt_release_binary(void *algo_ptr){
    hrov_memory_release_binary((struct hrov_table_binary *)algo_ptr);
}
void h_memory_check_binary(void *algo_ptr){
    struct hrov_table_binary *ht = (struct hrov_table_binary *)algo_ptr;
    size_t memory_size_v4 = 0;
    size_t memory_size_v6 = 0;
    size_t pfxt_v4 = hashmap_count(ht->sot_v4)*1.25;
    memory_size_v4 += pfxt_v4*sizeof(struct ipv4_asn_info);

    size_t pfxt_v6 = hashmap_count(ht->sot_v6)*1.25;
    memory_size_v6 += pfxt_v6*sizeof(struct ip6_t_asn_info);

    size_t pfxt_v4_agg = hashmap_count(ht->stt_v4)*1.25;
    memory_size_v4 += pfxt_v4_agg*sizeof(struct ipv4_complex_info);

    size_t pfxt_v6_agg = hashmap_count(ht->stt_v6)*1.25;
    memory_size_v6 += pfxt_v6_agg*sizeof(struct ip6_t_complex_info);

    size_t pfxt_v4_withdrawn = hashmap_count(ht->rc_sot_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn*sizeof(rcBlock_sot4);

    size_t pfxt_v4_withdrawn_agg = hashmap_count(ht->rc_stt_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn_agg*sizeof(rcBlock_stt4);

    size_t pfxt_v6_withdrawn = hashmap_count(ht->rc_sot_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn*sizeof(rcBlock_sot6);

    size_t pfxt_v6_withdrawn_agg = hashmap_count(ht->rc_stt_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn_agg*sizeof(rcBlock_stt6);

    size_t child_bitmap_v4 = hashmap_count(ht->child_bitmap_v4)*1.25;
    memory_size_v4 += child_bitmap_v4*sizeof(struct ipv4_info);
    
    size_t child_bitmap_v6 = hashmap_count(ht->child_bitmap_v6)*1.25;
    memory_size_v6 += child_bitmap_v6*sizeof(struct ip6_t_info);

    size_t wide_array_v4 = 0;
    size_t wide_array_v4_dyheader = hashmap_count(ht->wide_array_v4->dyheader)*1.25;
    wide_array_v4 += wide_array_v4_dyheader*sizeof(wideBlock4);
    size_t iter = 0;
    void *item;
    while (hashmap_iter(ht->wide_array_v4->dyheader, &iter, &item)) {
        const wideBlock4 *user = item;
        struct sc_array_w4 arr = user->body;
        wide_array_v4+= sc_array_size(&arr)*(sizeof(w4));
    }
    memory_size_v4 += wide_array_v4;

    size_t wide_array_v6 = 0;
    size_t wide_array_v6_dyheader = hashmap_count(ht->wide_array_v6->dyheader)*1.25;
    wide_array_v6 += wide_array_v6_dyheader*sizeof(wideBlock6);
    iter = 0;
    while (hashmap_iter(ht->wide_array_v6->dyheader, &iter, &item)) {
        const wideBlock6 *user = item;
        struct sc_array_w6 arr = user->body;
        wide_array_v6+= sc_array_size(&arr)*(sizeof(w6));
    }
    memory_size_v6 += wide_array_v6;

    uint64_t total_size_v4 = memory_size_v4/1024;
    uint64_t total_size_v6 = memory_size_v6/1024;

	printf("ipv4 size: %lu KB\n",total_size_v4);
	printf("ipv6 size: %lu KB\n",total_size_v6);
    return;
}

size_t h_memory_check_mute_binary(void *algo_ptr){
    struct hrov_table_binary *ht = (struct hrov_table_binary *)algo_ptr;
    size_t memory_size_v4 = 0;
    size_t memory_size_v6 = 0;
    size_t pfxt_v4 = hashmap_count(ht->sot_v4)*1.25;
    memory_size_v4 += pfxt_v4*sizeof(struct ipv4_asn_info);
    
    size_t pfxt_v6 = hashmap_count(ht->sot_v6)*1.25;
    memory_size_v6 += pfxt_v6*sizeof(struct ip6_t_asn_info);

    size_t pfxt_v4_agg = hashmap_count(ht->stt_v4)*1.25;
    memory_size_v4 += pfxt_v4_agg*sizeof(struct ipv4_complex_info);

    size_t pfxt_v6_agg = hashmap_count(ht->stt_v6)*1.25;
    memory_size_v6 += pfxt_v6_agg*sizeof(struct ip6_t_complex_info);

    size_t pfxt_v4_withdrawn = hashmap_count(ht->rc_sot_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn*sizeof(rcBlock_sot4);

    size_t pfxt_v4_withdrawn_agg = hashmap_count(ht->rc_stt_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn_agg*sizeof(rcBlock_stt4);

    size_t pfxt_v6_withdrawn = hashmap_count(ht->rc_sot_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn*sizeof(rcBlock_sot6);

    size_t pfxt_v6_withdrawn_agg = hashmap_count(ht->rc_stt_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn_agg*sizeof(rcBlock_stt6);

    size_t child_bitmap_v4 = hashmap_count(ht->child_bitmap_v4)*1.25;
    memory_size_v4 += child_bitmap_v4*sizeof(struct ipv4_info);
    
    size_t child_bitmap_v6 = hashmap_count(ht->child_bitmap_v6)*1.25;
    memory_size_v6 += child_bitmap_v6*sizeof(struct ip6_t_info);

    size_t wide_array_v4 = 0;
    size_t wide_array_v4_dyheader = hashmap_count(ht->wide_array_v4->dyheader)*1.25;
    wide_array_v4 += wide_array_v4_dyheader*sizeof(wideBlock4);
    size_t iter = 0;
    void *item;
    while (hashmap_iter(ht->wide_array_v4->dyheader, &iter, &item)) {
        const wideBlock4 *user = item;
        struct sc_array_w4 arr = user->body;
        wide_array_v4+= sc_array_size(&arr)*(sizeof(w4));
    }
    memory_size_v4 += wide_array_v4;

    size_t wide_array_v6 = 0;
    size_t wide_array_v6_dyheader = hashmap_count(ht->wide_array_v6->dyheader)*1.25;
    wide_array_v6 += wide_array_v6_dyheader*sizeof(wideBlock6);
    iter = 0;
    while (hashmap_iter(ht->wide_array_v6->dyheader, &iter, &item)) {
        const wideBlock6 *user = item;
        struct sc_array_w6 arr = user->body;
        wide_array_v6+= sc_array_size(&arr)*(sizeof(w6));
    }
    memory_size_v6 += wide_array_v6;

    size_t total_size = (memory_size_v4+memory_size_v6)/(1024*1024);
    return total_size;
}

void h_pfxt_print_wc_v4_nlbs(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_nlbs *ht = (struct hrov_table_nlbs *)algo->ht;
    rc_sot4_print(ht->rc_sot_v4);
    rc_sot6_print(ht->rc_sot_v6);
    rc_stt4_print(ht->rc_stt_v4);
    rc_stt6_print(ht->rc_stt_v6);
}

void h_pfxt_print_v4_nlbs(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_nlbs *ht = (struct hrov_table_nlbs *)algo->ht;
    puts("SOT v4");
    while (hashmap_iter(ht->sot_v4, &iter, &item)) {
        const struct ipv4_asn_info *user = item;
        printf("identifier: %x, asn: %u, (bitmap=%x)\n", user->key.addr, user->key.asn,user->bitmap);
    }
    puts("STT v4");
    iter=0;
    while (hashmap_iter(ht->stt_v4, &iter, &item)) {
        const struct ipv4_info *user = item;
        printf("identifier: %x, (bitmap=%x)\n", user->key, user->bm);
    }
    puts("-------------------");
    puts("WRT");
    patricia_tree_t *tree = ht->wide_tree_v4;
    patricia_node_t *node;
   
    PATRICIA_WALK_ALL(tree->head, node) {
        if(node->prefix) printf("prefix:%x\n",node->prefix->add.sin.s_addr);
        if(node->data){
            node_data_t *nd = (node_data_t *)node->data;
            for(int i = 0;i<nd->len;i++){
                printf("%d,%u\n",nd->ary[i].maxlen,nd->ary[i].asn);
            }
        }
    } PATRICIA_WALK_END;
    puts("-------------------");
    puts("rc");
    h_pfxt_print_wc_v4_nlbs(algo);
}

void h_pfxt_print_nlbs_v6(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_nlbs *ht = (struct hrov_table_nlbs *)algo->ht;
    puts("SOT");
    while (hashmap_iter(ht->sot_v6, &iter, &item)) {
        const struct ip6_t_asn_info *user = item;
        printf("ipaddr: %x %x %x %x, asn: %u, bitmap: %x\n", user->key.addr.u_ip6.u_ip6_addr32[0],user->key.addr.u_ip6.u_ip6_addr32[1],user->key.addr.u_ip6.u_ip6_addr32[2],user->key.addr.u_ip6.u_ip6_addr32[3], user->key.asn, user->bitmap);
    }
    puts("-------------------");
    puts("STT");
    iter = 0;
    while (hashmap_iter(ht->stt_v6, &iter, &item)) {
        const struct ip6_t_complex_info *user = item;
        printf("ipaddr: %x %x %x %x, bitmap: %x, withdrawn_flag: %u, wide_flag: %u\n", user->key.u_ip6.u_ip6_addr32[0],user->key.u_ip6.u_ip6_addr32[1],user->key.u_ip6.u_ip6_addr32[2],user->key.u_ip6.u_ip6_addr32[3], user->bm.bitmap, user->bm.withdrawn_flag, user->bm.wideROA_flag);
    }
}

void h_pfxt_print_wide_v6_nlbs(struct rov_algo_t *algo){
    struct hrov_table_nlbs *ht = (struct hrov_table_nlbs *)algo->ht;
    // wideArray_print_v6(ht->wide_array_v6);
}

void h_pfxt_print_child_bitmap_v6_nlbs(struct rov_algo_t *algo){
    size_t iter = 0;
    void *item;
    struct hrov_table_nlbs *ht = (struct hrov_table_nlbs *)algo->ht;
    puts("child info");
    while (hashmap_iter(ht->child_bitmap_v6, &iter, &item)) {
        const struct ip6_t_info *user = item;
        SHOW_IPV6_oct(user->key.u_ip6.u_ip6_addr32);
        printf("child bitmap %x\n",user->bm);
    }
}

void h_pfxt_print_nlbs(struct rov_algo_t *algo){
    struct hrov_table_nlbs *ht = (struct hrov_table_nlbs *)algo->ht;
    h_pfxt_print_v4_nlbs(algo);
    h_pfxt_print_nlbs_v6(algo);
    wideASN_print(ht->wide_array_v4_extra);
    wideASN_print(ht->wide_array_v6_extra);
    // h_pfxt_print_wide_v6_nlbs(algo);
    // h_pfxt_print_child_bitmap_v6_nlbs(algo);
    // h_pfxt_print_hash_v4_nlbs(algo);
    // h_pfxt_print_wc_v4_nlbs(algo);
    // struct hrov_table_nlbs *ht = (struct hrov_table_nlbs *)algo->ht;
    // lvl_bm_print_level(ht->lb,5);
    // lvl_bm_print_level(ht->lb,10);
    // lvl_bm_print_level(ht->lb,15);
    // lvl_bm_print_level(ht->lb,20);
    // puts("----------------------");
    // path_bm_print_level(ht->pb,5);
    // path_bm_print_level(ht->pb,10);
    // path_bm_print_level(ht->pb,15);
    // path_bm_print_level(ht->pb,20);
}

void h_pfxt_init_nlbs(struct rov_algo_t *algo){
    struct hrov_table_nlbs *pfxt = (struct hrov_table_nlbs *)malloc(sizeof(struct hrov_table_nlbs));
	hrov_pfxt_init_nlbs(pfxt);
    pfxt->widelen_v4 = algo->wide_threshold;
    pfxt->widelen_v6 = algo->wide_threshold;
	algo->ht = (void *)pfxt;
    return;
}

int h_pfx_add_nlbs(void *algo_ptr, void * record){
    return hrov_pfx_add_nlbs((struct hrov_table_nlbs *)algo_ptr,record);
}

int h_pfx_remove_nlbs(void *algo_ptr, void * pdu){
    return hrov_pfx_rm_nlbs((struct hrov_table_nlbs *)algo_ptr,pdu);
}

int h_pfx_validate_nlbs(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    return hrov_pfx_validate_nlbs((struct hrov_table_nlbs *)algo_ptr,asn,pfx,masklen,res);
}

void h_pfxt_release_nlbs(void *algo_ptr){
    hrov_memory_release_nlbs((struct hrov_table_nlbs *)algo_ptr);
}

void h_memory_check_nlbs(void *algo_ptr){
    struct hrov_table_nlbs *ht = (struct hrov_table_nlbs *)algo_ptr;
    size_t memory_size_v4 = 0;
    size_t memory_size_v6 = 0;
    // size_t pfxt_v4 = hashmap_count(ht->sot_v4)*1.25;
    // memory_size_v4 += pfxt_v4*sizeof(struct ipv4_asn_info);

    size_t pfxt_v6 = hashmap_count(ht->sot_v6)*1.25;
    memory_size_v6 += pfxt_v6*sizeof(struct ip6_t_asn_info);

    size_t pfxt_v4_agg = hashmap_count(ht->stt_v4)*1.25;
    memory_size_v4 += pfxt_v4_agg*sizeof(struct ipv4_complex_info);

    size_t pfxt_v6_agg = hashmap_count(ht->stt_v6)*1.25;
    memory_size_v6 += pfxt_v6_agg*sizeof(struct ip6_t_complex_info);

    size_t pfxt_v4_withdrawn = hashmap_count(ht->rc_sot_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn*sizeof(rcBlock_sot4);

    size_t pfxt_v4_withdrawn_agg = hashmap_count(ht->rc_stt_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn_agg*sizeof(rcBlock_stt4);

    size_t pfxt_v6_withdrawn = hashmap_count(ht->rc_sot_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn*sizeof(rcBlock_sot6);

    size_t pfxt_v6_withdrawn_agg = hashmap_count(ht->rc_stt_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn_agg*sizeof(rcBlock_stt6);

    size_t child_bitmap_v6 = hashmap_count(ht->child_bitmap_v6)*1.25;
    memory_size_v6 += child_bitmap_v6*sizeof(struct ip6_t_info);

    memory_size_v4 += sizeof(uint8_t)*TOTAL;
    // if(wide_array_v4_dyheader>0){
    //     memory_size_v4 += sizeof(uint8_t)*TOTAL*5;
    // }
    
    uint64_t total_size_v4 = memory_size_v4/1024;
    uint64_t total_size_v6 = memory_size_v6/1024;
    // printf("SOT v4 entry count: %lu\n",pfxt_v4);
    printf("SOT v6 entry count: %lu\n",pfxt_v6);
    printf("STT v4 entry count: %lu\n",pfxt_v4_agg);
    printf("STT v6 entry count: %lu\n",pfxt_v6_agg);
	printf("ipv4 size: %lu KB\n",total_size_v4);
	printf("ipv6 size: %lu KB\n",total_size_v6);
    // printf("part 1 timer: %f\n",ht->wide_v4_timer_part1);
    // printf("part 2 timer: %f\n",ht->wide_v4_timer_part2);

    return;
}

size_t h_memory_check_mute_nlbs(void *algo_ptr){
    struct hrov_table_nlbs *ht = (struct hrov_table_nlbs *)algo_ptr;
    size_t memory_size_v4 = 0;
    size_t memory_size_v6 = 0;
    size_t pfxt_v4 = hashmap_count(ht->sot_v4)*1.25;
    memory_size_v4 += pfxt_v4*sizeof(struct ipv4_asn_info);

    size_t pfxt_v6 = hashmap_count(ht->sot_v6)*1.25;
    memory_size_v6 += pfxt_v6*sizeof(struct ip6_t_asn_info);

    size_t pfxt_v4_agg = hashmap_count(ht->stt_v4)*1.25;
    memory_size_v4 += pfxt_v4_agg*sizeof(struct ipv4_complex_info);

    size_t pfxt_v6_agg = hashmap_count(ht->stt_v6)*1.25;
    memory_size_v6 += pfxt_v6_agg*sizeof(struct ip6_t_complex_info);

    size_t pfxt_v4_withdrawn = hashmap_count(ht->rc_sot_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn*sizeof(rcBlock_sot4);

    size_t pfxt_v4_withdrawn_agg = hashmap_count(ht->rc_stt_v4->map)*1.25;
    memory_size_v4 += pfxt_v4_withdrawn_agg*sizeof(rcBlock_stt4);

    size_t pfxt_v6_withdrawn = hashmap_count(ht->rc_sot_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn*sizeof(rcBlock_sot6);

    size_t pfxt_v6_withdrawn_agg = hashmap_count(ht->rc_stt_v6->map)*1.25;
    memory_size_v6 += pfxt_v6_withdrawn_agg*sizeof(rcBlock_stt6);

    size_t child_bitmap_v6 = hashmap_count(ht->child_bitmap_v6)*1.25;
    memory_size_v6 += child_bitmap_v6*sizeof(struct ip6_t_info);

    size_t wideasn_v4 = hashmap_count(ht->wide_array_v4_extra->dyheader)*1.25;
    memory_size_v4 += wideasn_v4*sizeof(wideASN_block);

     size_t wideasn_v6 = hashmap_count(ht->wide_array_v6_extra->dyheader)*1.25;
    memory_size_v6 += wideasn_v6*sizeof(wideASN_block);

    patricia_tree_t *tree = ht->wide_tree_v4;
    patricia_node_t *node;
   
    PATRICIA_WALK_ALL(tree->head, node) {
        memory_size_v4 += sizeof(patricia_node_t);
        if(node->prefix) memory_size_v4+=sizeof(prefix_t);
        if(node->data){
            node_data_t *nd = (node_data_t *)node->data;
            memory_size_v4 += sizeof(node_data_t);
            memory_size_v4 += sizeof(ROA)*nd->len;
            
        }
    } PATRICIA_WALK_END;

    tree = ht->wide_tree_v6;
   
    PATRICIA_WALK_ALL(tree->head, node) {
        memory_size_v6 += sizeof(patricia_node_t);
        if(node->prefix) memory_size_v6+=sizeof(prefix_t);
        if(node->data){
            node_data_t *nd = (node_data_t *)node->data;
            memory_size_v6 += sizeof(node_data_t);
            memory_size_v6 += sizeof(ROA)*nd->len;
            
        }
    } PATRICIA_WALK_END;
    
    memory_size_v4 += sizeof(uint8_t)*TOTAL;
    
    uint64_t total_size_v4 = memory_size_v4/1024;
    uint64_t total_size_v6 = memory_size_v6/1024;
    size_t total_size = (memory_size_v4+memory_size_v6)/(1024);
    return total_size;
}




// void h_pfxt_print_lbs(struct rov_algo_t *algo){

// }

// void h_pfxt_init_lbs(struct rov_algo_t *algo){
//     struct hrov_table_lbs *pfxt = (struct hrov_table_lbs *)malloc(sizeof(struct hrov_table_lbs));
// 	hrov_pfxt_init_lbs(pfxt);
// 	algo->ht = (void *)pfxt;
//     return;
// }

// int h_pfx_add_lbs(void *algo_ptr, void * record){
//     return hrov_pfx_add_lbs((struct hrov_table_lbs *)algo_ptr,record);
// }

// int h_pfx_remove_lbs(void *algo_ptr, void * pdu){
//     return hrov_pfx_rm_lbs((struct hrov_table_lbs *)algo_ptr,pdu);
// }

// int h_pfx_validate_lbs(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
//     return hrov_pfx_validate_lbs((struct hrov_table_lbs *)algo_ptr,asn,pfx,masklen,res);
// }

// void h_pfxt_release_lbs(void *algo_ptr){
//     hrov_memory_release_lbs((struct hrov_table_lbs *)algo_ptr);
// }

// void h_memory_check_lbs(void *algo_ptr){
//     hrov_memory_check_lbs((struct hrov_table_lbs *)algo_ptr);
// }
