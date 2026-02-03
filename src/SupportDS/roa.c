#include "roa.h"

void pt_init(pt_table *table){
    table->roa_table_ipv4 = New_Patricia(32);
    table->roa_table_ipv6 = New_Patricia(128);
    return;
}

// bool pt_insert_into_tree(patricia_tree_t *roa_table, prefix_t lookupPrefix, int maxlen, uint32_t asn){
//     patricia_node_t* treeNode = NULL;
//     treeNode = patricia_lookup(roa_table,&lookupPrefix);
//     if(treeNode == NULL){
//         return false;
//     }
//     // printf("%x\n",treeNode->prefix->add.sin.s_addr);
//     if(!treeNode->data){
//         treeNode->data = malloc(sizeof(SList));
//         initSList((SList *)treeNode->data);
//     }
//     ROA *roa = malloc(sizeof(ROA));
//     roa->asn = asn;
//     roa->maxlen = maxlen;
//     if(!appendDataToSList((SList *)treeNode->data,roa)) return false;
//     // SList *shead = (SList *)treeNode->data;
//     // printf("%d\n",shead->size);
//     // SListNode* roaListNode;
//     // FOREACH_SLIST((SList *)treeNode->data, roaListNode)
//     // {
//     //     ROA *roa = (ROA *)roaListNode->data;
//     //     printf("%u %d\n",roa->asn,roa->maxlen);
//     // }
//     return true;
// }

int append_elem(node_data_t *data, const ROA *record)
{
	ROA *tmp = realloc(data->ary, sizeof(ROA) * ((data->len) + 1));

	if (!tmp)
		return PFX_ERROR;
	data->len++;
	data->ary = tmp;
	data->ary[data->len - 1].asn = record->asn;
	data->ary[data->len - 1].maxlen = record->maxlen;
	return 1;
}

int delete_elem(node_data_t *data, const unsigned int index)
{
	ROA *tmp;
	ROA deleted_elem = data->ary[index];

	// if index is not the last elem in the list, move all other elems backwards in the array
	if (index != data->len - 1) {
		for (unsigned int i = index; i < data->len - 1; i++)
			data->ary[i] = data->ary[i + 1];
	}

	data->len--;
	if (!data->len) {
		free(data->ary);
		data->ary = NULL;
		return PFX_SUCCESS;
	}

	tmp = realloc(data->ary, sizeof(ROA) * data->len);
	if (!tmp) {
		data->ary[data->len] = deleted_elem;
		data->len++;
		return PFX_ERROR;
	}

	data->ary = tmp;

	return PFX_SUCCESS;
}

bool pt_insert_into_tree(patricia_tree_t *roa_table, prefix_t lookupPrefix, int maxlen, uint32_t asn){
    patricia_node_t* treeNode = NULL;
    treeNode = patricia_lookup(roa_table,&lookupPrefix);
    if(treeNode == NULL){
        return false;
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
    if(!append_elem((node_data_t *)treeNode->data,roa)) return false;
    return true;
}

bool pt_delete_into_tree(patricia_tree_t *roa_table, prefix_t lookupPrefix, int maxlen, uint32_t asn){
    patricia_node_t* treeNode = NULL;
    treeNode = patricia_lookup(roa_table,&lookupPrefix);
    if(treeNode == NULL){
        return false;
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
        if(index==-1) return false;
        delete_elem((node_data_t *)treeNode->data,index);
        if(roaListNode->len==0){
            patricia_remove(roa_table,treeNode);
        }
        return true;
    }
    else{
        return false;
    }
}

int pt_insert(pt_table *table, void *pdu){
    const int type = *((char *)pdu + 1);
    bool res = false;
    if(type == TROA_IPV4){
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        prefix_t lookupPrefix;
        lookupPrefix.family = AF_INET;
        lookupPrefix.bitlen = ipv4->prefix_len;
        lookupPrefix.add.sin.s_addr = htonl(ipv4->prefix);
        lookupPrefix.ref_count = 0;
        res = pt_insert_into_tree(table->roa_table_ipv4,lookupPrefix,ipv4->max_prefix_len,ipv4->asn);
    }
    else if (type == TROA_IPV6)
    {
        const struct pdu_ipv6 *ipv6 = (const struct pdu_ipv6 *)pdu;
        prefix_t lookupPrefix;
        lookupPrefix.family = AF_INET6;
        lookupPrefix.bitlen = ipv6->prefix_len;
        for(int i=0;i<4;i++){
            lookupPrefix.add.sin6.__in6_u.__u6_addr32[i] = htonl(ipv6->prefix[i]);
        }
        // memcpy(lookupPrefix.add.sin6.__in6_u.__u6_addr32,ipv6->prefix,sizeof(uint32_t)*4);
        lookupPrefix.ref_count = 0;
        res = pt_insert_into_tree(table->roa_table_ipv6,lookupPrefix,ipv6->max_prefix_len,ipv6->asn);
    }
    else if (type == HROV_IPV4){
		struct hpdu_ipv4 *ipv4 = (struct hpdu_ipv4 *)pdu;
		struct sc_array_pdu_ipv4 arr;
    	sc_array_init(&arr);
		parse_hpdu_v4(ipv4,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
			prefix_t lookupPrefix;
            lookupPrefix.family = AF_INET;
            lookupPrefix.bitlen = arr.elems[i].prefix_len;
            lookupPrefix.add.sin.s_addr = htonl(arr.elems[i].prefix);
            lookupPrefix.ref_count = 0;
            res = pt_insert_into_tree(table->roa_table_ipv4,lookupPrefix,arr.elems[i].max_prefix_len,arr.elems[i].asn);
		}
	} 
    else if (type == HROV_IPV6){
		struct hpdu_ipv6 *ipv6 = (struct hpdu_ipv6 *)pdu;
		struct sc_array_pdu_ipv6 arr;
    	sc_array_init(&arr);
		parse_hpdu_v6(ipv6,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
			prefix_t lookupPrefix;
            lookupPrefix.family = AF_INET6;
            lookupPrefix.bitlen = arr.elems[i].prefix_len;
            for(int i=0;i<4;i++){
                lookupPrefix.add.sin6.__in6_u.__u6_addr32[i] = htonl(arr.elems[i].prefix[i]);
            }
            // memcpy(lookupPrefix.add.sin6.__in6_u.__u6_addr32,ipv6->prefix,sizeof(uint32_t)*4);
            lookupPrefix.ref_count = 0;
			res = pt_insert_into_tree(table->roa_table_ipv6,lookupPrefix,arr.elems[i].max_prefix_len,arr.elems[i].asn);
		}
	}
    if(res){
        return SUCCESS;
    }
    else{
        return ERROR;
    }
}

int pt_remove(pt_table *table, void *pdu){
    const int type = *((char *)pdu + 1);
    bool res = false;
    if(type == TROA_IPV4){
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        prefix_t lookupPrefix;
        lookupPrefix.family = AF_INET;
        lookupPrefix.bitlen = ipv4->prefix_len;
        lookupPrefix.add.sin.s_addr = htonl(ipv4->prefix);
        lookupPrefix.ref_count = 0;
        res = pt_delete_into_tree(table->roa_table_ipv4,lookupPrefix,ipv4->max_prefix_len,ipv4->asn);
    }
    else if (type == TROA_IPV6)
    {
        const struct pdu_ipv6 *ipv6 = (const struct pdu_ipv6 *)pdu;
        prefix_t lookupPrefix;
        lookupPrefix.family = AF_INET6;
        lookupPrefix.bitlen = ipv6->prefix_len;
        for(int i=0;i<4;i++){
            lookupPrefix.add.sin6.__in6_u.__u6_addr32[i] = htonl(ipv6->prefix[i]);
        }
        // memcpy(lookupPrefix.add.sin6.__in6_u.__u6_addr32,ipv6->prefix,sizeof(uint32_t)*4);
        lookupPrefix.ref_count = 0;
        res = pt_delete_into_tree(table->roa_table_ipv6,lookupPrefix,ipv6->max_prefix_len,ipv6->asn);
    }
    else if (type == HROV_IPV4){
		struct hpdu_ipv4 *ipv4 = (struct hpdu_ipv4 *)pdu;
		struct sc_array_pdu_ipv4 arr;
    	sc_array_init(&arr);
		parse_hpdu_v4(ipv4,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
			prefix_t lookupPrefix;
            lookupPrefix.family = AF_INET;
            lookupPrefix.bitlen = arr.elems[i].prefix_len;
            lookupPrefix.add.sin.s_addr = htonl(arr.elems[i].prefix);
            lookupPrefix.ref_count = 0;
            res = pt_delete_into_tree(table->roa_table_ipv4,lookupPrefix,arr.elems[i].max_prefix_len,arr.elems[i].asn);
		}
	} 
    else if (type == HROV_IPV6){
		struct hpdu_ipv6 *ipv6 = (struct hpdu_ipv6 *)pdu;
		struct sc_array_pdu_ipv6 arr;
    	sc_array_init(&arr);
		parse_hpdu_v6(ipv6,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
			prefix_t lookupPrefix;
            lookupPrefix.family = AF_INET6;
            lookupPrefix.bitlen = arr.elems[i].prefix_len;
            for(int i=0;i<4;i++){
                lookupPrefix.add.sin6.__in6_u.__u6_addr32[i] = htonl(arr.elems[i].prefix[i]);
            }
            // memcpy(lookupPrefix.add.sin6.__in6_u.__u6_addr32,ipv6->prefix,sizeof(uint32_t)*4);
            lookupPrefix.ref_count = 0;
			res = pt_delete_into_tree(table->roa_table_ipv6,lookupPrefix,arr.elems[i].max_prefix_len,arr.elems[i].asn);
		}
	}
    if(res){
        return SUCCESS;
    }
    else{
        return ERROR;
    }
}

patricia_node_t* getParent(patricia_node_t * node){
    if(node->parent){
        node = node->parent;
        return node->data != NULL ? node : getParent(node);
    }
    return NULL;
}

int pt_validate_in_tree(patricia_tree_t *roa_tree, prefix_t lookupPrefix, uint32_t asn, enum pfxv_state * res){
    patricia_node_t *treeNode = NULL;
    int errbitmap = 0;
    treeNode = patricia_search_best(roa_tree,&lookupPrefix);
    if(!treeNode){
        *res=BGP_PFXV_STATE_NOT_FOUND;
        return errbitmap;
    }
    else{
        while(treeNode){
            if(treeNode->data){
                node_data_t *roaListNode = (node_data_t *)treeNode->data;
                for(int i=0;i<roaListNode->len;i++){
                    ROA roa = roaListNode->ary[i];
                    if((asn==roa.asn) && (lookupPrefix.bitlen<=roa.maxlen)){
                        *res = BGP_PFXV_STATE_VALID;
                        return errbitmap;
                    }
                    else{
                        // printf("%x,%x,%x,%x\n",treeNode->prefix->add.sin6.__in6_u.__u6_addr32[0],treeNode->prefix->add.sin6.__in6_u.__u6_addr32[1],treeNode->prefix->add.sin6.__in6_u.__u6_addr32[2],treeNode->prefix->add.sin6.__in6_u.__u6_addr32[3]);
                        // printf("%d,%u\n",roa.asn,roa.maxlen);
                        *res = BGP_PFXV_STATE_INVALID;
                    }  
                }
            }
            treeNode = treeNode->parent;
        }
        // *res = BGP_PFXV_STATE_INVALID;
        return errbitmap;
    }
    return errbitmap;
}

int pt_validate(pt_table *table, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    if(pfx->ver==LRTR_IPV4){
        prefix_t lookupPrefix;
        lookupPrefix.family = AF_INET;
        lookupPrefix.bitlen = masklen;
        lookupPrefix.add.sin.s_addr = htonl(pfx->u.addr4.addr);
        lookupPrefix.ref_count = 0;
        return pt_validate_in_tree(table->roa_table_ipv4,lookupPrefix,asn,res);
    }
    else{
        prefix_t lookupPrefix;
        lookupPrefix.family = AF_INET6;
        lookupPrefix.bitlen = masklen;
        for(int i=0;i<4;i++){
            lookupPrefix.add.sin6.__in6_u.__u6_addr32[i] = htonl(pfx->u.addr6.addr[i]);
        }
        // memcpy(lookupPrefix.add.sin6.__in6_u.__u6_addr32,msg->addr.u.addr6.addr,sizeof(uint32_t)*4);
        lookupPrefix.ref_count = 0;
        return pt_validate_in_tree(table->roa_table_ipv6,lookupPrefix,asn,res);
    }
    return ERROR;
}

size_t pt_memory_statistic(pt_table *table){
    patricia_tree_t *tree = table->roa_table_ipv4;
    patricia_node_t *node;
    size_t mem_total = 0;
    int node_len[200];
    memset(node_len,0,sizeof(int)*200);
    PATRICIA_WALK_ALL(tree->head, node) {
        mem_total += sizeof(patricia_node_t);
        if(node->prefix) mem_total+=sizeof(prefix_t);
        if(node->data){
            node_data_t *nd = (node_data_t *)node->data;
            mem_total += sizeof(node_data_t);
            mem_total += sizeof(ROA)*nd->len;
            node_len[nd->len]++;
        }
    } PATRICIA_WALK_END;
    // printf("IPv4 %luKB\n",mem_total);
    // for(int i=0;i<200;i++){
    //     if(node_len[i]>0){
    //         printf("%d %d\n",i,node_len[i]);
    //     }
    // }

    memset(node_len,0,sizeof(int)*200);
    tree = table->roa_table_ipv6;
    PATRICIA_WALK_ALL(tree->head, node) {
        mem_total += sizeof(patricia_node_t);
        if(node->prefix) mem_total+=sizeof(prefix_t);
        if(node->data){
            node_data_t *nd = (node_data_t *)node->data;
            mem_total += sizeof(node_data_t);
            mem_total += sizeof(ROA)*nd->len;
            node_len[nd->len]++;
        }
    } PATRICIA_WALK_END;
    // for(int i=0;i<200;i++){
    //     if(node_len[i]>0){
    //         printf("%d\n",node_len[i]);
    //     }
    // }
    mem_total = mem_total/1024;
    // printf("IPv6 %luKB\n",mem_total);
    return mem_total;
}
