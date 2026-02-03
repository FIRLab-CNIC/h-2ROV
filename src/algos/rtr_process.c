#include"rtr_process.h"

void rtr_pfxt_init(struct rov_algo_t *algo){
	struct pfx_table *pfxt = (struct pfx_table *)malloc(sizeof(struct pfx_table));
	pfx_table_init(pfxt,NULL);
	algo->ht = (void *)pfxt;
	return;
}

int rtr_pfx_add(void *algo_ptr, void * pdu)
{   
    const int type = *((char *)pdu + 1);
    if (type == TROA_IPV4) {
    	struct pfx_record pfxr;
		const struct pdu_ipv4 *ipv4 = pdu;
		pfxr.prefix.u.addr4.addr = ipv4->prefix;
		pfxr.asn = ipv4->asn;
		pfxr.prefix.ver = LRTR_IPV4;
		pfxr.min_len = ipv4->prefix_len;
		pfxr.max_len = ipv4->max_prefix_len;
		pfxr.socket = NULL;
		return pfx_table_add((struct pfx_table *)algo_ptr, &pfxr);
	} else if (type == TROA_IPV6) {
		struct pfx_record pfxr;
		const struct pdu_ipv6 *ipv6 = pdu;
		pfxr.asn = ipv6->asn;
		pfxr.prefix.ver = LRTR_IPV6;
		memcpy(pfxr.prefix.u.addr6.addr, ipv6->prefix, sizeof(pfxr.prefix.u.addr6.addr));
		pfxr.min_len = ipv6->prefix_len;
		pfxr.max_len = ipv6->max_prefix_len;
		pfxr.socket = NULL;
		return pfx_table_add((struct pfx_table *)algo_ptr, &pfxr);
	} else if (type == HROV_IPV4){
		struct hpdu_ipv4 *ipv4 = (struct hpdu_ipv4 *)pdu;
		struct sc_array_pdu_ipv4 arr;
    	sc_array_init(&arr);
		// printf("hroa: %x %x %u\n",ipv4->sub_tree_identifier,ipv4->Encoded_sub_tree,ipv4->asn);
		parse_hpdu_v4(ipv4,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
			// printf("%x %d %d %u\n",arr.elems[i].prefix,arr.elems[i].prefix_len,arr.elems[i].max_prefix_len,arr.elems[i].asn);
			struct pfx_record pfxr;
			pfxr.prefix.u.addr4.addr = arr.elems[i].prefix;
			pfxr.asn = arr.elems[i].asn;
			pfxr.prefix.ver = LRTR_IPV4;
			pfxr.min_len = arr.elems[i].prefix_len;
			pfxr.max_len = arr.elems[i].max_prefix_len;
			pfxr.socket = NULL;
			if(pfx_table_add((struct pfx_table *)algo_ptr, &pfxr)==PFX_ERROR) return ERROR;
		}
	} else if (type == HROV_IPV6){
		struct hpdu_ipv6 *ipv6 = (struct hpdu_ipv6 *)pdu;
		struct sc_array_pdu_ipv6 arr;
    	sc_array_init(&arr);
		parse_hpdu_v6(ipv6,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
			struct pfx_record pfxr;
			pfxr.asn = arr.elems[i].asn;
			pfxr.prefix.ver = LRTR_IPV6;
			memcpy(pfxr.prefix.u.addr6.addr, arr.elems[i].prefix, sizeof(pfxr.prefix.u.addr6.addr));
			pfxr.min_len = arr.elems[i].prefix_len;
			pfxr.max_len = arr.elems[i].max_prefix_len;
			pfxr.socket = NULL;
			if(pfx_table_add((struct pfx_table *)algo_ptr, &pfxr)==PFX_ERROR) return ERROR;
		}
	}
	else{
		return ERROR;
	}
}

int rtr_pfx_remove(void *algo_ptr, void * pdu)
{   
    const int type = *((char *)pdu + 1);
    if (type == TROA_IPV4) {
		struct pfx_record pfxr;
		const struct pdu_ipv4 *ipv4 = pdu;
		pfxr.prefix.u.addr4.addr = ipv4->prefix;
		pfxr.asn = ipv4->asn;
		pfxr.prefix.ver = LRTR_IPV4;
		pfxr.min_len = ipv4->prefix_len;
		pfxr.max_len = ipv4->max_prefix_len;
		pfxr.socket = NULL;
		return pfx_table_remove((struct pfx_table *)algo_ptr, &pfxr);
	} 
	else if (type == TROA_IPV6) {
		struct pfx_record pfxr;
		const struct pdu_ipv6 *ipv6 = pdu;
		pfxr.asn = ipv6->asn;
		pfxr.prefix.ver = LRTR_IPV6;
		memcpy(pfxr.prefix.u.addr6.addr, ipv6->prefix, sizeof(pfxr.prefix.u.addr6.addr));
		pfxr.min_len = ipv6->prefix_len;
		pfxr.max_len = ipv6->max_prefix_len;
		pfxr.socket = NULL;
		return pfx_table_remove((struct pfx_table *)algo_ptr, &pfxr);
	} 
	else if (type == HROV_IPV4){
		struct hpdu_ipv4 *ipv4 = (struct hpdu_ipv4 *)pdu;
		struct sc_array_pdu_ipv4 arr;
    	sc_array_init(&arr);
		parse_hpdu_v4(ipv4,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
			struct pfx_record pfxr;
			pfxr.prefix.u.addr4.addr = arr.elems[i].prefix;
			pfxr.asn = arr.elems[i].asn;
			pfxr.prefix.ver = LRTR_IPV4;
			pfxr.min_len = arr.elems[i].prefix_len;
			pfxr.max_len = arr.elems[i].max_prefix_len;
			pfxr.socket = NULL;
			if(pfx_table_remove((struct pfx_table *)algo_ptr, &pfxr)==PFX_ERROR) return ERROR;
		}
	} 
	else if (type == HROV_IPV6){
		struct hpdu_ipv6 *ipv6 = (struct hpdu_ipv6 *)pdu;
		struct sc_array_pdu_ipv6 arr;
    	sc_array_init(&arr);
		parse_hpdu_v6(ipv6,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
			struct pfx_record pfxr;
			pfxr.asn = arr.elems[i].asn;
			pfxr.prefix.ver = LRTR_IPV6;
			memcpy(pfxr.prefix.u.addr6.addr, arr.elems[i].prefix, sizeof(pfxr.prefix.u.addr6.addr));
			pfxr.min_len = arr.elems[i].prefix_len;
			pfxr.max_len = arr.elems[i].max_prefix_len;
			pfxr.socket = NULL;
			if(pfx_table_remove((struct pfx_table *)algo_ptr, &pfxr)==PFX_ERROR) return ERROR;
		}
	}
	else{
		return ERROR;
	}
}

int rtr_pfx_validate(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res)
{
	if(masklen==0){
		*res = BGP_PFXV_STATE_NOT_FOUND;
		return PFX_SUCCESS;
	}
    return pfx_table_validate((struct pfx_table *)algo_ptr, asn, pfx, masklen, res);
}

void rtr_free(void * algo_ptr){
    pfx_table_free((struct pfx_table *)algo_ptr);
    free(algo_ptr);
    return;
}

void counter(const struct pfx_record *pfx_record, void *data){
	int *cnt = (int *)data;
	*cnt = *cnt+1;
	data = (void *)cnt;
}

static void pfx_table_for_each(struct trie_node *n, uint64_t *size)
{
	if (n->lchild)
		pfx_table_for_each(n->lchild,size);
	
	size_t struct_size = sizeof(struct trie_node);
	struct node_data *nd;
	nd = (struct node_data *)n->data;
	struct_size += sizeof(nd->len);
	struct_size += sizeof(nd->ary);
	for(unsigned int i = 0; i < nd->len; i++){
		struct_size += sizeof(struct data_elem);
	}
	*size = *size + struct_size;

	if (n->rchild)
		pfx_table_for_each(n->rchild,size);
}

void pfx_table_for_each_ipv4(struct pfx_table *pfx_table, uint64_t *size)
{
	assert(pfx_table);

	if (!pfx_table->ipv4)
		return;
	pfx_table_for_each(pfx_table->ipv4, size);
}


void pfx_table_for_each_ipv6(struct pfx_table *pfx_table, uint64_t *size)
{
	assert(pfx_table);

	if (!pfx_table->ipv6)
		return;
	pfx_table_for_each(pfx_table->ipv6, size);
}

void memory_check(void *algo_ptr){
	uint64_t num_v4 = 0;
	pfx_table_for_each_ipv4((struct pfx_table *)algo_ptr,&num_v4);
	uint64_t num_v6 = 0;
	pfx_table_for_each_ipv6((struct pfx_table *)algo_ptr,&num_v6);
	uint64_t total_size_v4 = (num_v4+sizeof(pthread_rwlock_t))/1024;
	uint64_t total_size_v6 = (num_v6+sizeof(pthread_rwlock_t))/1024;
	printf("ipv4 size: %lu KB\n",total_size_v4);
	printf("ipv6 size: %lu KB\n",total_size_v6);
}

size_t memory_check_mute(void *algo_ptr){
	uint64_t num_v4 = 0;
	pfx_table_for_each_ipv4((struct pfx_table *)algo_ptr,&num_v4);
	uint64_t num_v6 = 0;
	pfx_table_for_each_ipv6((struct pfx_table *)algo_ptr,&num_v6);
	uint64_t total_size_v4 = (num_v4+sizeof(pthread_rwlock_t))/1024;
	uint64_t total_size_v6 = (num_v6+sizeof(pthread_rwlock_t))/1024;
	size_t total = (total_size_v4+total_size_v6);
	printf("%lu\n",total);
	return total;
}
