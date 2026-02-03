#include"bgp.h"

void bgp_rov_init(struct bgp_rov *br){
    br->roa_table_ip4=rt_setup(NET_ROA4);
    br->roa_table_ip6=rt_setup(NET_ROA6);
	return;
}

int bgp_rov_insert(struct bgp_rov *br, void *pdu){
    const int type = *((char *)pdu + 1);
    if(type == TROA_IPV4){
        net_addr_union addr = {};
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        addr.roa4.type = NET_ROA4;
        addr.roa4.length = sizeof(net_addr_roa4);
        addr.roa4.prefix = ipv4->prefix;
        addr.roa4.asn = ipv4->asn;
        addr.roa4.pxlen = ipv4->prefix_len;
        addr.roa4.max_pxlen = ipv4->max_prefix_len;
        rt_add(br->roa_table_ip4,&addr.n);
    }
    else if (type == TROA_IPV6)
    {
        net_addr_union addr = {};
        const struct pdu_ipv6 *ipv6 = (const struct pdu_ipv6 *)pdu;
        addr.roa6.type = NET_ROA6;
        addr.roa6.length = sizeof(net_addr_roa6);
        memcpy(addr.roa6.prefix.addr,ipv6->prefix,sizeof(uint32_t)*4);
        addr.roa6.asn = ipv6->asn;
        addr.roa6.pxlen = ipv6->prefix_len;
        addr.roa6.max_pxlen = ipv6->max_prefix_len;
        rt_add(br->roa_table_ip6,&addr.n);
    }
    else if (type == HROV_IPV4){
		struct hpdu_ipv4 *ipv4 = (struct hpdu_ipv4 *)pdu;
		struct sc_array_pdu_ipv4 arr;
    	sc_array_init(&arr);
		parse_hpdu_v4(ipv4,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
            net_addr_union addr = {};
			addr.roa4.type = NET_ROA4;
            addr.roa4.length = sizeof(net_addr_roa4);
            addr.roa4.prefix = arr.elems[i].prefix;
            addr.roa4.asn = arr.elems[i].asn;
            addr.roa4.pxlen = arr.elems[i].prefix_len;
            addr.roa4.max_pxlen = arr.elems[i].max_prefix_len;
            rt_add(br->roa_table_ip4,&addr.n);
		}
	} else if (type == HROV_IPV6){
		struct hpdu_ipv6 *ipv6 = (struct hpdu_ipv6 *)pdu;
		struct sc_array_pdu_ipv6 arr;
    	sc_array_init(&arr);
		parse_hpdu_v6(ipv6,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
            net_addr_union addr = {};
			addr.roa6.type = NET_ROA6;
            addr.roa6.length = sizeof(net_addr_roa6);
            memcpy(addr.roa6.prefix.addr,arr.elems[i].prefix,sizeof(uint32_t)*4);
            addr.roa6.asn = arr.elems[i].asn;
            addr.roa6.pxlen = arr.elems[i].prefix_len;
            addr.roa6.max_pxlen = arr.elems[i].max_prefix_len;
			rt_add(br->roa_table_ip6,&addr.n);
		}
	}
    return SUCCESS;
}

int bgp_rov_remove(struct bgp_rov *br,void *pdu){
    const int type = *((char *)pdu + 1);
    if(type == TROA_IPV4){
        net_addr_union addr = {};
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        addr.roa4.type = NET_ROA4;
        addr.roa4.length = sizeof(net_addr_roa4);
        addr.roa4.prefix = ipv4->prefix;
        addr.roa4.asn = ipv4->asn;
        addr.roa4.pxlen = ipv4->prefix_len;
        addr.roa4.max_pxlen = ipv4->max_prefix_len;
        fib_delete(&br->roa_table_ip4->fib,&addr.n);
        // rt_remove(br->roa_table_ip4,&addr.n);
    }
    else if (type == TROA_IPV6)
    {
        net_addr_union addr = {};
        const struct pdu_ipv6 *ipv6 = (const struct pdu_ipv6 *)pdu;
        addr.roa6.type = NET_ROA6;
        addr.roa6.length = sizeof(net_addr_roa6);
        memcpy(addr.roa6.prefix.addr,ipv6->prefix,sizeof(uint32_t)*4);
        addr.roa6.asn = ipv6->asn;
        addr.roa6.pxlen = ipv6->prefix_len;
        addr.roa6.max_pxlen = ipv6->max_prefix_len;
        fib_delete(&br->roa_table_ip6->fib,&addr.n);
        // rt_add(br->roa_table_ip6,&addr.n);
    }
    else if (type == HROV_IPV4){
		struct hpdu_ipv4 *ipv4 = (struct hpdu_ipv4 *)pdu;
		struct sc_array_pdu_ipv4 arr;
    	sc_array_init(&arr);
		parse_hpdu_v4(ipv4,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
            net_addr_union addr = {};
			addr.roa4.type = NET_ROA4;
            addr.roa4.length = sizeof(net_addr_roa4);
            addr.roa4.prefix = arr.elems[i].prefix;
            addr.roa4.asn = arr.elems[i].asn;
            addr.roa4.pxlen = arr.elems[i].prefix_len;
            addr.roa4.max_pxlen = arr.elems[i].max_prefix_len;
            fib_delete(&br->roa_table_ip4->fib,&addr.n);
		}
	} 
    else if (type == HROV_IPV6){
		struct hpdu_ipv6 *ipv6 = (struct hpdu_ipv6 *)pdu;
		struct sc_array_pdu_ipv6 arr;
    	sc_array_init(&arr);
		parse_hpdu_v6(ipv6,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
            net_addr_union addr = {};
			addr.roa6.type = NET_ROA6;
            addr.roa6.length = sizeof(net_addr_roa6);
            memcpy(addr.roa6.prefix.addr,arr.elems[i].prefix,sizeof(uint32_t)*4);
            addr.roa6.asn = arr.elems[i].asn;
            addr.roa6.pxlen = arr.elems[i].prefix_len;
            addr.roa6.max_pxlen = arr.elems[i].max_prefix_len;
			fib_delete(&br->roa_table_ip6->fib,&addr.n);
		}
	}
    return SUCCESS;
}

int bgp_rov_validate(struct bgp_rov *br, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    if(pfx->ver==LRTR_IPV4){
        net_addr_ip4 pfx4;
        pfx4.length = sizeof(net_addr_ip4);
        pfx4.prefix = pfx->u.addr4.addr;
        pfx4.pxlen = masklen;
        pfx4.type = NET_IP4;
        return net_roa_check_ip4_fib(br->roa_table_ip4,&pfx4,asn,res);
    }
    else{
        net_addr_ip6 pfx6;
        pfx6.length = sizeof(net_addr_ip6);
        memcpy(pfx6.prefix.addr,pfx->u.addr6.addr,sizeof(u32)*4);
        pfx6.pxlen = masklen;
        pfx6.type = NET_IP6;
        return net_roa_check_ip6_fib(br->roa_table_ip6,&pfx6,asn,res);
    }
    return -1;
}

size_t bgp_rov_memory_statistic(struct bgp_rov *br){
    size_t mem = rt_memory_statistic(br->roa_table_ip4);
    mem += rt_memory_statistic(br->roa_table_ip6);
    return mem;
}

/**
 *=============================================== 
 * compress trie from BIRD
 *===============================================
*/
int bgp_rov_trie_insert(struct bgp_rov *br, void *pdu){
    const int type = *((char *)pdu + 1);
    if(type == TROA_IPV4){
        net_addr_union addr = {};
        const struct pdu_ipv4 *ipv4 = (const struct pdu_ipv4 *)pdu;
        addr.roa4.type = NET_ROA4;
        addr.roa4.length = sizeof(net_addr_roa4);
        addr.roa4.prefix = ipv4->prefix;
        addr.roa4.asn = ipv4->asn;
        addr.roa4.pxlen = ipv4->prefix_len;
        addr.roa4.max_pxlen = ipv4->max_prefix_len;
        rt_add_trie(br->roa_table_ip4,&addr.n);
    }
    else if (type == TROA_IPV6)
    {
        net_addr_union addr = {};
        const struct pdu_ipv6 *ipv6 = (const struct pdu_ipv6 *)pdu;
        addr.roa6.type = NET_ROA6;
        addr.roa6.length = sizeof(net_addr_roa6);
        memcpy(addr.roa6.prefix.addr,ipv6->prefix,sizeof(uint32_t)*4);
        addr.roa6.asn = ipv6->asn;
        addr.roa6.pxlen = ipv6->prefix_len;
        addr.roa6.max_pxlen = ipv6->max_prefix_len;
        rt_add_trie(br->roa_table_ip6,&addr.n);
    }
    else if (type == HROV_IPV4){
		struct hpdu_ipv4 *ipv4 = (struct hpdu_ipv4 *)pdu;
		struct sc_array_pdu_ipv4 arr;
    	sc_array_init(&arr);
		parse_hpdu_v4(ipv4,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
            net_addr_union addr = {};
			addr.roa4.type = NET_ROA4;
            addr.roa4.length = sizeof(net_addr_roa4);
            addr.roa4.prefix = arr.elems[i].prefix;
            addr.roa4.asn = arr.elems[i].asn;
            addr.roa4.pxlen = arr.elems[i].prefix_len;
            addr.roa4.max_pxlen = arr.elems[i].max_prefix_len;
            rt_add_trie(br->roa_table_ip4,&addr.n);
		}
	} else if (type == HROV_IPV6){
		struct hpdu_ipv6 *ipv6 = (struct hpdu_ipv6 *)pdu;
		struct sc_array_pdu_ipv6 arr;
    	sc_array_init(&arr);
		parse_hpdu_v6(ipv6,&arr);
		for(int i=0;i<sc_array_size(&arr);i++){
            net_addr_union addr = {};
			addr.roa6.type = NET_ROA6;
            addr.roa6.length = sizeof(net_addr_roa6);
            memcpy(addr.roa6.prefix.addr,arr.elems[i].prefix,sizeof(uint32_t)*4);
            addr.roa6.asn = arr.elems[i].asn;
            addr.roa6.pxlen = arr.elems[i].prefix_len;
            addr.roa6.max_pxlen = arr.elems[i].max_prefix_len;
			rt_add_trie(br->roa_table_ip6,&addr.n);
		}
	}
    return SUCCESS;
}

int bgp_rov_trie_remove(struct bgp_rov *br,void *pdu){
    return SUCCESS;
}

int bgp_rov_trie_validate(struct bgp_rov *br, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    if(pfx->ver==LRTR_IPV4){
        net_addr_ip4 pfx4;
        pfx4.length = sizeof(net_addr_ip4);
        pfx4.prefix = pfx->u.addr4.addr;
        pfx4.pxlen = masklen;
        pfx4.type = NET_IP4;
        return net_roa_check_ip4_trie(br->roa_table_ip4,&pfx4,asn,res);
    }
    else{
        net_addr_ip6 pfx6;
        pfx6.length = sizeof(net_addr_ip6);
        memcpy(pfx6.prefix.addr,pfx->u.addr6.addr,sizeof(u32)*4);
        pfx6.pxlen = masklen;
        pfx6.type = NET_IP6;
        return net_roa_check_ip6_trie(br->roa_table_ip6,&pfx6,asn,res);
    }
    return -1;
}

size_t bgp_rov_trie_memory_statistic(struct bgp_rov *br){
    size_t mem = 0;
    int v4node = 0;
    count_node_ip4(&br->roa_table_ip4->trie->root.v4,&v4node);
    mem += v4node * sizeof(struct f_trie_node4)/1024;
    int v6node = 0;
    count_node_ip6(&br->roa_table_ip6->trie->root.v6,&v6node);
    mem += v6node * sizeof(struct f_trie_node6)/1024;
    mem += rt_memory_statistic(br->roa_table_ip4);
    mem += rt_memory_statistic(br->roa_table_ip6);
    return mem;
}

void trie_walk_v4(struct f_trie_node4 *root){
    if(root){
        printf("addr: %x, plen: %d, local: %x, accept: %x, mask: %x\n",root->addr,root->plen,root->local,root->accept,root->mask);
        for(int i=0;i<(1<<TRIE_STEP);i++){
            trie_walk_v4(root->c[i]);
        }
    }
    else{
        printf("null \n");
    }
}

void bgp_rov_show_trie(struct bgp_rov *br){
    trie_walk_v4(&br->roa_table_ip4->trie->root.v4);
}