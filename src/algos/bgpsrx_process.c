#include"bgpsrx_process.h"

void bgp_srx_init(struct rov_algo_t *algo){
    pt_table *pfxt = (pt_table *)malloc(sizeof(pt_table));
	pt_init(pfxt);
	algo->ht = (void *)pfxt;
	return;
}

int bgp_srx_add(void *algo_ptr, void * record){
    return pt_insert((pt_table *)algo_ptr, record);
}

int bgp_srx_remove(void *algo_ptr, void * pdu){
    return pt_remove((pt_table *)algo_ptr, pdu);
}

int bgp_srx_validate(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
    return pt_validate((pt_table *)algo_ptr,asn,pfx,masklen,res);
}

void bgp_srx_release(void *algo_ptr){
    
}

void bgp_srx_memory_check(void *algo_ptr){
    printf("%lu\n",pt_memory_statistic((pt_table *)algo_ptr));
}

size_t bgp_srx_memory_check_mute(void *algo_ptr){
    return pt_memory_statistic((pt_table *)algo_ptr);
}