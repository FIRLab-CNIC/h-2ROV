#include"bird_fib_process.h"

void bird_init(struct rov_algo_t *algo){
	struct bgp_rov* br = (struct bgp_rov*)malloc(sizeof(struct bgp_rov));
    bgp_rov_init(br);
	algo->ht = (void *)br;
	return;
}

int bird_add(void *algo_ptr, void * record){
	return bgp_rov_insert((struct bgp_rov*)algo_ptr,record);
}

int bird_remove(void *algo_ptr, void * pdu){
	return bgp_rov_remove((struct bgp_rov*)algo_ptr,pdu);
}

int bird_validate(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
	return bgp_rov_validate((struct bgp_rov*)algo_ptr,asn,pfx,masklen,res);
}

void bird_release(void *algo_ptr){

}

void bird_memory_check(void *algo_ptr){
	printf("%lu\n",bgp_rov_memory_statistic((struct bgp_rov*)algo_ptr));
}

size_t bird_memory_check_mute(void *algo_ptr){
	return bgp_rov_memory_statistic((struct bgp_rov*)algo_ptr);
}

int bird_add_trie(void *algo_ptr, void * record){
	return bgp_rov_trie_insert((struct bgp_rov*)algo_ptr,record);
}

int bird_remove_trie(void *algo_ptr, void * pdu){
	return bgp_rov_remove((struct bgp_rov*)algo_ptr,pdu);
}

int bird_validate_trie(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res){
	return bgp_rov_trie_validate((struct bgp_rov*)algo_ptr,asn,pfx,masklen,res);
}

void bird_release_trie(void *algo_ptr){

}

void bird_memory_check_trie(void *algo_ptr){
	printf("%lu\n",bgp_rov_trie_memory_statistic((struct bgp_rov*)algo_ptr));
}

size_t bird_memory_check_mute_trie(void *algo_ptr){
	return bgp_rov_trie_memory_statistic((struct bgp_rov*)algo_ptr);
}

void bird_trie_basic_print(void *algo){
	bgp_rov_show_trie((struct bgp_rov*)algo);
}