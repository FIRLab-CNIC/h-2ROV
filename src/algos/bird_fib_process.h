#ifndef BIRD_FIB_PROCESS_H
#define BIRD_FIB_PROCESS_H

#include"algos.h"
#include"../SupportDS/bgp.h"

void bird_init(struct rov_algo_t *algo);
int bird_add(void *algo_ptr, void * record);
int bird_remove(void *algo_ptr, void * pdu);
int bird_validate(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void bird_release(void *algo_ptr);
void bird_memory_check(void *algo_ptr);
size_t bird_memory_check_mute(void *algo_ptr);

int bird_add_trie(void *algo_ptr, void * record);
int bird_remove_trie(void *algo_ptr, void * pdu);
int bird_validate_trie(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void bird_release_trie(void *algo_ptr);
void bird_memory_check_trie(void *algo_ptr);
size_t bird_memory_check_mute_trie(void *algo_ptr);
void bird_trie_basic_print(void *algo);

static struct rov_algo_t bird = {
    .ht = NULL,
    .rov_init = bird_init,
    .rov_pfx_add = bird_add,
    .rov_pfx_rm = bird_remove,
    .rov_pfx_validate = bird_validate,
    .mem_check = bird_memory_check,
    .mem_check_mute = bird_memory_check_mute,
    .mem_release = bird_release
};

static struct rov_algo_t bird_trie = {
    .ht = NULL,
    .rov_init = bird_init,
    .rov_pfx_add = bird_add_trie,
    .rov_pfx_rm = bird_remove_trie,
    .rov_pfx_validate = bird_validate_trie,
    .mem_check = bird_memory_check_trie,
    .mem_check_mute = bird_memory_check_mute_trie,
    .mem_release = bird_release_trie
};



#endif