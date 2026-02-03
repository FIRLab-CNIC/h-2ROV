#ifndef RTR_PROCESS_H
#define RTR_PROCESS_H

#include <stdint.h>
#include<assert.h>
#include"../SupportDS/decoder.h"
#include"../SupportDS/common.h"
#include"algos.h"

void rtr_pfxt_init(struct rov_algo_t *algo);
int rtr_pfx_add(void *algo_ptr, void * record);
int rtr_pfx_remove(void *algo_ptr, void * pdu);
int rtr_pfx_validate(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void rtr_free(void * algo_ptr);
void memory_check(void *algo_ptr);
size_t memory_check_mute(void *algo_ptr);

struct trie_node {
	struct lrtr_ip_addr prefix;
	struct trie_node *rchild;
	struct trie_node *lchild;
	struct trie_node *parent;
	void *data;
	uint8_t len;
};

struct data_elem {
	uint32_t asn;
	uint8_t max_len;
	const struct rtr_socket *socket;
};

struct node_data {
	unsigned int len;
	struct data_elem *ary;
};

static const struct test_file trov_data[6] = {
							{
                                .pdu_file = "./test_data/trov_large/t_pdu.txt",
                                .validate_file = "./test_data/trov_large/rov_trie.txt",
                                .upd_wth_file = "./test_data/trov_large/update_withdrawn.txt",
                                .result_file = "./test_data/trov_large/validate_result.txt"
                            },
                            {

                            },
                            {
                                .pdu_file = "./test_data/trov_small/t_pdu.txt",
                                .validate_file = "./test_data/trov_small/rov_trie.txt",
                                .upd_wth_file = "./test_data/trov_small/update_withdrawn.txt",
                                .result_file = "./test_data/trov_small/validate_result.txt"
                            },
                            {
                                .pdu_file = "./test_data/trov_rd/t_vrp_curr.txt",
                                .validate_file = "./test_data/hrov_large/update_data.txt",
                                .upd_wth_file = "./test_data/trov_rd/update_withdrawn.txt",
                                .result_file = "./test_data/trov_rd/validate_result.txt"
                            },
                            {
                                .pdu_file = "./test_data/trov_rd/t_vrp_curr_v4.txt",
                                .validate_file = "./test_data/hrov_rd/update_data_v4.txt",
                                .upd_wth_file = "./test_data/trov_rd/t_vrp_insert_v4.txt",
                                .result_file = "./test_data/trov_rd/validate_result_v4.txt"
                            },
                            {
                                .pdu_file = "./test_data/trov_rd/t_vrp_curr_v6.txt",
                                .validate_file = "./test_data/hrov_rd/update_data_v6.txt",
                                .upd_wth_file = "./test_data/trov_rd/t_vrp_insert_v6.txt",
                                .result_file = "./test_data/trov_rd/validate_result_v6.txt"
                            }
						};

static const struct test_file mrov_data[6] = {
							{
                                .pdu_file = "./test_data/mrov_large/ver1/m_pdu.txt",
                                .validate_file = "./test_data/mrov_large/ver1/hrov_result.txt",
                                .upd_wth_file = "./test_data/mrov_large/ver1/update_withdrawn.txt",
                                .result_file = "./test_data/mrov_large/ver1/validate_result.txt"
                            },
                            {
                                .pdu_file = "./test_data/mrov_large/mpdu.txt",
                                .validate_file = "./test_data/hrov_large/update_data.txt",
                                .upd_wth_file = "./test_data/mrov_large/update_withdrawn.txt",
                                .result_file = "./test_data/mrov_large/validate_result.txt"
                            },
                            {
                                .pdu_file = "./test_data/mrov_small/m_pdu.txt",
                                .validate_file = "./test_data/mrov_small/hrov_result.txt",
                                .upd_wth_file = "./test_data/mrov_small/update_withdrawn.txt",
                                .result_file = "./test_data/mrov_small/validate_result.txt",
                            },
                            {
                                .pdu_file = "./test_data/mrov_rd/cm_vrp_curr.txt",
                                .validate_file = "./test_data/hrov_large/update_data.txt",
                                .upd_wth_file = "./test_data/mrov_rd/update_withdrawn.txt",
                                .result_file = "./test_data/mrov_rd/validate_result.txt"
                            },
                            {
                                .pdu_file = "./test_data/mrov_rd/cm_vrp_curr_v4.txt",
                                .validate_file = "./test_data/hrov_rd/update_data_v4.txt",
                                .upd_wth_file = "./test_data/mrov_rd/cm_vrp_insert_v4.txt",
                                .result_file = "./test_data/mrov_rd/validate_result_v4.txt"
                            },
                             {
                                .pdu_file = "./test_data/mrov_rd/cm_vrp_curr_v6.txt",
                                .validate_file = "./test_data/hrov_rd/update_data_v6.txt",
                                .upd_wth_file = "./test_data/mrov_rd/cm_vrp_insert_v6.txt",
                                .result_file = "./test_data/mrov_rd/validate_result_v6.txt"
                            }
						};

static struct rov_algo_t trov = {
    .ht = NULL,
    .rov_init = rtr_pfxt_init,
    .rov_pfx_add = rtr_pfx_add,
    .rov_pfx_rm = rtr_pfx_remove,
    .rov_pfx_validate = rtr_pfx_validate,
    .mem_check = memory_check,
    .mem_check_mute = memory_check_mute,
    .mem_release = rtr_free,
};

static struct rov_algo_t mrov = {
    .ht = NULL,
    .rov_init = rtr_pfxt_init,
    .rov_pfx_add = rtr_pfx_add,
    .rov_pfx_rm = rtr_pfx_remove,
    .rov_pfx_validate = rtr_pfx_validate,
    .mem_check = memory_check,
    .mem_check_mute = memory_check_mute,
    .mem_release = rtr_free
};


#endif