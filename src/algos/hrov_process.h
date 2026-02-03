#ifndef HROV_PROCESS_H
#define HROV_PROCESS_H

#include "hrov.h"

void hrov_table_basic_print(void *algo);

void h_pfxt_print_basic(struct rov_algo_t *algo);
void h_pfxt_init_basic(struct rov_algo_t *algo);
int h_pfx_add_basic(void *algo_ptr, void * record);
int h_pfx_remove_basic(void *algo_ptr, void * pdu);
int h_pfx_validate_basic(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void h_pfxt_release_basic(void *algo_ptr);
void h_memory_check_basic(void *algo_ptr);
size_t h_memory_check_mute_basic(void *algo_ptr);

void h_pfxt_print_binary(struct rov_algo_t *algo);
void h_pfxt_init_binary(struct rov_algo_t *algo);
int h_pfx_add_binary(void *algo_ptr, void * record);
int h_pfx_remove_binary(void *algo_ptr, void * pdu);
int h_pfx_validate_binary(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void h_pfxt_release_binary(void *algo_ptr);
void h_memory_check_binary(void *algo_ptr);
size_t h_memory_check_mute_binary(void *algo_ptr);

void h_pfxt_print_nlbs(struct rov_algo_t *algo);
void h_pfxt_init_nlbs(struct rov_algo_t *algo);
int h_pfx_add_nlbs(void *algo_ptr, void * record);
int h_pfx_remove_nlbs(void *algo_ptr, void * pdu);
int h_pfx_validate_nlbs(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void h_pfxt_release_nlbs(void *algo_ptr);
void h_memory_check_nlbs(void *algo_ptr);
size_t h_memory_check_mute_nlbs(void *algo_ptr);

static const struct test_file hrov_data[6] = {
                            {
                                .pdu_file = "./test_data/hrov_large/ver1/h_pdu.txt",
                                .validate_file = "./test_data/hrov_large/ver1/hrov_result.txt",
                                .upd_wth_file = "./test_data/hrov_large/ver1/update_withdrawn.txt",
                                .result_file = "./test_data/hrov_large/ver1/validate_result.txt"
                            },
                            {
                                .pdu_file = "./test_data/hrov_large/hpdu.txt",
                                .validate_file = "./test_data/hrov_large/update_data.txt",
                                .upd_wth_file = "./test_data/hrov_large/update_withdrawn.txt",
                                .result_file = "./test_data/hrov_large/validate_result.txt"
                            },
                            {
                                .pdu_file = "./test_data/hrov_small/h_pdu.txt",
                                .validate_file = "./test_data/hrov_small/hrov_result.txt",
                                .upd_wth_file = "./test_data/hrov_small/update_withdrawn.txt",
                                .result_file = "./test_data/hrov_small/validate_result.txt"
                            },
                            {
                                .pdu_file = "./test_data/hrov_rd/h_vrp_curr.txt",
                                .validate_file = "./test_data/hrov_large/update_data.txt",
                                .upd_wth_file = "./test_data/hrov_rd/update_withdrawn.txt",
                                .result_file = "./test_data/hrov_rd/validate_result.txt"
                            },
                            {
                                .pdu_file = "./test_data/hrov_rd/h_vrp_curr_v4.txt",
                                .validate_file = "./test_data/hrov_rd/update_data_v4.txt",
                                .upd_wth_file = "./test_data/hrov_rd/h_vrp_insert_v4.txt",
                                .result_file = "./test_data/hrov_rd/validate_result_v4.txt"
                            },
                            {
                                .pdu_file = "./test_data/hrov_rd/h_vrp_curr_v6.txt",
                                .validate_file = "./test_data/hrov_rd/update_data_v6.txt",
                                .upd_wth_file = "./test_data/hrov_rd/h_vrp_insert_v6.txt",
                                .result_file = "./test_data/hrov_rd/validate_result_v6.txt"
                            }};

static struct rov_algo_t hrov_basic = {
    .ht = NULL,
    .rov_init = h_pfxt_init_basic,
    .rov_pfx_add = h_pfx_add_basic,
    .rov_pfx_rm = h_pfx_remove_basic,
    .rov_pfx_validate = h_pfx_validate_basic,
    .mem_check = h_memory_check_basic,
    .mem_check_mute = h_memory_check_mute_basic,
    .mem_release = h_pfxt_release_basic
};


static struct rov_algo_t hrov_binary = {
    .ht = NULL,
    .rov_init = h_pfxt_init_binary,
    .rov_pfx_add = h_pfx_add_binary,
    .rov_pfx_rm = h_pfx_remove_binary,
    .rov_pfx_validate = h_pfx_validate_binary,
    .mem_check = h_memory_check_binary,
    .mem_check_mute = h_memory_check_mute_binary,
    .mem_release = h_pfxt_release_binary
};

static struct rov_algo_t hrov_nlbs_binary = {
    .ht = NULL,
    .rov_init = h_pfxt_init_nlbs,
    .rov_pfx_add = h_pfx_add_nlbs,
    .rov_pfx_rm = h_pfx_remove_nlbs,
    .rov_pfx_validate = h_pfx_validate_nlbs,
    .mem_check = h_memory_check_nlbs,
    .mem_check_mute = h_memory_check_mute_nlbs,
    .mem_release = h_pfxt_release_nlbs
};

#endif