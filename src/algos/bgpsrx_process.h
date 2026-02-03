#ifndef BGPSRX_PROCESS_H
#define BGPSRX_PROCESS_H

#include"algos.h"
#include"../SupportDS/roa.h"

void bgp_srx_init(struct rov_algo_t *algo);
int bgp_srx_add(void *algo_ptr, void * record);
int bgp_srx_remove(void *algo_ptr, void * pdu);
int bgp_srx_validate(void *algo_ptr, const uint32_t asn, const struct lrtr_ip_addr * pfx, const uint8_t masklen, enum pfxv_state * res);
void bgp_srx_release(void *algo_ptr);
void bgp_srx_memory_check(void *algo_ptr);
size_t bgp_srx_memory_check_mute(void *algo_ptr);

static struct rov_algo_t bgp_srx = {
    .ht = NULL,
    .rov_init = bgp_srx_init,
    .rov_pfx_add = bgp_srx_add,
    .rov_pfx_rm = bgp_srx_remove,
    .rov_pfx_validate = bgp_srx_validate,
    .mem_check = bgp_srx_memory_check,
    .mem_check_mute = bgp_srx_memory_check_mute,
    .mem_release = bgp_srx_release
};

#endif