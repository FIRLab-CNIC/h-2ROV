#ifndef ALGOS_H
#define ALGOS_H
#include<stdint.h>
#include"rtrlib/rtrlib.h"
#define IPV4_DATA 4
#define IPV6_DATA 5

#define COPY_ALGO(_dst, _src) {                              \
            _dst->ht = _src.ht;                              \
            _dst->rov_init = _src.rov_init;                  \
            _dst->rov_pfx_add = _src.rov_pfx_add;            \
            _dst->rov_pfx_rm = _src.rov_pfx_rm;              \
            _dst->rov_pfx_validate = _src.rov_pfx_validate;  \
            _dst->mem_check = _src.mem_check;                \
            _dst->mem_check_mute = _src.mem_check_mute;      \
            _dst->mem_release = _src.mem_release;            \
        }

struct test_file {
    char const* pdu_file;
    char const* validate_file;
    char const* upd_wth_file;
    char const* result_file;
};

struct algo_phy {
    void * pointer;
};

struct rov_algo_t {
    void *ht;

    int wide_threshold;

    void (*rov_init)(struct rov_algo_t *);

    int (*rov_pfx_add)(void *, void *);

    int (*rov_pfx_rm)(void *, void *);

    int (*rov_pfx_validate)(void *, const uint32_t, const struct lrtr_ip_addr *,const uint8_t, enum pfxv_state *);

    void *(*test_data_coding)(char *);

    void (*mem_check)(void *);

    size_t (*mem_check_mute)(void *);

    void (*mem_release)(void *);

    struct test_file files;

    char *result_file;

    char *algo_name;
};

                            
#endif