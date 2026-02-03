#ifndef MPRINT_H
#define MPRINT_H

/**
 * @brief self-defined print function for debugging
 * 
*/
#include<stdio.h>

/**
 * @brief print IPv6 address in oct
 * @param[in] a ipv6 address (uint32_t array)
*/
#define SHOW_IPV6_oct(a)(printf("%x %x %x %x\n",a[0],a[1],a[2],a[3]))

/**
 * @brief print IPv4 address in oct
 * @param[in] a ipv4 address (uint32_t)
*/
#define SHOW_IPV4_oct(a)(printf("%x\n",a))

/**
 * @brief print uint32_t in binary format
 * @param[in] src (uint32_t)
*/
#define binary_print(_src){                        \
    int _i=31;                                     \
    for(;_i>=0;_i--){                              \
        if((_src&(1<<_i))==0){                     \
            printf("0");                           \
        }else{                                     \
            printf("1");                           \
        }                                          \
        if(_i%4==0) printf(" ");                   \
    }                                              \
}

/**
 * @brief print wide ROA with ipv4 addr in binary format
 * @param[in] wr (wideROA_v4)
*/
#define print_wide_ROA_v4(_wr){                             \
    binary_print(_wr->pfx);                                 \
    printf("\n");                                           \
    printf("%d %d %u\n",_wr->masklen,_wr->maxlen,_wr->asn); \
}

/**
 * @brief print wide ROA with ipv6 addr in binary format
 * @param[in] wr (wideROA_v6)
*/
#define print_wide_ROA_v6(_wr){                                \
    binary_print(_wr->pfx[0]);                                 \
    printf(" ");                                               \
    binary_print(_wr->pfx[1]);                                 \
    printf(" ");                                               \
    binary_print(_wr->pfx[2]);                                 \
    printf(" ");                                               \
    binary_print(_wr->pfx[3]);                                 \
    printf("\n");                                              \
    printf("%d %d %u\n",_wr->masklen,_wr->maxlen,_wr->asn);    \
}


#endif