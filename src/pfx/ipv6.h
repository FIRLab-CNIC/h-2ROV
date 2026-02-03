#ifndef IPV6_H
#define IPV6_H

#include<stdio.h>
#include<stdint.h>
#include<string.h>

/**
 * @brief Struct holding an IPv6 address in host byte order.
 */
// typedef struct{
// 	uint32_t addr[4]; 
// }ipv6;

struct ip6_t {
    union {
		uint32_t u_ip6_addr32[4];
        uint64_t u_ip6_addr64[2];
	} u_ip6;
};

/**
 * @brief right move IPv6 addr
 * @param[in] src
 * @param[in,out] dest
 * @param[in] n bits you want to move
*/
#define r_move_v6(src,dest,n){              \
    int i,flag=0;                                  \
    int t = n/32;                                  \
    int mv = n%32;                                 \
    memcpy(dest,src,sizeof(uint32_t)*4);           \
    uint32_t pre = 0;                              \
    uint32_t mask = (1<<mv) - 1;                   \
    if(t==0){                                      \
        ;                                          \
    }                                              \
    else if(t==1){                                 \
        dest[3]=dest[2];                           \
        dest[2]=dest[1];                           \
        dest[1]=dest[0];                           \
        dest[0]=0;                                 \
    }                                              \
    else if(t==2){                                 \
        dest[3]=dest[1];                           \
        dest[2]=dest[0];                           \
        dest[1]=dest[0]=0;                         \
    }                                              \
    else if(t==3){                                 \
        dest[3]=dest[0];                           \
        dest[0]=dest[1]=dest[2]=0;                 \
    }                                              \
    else{                                          \
        dest[0]=dest[1]=dest[2]=dest[3]=0;         \
    }                                              \
    for(i=0;i<4;i++)                               \
    {                                              \
        uint32_t src_id = dest[i];                 \
        if(src_id==0 && flag==0)                   \
        {                                          \
            dest[i] = 0;                           \
            continue;                              \
        }                                          \
        else if(src_id > 0 && flag==0)             \
            {                                      \
            flag = 1;                              \
            pre = src_id & (mask);                 \
            dest[i] = (src_id >> mv);              \
        }                                          \
        else                                       \
        {                                          \
            dest[i] = (src_id >> mv) | (pre << (32-mv));\
            pre = src_id & (mask);                 \
        }                                          \
    }                                              \
}

#define r_move_v6_fast(src,dest,n){             \
    if(n==0){                                   \
        dest[0]=src[0];                         \
        dest[1]=src[1];                         \
        dest[2]=src[2];                         \
        dest[3]=src[3];                         \
    }                                           \
    else if(n<32){                              \
        unsigned int s = n;                     \
        dest[3] = (src[3] >> s) | (src[2] << (32 - s));\
        dest[2] = (src[2] >> s) | (src[1] << (32 - s));\
        dest[1] = (src[1] >> s) | (src[0] << (32 - s));\
        dest[0] = src[0] >> s;\
    }\
    else if(n<64){\
        unsigned int s = n - 32;\
        dest[3] = (src[2] >> s) | (src[1] << (32 - s));\
        dest[2] = (src[1] >> s) | (src[0] << (32 - s));\
        dest[1] = src[0] >> s;\
        dest[0] = 0;\
    }\
    else if(n<96){\
        unsigned int s = n - 64;\
        dest[3] = (src[1] >> s) | (src[0] << (32 - s));\
        dest[2] = src[0] >> s;\
        dest[0] = 0;\
        dest[1] = 0;\
    }\
    else if(n<128){\
        unsigned int s = n - 96;\
        dest[3] = src[0] >> s;\
        dest[0] = 0;\
        dest[1] = 0;\
        dest[2] = 0;\
    }\
    else{\
        dest[0] = 0;\
        dest[1] = 0;\
        dest[2] = 0;\
        dest[3] = 0;\
    }\
}

// void r_move_v6_fast(const uint32_t src[4],uint32_t dest[4],int n);

#define l_move_v6(src,dest,n){                 \
    int _i,flag=0;                                  \
    int t = n/32;                                  \
    int mv = n%32;                                 \
    memcpy(dest,src,sizeof(uint32_t)*4);           \
    uint32_t pre = 0;                              \
    if(t==0){                                      \
        ;                                          \
    }                                              \
    else if(t==1){                                 \
        dest[0]=dest[1];                           \
        dest[1]=dest[2];                           \
        dest[2]=dest[3];                           \
        dest[3]=0;                                 \
    }                                              \
    else if(t==2){                                 \
        dest[0]=dest[2];                           \
        dest[1]=dest[3];                           \
        dest[2]=dest[3]=0;                         \
    }                                              \
    else if(t==3){                                 \
        dest[0]=dest[3];                           \
        dest[1]=dest[2]=dest[3]=0;                 \
    }                                              \
    else{                                          \
        dest[0]=dest[1]=dest[2]=dest[3]=0;         \
    }                                              \
    if(mv>0){                                          \
        uint32_t mask = 0xffffffff- ((uint64_t)1<<(32 - mv)) + 1;  \
        for(_i=3;_i>=0;_i--)                           \
        {                                              \
            uint32_t src_id = dest[_i];                \
            if(src_id==0 && flag==0)                   \
            {                                          \
                dest[_i] = 0;                          \
                continue;                              \
            }                                          \
            else if(src_id > 0 && flag==0)             \
            {                                          \
                flag = 1;                              \
                pre = src_id & (mask);                 \
                dest[_i] = (src_id << mv);             \
            }                                          \
            else                                       \
            {                                          \
                dest[_i] = (src_id << mv) | (pre >> (32-mv));\
                pre = src_id & (mask);                 \
            }                                          \
        }                                              \
    }                                                  \
}

/**
 * @brief count how many bits > 0 in uint32_t*4
 * @param[in] _ip_addr uint32_t[]
*/
#define count_Bits_v6_c(_ip_addr,_res){              \
    int _tmp = 0, _flag = 0, _i = 0;                  \
    for(_i=0;_i<4;_i++)                               \
    {                                              \
        if(_ip_addr[_i]==0 && _flag==0){              \
            continue;                              \
        }                                          \
        else if(_ip_addr[_i]>0 && _flag==0)           \
        {                                          \
            _flag = 1;                              \
            _tmp += (int)log2(_ip_addr[_i])+1;        \
        }                                          \
        else                                       \
        {                                          \
            _tmp += 32;                             \
        }                                          \
    }                                              \
    *_res = _tmp;                                   \
}

#endif