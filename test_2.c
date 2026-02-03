#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include<xxhash.h>
#include"src/SupportDS/sc-vector.h"

struct ip6_t {
    union {
		uint8_t  u_ip6_addr8[16];
		uint16_t u_ip6_addr16[8];
		uint32_t u_ip6_addr32[4];
        uint64_t u_ip6_addr64[2];
	} u_ip6;
};

typedef struct{
	uint32_t addr[4]; 
}ipv6;

struct ip6_t_asn
{
    struct ip6_t addr;
    uint32_t asn;
};


int ipv6_equal_32bit(const void *a, const void *b, void *udata) {
    const struct ip6_t *ua = a;
    const struct ip6_t *ub = b;
    return ua->u_ip6.u_ip6_addr32[3] == ua->u_ip6.u_ip6_addr32[3] && ua->u_ip6.u_ip6_addr32[2] == ua->u_ip6.u_ip6_addr32[2] && ua->u_ip6.u_ip6_addr32[1] == ua->u_ip6.u_ip6_addr32[1] && ua->u_ip6.u_ip6_addr32[0] == ua->u_ip6.u_ip6_addr32[0] ? 0 : 1;
}

int ipv6_equal_64bit(const void *a, const void *b, void *udata) {
    const struct ip6_t *ua = a;
    const struct ip6_t *ub = b;
    return (ua->u_ip6.u_ip6_addr64[0] == ua->u_ip6.u_ip6_addr64[0] && ua->u_ip6.u_ip6_addr64[1] == ua->u_ip6.u_ip6_addr64[1]) ? 0 : 1;
}

void benchmark(int (*cmp_func)(const void *, const void *, void *), struct ip6_t *data, int n) {
    clock_t start = clock();
    for (int i = 0; i < n; i++) {
        cmp_func(&data[i], &data[n - i - 1], NULL);
    }
    clock_t end = clock();
    printf("Time taken: %lf seconds\n", (double)(end - start) / CLOCKS_PER_SEC);
}

void validtest(){
    ipv6 org;
    struct ip6_t dest;
    org.addr[0]=rand();
    org.addr[1]=rand();
    org.addr[2]=rand();
    org.addr[3]=rand();
    printf("%x %x %x %x\n",org.addr[0],org.addr[1],org.addr[2],org.addr[3]);
    memcpy(dest.u_ip6.u_ip6_addr32,org.addr,sizeof(ipv6));
    printf("32- %x %x %x %x\n",dest.u_ip6.u_ip6_addr32[0],dest.u_ip6.u_ip6_addr32[1],dest.u_ip6.u_ip6_addr32[2],dest.u_ip6.u_ip6_addr32[3]);
    printf("64- %lx %lx \n",dest.u_ip6.u_ip6_addr64[0],dest.u_ip6.u_ip6_addr64[1]);

}

void insert(){
    struct ip6_t_asn a;
    printf("Size of ip6_t: %zu bytes\n", sizeof(struct ip6_t));
    printf("Size of ip6_t_asn: %zu bytes\n", sizeof(struct ip6_t_asn));
    printf("Offset of addr: %zu\n", offsetof(struct ip6_t_asn, addr));
    printf("Offset of asn: %zu\n", offsetof(struct ip6_t_asn, asn));
    a.addr.u_ip6.u_ip6_addr32[0] = 0;
    a.addr.u_ip6.u_ip6_addr32[1] = 0;
    a.addr.u_ip6.u_ip6_addr32[2] = 0;
    a.addr.u_ip6.u_ip6_addr32[3] = 2542539;
    a.asn = 207728;
    printf("%lu\n",XXH3_64bits_withSeed(&a,sizeof(struct ip6_t_asn),0));
}

void validate(){
    struct ip6_t_asn a;
    a.addr.u_ip6.u_ip6_addr32[0] = 0;
    a.addr.u_ip6.u_ip6_addr32[1] = 0;
    a.addr.u_ip6.u_ip6_addr32[2] = 0;
    a.addr.u_ip6.u_ip6_addr32[3] = 2542539;
    a.asn = 207728;
    printf("%lu\n",XXH3_64bits_withSeed(&a,sizeof(struct ip6_t_asn),0));
}

void r_move_v6_fast(uint32_t src[4],uint32_t dest[4],int n){
   if(n<32){
        unsigned int s = n;
        dest[3] = (src[3] >> s) | (src[2] << (32 - s));
        printf("%u,%x,%x\n",s,src[2],src[2]<<(32-s));
        dest[2] = (src[2] >> s) | (src[1] << (32 - s));
        dest[1] = (src[1] >> s) | (src[0] << (32 - s));
        dest[0] = src[0] >> s;
    }
    else if(n<64){
        unsigned int s = n - 32;
        dest[3] = (src[2] >> s) | (src[1] << (32 - s));
        dest[2] = (src[1] >> s) | (src[0] << (32 - s));
        dest[1] = src[0] >> s;
        dest[0] = 0;
    }
    else if(n<96){
        unsigned int s = n - 64;
        dest[3] = (src[1] >> s) | (src[0] << (32 - s));
        dest[2] = src[0] >> s;
        dest[0] = 0;
        dest[1] = 0;
    }
    else if(n<128){
        unsigned int s = n - 96;
        dest[3] = src[0] >> s;
        dest[0] = 0;
        dest[1] = 0;
        dest[2] = 0;
    }
    else{
        dest[0] = 0;
        dest[1] = 0;
        dest[2] = 0;
        dest[3] = 0;
    }
}

//start from 0
uint32_t get_subtree_pos_v6(const uint32_t prefix[], int i, int j) {
    uint32_t result = 0;

    // 检查参数
    if (i > j || j - i > 4) {
        return result;
    }

    int start_bit = i;
    int end_bit = j;

    int start_index = start_bit / 32;
    int start_offset = start_bit % 32;
    int end_index = end_bit / 32;
    int end_offset = end_bit % 32;

    if (start_index == end_index) {
        // 在同一个 uint32_t 中
        result = (prefix[start_index] >> (31 - end_offset)) & ((1 << (end_offset - start_offset + 1)) - 1);
    } else {
        // 跨越两个 uint32_t
        result = (prefix[start_index] & ((1 << (32 - start_offset)) - 1)) << (end_offset + 1);
        result |= (prefix[end_index] >> (31 - end_offset));
    }

    return result|(1<<(j-i+1));
}

uint32_t get_subtree_pos_v6_exp(const uint32_t prefix[], int hanging_level, int masklen) {
    int d = hanging_level / 32;
    int left = hanging_level % 32;
    int diff = masklen - hanging_level;
    
    if (left + diff <= 32) {
        // 提取同一个 uint32_t 元素中的位
        uint32_t mask = (1U << diff) - 1;
        return ((prefix[d] >> (32 - left - diff)) & mask) | (1U << diff);
    } else {
        // 跨越两个 uint32_t 元素
        int r = 32 - left;
        uint32_t part1 = prefix[d] & ((1U << r) - 1);
        uint32_t part2 = prefix[d + 1] >> (32 - (diff - r));
        return ((part1 << (diff - r)) | part2) | (1U << diff);
    }
}

uint32_t get_bits(uint32_t addr[4], int i) {
    // 计算第 i 位所在的 uint32_t 数组的索引和位偏移
    int idx = i / 32;
    int bit_offset = i % 32;

    // 如果跨越了 32 位边界，需要特殊处理
    if (bit_offset < 28) {
        return (addr[idx] >> (32 - bit_offset - 5)) & 0x1F;
    } else {
        // 跨越了 32 位边界，分两部分处理
        int remaining_bits = 5 - (32 - bit_offset);
        uint32_t part1 = (addr[idx] & ((1U << (32 - bit_offset)) - 1)) << remaining_bits;
        uint32_t part2 = addr[idx + 1] >> (32 - remaining_bits);
        return part1 | part2;
    }
}

int main() {
    // validtest();
    // insert();
    // validate();
    // int remaining_bits = 30;
    // uint32_t mask = ((1U << remaining_bits) - 1) << (32 - remaining_bits);
    // printf("%x\n",mask);
    // struct ip6_t_asn a;
    uint32_t pfx[4];
    pfx[0]=0x2a0eb10f;
    pfx[1]=0x1a3e0000;
    pfx[2]=0;
    pfx[3]=0;
    printf("%x\n",get_bits(pfx,32));
    // uint32_t res = get_subtree_pos_v6_exp(pfx,20,20);
    // printf("%d\n",res);

    // r_move_v6_fast(pfx,pfx,0);
    // for(int i=0;i<4;i++) printf("%x,",pfx[i]);
    // puts("");
    // uint32_t p = 9;
    // printf("%x\n",p);
    // p = p<<(32-0);
    // printf("%x\n",p);
    // printf("%lx,%lx\n",a.addr.u_ip6.u_ip6_addr64[0],a.addr.u_ip6.u_ip6_addr64[1]);
    // printf("%x,%x,%x,%x\n",a.addr.u_ip6.u_ip6_addr32[0],a.addr.u_ip6.u_ip6_addr32[1],a.addr.u_ip6.u_ip6_addr32[2],a.addr.u_ip6.u_ip6_addr32[3]);
    // r_move_v6_fast(a.addr.u_ip6.u_ip6_addr32,a.addr.u_ip6.u_ip6_addr32,4);
    // //  printf("%lx,%lx\n",a.addr.u_ip6.u_ip6_addr64[0],a.addr.u_ip6.u_ip6_addr64[1]);
    // printf("%x,%x,%x,%x\n",a.addr.u_ip6.u_ip6_addr32[0],a.addr.u_ip6.u_ip6_addr32[1],a.addr.u_ip6.u_ip6_addr32[2],a.addr.u_ip6.u_ip6_addr32[3]);
    // int n = 100000000;
    // struct ip6_t *data = malloc(n * sizeof(struct ip6_t));
    // for (int i = 0; i < n; i++) {
    //     data[i].u_ip6.u_ip6_addr64[0] = rand();
    //     data[i].u_ip6.u_ip6_addr64[1] = rand();
    // }

    // printf("Benchmarking 32-bit comparison...\n");
    // benchmark(ipv6_equal_32bit, data, n);

    // printf("Benchmarking 64-bit comparison...\n");
    // benchmark(ipv6_equal_64bit, data, n);

    // free(data);
    return 0;
}
