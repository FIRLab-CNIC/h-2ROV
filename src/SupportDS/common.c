#include"common.h"

uint64_t hash_ipv4_asn_info(const void *item, uint64_t seed0, uint64_t seed1){
    const struct ipv4_asn_info * p = (const struct ipv4_asn_info*)item;
    // return XXH3_64bits(&p->key,sizeof(struct ipv4_asn));
    return XXH3_64bits_withSeed(&p->key,sizeof(struct ipv4_asn),seed0);
    // return hxgcum((unsigned int*)&p->key,8,p->key.asn);
    // return XXH64(&p->key,sizeof(struct ipv4_asn),seed0);
    // return hashmap_sip(&p->key, sizeof(struct ip_addr_v4), seed0, seed1);

}

// uint64_t hash_ipv6_asn_info(const void *item, uint64_t seed0, uint64_t seed1){
//     const struct ipv6_asn_info * p = (const struct ipv6_asn_info *)item;
//     // return hxgcum((unsigned int*)&p->key,20,p->key.addr[3]); 
//     // return hashmap_sip(&p->key, sizeof(struct ip_addr_v6), seed0, seed1);
//     // return XXH64(&p->key,sizeof(struct ipv6_asn),seed0);
//     // return XXH3_64bits(&p->key,sizeof(struct ipv6_asn));
//     return XXH3_64bits_withSeed(&p->key,sizeof(struct ipv6_asn),seed0);
//     // return mum_hash(&p->key,sizeof(struct ipv6_asn),seed0);
//     // return hashmap_murmur(&p->key, sizeof(struct ipv6_asn), seed0, seed1);
// }


uint64_t hash_ipv4_info(const void *item, uint64_t seed0, uint64_t seed1){  
    const struct ipv4_info * p = (const struct ipv4_info *)item;
    // return hashmap_sip(&p->key, sizeof(struct ip_addr_agg_v4), seed0, seed1);
    // return XXH3_64bits(&p->key,sizeof(ipv4));
    // return hxgcum((unsigned int*)&p->key,4,p->key); 
    return XXH3_64bits_withSeed(&p->key,4,seed0);
    // return XXH64(&p->key,sizeof(ipv4),seed0); 
}

// uint64_t  hash_ipv6_info(const void *item, uint64_t seed0, uint64_t seed1){ 
//     const struct ipv6_info * p = (const struct ipv6_info *)item;
//     // return hxgcum((unsigned int*)&p->key,16,p->key.addr[3]);
//     // return hashmap_murmur(&p->key, sizeof(ipv6), seed0, seed1);
//     // return XXH64(&p->key,sizeof(ipv6),seed0);
//     return XXH3_64bits_withSeed(&p->key,sizeof(ipv6),seed0);
//     // return mum_hash(&p->key,sizeof(ipv6),seed0);
// }

// uint64_t hash_ipv6_leafnode_level(const void *item, uint64_t seed0, uint64_t seed1){
//     const struct ipv6_leafnode_level * p = (const struct ipv6_leafnode_level *)item;
//     // return hashmap_murmur(&p->key, sizeof(ipv6), seed0, seed1);
//     // return XXH64(&p->key,sizeof(ipv6),seed0);
//     return XXH3_64bits_withSeed(&p->key,sizeof(ipv6),seed0);
//     // return mum_hash(&p->key,sizeof(ipv6),seed0);
// }

uint64_t hash_ipv4_complex_info(const void *item, uint64_t seed0, uint64_t seed1){
    const struct ipv4_complex_info * p = (const struct ipv4_complex_info *)item;
    // return hashmap_sip(&p->key, sizeof(struct ip_addr_agg_v4), seed0, seed1);
    // return XXH3_64bits(&p->key,sizeof(ipv4));
    return XXH3_64bits_withSeed(&p->key,4,seed0);
    // return hxgcum((unsigned int*)&p->key,4,p->key); 
    // return XXH64(&p->key,sizeof(ipv4),seed0); 
}


// uint64_t hash_ipv6_complex_info(const void *item, uint64_t seed0, uint64_t seed1){
//     const struct ipv6_complex_info * p = (const struct ipv6_complex_info *)item;
//     // return hashmap_sip(&p->key, sizeof(struct ip_addr_agg_v6), seed0, seed1);
//     // return hashmap_murmur(&p->key, sizeof(ipv6), seed0, seed1);
//     // return XXH64(&p->key,sizeof(ipv6),seed0);
//     return XXH3_64bits_withSeed(&p->key,sizeof(ipv6),seed0);
//     // return mum_hash(&p->key,sizeof(ipv6),seed0);
// }


int ipv4_asn_equal(const void *a, const void *b, void *udata)
{
    const struct ipv4_asn * ua = a;
    const struct ipv4_asn * ub = b;
    return ua->addr==ub->addr && ua->asn == ub->asn ? 0 : 1;
}

int ipv4_equal(const void *a, const void *b, void *udata)
{
    const ipv4 * ua = a;
    const ipv4 * ub = b;
    return *ua == *ub ? 0 : 1;
}

int ipv4_cmp(const void *a, const void *b)
{
    const ipv4 * ua = a;
    const ipv4 * ub = b;
    return *ua - *ub;
}

// int ipv6_asn_equal(const void *a, const void *b, void *udata)
// {
//     const struct ipv6_asn * ua = a;
//     const struct ipv6_asn * ub = b;
//     return ua->asn == ub->asn&&ua->addr.addr[3]==ub->addr.addr[3]&&ua->addr.addr[2]==ub->addr.addr[2]&&ua->addr.addr[1]==ub->addr.addr[1]&&ua->addr.addr[0]==ub->addr.addr[0]? 0 : 1;
// }


// int ipv6_equal(const void *a, const void *b, void *udata){
//     const ipv6 * ua = a;
//     const ipv6 * ub = b;
//     return ua->addr[3]==ub->addr[3]&&ua->addr[2]==ub->addr[2]&&ua->addr[1]==ub->addr[1]&&ua->addr[0]==ub->addr[0]? 0 : 1;
// }

// int ipv6_cmp(const void *a, const void *b, void *udata){
//     const ipv6 * ua = a;
//     const ipv6 * ub = b;
//     for(int i=0;i<4;i++){
//         if(ua->addr[i]<ub->addr[i])
//         {
//             return -1;
//         }
//         else if(ua->addr[i]>ub->addr[i])
//         {
//             return 1;
//         }
//     }
//     return 0;
// }

//test

uint64_t hash_ip6_t_info(const void *item, uint64_t seed0, uint64_t seed1){
    const struct ip6_t_info * p = (const struct ip6_t_info *)item;
    return XXH3_64bits_withSeed(&p->key,sizeof(struct ip6_t),seed0);
}

uint64_t hash_ip6_t_asn_info(const void *item, uint64_t seed0, uint64_t seed1){
    const struct ip6_t_asn_info * p = (const struct ip6_t_asn_info *)item;
    // SHOW_IPV6_oct(p->key.addr.u_ip6.u_ip6_addr32);
    // printf("%u\n",p->key.asn);
    // return hashmap_murmur(&p->key, 20, seed0, seed1);
    return XXH3_64bits_withSeed(&p->key,20,seed0);
}

uint64_t hash_ip6_t_complex_info(const void *item, uint64_t seed0, uint64_t seed1){
    const struct ip6_t_complex_info * p = (const struct ip6_t_complex_info *)item;
    return XXH3_64bits_withSeed(&p->key,sizeof(struct ip6_t),seed0);
}

uint64_t hash_ip6_t_leafnode_level(const void *item, uint64_t seed0, uint64_t seed1){
    const struct ip6_t_leafnode_level * p = (const struct ip6_t_leafnode_level *)item;
    // uint32_t key = p->key.u_ip6.u_ip6_addr32[3]&0xfffff;
    // return key;
    // return hxgcum((unsigned int*)&p->key,4,p->key);
    return XXH3_64bits_withSeed(&p->key,sizeof(ipv4),seed0);
}

int ip6_t_asn_equal(const void *a, const void *b, void *udata){
    const struct ip6_t_asn * ua = a;
    const struct ip6_t_asn * ub = b; 
    return ua->asn == ub->asn && ua->addr.u_ip6.u_ip6_addr64[1] == ub->addr.u_ip6.u_ip6_addr64[1] && ua->addr.u_ip6.u_ip6_addr64[0]==ub->addr.u_ip6.u_ip6_addr64[0] ? 0 : 1;
}

int ip6_t_equal(const void *a, const void *b, void *udata){
    const struct ip6_t * ua = a;
    const struct ip6_t * ub = b;
    return ua->u_ip6.u_ip6_addr64[1] == ub->u_ip6.u_ip6_addr64[1] && ua->u_ip6.u_ip6_addr64[0]==ub->u_ip6.u_ip6_addr64[0] ? 0 : 1;
}

int ip6_midlevel_equal(const void *a, const void *b, void *udata){
    const uint32_t * ua = a;
    const uint32_t * ub = b;
    return *ua == *ub ? 0 : 1;
}

int ip6_t_cmp(const void *a, const void *b, void *udata){
    const struct ip6_t * ua = a;
    const struct ip6_t * ub = b;
    for(int i=0;i<2;i++){
        if(ua->u_ip6.u_ip6_addr64[i]<ua->u_ip6.u_ip6_addr64[i])
        {
            return -1;
        }
        else if(ua->u_ip6.u_ip6_addr64[i]>ua->u_ip6.u_ip6_addr64[i])
        {
            return 1;
        }
    }
    return 0;
}