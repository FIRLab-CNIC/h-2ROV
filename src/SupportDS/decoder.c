#include"decoder.h"

// #define DEBUG_SUBTREE 0
// #define DEBUG 0

int bLen[] = {0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};

bool have_child(uint32_t bitmap, int num) {
    return (num <= 15) && ((bitmap & (1 << (num << 1))) != 0) && ((bitmap & 1 << ((num << 1) + 1)) != 0);
}

uint32_t cal_mask(uint8_t num, uint8_t subtree_height){
    uint32_t res = 0;
    uint8_t count = 0;
    struct sc_array_int arr;
    sc_array_init(&arr);
    sc_array_add(&arr,num);
    while(count<=subtree_height){
        struct sc_array_int tmpnum;
        sc_array_init(&tmpnum);
        while(sc_array_size(&arr)>0){
            uint8_t n = arr.elems[0];
            sc_array_del(&arr,0);
            res |= (1<<n);
            sc_array_add(&tmpnum,(n<<1));
            sc_array_add(&tmpnum,(n<<1)+1);
        }
        for(int i=0;i<sc_array_size(&tmpnum);i++){
            sc_array_add(&arr,tmpnum.elems[i]);
        }
        count+=1;
    }
    return res;
}

uint8_t cal_sub_tree(uint32_t bitmap,uint8_t index){
    int res = 0;
    struct sc_array_int sc;
    sc_array_init(&sc);
    sc_array_add(&sc,index);
#ifdef DEBUG_SUBTREE
        printf("index %d\n",index);
#endif
    while (1)
    {
        struct sc_array_int tmp;
        sc_array_init(&tmp);
        while(sc_array_size(&sc)>0){
            uint8_t i = sc.elems[0];
            sc_array_del(&sc,0);
#ifdef DEBUG_SUBTREE
            printf("sc elem %d\n",i);
            printf("sc array size %lu\n",sc_array_size(&sc));
#endif
            if(!have_child(bitmap,i)){
                return res;
            }
            uint8_t next_level = i<<1;
            sc_array_add(&tmp,next_level);
            sc_array_add(&tmp,next_level+1);
#ifdef DEBUG_SUBTREE
            printf("next level %d\n",next_level);
#endif
        }
        res+=1;
        for(int i=0;i<sc_array_size(&tmp);i++){
            sc_array_add(&sc,tmp.elems[i]);
        }
    }

}

void parse_hpdu_v4(struct hpdu_ipv4 *pdu, struct sc_array_pdu_ipv4 *arr){
    ipv4 identifier = pdu->sub_tree_identifier;
    uint32_t bitmap = pdu->Encoded_sub_tree;
    uint32_t asn = pdu->asn;
    int len = count_Bits_v4_c(identifier);
    int level = len-1;
    set_one_bit_zero(identifier,level);
    ipv4 pfx = level==0?0:identifier<<(32-level);
    int bit_mask = 2;
    int count = 1;
    // printf("%d, %u, %x\n",level,identifier,pfx);
    while(count<=31){
        if((bit_mask&bitmap)!=0){
            int height = bLen[count];
            uint8_t subtree_height = cal_sub_tree(bitmap, count);

            uint32_t prefix_mask = 1<<7;
            while((prefix_mask&count)==0) prefix_mask >>= 1;
            uint32_t prefix_tail = count & (~prefix_mask);

            ipv4 prefix;
            prefix = pfx | (prefix_tail << (32 - level - height));
            struct pdu_ipv4 pdu;
            pdu_v4(&pdu, TROA_IPV4, prefix, level+height, level+height+subtree_height, asn);
            sc_array_add(arr,pdu);
            uint32_t mask = cal_mask(count, subtree_height);
#ifdef DEBUG
            printf("mask : %x\n",mask);
#endif
            bitmap = bitmap & (~mask);
        }
        bit_mask = bit_mask << 1;
        count+=1;
    }
}

void parse_hpdu_v6(struct hpdu_ipv6 *pdu, struct sc_array_pdu_ipv6 *arr){
    struct ip6_t identifier;
    memcpy(&identifier.u_ip6.u_ip6_addr32,pdu->sub_tree_identifier,sizeof(pdu->sub_tree_identifier));
#ifdef DEBUG
    printf("identifier\n");
    SHOW_IPV6_oct(identifier.addr);
#endif
    uint32_t bitmap = pdu->Encoded_sub_tree;
    uint32_t asn = pdu->asn;
    int len = 0;
    count_Bits_v6_c(identifier.u_ip6.u_ip6_addr32,&len);
    int level = len - 1;
    set_one_bit_zero_v6(identifier.u_ip6.u_ip6_addr32,level);
#ifdef DEBUG
    printf("level is %d\nset first bit zero\n",level);
    SHOW_IPV6_oct(identifier.addr);
#endif
    struct ip6_t pfx;
    l_move_v6(identifier.u_ip6.u_ip6_addr32,pfx.u_ip6.u_ip6_addr32,(128-level));
#ifdef DEBUG
    printf("after lmove\n");
    SHOW_IPV6_oct(pfx.addr);
#endif
    int bit_mask = 2;
    int count = 1;
    while(count<=31){
        if((bit_mask&bitmap)!=0){
            int height = bLen[count];
            uint8_t subtree_height = cal_sub_tree(bitmap, count);

            uint32_t prefix_mask = 1<<7;
            while((prefix_mask&count)==0) prefix_mask >>= 1;
            uint32_t prefix_tail = count & (~prefix_mask);
            struct ip6_t prefix_tail_v6;
            for(int i=0;i<4;i++) prefix_tail_v6.u_ip6.u_ip6_addr32[i]=0;
            prefix_tail_v6.u_ip6.u_ip6_addr32[3] = prefix_tail;
            l_move_v6(prefix_tail_v6.u_ip6.u_ip6_addr32,prefix_tail_v6.u_ip6.u_ip6_addr32,(128-level-height));
            struct ip6_t prefix;
            memcpy(prefix.u_ip6.u_ip6_addr32,pfx.u_ip6.u_ip6_addr32,sizeof(struct ip6_t));
            for(int i=0;i<4;i++) prefix.u_ip6.u_ip6_addr32[i] |= prefix_tail_v6.u_ip6.u_ip6_addr32[i];
#ifdef DEBUG
            printf("prefix tail\n");
            SHOW_IPV6_oct(prefix_tail_v6.addr);
            printf("after generate tail\n");
            SHOW_IPV6_oct(prefix.addr);
#endif
            struct pdu_ipv6 pdu;
            pdu_v6(&pdu, TROA_IPV4, prefix, level+height, level+height+subtree_height, asn);
            sc_array_add(arr,pdu);
            uint32_t mask = cal_mask(count, subtree_height);
#ifdef DEBUG
            printf("mask : %x\n",mask);
#endif
            bitmap = bitmap & (~mask);
        }
        bit_mask = bit_mask << 1;
        count+=1;
    }
}