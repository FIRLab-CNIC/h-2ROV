#include"decoder_test.h"

void decoder_v4_test(){
    struct hpdu_ipv4 hpdu;
    // 0xcc = 1100 1100
    //           1
    //        2     3
    //     4     5    6   7
    //  8     9
    //16 17 18 19
    init_hpdu_v4(&hpdu,"001ca7f1",0xc020e,222);
    struct sc_array_pdu_ipv4 arr;
    sc_array_init(&arr);
    parse_hpdu_v4(&hpdu,&arr);
    for(int i=0;i<sc_array_size(&arr);i++){
        struct pdu_ipv4 pdu = arr.elems[i];
        printf("pfx: %x, masklen: %d, maxlen: %d, asn: %u\n",pdu.prefix,pdu.prefix_len,pdu.max_prefix_len,pdu.asn);
    }
}

void decoder_v6_test(){
    struct hpdu_ipv6 hpdu;
    // 0xcc = 1100 1100
    //           1
    //        2     3
    //     4     5    6   7
    //  8     9
    //16 17 18 19
    init_hpdu_v6(&hpdu,"00000000000000000000340020cf0097",0xc020e,222);
    struct sc_array_pdu_ipv6 arr;
    sc_array_init(&arr);
    parse_hpdu_v6(&hpdu,&arr);
    for(int i=0;i<sc_array_size(&arr);i++){
        struct pdu_ipv6 pdu = arr.elems[i];
        printf("pfx: %x %x %x %x, masklen: %d, maxlen: %d, asn: %u\n",pdu.prefix[0],pdu.prefix[1],pdu.prefix[2],pdu.prefix[3],pdu.prefix_len,pdu.max_prefix_len,pdu.asn);
    }
}