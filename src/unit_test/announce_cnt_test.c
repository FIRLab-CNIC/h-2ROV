#include"announce_cnt_test.h"

void announce_cnt_insert_test(){
    rc_sot4 rc;
    rc_sot4_init(&rc);
    struct ipv4_asn k;
    k.addr = 1;
    k.asn = 1;
    rc_sot4_insert_new(&rc,k,0xff00,0x1ee00);
    rc_sot4_insert(&rc,k,0xf7a02);
    binary_print(0xff00);printf("\n");
    binary_print(0x1ee00);printf("\n");
    binary_print(0xf7a02);printf("\n");
    rc_sot4_print(&rc);
}

void announce_cnt_remove_test(){
    printf("%lu\n",sizeof(reference_cnt));
    rc_sot4 rc;
    rc_sot4_init(&rc);
    struct ipv4_asn k;
    k.addr = 1;
    k.asn = 1;
    rc_sot4_insert_new(&rc,k,0xff00,0x1ee00);
    rc_sot4_insert(&rc,k,0xf7a02);
    uint32_t bm = 0xff00 | 0x1ee00 | 0xf7a02;
    printf("bm originally : ");
    binary_print(bm);printf("\n");
    binary_print(0xff00);printf("\n");
    binary_print(0x1ee00);printf("\n");
    binary_print(0xf7a02);printf("\n");
    rc_sot4_print(&rc);
    rc_sot4_remove(&rc,k,0xa00,&bm);
    rc_sot4_remove(&rc,k,0xa00,&bm);
    rc_sot4_remove(&rc,k,0xa00,&bm);
    binary_print(0xa00);printf("\n");
    printf("bm currently : ");
    binary_print(bm);printf("\n");
    rc_sot4_print(&rc);
}