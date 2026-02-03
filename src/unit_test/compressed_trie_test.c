#include"compressed_trie_test.h"

void walk_v4(struct f_trie_node4 *root){
    if(root){
        printf("addr: %x, plen: %d, local: %x, accept: %x, mask: %x\n",root->addr,root->plen,root->local,root->accept,root->mask);
        for(int i=0;i<(1<<TRIE_STEP);i++){
            printf("%d\n",i);
            walk_v4(root->c[i]);
        }
    }
    else{
        printf("null \n");
    }
}


void compressed_trie_test(){
    struct f_trie *trie = f_new_trie(0);
    net_addr_union addr = {};
    addr.roa4.type = NET_ROA4;
    addr.roa4.length = sizeof(net_addr_roa4);
    addr.roa4.prefix = 0x2f32e000;
    addr.roa4.asn = 12;
    addr.roa4.pxlen = 20;
    addr.roa4.max_pxlen = 20;

    trie_add_prefix(trie,&addr.n,20,20);
    addr.roa4.pxlen = 21;
    addr.roa4.pxlen = 21;
    trie_add_prefix(trie,&addr.n,21,21);
    addr.roa4.prefix = 0x2f32e800;
    addr.roa4.pxlen = 21;
    addr.roa4.pxlen = 21;
    trie_add_prefix(trie,&addr.n,21,21);
    addr.roa4.pxlen = 24;
    addr.roa4.pxlen = 24;
    trie_add_prefix(trie,&addr.n,24,24);
    walk_v4(&trie->root.v4);
    struct f_trie_node4 *c[1 << TRIE_STEP];
    printf("%lu %lu\n",sizeof(struct f_trie_node4),sizeof(c));
}