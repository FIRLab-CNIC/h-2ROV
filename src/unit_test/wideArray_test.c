#include"wideArray_test.h"

void wideArray_insert_test(){
    wideArray4 w;
    wideArray_init_v4(&w);

    for(int i=0;i<4;i++){
        wideArray_insert_v4(&w,i,i,i,i,i);
        wideArray_insert_v4(&w,i,2*i,2*i,2*i,2*i);
    }
    wideArray_print_v4(&w);
    
}

void wideArray_remove_test(){
    wideArray4 w;
    wideArray_init_v4(&w);

    for(int i=0;i<4;i++){
        wideArray_insert_v4(&w,i,i,i,i,i);
        wideArray_insert_v4(&w,i,2*i,2*i,2*i,2*i);
    }
    
    for(int i=0;i<4;i++){
        int f = WA_NOTNULL;
        wideArray_remove_v4(&w,i,i,i,i,i,&f);
        printf("flag : %d\n",f);
    }
    wideArray_print_v4(&w);
}