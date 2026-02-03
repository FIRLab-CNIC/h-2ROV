// #include"level_bitmap.h"

// void lvl_bm_init(level_bitmap *lb){
//     int i=0;
//     for(;i<TOTAL;i++){
//         lb->lvl_bm[i]=0;
//     }
// }

// void lvl_bm_get_position(uint32_t identifier, int hanging_level, int *offset, int *pos){
//     uint32_t mask = ~((uint32_t)1<<hanging_level);
//     identifier = identifier & mask;
//     int index = hanging_level/5;
//     int start = LB_START[index];
//     int tmp = identifier/64;
//     *offset = start+tmp;
//     *pos = identifier%64;
// }

// bool lvl_bm_judge_exact_bit(level_bitmap *lb, int offset, int pos){
//     return (lb->lvl_bm[offset]&((uint64_t)1<<pos))>0;
// }

// void lvl_bm_set_bits_to_1(level_bitmap *lb,int len,int start,int pos){
//     if(pos+len-1<64){
//         uint64_t low = (__UINT64_MAX__)<<pos;
//         uint64_t high = (__UINT64_MAX__)>>(63-(pos+len-1));
//         uint64_t mask = low&high;
//         lb->lvl_bm[start] = lb->lvl_bm[start] | mask;
//     }
//     else{
//         int start_len = 64 - pos;
//         int left_len = len - start_len;
//         int array_to_1 = left_len/64;
//         left_len = left_len % 64;
//         uint64_t mask1 = (__UINT64_MAX__)<<pos;
//         lb->lvl_bm[start] = lb->lvl_bm[start] | mask1;
//         int i=1;
//         for(;i<=array_to_1;i++){
//             lb->lvl_bm[start+i] = __UINT64_MAX__;
//         }
//         uint64_t mask2 = ~((__UINT64_MAX__)<<left_len);
//         lb->lvl_bm[start+i] = lb->lvl_bm[start+i] | mask2;
//     }
// }

// void lvl_bm_set_bit_to_1(level_bitmap *lb, int hanging_level, uint32_t identifier){
//     int index = hanging_level/5;
//     int start = LB_START[index];
//     int offset = identifier/64;
//     int pos = identifier%64;
//     lb->lvl_bm[start+offset] = lb->lvl_bm[start+offset] | ((uint64_t)1<<pos);
//     // printf("%d %d\n",offset,pos);
//     //set its children to 1
//     int len=1;
//     while(hanging_level<LVL_BM){
//         len=len*32;
//         identifier = identifier<<HANGING_LEVEL;
//         hanging_level+=HANGING_LEVEL;
//         index = hanging_level/5;
//         start = LB_START[index];
//         offset = identifier/64;
//         pos = identifier%64;
//         lvl_bm_set_bits_to_1(lb,len,start+offset,pos);
//     }
// }

// void lvl_bm_set_bits_to_0(level_bitmap *lb,int len,int start,int pos){
//     if(pos+len-1<64){
//         uint64_t low = (__UINT64_MAX__)<<pos;
//         uint64_t high = (__UINT64_MAX__)>>(63-(pos+len-1));
//         uint64_t mask = ~(low&high);
//         lb->lvl_bm[start] = lb->lvl_bm[start] & mask;
//     }
//     else{
//         int start_len = 64 - pos;
//         int left_len = len - start_len;
//         int array_to_1 = left_len/64;
//         left_len = left_len - 64*array_to_1;
//         uint64_t mask1 = ~((__UINT64_MAX__)<<pos);
//         lb->lvl_bm[start] = lb->lvl_bm[start] & mask1;
//         int i=1;
//         for(;i<=array_to_1;i++){
//             lb->lvl_bm[start+i] = 0x0;
//         }
//         uint64_t mask2 = ((__UINT64_MAX__)<<left_len);
//         lb->lvl_bm[start+i] = lb->lvl_bm[start+i] & mask2;
//     }
// }

// void lvl_bm_set_bit_to_0(level_bitmap *lb, int hanging_level, uint32_t identifier){
//     int index = hanging_level/5;
//     int start = LB_START[index];
//     int offset = identifier/64;
//     int pos = identifier%64;
//     lb->lvl_bm[start+offset] = lb->lvl_bm[start+offset] & (~((uint64_t)1<<pos));
//     //set its children to 1
//     int len=1;
//     while(hanging_level<LVL_BM){
//         len=len*32;
//         identifier = identifier<<HANGING_LEVEL;
//         hanging_level+=HANGING_LEVEL;
//         index = hanging_level/5;
//         start = LB_START[index];
//         offset = identifier/64;
//         pos = identifier%64;
//         lvl_bm_set_bits_to_0(lb,len,start+offset,pos);
//     }
// }

// void lvl_bm_set(level_bitmap *lb, uint32_t identifier, uint32_t bitmap){
//     uint32_t bm = bitmap;
//     int hanging_level = count_Bits_v4_c(identifier) - 1;
//     if(hanging_level<LVL_BM){
//         //if identifier's corresponding bit is 1, then all things done
//         int offset=0, pos=0;
//         lvl_bm_get_position(identifier,hanging_level,&offset,&pos);
//         if(lvl_bm_judge_exact_bit(lb,offset,pos)) return;
//         //else set bits the bitmap can cover
//         identifier = set_one_bit_zero(identifier,hanging_level) << HANGING_LEVEL;
//         int i;
//         for(i=0;i<16;i++){
//             if((LB_PATH[i]&bm)>0){
//                 lvl_bm_set_bit_to_1(lb,hanging_level+HANGING_LEVEL,identifier+2*i);
//                 lvl_bm_set_bit_to_1(lb,hanging_level+HANGING_LEVEL,identifier+2*i+1);
//             }
//             else{
//                 lvl_bm_set_bit_to_0(lb,hanging_level+HANGING_LEVEL,identifier+2*i);
//                 lvl_bm_set_bit_to_0(lb,hanging_level+HANGING_LEVEL,identifier+2*i+1);
//             }
//         }
        
//     }
      
// }

// void lvl_bm_print_level(level_bitmap *lb,int level){
//     int i,index=level/5;
//     for(i=LB_START[index];i<LB_START[index+1];i++){
//         printf("%lx\t",lb->lvl_bm[i]);
//         if(i%4==0) printf("\n");
//     }
//     printf("\n");
// }
#include"level_bitmap.h"

void lvl_bm_init(level_bitmap *lb){
    int i=0;
    for(;i<TOTAL;i++){
        lb->lvl_bm[i]=0;
    }
}

bool lvl_bm_judge_exact_bit(level_bitmap *lb, int offset){
    return lb->lvl_bm[offset]>0;
}

void lvl_bm_add(level_bitmap *lb, int hanging_level, uint32_t identifier){
    int index = hanging_level/5;
    int start = LB_START[index];
    int offset = identifier;
    lb->lvl_bm[start+offset]++;
    int len=1;
    while(hanging_level<LVL_BM){
        len=len*32;
        identifier = identifier<<HANGING_LEVEL;
        hanging_level+=HANGING_LEVEL;
        index++;
        start = LB_START[index];
        for(int i=0;i<len;i++){
            lb->lvl_bm[start+identifier+i]++;
        }
    }
}

void lvl_bm_insert(level_bitmap *lb, uint32_t identifier, uint32_t bitmap){
    int hanging_level = count_Bits_v4_c(identifier) - 1;
    if(hanging_level<LVL_BM){
        identifier = set_one_bit_zero(identifier,hanging_level);
        int count = __builtin_popcount(bitmap);
        hanging_level+=HANGING_LEVEL;
        for(int i=0;i<count;i++){
            int index = __builtin_ctz(bitmap);
            bitmap = set_one_bit_zero(bitmap,index);
            int length = LB_LEN[index];
            uint32_t pfx = LB_PFX[index];
            uint32_t first_identifier = (identifier<<HANGING_LEVEL)+pfx;
            for(int y=0;y<length;y++){
                lvl_bm_add(lb,hanging_level,first_identifier);
                first_identifier++;
            }
        }
        // int i;
        // for(i=0;i<16;i++){
        //     if((LB_PATH[i]&bm)>0){
        //         lvl_bm_add(lb,hanging_level+HANGING_LEVEL,identifier+2*i);
        //         lvl_bm_add(lb,hanging_level+HANGING_LEVEL,identifier+2*i+1);
        //     }
        // }
        
    }  
}

void lvl_bm_sub(level_bitmap *lb, int hanging_level, uint32_t identifier){
    int index = hanging_level/5;
    int start = LB_START[index];
    int offset = identifier;
    lb->lvl_bm[start+offset]--;
    int len=1;
    while(hanging_level<LVL_BM){
        len=len*32;
        identifier = identifier<<HANGING_LEVEL;
        hanging_level+=HANGING_LEVEL;
        index++;
        start = LB_START[index];
        for(int i=0;i<len;i++){
            lb->lvl_bm[start+identifier+i]--;
        }
    }
}

void lvl_bm_remove(level_bitmap *lb, uint32_t identifier, uint32_t bitmap){
    int hanging_level = count_Bits_v4_c(identifier) - 1;
    if(hanging_level<LVL_BM){
        identifier = set_one_bit_zero(identifier,hanging_level);
        int count = __builtin_popcount(bitmap);
        hanging_level+=HANGING_LEVEL;
        for(int i=0;i<count;i++){
            int index = __builtin_ctz(bitmap);
            bitmap = set_one_bit_zero(bitmap,index);
            int length = LB_LEN[index];
            uint32_t pfx = LB_PFX[index];
            uint32_t first_identifier = (identifier<<HANGING_LEVEL)+pfx;
            for(int y=0;y<length;y++){
                lvl_bm_sub(lb,hanging_level,first_identifier);
                first_identifier++;
            }
        }
        
    }  
}

int lvl_bm_get_position(uint32_t identifier, int hanging_level){
    uint32_t mask = ~((uint32_t)1<<hanging_level);
    identifier = identifier & mask;
    int index = hanging_level/5;
    int start = LB_START[index];
    int offset = identifier;
    return offset+start;
}

void lvl_bm_print_level(level_bitmap *lb,int level){
    int i,index=level/5;
    for(i=LB_START[index];i<LB_START[index+1];i++){
        printf("%d ",lb->lvl_bm[i]);
        if((i+1)%16==0) printf("\n");
    }
    printf("\n");
    puts("------------------");
}
