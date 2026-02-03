#include"path_bitmap.h"

void path_bm_init(path_bitmap *pb){
    for(int i=0;i<TOTAL_PB;i++){
        for(int j=0;j<5;j++){
            pb->path_bm[i][j]=0;
        }
    }
}

void path_bm_add(path_bitmap *pb, int hanging_level, uint32_t identifier, int bit){
    int index = hanging_level/HANGING_LEVEL;
    int start = PB_START[index];
    int offset = identifier;
    pb->path_bm[start+offset][bit]++;
    int len=1;
    while(hanging_level<LVL_PB){
        len=len*32;
        identifier = identifier<<HANGING_LEVEL;
        hanging_level+=HANGING_LEVEL;
        index++;
        start = PB_START[index];
        for(int i=0;i<len;i++){
            pb->path_bm[start+identifier+i][bit]++;
        }
    }
}

void path_bm_insert(path_bitmap *pb, uint32_t identifier, uint32_t bitmap){
    int hanging_level = count_Bits_v4_c(identifier) - 1;
    if(hanging_level<LVL_PB){
        identifier = set_one_bit_zero(identifier,hanging_level);
        int bit = hanging_level/HANGING_LEVEL;
        int count = __builtin_popcount(bitmap);
        hanging_level+=HANGING_LEVEL;
        int start = PB_START[bit];
        int offset = identifier;
        pb->path_bm[start+offset][bit]++;
        for(int i=0;i<count;i++){
            int index = __builtin_ctz(bitmap);
            bitmap = set_one_bit_zero(bitmap,index);
            int length = PB_LEN[index];
            uint32_t pfx = PB_PFX[index];
            uint32_t first_identifier = (identifier<<HANGING_LEVEL)+pfx;
            for(int y=0;y<length;y++){
                path_bm_add(pb,hanging_level,first_identifier,bit);
                first_identifier++;
            }
        }
    }
}

void path_bm_sub(path_bitmap *pb, int hanging_level, uint32_t identifier, int bit){
    int index = hanging_level/HANGING_LEVEL;
    int start = PB_START[index];
    int offset = identifier;
    pb->path_bm[start+offset][bit]--;
    int len=1;
    while(hanging_level<LVL_PB){
        len=len*32;
        identifier = identifier<<HANGING_LEVEL;
        hanging_level+=HANGING_LEVEL;
        index++;
        start = PB_START[index];
        for(int i=0;i<len;i++){
            pb->path_bm[start+identifier+i][bit]--;
        }
    }
}

void path_bm_remove(path_bitmap *pb, uint32_t identifier, uint32_t bitmap){
    int hanging_level = count_Bits_v4_c(identifier) - 1;
    if(hanging_level<LVL_PB){
        identifier = set_one_bit_zero(identifier,hanging_level);
        int bit = hanging_level/HANGING_LEVEL;
        int count = __builtin_popcount(bitmap);
        hanging_level+=HANGING_LEVEL;
        int start = PB_START[bit];
        int offset = identifier;
        pb->path_bm[start+offset][bit]--;
        for(int i=0;i<count;i++){
            int index = __builtin_ctz(bitmap);
            bitmap = set_one_bit_zero(bitmap,index);
            int length = PB_LEN[index];
            uint32_t pfx = PB_PFX[index];
            uint32_t first_identifier = (identifier<<HANGING_LEVEL)+pfx;
            for(int y=0;y<length;y++){
                path_bm_sub(pb,hanging_level,first_identifier,bit);
                first_identifier++;
            }
        }
    }
}

void path_bm_print_level(path_bitmap *pb,int level){
    int i,index=level/5;
    for(i=PB_START[index];i<PB_START[index+1];i++){
        for(int j=0;j<5;j++){
            printf("%d ",pb->path_bm[i][j]);
        }
        printf("\t");
        if((i+1)%4==0) printf("\n");
    }
    printf("\n");
    puts("------------------");
}

int path_bm_get_position(uint32_t identifier, int hanging_level){
    uint32_t mask = ~((uint32_t)1<<hanging_level);
    identifier = identifier & mask;
    int index = hanging_level/5;
    int start = PB_START[index];
    int offset = identifier;
    return offset+start;
}

uint8_t *get_path_bm_with_position(path_bitmap *pb, int position){
    return pb->path_bm[position];
}