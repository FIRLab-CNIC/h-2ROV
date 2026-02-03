#include "hrov.h"

uint32_t get_bits_128_c(const uint32_t val[4], const uint32_t from, const uint8_t number, int move)
{
	int d = from / 32;
	int left = from % 32;
	if(left+number<=32)
	{
		uint32_t mask = ~0;
		if (number != 32)
			mask = ~(mask >> number);

		mask >>= left;
		return (mask & val[d]) >> move;
	}
	else
	{
		uint32_t part1,part2;
		uint32_t mask = ~0;
		int r = (d+1)*32-from;
		mask = ~(mask >> r); 
		mask >>= (32-r);
		part1 = (mask & val[d]);

		mask = ~0;
		mask = ~(mask >> (number - r));
		part2 = (mask & val[d+1]);
		return (part1 << (number - r)) | (part2 >> (32 - (number - r)));
	}
	return 0;
}

int get_position_v6_c(uint32_t src[4], int total_len, int from)
{
    int diff = 128 - total_len;
    int dest = diff + from + 2;
    int move = 128 - dest - HANGING_LEVEL + 1;
    return get_bits_128_c(src, dest, HANGING_LEVEL -1, move);
}

int ShortDivOutputBin(uint32_t input)
{
    uint8_t temp[33] = {0};  
    int i = 0;
    while(input)
    {
        temp[i] = input % 2;    //取余数存放到数组中，此为得到的二进制数
        input = (uint32_t)input / 2;  //短除，while中判断是否除尽
        i++;  //存储了一个二进制数，自加存储下一个
    }
	return i - 1;
}

// bool have_child(uint32_t bitmap, int num) {
//     return num <= 15 && bitmap & 1 << (num << 1) != 0 && bitmap & 1 << ((num << 1) + 1) != 0;
// }

// int cal_sub_tree_height(uint32_t *bitmap,int count){
//     int sub_tree_height = 0;
//     int queue[32];
//     int headptr=0,currprt=0,queueSize=0;
//     queue[0]=count;
//     currprt=1;
//     queueSize=1;
//     while(1){
//         while(queueSize>0){
//             int h = queue[headptr];
//             headptr++;
//             queueSize--;
//             *bitmap &= ~(1<<h);
//             if(!have_child(*bitmap,h)){
//                 return sub_tree_height;
//             }
//             int child = h << 1;
//             queue[currprt] = child;
//             currprt++;
//             queue[currprt] = child+1;
//             currprt++;
//         }
        
//         sub_tree_height++;
//     }
// }

// void bitmap_to_pfx_v6(uint32_t identifier[], uint32_t bitmap){
//     int count = __builtin_popcount(bitmap);
//     uint32_t pfx[count][4];
//     int res=0;
//     count_Bits_v6_c(identifier,&res);
//     int basic_mask_length = res-1;
//     for(int i=0;i<4;i++){
//         if(identifier[i]!=0){
//             int first_zero = __builtin_clz(identifier[i]);
//             identifier[i]=identifier[i]&(~(1<<(31-first_zero)));
//             break;
//         }
//     }
//     // SHOW_IPV6_oct(identifier);
//     int i=0;
//     while(bitmap>1){
//         int last_zero = __builtin_ctz(bitmap);
//         if(last_zero==0){
//             continue;
//         }
//         memcpy(pfx[i],identifier,sizeof(uint32_t)*4);
//         bitmap = bitmap &(~(1<<last_zero));
//         int sub_tree_height = cal_sub_tree_height(&bitmap,i);
//         int sub_len = (int)log2(last_zero)+1-1;
//         if(sub_len>0) l_move_v6(pfx[i],pfx[i],sub_len);
//         pfx[i][3]=pfx[i][3]+(last_zero&((1<<sub_len)-1));
//         l_move_v6(pfx[i],pfx[i],(128-sub_len-basic_mask_length));
//         SHOW_IPV6_oct(pfx[i]);

//         printf("%d\n",basic_mask_length+sub_len);
//     }
// }



uint32_t calculate_bitmap(uint32_t prefix,int masklen,int maxlen){
    int hanging_level = get_hanging_level(masklen);
    int next_hanging_level = hanging_level + 5;
    uint32_t bitmap=0;
    int t=1,r=min_t(maxlen,next_hanging_level-1);
    int index=0;
    get_subtree_pos_v4_c(prefix, hanging_level, masklen, &index);
    for(int i=masklen;i<=r;i++){
        uint32_t bit = 1<<index;
        for(int j=0;j<t;j++){
            bitmap |= bit;
            bit=bit<<1;
        }
        index*=2;
        t=t*2;
    }
    return bitmap;
}

uint32_t calculate_bitmap_v6(uint32_t prefix[],int masklen,int maxlen){
    int hanging_level = get_hanging_level(masklen);
    int next_hanging_level = hanging_level + HANGING_LEVEL;
    uint32_t bitmap=0;
    uint32_t index=0;
    get_subtree_pos_v6(prefix,hanging_level,masklen,index);
    int times=1;
    for(int i=masklen;i<=min_t(maxlen,next_hanging_level-1);i++){
        uint32_t bit = 1<<index;
        for(int j=0;j<times;j++){
            bitmap |= bit;
            bit=bit<<1;
        }
        times*=2;
        index*=2;
    }
    return bitmap;
}

