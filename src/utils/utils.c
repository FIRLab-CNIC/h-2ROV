#include "utils.h"

// inline void get_subtree_identifier_v6(uint32_t dest[4], const uint32_t org[4], int hanging_level)
// {
//     int move = 128-hanging_level;
//     int d=move/5;
//     int left=move%5;
//     r_move_v6_fast(org,dest,move);
//     int bit = move - 1;
//     // d = bit / 32;
//     d = bit >> 5;
//     // left = bit % 32;
//     left = bit & 31;
//     dest[d] = dest[d] | (1<<(31-left));
//     // dest[d] = dest[d] | (lmove_res[31-left]);
// }

// uint32_t get_subtree_pos_v6(const uint32_t prefix[], int hanging_level, int masklen)
// {
//     // int d = hanging_level / 32;
//     int d = hanging_level >> 5;
//     // int left = hanging_level % 32;
//     int left = hanging_level & 31;
//     int diff = masklen - hanging_level;
//     if(left+diff<=32)
//     {
//         uint32_t mask = ~0;
		
//         mask = ~(mask >> diff);

// 		mask >>= left;
// 		return ((mask & prefix[d]) >> (32*(d+1)-(masklen+1)+1))|(1<<diff);
// 		// return ((mask & prefix[d]) >> (32*(d+1)-(masklen+1)+1))|(lmove_res[diff]);
//     }
//     else
//     {
//         uint32_t part1,part2;
// 		uint32_t mask = ~0;
// 		int r = (d+1)*32-hanging_level;
// 		mask = ~(mask >> r); 
// 		mask >>= (32-r);
// 		part1 = (mask & prefix[d]);

// 		mask = ~0;
// 		mask = ~(mask >> (diff - r));
// 		part2 = (mask & prefix[d+1]) >> (32 - diff + r);
// 		return ((part1 << (diff - r)) | part2)|(1<<diff);
// 		// return ((part1 << (diff - r)) | part2)|(lmove_res[diff]);
//     }
// }

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

uint32_t get_subtree_pos_v6_t(const uint32_t prefix[], int i, int j) {
    uint32_t result = 0;

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
