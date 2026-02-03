#ifndef UTILS_H
#define UTILS_H

/**
 * @brief utils about IP/hanging level
 * 
*/
#include<stdint.h>
#include<stdio.h>
#include "../pfx/ipv6.h"



#define min_t(a,b)((a<b)?a:b)
#define max_t(a,b)((a<b)?b:a)
/**
 * @brief get hanging level by given masklen
 * @param[in] _masklen the len of the prefix
*/
#define get_hanging_level(_masklen)(_masklen-_masklen%HANGING_LEVEL)

/**
 * @brief set uint32_t last bit to 0
 * @param[in] _org uint32_t
*/
#define set_last_bit_zero(_org)(_org & (0xfffffffe))

/**
 * @brief set a certain bit to 0
 * @param[in,out] _org uint32_t
 * @param[in] _index index of the bit you want to set to 0, ranges in [0,31]
*/
#define set_one_bit_zero(_org,_index)(_org & (~(1<<_index)))

#define set_one_bit_zero_v6(_org,_index)(_org[3-((_index)/32)] &= (~(1<<((_index)%32))))

#define get_bits_c(val, from, number, move, res){  \
	uint32_t mask = ~0;                            \
	if (number != 32)                              \
		mask = ~(mask >> number);                  \
	mask >>= from;                                 \
	*res = (mask & val) >> move;                   \
}

/**
 * @brief get subtree identifier by given prefix and hanging level
 * @param[in] org given prefix
 * @param[in] hanging_level
*/
#define get_subtree_identifier_v4(_org, _hanging_level)((_org >> (32-_hanging_level))|(1<<_hanging_level))


#define get_position_v4_c(src,total_len, from,res){                  \
    int diff = 32 - total_len;                                       \
    int dest = diff + 1 + from + 1;                                  \
    int move = 32 - dest - HANGING_LEVEL + 1;                        \
    get_bits_c(src, dest, HANGING_LEVEL - 1, move, res);             \
}

/**
 * @brief get subtree identifier by given prefix and hanging level
 * @param[in,out] dest result identifier
 * @param[in] org given prefix
 * @param[in] hanging_level
*/
#define get_subtree_identifier_v6(dest, org, hanging_level) \
{                                                           \
    int _move = 128-hanging_level;                           \
    int _d=_move/5;                                           \
    int _left=_move%5;                                        \
    r_move_v6_fast(org,dest,_move);                          \
    int _bit = _move - 1;                                     \
    _d = _bit >> 5;                                           \
    _left = _bit & 31;                                        \
    dest[_d] = dest[_d] | (1<<(31-_left));                     \
}
// inline void get_subtree_identifier_v6(uint32_t dest[4], const uint32_t org[4], int hanging_level);


/**
 * @brief get prefix in subtree's position
 * @param[in] prefix
 * @param[in] hanging_level hanging level to the subtree id related to prefix
 * @param[in] masklen masklen of the prefix
*/
#define get_subtree_pos_v6(prefix, hanging_level, masklen, res)  \
{\
    int _d = hanging_level >> 5;\
    int _left = hanging_level & 31;\
    int _diff = masklen - hanging_level;\
    if(_left+_diff<=32)\
    {\
        uint32_t _mask = ~0;\
        _mask = ~(_mask >> _diff);\
		_mask >>= _left;\
		res = ((_mask & prefix[_d]) >> (32*(_d+1)-(masklen+1)+1))|(1<<_diff);\
    }\
    else\
    {\
        uint32_t _part1,_part2;\
		uint32_t _mask = ~0;\
		int _r = (_d+1)*32-hanging_level;\
		_mask = ~(_mask >> _r); \
		_mask >>= (32-_r);\
		_part1 = (_mask & prefix[_d]);\
		_mask = ~0;\
		_mask = ~(_mask >> (_diff - _r));\
		_part2 = (_mask & prefix[_d+1]) >> (32 - _diff + _r);\
		res = ((_part1 << (_diff - _r)) | _part2)|(1<<_diff);\
    }\
}

uint32_t get_subtree_pos_v6_t(const uint32_t prefix[], int hanging_level, int masklen);
uint32_t get_subtree_pos_v6_exp(const uint32_t prefix[], int hanging_level, int masklen);

#endif