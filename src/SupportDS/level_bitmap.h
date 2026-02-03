#ifndef LEVEL_BITMAP_H
#define LEVEL_BITMAP_H

/**
 * @brief define level bitmap for IPv4 optimize
*/

#include<stdint.h>
#include<math.h>
#include<stdlib.h>
#include"common.h"
#include"../utils/utils.h"
#include"../pfx/ipv4.h"

// #define TOTAL 17063
// #define LVL_BM 20

// static const int LB_START[] = {0,0,1,17,529,16913};
// static const long LB_PATH[] = {65814,131350,262678,524822,1049638,2098214,4196390,8390694,16781386,33558602,67117130,134225994,268451978,536887434,1073774730,2147516554};

// typedef struct{
//     uint64_t lvl_bm[TOTAL];
// }level_bitmap;

// /**
//  * @brief level bitmap init
//  * @param[in] lb
// */
// void lvl_bm_init(level_bitmap *lb);

// /**
//  * @brief set bits covered by (identifier+bitmap) to 1
//  * @param[in] lb
//  * @param[in] identifier
//  * @param[in] bitmap
// */
// void lvl_bm_set(level_bitmap *lb, uint32_t identifier, uint32_t bitmap);

// /**
//  * @brief make corrsponding level to standard output
//  * @param[in] lb
//  * @param[in] level
// */
// void lvl_bm_print_level(level_bitmap *lb,int level);

// bool lvl_bm_judge_exact_bit(level_bitmap *lb, int offset, int pos);
// void lvl_bm_get_position(uint32_t identifier, int hanging_level, int *offset, int *pos);

#define LVL_BM 20
#define TOTAL 1082400
static const int LB_START[] = {0,0,32,1056,33824,1082400};
static const long LB_PATH[] = {65814,131350,262678,524822,1049638,2098214,4196390,8390694,16781386,33558602,67117130,134225994,268451978,536887434,1073774730,2147516554};
static const int LB_LEN[] = {0,32,16,16,8,8,8,8,4,4,4,4,4,4,4,4,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2};
static const int LB_PFX[] = {0,
                                0,0,16,0,
                                8,16,24,0,
                                4,8,12,16,
                                20,24,28,0,
                                2,4,6,8,
                                10,12,14,16,
                                18,20,22,24,
                                26,28,30
                            };

typedef struct{
    uint8_t lvl_bm[TOTAL];
}level_bitmap;

/**
 * @brief level bitmap init
 * @param[in] lb
*/
void lvl_bm_init(level_bitmap *lb);

/**
 * @brief insert bits covered by (identifier+bitmap) to 1
 * @param[in] lb
 * @param[in] identifier
 * @param[in] bitmap
*/
void lvl_bm_insert(level_bitmap *lb, uint32_t identifier, uint32_t bitmap);
void lvl_bm_remove(level_bitmap *lb, uint32_t identifier, uint32_t bitmap);

int lvl_bm_get_position(uint32_t identifier, int hanging_level);

/**
 * @brief make corrsponding level to standard output
 * @param[in] lb
 * @param[in] level
*/
void lvl_bm_print_level(level_bitmap *lb,int level);

bool lvl_bm_judge_exact_bit(level_bitmap *lb, int offset);
#endif