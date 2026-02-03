#ifndef PATH_BITMAP_H
#define PATH_BITMAP_H
/**
 * designed for ipv4 optimize
*/
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include <stdbool.h>
#include"common.h"
#include"../utils/utils.h"
#include"../pfx/ipv4.h"

#define LVL_PB 20
#define TOTAL_PB 1082400
static const int PB_START[] = {0,0,32,1056,33824,1082400};
static const long PB_PATH[] = {65814,131350,262678,524822,1049638,2098214,4196390,8390694,16781386,33558602,67117130,134225994,268451978,536887434,1073774730,2147516554};
static const int PB_LEN[] = {0,32,16,16,8,8,8,8,4,4,4,4,4,4,4,4,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2};
static const int PB_PFX[] = {0,
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
    uint8_t path_bm[TOTAL_PB][5];
}path_bitmap;

/**
 * @brief path bitmap init
 * @param[in] pb
*/
void path_bm_init(path_bitmap *pb);

/**
 * @brief insert bits covered by (identifier+bitmap) to 1
 * @param[in] lb
 * @param[in] identifier
 * @param[in] bitmap
*/
void path_bm_insert(path_bitmap *lb, uint32_t identifier, uint32_t bitmap);
void path_bm_remove(path_bitmap *lb, uint32_t identifier, uint32_t bitmap);

int path_bm_get_position(uint32_t identifier, int hanging_level);

/**
 * @brief make corrsponding level to standard output
 * @param[in] lb
 * @param[in] level
*/
void path_bm_print_level(path_bitmap *lb,int level);

uint8_t *get_path_bm_with_position(path_bitmap *pb, int position);

#endif