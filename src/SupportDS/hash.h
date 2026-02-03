#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include"../pfx/ipv6.h"

#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))
#define rot16(x, k) (((x) << (k)) | ((x) >> (16 - (k))))
#define rot8(x, k) (((x) << (k)) | ((x) >> (8 - (k))))

static uint32_t
hxgcum(unsigned int *key, int byte_len, unsigned int initval)
{
    unsigned short *srt = (unsigned short*) key;
    unsigned int *itr;
    uint32_t h = initval;

    itr = (uint32_t *)srt;

    switch (byte_len) {
        case 8:
            h += rot(itr[0], 5);
            h += rot(itr[1], 11);
            break;
        case 4:
            h += rot(itr[0], 5);
            break;
    }

    return h;
}

#endif