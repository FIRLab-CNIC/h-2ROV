#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>

typedef uint32_t ipv4;

/**
 * @brief count how many bits > 0 in uint32_t
 * @param[in] _ip_addr uint32_t
*/
#define count_Bits_v4_c(_ip_addr)((int)log2(_ip_addr)+1)

#define r_move_v4(src,dest,lvl) (dest=src>>lvl)
#define l_move_v4(src,dest,lvl) (dest=src<<lvl)

#endif