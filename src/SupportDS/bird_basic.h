#ifndef BIRD_BASIC_H
#define BIRD_BASIC_H

#include<stdint.h>
#include<string.h>
#include <netinet/in.h>

typedef int8_t s8;
typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef int32_t s32;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;
typedef uint8_t byte;
typedef uint16_t word;
typedef unsigned int uint;

#define ROUND_DOWN_POW2(a,b)  ((a) & ~((b)-1))

#define MIN_(a,b) (((a)<(b))?(a):(b))
#define MAX_(a,b) (((a)>(b))?(a):(b))

#ifndef PARSER
#undef MIN
#undef MAX
#define MIN(a,b) MIN_(a,b)
#define MAX(a,b) MAX_(a,b)
#endif

static inline u32 u32_hash(u32 v) { return v * 2902958171u; }

static inline u32 u32_mkmask(uint n){ return n ? ~((1 << (32 - n)) - 1) : 0;}

static uint u32_masklen(u32 x)
{
  int l = 0;
  u32 n = ~x;

  if (n & (n+1)) return 255;
  if (x & 0x0000ffff) { x &= 0x0000ffff; l += 16; }
  if (x & 0x00ff00ff) { x &= 0x00ff00ff; l += 8; }
  if (x & 0x0f0f0f0f) { x &= 0x0f0f0f0f; l += 4; }
  if (x & 0x33333333) { x &= 0x33333333; l += 2; }
  if (x & 0x55555555) l++;
  if (x & 0xaaaaaaaa) l++;
  return l;
}

static u32 u32_log2(u32 v)
{
  /* The code from http://www-graphics.stanford.edu/~seander/bithacks.html */
  u32 r, shift;
  r =     (v > 0xFFFF) << 4; v >>= r;
  shift = (v > 0xFF  ) << 3; v >>= shift; r |= shift;
  shift = (v > 0xF   ) << 2; v >>= shift; r |= shift;
  shift = (v > 0x3   ) << 1; v >>= shift; r |= shift;
  r |= (v >> 1);
  return r;
}


static inline u32
get_u32(const void *p)
{
  u32 x;
  memcpy(&x, p, 4);
  return ntohl(x);
}

typedef struct buffer {
  byte *start;
  byte *pos;
  byte *end;
} buffer;

#define STACK_BUFFER_INIT(buf,size)		\
  do {						\
    buf.start = alloca(size);			\
    buf.pos = buf.start;			\
    buf.end = buf.start + size;			\
  } while(0)

#define LOG_BUFFER_INIT(buf)			\
  STACK_BUFFER_INIT(buf, LOG_BUFFER_SIZE)

#define LOG_BUFFER_SIZE 1024


#endif