/*
 *	BIRD Internet Routing Daemon -- The Internet Protocol
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_IP_H_
#define _BIRD_IP_H_

#include<string.h>
#include<stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include"bird_basic.h"

#define IP4_NONE		_MI4(0)
#define IP6_NONE		_MI6(0,0,0,0)

#define IP4_MAX_PREFIX_LENGTH	32
#define IP6_MAX_PREFIX_LENGTH	128

#define IP4_MAX_TEXT_LENGTH	15	/* "255.255.255.255" */
#define IP6_MAX_TEXT_LENGTH	39	/* "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" */
#define IPA_MAX_TEXT_LENGTH	39

#define IP4_MIN_MTU		576
#define IP6_MIN_MTU		1280

#define IP_PREC_INTERNET_CONTROL 0xc0

#define IP4_HEADER_LENGTH	20
#define IP6_HEADER_LENGTH	40
#define UDP_HEADER_LENGTH	8

#define MPLS_NULL		3


/* IANA Address Family Numbers */
/* https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml */
/* Would use AF_ prefix, but that collides with POSIX address family numbers */
#define AFI_IPV4		1
#define AFI_IPV6		2


#ifdef DEBUGGING

typedef struct ip4_addr {
  u32 addr;
} ip4_addr;

#define _MI4(x) ((struct ip4_addr) { x })
#define _I(x) (x).addr

#else

typedef u32 ip4_addr;

#define _MI4(x) ((u32) (x))
#define _I(x) (x)

#endif


typedef struct ip6_addr {
  u32 addr[4];
} ip6_addr;

#define _MI6(a,b,c,d) ((struct ip6_addr) {{ a, b, c, d }})
#define _I0(a) ((a).addr[0])
#define _I1(a) ((a).addr[1])
#define _I2(a) ((a).addr[2])
#define _I3(a) ((a).addr[3])


/* Structure ip_addr may contain both IPv4 and IPv6 addresses */
typedef ip6_addr ip_addr;
#define IPA_NONE IP6_NONE

#define ipa_from_ip4(x) _MI6(0,0,0xffff,_I(x))
#define ipa_from_ip6(x) x
#define ipa_from_u32(x) ipa_from_ip4(ip4_from_u32(x))

#define ipa_to_ip4(x) _MI4(_I3(x))
#define ipa_to_ip6(x) x
#define ipa_to_u32(x) ip4_to_u32(ipa_to_ip4(x))

#define ipa_is_ip4(a) ip6_is_v4mapped(a)
#define ipa_is_ip6(a) (! ip6_is_v4mapped(a))

#define IPA_NONE4 ipa_from_ip4(IP4_NONE)
#define IPA_NONE6 ipa_from_ip6(IP6_NONE)


/*
 *	Public constructors
 */

#define ip4_from_u32(x) _MI4(x)
#define ip4_to_u32(x) _I(x)

#define ip4_build(a,b,c,d) _MI4(((a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define ip6_build(a,b,c,d) _MI6(a,b,c,d)

#define ipa_build4(a,b,c,d) ipa_from_ip4(ip4_build(a,b,c,d))
#define ipa_build6(a,b,c,d) ipa_from_ip6(ip6_build(a,b,c,d))


/*
 *	Basic algebraic functions
 */

static inline int ip4_equal(ip4_addr a, ip4_addr b)
{ return _I(a) == _I(b); }

static inline int ip4_zero(ip4_addr a)
{ return _I(a) == 0; }

static inline int ip4_nonzero(ip4_addr a)
{ return _I(a) != 0; }

static inline ip4_addr ip4_and(ip4_addr a, ip4_addr b)
{ return _MI4(_I(a) & _I(b)); }

static inline ip4_addr ip4_or(ip4_addr a, ip4_addr b)
{ return _MI4(_I(a) | _I(b)); }

static inline ip4_addr ip4_xor(ip4_addr a, ip4_addr b)
{ return _MI4(_I(a) ^ _I(b)); }

static inline ip4_addr ip4_not(ip4_addr a)
{ return _MI4(~_I(a)); }


static inline int ip6_equal(ip6_addr a, ip6_addr b)
{ return _I0(a) == _I0(b) && _I1(a) == _I1(b) && _I2(a) == _I2(b) && _I3(a) == _I3(b); }

static inline int ip6_zero(ip6_addr a)
{ return  !_I0(a) && !_I1(a) && !_I2(a) && !_I3(a); }

static inline int ip6_nonzero(ip6_addr a)
{ return _I0(a) || _I1(a) || _I2(a) || _I3(a); }

static inline ip6_addr ip6_and(ip6_addr a, ip6_addr b)
{ return _MI6(_I0(a) & _I0(b), _I1(a) & _I1(b), _I2(a) & _I2(b), _I3(a) & _I3(b)); }

static inline ip6_addr ip6_or(ip6_addr a, ip6_addr b)
{ return _MI6(_I0(a) | _I0(b), _I1(a) | _I1(b), _I2(a) | _I2(b), _I3(a) | _I3(b)); }

static inline ip6_addr ip6_xor(ip6_addr a, ip6_addr b)
{ return _MI6(_I0(a) ^ _I0(b), _I1(a) ^ _I1(b), _I2(a) ^ _I2(b), _I3(a) ^ _I3(b)); }

static inline ip6_addr ip6_not(ip6_addr a)
{ return _MI6(~_I0(a), ~_I1(a), ~_I2(a), ~_I3(a)); }


#define ipa_equal(x,y) ip6_equal(x,y)
#define ipa_zero(x) ip6_zero(x)
#define ipa_nonzero(x) ip6_nonzero(x)
#define ipa_and(x,y) ip6_and(x,y)
#define ipa_or(x,y) ip6_or(x,y)
#define ipa_xor(x,y) ip6_xor(x,y)
#define ipa_not(x) ip6_not(x)


/*
 * A zero address is either a token for invalid/unused, or the prefix of default
 * routes. These functions should be used in the second case, where both IPv4
 * and IPv6 zero addresses should be checked.
 */

static inline int ipa_zero2(ip_addr a)
{ return  !_I0(a) && !_I1(a) && ((_I2(a) == 0) || (_I2(a) == 0xffff)) && !_I3(a); }

static inline int ipa_nonzero2(ip_addr a)
{ return _I0(a) || _I1(a) || ((_I2(a) != 0) && (_I2(a) != 0xffff)) || _I3(a); }


/*
 *	Hash and compare functions
 */

static inline u32 ip4_hash(ip4_addr a)
{ return u32_hash(_I(a)); }

static inline u32 ip6_hash(ip6_addr a)
{
  /* Returns a 32-bit hash key, although low-order bits are not mixed */
  u32 x = _I0(a) ^ _I1(a) ^ _I2(a) ^ _I3(a);
  return x ^ (x << 16) ^ (x << 24);
}

static inline int ip4_compare(ip4_addr a, ip4_addr b)
{ return (_I(a) > _I(b)) - (_I(a) < _I(b)); }

static int ip6_compare(ip6_addr a, ip6_addr b){
  int i;
  for (i=0; i<4; i++)
    if (a.addr[i] > b.addr[i])
      return 1;
    else if (a.addr[i] < b.addr[i])
      return -1;
  return 0;
}

#define ipa_hash(x) ip6_hash(x)
#define ipa_compare(x,y) ip6_compare(x,y)


/*
 *	IP address classification
 */

/* Address class */
#define IADDR_INVALID		-1
#define IADDR_SCOPE_MASK       	0xfff
#define IADDR_HOST		0x1000
#define IADDR_BROADCAST		0x2000
#define IADDR_MULTICAST		0x4000

/* Address scope */
#define SCOPE_HOST		0
#define SCOPE_LINK		1
#define SCOPE_SITE		2
#define SCOPE_ORGANIZATION	3
#define SCOPE_UNIVERSE		4
#define SCOPE_UNDEFINED		5

int ip4_classify(ip4_addr ad);
int ip6_classify(ip6_addr *a);

static inline int ip6_is_link_local(ip6_addr a)
{ return (_I0(a) & 0xffc00000) == 0xfe800000; }

static inline int ip6_is_v4mapped(ip6_addr a)
{ return _I0(a) == 0 && _I1(a) == 0 && _I2(a) == 0xffff; }

#define ipa_classify(x) ip6_classify(&(x))
#define ipa_is_link_local(x) ip6_is_link_local(x)

static inline int ip4_is_unicast(ip4_addr a)
{ return _I(a) < 0xe0000000; }

/* XXXX remove */
static inline int ipa_classify_net(ip_addr a)
{ return ipa_zero2(a) ? (IADDR_HOST | SCOPE_UNIVERSE) : ipa_classify(a); }


/*
 *	Miscellaneous IP prefix manipulation
 */

static inline ip4_addr ip4_mkmask(uint n)
{ return _MI4(u32_mkmask(n)); }

static inline uint ip4_masklen(ip4_addr a)
{ return u32_masklen(_I(a)); }

static ip6_addr ip6_mkmask(uint n){
  ip6_addr a;
  int i;

  for (i=0; i<4; i++)
  {
    if (!n)
      a.addr[i] = 0;
    else if (n >= 32)
    {
      a.addr[i] = ~0;
      n -= 32;
    }
    else
    {
      a.addr[i] = u32_mkmask(n);
      n = 0;
    }
  }

  return a;
}

static uint ip6_masklen_t(ip6_addr *a){
  int i, j, n;

  for (i=0, n=0; i<4; i++, n+=32)
    if (a->addr[i] != ~0U)
    {
      j = u32_masklen(a->addr[i]);
      if (j == 255)
	return j;
      n += j;
      while (++i < 4)
	if (a->addr[i])
	  return 255;
      break;
    }

  return n;
}

/* ipX_pxlen() requires that x != y */
static inline uint ip4_pxlen(ip4_addr a, ip4_addr b)
{ return 31 - u32_log2(_I(a) ^ _I(b)); }

static inline uint ip6_pxlen(ip6_addr a, ip6_addr b)
{
  int i = 0;
  i += (a.addr[i] == b.addr[i]);
  i += (a.addr[i] == b.addr[i]);
  i += (a.addr[i] == b.addr[i]);
  i += (a.addr[i] == b.addr[i]);
  return 32 * i + 31 - u32_log2(a.addr[i] ^ b.addr[i]);
}

static inline int ip4_prefix_equal(ip4_addr a, ip4_addr b, uint n)
{
  return (_I(a) ^ _I(b)) < ((u64) 1 << (32 - n));
}

static inline int ip6_prefix_equal(ip6_addr a, ip6_addr b, uint n)
{
  uint n0 = n / 32;
  uint n1 = n % 32;

  return
    ((n0 <= 0) || (_I0(a) == _I0(b))) &&
    ((n0 <= 1) || (_I1(a) == _I1(b))) &&
    ((n0 <= 2) || (_I2(a) == _I2(b))) &&
    ((n0 <= 3) || (_I3(a) == _I3(b))) &&
    (!n1 || ((a.addr[n0] ^ b.addr[n0]) < (1u << (32 - n1))));
}

static inline u32 ip4_getbit(ip4_addr a, uint pos)
{ return (_I(a) >> (31 - pos)) & 1; }

static inline u32 ip4_getbits(ip4_addr a, uint pos, uint n)
{ return (_I(a) >> ((32 - n) - pos)) & ((1u << n) - 1); }

static inline u32 ip6_getbit(ip6_addr a, uint pos)
{ return (a.addr[pos / 32] >> (31 - (pos % 32))) & 0x1; }

static inline u32 ip6_getbits(ip6_addr a, uint pos, uint n)
{ return (a.addr[pos / 32] >> ((32 - n) - (pos % 32))) & ((1u << n) - 1); }

static inline u32 ip4_setbit(ip4_addr *a, uint pos)
{ return _I(*a) |= (0x80000000 >> pos); }

static inline u32 ip6_setbit(ip6_addr *a, uint pos)
{ return a->addr[pos / 32] |= (0x80000000 >> (pos % 32)); }

static inline u32 ip4_clrbit(ip4_addr *a, uint pos)
{ return _I(*a) &= ~(0x80000000 >> pos); }

static inline u32 ip6_clrbit(ip6_addr *a, uint pos)
{ return a->addr[pos / 32] &= ~(0x80000000 >> (pos % 32)); }

static inline ip4_addr ip4_setbits(ip4_addr a, uint pos, uint val)
{ _I(a) |= val << (31 - pos); return a; }

static inline ip6_addr ip6_setbits(ip6_addr a, uint pos, uint val)
{ a.addr[pos / 32] |= val << (31 - pos % 32); return a; }


static inline ip4_addr ip4_opposite_m1(ip4_addr a)
{ return _MI4(_I(a) ^ 1); }

static inline ip4_addr ip4_opposite_m2(ip4_addr a)
{ return _MI4(_I(a) ^ 3); }

static inline ip6_addr ip6_opposite_m1(ip6_addr a)
{ return _MI6(_I0(a), _I1(a), _I2(a), _I3(a) ^ 1); }

static inline ip6_addr ip6_opposite_m2(ip6_addr a)
{ return _MI6(_I0(a), _I1(a), _I2(a), _I3(a) ^ 3); }

ip4_addr ip4_class_mask(ip4_addr ad);

#define ipa_opposite_m1(x) ip6_opposite_m1(x)
#define ipa_opposite_m2(x) ip6_opposite_m2(x)


#endif
