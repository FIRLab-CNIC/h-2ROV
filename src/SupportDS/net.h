#ifndef NET_H
#define NET_H

#include<string.h>
#include<stdint.h>
#include"bird_ip.h"

#define ROA_UNKNOWN	0
#define ROA_VALID	1
#define ROA_INVALID	2

#define NET_IP4		1
#define NET_IP6		2
#define NET_VPN4	3
#define NET_VPN6	4
#define NET_ROA4	5
#define NET_ROA6	6
#define NET_FLOW4	7
#define NET_FLOW6	8
#define NET_IP6_SADR	9
#define NET_MPLS	10
#define NET_MAX		11

#define NB_IP4		(1 << NET_IP4)
#define NB_IP6		(1 << NET_IP6)
#define NB_VPN4		(1 << NET_VPN4)
#define NB_VPN6		(1 << NET_VPN6)
#define NB_ROA4		(1 << NET_ROA4)
#define NB_ROA6		(1 << NET_ROA6)
#define NB_FLOW4	(1 << NET_FLOW4)
#define NB_FLOW6	(1 << NET_FLOW6)
#define NB_IP6_SADR	(1 << NET_IP6_SADR)
#define NB_MPLS		(1 << NET_MPLS)

#define NB_IP		(NB_IP4 | NB_IP6)
#define NB_VPN		(NB_VPN4 | NB_VPN6)
#define NB_ROA		(NB_ROA4 | NB_ROA6)
#define NB_FLOW		(NB_FLOW4 | NB_FLOW6)
#define NB_DEST		(NB_IP | NB_IP6_SADR | NB_VPN | NB_MPLS)
#define NB_ANY		0xffffffff

typedef struct net_addr {
  u8 type;
  u8 pxlen;
  u16 length;
  u8 data[20];
  u64 align[0];
} net_addr;

typedef struct net_addr_ip4 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip4_addr prefix;
} net_addr_ip4;

typedef struct net_addr_ip6 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip6_addr prefix;
} net_addr_ip6;

typedef struct net_addr_roa4 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip4_addr prefix;
  u32 max_pxlen;
  u32 asn;
} net_addr_roa4;

typedef struct net_addr_roa6 {
  u8 type;
  u8 pxlen;
  u16 length;
  ip6_addr prefix;
  u32 max_pxlen;
  u32 asn;
} net_addr_roa6;

typedef union net_addr_union {
  net_addr n;
  net_addr_ip4 ip4;
  net_addr_ip6 ip6;
  net_addr_roa4 roa4;
  net_addr_roa6 roa6;
} net_addr_union;

#define NET_ADDR_IP4(prefix,pxlen) \
  ((net_addr_ip4) { NET_IP4, pxlen, sizeof(net_addr_ip4), prefix })

#define NET_ADDR_IP6(prefix,pxlen) \
  ((net_addr_ip6) { NET_IP6, pxlen, sizeof(net_addr_ip6), prefix })

#define NET_ADDR_ROA4(prefix,pxlen,max_pxlen,asn) \
  ((net_addr_roa4) { NET_ROA4, pxlen, sizeof(net_addr_roa4), prefix, max_pxlen, asn })

#define NET_ADDR_ROA6(prefix,pxlen,max_pxlen,asn) \
  ((net_addr_roa6) { NET_ROA6, pxlen, sizeof(net_addr_roa6), prefix, max_pxlen, asn })

static inline u32 net_hash_roa4(const net_addr_roa4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_roa6(const net_addr_roa6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26); }


static inline ip4_addr net4_prefix(const net_addr *a)
{ return ((net_addr_ip4 *) a)->prefix; }

static inline ip6_addr net6_prefix(const net_addr *a)
{ return ((net_addr_ip6 *) a)->prefix; }

static inline uint net4_pxlen(const net_addr *a)
{ return a->pxlen; }

static inline uint net6_pxlen(const net_addr *a)
{ return a->pxlen; }

static inline uint net_pxlen(const net_addr *a)
{ return a->pxlen; }

static inline int net_equal(const net_addr *a, const net_addr *b)
{ return (a->length == b->length) && !memcmp(a, b, a->length); }

static inline int net_equal_roa4(const net_addr_roa4 *a, const net_addr_roa4 *b)
{ return !memcmp(a, b, sizeof(net_addr_roa4)); }

static inline int net_equal_roa6(const net_addr_roa6 *a, const net_addr_roa6 *b)
{ return !memcmp(a, b, sizeof(net_addr_roa6)); }

static inline void net_copy_roa4(net_addr_roa4 *dst, const net_addr_roa4 *src)
{ memcpy(dst, src, sizeof(net_addr_roa4)); }

static inline void net_copy_roa6(net_addr_roa6 *dst, const net_addr_roa6 *src)
{ memcpy(dst, src, sizeof(net_addr_roa6)); }

static inline int net_equal_prefix_roa4(const net_addr_roa4 *a, const net_addr_roa4 *b)
{ return ip4_equal(a->prefix, b->prefix) && (a->pxlen == b->pxlen); }

static inline int net_equal_prefix_roa6(const net_addr_roa6 *a, const net_addr_roa6 *b)
{ return ip6_equal(a->prefix, b->prefix) && (a->pxlen == b->pxlen); }

static inline void net_fill_ip4(net_addr *a, ip4_addr prefix, uint pxlen)
{ *(net_addr_ip4 *)a = NET_ADDR_IP4(prefix, (u8)pxlen); }

static inline void net_fill_ip6(net_addr *a, ip6_addr prefix, uint pxlen)
{ *(net_addr_ip6 *)a = NET_ADDR_IP6(prefix, (u8)pxlen); }

#endif
