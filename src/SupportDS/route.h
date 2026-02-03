#ifndef ROUTE_H
#define ROUTE_H
#include<stdio.h>
#include<stdlib.h>
#include"rtrlib/rtrlib.h"
#include"../utils/coding.h"
#include"../utils/mprint.h"
#include"compressed_trie.h"
#include"common.h"

struct fib {
  struct fib_node **hash_table;		/* Node hash table */
  uint hash_size;			/* Number of hash table entries (a power of two) */
  uint hash_order;			/* Binary logarithm of hash_size */
  uint hash_shift;			/* 32 - hash_order */
  uint addr_type;			/* Type of address data stored in fib (NET_*) */
  uint entries;				/* Number of entries */
  uint entries_min, entries_max;	/* Entry count limits (else start rehashing) */
};

struct fib_node {
  struct fib_node *next;		/* Next in hash chain */
  struct fib_iterator *readers;		/* List of readers of this node */
  net_addr *addr;
};

static inline void * fib_node_to_user(struct fib *f, struct fib_node *e)
{ return e ? e : NULL; }

static inline struct fib_node * fib_user_to_node(struct fib *f, void *e)
{ return e ? (struct fib_node *)e : NULL; }

void fib_init(struct fib *f, uint addr_type, uint hash_order);
void *fib_find(struct fib *, const net_addr *);	/* Find or return NULL if doesn't exist */
void *fib_get_chain(struct fib *f, const net_addr *a); /* Find first node in linked list from hash table */
void *fib_get(struct fib *, const net_addr *);	/* Find or create new if nonexistent */
void *fib_get_trie(struct fib *f, const net_addr *a);
// void *fib_route(struct fib *, const net_addr *); /* Longest-match routing lookup */
void fib_delete(struct fib *f, const net_addr *a);/* Remove fib entry */
// void fib_free(struct fib *);		/* Destroy the fib */
// void fib_check(struct fib *);		/* Consistency check for debugging */
void fib_print(struct fib *f);
static void fib_rehash(struct fib *f, int step);
size_t fib_memory_statistic(struct fib *f);

typedef struct rtable {
  struct fib fib;
  struct f_trie *trie;
  uint addr_type;			/* Type of address data stored in table (NET_*) */
} rtable;

//init
rtable *rt_setup(uint);
static inline void rt_add(rtable *tab, const net_addr *addr) { fib_get(&tab->fib, addr);}
static inline void rt_add_trie(rtable *tab, const net_addr *addr) { fib_get_trie(&tab->fib, addr);}
//remove

int net_roa_check_ip4_fib(rtable *tab, const net_addr_ip4 *px, u32 asn, enum pfxv_state * res);
int net_roa_check_ip6_fib(rtable *tab, const net_addr_ip6 *px, u32 asn, enum pfxv_state * res);
size_t rt_memory_statistic(rtable *tab);

int net_roa_check_ip4_trie(rtable *tab, const net_addr_ip4 *px, u32 asn, enum pfxv_state * res);
int net_roa_check_ip6_trie(rtable *tab, const net_addr_ip6 *px, u32 asn, enum pfxv_state * res);
//TODO
size_t rt_memory_statistic_trie(rtable *tab);
#endif