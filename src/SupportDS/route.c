#include"route.h"

#define HASH_DEF_ORDER 10
#define HASH_HI_MARK * 2
#define HASH_HI_STEP 1
#define HASH_HI_MAX 24
#define HASH_LO_MARK / 5
#define HASH_LO_STEP 2
#define HASH_LO_MIN 10

#define NET_HASH(a,t) net_hash_##t((const net_addr_##t *) a)
#define OFFSETOF(s, i) ((size_t) &((s *)0)->i)
#define SKIP_BACK(s, i, p) ((s *)((char *)p - OFFSETOF(s, i)))

u32
net_hash(const net_addr *n)
{
  switch (n->type)
  {
  case NET_ROA4: return NET_HASH(n, roa4);
  case NET_ROA6: return NET_HASH(n, roa6);
  default: puts("invalid type");
  }
}


static inline u32
fib_hash(struct fib *f, const net_addr *a)
{
  /* Same as FIB_HASH() */
  return net_hash(a) >> f->hash_shift;
}

static void
fib_ht_alloc(struct fib *f)
{
  f->hash_size = 1 << f->hash_order;
  f->hash_shift = 32 - f->hash_order;
  if (f->hash_order > HASH_HI_MAX - HASH_HI_STEP)
    f->entries_max = ~0;
  else
    f->entries_max = f->hash_size HASH_HI_MARK;
  if (f->hash_order < HASH_LO_MIN + HASH_LO_STEP)
    f->entries_min = 0;
  else
    f->entries_min = f->hash_size HASH_LO_MARK;
  f->hash_table = malloc(f->hash_size * sizeof(struct fib_node *));
  bzero(f->hash_table, f->hash_size * sizeof(struct fib_node *));
}

/**
 * fib_init - initialize a new FIB
 * @f: the FIB to be initialized (the structure itself being allocated by the caller)
 * @node_size: node size to be used (each node consists of a standard header &fib_node
 * followed by user data)
 * @hash_order: initial hash order (a binary logarithm of hash table size), 0 to use default order
 * (recommended)
 * @init: pointer a function to be called to initialize a newly created node
 *
 * This function initializes a newly allocated FIB and prepares it for use.
 */
void
fib_init(struct fib *f, uint addr_type, uint hash_order)
{
  if (!hash_order)
    hash_order = HASH_DEF_ORDER;
  f->addr_type = addr_type;
  f->hash_order = hash_order;
  fib_ht_alloc(f);
  f->entries = 0;
  f->entries_min = 0;
}

#define CAST(t) (const net_addr_##t *)
#define CAST2(t) (net_addr_##t *)
#define FIB_HASH(f,a,t) (net_hash_##t(CAST(t) a) >> f->hash_shift)

#define FIB_INSERT(f,a,e,t)						\
  ({									\
  u32 h = net_hash_##t(CAST(t) a);					\
  struct fib_node **ee = f->hash_table + (h >> f->hash_shift);		\
  struct fib_node *g;							\
  while ((g = *ee) && (net_hash_##t(CAST(t) g->addr) < h))		\
    ee = &g->next;							\
							\
  e->next = *ee;							\
  *ee = e;								\
  })

static void
fib_insert(struct fib *f, const net_addr *a, struct fib_node *e)
{
  assert(f->addr_type == a->type);
  switch (f->addr_type)
  {
  case NET_ROA4: FIB_INSERT(f, a, e, roa4); return;
  case NET_ROA6: FIB_INSERT(f, a, e, roa6); return;
  default: puts("invalid type");
  }
}

#define FIB_FIND(f,a,t)							\
  ({									\
    struct fib_node *e = f->hash_table[FIB_HASH(f, a, t)];		\
    while (e && !net_equal_##t(CAST(t) e->addr, CAST(t) a)){		\
      e = e->next;					\
    }\
    fib_node_to_user(f, e);						\
  })

void fib_print(struct fib *f){
  for(int i=0;i<f->hash_size;i++){
    if(f->hash_table[i]){
      struct fib_node *e = f->hash_table[i];
      if(e->addr->type==NET_ROA4){
        struct fib_node *ee = e;
        puts("list header");
        while(ee){
          net_addr_roa4 *et = (net_addr_roa4 *)ee->addr;
          printf("%x/%d %d %u\n",et->prefix,et->pxlen,et->max_pxlen,et->asn);
          ee=ee->next;
        }
      }
    }
  }
}

/**
 * fib_find - search for FIB node by prefix
 * @f: FIB to search in
 * @n: network address
 *
 * Search for a FIB node corresponding to the given prefix, return
 * a pointer to it or %NULL if no such node exists.
 */
void *
fib_find(struct fib *f, const net_addr *a)
{
  assert(f->addr_type == a->type);

  switch (f->addr_type)
  {
      case NET_ROA4: return FIB_FIND(f, a, roa4);
      case NET_ROA6: return FIB_FIND(f, a, roa6);
      default: puts("invalid type");break;
  }
}


/**
 * fib_get - find or create a FIB node
 * @f: FIB to work with
 * @n: network address
 *
 * Search for a FIB node corresponding to the given prefix and
 * return a pointer to it. If no such node exists, create it.
 */
void *
fib_get(struct fib *f, const net_addr *a)
{
  void *b = fib_find(f, a);
  if (b)
    return b;
  b = malloc(sizeof(struct fib_node));
  struct fib_node *e = b;
  e->readers = NULL;
  if(a->type == NET_ROA4){
    e->addr = malloc(sizeof(net_addr_roa4));
    memcpy(e->addr,a,sizeof(net_addr_roa4));
  }
  else if(a->type == NET_ROA6){
    e->addr = malloc(sizeof(net_addr_roa6));
    memcpy(e->addr,a,sizeof(net_addr_roa6));
  }
  fib_insert(f, a, e);
  if (f->entries++ > f->entries_max)
    fib_rehash(f, HASH_HI_STEP);
  return b;
}

/**
 * fib_delete - delete a FIB node
 * @f: FIB to delete from
 * @E: entry to delete
 *
 * This function removes the given entry from the FIB,
 * taking care of all the asynchronous readers by shifting
 * them to the next node in the canonical reading order.
 */
void
fib_delete(struct fib *f, const net_addr *a)
{
  void *b = fib_find(f, a);
  if (b){
    struct fib_node *e = b;
    uint h = fib_hash(f, a);
    struct fib_node **ee = f->hash_table + h;

    while (*ee)
      {
        if (*ee == e)
        {
          *ee = e->next;
          free(e);

          if (f->entries-- < f->entries_min)
            fib_rehash(f, -HASH_LO_STEP);
          return;
        }
        ee = &((*ee)->next);
      }
  }
  else{
    puts("fib_delete() called for invalid node");
  }
}

void *
fib_get_trie(struct fib *f, const net_addr *a)
{
  void *b = fib_find(f, a);
  if (b)
    return b;
  b = malloc(sizeof(struct fib_node));
  struct fib_node *e = b;
  e->readers = NULL;
  if(a->type == NET_ROA4){
    e->addr = malloc(sizeof(net_addr_roa4));
    memcpy(e->addr,a,sizeof(net_addr_roa4));
  }
  else if(a->type == NET_ROA6){
    e->addr = malloc(sizeof(net_addr_roa6));
    memcpy(e->addr,a,sizeof(net_addr_roa6));
  }
  fib_insert(f, a, e);
  rtable *tab = SKIP_BACK(rtable, fib, f);
  trie_add_prefix(tab->trie,e->addr,e->addr->pxlen,e->addr->pxlen);
  if (f->entries++ > f->entries_max)
    fib_rehash(f, HASH_HI_STEP);
  return b;
}


static void
fib_rehash(struct fib *f, int step)
{
  unsigned old, new, oldn, newn, ni, nh;
  struct fib_node **n, *e, *x, **t, **m, **h;

  old = f->hash_order;
  oldn = f->hash_size;
  new = old + step;
  m = h = f->hash_table;
  f->hash_order = new;
  fib_ht_alloc(f);
  t = n = f->hash_table;
  newn = f->hash_size;
  ni = 0;

  while (oldn--)
    {
      x = *h++;
      while (e = x)
	{
	  x = e->next;
	  nh = fib_hash(f, e->addr);
	  while (nh > ni)
	    {
	      *t = NULL;
	      ni++;
	      t = ++n;
	    }
	  *t = e;
	  t = &e->next;
	}
    }
  while (ni < newn)
    {
      *t = NULL;
      ni++;
      t = ++n;
    }
  // fib_ht_free(m);
}

void *
fib_get_chain(struct fib *f, const net_addr *a)
{
  assert(f->addr_type == a->type);

  struct fib_node *e = f->hash_table[fib_hash(f, a)];
  return e;
}

size_t fib_memory_statistic(struct fib *f){
  size_t fib_memory_size = sizeof(struct fib);
  for(int i=0;i<f->hash_size;i++){
    fib_memory_size += sizeof(struct fib_node *);
    if(f->hash_table[i]){   
      struct fib_node *e = f->hash_table[i];
      while(e){
        fib_memory_size+=sizeof(struct fib_node *);
        fib_memory_size+=sizeof(net_addr);   
        e=e->next;
      }
    }
  }
  fib_memory_size = fib_memory_size/1024;
  // printf("memory size of fib: %lu KB\n",fib_memory_size);
  return fib_memory_size;
}

rtable *rt_setup(uint addr_type)
{
  rtable *t = (rtable *)malloc(sizeof(struct rtable));
  t->addr_type = addr_type;
  t->trie = f_new_trie(0);
  fib_init(&t->fib, t->addr_type, 0);
  return t;
}

int net_roa_check_ip4_fib(rtable *tab, const net_addr_ip4 *px, u32 asn, enum pfxv_state * res)
{
  struct net_addr_roa4 n = NET_ADDR_ROA4(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;
  int cnt=0;
  while (1)
  {
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_roa4 *roa = (void *) fn->addr;
      if (net_equal_prefix_roa4(roa, &n))
      {
        // printf("%u,%d\n",roa->pxlen,asn);
        cnt++;
        anything = 1;
        if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen)){
          *res = BGP_PFXV_STATE_VALID;
          return SUCCESS;
        }
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    
    ip4_clrbit(&n.prefix, n.pxlen);
  }
  // if(*res==BGP_PFXV_STATE_VALID){
  // printf("%d\n",cnt);
  // }
  if(anything){
    *res = BGP_PFXV_STATE_INVALID;
  }
  else{
    *res = BGP_PFXV_STATE_NOT_FOUND;
  }
  return SUCCESS;
}

int net_roa_check_ip6_fib(rtable *tab, const net_addr_ip6 *px, u32 asn, enum pfxv_state * res)
{
  struct net_addr_roa6 n = NET_ADDR_ROA6(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;
  int cnt=0;
  while (1)
  {
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_roa6 *roa = (void *) fn->addr;
      if (net_equal_prefix_roa6(roa, &n))
      {
        cnt++;
	      anything = 1;
	      if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen)){
          *res = BGP_PFXV_STATE_VALID;
          return SUCCESS;
        }
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    ip6_clrbit(&n.prefix, n.pxlen);
  }
  // if(*res==BGP_PFXV_STATE_VALID) printf("%d\n",cnt);
  if(anything){
    *res = BGP_PFXV_STATE_INVALID;
  }
  else{
    *res = BGP_PFXV_STATE_NOT_FOUND;
  }
  return SUCCESS;
}

int net_roa_check_ip4_trie(rtable *tab, const net_addr_ip4 *px, u32 asn,  enum pfxv_state * res)
{
  int anything = 0;

  TRIE_WALK_TO_ROOT_IP4(tab->trie, px, px0)
  {
    net_addr_roa4 roa0 = NET_ADDR_ROA4(px0.prefix, px0.pxlen, 0, 0);
    // printf("%x/%d,%d\n",roa0.prefix,roa0.length,roa0.pxlen);
    struct fib_node *fn;
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &roa0); fn; fn = fn->next)
    {
      net_addr_roa4 *roa = (void *) fn->addr;
      if (net_equal_prefix_roa4(roa, &roa0))
      {
        anything = 1;
        if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen)){
          *res = BGP_PFXV_STATE_VALID;
          return SUCCESS;
        }
      }
    }
  }
  TRIE_WALK_TO_ROOT_END;
  if(anything){
    *res = BGP_PFXV_STATE_INVALID;
  }
  else{
    *res = BGP_PFXV_STATE_NOT_FOUND;
  }
  return SUCCESS;
}

int net_roa_check_ip6_trie(rtable *tab, const net_addr_ip6 *px, u32 asn, enum pfxv_state * res)
{
  int anything = 0;

  TRIE_WALK_TO_ROOT_IP6(tab->trie, px, px0)
  {
    net_addr_roa6 roa0 = NET_ADDR_ROA6(px0.prefix, px0.pxlen, 0, 0);

    struct fib_node *fn;
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &roa0); fn; fn = fn->next)
    {
      net_addr_roa6 *roa = (void *) fn->addr;
      if (net_equal_prefix_roa6(roa, &roa0))
      {
        anything = 1;
        if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen)){
          *res = BGP_PFXV_STATE_VALID;
          return SUCCESS;
        }
      }
    }
  }
  TRIE_WALK_TO_ROOT_END;
  if(anything){
    *res = BGP_PFXV_STATE_INVALID;
  }
  else{
    *res = BGP_PFXV_STATE_NOT_FOUND;
  }
  return SUCCESS;
}



size_t rt_memory_statistic(rtable *tab){
  return fib_memory_statistic(&tab->fib);
}
