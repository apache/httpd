/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
 * Resource allocation code... the code here is responsible for making
 * sure that nothing leaks.
 *
 * rst --- 4/95 --- 6/95
 */

#include "httpd.h"
#include "multithread.h"
#include "http_log.h"

#include <stdarg.h>

#ifdef OS2
#define INCL_DOS
#include <os2.h>
#endif

/* debugging support, define this to enable code which helps detect re-use
 * of freed memory and other such nonsense.
 *
 * The theory is simple.  The FILL_BYTE (0xa5) is written over all malloc'd
 * memory as we receive it, and is written over everything that we free up
 * during a clear_pool.  We check that blocks on the free list always
 * have the FILL_BYTE in them, and we check during palloc() that the bytes
 * still have FILL_BYTE in them.  If you ever see garbage URLs or whatnot
 * containing lots of 0xa5s then you know something used data that's been
 * freed or uninitialized.
 */
/* #define ALLOC_DEBUG */

/* debugging support, if defined all allocations will be done with
 * malloc and free()d appropriately at the end.  This is intended to be
 * used with something like Electric Fence or Purify to help detect
 * memory problems.  Note that if you're using efence then you should also
 * add in ALLOC_DEBUG.  But don't add in ALLOC_DEBUG if you're using Purify
 * because ALLOC_DEBUG would hide all the uninitialized read errors that
 * Purify can diagnose.
 */
/* #define ALLOC_USE_MALLOC */

/* Pool debugging support.  This is intended to detect cases where the
 * wrong pool is used when assigning data to an object in another pool.
 * In particular, it causes the table_{set,add,merge}n routines to check
 * that their arguments are safe for the table they're being placed in.
 * It currently only works with the unix multiprocess model, but could
 * be extended to others.
 */
/* #define POOL_DEBUG */

/* Provide diagnostic information about make_table() calls which are
 * possibly too small.  This requires a recent gcc which supports
 * __builtin_return_address().  The error_log output will be a
 * message such as:
 *    table_push: table created by 0x804d874 hit limit of 10
 * Use "l *0x804d874" to find the source that corresponds to.  It
 * indicates that a table allocated by a call at that address has
 * possibly too small an initial table size guess.
 */
/* #define MAKE_TABLE_PROFILE */

/* Provide some statistics on the cost of allocations.  It requires a
 * bit of an understanding of how alloc.c works.
 */
/* #define ALLOC_STATS */

#ifdef POOL_DEBUG
#ifdef ALLOC_USE_MALLOC
# error "sorry, no support for ALLOC_USE_MALLOC and POOL_DEBUG at the same time"
#endif
#ifdef MULTITHREAD
# error "sorry, no support for MULTITHREAD and POOL_DEBUG at the same time"
#endif
#endif

#ifdef ALLOC_USE_MALLOC
#undef BLOCK_MINFREE
#undef BLOCK_MINALLOC
#define BLOCK_MINFREE	0
#define BLOCK_MINALLOC	0
#endif

/*****************************************************************
 *
 * Managing free storage blocks...
 */

union align {
    /* Types which are likely to have the longest RELEVANT alignment
     * restrictions...
     */

    char *cp;
    void (*f) (void);
    long l;
    FILE *fp;
    double d;
};

#define CLICK_SZ (sizeof(union align))

union block_hdr {
    union align a;

    /* Actual header... */

    struct {
	char *endp;
	union block_hdr *next;
	char *first_avail;
#ifdef POOL_DEBUG
	union block_hdr *global_next;
	struct pool *owning_pool;
#endif
    } h;
};

static union block_hdr *block_freelist = NULL;
static mutex *alloc_mutex = NULL;
static mutex *spawn_mutex = NULL;
#ifdef POOL_DEBUG
static char *known_stack_point;
static int stack_direction;
static union block_hdr *global_block_list;
#define FREE_POOL	((struct pool *)(-1))
#endif
#ifdef ALLOC_STATS
static unsigned long long num_free_blocks_calls;
static unsigned long long num_blocks_freed;
static unsigned max_blocks_in_one_free;
static unsigned num_malloc_calls;
static unsigned num_malloc_bytes;
#endif

#ifdef ALLOC_DEBUG
#define FILL_BYTE	((char)(0xa5))

#define debug_fill(ptr,size)	((void)memset((ptr), FILL_BYTE, (size)))

static ap_inline void debug_verify_filled(const char *ptr,
    const char *endp, const char *error_msg)
{
    for (; ptr < endp; ++ptr) {
	if (*ptr != FILL_BYTE) {
	    fputs(error_msg, stderr);
	    abort();
	    exit(1);
	}
    }
}

#else
#define debug_fill(a,b)
#define debug_verify_filled(a,b,c)
#endif


/* Get a completely new block from the system pool. Note that we rely on
   malloc() to provide aligned memory. */

static union block_hdr *malloc_block(int size)
{
    union block_hdr *blok;

#ifdef ALLOC_DEBUG
    /* make some room at the end which we'll fill and expect to be
     * always filled
     */
    size += CLICK_SZ;
#endif
#ifdef ALLOC_STATS
    ++num_malloc_calls;
    num_malloc_bytes += size + sizeof(union block_hdr);
#endif
    blok = (union block_hdr *) malloc(size + sizeof(union block_hdr));
    if (blok == NULL) {
	fprintf(stderr, "Ouch!  malloc failed in malloc_block()\n");
	exit(1);
    }
    debug_fill(blok, size + sizeof(union block_hdr));
    blok->h.next = NULL;
    blok->h.first_avail = (char *) (blok + 1);
    blok->h.endp = size + blok->h.first_avail;
#ifdef ALLOC_DEBUG
    blok->h.endp -= CLICK_SZ;
#endif
#ifdef POOL_DEBUG
    blok->h.global_next = global_block_list;
    global_block_list = blok;
    blok->h.owning_pool = NULL;
#endif

    return blok;
}



#if defined(ALLOC_DEBUG) && !defined(ALLOC_USE_MALLOC)
static void chk_on_blk_list(union block_hdr *blok, union block_hdr *free_blk)
{
    debug_verify_filled(blok->h.endp, blok->h.endp + CLICK_SZ,
	"Ouch!  Someone trounced the padding at the end of a block!\n");
    while (free_blk) {
	if (free_blk == blok) {
	    fprintf(stderr, "Ouch!  Freeing free block\n");
	    abort();
	    exit(1);
	}
	free_blk = free_blk->h.next;
    }
}
#else
#define chk_on_blk_list(_x, _y)
#endif

/* Free a chain of blocks --- must be called with alarms blocked. */

static void free_blocks(union block_hdr *blok)
{
#ifdef ALLOC_USE_MALLOC
    union block_hdr *next;

    for (; blok; blok = next) {
	next = blok->h.next;
	free(blok);
    }
#else
#ifdef ALLOC_STATS
    unsigned num_blocks;
#endif
    /* First, put new blocks at the head of the free list ---
     * we'll eventually bash the 'next' pointer of the last block
     * in the chain to point to the free blocks we already had.
     */

    union block_hdr *old_free_list;

    if (blok == NULL)
	return;			/* Sanity check --- freeing empty pool? */

    (void) ap_acquire_mutex(alloc_mutex);
    old_free_list = block_freelist;
    block_freelist = blok;

    /*
     * Next, adjust first_avail pointers of each block --- have to do it
     * sooner or later, and it simplifies the search in new_block to do it
     * now.
     */

#ifdef ALLOC_STATS
    num_blocks = 1;
#endif
    while (blok->h.next != NULL) {
#ifdef ALLOC_STATS
	++num_blocks;
#endif
	chk_on_blk_list(blok, old_free_list);
	blok->h.first_avail = (char *) (blok + 1);
	debug_fill(blok->h.first_avail, blok->h.endp - blok->h.first_avail);
#ifdef POOL_DEBUG
	blok->h.owning_pool = FREE_POOL;
#endif
	blok = blok->h.next;
    }

    chk_on_blk_list(blok, old_free_list);
    blok->h.first_avail = (char *) (blok + 1);
    debug_fill(blok->h.first_avail, blok->h.endp - blok->h.first_avail);
#ifdef POOL_DEBUG
    blok->h.owning_pool = FREE_POOL;
#endif

    /* Finally, reset next pointer to get the old free blocks back */

    blok->h.next = old_free_list;

#ifdef ALLOC_STATS
    if (num_blocks > max_blocks_in_one_free) {
	max_blocks_in_one_free = num_blocks;
    }
    ++num_free_blocks_calls;
    num_blocks_freed += num_blocks;
#endif

    (void) ap_release_mutex(alloc_mutex);
#endif
}


/* Get a new block, from our own free list if possible, from the system
 * if necessary.  Must be called with alarms blocked.
 */

static union block_hdr *new_block(int min_size)
{
    union block_hdr **lastptr = &block_freelist;
    union block_hdr *blok = block_freelist;

    /* First, see if we have anything of the required size
     * on the free list...
     */

    while (blok != NULL) {
	if (min_size + BLOCK_MINFREE <= blok->h.endp - blok->h.first_avail) {
	    *lastptr = blok->h.next;
	    blok->h.next = NULL;
	    debug_verify_filled(blok->h.first_avail, blok->h.endp,
		"Ouch!  Someone trounced a block on the free list!\n");
	    return blok;
	}
	else {
	    lastptr = &blok->h.next;
	    blok = blok->h.next;
	}
    }

    /* Nope. */

    min_size += BLOCK_MINFREE;
    blok = malloc_block((min_size > BLOCK_MINALLOC) ? min_size : BLOCK_MINALLOC);
    return blok;
}


/* Accounting */

static long bytes_in_block_list(union block_hdr *blok)
{
    long size = 0;

    while (blok) {
	size += blok->h.endp - (char *) (blok + 1);
	blok = blok->h.next;
    }

    return size;
}


/*****************************************************************
 *
 * Pool internals and management...
 * NB that subprocesses are not handled by the generic cleanup code,
 * basically because we don't want cleanups for multiple subprocesses
 * to result in multiple three-second pauses.
 */

struct process_chain;
struct cleanup;

static void run_cleanups(struct cleanup *);
static void free_proc_chain(struct process_chain *);

struct pool {
    union block_hdr *first;
    union block_hdr *last;
    struct cleanup *cleanups;
    struct process_chain *subprocesses;
    struct pool *sub_pools;
    struct pool *sub_next;
    struct pool *sub_prev;
    struct pool *parent;
    char *free_first_avail;
#ifdef ALLOC_USE_MALLOC
    void *allocation_list;
#endif
#ifdef POOL_DEBUG
    struct pool *joined;
#endif
};

static pool *permanent_pool;

/* Each pool structure is allocated in the start of its own first block,
 * so we need to know how many bytes that is (once properly aligned...).
 * This also means that when a pool's sub-pool is destroyed, the storage
 * associated with it is *completely* gone, so we have to make sure it
 * gets taken off the parent's sub-pool list...
 */

#define POOL_HDR_CLICKS (1 + ((sizeof(struct pool) - 1) / CLICK_SZ))
#define POOL_HDR_BYTES (POOL_HDR_CLICKS * CLICK_SZ)

API_EXPORT(struct pool *) ap_make_sub_pool(struct pool *p)
{
    union block_hdr *blok;
    pool *new_pool;

    ap_block_alarms();

    (void) ap_acquire_mutex(alloc_mutex);

    blok = new_block(POOL_HDR_BYTES);
    new_pool = (pool *) blok->h.first_avail;
    blok->h.first_avail += POOL_HDR_BYTES;
#ifdef POOL_DEBUG
    blok->h.owning_pool = new_pool;
#endif

    memset((char *) new_pool, '\0', sizeof(struct pool));
    new_pool->free_first_avail = blok->h.first_avail;
    new_pool->first = new_pool->last = blok;

    if (p) {
	new_pool->parent = p;
	new_pool->sub_next = p->sub_pools;
	if (new_pool->sub_next)
	    new_pool->sub_next->sub_prev = new_pool;
	p->sub_pools = new_pool;
    }

    (void) ap_release_mutex(alloc_mutex);
    ap_unblock_alarms();

    return new_pool;
}

#ifdef POOL_DEBUG
static void stack_var_init(char *s)
{
    char t;

    if (s < &t) {
	stack_direction = 1; /* stack grows up */
    }
    else {
	stack_direction = -1; /* stack grows down */
    }
}
#endif

#ifdef ALLOC_STATS
static void dump_stats(void)
{
    fprintf(stderr,
	"alloc_stats: [%d] #free_blocks %llu #blocks %llu max %u #malloc %u #bytes %u\n",
	(int)getpid(),
	num_free_blocks_calls,
	num_blocks_freed,
	max_blocks_in_one_free,
	num_malloc_calls,
	num_malloc_bytes);
}
#endif

API_EXPORT(pool *) ap_init_alloc(void)
{
#ifdef POOL_DEBUG
    char s;

    known_stack_point = &s;
    stack_var_init(&s);
#endif
    alloc_mutex = ap_create_mutex(NULL);
    spawn_mutex = ap_create_mutex(NULL);
    permanent_pool = ap_make_sub_pool(NULL);
#ifdef ALLOC_STATS
    atexit(dump_stats);
#endif

    return permanent_pool;
}

void ap_cleanup_alloc(void)
{
    ap_destroy_mutex(alloc_mutex);
    ap_destroy_mutex(spawn_mutex);
}

API_EXPORT(void) ap_clear_pool(struct pool *a)
{
    ap_block_alarms();

    (void) ap_acquire_mutex(alloc_mutex);
    while (a->sub_pools)
	ap_destroy_pool(a->sub_pools);
    (void) ap_release_mutex(alloc_mutex);
    /* Don't hold the mutex during cleanups. */
    run_cleanups(a->cleanups);
    a->cleanups = NULL;
    free_proc_chain(a->subprocesses);
    a->subprocesses = NULL;
    free_blocks(a->first->h.next);
    a->first->h.next = NULL;

    a->last = a->first;
    a->first->h.first_avail = a->free_first_avail;
    debug_fill(a->first->h.first_avail,
	a->first->h.endp - a->first->h.first_avail);

#ifdef ALLOC_USE_MALLOC
    {
	void *c, *n;

	for (c = a->allocation_list; c; c = n) {
	    n = *(void **)c;
	    free(c);
	}
	a->allocation_list = NULL;
    }
#endif

    ap_unblock_alarms();
}

API_EXPORT(void) ap_destroy_pool(pool *a)
{
    ap_block_alarms();
    ap_clear_pool(a);

    (void) ap_acquire_mutex(alloc_mutex);
    if (a->parent) {
	if (a->parent->sub_pools == a)
	    a->parent->sub_pools = a->sub_next;
	if (a->sub_prev)
	    a->sub_prev->sub_next = a->sub_next;
	if (a->sub_next)
	    a->sub_next->sub_prev = a->sub_prev;
    }
    (void) ap_release_mutex(alloc_mutex);

    free_blocks(a->first);
    ap_unblock_alarms();
}

API_EXPORT(long) ap_bytes_in_pool(pool *p)
{
    return bytes_in_block_list(p->first);
}
API_EXPORT(long) ap_bytes_in_free_blocks(void)
{
    return bytes_in_block_list(block_freelist);
}

/*****************************************************************
 * POOL_DEBUG support
 */
#ifdef POOL_DEBUG

/* the unix linker defines this symbol as the last byte + 1 of
 * the executable... so it includes TEXT, BSS, and DATA
 */
extern char _end;

/* is ptr in the range [lo,hi) */
#define is_ptr_in_range(ptr, lo, hi)	\
    (((unsigned long)(ptr) - (unsigned long)(lo)) \
	< \
	(unsigned long)(hi) - (unsigned long)(lo))

/* Find the pool that ts belongs to, return NULL if it doesn't
 * belong to any pool.
 */
API_EXPORT(pool *) ap_find_pool(const void *ts)
{
    const char *s = ts;
    union block_hdr **pb;
    union block_hdr *b;

    /* short-circuit stuff which is in TEXT, BSS, or DATA */
    if (is_ptr_in_range(s, 0, &_end)) {
	return NULL;
    }
    /* consider stuff on the stack to also be in the NULL pool...
     * XXX: there's cases where we don't want to assume this
     */
    if ((stack_direction == -1 && is_ptr_in_range(s, &ts, known_stack_point))
	|| (stack_direction == 1 && is_ptr_in_range(s, known_stack_point, &ts))) {
	abort();
	return NULL;
    }
    ap_block_alarms();
    /* search the global_block_list */
    for (pb = &global_block_list; *pb; pb = &b->h.global_next) {
	b = *pb;
	if (is_ptr_in_range(s, b, b->h.endp)) {
	    if (b->h.owning_pool == FREE_POOL) {
		fprintf(stderr,
		    "Ouch!  find_pool() called on pointer in a free block\n");
		abort();
		exit(1);
	    }
	    if (b != global_block_list) {
		/* promote b to front of list, this is a hack to speed
		 * up the lookup */
		*pb = b->h.global_next;
		b->h.global_next = global_block_list;
		global_block_list = b;
	    }
	    ap_unblock_alarms();
	    return b->h.owning_pool;
	}
    }
    ap_unblock_alarms();
    return NULL;
}

/* return TRUE iff a is an ancestor of b
 * NULL is considered an ancestor of all pools
 */
API_EXPORT(int) ap_pool_is_ancestor(pool *a, pool *b)
{
    if (a == NULL) {
	return 1;
    }
    while (a->joined) {
	a = a->joined;
    }
    while (b) {
	if (a == b) {
	    return 1;
	}
	b = b->parent;
    }
    return 0;
}

/* All blocks belonging to sub will be changed to point to p
 * instead.  This is a guarantee by the caller that sub will not
 * be destroyed before p is.
 */
API_EXPORT(void) ap_pool_join(pool *p, pool *sub)
{
    union block_hdr *b;

    /* We could handle more general cases... but this is it for now. */
    if (sub->parent != p) {
	fprintf(stderr, "pool_join: p is not parent of sub\n");
	abort();
    }
    ap_block_alarms();
    while (p->joined) {
	p = p->joined;
    }
    sub->joined = p;
    for (b = global_block_list; b; b = b->h.global_next) {
	if (b->h.owning_pool == sub) {
	    b->h.owning_pool = p;
	}
    }
    ap_unblock_alarms();
}
#endif

/*****************************************************************
 *
 * Allocating stuff...
 */


API_EXPORT(void *) ap_palloc(struct pool *a, int reqsize)
{
#ifdef ALLOC_USE_MALLOC
    int size = reqsize + CLICK_SZ;
    void *ptr;

    ap_block_alarms();
    ptr = malloc(size);
    if (ptr == NULL) {
	fputs("Ouch!  Out of memory!\n", stderr);
	exit(1);
    }
    debug_fill(ptr, size); /* might as well get uninitialized protection */
    *(void **)ptr = a->allocation_list;
    a->allocation_list = ptr;
    ap_unblock_alarms();
    return (char *)ptr + CLICK_SZ;
#else

    /* Round up requested size to an even number of alignment units (core clicks)
     */

    int nclicks = 1 + ((reqsize - 1) / CLICK_SZ);
    int size = nclicks * CLICK_SZ;

    /* First, see if we have space in the block most recently
     * allocated to this pool
     */

    union block_hdr *blok = a->last;
    char *first_avail = blok->h.first_avail;
    char *new_first_avail;

    if (reqsize <= 0)
	return NULL;

    new_first_avail = first_avail + size;

    if (new_first_avail <= blok->h.endp) {
	debug_verify_filled(first_avail, blok->h.endp,
	    "Ouch!  Someone trounced past the end of their allocation!\n");
	blok->h.first_avail = new_first_avail;
	return (void *) first_avail;
    }

    /* Nope --- get a new one that's guaranteed to be big enough */

    ap_block_alarms();

    (void) ap_acquire_mutex(alloc_mutex);

    blok = new_block(size);
    a->last->h.next = blok;
    a->last = blok;
#ifdef POOL_DEBUG
    blok->h.owning_pool = a;
#endif

    (void) ap_release_mutex(alloc_mutex);

    ap_unblock_alarms();

    first_avail = blok->h.first_avail;
    blok->h.first_avail += size;

    return (void *) first_avail;
#endif
}

API_EXPORT(void *) ap_pcalloc(struct pool *a, int size)
{
    void *res = ap_palloc(a, size);
    memset(res, '\0', size);
    return res;
}

API_EXPORT(char *) ap_pstrdup(struct pool *a, const char *s)
{
    char *res;
    size_t len;

    if (s == NULL)
	return NULL;
    len = strlen(s) + 1;
    res = ap_palloc(a, len);
    memcpy(res, s, len);
    return res;
}

API_EXPORT(char *) ap_pstrndup(struct pool *a, const char *s, int n)
{
    char *res;

    if (s == NULL)
	return NULL;
    res = ap_palloc(a, n + 1);
    memcpy(res, s, n);
    res[n] = '\0';
    return res;
}

API_EXPORT_NONSTD(char *) ap_pstrcat(pool *a,...)
{
    char *cp, *argp, *res;

    /* Pass one --- find length of required string */

    int len = 0;
    va_list adummy;

    va_start(adummy, a);

    while ((cp = va_arg(adummy, char *)) != NULL)
	     len += strlen(cp);

    va_end(adummy);

    /* Allocate the required string */

    res = (char *) ap_palloc(a, len + 1);
    cp = res;
    *cp = '\0';

    /* Pass two --- copy the argument strings into the result space */

    va_start(adummy, a);

    while ((argp = va_arg(adummy, char *)) != NULL) {
	strcpy(cp, argp);
	cp += strlen(argp);
    }

    va_end(adummy);

    /* Return the result string */

    return res;
}

/* ap_psprintf is implemented by writing directly into the current
 * block of the pool, starting right at first_avail.  If there's
 * insufficient room, then a new block is allocated and the earlier
 * output is copied over.  The new block isn't linked into the pool
 * until all the output is done.
 *
 * Note that this is completely safe because nothing else can
 * allocate in this pool while ap_psprintf is running.  alarms are
 * blocked, and the only thing outside of alloc.c that's invoked
 * is ap_vformatter -- which was purposefully written to be
 * self-contained with no callouts.
 */

struct psprintf_data {
    ap_vformatter_buff vbuff;
#ifdef ALLOC_USE_MALLOC
    char *base;
#else
    union block_hdr *blok;
    int got_a_new_block;
#endif
};

#define AP_PSPRINTF_MIN_SIZE 32  /* Minimum size of allowable avail block */

static int psprintf_flush(ap_vformatter_buff *vbuff)
{
    struct psprintf_data *ps = (struct psprintf_data *)vbuff;
#ifdef ALLOC_USE_MALLOC
    int cur_len, size;
    char *ptr;

    cur_len = (char *)ps->vbuff.curpos - ps->base;
    size = cur_len << 1;
    if (size < AP_PSPRINTF_MIN_SIZE)
        size = AP_PSPRINTF_MIN_SIZE;
    ptr = realloc(ps->base, size);
    if (ptr == NULL) {
	fputs("Ouch!  Out of memory!\n", stderr);
	exit(1);
    }
    ps->base = ptr;
    ps->vbuff.curpos = ptr + cur_len;
    ps->vbuff.endpos = ptr + size - 1;
    return 0;
#else
    union block_hdr *blok;
    union block_hdr *nblok;
    size_t cur_len, size;
    char *strp;

    blok = ps->blok;
    strp = ps->vbuff.curpos;
    cur_len = strp - blok->h.first_avail;
    size = cur_len << 1;
    if (size < AP_PSPRINTF_MIN_SIZE)
        size = AP_PSPRINTF_MIN_SIZE;

    /* must try another blok */
    (void) ap_acquire_mutex(alloc_mutex);
    nblok = new_block(size);
    (void) ap_release_mutex(alloc_mutex);
    memcpy(nblok->h.first_avail, blok->h.first_avail, cur_len);
    ps->vbuff.curpos = nblok->h.first_avail + cur_len;
    /* save a byte for the NUL terminator */
    ps->vbuff.endpos = nblok->h.endp - 1;

    /* did we allocate the current blok? if so free it up */
    if (ps->got_a_new_block) {
	debug_fill(blok->h.first_avail, blok->h.endp - blok->h.first_avail);
	(void) ap_acquire_mutex(alloc_mutex);
	blok->h.next = block_freelist;
	block_freelist = blok;
	(void) ap_release_mutex(alloc_mutex);
    }
    ps->blok = nblok;
    ps->got_a_new_block = 1;
    /* note that we've deliberately not linked the new block onto
     * the pool yet... because we may need to flush again later, and
     * we'd have to spend more effort trying to unlink the block.
     */
    return 0;
#endif
}

API_EXPORT(char *) ap_pvsprintf(pool *p, const char *fmt, va_list ap)
{
#ifdef ALLOC_USE_MALLOC
    struct psprintf_data ps;
    void *ptr;

    ap_block_alarms();
    ps.base = malloc(512);
    if (ps.base == NULL) {
	fputs("Ouch!  Out of memory!\n", stderr);
	exit(1);
    }
    /* need room at beginning for allocation_list */
    ps.vbuff.curpos = ps.base + CLICK_SZ;
    ps.vbuff.endpos = ps.base + 511;
    ap_vformatter(psprintf_flush, &ps.vbuff, fmt, ap);
    *ps.vbuff.curpos++ = '\0';
    ptr = ps.base;
    /* shrink */
    ptr = realloc(ptr, (char *)ps.vbuff.curpos - (char *)ptr);
    if (ptr == NULL) {
	fputs("Ouch!  Out of memory!\n", stderr);
	exit(1);
    }
    *(void **)ptr = p->allocation_list;
    p->allocation_list = ptr;
    ap_unblock_alarms();
    return (char *)ptr + CLICK_SZ;
#else
    struct psprintf_data ps;
    char *strp;
    int size;

    ap_block_alarms();
    ps.blok = p->last;
    ps.vbuff.curpos = ps.blok->h.first_avail;
    ps.vbuff.endpos = ps.blok->h.endp - 1;	/* save one for NUL */
    ps.got_a_new_block = 0;

    if (ps.blok->h.first_avail == ps.blok->h.endp)
        psprintf_flush(&ps.vbuff);		/* ensure room for NUL */
    ap_vformatter(psprintf_flush, &ps.vbuff, fmt, ap);

    strp = ps.vbuff.curpos;
    *strp++ = '\0';

    size = strp - ps.blok->h.first_avail;
    size = (1 + ((size - 1) / CLICK_SZ)) * CLICK_SZ;
    strp = ps.blok->h.first_avail;	/* save away result pointer */
    ps.blok->h.first_avail += size;

    /* have to link the block in if it's a new one */
    if (ps.got_a_new_block) {
	p->last->h.next = ps.blok;
	p->last = ps.blok;
#ifdef POOL_DEBUG
	ps.blok->h.owning_pool = p;
#endif
    }
    ap_unblock_alarms();

    return strp;
#endif
}

API_EXPORT_NONSTD(char *) ap_psprintf(pool *p, const char *fmt, ...)
{
    va_list ap;
    char *res;

    va_start(ap, fmt);
    res = ap_pvsprintf(p, fmt, ap);
    va_end(ap);
    return res;
}

/*****************************************************************
 *
 * The 'array' functions...
 */

static void make_array_core(array_header *res, pool *p, int nelts, int elt_size)
{
    if (nelts < 1)
	nelts = 1;		/* Assure sanity if someone asks for
				 * array of zero elts.
				 */

    res->elts = ap_pcalloc(p, nelts * elt_size);

    res->pool = p;
    res->elt_size = elt_size;
    res->nelts = 0;		/* No active elements yet... */
    res->nalloc = nelts;	/* ...but this many allocated */
}

API_EXPORT(array_header *) ap_make_array(pool *p, int nelts, int elt_size)
{
    array_header *res = (array_header *) ap_palloc(p, sizeof(array_header));

    make_array_core(res, p, nelts, elt_size);
    return res;
}

API_EXPORT(void *) ap_push_array(array_header *arr)
{
    if (arr->nelts == arr->nalloc) {
	int new_size = (arr->nalloc <= 0) ? 1 : arr->nalloc * 2;
	char *new_data;

	new_data = ap_pcalloc(arr->pool, arr->elt_size * new_size);

	memcpy(new_data, arr->elts, arr->nalloc * arr->elt_size);
	arr->elts = new_data;
	arr->nalloc = new_size;
    }

    ++arr->nelts;
    return arr->elts + (arr->elt_size * (arr->nelts - 1));
}

API_EXPORT(void) ap_array_cat(array_header *dst, const array_header *src)
{
    int elt_size = dst->elt_size;

    if (dst->nelts + src->nelts > dst->nalloc) {
	int new_size = (dst->nalloc <= 0) ? 1 : dst->nalloc * 2;
	char *new_data;

	while (dst->nelts + src->nelts > new_size)
	    new_size *= 2;

	new_data = ap_pcalloc(dst->pool, elt_size * new_size);
	memcpy(new_data, dst->elts, dst->nalloc * elt_size);

	dst->elts = new_data;
	dst->nalloc = new_size;
    }

    memcpy(dst->elts + dst->nelts * elt_size, src->elts, elt_size * src->nelts);
    dst->nelts += src->nelts;
}

API_EXPORT(array_header *) ap_copy_array(pool *p, const array_header *arr)
{
    array_header *res = ap_make_array(p, arr->nalloc, arr->elt_size);

    memcpy(res->elts, arr->elts, arr->elt_size * arr->nelts);
    res->nelts = arr->nelts;
    return res;
}

/* This cute function copies the array header *only*, but arranges
 * for the data section to be copied on the first push or arraycat.
 * It's useful when the elements of the array being copied are
 * read only, but new stuff *might* get added on the end; we have the
 * overhead of the full copy only where it is really needed.
 */

static ap_inline void copy_array_hdr_core(array_header *res,
    const array_header *arr)
{
    res->elts = arr->elts;
    res->elt_size = arr->elt_size;
    res->nelts = arr->nelts;
    res->nalloc = arr->nelts;	/* Force overflow on push */
}

API_EXPORT(array_header *) ap_copy_array_hdr(pool *p, const array_header *arr)
{
    array_header *res = (array_header *) ap_palloc(p, sizeof(array_header));

    res->pool = p;
    copy_array_hdr_core(res, arr);
    return res;
}

/* The above is used here to avoid consing multiple new array bodies... */

API_EXPORT(array_header *) ap_append_arrays(pool *p,
					 const array_header *first,
					 const array_header *second)
{
    array_header *res = ap_copy_array_hdr(p, first);

    ap_array_cat(res, second);
    return res;
}

/* ap_array_pstrcat generates a new string from the pool containing
 * the concatenated sequence of substrings referenced as elements within
 * the array.  The string will be empty if all substrings are empty or null,
 * or if there are no elements in the array.
 * If sep is non-NUL, it will be inserted between elements as a separator.
 */
API_EXPORT(char *) ap_array_pstrcat(pool *p, const array_header *arr,
                                    const char sep)
{
    char *cp, *res, **strpp;
    int i, len;

    if (arr->nelts <= 0 || arr->elts == NULL)      /* Empty table? */
        return (char *) ap_pcalloc(p, 1);

    /* Pass one --- find length of required string */

    len = 0;
    for (i = 0, strpp = (char **) arr->elts; ; ++strpp) {
        if (strpp && *strpp != NULL) {
            len += strlen(*strpp);
        }
        if (++i >= arr->nelts)
            break;
        if (sep)
            ++len;
    }

    /* Allocate the required string */

    res = (char *) ap_palloc(p, len + 1);
    cp = res;

    /* Pass two --- copy the argument strings into the result space */

    for (i = 0, strpp = (char **) arr->elts; ; ++strpp) {
        if (strpp && *strpp != NULL) {
            len = strlen(*strpp);
            memcpy(cp, *strpp, len);
            cp += len;
        }
        if (++i >= arr->nelts)
            break;
        if (sep)
            *cp++ = sep;
    }

    *cp = '\0';

    /* Return the result string */

    return res;
}


/*****************************************************************
 *
 * The "table" functions.
 */

/* XXX: if you tweak this you should look at is_empty_table() and table_elts()
 * in ap_alloc.h */
struct table {
    /* This has to be first to promote backwards compatibility with
     * older modules which cast a table * to an array_header *...
     * they should use the table_elts() function for most of the
     * cases they do this for.
     */
    array_header a;
#ifdef MAKE_TABLE_PROFILE
    void *creator;
#endif
};

#ifdef MAKE_TABLE_PROFILE
static table_entry *table_push(table *t)
{
    if (t->a.nelts == t->a.nalloc) {
	fprintf(stderr,
	    "table_push: table created by %p hit limit of %u\n",
	    t->creator, t->a.nalloc);
    }
    return (table_entry *) ap_push_array(&t->a);
}
#else
#define table_push(t)	((table_entry *) ap_push_array(&(t)->a))
#endif


API_EXPORT(table *) ap_make_table(pool *p, int nelts)
{
    table *t = ap_palloc(p, sizeof(table));

    make_array_core(&t->a, p, nelts, sizeof(table_entry));
#ifdef MAKE_TABLE_PROFILE
    t->creator = __builtin_return_address(0);
#endif
    return t;
}

API_EXPORT(table *) ap_copy_table(pool *p, const table *t)
{
    table *new = ap_palloc(p, sizeof(table));

#ifdef POOL_DEBUG
    /* we don't copy keys and values, so it's necessary that t->a.pool
     * have a life span at least as long as p
     */
    if (!ap_pool_is_ancestor(t->a.pool, p)) {
	fprintf(stderr, "copy_table: t's pool is not an ancestor of p\n");
	abort();
    }
#endif
    make_array_core(&new->a, p, t->a.nalloc, sizeof(table_entry));
    memcpy(new->a.elts, t->a.elts, t->a.nelts * sizeof(table_entry));
    new->a.nelts = t->a.nelts;
    return new;
}

API_EXPORT(void) ap_clear_table(table *t)
{
    t->a.nelts = 0;
}

API_EXPORT(const char *) ap_table_get(const table *t, const char *key)
{
    table_entry *elts = (table_entry *) t->a.elts;
    int i;

    if (key == NULL)
	return NULL;

    for (i = 0; i < t->a.nelts; ++i)
	if (!strcasecmp(elts[i].key, key))
	    return elts[i].val;

    return NULL;
}

API_EXPORT(void) ap_table_set(table *t, const char *key, const char *val)
{
    register int i, j, k;
    table_entry *elts = (table_entry *) t->a.elts;
    int done = 0;

    for (i = 0; i < t->a.nelts; ) {
	if (!strcasecmp(elts[i].key, key)) {
	    if (!done) {
		elts[i].val = ap_pstrdup(t->a.pool, val);
		done = 1;
		++i;
	    }
	    else {		/* delete an extraneous element */
		for (j = i, k = i + 1; k < t->a.nelts; ++j, ++k) {
		    elts[j].key = elts[k].key;
		    elts[j].val = elts[k].val;
		}
		--t->a.nelts;
	    }
	}
	else {
	    ++i;
	}
    }

    if (!done) {
	elts = (table_entry *) table_push(t);
	elts->key = ap_pstrdup(t->a.pool, key);
	elts->val = ap_pstrdup(t->a.pool, val);
    }
}

API_EXPORT(void) ap_table_setn(table *t, const char *key, const char *val)
{
    register int i, j, k;
    table_entry *elts = (table_entry *) t->a.elts;
    int done = 0;

#ifdef POOL_DEBUG
    {
	if (!ap_pool_is_ancestor(ap_find_pool(key), t->a.pool)) {
	    fprintf(stderr, "table_set: key not in ancestor pool of t\n");
	    abort();
	}
	if (!ap_pool_is_ancestor(ap_find_pool(val), t->a.pool)) {
	    fprintf(stderr, "table_set: val not in ancestor pool of t\n");
	    abort();
	}
    }
#endif

    for (i = 0; i < t->a.nelts; ) {
	if (!strcasecmp(elts[i].key, key)) {
	    if (!done) {
		elts[i].val = (char *)val;
		done = 1;
		++i;
	    }
	    else {		/* delete an extraneous element */
		for (j = i, k = i + 1; k < t->a.nelts; ++j, ++k) {
		    elts[j].key = elts[k].key;
		    elts[j].val = elts[k].val;
		}
		--t->a.nelts;
	    }
	}
	else {
	    ++i;
	}
    }

    if (!done) {
	elts = (table_entry *) table_push(t);
	elts->key = (char *)key;
	elts->val = (char *)val;
    }
}

API_EXPORT(void) ap_table_unset(table *t, const char *key)
{
    register int i, j, k;
    table_entry *elts = (table_entry *) t->a.elts;

    for (i = 0; i < t->a.nelts;) {
	if (!strcasecmp(elts[i].key, key)) {

	    /* found an element to skip over
	     * there are any number of ways to remove an element from
	     * a contiguous block of memory.  I've chosen one that
	     * doesn't do a memcpy/bcopy/array_delete, *shrug*...
	     */
	    for (j = i, k = i + 1; k < t->a.nelts; ++j, ++k) {
		elts[j].key = elts[k].key;
		elts[j].val = elts[k].val;
	    }
	    --t->a.nelts;
	}
	else {
	    ++i;
	}
    }
}

API_EXPORT(void) ap_table_merge(table *t, const char *key, const char *val)
{
    table_entry *elts = (table_entry *) t->a.elts;
    int i;

    for (i = 0; i < t->a.nelts; ++i)
	if (!strcasecmp(elts[i].key, key)) {
	    elts[i].val = ap_pstrcat(t->a.pool, elts[i].val, ", ", val, NULL);
	    return;
	}

    elts = (table_entry *) table_push(t);
    elts->key = ap_pstrdup(t->a.pool, key);
    elts->val = ap_pstrdup(t->a.pool, val);
}

API_EXPORT(void) ap_table_mergen(table *t, const char *key, const char *val)
{
    table_entry *elts = (table_entry *) t->a.elts;
    int i;

#ifdef POOL_DEBUG
    {
	if (!ap_pool_is_ancestor(ap_find_pool(key), t->a.pool)) {
	    fprintf(stderr, "table_set: key not in ancestor pool of t\n");
	    abort();
	}
	if (!ap_pool_is_ancestor(ap_find_pool(val), t->a.pool)) {
	    fprintf(stderr, "table_set: key not in ancestor pool of t\n");
	    abort();
	}
    }
#endif

    for (i = 0; i < t->a.nelts; ++i) {
	if (!strcasecmp(elts[i].key, key)) {
	    elts[i].val = ap_pstrcat(t->a.pool, elts[i].val, ", ", val, NULL);
	    return;
	}
    }

    elts = (table_entry *) table_push(t);
    elts->key = (char *)key;
    elts->val = (char *)val;
}

API_EXPORT(void) ap_table_add(table *t, const char *key, const char *val)
{
    table_entry *elts = (table_entry *) t->a.elts;

    elts = (table_entry *) table_push(t);
    elts->key = ap_pstrdup(t->a.pool, key);
    elts->val = ap_pstrdup(t->a.pool, val);
}

API_EXPORT(void) ap_table_addn(table *t, const char *key, const char *val)
{
    table_entry *elts = (table_entry *) t->a.elts;

#ifdef POOL_DEBUG
    {
	if (!ap_pool_is_ancestor(ap_find_pool(key), t->a.pool)) {
	    fprintf(stderr, "table_set: key not in ancestor pool of t\n");
	    abort();
	}
	if (!ap_pool_is_ancestor(ap_find_pool(val), t->a.pool)) {
	    fprintf(stderr, "table_set: key not in ancestor pool of t\n");
	    abort();
	}
    }
#endif

    elts = (table_entry *) table_push(t);
    elts->key = (char *)key;
    elts->val = (char *)val;
}

API_EXPORT(table *) ap_overlay_tables(pool *p, const table *overlay, const table *base)
{
    table *res;

#ifdef POOL_DEBUG
    /* we don't copy keys and values, so it's necessary that
     * overlay->a.pool and base->a.pool have a life span at least
     * as long as p
     */
    if (!ap_pool_is_ancestor(overlay->a.pool, p)) {
	fprintf(stderr, "overlay_tables: overlay's pool is not an ancestor of p\n");
	abort();
    }
    if (!ap_pool_is_ancestor(base->a.pool, p)) {
	fprintf(stderr, "overlay_tables: base's pool is not an ancestor of p\n");
	abort();
    }
#endif

    res = ap_palloc(p, sizeof(table));
    /* behave like append_arrays */
    res->a.pool = p;
    copy_array_hdr_core(&res->a, &overlay->a);
    ap_array_cat(&res->a, &base->a);

    return res;
}

/* And now for something completely abstract ...

 * For each key value given as a vararg:
 *   run the function pointed to as
 *     int comp(void *r, char *key, char *value);
 *   on each valid key-value pair in the table t that matches the vararg key,
 *   or once for every valid key-value pair if the vararg list is empty,
 *   until the function returns false (0) or we finish the table.
 *
 * Note that we restart the traversal for each vararg, which means that
 * duplicate varargs will result in multiple executions of the function
 * for each matching key.  Note also that if the vararg list is empty,
 * only one traversal will be made and will cut short if comp returns 0.
 *
 * Note that the table_get and table_merge functions assume that each key in
 * the table is unique (i.e., no multiple entries with the same key).  This
 * function does not make that assumption, since it (unfortunately) isn't
 * true for some of Apache's tables.
 *
 * Note that rec is simply passed-on to the comp function, so that the
 * caller can pass additional info for the task.
 */
API_EXPORT_NONSTD(void) ap_table_do(int (*comp) (void *, const char *, const char *), 
	                            void *rec, const table *t,...)
{
    va_list vp;
    char *argp;
    table_entry *elts = (table_entry *) t->a.elts;
    int rv, i;

    va_start(vp, t);

    argp = va_arg(vp, char *);

    do {
	for (rv = 1, i = 0; rv && (i < t->a.nelts); ++i) {
	    if (elts[i].key && (!argp || !strcasecmp(elts[i].key, argp))) {
		rv = (*comp) (rec, elts[i].key, elts[i].val);
	    }
	}
    } while (argp && ((argp = va_arg(vp, char *)) != NULL));

    va_end(vp);
}

/* Curse libc and the fact that it doesn't guarantee a stable sort.  We
 * have to enforce stability ourselves by using the order field.  If it
 * provided a stable sort then we wouldn't even need temporary storage to
 * do the work below. -djg
 *
 * ("stable sort" means that equal keys retain their original relative
 * ordering in the output.)
 */
typedef struct {
    char *key;
    char *val;
    int order;
} overlap_key;

static int sort_overlap(const void *va, const void *vb)
{
    const overlap_key *a = va;
    const overlap_key *b = vb;
    int r;

    r = strcasecmp(a->key, b->key);
    if (r) {
	return r;
    }
    return a->order - b->order;
}

/* prefer to use the stack for temp storage for overlaps smaller than this */
#ifndef AP_OVERLAP_TABLES_ON_STACK
#define AP_OVERLAP_TABLES_ON_STACK	(512)
#endif

API_EXPORT(void) ap_overlap_tables(table *a, const table *b, unsigned flags)
{
    overlap_key cat_keys_buf[AP_OVERLAP_TABLES_ON_STACK];
    overlap_key *cat_keys;
    int nkeys;
    table_entry *e;
    table_entry *last_e;
    overlap_key *left;
    overlap_key *right;
    overlap_key *last;

    nkeys = a->a.nelts + b->a.nelts;
    if (nkeys < AP_OVERLAP_TABLES_ON_STACK) {
	cat_keys = cat_keys_buf;
    }
    else {
	/* XXX: could use scratch free space in a or b's pool instead...
	 * which could save an allocation in b's pool.
	 */
	cat_keys = ap_palloc(b->a.pool, sizeof(overlap_key) * nkeys);
    }

    nkeys = 0;

    /* Create a list of the entries from a concatenated with the entries
     * from b.
     */
    e = (table_entry *)a->a.elts;
    last_e = e + a->a.nelts;
    while (e < last_e) {
	cat_keys[nkeys].key = e->key;
	cat_keys[nkeys].val = e->val;
	cat_keys[nkeys].order = nkeys;
	++nkeys;
	++e;
    }

    e = (table_entry *)b->a.elts;
    last_e = e + b->a.nelts;
    while (e < last_e) {
	cat_keys[nkeys].key = e->key;
	cat_keys[nkeys].val = e->val;
	cat_keys[nkeys].order = nkeys;
	++nkeys;
	++e;
    }

    qsort(cat_keys, nkeys, sizeof(overlap_key), sort_overlap);

    /* Now iterate over the sorted list and rebuild a.
     * Start by making sure it has enough space.
     */
    a->a.nelts = 0;
    if (a->a.nalloc < nkeys) {
	a->a.elts = ap_palloc(a->a.pool, a->a.elt_size * nkeys * 2);
	a->a.nalloc = nkeys * 2;
    }

    /*
     * In both the merge and set cases we retain the invariant:
     *
     * left->key, (left+1)->key, (left+2)->key, ..., (right-1)->key
     * are all equal keys.  (i.e. strcasecmp returns 0)
     *
     * We essentially need to find the maximal
     * right for each key, then we can do a quick merge or set as
     * appropriate.
     */

    if (flags & AP_OVERLAP_TABLES_MERGE) {
	left = cat_keys;
	last = left + nkeys;
	while (left < last) {
	    right = left + 1;
	    if (right == last
		|| strcasecmp(left->key, right->key)) {
		ap_table_addn(a, left->key, left->val);
		left = right;
	    }
	    else {
		char *strp;
		char *value;
		size_t len;

		/* Have to merge some headers.  Let's re-use the order field,
		 * since it's handy... we'll store the length of val there.
		 */
		left->order = strlen(left->val);
		len = left->order;
		do {
		    right->order = strlen(right->val);
		    len += 2 + right->order;
		    ++right;
		} while (right < last
			&& !strcasecmp(left->key, right->key));
		/* right points one past the last header to merge */
		value = ap_palloc(a->a.pool, len + 1);
		strp = value;
		for (;;) {
		    memcpy(strp, left->val, left->order);
		    strp += left->order;
		    ++left;
		    if (left == right) break;
		    *strp++ = ',';
		    *strp++ = ' ';
		}
		*strp = 0;
		ap_table_addn(a, (left-1)->key, value);
	    }
	}
    }
    else {
	left = cat_keys;
	last = left + nkeys;
	while (left < last) {
	    right = left + 1;
	    while (right < last && !strcasecmp(left->key, right->key)) {
		++right;
	    }
	    ap_table_addn(a, (right-1)->key, (right-1)->val);
	    left = right;
	}
    }
}

/*****************************************************************
 *
 * Managing generic cleanups.  
 */

struct cleanup {
    void *data;
    void (*plain_cleanup) (void *);
    void (*child_cleanup) (void *);
    struct cleanup *next;
};

API_EXPORT(void) ap_register_cleanup_ex(pool *p, void *data,
				      void (*plain_cleanup) (void *),
				      void (*child_cleanup) (void *),
				      int (*magic_cleanup) (void *))
{
    struct cleanup *c;
    if (p) {
	c = (struct cleanup *) ap_palloc(p, sizeof(struct cleanup));
	c->data = data;
	c->plain_cleanup = plain_cleanup;
	c->child_cleanup = child_cleanup;
	c->next = p->cleanups;
	p->cleanups = c;
    }
    /* attempt to do magic even if not passed a pool. Allows us
     * to perform the magic, therefore, "whenever" we want/need */
    if (magic_cleanup) {
	if (!magic_cleanup(data)) 
	   ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
		 "exec() may not be safe");
    }
}

API_EXPORT(void) ap_register_cleanup(pool *p, void *data,
				     void (*plain_cleanup) (void *),
				     void (*child_cleanup) (void *))
{
    ap_register_cleanup_ex(p, data, plain_cleanup, child_cleanup, NULL);
}

API_EXPORT(void) ap_kill_cleanup(pool *p, void *data, void (*cleanup) (void *))
{
    struct cleanup *c = p->cleanups;
    struct cleanup **lastp = &p->cleanups;

    while (c) {
	if (c->data == data && c->plain_cleanup == cleanup) {
	    *lastp = c->next;
	    break;
	}

	lastp = &c->next;
	c = c->next;
    }
}

API_EXPORT(void) ap_run_cleanup(pool *p, void *data, void (*cleanup) (void *))
{
    ap_block_alarms();		/* Run cleanup only once! */
    (*cleanup) (data);
    ap_kill_cleanup(p, data, cleanup);
    ap_unblock_alarms();
}

static void run_cleanups(struct cleanup *c)
{
    while (c) {
	(*c->plain_cleanup) (c->data);
	c = c->next;
    }
}

static void run_child_cleanups(struct cleanup *c)
{
    while (c) {
	(*c->child_cleanup) (c->data);
	c = c->next;
    }
}

static void cleanup_pool_for_exec(pool *p)
{
    run_child_cleanups(p->cleanups);
    p->cleanups = NULL;

    for (p = p->sub_pools; p; p = p->sub_next)
	cleanup_pool_for_exec(p);
}

API_EXPORT(void) ap_cleanup_for_exec(void)
{
#if !defined(WIN32) && !defined(OS2)
    /*
     * Don't need to do anything on NT or OS/2, because I
     * am actually going to spawn the new process - not
     * exec it. All handles that are not inheritable, will
     * be automajically closed. The only problem is with
     * file handles that are open, but there isn't much
     * I can do about that (except if the child decides
     * to go out and close them
     */
    ap_block_alarms();
    cleanup_pool_for_exec(permanent_pool);
    ap_unblock_alarms();
#endif /* ndef WIN32 */
}

API_EXPORT_NONSTD(void) ap_null_cleanup(void *data)
{
    /* do nothing cleanup routine */
}

/*****************************************************************
 *
 * Files and file descriptors; these are just an application of the
 * generic cleanup interface.
 */

int ap_close_fd_on_exec(int fd)
{
#if defined(F_SETFD) && defined(FD_CLOEXEC)
    /* Protect the fd so that it will not be inherited by child processes */
    if(fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
	ap_log_error(APLOG_MARK, APLOG_ERR, NULL,
		     "fcntl(%d, F_SETFD, FD_CLOEXEC) failed", fd);
	return 0;
    }

    return 1;
#else
    return 0;
#endif
}

static void fd_cleanup(void *fdv)
{
    close((int) (long) fdv);
}

static int fd_magic_cleanup(void *fdv)
{
    return ap_close_fd_on_exec((int) (long) fdv);
}

API_EXPORT(void) ap_note_cleanups_for_fd_ex(pool *p, int fd, int domagic)
{
    ap_register_cleanup_ex(p, (void *) (long) fd, fd_cleanup, fd_cleanup,
                           domagic ? fd_magic_cleanup : NULL);
}

API_EXPORT(void) ap_note_cleanups_for_fd(pool *p, int fd)
{
    ap_note_cleanups_for_fd_ex(p, fd, 0);
}

API_EXPORT(void) ap_kill_cleanups_for_fd(pool *p, int fd)
{
    ap_kill_cleanup(p, (void *) (long) fd, fd_cleanup);
}

API_EXPORT(int) ap_popenf_ex(pool *a, const char *name, int flg, int mode,
                             int domagic)
{
    int fd;
    int save_errno;

    ap_block_alarms();
    fd = open(name, flg, mode);
    save_errno = errno;
    if (fd >= 0) {
	fd = ap_slack(fd, AP_SLACK_HIGH);
	ap_note_cleanups_for_fd_ex(a, fd, domagic);
    }
    ap_unblock_alarms();
    errno = save_errno;
    return fd;
}

API_EXPORT(int) ap_popenf(pool *a, const char *name, int flg, int mode)
{
    return ap_popenf_ex(a, name, flg, mode, 0);
}

API_EXPORT(int) ap_pclosef(pool *a, int fd)
{
    int res;
    int save_errno;

    ap_block_alarms();
    res = close(fd);
    save_errno = errno;
    ap_kill_cleanup(a, (void *) (long) fd, fd_cleanup);
    ap_unblock_alarms();
    errno = save_errno;
    return res;
}

#ifdef WIN32
static void h_cleanup(void *fdv)
{
    CloseHandle((HANDLE) fdv);
}

API_EXPORT(void) ap_note_cleanups_for_h(pool *p, HANDLE hDevice)
{
    ap_register_cleanup(p, (void *) hDevice, h_cleanup, h_cleanup);
}

API_EXPORT(int) ap_pcloseh(pool *a, HANDLE hDevice)
{
    int res=0;
    int save_errno;

    ap_block_alarms();
    
    if (!CloseHandle(hDevice)) {
        res = GetLastError();
    }
    
    save_errno = errno;
    ap_kill_cleanup(a, (void *) hDevice, h_cleanup);
    ap_unblock_alarms();
    errno = save_errno;
    return res;
}
#endif

/* Note that we have separate plain_ and child_ cleanups for FILE *s,
 * since fclose() would flush I/O buffers, which is extremely undesirable;
 * we just close the descriptor.
 */

static void file_cleanup(void *fpv)
{
    fclose((FILE *) fpv);
}
static void file_child_cleanup(void *fpv)
{
    close(fileno((FILE *) fpv));
}
static int file_magic_cleanup(void *fpv)
{
    return ap_close_fd_on_exec(fileno((FILE *) fpv));
}

API_EXPORT(void) ap_note_cleanups_for_file_ex(pool *p, FILE *fp, int domagic)
{
    ap_register_cleanup_ex(p, (void *) fp, file_cleanup, file_child_cleanup,
                           domagic ? file_magic_cleanup : NULL);
}

API_EXPORT(void) ap_note_cleanups_for_file(pool *p, FILE *fp)
{
    ap_note_cleanups_for_file_ex(p, fp, 0);
}

API_EXPORT(FILE *) ap_pfopen(pool *a, const char *name, const char *mode)
{
    FILE *fd = NULL;
    int baseFlag, desc;
    int modeFlags = 0;
    int saved_errno;

#ifdef WIN32
    modeFlags = _S_IREAD | _S_IWRITE;
#else
    modeFlags = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
#endif

    ap_block_alarms();

    if (*mode == 'a') {
	/* Work around faulty implementations of fopen */
	baseFlag = (*(mode + 1) == '+') ? O_RDWR : O_WRONLY;
	desc = open(name, baseFlag | O_APPEND | O_CREAT,
		    modeFlags);
	if (desc >= 0) {
	    desc = ap_slack(desc, AP_SLACK_LOW);
	    fd = ap_fdopen(desc, mode);
	}
    }
    else {
	fd = fopen(name, mode);
    }
    saved_errno = errno;
    if (fd != NULL)
	ap_note_cleanups_for_file(a, fd);
    ap_unblock_alarms();
    errno = saved_errno;
    return fd;
}

API_EXPORT(FILE *) ap_pfdopen(pool *a, int fd, const char *mode)
{
    FILE *f;
    int saved_errno;

    ap_block_alarms();
    f = ap_fdopen(fd, mode);
    saved_errno = errno;
    if (f != NULL)
	ap_note_cleanups_for_file(a, f);
    ap_unblock_alarms();
    errno = saved_errno;
    return f;
}


API_EXPORT(int) ap_pfclose(pool *a, FILE *fd)
{
    int res;

    ap_block_alarms();
    res = fclose(fd);
    ap_kill_cleanup(a, (void *) fd, file_cleanup);
    ap_unblock_alarms();
    return res;
}

/*
 * DIR * with cleanup
 */

static void dir_cleanup(void *dv)
{
    closedir((DIR *) dv);
}

API_EXPORT(DIR *) ap_popendir(pool *p, const char *name)
{
    DIR *d;
    int save_errno;

    ap_block_alarms();
    d = opendir(name);
    if (d == NULL) {
	save_errno = errno;
	ap_unblock_alarms();
	errno = save_errno;
	return NULL;
    }
    ap_register_cleanup(p, (void *) d, dir_cleanup, dir_cleanup);
    ap_unblock_alarms();
    return d;
}

API_EXPORT(void) ap_pclosedir(pool *p, DIR * d)
{
    ap_block_alarms();
    ap_kill_cleanup(p, (void *) d, dir_cleanup);
    closedir(d);
    ap_unblock_alarms();
}

/*****************************************************************
 *
 * Files and file descriptors; these are just an application of the
 * generic cleanup interface.
 */

static void socket_cleanup(void *fdv)
{
    closesocket((int) (long) fdv);
}
static int socket_magic_cleanup(void *fpv)
{
    return ap_close_fd_on_exec((int) (long) fpv);
}

API_EXPORT(void) ap_note_cleanups_for_socket_ex(pool *p, int fd, int domagic)
{
    ap_register_cleanup_ex(p, (void *) (long) fd, socket_cleanup,
                           socket_cleanup,
                           domagic ? socket_magic_cleanup : NULL);
}

API_EXPORT(void) ap_note_cleanups_for_socket(pool *p, int fd)
{
    ap_note_cleanups_for_socket_ex(p, fd, 0);
}

API_EXPORT(void) ap_kill_cleanups_for_socket(pool *p, int sock)
{
    ap_kill_cleanup(p, (void *) (long) sock, socket_cleanup);
}

API_EXPORT(int) ap_psocket_ex(pool *p, int domain, int type, int protocol,
                              int domagic)
{
    int fd;

    ap_block_alarms();
    fd = socket(domain, type, protocol);
    if (fd == -1) {
	int save_errno = errno;
	ap_unblock_alarms();
	errno = save_errno;
	return -1;
    }
    ap_note_cleanups_for_socket_ex(p, fd, domagic);
    ap_unblock_alarms();
    return fd;
}

API_EXPORT(int) ap_psocket(pool *p, int domain, int type, int protocol)
{
    return ap_psocket_ex(p, domain, type, protocol, 0);
}

API_EXPORT(int) ap_pclosesocket(pool *a, int sock)
{
    int res;
    int save_errno;

    ap_block_alarms();
    res = closesocket(sock);
#if defined(WIN32) || defined(NETWARE)
    errno = WSAGetLastError();
#endif /* WIN32 */
    save_errno = errno;
    ap_kill_cleanup(a, (void *) (long) sock, socket_cleanup);
    ap_unblock_alarms();
    errno = save_errno;
    return res;
}


/*
 * Here's a pool-based interface to POSIX regex's regcomp().
 * Note that we return regex_t instead of being passed one.
 * The reason is that if you use an already-used regex_t structure,
 * the memory that you've already allocated gets forgotten, and
 * regfree() doesn't clear it. So we don't allow it.
 */

static void regex_cleanup(void *preg)
{
    regfree((regex_t *) preg);
}

API_EXPORT(regex_t *) ap_pregcomp(pool *p, const char *pattern, int cflags)
{
    regex_t *preg = ap_palloc(p, sizeof(regex_t));

    if (regcomp(preg, pattern, cflags))
	return NULL;

    ap_register_cleanup(p, (void *) preg, regex_cleanup, regex_cleanup);

    return preg;
}


API_EXPORT(void) ap_pregfree(pool *p, regex_t * reg)
{
    ap_block_alarms();
    regfree(reg);
    ap_kill_cleanup(p, (void *) reg, regex_cleanup);
    ap_unblock_alarms();
}

/*****************************************************************
 *
 * More grotty system stuff... subprocesses.  Frump.  These don't use
 * the generic cleanup interface because I don't want multiple
 * subprocesses to result in multiple three-second pauses; the
 * subprocesses have to be "freed" all at once.  If someone comes
 * along with another resource they want to allocate which has the
 * same property, we might want to fold support for that into the
 * generic interface, but for now, it's a special case
 */

struct process_chain {
    pid_t pid;
    enum kill_conditions kill_how;
    struct process_chain *next;
};

API_EXPORT(void) ap_note_subprocess(pool *a, pid_t pid, enum kill_conditions 
how) {
    struct process_chain *new =
    (struct process_chain *) ap_palloc(a, sizeof(struct process_chain));

    new->pid = pid;
    new->kill_how = how;
    new->next = a->subprocesses;
    a->subprocesses = new;
}

#ifdef WIN32
#define os_pipe(fds) _pipe(fds, 512, O_BINARY | O_NOINHERIT)
#else
#define os_pipe(fds) pipe(fds)
#endif /* WIN32 */

/* for ap_fdopen, to get binary mode */
#if defined (OS2) || defined (WIN32) || defined (NETWARE)
#define BINMODE	"b"
#else
#define BINMODE
#endif

static pid_t spawn_child_core(pool *p, int (*func) (void *, child_info *),
			    void *data,enum kill_conditions kill_how,
			    int *pipe_in, int *pipe_out, int *pipe_err)
{
    pid_t pid;
    int in_fds[2];
    int out_fds[2];
    int err_fds[2];
    int save_errno;

    if (pipe_in && os_pipe(in_fds) < 0) {
	return 0;
    }

    if (pipe_out && os_pipe(out_fds) < 0) {
	save_errno = errno;
	if (pipe_in) {
	    close(in_fds[0]);
	    close(in_fds[1]);
	}
	errno = save_errno;
	return 0;
    }

    if (pipe_err && os_pipe(err_fds) < 0) {
	save_errno = errno;
	if (pipe_in) {
	    close(in_fds[0]);
	    close(in_fds[1]);
	}
	if (pipe_out) {
	    close(out_fds[0]);
	    close(out_fds[1]);
	}
	errno = save_errno;
	return 0;
    }

#ifdef WIN32

    {
	HANDLE thread_handle;
	int hStdIn, hStdOut, hStdErr;
	int old_priority;
	child_info info;

	(void) ap_acquire_mutex(spawn_mutex);
	thread_handle = GetCurrentThread();	/* doesn't need to be closed */
	old_priority = GetThreadPriority(thread_handle);
	SetThreadPriority(thread_handle, THREAD_PRIORITY_HIGHEST);
	/* Now do the right thing with your pipes */
	if (pipe_in) {
	    hStdIn = dup(fileno(stdin));
	    if(dup2(in_fds[0], fileno(stdin)))
		ap_log_error(APLOG_MARK, APLOG_ERR, NULL, "dup2(stdin) failed");
	    close(in_fds[0]);
	}
	if (pipe_out) {
	    hStdOut = dup(fileno(stdout));
	    close(fileno(stdout));
	    if(dup2(out_fds[1], fileno(stdout)))
		ap_log_error(APLOG_MARK, APLOG_ERR, NULL, "dup2(stdout) failed");
	    close(out_fds[1]);
	}
	if (pipe_err) {
	    hStdErr = dup(fileno(stderr));
	    if(dup2(err_fds[1], fileno(stderr)))
		ap_log_error(APLOG_MARK, APLOG_ERR, NULL, "dup2(stderr) failed");
	    close(err_fds[1]);
	}

	info.hPipeInputRead   = GetStdHandle(STD_INPUT_HANDLE);
	info.hPipeOutputWrite = GetStdHandle(STD_OUTPUT_HANDLE);
	info.hPipeErrorWrite  = GetStdHandle(STD_ERROR_HANDLE);

	pid = (*func) (data, &info);
        if (pid == -1) pid = 0;   /* map Win32 error code onto Unix default */

        if (!pid) {
	    save_errno = errno;
	    close(in_fds[1]);
	    close(out_fds[0]);
	    close(err_fds[0]);
	}

	/* restore the original stdin, stdout and stderr */
	if (pipe_in) {
	    dup2(hStdIn, fileno(stdin));
	    close(hStdIn);
        }
	if (pipe_out) {
	    dup2(hStdOut, fileno(stdout));
	    close(hStdOut);
	}
	if (pipe_err) {
	    dup2(hStdErr, fileno(stderr));
	    close(hStdErr);
	}

        if (pid) {
	    ap_note_subprocess(p, pid, kill_how);
	    if (pipe_in) {
		*pipe_in = in_fds[1];
	    }
	    if (pipe_out) {
		*pipe_out = out_fds[0];
	    }
	    if (pipe_err) {
		*pipe_err = err_fds[0];
	    }
	}
	SetThreadPriority(thread_handle, old_priority);
	(void) ap_release_mutex(spawn_mutex);
	/*
	 * go on to the end of the function, where you can
	 * unblock alarms and return the pid
	 */

    }
#elif defined(NETWARE)
     /* NetWare currently has no pipes yet. This will
        be solved with the new libc for NetWare soon. */
     pid = 0;
#elif defined(OS2)
    {
        int save_in=-1, save_out=-1, save_err=-1;
        
        if (pipe_out) {
            save_out = dup(STDOUT_FILENO);
            dup2(out_fds[1], STDOUT_FILENO);
            close(out_fds[1]);
            DosSetFHState(out_fds[0], OPEN_FLAGS_NOINHERIT);
        }

        if (pipe_in) {
            save_in = dup(STDIN_FILENO);
            dup2(in_fds[0], STDIN_FILENO);
            close(in_fds[0]);
            DosSetFHState(in_fds[1], OPEN_FLAGS_NOINHERIT);
        }

        if (pipe_err) {
            save_err = dup(STDERR_FILENO);
            dup2(err_fds[1], STDERR_FILENO);
            close(err_fds[1]);
            DosSetFHState(err_fds[0], OPEN_FLAGS_NOINHERIT);
        }
        
        pid = func(data, NULL);
    
        if ( pid )
            ap_note_subprocess(p, pid, kill_how);

        if (pipe_out) {
            close(STDOUT_FILENO);
            dup2(save_out, STDOUT_FILENO);
            close(save_out);
            *pipe_out = out_fds[0];
        }

        if (pipe_in) {
            close(STDIN_FILENO);
            dup2(save_in, STDIN_FILENO);
            close(save_in);
            *pipe_in = in_fds[1];
        }

        if (pipe_err) {
            close(STDERR_FILENO);
            dup2(save_err, STDERR_FILENO);
            close(save_err);
            *pipe_err = err_fds[0];
        }
    }
#elif defined(TPF)
   return (pid = ap_tpf_spawn_child(p, func, data, kill_how,	
                 pipe_in, pipe_out, pipe_err, out_fds, in_fds, err_fds));		
#else

    if ((pid = fork()) < 0) {
	save_errno = errno;
	if (pipe_in) {
	    close(in_fds[0]);
	    close(in_fds[1]);
	}
	if (pipe_out) {
	    close(out_fds[0]);
	    close(out_fds[1]);
	}
	if (pipe_err) {
	    close(err_fds[0]);
	    close(err_fds[1]);
	}
	errno = save_errno;
	return 0;
    }

    if (!pid) {
	/* Child process */
	RAISE_SIGSTOP(SPAWN_CHILD);

	if (pipe_out) {
	    close(out_fds[0]);
	    dup2(out_fds[1], STDOUT_FILENO);
	    close(out_fds[1]);
	}

	if (pipe_in) {
	    close(in_fds[1]);
	    dup2(in_fds[0], STDIN_FILENO);
	    close(in_fds[0]);
	}

	if (pipe_err) {
	    close(err_fds[0]);
	    dup2(err_fds[1], STDERR_FILENO);
	    close(err_fds[1]);
	}

	/* HP-UX SIGCHLD fix goes here, if someone will remind me what it is... */
	signal(SIGCHLD, SIG_DFL);	/* Was that it? */

	func(data, NULL);
	exit(1);		/* Should only get here if the exec in func() failed */
    }

    /* Parent process */

    ap_note_subprocess(p, pid, kill_how);

    if (pipe_out) {
	close(out_fds[1]);
	*pipe_out = out_fds[0];
    }

    if (pipe_in) {
	close(in_fds[0]);
	*pipe_in = in_fds[1];
    }

    if (pipe_err) {
	close(err_fds[1]);
	*pipe_err = err_fds[0];
    }
#endif /* WIN32 */

    return pid;
}


API_EXPORT(int) ap_spawn_child(pool *p, int (*func) (void *, child_info *),
			       void *data, enum kill_conditions kill_how,
			       FILE **pipe_in, FILE **pipe_out,
			       FILE **pipe_err)
{
    int fd_in, fd_out, fd_err;
    pid_t pid;
    int save_errno;

    ap_block_alarms();

    pid = spawn_child_core(p, func, data, kill_how,
			   pipe_in ? &fd_in : NULL,
			   pipe_out ? &fd_out : NULL,
			   pipe_err ? &fd_err : NULL);

    if (pid == 0) {
	save_errno = errno;
	ap_unblock_alarms();
	errno = save_errno;
	return 0;
    }

    if (pipe_out) {
	*pipe_out = ap_fdopen(fd_out, "r" BINMODE);
	if (*pipe_out)
	    ap_note_cleanups_for_file(p, *pipe_out);
	else
	    close(fd_out);
    }

    if (pipe_in) {
	*pipe_in = ap_fdopen(fd_in, "w" BINMODE);
	if (*pipe_in)
	    ap_note_cleanups_for_file(p, *pipe_in);
	else
	    close(fd_in);
    }

    if (pipe_err) {
	*pipe_err = ap_fdopen(fd_err, "r" BINMODE);
	if (*pipe_err)
	    ap_note_cleanups_for_file(p, *pipe_err);
	else
	    close(fd_err);
    }

    ap_unblock_alarms();
    return pid;
}

API_EXPORT(int) ap_bspawn_child(pool *p, int (*func) (void *, child_info *), void *data,
				enum kill_conditions kill_how,
				BUFF **pipe_in, BUFF **pipe_out, BUFF **pipe_err)
{
#ifdef WIN32
    SECURITY_ATTRIBUTES sa = {0};  
    HANDLE hPipeOutputRead  = NULL;
    HANDLE hPipeOutputWrite = NULL;
    HANDLE hPipeInputRead   = NULL;
    HANDLE hPipeInputWrite  = NULL;
    HANDLE hPipeErrorRead   = NULL;
    HANDLE hPipeErrorWrite  = NULL;
    HANDLE hPipeInputWriteDup = NULL;
    HANDLE hPipeOutputReadDup = NULL;
    HANDLE hPipeErrorReadDup  = NULL;
    HANDLE hCurrentProcess;
    pid_t pid = 0;
    child_info info;


    ap_block_alarms();

    /*
     *  First thing to do is to create the pipes that we will use for stdin, stdout, and
     *  stderr in the child process.
     */      
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;


    /* Create pipes for standard input/output/error redirection. */
    if (pipe_in && !CreatePipe(&hPipeInputRead, &hPipeInputWrite, &sa, 0))
	return 0;

    if (pipe_out && !CreatePipe(&hPipeOutputRead, &hPipeOutputWrite, &sa, 0)) {
	if(pipe_in) {
	    CloseHandle(hPipeInputRead);
	    CloseHandle(hPipeInputWrite);
	}
	return 0;
    }

    if (pipe_err && !CreatePipe(&hPipeErrorRead, &hPipeErrorWrite, &sa, 0)) {
	if(pipe_in) {
	    CloseHandle(hPipeInputRead);
	    CloseHandle(hPipeInputWrite);
	}
	if(pipe_out) {
	    CloseHandle(hPipeOutputRead);
	    CloseHandle(hPipeOutputWrite);
	}
	return 0;
    }
    /*
     * When the pipe handles are created, the security descriptor
     * indicates that the handle can be inherited.  However, we do not
     * want the server side handles to the pipe to be inherited by the
     * child CGI process. If the child CGI does inherit the server
     * side handles, then the child may be left around if the server
     * closes its handles (e.g. if the http connection is aborted),
     * because the child will have a valid copy of handles to both
     * sides of the pipes, and no I/O error will occur.  Microsoft
     * recommends using DuplicateHandle to turn off the inherit bit
     * under NT and Win95.
     */
    hCurrentProcess = GetCurrentProcess();
    if ((pipe_in && !DuplicateHandle(hCurrentProcess, hPipeInputWrite,
				     hCurrentProcess,
				     &hPipeInputWriteDup, 0, FALSE,
				     DUPLICATE_SAME_ACCESS))
	|| (pipe_out && !DuplicateHandle(hCurrentProcess, hPipeOutputRead,
					 hCurrentProcess, &hPipeOutputReadDup,
					 0, FALSE, DUPLICATE_SAME_ACCESS))
	|| (pipe_err && !DuplicateHandle(hCurrentProcess, hPipeErrorRead,
					 hCurrentProcess, &hPipeErrorReadDup,
					 0, FALSE, DUPLICATE_SAME_ACCESS))) {
	if (pipe_in) {
	    CloseHandle(hPipeInputRead);
	    CloseHandle(hPipeInputWrite);
	}
	if (pipe_out) {
	    CloseHandle(hPipeOutputRead);
	    CloseHandle(hPipeOutputWrite);
	}
	if (pipe_err) {
	    CloseHandle(hPipeErrorRead);
	    CloseHandle(hPipeErrorWrite);
	}
	return 0;
    }
    else {
	if (pipe_in) {
	    CloseHandle(hPipeInputWrite);
	    hPipeInputWrite = hPipeInputWriteDup;
	}
	if (pipe_out) {
	    CloseHandle(hPipeOutputRead);
	    hPipeOutputRead = hPipeOutputReadDup;
	}
	if (pipe_err) {
	    CloseHandle(hPipeErrorRead);
	    hPipeErrorRead = hPipeErrorReadDup;
	}
    }

    /* The script writes stdout to this pipe handle */
    info.hPipeOutputWrite = hPipeOutputWrite;  

    /* The script reads stdin from this pipe handle */
    info.hPipeInputRead = hPipeInputRead;

    /* The script writes stderr to this pipe handle */
    info.hPipeErrorWrite = hPipeErrorWrite;    
     
    /*
     *  Try to launch the CGI.  Under the covers, this call 
     *  will try to pick up the appropriate interpreter if 
     *  one is needed.
     */
    pid = func(data, &info);
    if (pid == -1) {
        /* Things didn't work, so cleanup */
        pid = 0;   /* map Win32 error code onto Unix default */
        CloseHandle(hPipeOutputRead);
        CloseHandle(hPipeInputWrite);
        CloseHandle(hPipeErrorRead);
    }
    else {
        if (pipe_out) {
            /*
             *  This pipe represents stdout for the script, 
             *  so we read from this pipe.
             */
	    /* Create a read buffer */
            *pipe_out = ap_bcreate(p, B_RD);

	    /* Setup the cleanup routine for the handle */
            ap_note_cleanups_for_h(p, hPipeOutputRead);   

	    /* Associate the handle with the new buffer */
            ap_bpushh(*pipe_out, hPipeOutputRead);
        }
        
        if (pipe_in) {
            /*
             *  This pipe represents stdin for the script, so we 
             *  write to this pipe.
             */
	    /* Create a write buffer */
            *pipe_in = ap_bcreate(p, B_WR);             

	    /* Setup the cleanup routine for the handle */
            ap_note_cleanups_for_h(p, hPipeInputWrite);

	    /* Associate the handle with the new buffer */
            ap_bpushh(*pipe_in, hPipeInputWrite);

        }
      
        if (pipe_err) {
            /*
             *  This pipe represents stderr for the script, so 
             *  we read from this pipe.
             */
	    /* Create a read buffer */
            *pipe_err = ap_bcreate(p, B_RD);

	    /* Setup the cleanup routine for the handle */
            ap_note_cleanups_for_h(p, hPipeErrorRead);

	    /* Associate the handle with the new buffer */
            ap_bpushh(*pipe_err, hPipeErrorRead);
        }
    }  


    /*
     * Now that handles have been inherited, close them to be safe.
     * You don't want to read or write to them accidentally, and we
     * sure don't want to have a handle leak.
     */
    CloseHandle(hPipeOutputWrite);
    CloseHandle(hPipeInputRead);
    CloseHandle(hPipeErrorWrite);

#else
    int fd_in, fd_out, fd_err;
    pid_t pid;
    int save_errno;

    ap_block_alarms();

    pid = spawn_child_core(p, func, data, kill_how,
			   pipe_in ? &fd_in : NULL,
			   pipe_out ? &fd_out : NULL,
			   pipe_err ? &fd_err : NULL);

    if (pid == 0) {
	save_errno = errno;
	ap_unblock_alarms();
	errno = save_errno;
	return 0;
    }

    if (pipe_out) {
	*pipe_out = ap_bcreate(p, B_RD);
	ap_note_cleanups_for_fd_ex(p, fd_out, 0);
	ap_bpushfd(*pipe_out, fd_out, fd_out);
    }

    if (pipe_in) {
	*pipe_in = ap_bcreate(p, B_WR);
	ap_note_cleanups_for_fd_ex(p, fd_in, 0);
	ap_bpushfd(*pipe_in, fd_in, fd_in);
    }

    if (pipe_err) {
	*pipe_err = ap_bcreate(p, B_RD);
	ap_note_cleanups_for_fd_ex(p, fd_err, 0);
	ap_bpushfd(*pipe_err, fd_err, fd_err);
    }
#endif

    ap_unblock_alarms();
    return pid;
}


/* 
 * Timing constants for killing subprocesses
 * There is a total 3-second delay between sending a SIGINT 
 * and sending of the final SIGKILL.
 * TIMEOUT_INTERVAL should be set to TIMEOUT_USECS / 64
 * for the exponetial timeout alogrithm.
 */
#define TIMEOUT_USECS    3000000
#define TIMEOUT_INTERVAL   46875

static void free_proc_chain(struct process_chain *procs)
{
    /* Dispose of the subprocesses we've spawned off in the course of
     * whatever it was we're cleaning up now.  This may involve killing
     * some of them off...
     */
    struct process_chain *p;
    int need_timeout = 0;
    int status;
#if !defined(WIN32) && !defined(NETWARE)
    int timeout_interval;
    struct timeval tv;
#endif

    if (procs == NULL)
	return;			/* No work.  Whew! */

    /* First, check to see if we need to do the SIGTERM, sleep, SIGKILL
     * dance with any of the processes we're cleaning up.  If we've got
     * any kill-on-sight subprocesses, ditch them now as well, so they
     * don't waste any more cycles doing whatever it is that they shouldn't
     * be doing anymore.
     */
#ifdef WIN32
    /* Pick up all defunct processes */
    for (p = procs; p; p = p->next) {
	if (GetExitCodeProcess((HANDLE) p->pid, &status)) {
	    p->kill_how = kill_never;
	}
    }


    for (p = procs; p; p = p->next) {
	if (p->kill_how == kill_after_timeout) {
	    need_timeout = 1;
	}
	else if (p->kill_how == kill_always) {
	    TerminateProcess((HANDLE) p->pid, 1);
	}
    }
    /* Sleep only if we have to... */

    if (need_timeout)
	sleep(3);

    /* OK, the scripts we just timed out for have had a chance to clean up
     * --- now, just get rid of them, and also clean up the system accounting
     * goop...
     */

    for (p = procs; p; p = p->next) {
	if (p->kill_how == kill_after_timeout)
	    TerminateProcess((HANDLE) p->pid, 1);
    }

    for (p = procs; p; p = p->next) {
	CloseHandle((HANDLE) p->pid);
    }
#elif defined(NETWARE)
#else
#ifndef NEED_WAITPID
    /* Pick up all defunct processes */
    for (p = procs; p; p = p->next) {
	if (waitpid(p->pid, (int *) 0, WNOHANG) > 0) {
	    p->kill_how = kill_never;
	}
    }
#endif

    for (p = procs; p; p = p->next) {
	if ((p->kill_how == kill_after_timeout)
	    || (p->kill_how == kill_only_once)) {
	    /* Subprocess may be dead already.  Only need the timeout if not. */
	    if (ap_os_kill(p->pid, SIGTERM) == -1) {
                p->kill_how = kill_never;
            }
            else {
		need_timeout = 1;
            }
	}
	else if (p->kill_how == kill_always) {
	    kill(p->pid, SIGKILL);
	}
    }

    /* Sleep only if we have to. The sleep algorithm grows
     * by a factor of two on each iteration. TIMEOUT_INTERVAL
     * is equal to TIMEOUT_USECS / 64.
     */
    if (need_timeout) {
        timeout_interval = TIMEOUT_INTERVAL;
        tv.tv_sec = 0;
        tv.tv_usec = timeout_interval;
        select(0, NULL, NULL, NULL, &tv);

        do {
            need_timeout = 0;
            for (p = procs; p; p = p->next) {
                if (p->kill_how == kill_after_timeout) {
                    if (waitpid(p->pid, (int *) 0, WNOHANG | WUNTRACED) > 0)
                        p->kill_how = kill_never;
                    else
                        need_timeout = 1;
                }
            }
            if (need_timeout) {
                if (timeout_interval >= TIMEOUT_USECS) {
                    break;
                }
                tv.tv_sec = timeout_interval / 1000000;
                tv.tv_usec = timeout_interval % 1000000;
                select(0, NULL, NULL, NULL, &tv);
                timeout_interval *= 2;
            }
        } while (need_timeout);
    }

    /* OK, the scripts we just timed out for have had a chance to clean up
     * --- now, just get rid of them, and also clean up the system accounting
     * goop...
     */

    for (p = procs; p; p = p->next) {
	if (p->kill_how == kill_after_timeout)
	    kill(p->pid, SIGKILL);

	if (p->kill_how != kill_never)
	    waitpid(p->pid, &status, 0);
    }
#endif /* !WIN32 && !NETWARE*/
}
