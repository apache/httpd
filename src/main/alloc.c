/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */


/*
 * Resource allocation code... the code here is responsible for making
 * sure that nothing leaks.
 *
 * rst --- 4/95 --- 6/95
 */

#include "httpd.h"
#include "multithread.h"

#include <stdarg.h>

/*****************************************************************
 *
 * Managing free storage blocks...
 */

union align
{
  /* Types which are likely to have the longest RELEVANT alignment
   * restrictions...
   */
  
  char *cp;
  void (*f)(void);
  long l;
  FILE *fp;
  double d;
};

#define CLICK_SZ (sizeof(union align))

union block_hdr
{
  union align a;
  
  /* Actual header... */
  
  struct {
    char *endp;
    union block_hdr *next;
    char *first_avail;
  } h;
};

union block_hdr *block_freelist = NULL;
mutex *alloc_mutex = NULL;
mutex *spawn_mutex = NULL;


/* Get a completely new block from the system pool. Note that we rely on
malloc() to provide aligned memory. */

union block_hdr *malloc_block (int size)
{
  union block_hdr *blok =
    (union block_hdr *)malloc(size + sizeof(union block_hdr));

  if (blok == NULL) {
      fprintf (stderr, "Ouch!  malloc failed in malloc_block()\n");
      exit (1);
  }
  blok->h.next = NULL;
  blok->h.first_avail = (char *)(blok + 1);
  blok->h.endp = size + blok->h.first_avail;
  
  return blok;
}



void chk_on_blk_list (union block_hdr *blok, union block_hdr *free_blk)
{
  /* Debugging code.  Left in for the moment. */
    
  while (free_blk) {
    if (free_blk == blok) {
      fprintf (stderr, "Ouch!  Freeing free block\n");
      exit (1);
    }
    free_blk = free_blk->h.next;
  }
}

/* Free a chain of blocks --- must be called with alarms blocked. */

void free_blocks (union block_hdr *blok)
{
  /* First, put new blocks at the head of the free list ---
   * we'll eventually bash the 'next' pointer of the last block
   * in the chain to point to the free blocks we already had.
   */
  
  union block_hdr *old_free_list;

  if (blok == NULL) return;	/* Sanity check --- freeing empty pool? */
  
  (void)acquire_mutex(alloc_mutex);
  old_free_list = block_freelist;
  block_freelist = blok;
  
  /*
   * Next, adjust first_avail pointers of each block --- have to do it
   * sooner or later, and it simplifies the search in new_block to do it
   * now.
   */

  while (blok->h.next != NULL) {
    chk_on_blk_list (blok, old_free_list);
    blok->h.first_avail = (char *)(blok + 1);
    blok = blok->h.next;
  }

  chk_on_blk_list (blok, old_free_list);
  blok->h.first_avail = (char *)(blok + 1);

  /* Finally, reset next pointer to get the old free blocks back */

  blok->h.next = old_free_list;
  (void)release_mutex(alloc_mutex);
}




/* Get a new block, from our own free list if possible, from the system
 * if necessary.  Must be called with alarms blocked.
 */

union block_hdr *new_block (int min_size)
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
      return blok;
    }
    else {
      lastptr = &blok->h.next;
      blok = blok->h.next;
    }
  }

  /* Nope. */

  min_size += BLOCK_MINFREE;
  return malloc_block((min_size > BLOCK_MINALLOC) ? min_size : BLOCK_MINALLOC);
}



/* Accounting */

long bytes_in_block_list (union block_hdr *blok)
{
  long size = 0;

  while (blok) {
    size += blok->h.endp - (char *)(blok + 1);
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

static void run_cleanups (struct cleanup *);
static void free_proc_chain (struct process_chain *);

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
};

pool *permanent_pool;

/* Each pool structure is allocated in the start of its own first block,
 * so we need to know how many bytes that is (once properly aligned...).
 * This also means that when a pool's sub-pool is destroyed, the storage
 * associated with it is *completely* gone, so we have to make sure it
 * gets taken off the parent's sub-pool list...
 */

#define POOL_HDR_CLICKS (1 + ((sizeof(struct pool) - 1) / CLICK_SZ))
#define POOL_HDR_BYTES (POOL_HDR_CLICKS * CLICK_SZ)			 

API_EXPORT(struct pool *) make_sub_pool (struct pool *p)
{
  union block_hdr *blok;
  pool *new_pool;

  block_alarms();

  (void)acquire_mutex(alloc_mutex);
  
  blok = new_block (0);
  new_pool = (pool *)blok->h.first_avail;
  blok->h.first_avail += POOL_HDR_BYTES;

  memset ((char *)new_pool, '\0', sizeof (struct pool));
  new_pool->free_first_avail = blok->h.first_avail;
  new_pool->first = new_pool->last = blok;
    
  if (p) {
    new_pool->parent = p;
    new_pool->sub_next = p->sub_pools;
    if (new_pool->sub_next) new_pool->sub_next->sub_prev = new_pool;
    p->sub_pools = new_pool;
  }
  
  (void)release_mutex(alloc_mutex);
  unblock_alarms();
  
  return new_pool;
}

void init_alloc(void)
{
    alloc_mutex = create_mutex(NULL);
    spawn_mutex = create_mutex(NULL);
    permanent_pool = make_sub_pool (NULL);
}

API_EXPORT(void) clear_pool (struct pool *a)
{
  block_alarms();
  
  while (a->sub_pools)
    destroy_pool (a->sub_pools);
    
  a->sub_pools = NULL;
  
  run_cleanups (a->cleanups);        a->cleanups = NULL;
  free_proc_chain (a->subprocesses); a->subprocesses = NULL;
  free_blocks (a->first->h.next);    a->first->h.next = NULL;

  a->last = a->first;
  a->first->h.first_avail = a->free_first_avail;

  unblock_alarms();
}

API_EXPORT(void) destroy_pool (pool *a)
{
  block_alarms();
  clear_pool (a);

  if (a->parent) {
    if (a->parent->sub_pools == a) a->parent->sub_pools = a->sub_next;
    if (a->sub_prev) a->sub_prev->sub_next = a->sub_next;
    if (a->sub_next) a->sub_next->sub_prev = a->sub_prev;
  }
  
  free_blocks (a->first);
  unblock_alarms();
}

API_EXPORT(long) bytes_in_pool (pool *p) {
    return bytes_in_block_list (p->first);
}
API_EXPORT(long) bytes_in_free_blocks (void) {
    return bytes_in_block_list (block_freelist);
}

/*****************************************************************
 *
 * Allocating stuff...
 */


API_EXPORT(void *) palloc (struct pool *a, int reqsize)
{
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

  if(reqsize <= 0)
      return NULL;
  
  new_first_avail = first_avail + size;
  
  if (new_first_avail <= blok->h.endp) {
    blok->h.first_avail = new_first_avail;
    return (void *)first_avail;
  }

  /* Nope --- get a new one that's guaranteed to be big enough */
  
  block_alarms();
  
  (void)acquire_mutex(alloc_mutex);

  blok = new_block (size);
  a->last->h.next = blok;
  a->last = blok;
  
  (void)release_mutex(alloc_mutex);

  unblock_alarms();

  first_avail = blok->h.first_avail;
  blok->h.first_avail += size;

  return (void *)first_avail;
}

API_EXPORT(void *) pcalloc(struct pool *a, int size)
{
  void *res = palloc (a, size);
  memset (res, '\0', size);
  return res;
}

API_EXPORT(char *) pstrdup(struct pool *a, const char *s)
{
  char *res;
  if (s == NULL) return NULL;
  res = palloc (a, strlen(s) + 1);
  strcpy (res, s);
  return res;
}

API_EXPORT(char *) pstrndup(struct pool *a, const char *s, int n)
{
  char *res;
  if (s == NULL) return NULL;
  res = palloc (a, n + 1);
  strncpy (res, s, n);
  res[n] = '\0';
  return res;
}

char *pstrcat(pool *a, ...)
{
  char *cp, *argp, *res;
  
  /* Pass one --- find length of required string */
  
  int len = 0;
  va_list adummy;
  
  va_start (adummy, a);

  while ((cp = va_arg (adummy, char *)) != NULL) 
    len += strlen(cp);

  va_end (adummy);

  /* Allocate the required string */

  if (len == 0) {
      return NULL;
  }
  res = (char *)palloc(a, len + 1);
  cp = res;

  /* Pass two --- copy the argument strings into the result space */

  va_start (adummy, a);
  
  while ((argp = va_arg (adummy, char *)) != NULL) {
    strcpy (cp, argp);
    cp += strlen(argp);
  }

  va_end (adummy);

  /* Return the result string */

  return res;
}


/*****************************************************************
 *
 * The 'array' functions...
 */

API_EXPORT(array_header *) make_array (pool *p, int nelts, int elt_size)
{
  array_header *res = (array_header *)palloc(p, sizeof(array_header));

  if (nelts < 1) nelts = 1;	/* Assure sanity if someone asks for
				 * array of zero elts.
				 */
  
  res->elts = pcalloc (p, nelts * elt_size);
  
  res->pool = p;
  res->elt_size = elt_size;
  res->nelts = 0;		/* No active elements yet... */
  res->nalloc = nelts;		/* ...but this many allocated */

  return res;
}

API_EXPORT(void *) push_array (array_header *arr)
{
  if (arr->nelts == arr->nalloc) {
    int new_size = (arr->nalloc <= 0) ? 1 : arr->nalloc * 2;
    char *new_data;
    
    new_data = pcalloc (arr->pool, arr->elt_size * new_size);

    memcpy (new_data, arr->elts, arr->nalloc * arr->elt_size);
    arr->elts = new_data;
    arr->nalloc = new_size;
  }

  ++arr->nelts;
  return arr->elts + (arr->elt_size * (arr->nelts - 1));
}

API_EXPORT(void) array_cat (array_header *dst, const array_header *src)
{
  int elt_size = dst->elt_size;
  
  if (dst->nelts + src->nelts > dst->nalloc) {
    int new_size = (dst->nalloc <= 0) ? 1 : dst->nalloc * 2;
    char *new_data;

    while (dst->nelts + src->nelts > new_size)
      new_size *= 2;

    new_data = pcalloc (dst->pool, elt_size * new_size);
    memcpy (new_data, dst->elts, dst->nalloc * elt_size);
    
    dst->elts = new_data;
    dst->nalloc = new_size;
  }

  memcpy (dst->elts + dst->nelts * elt_size, src->elts, elt_size * src->nelts);
  dst->nelts += src->nelts;
}

API_EXPORT(array_header *) copy_array (pool *p, const array_header *arr)
{
  array_header *res = make_array (p, arr->nalloc, arr->elt_size);

  memcpy (res->elts, arr->elts, arr->elt_size * arr->nelts);
  res->nelts = arr->nelts;
  return res;
}

/* This cute function copies the array header *only*, but arranges
 * for the data section to be copied on the first push or arraycat.
 * It's useful when the elements of the array being copied are
 * read only, but new stuff *might* get added on the end; we have the
 * overhead of the full copy only where it is really needed.
 */

API_EXPORT(array_header *) copy_array_hdr (pool *p, const array_header *arr)
{
  array_header *res = (array_header *)palloc(p, sizeof(array_header));

  res->elts = arr->elts;
  
  res->pool = p;
  res->elt_size = arr->elt_size;
  res->nelts = arr->nelts;
  res->nalloc = arr->nelts;	/* Force overflow on push */

  return res;
}

/* The above is used here to avoid consing multiple new array bodies... */

API_EXPORT(array_header *) append_arrays (pool *p,
			     const array_header *first,
			     const array_header *second)
{
  array_header *res = copy_array_hdr (p, first);

  array_cat (res, second);
  return res;
}


/*****************************************************************
 *
 * The "table" functions.
 */

API_EXPORT(table *) make_table (pool *p, int nelts) {
    return make_array (p, nelts, sizeof (table_entry));
}

API_EXPORT(table *) copy_table (pool *p, const table *t) {
    return copy_array (p, t);
}

API_EXPORT(void) clear_table (table *t)
{
    t->nelts = 0;
}

API_EXPORT(array_header *) table_elts (table *t) { return t; }

API_EXPORT(char *) table_get (const table *t, const char *key)
{
    table_entry *elts = (table_entry *)t->elts;
    int i;

    if (key == NULL) return NULL;
    
    for (i = 0; i < t->nelts; ++i)
        if (!strcasecmp (elts[i].key, key))
	    return elts[i].val;

    return NULL;
}

API_EXPORT(void) table_set (table *t, const char *key, const char *val)
{
    register int i, j, k;
    table_entry *elts = (table_entry *)t->elts;
    int done = 0;

    for (i = 0; i < t->nelts; ++i)
	if (!strcasecmp (elts[i].key, key)) {
	    if (!done) {
	        elts[i].val = pstrdup(t->pool, val);
	        done = 1;
	    }
	    else {     /* delete an extraneous element */
                for (j = i, k = i + 1; k < t->nelts; ++j, ++k) {
                    elts[j].key = elts[k].key;
                    elts[j].val = elts[k].val;
                }
                --t->nelts;
	    }
	}

    if (!done) {
        elts = (table_entry *)push_array(t);
        elts->key = pstrdup (t->pool, key);
        elts->val = pstrdup (t->pool, val);
    }
}

API_EXPORT(void) table_unset( table *t, const char *key ) 
{
    register int i, j, k;   
    table_entry *elts = (table_entry *)t->elts;
 
    for (i = 0; i < t->nelts; ++i)
        if (!strcasecmp (elts[i].key, key)) {
 
            /* found an element to skip over
             * there are any number of ways to remove an element from
             * a contiguous block of memory.  I've chosen one that
             * doesn't do a memcpy/bcopy/array_delete, *shrug*...
             */
            for (j = i, k = i + 1; k < t->nelts; ++j, ++k) {
                elts[j].key = elts[k].key;
                elts[j].val = elts[k].val;
            }
            --t->nelts;
        }
}     

API_EXPORT(void) table_merge (table *t, const char *key, const char *val)
{
    table_entry *elts = (table_entry *)t->elts;
    int i;

    for (i = 0; i < t->nelts; ++i)
        if (!strcasecmp (elts[i].key, key)) {
	    elts[i].val = pstrcat (t->pool, elts[i].val, ", ", val, NULL);
	    return;
	}

    elts = (table_entry *)push_array(t);
    elts->key = pstrdup (t->pool, key);
    elts->val = pstrdup (t->pool, val);
}

API_EXPORT(void) table_add (table *t, const char *key, const char *val)
{
    table_entry *elts = (table_entry *)t->elts;

    elts = (table_entry *)push_array(t);
    elts->key = pstrdup (t->pool, key);
    elts->val = pstrdup (t->pool, val);
}

API_EXPORT(table *) overlay_tables (pool *p, const table *overlay, const table *base)
{
    return append_arrays (p, overlay, base);
}

/* And now for something completely abstract ...
 *
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
void table_do (int (*comp)(void *, const char *, const char *), void *rec,
               const table *t, ...)
{
    va_list vp;
    char *argp;
    table_entry *elts = (table_entry *)t->elts;
    int rv, i;
  
    va_start(vp, t);

    argp = va_arg(vp, char *);

    do {
        for (rv = 1, i = 0; rv && (i < t->nelts); ++i) {
            if (elts[i].key && (!argp || !strcasecmp(elts[i].key, argp))) {
                rv = (*comp)(rec, elts[i].key, elts[i].val);
            }
        }
    } while (argp && ((argp = va_arg(vp, char *)) != NULL));

    va_end(vp);
}

/*****************************************************************
 *
 * Managing generic cleanups.  
 */

struct cleanup {
  void *data;
  void (*plain_cleanup)(void *);
  void (*child_cleanup)(void *);
  struct cleanup *next;
};

API_EXPORT(void) register_cleanup (pool *p, void *data, void (*plain_cleanup)(void *),
		       void (*child_cleanup)(void *))
{
  struct cleanup *c = (struct cleanup *)palloc(p, sizeof (struct cleanup));
  c->data = data;
  c->plain_cleanup = plain_cleanup;
  c->child_cleanup = child_cleanup;
  c->next = p->cleanups;
  p->cleanups = c;
}

API_EXPORT(void) kill_cleanup (pool *p, void *data, void (*cleanup)(void *))
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

API_EXPORT(void) run_cleanup (pool *p, void *data, void (*cleanup)(void *))
{
  block_alarms();		/* Run cleanup only once! */
  (*cleanup)(data);
  kill_cleanup (p, data, cleanup);
  unblock_alarms();
}

static void run_cleanups (struct cleanup *c)
{
  while (c) {
    (*c->plain_cleanup)(c->data);
    c = c->next;
  }
}

static void run_child_cleanups (struct cleanup *c)
{
  while (c) {
    (*c->child_cleanup)(c->data);
    c = c->next;
  }
}

static void cleanup_pool_for_exec (pool *p)
{
  run_child_cleanups (p->cleanups);
  p->cleanups = NULL;

  for (p = p->sub_pools; p; p = p->sub_next)
    cleanup_pool_for_exec (p);
}

API_EXPORT(void) cleanup_for_exec(void)
{
#ifndef WIN32
    /*
     * Don't need to do anything on NT, because I
     * am actually going to spawn the new process - not
     * exec it. All handles that are not inheritable, will
     * be automajically closed. The only problem is with
     * file handles that are open, but there isn't much
     * I can do about that (except if the child decides
     * to go out and close them
     */
  block_alarms();
  cleanup_pool_for_exec (permanent_pool);
  unblock_alarms();
#endif /* ndef WIN32 */
}

/*****************************************************************
 *
 * Files and file descriptors; these are just an application of the
 * generic cleanup interface.
 */

static void fd_cleanup (void *fdv) { close ((int)fdv); }

API_EXPORT(void) note_cleanups_for_fd (pool *p, int fd) {
  register_cleanup (p, (void *)fd, fd_cleanup, fd_cleanup);
}

API_EXPORT(void) kill_cleanups_for_fd(pool *p,int fd)
    {
    kill_cleanup(p,(void *)fd,fd_cleanup);
    }

API_EXPORT(int) popenf(pool *a, const char *name, int flg, int mode)
{
  int fd;
  int save_errno;

  block_alarms();
  fd = open(name, flg, mode);
  save_errno = errno;
  if (fd >= 0) {
    fd = ap_slack (fd, AP_SLACK_HIGH);
    note_cleanups_for_fd (a, fd);
  }
  unblock_alarms();
  errno = save_errno;
  return fd;
}

API_EXPORT(int) pclosef(pool *a, int fd)
{
  int res;
  int save_errno;
  
  block_alarms();
  res = close(fd);
  save_errno = errno;
  kill_cleanup(a, (void *)fd, fd_cleanup);
  unblock_alarms();
  errno = save_errno;
  return res;
}

/* Note that we have separate plain_ and child_ cleanups for FILE *s,
 * since fclose() would flush I/O buffers, which is extremely undesirable;
 * we just close the descriptor.
 */

static void file_cleanup (void *fpv) { fclose ((FILE *)fpv); }
static void file_child_cleanup (void *fpv) { close (fileno ((FILE *)fpv)); }

API_EXPORT(void) note_cleanups_for_file (pool *p, FILE *fp) {
  register_cleanup (p, (void *)fp, file_cleanup, file_child_cleanup);
}

API_EXPORT(FILE *) pfopen(pool *a, const char *name, const char *mode)
{
  FILE *fd = NULL;
  int baseFlag, desc;
  int modeFlags = 0;

#ifdef WIN32
  modeFlags = _S_IREAD | _S_IWRITE;
#else
  modeFlags = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
#endif

  block_alarms();

  if (*mode == 'a') {
    /* Work around faulty implementations of fopen */
    baseFlag = (*(mode+1) == '+') ? O_RDWR : O_WRONLY;
    desc = open(name, baseFlag | O_APPEND | O_CREAT,
		modeFlags);
    if (desc >= 0) {
      desc = ap_slack(desc, AP_SLACK_LOW);
      fd = fdopen(desc, mode);
    }
  } else {
    fd = fopen(name, mode);
  }

  if (fd != NULL) note_cleanups_for_file (a, fd);
  unblock_alarms();
  return fd;
}

API_EXPORT(FILE *) pfdopen(pool *a,int fd, const char *mode)
{
  FILE *f;

  block_alarms();
  f=fdopen(fd,mode);
  if(f != NULL)
    note_cleanups_for_file(a,f);
  unblock_alarms();
  return f;
}


API_EXPORT(int) pfclose(pool *a, FILE *fd)
{
  int res;
  
  block_alarms();
  res = fclose(fd);
  kill_cleanup(a, (void *)fd, file_cleanup);
  unblock_alarms();
  return res;
}

/*
 * DIR * with cleanup
 */

static void dir_cleanup (void *dv)
{
    closedir ((DIR *)dv);
}

API_EXPORT(DIR *) popendir (pool *p, const char *name)
{
    DIR *d;
    int save_errno;

    block_alarms ();
    d = opendir (name);
    if (d == NULL) {
	save_errno = errno;
	unblock_alarms ();
	errno = save_errno;
	return NULL;
    }
    register_cleanup (p, (void *)d, dir_cleanup, dir_cleanup);
    unblock_alarms ();
    return d;
}

API_EXPORT(void) pclosedir (pool *p, DIR *d)
{
    block_alarms ();
    kill_cleanup (p, (void *)d, dir_cleanup);
    closedir (d);
    unblock_alarms ();
}

/*****************************************************************
 *
 * Files and file descriptors; these are just an application of the
 * generic cleanup interface.
 */

static void socket_cleanup (void *fdv)
{
    int rv;
    
    rv = closesocket((int)fdv);
}

API_EXPORT(void) note_cleanups_for_socket (pool *p, int fd) {
  register_cleanup (p, (void *)fd, socket_cleanup, socket_cleanup);
}

API_EXPORT(void) kill_cleanups_for_socket(pool *p,int sock)
{
    kill_cleanup(p,(void *)sock,socket_cleanup);
}

API_EXPORT(int) pclosesocket(pool *a, int sock)
{
  int res;
  int save_errno;
  
  block_alarms();
  res = closesocket(sock);
#ifdef WIN32
  errno = WSAGetLastError() - WSABASEERR;
#endif /* WIN32 */
  save_errno = errno;
  kill_cleanup(a, (void *)sock, socket_cleanup);
  unblock_alarms();
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

static void regex_cleanup (void *preg) { regfree ((regex_t *)preg); }

API_EXPORT(regex_t *) pregcomp(pool *p, const char *pattern, int cflags) {
    regex_t *preg = palloc(p, sizeof(regex_t));

    if (regcomp(preg, pattern, cflags))
	return NULL;

    register_cleanup (p, (void *)preg, regex_cleanup, regex_cleanup);

    return preg;
}


API_EXPORT(void) pregfree(pool *p, regex_t *reg)
{
    block_alarms();
    regfree (reg);
    kill_cleanup (p, (void *)reg, regex_cleanup);
    unblock_alarms();
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

API_EXPORT(void) note_subprocess (pool *a, int pid, enum kill_conditions how)
{
  struct process_chain *new =
    (struct process_chain *)palloc(a, sizeof(struct process_chain));

  new->pid = pid;
  new->kill_how = how;
  new->next = a->subprocesses;
  a->subprocesses = new;
}

#ifdef WIN32
#define enc_pipe(fds) _pipe(fds, 512, O_TEXT | O_NOINHERIT)
#else
#define enc_pipe(fds) pipe(fds)
#endif /* WIN32 */

API_EXPORT(int) spawn_child_err (pool *p, int (*func)(void *), void *data,
		     enum kill_conditions kill_how,
		     FILE **pipe_in, FILE **pipe_out, FILE **pipe_err)
{
  int pid;
  int in_fds[2];
  int out_fds[2];
  int err_fds[2];
  int save_errno;

  block_alarms();
  
  if (pipe_in && enc_pipe (in_fds) < 0)
  {
      save_errno = errno;
      unblock_alarms();
      errno = save_errno;
      return 0;
  }
  
  if (pipe_out && enc_pipe (out_fds) < 0) {
    save_errno = errno;
    if (pipe_in) {
      close (in_fds[0]); close (in_fds[1]);
    }
    unblock_alarms();
    errno = save_errno;
    return 0;
  }

  if (pipe_err && enc_pipe (err_fds) < 0) {
    save_errno = errno;
    if (pipe_in) {
      close (in_fds[0]); close (in_fds[1]);
    }
    if (pipe_out) {
      close (out_fds[0]); close (out_fds[1]);
    }
    unblock_alarms();
    errno = save_errno;
    return 0;
  }

#ifdef WIN32

  {
      HANDLE thread_handle;
      int hStdIn, hStdOut, hStdErr;
      int old_priority;
      
      (void)acquire_mutex(spawn_mutex);
      thread_handle = GetCurrentThread(); /* doesn't need to be closed */
      old_priority = GetThreadPriority(thread_handle);
      SetThreadPriority(thread_handle, THREAD_PRIORITY_HIGHEST);
      /* Now do the right thing with your pipes */
      if(pipe_in)
      {
          hStdIn = dup(fileno(stdin));
          dup2(in_fds[0], fileno(stdin));
          close(in_fds[0]);
      }
      if(pipe_out)
      {
          hStdOut = dup(fileno(stdout));
          dup2(out_fds[1], fileno(stdout));
          close(out_fds[1]);
      }
      if(pipe_err)
      {
          hStdErr = dup(fileno(stderr));
          dup2(err_fds[1], fileno(stderr));
          close(err_fds[1]);
      }

      pid = (*func)(data);
      if(!pid)
      {
          save_errno = errno;
          close(in_fds[1]);
          close(out_fds[0]);
          close(err_fds[0]);
      }

      /* restore the original stdin, stdout and stderr */
      if(pipe_in)
          dup2(hStdIn, fileno(stdin));
      if(pipe_out)
          dup2(hStdOut, fileno(stdout));
      if(pipe_err)
          dup2(hStdErr, fileno(stderr));

      if(pid)
      {
          note_subprocess(p, pid, kill_how);
          if(pipe_in)
          {
              *pipe_in = fdopen(in_fds[1], "wb");
              if(*pipe_in)
                  note_cleanups_for_file(p, *pipe_in);
          }
          if(pipe_out)
          {
              *pipe_out = fdopen(out_fds[0], "rb");
              if(*pipe_out)
                  note_cleanups_for_file(p, *pipe_out);
          }
          if(pipe_err)
          {
              *pipe_err = fdopen(err_fds[0], "rb");
              if(*pipe_err)
                  note_cleanups_for_file(p, *pipe_err);
          }
      }
      SetThreadPriority(thread_handle, old_priority);
      (void)release_mutex(spawn_mutex);
      /*
       * go on to the end of the function, where you can
       * unblock alarms and return the pid
       */

  }
#else

  if ((pid = fork()) < 0) {
    save_errno = errno;
    if (pipe_in) {
      close (in_fds[0]); close (in_fds[1]);
    }
    if (pipe_out) {
      close (out_fds[0]); close (out_fds[1]);
    }
    if (pipe_err) {
      close (err_fds[0]); close (err_fds[1]);
    }
    unblock_alarms();
    errno = save_errno;
    return 0;
  }

  if (!pid) {
    /* Child process */
    
    if (pipe_out) {
      close (out_fds[0]);
      dup2 (out_fds[1], STDOUT_FILENO);
      close (out_fds[1]);
    }

    if (pipe_in) {
      close (in_fds[1]);
      dup2 (in_fds[0], STDIN_FILENO);
      close (in_fds[0]);
    }

    if (pipe_err) {
      close (err_fds[0]);
      dup2 (err_fds[1], STDERR_FILENO);
      close (err_fds[1]);
    }

    /* HP-UX SIGCHLD fix goes here, if someone will remind me what it is... */
    signal (SIGCHLD, SIG_DFL);	/* Was that it? */
    
    func (data);
    exit (1);		/* Should only get here if the exec in func() failed */
  }

  /* Parent process */

  note_subprocess (p, pid, kill_how);
  
  if (pipe_out) {
    close (out_fds[1]);
#ifdef __EMX__
    /* Need binary mode set for OS/2. */
    *pipe_out = fdopen (out_fds[0], "rb");
#else
    *pipe_out = fdopen (out_fds[0], "r");
#endif  
  
    if (*pipe_out) note_cleanups_for_file (p, *pipe_out);
  }

  if (pipe_in) {
    close (in_fds[0]);
#ifdef __EMX__
    /* Need binary mode set for OS/2 */
    *pipe_in = fdopen (in_fds[1], "wb");
#else
    *pipe_in = fdopen (in_fds[1], "w");
#endif
    
    if (*pipe_in) note_cleanups_for_file (p, *pipe_in);
  }

  if (pipe_err) {
    close (err_fds[1]);
#ifdef __EMX__
    /* Need binary mode set for OS/2. */
    *pipe_err = fdopen (err_fds[0], "rb");
#else
    *pipe_err = fdopen (err_fds[0], "r");
#endif
  
    if (*pipe_err) note_cleanups_for_file (p, *pipe_err);
  }
#endif /* WIN32 */

  unblock_alarms();
  return pid;
}

static void free_proc_chain (struct process_chain *procs)
{
  /* Dispose of the subprocesses we've spawned off in the course of
   * whatever it was we're cleaning up now.  This may involve killing
   * some of them off...
   */

  struct process_chain *p;
  int need_timeout = 0;
  int status;

  if (procs == NULL) return;	/* No work.  Whew! */

  /* First, check to see if we need to do the SIGTERM, sleep, SIGKILL
   * dance with any of the processes we're cleaning up.  If we've got
   * any kill-on-sight subprocesses, ditch them now as well, so they
   * don't waste any more cycles doing whatever it is that they shouldn't
   * be doing anymore.
   */
#ifdef WIN32
  /* Pick up all defunct processes */
  for (p = procs; p; p = p->next) {
    if (GetExitCodeProcess((HANDLE)p->pid, &status)) {
      p->kill_how = kill_never;
    }
  }


  for (p = procs; p; p = p->next) {
    if (p->kill_how == kill_after_timeout) {
	need_timeout = 1;
    } else if (p->kill_how == kill_always) {
      TerminateProcess((HANDLE)p->pid, 1);
    }
  }
  /* Sleep only if we have to... */

  if (need_timeout) sleep (3);

  /* OK, the scripts we just timed out for have had a chance to clean up
   * --- now, just get rid of them, and also clean up the system accounting
   * goop...
   */

  for (p = procs; p; p = p->next){
    if (p->kill_how == kill_after_timeout) 
      TerminateProcess((HANDLE)p->pid, 1);
  }

  for (p = procs; p; p = p->next){
    CloseHandle((HANDLE)p->pid);
  }
#else
#ifndef NEED_WAITPID
  /* Pick up all defunct processes */
  for (p = procs; p; p = p->next) {
    if (waitpid (p->pid, (int *) 0, WNOHANG) > 0) {
      p->kill_how = kill_never;
    }
  }
#endif

  for (p = procs; p; p = p->next) {
    if ((p->kill_how == kill_after_timeout)
	|| (p->kill_how == kill_only_once)) {
      /* Subprocess may be dead already.  Only need the timeout if not. */
      if (kill (p->pid, SIGTERM) != -1)
	need_timeout = 1;
    } else if (p->kill_how == kill_always) {
      kill (p->pid, SIGKILL);
    }
  }

  /* Sleep only if we have to... */

  if (need_timeout) sleep (3);

  /* OK, the scripts we just timed out for have had a chance to clean up
   * --- now, just get rid of them, and also clean up the system accounting
   * goop...
   */

  for (p = procs; p; p = p->next){
    
    if (p->kill_how == kill_after_timeout) 
      kill (p->pid, SIGKILL);

    if (p->kill_how != kill_never)
      waitpid (p->pid, &status, 0);
  }
#endif /* WIN32 */
}

