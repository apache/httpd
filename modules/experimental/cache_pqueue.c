/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

#include "apr_general.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif

#if APR_HAVE_STRING_H
#include <string.h>
#endif

#include "cache_pqueue.h"
#define left(i) (2*(i))
#define right(i) ((2*(i))+1)
#define parent(i) ((i)/2)
/*
 *  Priority queue structure
 */
struct cache_pqueue_t
{
    apr_ssize_t size;
    apr_ssize_t avail;
    apr_ssize_t step;
    cache_pqueue_get_priority pri;
    cache_pqueue_getpos get;
    cache_pqueue_setpos set;
    void **d;
};

cache_pqueue_t *cache_pq_init(apr_ssize_t n,
                              cache_pqueue_get_priority pri,
                              cache_pqueue_getpos get,
                              cache_pqueue_setpos set)
{
    cache_pqueue_t *q;

    if (!(q = malloc(sizeof(cache_pqueue_t)))) {
        return NULL;
    }

    /* Need to allocate n+1 elements since element 0 isn't used. */
    if (!(q->d = malloc(sizeof(void*) * (n+1)))) {
        free(q);
        return NULL;
    }
    q->avail = q->step = (n+1);  /* see comment above about n+1 */
    q->pri = pri;
    q->size = 1;
    q->get = get;
    q->set = set;
    return q;
}
/*
 * cleanup
 */
void cache_pq_free(cache_pqueue_t *q)
{
    free(q->d);
    free(q);
}
/*
 * pqsize: size of the queue.
 */
apr_ssize_t cache_pq_size(cache_pqueue_t *q)
{
    /* queue element 0 exists but doesn't count since it isn't used. */
    return (q->size - 1);
}

static void cache_pq_bubble_up(cache_pqueue_t *q, apr_ssize_t i)
{
    apr_ssize_t parent_node;
    void *moving_node = q->d[i];
    long moving_pri = q->pri(moving_node);

    for (parent_node = parent(i);
         ((i > 1) && (q->pri(q->d[parent_node]) < moving_pri));
         i = parent_node, parent_node = parent(i))
    {
        q->d[i] = q->d[parent_node];
        q->set(q->d[i], i);
    }

    q->d[i] = moving_node;
    q->set(moving_node, i);
}

static apr_ssize_t maxchild(cache_pqueue_t *q, apr_ssize_t i)
{
    apr_ssize_t child_node = left(i);

    if (child_node >= q->size)
        return 0;

    if ((child_node+1 < q->size) &&
        (q->pri(q->d[child_node+1]) > q->pri(q->d[child_node])))
    {
        child_node++; /* use right child instead of left */
    }

    return child_node;
}

static void cache_pq_percolate_down(cache_pqueue_t *q, apr_ssize_t i)
{
    apr_ssize_t child_node;
    void *moving_node = q->d[i];
    long moving_pri = q->pri(moving_node);

    while ((child_node = maxchild(q, i)) &&
           (moving_pri < q->pri(q->d[child_node])))
    {
        q->d[i] = q->d[child_node];
        q->set(q->d[i], i);
        i = child_node;
    }

    q->d[i] = moving_node;
    q->set(moving_node, i);
}

apr_status_t cache_pq_insert(cache_pqueue_t *q, void *d)
{
    void *tmp;
    apr_ssize_t i;
    apr_ssize_t newsize;

    if (!q) return APR_EGENERAL;

    /* allocate more memory if necessary */
    if (q->size >= q->avail) {
        newsize = q->size + q->step;
        if (!(tmp = realloc(q->d, sizeof(void*) * newsize))) {
            return APR_EGENERAL;
        };
        q->d = tmp;
        q->avail = newsize;
    }

    /* insert item */
    i = q->size++;
    q->d[i] = d;
    cache_pq_bubble_up(q, i);
    return APR_SUCCESS;
}

/*
 * move a existing entry to a new priority
 */
void cache_pq_change_priority(cache_pqueue_t *q,
                              long old_priority,
                              long new_priority,
                              void *d)
{
    apr_ssize_t posn;

    posn = q->get(d);
    if (new_priority > old_priority)
        cache_pq_bubble_up(q, posn);
    else
        cache_pq_percolate_down(q, posn);
}

apr_status_t cache_pq_remove(cache_pqueue_t *q, void *d)
{
    apr_ssize_t posn = q->get(d);
    q->d[posn] = q->d[--q->size];
    if (q->pri(q->d[posn]) > q->pri(d))
        cache_pq_bubble_up(q, posn);
    else
        cache_pq_percolate_down(q, posn);

    return APR_SUCCESS;
}

void *cache_pq_pop(cache_pqueue_t *q)
{
    void *head;

    if (!q || q->size == 1)
        return NULL;

    head = q->d[1];
    q->d[1] = q->d[--q->size];
    cache_pq_percolate_down(q, 1);

    return head;
}

void *cache_pq_peek(cache_pqueue_t *q)
{
    void *d;
    if (!q || q->size == 1)
        return NULL;
    d = q->d[1];
    return d;
}

static void cache_pq_set_null( void*d, apr_ssize_t val)
{
    /* do nothing */
}

/*
 * this is a debug function.. so it's EASY not fast
 */
void cache_pq_dump(cache_pqueue_t *q,
                   FILE*out,
                   cache_pqueue_print_entry print)
{
    int i;

    fprintf(stdout,"posn\tleft\tright\tparent\tmaxchild\t...\n");
    for (i = 1; i < q->size ;i++) {
        fprintf(stdout,
                "%d\t%d\t%d\t%d\t%" APR_SSIZE_T_FMT "\t",
                i,
                left(i), right(i), parent(i),
                maxchild(q, i));
        print(out, q->d[i]);
    }
}

/*
 * this is a debug function.. so it's EASY not fast
 */
void cache_pq_print(cache_pqueue_t *q,
                    FILE*out,
                    cache_pqueue_print_entry print)
{
    cache_pqueue_t *dup;
    dup = cache_pq_init(q->size, q->pri, q->get, cache_pq_set_null);
    dup->size = q->size;
    dup->avail = q->avail;
    dup->step = q->step;

    memcpy(dup->d, q->d, q->size*sizeof(void*));

    while (cache_pq_size(dup) > 1) {
        void *e = NULL;
        e = cache_pq_pop(dup);
        if (e)
            print(out, e);
        else
            break;
    }
    cache_pq_free(dup);
}

static int cache_pq_subtree_is_valid(cache_pqueue_t *q, int pos)
{
    if (left(pos) < q->size) {
        /* has a left child */
        if (q->pri(q->d[pos]) < q->pri(q->d[left(pos)]))
            return 0;
        if (!cache_pq_subtree_is_valid(q, left(pos)))
            return 0;
    }
    if (right(pos) < q->size) {
        /* has a right child */
        if (q->pri(q->d[pos]) < q->pri(q->d[right(pos)]))
            return 0;
        if (!cache_pq_subtree_is_valid(q, right(pos)))
            return 0;
    }
    return 1;
}

int cache_pq_is_valid(cache_pqueue_t *q)
{
    return cache_pq_subtree_is_valid(q, 1);
}
