/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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

#ifndef CACHE_PQUEUE_H
#define CACHE_PQUEUE_H

#include <apr.h>
#include <apr_errno.h>

#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** the cache priority queue handle */
typedef struct cache_pqueue_t cache_pqueue_t;

/**
 * callback function to assign a priority for a element
 * @param a the element
 * @return  the score (the lower the score the longer it is kept int the queue)
 */
typedef long (*cache_pqueue_set_priority)(long queue_clock, void *a);
typedef long (*cache_pqueue_get_priority)(void *a);

/** callback function to get a position of a element */
typedef apr_ssize_t (*cache_pqueue_getpos)(void *a);

/**
 * callback function to set a position of a element
 * @param a   the element
 * @param pos the position to set it to
 */
typedef void (*cache_pqueue_setpos)(void *a, apr_ssize_t pos);

/** debug callback function to print a entry */
typedef void (*cache_pqueue_print_entry)(FILE *out, void *a);

/**
 * initialize the queue
 *
 * @param n the initial estimate of the number of queue items for which memory
 *          should be preallocated
 * @param pri the callback function to run to assign a score to a element
 * @param get the callback function to get the current element's position
 * @param set the callback function to set the current element's position
 *
 * @Return the handle or NULL for insufficent memory
 */
cache_pqueue_t *cache_pq_init(apr_ssize_t n,
                              cache_pqueue_get_priority pri,
                              cache_pqueue_getpos get,
                              cache_pqueue_setpos set);
/**
 * free all memory used by the queue
 * @param q the queue
 */
void cache_pq_free(cache_pqueue_t *q);
/**
 * return the size of the queue.
 * @param q the queue
 */
apr_ssize_t cache_pq_size(cache_pqueue_t *q);

/**
 * insert an item into the queue.
 * @param q the queue
 * @param d the item
 * @return APR_SUCCESS on success
 */
apr_status_t cache_pq_insert(cache_pqueue_t *q, void *d);

/*
 * move a existing entry to a different priority
 * @param q the queue
 * @param old the old priority
 * @param d the entry
 */
void cache_pq_change_priority(cache_pqueue_t *q,
                              long old_priority,
                              long new_priority,
                              void *d);

/**
 * pop the highest-ranking item from the queue.
 * @param p the queue
 * @param d where to copy the entry to
 * @return NULL on error, otherwise the entry
 */
void *cache_pq_pop(cache_pqueue_t *q);

/**
 * remove an item from the queue.
 * @param p the queue
 * @param d the entry
 * @return APR_SUCCESS on success
 */
apr_status_t cache_pq_remove(cache_pqueue_t *q, void *d);

/**
 * access highest-ranking item without removing it.
 * @param q the queue
 * @param d the entry
 * @return NULL on error, otherwise the entry
 */
void *cache_pq_peek(cache_pqueue_t *q);

/**
 * print the queue
 * @internal
 * DEBUG function only
 * @param q the queue
 * @param out the output handle
 * @param the callback function to print the entry
 */
void cache_pq_print(cache_pqueue_t *q, 
                    FILE *out, 
                    cache_pqueue_print_entry print);

/**
 * dump the queue and it's internal structure
 * @internal
 * debug function only
 * @param q the queue
 * @param out the output handle
 * @param the callback function to print the entry
 */
void cache_pq_dump(cache_pqueue_t *q, 
                   FILE *out,
                   cache_pqueue_print_entry print);

/**
 * checks that the pq is in the right order, etc
 * @internal
 * debug function only
 * @param q the queue
 */
int cache_pq_is_valid(cache_pqueue_t *q);

#ifdef __cplusplus
}
#endif

#endif /* !CACHE_PQUEUE_H */
