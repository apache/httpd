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

#include "mod_cache.h"
#include "cache_hash.h"
#include "cache_pqueue.h"
#include "cache_cache.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STRING_H
#include <string.h>
#endif

struct cache_cache_t  {
    int             max_entries;
    apr_size_t      max_size;
    apr_size_t      current_size;
    int             total_purges;
    long            queue_clock;
    cache_hash_t   *ht;
    cache_pqueue_t *pq;
    cache_pqueue_set_priority set_pri;
    cache_pqueue_get_priority get_pri;
    cache_cache_inc_frequency *inc_entry;
    cache_cache_get_size *size_entry;
    cache_cache_get_key *key_entry;
    cache_cache_free *free_entry;
};

CACHE_DECLARE(cache_cache_t *)cache_init(int max_entries,
                                         apr_size_t max_size,
                                         cache_pqueue_get_priority get_pri,
                                         cache_pqueue_set_priority set_pri,
                                         cache_pqueue_getpos get_pos,
                                         cache_pqueue_setpos set_pos,
                                         cache_cache_inc_frequency *inc_entry,
                                         cache_cache_get_size *size_entry,
                                         cache_cache_get_key* key_entry,
                                         cache_cache_free *free_entry)
{
    cache_cache_t *tmp;
    tmp = malloc(sizeof(cache_cache_t));
    tmp->max_entries = max_entries;
    tmp->max_size = max_size;
    tmp->current_size = 0;
    tmp->total_purges = 0;
    tmp->queue_clock = 0;
    tmp->get_pri = get_pri;
    tmp->set_pri = set_pri;
    tmp->inc_entry = inc_entry;
    tmp->size_entry = size_entry;
    tmp->key_entry = key_entry;
    tmp->free_entry = free_entry;

    tmp->ht = cache_hash_make(max_entries);
    tmp->pq = cache_pq_init(max_entries, get_pri, get_pos, set_pos);

    return tmp;
}

CACHE_DECLARE(void) cache_free(cache_cache_t *c)
{
    cache_pq_free(c->pq);
    cache_hash_free(c->ht);
    free(c);
}


CACHE_DECLARE(void*) cache_find(cache_cache_t* c, const char *key)
{
    void *e;

    e = cache_hash_get(c->ht, key, CACHE_HASH_KEY_STRING);
    if (!e)
        return NULL;

    return e;
}

CACHE_DECLARE(void) cache_update(cache_cache_t* c, void *entry)
{
    long old_priority;
    long new_priority;

    old_priority = c->set_pri(c->queue_clock, entry);
    c->inc_entry(entry);
    new_priority = c->set_pri(c->queue_clock, entry);
    cache_pq_change_priority(c->pq, old_priority, new_priority, entry);
}

CACHE_DECLARE(void) cache_insert(cache_cache_t* c, void *entry)
{
    void *ejected = NULL;
    long priority;

    c->set_pri(c->queue_clock, entry);
    /* FIX: check if priority of bottom item is greater than inserted one */
    while ((cache_pq_size(c->pq) >= c->max_entries) ||
            ((c->current_size + c->size_entry(entry)) > c->max_size)) {

        ejected = cache_pq_pop(c->pq);
        /* FIX: If ejected is NULL, we'll segfault here */
        priority = c->get_pri(ejected);

        if (c->queue_clock < priority)
            c->queue_clock = priority;

        cache_hash_set(c->ht,
                       c->key_entry(ejected),
                       CACHE_HASH_KEY_STRING,
                       NULL);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Cache Purge of %s",c->key_entry(ejected));
        c->current_size -= c->size_entry(ejected);
        c->free_entry(ejected);
        c->total_purges++;
    }
    c->current_size += c->size_entry(entry);

    cache_pq_insert(c->pq, entry);
    cache_hash_set(c->ht, c->key_entry(entry), CACHE_HASH_KEY_STRING, entry);
}

CACHE_DECLARE(void *) cache_pop(cache_cache_t *c)
{
    void *entry;

    if (!c)
        return NULL;

    entry = cache_pq_pop(c->pq);

    if (!entry)
        return NULL;

    c->current_size -= c->size_entry(entry);
    cache_hash_set(c->ht, c->key_entry(entry), CACHE_HASH_KEY_STRING, NULL);

    return entry;
}

CACHE_DECLARE(apr_status_t) cache_remove(cache_cache_t *c, void *entry)
{
    apr_size_t entry_size = c->size_entry(entry);
    apr_status_t rc;
    rc = cache_pq_remove(c->pq, entry);
    if (rc != APR_SUCCESS)
        return rc;

    cache_hash_set(c->ht, c->key_entry(entry), CACHE_HASH_KEY_STRING, NULL);
    c->current_size -= entry_size;

    return APR_SUCCESS;
}
