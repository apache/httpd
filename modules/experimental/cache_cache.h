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

#ifndef CACHE_CACHE_H
#define CACHE_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mod_cache.h"

/**
 * @file cache_hash.h
 * @brief Cache Cache Functions
 */

/**
 * @defgroup Cache_cache  Cache Functions
 * @ingroup CACHE
 * @{
 */
/** ADT for the cache */
typedef struct cache_cache_t cache_cache_t;

/** callback to increment the frequency of a item */
typedef void cache_cache_inc_frequency(void*a);
/** callback to get the size of a item */
typedef apr_size_t cache_cache_get_size(void*a);
/** callback to get the key of a item */
typedef const char* cache_cache_get_key(void *a);
/** callback to free an entry */
typedef void cache_cache_free(void *a);

/**
 * initialize the cache ADT
 * @param max_entries the number of entries in the cache
 * @param max_size    the size of the cache
 * @param get_pri     callback to get a priority of a entry
 * @param set_pri     callback to set a priority of a entry
 * @param get_pos     callback to get the position of a entry in the cache
 * @param set_pos     callback to set the position of a entry in the cache
 * @param inc_entry   callback to increment the frequency of a entry
 * @param size_entry  callback to get the size of a entry
 * @param key_entry   callback to get the key of a entry
 * @param free_entry  callback to free an entry
 */
CACHE_DECLARE(cache_cache_t *)cache_init(int max_entries, 
                                         apr_size_t max_size,
                                         cache_pqueue_get_priority get_pri,
                                         cache_pqueue_set_priority set_pri,
                                         cache_pqueue_getpos get_pos,
                                         cache_pqueue_setpos set_pos,
                                         cache_cache_inc_frequency *inc_entry,
                                         cache_cache_get_size *size_entry,
                                         cache_cache_get_key *key_entry,
                                         cache_cache_free *free_entry);

/**
 * free up the cache
 * @param c the cache
 */
CACHE_DECLARE(void) cache_free(cache_cache_t *c);
/**
 * find a entry in the cache, incrementing the frequency if found
 * @param c the cache
 * @param key the key
 */
CACHE_DECLARE(void*) cache_find(cache_cache_t* c, const char *key);
/** 
 * insert a entry into the cache
 * @param c the cache
 * @param entry the entry
 */
CACHE_DECLARE(void) cache_update(cache_cache_t* c, void *entry);
/** 
 * insert a entry into the cache
 * @param c the cache
 * @param entry the entry
 */
CACHE_DECLARE(void) cache_insert(cache_cache_t* c, void *entry);
/**
 * pop the lowest priority item off
 * @param c the cache
 * @returns the entry or NULL
 */
CACHE_DECLARE(void *)cache_pop(cache_cache_t* c);
/** 
 * remove an item from the cache 
 * @param c the cache
 * @param entry the actual entry (from a find)
 */
CACHE_DECLARE(apr_status_t) cache_remove(cache_cache_t* c, void *entry);
/** @} */
#ifdef __cplusplus
}
#endif

#endif /* !CACHE_CACHE_H */
