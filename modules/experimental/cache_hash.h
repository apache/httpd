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

#ifndef CACHE_HASH_H
#define CACHE_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mod_cache.h"

/**
 * @file cache_hash.h
 * @brief Cache Hash Tables
 */

/**
 * @defgroup Cache_Hash  Hash Tables
 * @ingroup CACHE
 * @{
 */

/**
 * When passing a key to cache_hash_set or cache_hash_get, this value can be
 * passed to indicate a string-valued key, and have cache_hash compute the
 * length automatically.
 *
 * @remark cache_hash will use strlen(key) for the length. The null-terminator
 *         is not included in the hash value (why throw a constant in?).
 *         Since the hash table merely references the provided key (rather
 *         than copying it), cache_hash_this() will return the null-term'd key.
 */
#define CACHE_HASH_KEY_STRING     (-1)

/**
 * Abstract type for hash tables.
 */
typedef struct cache_hash_t cache_hash_t;

/**
 * Abstract type for scanning hash tables.
 */
typedef struct cache_hash_index_t cache_hash_index_t;

/**
 * Create a hash table.
 * @param size 
 * @return The hash table just created
  */
CACHE_DECLARE(cache_hash_t *) cache_hash_make(apr_size_t size);

/**
 * Create a hash table.
 * @param *ht Pointer to the hash table to be freed.
 * @return void
 * @remark The caller should ensure that all objects have been removed
 *         from the cache prior to calling cache_hash_free(). Objects 
 *         not removed from the cache prior to calling cache_hash_free()
 *         will be unaccessable.
 */
CACHE_DECLARE(void) cache_hash_free(cache_hash_t *ht);


/**
 * Associate a value with a key in a hash table.
 * @param ht The hash table
 * @param key Pointer to the key
 * @param klen Length of the key. Can be CACHE_HASH_KEY_STRING to use the string length.
 * @param val Value to associate with the key
 * @remark If the value is NULL the hash entry is deleted.
 * @return The value of the deleted cache entry (so the caller can clean it up).
 */
CACHE_DECLARE(void *) cache_hash_set(cache_hash_t *ht, const void *key,
                                     apr_ssize_t klen, const void *val);

/**
 * Look up the value associated with a key in a hash table.
 * @param ht The hash table
 * @param key Pointer to the key
 * @param klen Length of the key. Can be CACHE_HASH_KEY_STRING to use the string length.
 * @return Returns NULL if the key is not present.
 */
CACHE_DECLARE(void *) cache_hash_get(cache_hash_t *ht, const void *key,
                                   apr_ssize_t klen);

/**
 * Start iterating over the entries in a hash table.
 * @param ht The hash table
 * @example
 */
/**
 * <PRE>
 * 
 *     int sum_values(cache_hash_t *ht)
 *     {
 *         cache_hash_index_t *hi;
 * 	   void *val;
 * 	   int sum = 0;
 * 	   for (hi = cache_hash_first(ht); hi; hi = cache_hash_next(hi)) {
 * 	       cache_hash_this(hi, NULL, NULL, &val);
 * 	       sum += *(int *)val;
 * 	   }
 * 	   return sum;
 *     }
 * 
 * There is no restriction on adding or deleting hash entries during an
 * iteration (although the results may be unpredictable unless all you do
 * is delete the current entry) and multiple iterations can be in
 * progress at the same time.
 * </PRE>
  */
CACHE_DECLARE(cache_hash_index_t *) cache_hash_first(cache_hash_t *ht);

/**
 * Continue iterating over the entries in a hash table.
 * @param hi The iteration state
 * @return a pointer to the updated iteration state.  NULL if there are no more  
 *         entries.
 */
CACHE_DECLARE(cache_hash_index_t *) cache_hash_next(cache_hash_index_t *hi);

/**
 * Get the current entry's details from the iteration state.
 * @param hi The iteration state
 * @param key Return pointer for the pointer to the key.
 * @param klen Return pointer for the key length.
 * @param val Return pointer for the associated value.
 * @remark The return pointers should point to a variable that will be set to the
 *         corresponding data, or they may be NULL if the data isn't interesting.
 */
CACHE_DECLARE(void) cache_hash_this(cache_hash_index_t *hi, const void **key, 
                                  apr_ssize_t *klen, void **val);

/**
 * Get the number of key/value pairs in the hash table.
 * @param ht The hash table
 * @return The number of key/value pairs in the hash table.
 */
CACHE_DECLARE(int) cache_hash_count(cache_hash_t *ht);


/** @} */
#ifdef __cplusplus
}
#endif

#endif	/* !CACHE_HASH_H */
