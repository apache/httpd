/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file cache_hash.h
 * @brief Cache Hash Tables
 *
 * @defgroup Cache_Hash  Hash Tables
 * @ingroup  MOD_CACHE
 * @{
 */

#ifndef CACHE_HASH_H
#define CACHE_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mod_cache.h"

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
cache_hash_t* cache_hash_make(apr_size_t size);

/**
 * Create a hash table.
 * @param *ht Pointer to the hash table to be freed.
 * @return void
 * @remark The caller should ensure that all objects have been removed
 *         from the cache prior to calling cache_hash_free(). Objects 
 *         not removed from the cache prior to calling cache_hash_free()
 *         will be unaccessable.
 */
void cache_hash_free(cache_hash_t *ht);


/**
 * Associate a value with a key in a hash table.
 * @param ht The hash table
 * @param key Pointer to the key
 * @param klen Length of the key. Can be CACHE_HASH_KEY_STRING to use the string length.
 * @param val Value to associate with the key
 * @remark If the value is NULL the hash entry is deleted.
 * @return The value of the deleted cache entry (so the caller can clean it up).
 */
void* cache_hash_set(cache_hash_t *ht, const void *key,
                                     apr_ssize_t klen, const void *val);

/**
 * Look up the value associated with a key in a hash table.
 * @param ht The hash table
 * @param key Pointer to the key
 * @param klen Length of the key. Can be CACHE_HASH_KEY_STRING to use the string length.
 * @return Returns NULL if the key is not present.
 */
void* cache_hash_get(cache_hash_t *ht, const void *key,
                                   apr_ssize_t klen);

/**
 * Start iterating over the entries in a hash table.
 * @param ht The hash table
 *
 * Here is an example of using this:
 * @code
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
 * @endcode
 *
 * There is no restriction on adding or deleting hash entries during an
 * iteration (although the results may be unpredictable unless all you do
 * is delete the current entry) and multiple iterations can be in
 * progress at the same time.
  */
cache_hash_index_t* cache_hash_first(cache_hash_t *ht);

/**
 * Continue iterating over the entries in a hash table.
 * @param hi The iteration state
 * @return a pointer to the updated iteration state.  NULL if there are no more  
 *         entries.
 */
cache_hash_index_t* cache_hash_next(cache_hash_index_t *hi);

/**
 * Get the current entry's details from the iteration state.
 * @param hi The iteration state
 * @param key Return pointer for the pointer to the key.
 * @param klen Return pointer for the key length.
 * @param val Return pointer for the associated value.
 * @remark The return pointers should point to a variable that will be set to the
 *         corresponding data, or they may be NULL if the data isn't interesting.
 */
void cache_hash_this(cache_hash_index_t *hi, const void **key, 
                                  apr_ssize_t *klen, void **val);

/**
 * Get the number of key/value pairs in the hash table.
 * @param ht The hash table
 * @return The number of key/value pairs in the hash table.
 */
int cache_hash_count(cache_hash_t *ht);


/** @} */
#ifdef __cplusplus
}
#endif

#endif	/* !CACHE_HASH_H */
