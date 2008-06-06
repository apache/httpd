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
 * @file cache_cache.h
 * @brief Cache Cache Functions
 *
 * @defgroup Cache_cache  Cache Functions
 * @ingroup  MOD_CACHE
 * @{
 */

#ifndef CACHE_CACHE_H
#define CACHE_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mod_cache.h"

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
cache_cache_t* cache_init(int max_entries, 
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
void cache_free(cache_cache_t *c);
/**
 * find a entry in the cache, incrementing the frequency if found
 * @param c the cache
 * @param key the key
 */
void* cache_find(cache_cache_t* c, const char *key);
/** 
 * insert a entry into the cache
 * @param c the cache
 * @param entry the entry
 */
void cache_update(cache_cache_t* c, void *entry);
/** 
 * insert a entry into the cache
 * @param c the cache
 * @param entry the entry
 */
void cache_insert(cache_cache_t* c, void *entry);
/**
 * pop the lowest priority item off
 * @param c the cache
 * @returns the entry or NULL
 */
void* cache_pop(cache_cache_t* c);
/** 
 * remove an item from the cache 
 * @param c the cache
 * @param entry the actual entry (from a find)
 */
apr_status_t cache_remove(cache_cache_t* c, void *entry);
#ifdef __cplusplus
}
#endif

#endif /* !CACHE_CACHE_H */
/** @} */
