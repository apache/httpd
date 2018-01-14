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
 * @file cache_storage.h
 * @brief Cache Storage Functions
 *
 * @defgroup Cache_storage  Cache Storage Functions
 * @ingroup  MOD_CACHE
 * @{
 */

#ifndef CACHE_STORAGE_H
#define CACHE_STORAGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mod_cache.h"
#include "cache_util.h"

/**
 * cache_storage.c
 */
int cache_remove_url(cache_request_rec *cache, request_rec *r);
int cache_create_entity(cache_request_rec *cache, request_rec *r,
                        apr_off_t size, apr_bucket_brigade *in);
int cache_select(cache_request_rec *cache, request_rec *r);

/**
 * invalidate a specific URL entity in all caches
 *
 * All cached entities for this URL are removed, usually in
 * response to a POST/PUT or DELETE.
 *
 * This function returns OK if at least one entity was found and
 * removed, and DECLINED if no cached entities were removed.
 * @param cache cache_request_rec
 * @param r request_rec
 */
int cache_invalidate(cache_request_rec *cache, request_rec *r);

apr_status_t cache_generate_key_default(request_rec *r, apr_pool_t* p,
        const char **key);

/**
 * Merge in cached headers into the response
 * @param h cache_handle_t
 * @param r request_rec
 * @param top headers to be applied
 * @param bottom headers to be overwritten
 * @param revalidation true if revalidation is taking place
 */
void cache_accept_headers(cache_handle_t *h, request_rec *r, apr_table_t *top,
        apr_table_t *bottom, int revalidation);

#ifdef __cplusplus
}
#endif

#endif /* !CACHE_STORAGE_H */
/** @} */
