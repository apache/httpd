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
 * @file cache_util.h
 * @brief Cache Storage Functions
 *
 * @defgroup Cache_util  Cache Utility Functions
 * @ingroup  MOD_CACHE
 * @{
 */

#ifndef CACHE_UTIL_H
#define CACHE_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mod_cache.h"

/**
 * cache_util.c
 */

/**
 * Check the freshness of the cache object per RFC2616 section 13.2 (Expiration Model)
 * @param h cache_handle_t
 * @param r request_rec
 * @return 0 ==> cache object is stale, 1 ==> cache object is fresh
 */
int cache_check_freshness(cache_handle_t *h, cache_request_rec *cache,
        request_rec *r);

/**
 * Try obtain a cache wide lock on the given cache key.
 *
 * If we return APR_SUCCESS, we obtained the lock, and we are clear to
 * proceed to the backend. If we return APR_EEXISTS, the the lock is
 * already locked, someone else has gone to refresh the backend data
 * already, so we must return stale data with a warning in the mean
 * time. If we return anything else, then something has gone pear
 * shaped, and we allow the request through to the backend regardless.
 *
 * This lock is created from the request pool, meaning that should
 * something go wrong and the lock isn't deleted on return of the
 * request headers from the backend for whatever reason, at worst the
 * lock will be cleaned up when the request is dies or finishes.
 *
 * If something goes truly bananas and the lock isn't deleted when the
 * request dies, the lock will be trashed when its max-age is reached,
 * or when a request arrives containing a Cache-Control: no-cache. At
 * no point is it possible for this lock to permanently deny access to
 * the backend.
 */
apr_status_t cache_try_lock(cache_server_conf *conf,
        cache_request_rec *cache, request_rec *r, char *key);

/**
 * Remove the cache lock, if present.
 *
 * First, try to close the file handle, whose delete-on-close should
 * kill the file. Otherwise, just delete the file by name.
 *
 * If no lock name has yet been calculated, do the calculation of the
 * lock name first before trying to delete the file.
 *
 * If an optional bucket brigade is passed, the lock will only be
 * removed if the bucket brigade contains an EOS bucket.
 */
apr_status_t cache_remove_lock(cache_server_conf *conf,
        cache_request_rec *cache, request_rec *r, char *key,
        apr_bucket_brigade *bb);

/**
 * Merge in cached headers into the response
 * @param h cache_handle_t
 * @param r request_rec
 * @param preserve_orig If 1, the values in r->headers_out are preserved.
 *        Otherwise, they are overwritten by the cached value.
 */
void cache_accept_headers(cache_handle_t *h, request_rec *r,
        int preserve_orig);

cache_provider_list *cache_get_providers(request_rec *r,
        cache_server_conf *conf, apr_uri_t uri);

#ifdef __cplusplus
}
#endif

#endif /* !CACHE_UTIL_H */
/** @} */
