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

/**
 * cache_storage.c
 */
int cache_remove_url(cache_request_rec *cache, apr_pool_t *p);
int cache_create_entity(cache_request_rec *cache, request_rec *r,
                        apr_off_t size, apr_bucket_brigade *in);
int cache_select(cache_request_rec *cache, request_rec *r);
apr_status_t cache_generate_key_default(cache_request_rec *cache, request_rec *r,
                                        apr_pool_t* p, char **key);

#ifdef __cplusplus
}
#endif

#endif /* !CACHE_STORAGE_H */
/** @} */
