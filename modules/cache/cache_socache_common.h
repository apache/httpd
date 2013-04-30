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
 * @file cache_socache_common.h
 * @brief Common Shared Object Cache vars/structs
 *
 * @defgroup Cache_cache  Cache Functions
 * @ingroup  MOD_SOCACHE_CACHE
 * @{
 */

#ifndef CACHE_SOCACHE_COMMON_H
#define CACHE_SOCACHE_COMMON_H

#include "apr_time.h"

#include "cache_common.h"

#define CACHE_SOCACHE_VARY_FORMAT_VERSION 1
#define CACHE_SOCACHE_DISK_FORMAT_VERSION 2

typedef struct {
    /* Indicates the format of the header struct stored on-disk. */
    apr_uint32_t format;
    /* The HTTP status code returned for this response.  */
    int status;
    /* The size of the entity name that follows. */
    apr_size_t name_len;
    /* The number of times we've cached this entity. */
    apr_size_t entity_version;
    /* Miscellaneous time values. */
    apr_time_t date;
    apr_time_t expire;
    apr_time_t request_time;
    apr_time_t response_time;
    /* Does this cached request have a body? */
    unsigned int header_only:1;
    /* The parsed cache control header */
    cache_control_t control;
} cache_socache_info_t;

#endif /* CACHE_SOCACHE_COMMON_H */
/** @} */
