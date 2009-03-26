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
 * @file  util_mutex.h
 * @brief Apache Mutex support library
 *
 * @defgroup APACHE_CORE_MUTEX Mutex Library
 * @ingroup  APACHE_CORE
 * @{
 */

#ifndef UTIL_MUTEX_H
#define UTIL_MUTEX_H

#include "httpd.h"
#include "apr_global_mutex.h"

#if APR_HAS_FLOCK_SERIALIZE
# define AP_LIST_FLOCK_SERIALIZE ", 'flock:/path/to/file'"
#else
# define AP_LIST_FLOCK_SERIALIZE
#endif
#if APR_HAS_FCNTL_SERIALIZE
# define AP_LIST_FCNTL_SERIALIZE ", 'fcntl:/path/to/file'"
#else
# define AP_LIST_FCNTL_SERIALIZE
#endif
#if APR_HAS_SYSVSEM_SERIALIZE
# define AP_LIST_SYSVSEM_SERIALIZE ", 'sysvsem'"
#else
# define AP_LIST_SYSVSEM_SERIALIZE
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
# define AP_LIST_POSIXSEM_SERIALIZE ", 'posixsem'"
#else
# define AP_LIST_POSIXSEM_SERIALIZE
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
# define AP_LIST_PTHREAD_SERIALIZE ", 'pthread'"
#else
# define AP_LIST_PTHREAD_SERIALIZE
#endif
#if APR_HAS_FLOCK_SERIALIZE || APR_HAS_FCNTL_SERIALIZE
# define AP_LIST_FILE_SERIALIZE ", 'file:/path/to/file'"
#else
# define AP_LIST_FILE_SERIALIZE
#endif
#if APR_HAS_SYSVSEM_SERIALIZE || APR_HAS_POSIXSEM_SERIALIZE
# define AP_LIST_SEM_SERIALIZE ", 'sem'"
#else
# define AP_LIST_SEM_SERIALIZE
#endif

#define AP_ALL_AVAILABLE_MUTEXES_STRING                  \
    "Mutex mechanisms are: 'none', 'default'"            \
    AP_LIST_FLOCK_SERIALIZE   AP_LIST_FCNTL_SERIALIZE    \
    AP_LIST_FILE_SERIALIZE    AP_LIST_PTHREAD_SERIALIZE  \
    AP_LIST_SYSVSEM_SERIALIZE AP_LIST_POSIXSEM_SERIALIZE \
    AP_LIST_SEM_SERIALIZE

#define AP_AVAILABLE_MUTEXES_STRING                      \
    "Mutex mechanisms are: 'default'"                    \
    AP_LIST_FLOCK_SERIALIZE   AP_LIST_FCNTL_SERIALIZE    \
    AP_LIST_FILE_SERIALIZE    AP_LIST_PTHREAD_SERIALIZE  \
    AP_LIST_SYSVSEM_SERIALIZE AP_LIST_POSIXSEM_SERIALIZE \
    AP_LIST_SEM_SERIALIZE

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get Mutex config data and parse it
 * @param arg The mutex config string
 * @param pool The allocation pool
 * @param mutexmech The APR mutex locking mechanism
 * @param mutexfile The lockfile to use as required
 * @return APR status code
 * @fn apr_status_t ap_parse_mutex(const char *arg, apr_pool_t *pool,
                                        apr_lockmech_e *mutexmech,
                                        const char **mutexfile)
 */
AP_DECLARE(apr_status_t) ap_parse_mutex(const char *arg, apr_pool_t *pool,
                                        apr_lockmech_e *mutexmech,
                                        const char **mutexfile);


#ifdef __cplusplus
}
#endif

#endif /* UTIL_MUTEX_H */
/** @} */
