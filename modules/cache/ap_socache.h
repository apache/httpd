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
 * @file ap_socache.h
 * @brief Small object cache provider interface.
 *
 * @defgroup AP_SOCACHE ap_socache
 * @ingroup  APACHE_MODS
 * @{
 */

#ifndef AP_SOCACHE_H
#define AP_SOCACHE_H 

#include "httpd.h"
#include "ap_provider.h"
#include "apr_pools.h"

/* If this flag is set, the store/retrieve/delete/status interfaces of
 * the provider are NOT safe to be called concurrently from multiple
 * processes or threads, and an external global mutex must be used to
 * serialize access to the provider. */
#define AP_SOCACHE_FLAG_NOTMPSAFE (0x0001)

/* A cache instance. */
typedef struct ap_socache_instance_t ap_socache_instance_t;

typedef struct ap_socache_provider_t {
    /* Canonical provider name: */
    const char *name;

    /* Bitmask of AP_SOCACHE_FLAG_* flags: */
    unsigned int flags;

    /* Create a session cache based on the given configuration string
     * ARG.  Returns NULL on success, or an error string on failure.
     * Pool TMP should be used for any temporary allocations, pool P
     * should be used for any allocations lasting as long as the
     * lifetime of the return context.
     *
     * The context pointer returned in *INSTANCE will be passed as the
     * first argument to subsequent invocations. */
    const char *(*create)(ap_socache_instance_t **instance, const char *arg, 
                          apr_pool_t *tmp, apr_pool_t *p);
    /* Initialize the cache.  Return APR error code.   */
    apr_status_t (*init)(ap_socache_instance_t *instance, /* hints, namespace */
                         server_rec *s, apr_pool_t *pool);
    /* Destroy a given cache context. */    
    void (*destroy)(ap_socache_instance_t *instance, server_rec *s);
    /* Store an object in the cache with key ID of length IDLEN, with
     * DATA of length DATALEN.  The object expires at abolute time
     * EXPIRY.  */
    apr_status_t (*store)(ap_socache_instance_t *instance, server_rec *s, 
                          const unsigned char *id, unsigned int idlen, 
                          time_t expiry, 
                          unsigned char *data, unsigned int datalen);
    /* Retrieve cached object with key ID of length IDLEN, returning
     * TRUE on success or FALSE otherwise.  If TRUE, the data must be
     * placed in DEST, which has length on entry of *DESTLEN.
     * *DESTLEN must be updated to equal the length of data written on
     * exit. */
    apr_status_t (*retrieve)(ap_socache_instance_t *instance, server_rec *s,
                             const unsigned char *id, unsigned int idlen,
                             unsigned char *data, unsigned int *datalen,
                             apr_pool_t *pool);
    /* Remove an object from the cache with key ID of length IDLEN.
     * POOL may be used for temporary allocations. */
    void (*delete)(ap_socache_instance_t *instance, server_rec *s,
                   const unsigned char *id, unsigned int idlen,
                   apr_pool_t *pool);
    /* Dump cache status for mod_status output. */
    void (*status)(ap_socache_instance_t *instance, request_rec *r, int flags);
} ap_socache_provider_t;

/* Cache providers are registered using the ap_provider_* interface,
 * with the following group and version:  */
#define AP_SOCACHE_PROVIDER_GROUP "socache"
#define AP_SOCACHE_PROVIDER_VERSION "0"

#endif /* AP_SOCACHE_H */
/** @} */
