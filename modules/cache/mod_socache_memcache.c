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


#include "httpd.h"
#include "http_config.h"

#include "apr.h"
#include "apu_version.h"

/* apr_memcache support requires >= 1.3 */
#if APU_MAJOR_VERSION > 1 || \
    (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION > 2)
#define HAVE_APU_MEMCACHE 1
#endif

#ifdef HAVE_APU_MEMCACHE

#include "ap_socache.h"
#include "ap_mpm.h"
#include "http_log.h"
#include "apr_memcache.h"

/* The underlying apr_memcache system is thread safe.. */
#define MC_KEY_LEN 254

#ifndef MC_DEFAULT_SERVER_PORT
#define MC_DEFAULT_SERVER_PORT 11211
#endif


#ifndef MC_DEFAULT_SERVER_MIN
#define MC_DEFAULT_SERVER_MIN 0
#endif

#ifndef MC_DEFAULT_SERVER_SMAX
#define MC_DEFAULT_SERVER_SMAX 1
#endif

#ifndef MC_DEFAULT_SERVER_TTL
#define MC_DEFAULT_SERVER_TTL 600
#endif

struct ap_socache_instance_t {
    const char *servers;
    apr_memcache_t *mc;
    const char *tag;
    apr_size_t taglen; /* strlen(tag) + 1 */
};

static const char *socache_mc_create(ap_socache_instance_t **context, 
                                     const char *arg, 
                                     apr_pool_t *tmp, apr_pool_t *p)
{
    ap_socache_instance_t *ctx;
    
    *context = ctx = apr_palloc(p, sizeof *ctx);

    if (!arg || !*arg) {
        return "List of server names required to create memcache socache.";
    }
    
    ctx->servers = apr_pstrdup(p, arg);

    return NULL;
}

static apr_status_t socache_mc_init(ap_socache_instance_t *ctx, 
                                    const char *namespace,
                                    const struct ap_socache_hints *hints,
                                    server_rec *s, apr_pool_t *p)
{
    apr_status_t rv;
    int thread_limit = 0;
    int nservers = 0;
    char *cache_config;
    char *split;
    char *tok;

    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);

    /* Find all the servers in the first run to get a total count */
    cache_config = apr_pstrdup(p, ctx->servers);
    split = apr_strtok(cache_config, ",", &tok);
    while (split) {
        nservers++;
        split = apr_strtok(NULL,",", &tok);
    }

    rv = apr_memcache_create(p, nservers, 0, &ctx->mc);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "socache: Failed to create Memcache Object of '%d' size.", 
                     nservers);
        return rv;
    }

    /* Now add each server to the memcache */
    cache_config = apr_pstrdup(p, ctx->servers);
    split = apr_strtok(cache_config, ",", &tok);
    while (split) {
        apr_memcache_server_t *st;
        char *host_str;
        char *scope_id;
        apr_port_t port;

        rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "socache: Failed to Parse memcache Server: '%s'", split);
            return rv;
        }

        if (host_str == NULL) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "socache: Failed to Parse Server, "
                         "no hostname specified: '%s'", split);
            return APR_EINVAL;
        }

        if (port == 0) {
            port = MC_DEFAULT_SERVER_PORT;
        }

        rv = apr_memcache_server_create(p,
                                        host_str, port,
                                        MC_DEFAULT_SERVER_MIN,
                                        MC_DEFAULT_SERVER_SMAX,
                                        thread_limit,
                                        MC_DEFAULT_SERVER_TTL,
                                        &st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "socache: Failed to Create memcache Server: %s:%d", 
                         host_str, port);
            return rv;
        }

        rv = apr_memcache_add_server(ctx->mc, st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "socache: Failed to Add memcache Server: %s:%d", 
                         host_str, port);
            return rv;
        }

        split = apr_strtok(NULL,",", &tok);
    }

    ctx->tag = apr_pstrcat(p, namespace, ":", NULL);
    ctx->taglen = strlen(ctx->tag) + 1;

    /* socache API constraint: */
    AP_DEBUG_ASSERT(ctx->taglen <= 16);

    return APR_SUCCESS;
}

static void socache_mc_destroy(ap_socache_instance_t *context, server_rec *s)
{
    /* noop. */
}

/* Converts (binary) id into a key prefixed by the predetermined
 * namespace tag; writes output to key buffer.  Returns non-zero if
 * the id won't fit in the key buffer. */
static int socache_mc_id2key(ap_socache_instance_t *ctx,
                             const unsigned char *id, unsigned int idlen,
                             char *key, apr_size_t keylen)
{
    char *cp;
    unsigned int n;

    if (idlen * 2 + ctx->taglen >= keylen)
        return 1;

    cp = apr_cpystrn(key, ctx->tag, ctx->taglen);

    for (n = 0; n < idlen; n++) {
        apr_snprintf(cp, 3, "%02X", (unsigned) id[n]);
        cp += 2;
    }

    *cp = '\0';
    return 0;
}

static apr_status_t socache_mc_store(ap_socache_instance_t *ctx, server_rec *s, 
                                     const unsigned char *id, unsigned int idlen,
                                     apr_time_t expiry,
                                     unsigned char *ucaData, unsigned int nData,
                                     apr_pool_t *p)
{
    char buf[MC_KEY_LEN];
    apr_status_t rv;

    if (socache_mc_id2key(ctx, id, idlen, buf, sizeof buf)) {
        return APR_EINVAL;
    }

    /* In APR-util - unclear what 'timeout' is, as it was not implemented */
    rv = apr_memcache_set(ctx->mc, buf, (char*)ucaData, nData, 0, 0);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "scache_mc: error setting key '%s' "
                     "with %d bytes of data", buf, nData);
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t socache_mc_retrieve(ap_socache_instance_t *ctx, server_rec *s, 
                                        const unsigned char *id, unsigned int idlen,
                                        unsigned char *dest, unsigned int *destlen,
                                        apr_pool_t *p)
{
    apr_size_t data_len;
    char buf[MC_KEY_LEN], *data;
    apr_status_t rv;

    if (socache_mc_id2key(ctx, id, idlen, buf, sizeof buf)) {
        return APR_EINVAL;
    }

    /* ### this could do with a subpool, but _getp looks like it will
     * eat memory like it's going out of fashion anyway. */

    rv = apr_memcache_getp(ctx->mc, p, buf, &data, &data_len, NULL);
    if (rv) {
        if (rv != APR_NOTFOUND) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "scache_mc: 'retrieve' FAIL");
        }
        return rv;
    }
    else if (data_len > *destlen) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "scache_mc: 'retrieve' OVERFLOW");
        return APR_ENOMEM;
    }    

    memcpy(dest, data, data_len);
    *destlen = data_len;

    return APR_SUCCESS;
}

static apr_status_t socache_mc_remove(ap_socache_instance_t *ctx, server_rec *s, 
                                      const unsigned char *id, 
                                      unsigned int idlen, apr_pool_t *p)
{
    char buf[MC_KEY_LEN];
    apr_status_t rv;

    if (socache_mc_id2key(ctx, id, idlen, buf, sizeof buf)) {
        return APR_EINVAL;
    }

    rv = apr_memcache_delete(ctx->mc, buf, 0);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s,
                     "scache_mc: error deleting key '%s' ",
                     buf);
    }

    return rv;
}

static void socache_mc_status(ap_socache_instance_t *ctx, request_rec *r, int flags)
{
    /* TODO: Make a mod_status handler. meh. */
}

static apr_status_t socache_mc_iterate(ap_socache_instance_t *instance,
                                       server_rec *s,
                                       ap_socache_iterator_t *iterator,
                                       apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}

static const ap_socache_provider_t socache_mc = {
    "memcache",
    0,
    socache_mc_create,
    socache_mc_init,
    socache_mc_destroy,
    socache_mc_store,
    socache_mc_retrieve,
    socache_mc_remove,
    socache_mc_status,
    socache_mc_iterate
};

#endif /* HAVE_APU_MEMCACHE */

static void register_hooks(apr_pool_t *p)
{
#ifdef HAVE_APU_MEMCACHE
    ap_register_provider(p, AP_SOCACHE_PROVIDER_GROUP, "mc", 
                         AP_SOCACHE_PROVIDER_VERSION,
                         &socache_mc);
#endif
}

AP_DECLARE_MODULE(socache_memcache) = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, NULL, NULL, NULL,
    register_hooks
};
