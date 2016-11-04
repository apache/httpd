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

/* apr_redis support requires >= 1.6 */
#if APU_MAJOR_VERSION > 1 || \
    (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION > 5)
#define HAVE_APU_REDIS 1
#endif

#ifdef HAVE_APU_REDIS

#include "ap_socache.h"
#include "ap_mpm.h"
#include "http_log.h"
#include "apr_redis.h"

/* The underlying apr_redis system is thread safe.. */
#define RD_KEY_LEN 254

#ifndef RD_DEFAULT_SERVER_PORT
#define RD_DEFAULT_SERVER_PORT 6379
#endif


#ifndef RD_DEFAULT_SERVER_MIN
#define RD_DEFAULT_SERVER_MIN 0
#endif

#ifndef RD_DEFAULT_SERVER_SMAX
#define RD_DEFAULT_SERVER_SMAX 1
#endif

#ifndef RD_DEFAULT_SERVER_TTL
#define RD_DEFAULT_SERVER_TTL    apr_time_from_sec(15)
#endif

#ifndef RD_DEFAULT_SERVER_RWTO
#define RD_DEFAULT_SERVER_RWTO    apr_time_from_sec(5)
#endif

module AP_MODULE_DECLARE_DATA socache_redis_module;

typedef struct {
    apr_uint32_t ttl;
    apr_uint32_t rwto;
} socache_rd_svr_cfg;

struct ap_socache_instance_t {
    const char *servers;
    apr_redis_t *rc;
    const char *tag;
    apr_size_t taglen; /* strlen(tag) + 1 */
};

static const char *socache_rd_create(ap_socache_instance_t **context,
                                     const char *arg,
                                     apr_pool_t *tmp, apr_pool_t *p)
{
    ap_socache_instance_t *ctx;

    *context = ctx = apr_palloc(p, sizeof *ctx);

    if (!arg || !*arg) {
        return "List of server names required to create redis socache.";
    }

    ctx->servers = apr_pstrdup(p, arg);

    return NULL;
}

static apr_status_t socache_rd_init(ap_socache_instance_t *ctx,
                                    const char *namespace,
                                    const struct ap_socache_hints *hints,
                                    server_rec *s, apr_pool_t *p)
{
    apr_status_t rv;
    int thread_limit = 0;
    apr_uint16_t nservers = 0;
    char *cache_config;
    char *split;
    char *tok;

    socache_rd_svr_cfg *sconf = ap_get_module_config(s->module_config, &socache_redis_module);

    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);

    /* Find all the servers in the first run to get a total count */
    cache_config = apr_pstrdup(p, ctx->servers);
    split = apr_strtok(cache_config, ",", &tok);
    while (split) {
        nservers++;
        split = apr_strtok(NULL,",", &tok);
    }

    rv = apr_redis_create(p, nservers, 0, &ctx->rc);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                     "Failed to create Redis Object of '%d' size.",
                     nservers);
        return rv;
    }

    /* Now add each server to the redis */
    cache_config = apr_pstrdup(p, ctx->servers);
    split = apr_strtok(cache_config, ",", &tok);
    while (split) {
        apr_redis_server_t *st;
        char *host_str;
        char *scope_id;
        apr_port_t port;

        rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                         "Failed to Parse redis Server: '%s'", split);
            return rv;
        }

        if (host_str == NULL) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                         "Failed to Parse Server, "
                         "no hostname specified: '%s'", split);
            return APR_EINVAL;
        }

        if (port == 0) {
            port = RD_DEFAULT_SERVER_PORT;
        }

        rv = apr_redis_server_create(p,
                                     host_str, port,
                                     RD_DEFAULT_SERVER_MIN,
                                     RD_DEFAULT_SERVER_SMAX,
                                     thread_limit,
                                     sconf->ttl,
                                     sconf->rwto,
                                     &st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                         "Failed to Create redis Server: %s:%d",
                         host_str, port);
            return rv;
        }

        rv = apr_redis_add_server(ctx->rc, st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                         "Failed to Add redis Server: %s:%d",
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

static void socache_rd_destroy(ap_socache_instance_t *context, server_rec *s)
{
    /* noop. */
}

/* Converts (binary) id into a key prefixed by the predetermined
 * namespace tag; writes output to key buffer.  Returns non-zero if
 * the id won't fit in the key buffer. */
static int socache_rd_id2key(ap_socache_instance_t *ctx,
                             const unsigned char *id, unsigned int idlen,
                             char *key, apr_size_t keylen)
{
    char *cp;

    if (idlen * 2 + ctx->taglen >= keylen)
        return 1;

    cp = apr_cpystrn(key, ctx->tag, ctx->taglen);
    ap_bin2hex(id, idlen, cp);

    return 0;
}

static apr_status_t socache_rd_store(ap_socache_instance_t *ctx, server_rec *s,
                                     const unsigned char *id, unsigned int idlen,
                                     apr_time_t expiry,
                                     unsigned char *ucaData, unsigned int nData,
                                     apr_pool_t *p)
{
    char buf[RD_KEY_LEN];
    apr_status_t rv;
    apr_uint32_t timeout;

    if (socache_rd_id2key(ctx, id, idlen, buf, sizeof(buf))) {
        return APR_EINVAL;
    }
    timeout = apr_time_sec(expiry - apr_time_now());
    if (timeout <= 0) {
        return APR_EINVAL;
    }

    rv = apr_redis_setex(ctx->rc, buf, (char*)ucaData, nData, timeout, 0);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                     "scache_rd: error setting key '%s' "
                     "with %d bytes of data", buf, nData);
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t socache_rd_retrieve(ap_socache_instance_t *ctx, server_rec *s,
                                        const unsigned char *id, unsigned int idlen,
                                        unsigned char *dest, unsigned int *destlen,
                                        apr_pool_t *p)
{
    apr_size_t data_len;
    char buf[RD_KEY_LEN], *data;
    apr_status_t rv;

    if (socache_rd_id2key(ctx, id, idlen, buf, sizeof buf)) {
        return APR_EINVAL;
    }

    /* ### this could do with a subpool, but _getp looks like it will
     * eat memory like it's going out of fashion anyway. */

    rv = apr_redis_getp(ctx->rc, p, buf, &data, &data_len, NULL);
    if (rv) {
        if (rv != APR_NOTFOUND) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                         "scache_rd: 'retrieve' FAIL");
        }
        return rv;
    }
    else if (data_len > *destlen) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                     "scache_rd: 'retrieve' OVERFLOW");
        return APR_ENOMEM;
    }

    memcpy(dest, data, data_len);
    *destlen = data_len;

    return APR_SUCCESS;
}

static apr_status_t socache_rd_remove(ap_socache_instance_t *ctx, server_rec *s,
                                      const unsigned char *id,
                                      unsigned int idlen, apr_pool_t *p)
{
    char buf[RD_KEY_LEN];
    apr_status_t rv;

    if (socache_rd_id2key(ctx, id, idlen, buf, sizeof buf)) {
        return APR_EINVAL;
    }

    rv = apr_redis_delete(ctx->rc, buf, 0);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO()
                     "scache_rd: error deleting key '%s' ",
                     buf);
    }

    return rv;
}

static void socache_rd_status(ap_socache_instance_t *ctx, request_rec *r, int flags)
{
    /* TODO: Make a mod_status handler. meh. */
}

static apr_status_t socache_rd_iterate(ap_socache_instance_t *instance,
                                       server_rec *s, void *userctx,
                                       ap_socache_iterator_t *iterator,
                                       apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}

static const ap_socache_provider_t socache_mc = {
    "redis",
    0,
    socache_rd_create,
    socache_rd_init,
    socache_rd_destroy,
    socache_rd_store,
    socache_rd_retrieve,
    socache_rd_remove,
    socache_rd_status,
    socache_rd_iterate,
};

#endif /* HAVE_APU_REDIS */

static void* create_server_config(apr_pool_t* p, server_rec* s)
{
    socache_rd_svr_cfg *sconf = apr_palloc(p, sizeof(socache_rd_svr_cfg));

    sconf->ttl = RD_DEFAULT_SERVER_TTL;
    sconf->rwto = RD_DEFAULT_SERVER_RWTO;

    return sconf;
}

static const char *socache_rd_set_ttl(cmd_parms *cmd, void *dummy,
                                      const char *arg)
{
    apr_interval_time_t ttl;
    socache_rd_svr_cfg *sconf = ap_get_module_config(cmd->server->module_config,
                                                     &socache_redis_module);

    if (ap_timeout_parameter_parse(arg, &ttl, "s") != APR_SUCCESS) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " has wrong format", NULL);
    }

    if ((ttl < apr_time_from_sec(0)) || (ttl > apr_time_from_sec(3600))) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " can only be 0 or up to one hour.", NULL);
    }

    /* apr_redis_server_create needs a ttl in usec. */
    sconf->ttl = ttl;

    return NULL;
}

static const char *socache_rd_set_rwto(cmd_parms *cmd, void *dummy,
                                      const char *arg)
{
    apr_interval_time_t rwto;
    socache_rd_svr_cfg *sconf = ap_get_module_config(cmd->server->module_config,
                                                     &socache_redis_module);

    if (ap_timeout_parameter_parse(arg, &rwto, "s") != APR_SUCCESS) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " has wrong format", NULL);
    }

    if ((rwto < apr_time_from_sec(0)) || (rwto > apr_time_from_sec(3600))) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " can only be 0 or up to one hour.", NULL);
    }

    /* apr_redis_server_create needs a ttl in usec. */
    sconf->rwto = rwto;

    return NULL;
}

static void register_hooks(apr_pool_t *p)
{
#ifdef HAVE_APU_REDIS

    ap_register_provider(p, AP_SOCACHE_PROVIDER_GROUP, "redis",
                         AP_SOCACHE_PROVIDER_VERSION,
                         &socache_mc);
#endif
}

static const command_rec socache_redis_cmds[] =
{
    AP_INIT_TAKE1("RedisConnPoolTTL", socache_rd_set_ttl, NULL, RSRC_CONF,
                      "TTL used for the connection pool with the Redis server(s)"),
    AP_INIT_TAKE1("RedisTimeout", socache_rd_set_rwto, NULL, RSRC_CONF,
                  "R/W timeout used for the connection with the Redis server(s)"),
    {NULL}
};

AP_DECLARE_MODULE(socache_redis) = {
    STANDARD20_MODULE_STUFF, 
    NULL,                        /* create per-dir    config structures */
    NULL,                        /* merge  per-dir    config structures */
    create_server_config,        /* create per-server config structures */
    NULL,                        /* merge  per-server config structures */
    socache_redis_cmds,          /* table of config file commands       */
    register_hooks               /* register hooks                      */
};

