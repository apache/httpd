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
#include "http_protocol.h"

#include "apr.h"

#include "ap_socache.h"
#include "ap_mpm.h"
#include "http_log.h"
#include "apr_memcache.h"
#include "apr_strings.h"
#include "mod_status.h"

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
#define MC_DEFAULT_SERVER_TTL    apr_time_from_sec(15)
#endif

module AP_MODULE_DECLARE_DATA socache_memcache_module;

typedef struct {
    apr_uint32_t ttl;
} socache_mc_svr_cfg;

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
    apr_uint16_t nservers = 0;
    char *cache_config;
    char *split;
    char *tok;

    socache_mc_svr_cfg *sconf = ap_get_module_config(s->module_config,
                                                     &socache_memcache_module);

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
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00785)
                     "Failed to create Memcache Object of '%d' size.",
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
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00786)
                         "Failed to Parse memcache Server: '%s'", split);
            return rv;
        }

        if (host_str == NULL) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00787)
                         "Failed to Parse Server, "
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
                                        sconf->ttl,
                                        &st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00788)
                         "Failed to Create memcache Server: %s:%d",
                         host_str, port);
            return rv;
        }

        rv = apr_memcache_add_server(ctx->mc, st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00789)
                         "Failed to Add memcache Server: %s:%d",
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

    if (idlen * 2 + ctx->taglen >= keylen)
        return 1;

    cp = apr_cpystrn(key, ctx->tag, ctx->taglen);
    ap_bin2hex(id, idlen, cp);

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

    /* memcache needs time in seconds till expiry; fail if this is not
     * positive *before* casting to unsigned (apr_uint32_t). */
    expiry -= apr_time_now();
    if (apr_time_sec(expiry) <= 0) {
        return APR_EINVAL;
    }
    rv = apr_memcache_set(ctx->mc, buf, (char*)ucaData, nData,
                          apr_time_sec(expiry), 0);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00790)
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
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00791)
                         "scache_mc: 'retrieve' FAIL");
        }
        return rv;
    }
    else if (data_len > *destlen) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00792)
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(00793)
                     "scache_mc: error deleting key '%s' ",
                     buf);
    }

    return rv;
}

static void socache_mc_status(ap_socache_instance_t *ctx, request_rec *r, int flags)
{
    apr_memcache_t *rc = ctx->mc;
    int i;

    for (i = 0; i < rc->ntotal; i++) {
        apr_memcache_server_t *ms;
        apr_memcache_stats_t *stats;
        apr_status_t rv;
        char *br = (!(flags & AP_STATUS_SHORT) ? "<br />" : "");

        ms = rc->live_servers[i];

        ap_rprintf(r, "Memcached server: %s:%d [%s]%s\n", ms->host, (int)ms->port,
                (ms->status == APR_MC_SERVER_LIVE) ? "Up" : "Down",
                br);
        rv = apr_memcache_stats(ms, r->pool, &stats);
        if (rv != APR_SUCCESS)
            continue;
        if (!(flags & AP_STATUS_SHORT)) {
            ap_rprintf(r, "<b>Version:</b> <i>%s</i> [%u bits], PID: <i>%u</i>, Uptime: <i>%u hrs</i> <br />\n",
                    stats->version , stats->pointer_size, stats->pid, stats->uptime/3600);
            ap_rprintf(r, "<b>Clients::</b> Structures: <i>%u</i>, Total: <i>%u</i>, Current: <i>%u</i> <br />\n",
                    stats->connection_structures, stats->total_connections, stats->curr_connections);
            ap_rprintf(r, "<b>Storage::</b> Total Items: <i>%u</i>, Current Items: <i>%u</i>, Bytes: <i>%" APR_UINT64_T_FMT "</i> <br />\n",
                    stats->total_items, stats->curr_items, stats->bytes);
            ap_rprintf(r, "<b>CPU::</b> System: <i>%u</i>, User: <i>%u</i> <br />\n",
                    (unsigned)stats->rusage_system, (unsigned)stats->rusage_user );
            ap_rprintf(r, "<b>Cache::</b> Gets: <i>%u</i>, Sets: <i>%u</i>, Hits: <i>%u</i>, Misses: <i>%u</i> <br />\n",
                    stats->cmd_get, stats->cmd_set, stats->get_hits, stats->get_misses);
            ap_rprintf(r, "<b>Net::</b> Input bytes: <i>%" APR_UINT64_T_FMT "</i>, Output bytes: <i>%" APR_UINT64_T_FMT "</i> <br />\n",
                    stats->bytes_read, stats->bytes_written);
            ap_rprintf(r, "<b>Misc::</b> Evictions: <i>%" APR_UINT64_T_FMT "</i>, MaxMem: <i>%u</i>, Threads: <i>%u</i> <br />\n",
                    stats->evictions, stats->limit_maxbytes, stats->threads);
            ap_rputs("<hr><br />\n", r);
        }
        else {
            ap_rprintf(r, "Version: %s [%u bits], PID: %u, Uptime: %u hrs %s\n",
                    stats->version , stats->pointer_size, stats->pid, stats->uptime/3600, br);
            ap_rprintf(r, "Clients:: Structures: %d, Total: %d, Current: %u %s\n",
                    stats->connection_structures, stats->total_connections, stats->curr_connections, br);
            ap_rprintf(r, "Storage:: Total Items: %u, Current Items: %u, Bytes: %" APR_UINT64_T_FMT " %s\n",
                    stats->total_items, stats->curr_items, stats->bytes, br);
            ap_rprintf(r, "CPU:: System: %u, User: %u %s\n",
                    (unsigned)stats->rusage_system, (unsigned)stats->rusage_user , br);
            ap_rprintf(r, "Cache:: Gets: %u, Sets: %u, Hits: %u, Misses: %u %s\n",
                    stats->cmd_get, stats->cmd_set, stats->get_hits, stats->get_misses, br);
            ap_rprintf(r, "Net:: Input bytes: %" APR_UINT64_T_FMT ", Output bytes: %" APR_UINT64_T_FMT " %s\n",
                    stats->bytes_read, stats->bytes_written, br);
            ap_rprintf(r, "Misc:: Evictions: %" APR_UINT64_T_FMT ", MaxMem: %u, Threads: %u %s\n",
                    stats->evictions, stats->limit_maxbytes, stats->threads, br);
        }
    }

}

static apr_status_t socache_mc_iterate(ap_socache_instance_t *instance,
                                       server_rec *s, void *userctx,
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

static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    socache_mc_svr_cfg *sconf = apr_pcalloc(p, sizeof(socache_mc_svr_cfg));
    
    sconf->ttl = MC_DEFAULT_SERVER_TTL;

    return sconf;
}

static const char *socache_mc_set_ttl(cmd_parms *cmd, void *dummy,
                                      const char *arg)
{
    apr_interval_time_t ttl;
    socache_mc_svr_cfg *sconf = ap_get_module_config(cmd->server->module_config,
                                                     &socache_memcache_module);

    if (ap_timeout_parameter_parse(arg, &ttl, "s") != APR_SUCCESS) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " has wrong format", NULL);
    }

    if ((ttl < apr_time_from_sec(0)) || (ttl > apr_time_from_sec(3600))) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " can only be 0 or up to one hour.", NULL);
    }

    /* apr_memcache_server_create needs a ttl in usec. */
    sconf->ttl = ttl;

    return NULL;
}

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AP_SOCACHE_PROVIDER_GROUP, "memcache",
                         AP_SOCACHE_PROVIDER_VERSION,
                         &socache_mc);
}

static const command_rec socache_memcache_cmds[] = {
    AP_INIT_TAKE1("MemcacheConnTTL", socache_mc_set_ttl, NULL, RSRC_CONF,
                  "TTL used for the connection with the memcache server(s)"),
    { NULL }
};

AP_DECLARE_MODULE(socache_memcache) = {
    STANDARD20_MODULE_STUFF,
    NULL,                     /* create per-dir    config structures */
    NULL,                     /* merge  per-dir    config structures */
    create_server_config,     /* create per-server config structures */
    NULL,                     /* merge  per-server config structures */
    socache_memcache_cmds,    /* table of config file commands       */
    register_hooks            /* register hooks                      */
};
