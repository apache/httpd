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

#include "mod_proxy.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "apr_version.h"
#include "apr_hooks.h"

#ifndef LBM_HEARTBEAT_MAX_LASTSEEN
/* If we haven't seen a heartbeat in the last N seconds, don't count this IP
 * as allive.
 */
#define LBM_HEARTBEAT_MAX_LASTSEEN (10)
#endif

module AP_MODULE_DECLARE_DATA lbmethod_heartbeat_module;

typedef struct lb_hb_ctx_t
{
    const char *path;
} lb_hb_ctx_t;

typedef struct hb_server_t {
    const char *ip;
    int busy;
    int ready;
    int seen;
    proxy_worker *worker;
} hb_server_t;

static void
argstr_to_table(apr_pool_t *p, char *str, apr_table_t *parms)
{
    char *key;
    char *value;
    char *strtok_state;
    
    key = apr_strtok(str, "&", &strtok_state);
    while (key) {
        value = strchr(key, '=');
        if (value) {
            *value = '\0';      /* Split the string in two */
            value++;            /* Skip passed the = */
        }
        else {
            value = "1";
        }
        ap_unescape_url(key);
        ap_unescape_url(value);
        apr_table_set(parms, key, value);
        /*
         ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
         "Found query arg: %s = %s", key, value);
         */
        key = apr_strtok(NULL, "&", &strtok_state);
    }
}

static apr_status_t read_heartbeats(const char *path, apr_hash_t *servers,
                                    apr_pool_t *pool)
{
    apr_finfo_t fi;
    apr_status_t rv;
    apr_file_t *fp;

    if (!path) {
        return APR_SUCCESS;
    }

    rv = apr_file_open(&fp, path, APR_READ|APR_BINARY|APR_BUFFERED,
                       APR_OS_DEFAULT, pool);

    if (rv) {
        return rv;
    }

    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, fp);

    if (rv) {
        return rv;
    }

    {
        char *t;
        int lineno = 0;
        apr_bucket_alloc_t *ba = apr_bucket_alloc_create(pool);
        apr_bucket_brigade *bb = apr_brigade_create(pool, ba);
        apr_bucket_brigade *tmpbb = apr_brigade_create(pool, ba);
        apr_table_t *hbt = apr_table_make(pool, 10);

        apr_brigade_insert_file(bb, fp, 0, fi.size, pool);

        do {
            hb_server_t *server;
            char buf[4096];
            apr_size_t bsize = sizeof(buf);
            const char *ip;

            apr_brigade_cleanup(tmpbb);

            if (APR_BRIGADE_EMPTY(bb)) {
                break;
            }

            rv = apr_brigade_split_line(tmpbb, bb,
                                        APR_BLOCK_READ, sizeof(buf));
            lineno++;

            if (rv) {
                return rv;
            }

            apr_brigade_flatten(tmpbb, buf, &bsize);

            if (bsize == 0) {
                break;
            }

            buf[bsize - 1] = 0;

            /* comment */
            if (buf[0] == '#') {
                continue;
            }

            /* line format: <IP> <query_string>\n */
            t = strchr(buf, ' ');
            if (!t) {
                continue;
            }
            
            ip = apr_pstrndup(pool, buf, t - buf);
            t++;

            server = apr_hash_get(servers, ip, APR_HASH_KEY_STRING);
            
            if (server == NULL) {
                server = apr_pcalloc(pool, sizeof(hb_server_t));
                server->ip = ip;
                server->seen = -1;

                apr_hash_set(servers, server->ip, APR_HASH_KEY_STRING, server);
            }
            
            apr_table_clear(hbt);

            argstr_to_table(pool, apr_pstrdup(pool, t), hbt);

            if (apr_table_get(hbt, "busy")) {
                server->busy = atoi(apr_table_get(hbt, "busy"));
            }

            if (apr_table_get(hbt, "ready")) {
                server->ready = atoi(apr_table_get(hbt, "ready"));
            }

            if (apr_table_get(hbt, "lastseen")) {
                server->seen = atoi(apr_table_get(hbt, "lastseen"));
            }

            if (server->busy == 0 && server->ready != 0) {
                /* Server has zero threads active, but lots of them ready, 
                 * it likely just started up, so lets /4 the number ready, 
                 * to prevent us from completely flooding it with all new 
                 * requests.
                 */
                server->ready = server->ready / 4;
            }

        } while (1);
    }

    return APR_SUCCESS;
}

/*
 * Finding a random number in a range. 
 *      n' = a + n(b-a+1)/(M+1)
 * where:
 *      n' = random number in range
 *      a  = low end of range
 *      b  = high end of range
 *      n  = random number of 0..M
 *      M  = maxint
 * Algorithm 'borrowed' from PHP's rand() function.
 */
#define RAND_RANGE(__n, __min, __max, __tmax) \
(__n) = (__min) + (long) ((double) ((__max) - (__min) + 1.0) * ((__n) / ((__tmax) + 1.0)))

static apr_status_t random_pick(apr_uint32_t *number,
                                apr_uint32_t min,
                                apr_uint32_t max)
{
    apr_status_t rv = 
        apr_generate_random_bytes((void*)number, sizeof(apr_uint32_t));

    if (rv) {
        return rv;
    }

    RAND_RANGE(*number, min, max, APR_UINT32_MAX);

    return APR_SUCCESS;
}

static proxy_worker *find_best_hb(proxy_balancer *balancer,
                                  request_rec *r)
{
    apr_status_t rv;
    int i;
    apr_uint32_t openslots = 0;
    proxy_worker **worker;
    hb_server_t *server;
    apr_array_header_t *up_servers;
    proxy_worker *mycandidate = NULL;
    apr_pool_t *tpool;
    apr_hash_t *servers;

    lb_hb_ctx_t *ctx = 
        ap_get_module_config(r->server->module_config,
                             &lbmethod_heartbeat_module);

    apr_pool_create(&tpool, r->pool);

    servers = apr_hash_make(tpool);

    rv = read_heartbeats(ctx->path, servers, tpool);

    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "lb_heartbeat: Unable to read heartbeats at '%s'",
                      ctx->path);
        apr_pool_destroy(tpool);
        return NULL;
    }

    up_servers = apr_array_make(tpool, apr_hash_count(servers), sizeof(hb_server_t *));

    for (i = 0; i < balancer->workers->nelts; i++) {
        worker = &APR_ARRAY_IDX(balancer->workers, i, proxy_worker *);
        server = apr_hash_get(servers, (*worker)->hostname, APR_HASH_KEY_STRING);

        if (!server) {
            continue;
        }

        if (!PROXY_WORKER_IS_USABLE(*worker)) {
            ap_proxy_retry_worker("BALANCER", *worker, r->server);
        }

        if (PROXY_WORKER_IS_USABLE(*worker)) {
            server->worker = *worker;
            if (server->seen < LBM_HEARTBEAT_MAX_LASTSEEN) {
                openslots += server->ready;
                APR_ARRAY_PUSH(up_servers, hb_server_t *) = server;
            }
        }
    }

    if (openslots > 0) {
        apr_uint32_t c = 0;
        apr_uint32_t pick = 0;;

        rv = random_pick(&pick, 0, openslots);

        if (rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "lb_heartbeat: failed picking a random number. how random.");
            apr_pool_destroy(tpool);
            return NULL;
        }

        for (i = 0; i < up_servers->nelts; i++) {
            server = APR_ARRAY_IDX(up_servers, i, hb_server_t *);
            if (pick > c && pick <= c + server->ready) {
                mycandidate = server->worker;
            }

            c += server->ready;
        }
    }

    apr_pool_destroy(tpool);

    return mycandidate;
}

static apr_status_t reset(proxy_balancer *balancer, server_rec *r) {
        return APR_SUCCESS;
}

static apr_status_t age(proxy_balancer *balancer, server_rec *r) {
        return APR_SUCCESS;
}

static const proxy_balancer_method heartbeat =
{
    "heartbeat",
    &find_best_hb,
    NULL,
    &reset,
    &age
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, PROXY_LBMETHOD, "heartbeat", "0", &heartbeat);
}

static void *lb_hb_create_config(apr_pool_t *p, server_rec *s)
{
    lb_hb_ctx_t *ctx = (lb_hb_ctx_t *) apr_palloc(p, sizeof(lb_hb_ctx_t));
    
    ctx->path = ap_server_root_relative(p, "logs/hb.dat");
    
    return ctx;
}

static void *lb_hb_merge_config(apr_pool_t *p, void *basev, void *overridesv)
{
    lb_hb_ctx_t *ps = apr_pcalloc(p, sizeof(lb_hb_ctx_t));
    lb_hb_ctx_t *base = (lb_hb_ctx_t *) basev;
    lb_hb_ctx_t *overrides = (lb_hb_ctx_t *) overridesv;

    if (overrides->path) {
        ps->path = apr_pstrdup(p, overrides->path);
    }
    else {
        ps->path = apr_pstrdup(p, base->path);
    }

    return ps;
}

static const char *cmd_lb_hb_storage(cmd_parms *cmd,
                                  void *dconf, const char *path)
{
    apr_pool_t *p = cmd->pool;
    lb_hb_ctx_t *ctx =
    (lb_hb_ctx_t *) ap_get_module_config(cmd->server->module_config,
                                         &lbmethod_heartbeat_module);

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    
    if (err != NULL) {
        return err;
    }

    ctx->path = ap_server_root_relative(p, path);

    return NULL;
}

static const command_rec cmds[] = {
    AP_INIT_TAKE1("HeartbeatStorage", cmd_lb_hb_storage, NULL, RSRC_CONF,
                  "Path to read heartbeat data."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA lbmethod_heartbeat_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    lb_hb_create_config,        /* create per-server config structure */
    lb_hb_merge_config,         /* merge per-server config structures */
    cmds,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
