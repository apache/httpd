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
 
#include <assert.h>

#include <apr_hash.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_vhost.h>

#include <ap_mpm.h>

#include <apr_strings.h>

#include "h2.h"
#include "h2_conn_ctx.h"
#include "h2_c1.h"
#include "h2_config.h"
#include "h2_protocol.h"
#include "h2_private.h"

#define DEF_VAL     (-1)

#define H2_CONFIG_GET(a, b, n) \
    (((a)->n == DEF_VAL)? (b) : (a))->n

#define H2_CONFIG_SET(a, n, v) \
    ((a)->n = v)

#define CONFIG_CMD_SET(cmd,dir,var,val) \
    h2_config_seti(((cmd)->path? (dir) : NULL), h2_config_sget((cmd)->server), var, val)

#define CONFIG_CMD_SET64(cmd,dir,var,val) \
    h2_config_seti64(((cmd)->path? (dir) : NULL), h2_config_sget((cmd)->server), var, val)

/* Apache httpd module configuration for h2. */
typedef struct h2_config {
    const char *name;
    int h2_max_streams;              /* max concurrent # streams (http2) */
    int h2_window_size;              /* stream window size (http2) */
    int min_workers;                 /* min # of worker threads/child */
    int max_workers;                 /* max # of worker threads/child */
    apr_interval_time_t idle_limit;  /* max duration for idle workers */
    int stream_max_mem_size;         /* max # bytes held in memory/stream */
    int h2_direct;                   /* if mod_h2 is active directly */
    int modern_tls_only;             /* Accept only modern TLS in HTTP/2 connections */  
    int h2_upgrade;                  /* Allow HTTP/1 upgrade to h2/h2c */
    apr_int64_t tls_warmup_size;     /* Amount of TLS data to send before going full write size */
    int tls_cooldown_secs;           /* Seconds of idle time before going back to small TLS records */
    int h2_push;                     /* if HTTP/2 server push is enabled */
    struct apr_hash_t *priorities;   /* map of content-type to h2_priority records */
    
    int push_diary_size;             /* # of entries in push diary */
    int copy_files;                  /* if files shall be copied vs setaside on output */
    apr_array_header_t *push_list;   /* list of h2_push_res configurations */
    int early_hints;                 /* support status code 103 */
    int padding_bits;
    int padding_always;
    int output_buffered;
    apr_interval_time_t stream_timeout;/* beam timeout */
} h2_config;

typedef struct h2_dir_config {
    const char *name;
    int h2_upgrade;                  /* Allow HTTP/1 upgrade to h2/h2c */
    int h2_push;                     /* if HTTP/2 server push is enabled */
    apr_array_header_t *push_list;   /* list of h2_push_res configurations */
    int early_hints;                 /* support status code 103 */
    apr_interval_time_t stream_timeout;/* beam timeout */
} h2_dir_config;


static h2_config defconf = {
    "default",
    100,                    /* max_streams */
    H2_INITIAL_WINDOW_SIZE, /* window_size */
    -1,                     /* min workers */
    -1,                     /* max workers */
    apr_time_from_sec(10 * 60), /* workers idle limit */
    32 * 1024,              /* stream max mem size */
    -1,                     /* h2 direct mode */
    1,                      /* modern TLS only */
    -1,                     /* HTTP/1 Upgrade support */
    1024*1024,              /* TLS warmup size */
    1,                      /* TLS cooldown secs */
    1,                      /* HTTP/2 server push enabled */
    NULL,                   /* map of content-type to priorities */
    256,                    /* push diary size */
    0,                      /* copy files across threads */
    NULL,                   /* push list */
    0,                      /* early hints, http status 103 */
    0,                      /* padding bits */
    1,                      /* padding always */
    1,                      /* stream output buffered */
    -1,                     /* beam timeout */
};

static h2_dir_config defdconf = {
    "default",
    -1,                     /* HTTP/1 Upgrade support */
    -1,                     /* HTTP/2 server push enabled */
    NULL,                   /* push list */
    -1,                     /* early hints, http status 103 */
    -1,                     /* beam timeout */
};

void h2_config_init(apr_pool_t *pool)
{
    (void)pool;
}

void *h2_config_create_svr(apr_pool_t *pool, server_rec *s)
{
    h2_config *conf = (h2_config *)apr_pcalloc(pool, sizeof(h2_config));
    char *name = apr_pstrcat(pool, "srv[", s->defn_name, "]", NULL);
    
    conf->name                 = name;
    conf->h2_max_streams       = DEF_VAL;
    conf->h2_window_size       = DEF_VAL;
    conf->min_workers          = DEF_VAL;
    conf->max_workers          = DEF_VAL;
    conf->idle_limit           = DEF_VAL;
    conf->stream_max_mem_size  = DEF_VAL;
    conf->h2_direct            = DEF_VAL;
    conf->modern_tls_only      = DEF_VAL;
    conf->h2_upgrade           = DEF_VAL;
    conf->tls_warmup_size      = DEF_VAL;
    conf->tls_cooldown_secs    = DEF_VAL;
    conf->h2_push              = DEF_VAL;
    conf->priorities           = NULL;
    conf->push_diary_size      = DEF_VAL;
    conf->copy_files           = DEF_VAL;
    conf->push_list            = NULL;
    conf->early_hints          = DEF_VAL;
    conf->padding_bits         = DEF_VAL;
    conf->padding_always       = DEF_VAL;
    conf->output_buffered      = DEF_VAL;
    conf->stream_timeout       = DEF_VAL;
    return conf;
}

static void *h2_config_merge(apr_pool_t *pool, void *basev, void *addv)
{
    h2_config *base = (h2_config *)basev;
    h2_config *add = (h2_config *)addv;
    h2_config *n = (h2_config *)apr_pcalloc(pool, sizeof(h2_config));
    char *name = apr_pstrcat(pool, "merged[", add->name, ", ", base->name, "]", NULL);
    n->name = name;

    n->h2_max_streams       = H2_CONFIG_GET(add, base, h2_max_streams);
    n->h2_window_size       = H2_CONFIG_GET(add, base, h2_window_size);
    n->min_workers          = H2_CONFIG_GET(add, base, min_workers);
    n->max_workers          = H2_CONFIG_GET(add, base, max_workers);
    n->idle_limit           = H2_CONFIG_GET(add, base, idle_limit);
    n->stream_max_mem_size  = H2_CONFIG_GET(add, base, stream_max_mem_size);
    n->h2_direct            = H2_CONFIG_GET(add, base, h2_direct);
    n->modern_tls_only      = H2_CONFIG_GET(add, base, modern_tls_only);
    n->h2_upgrade           = H2_CONFIG_GET(add, base, h2_upgrade);
    n->tls_warmup_size      = H2_CONFIG_GET(add, base, tls_warmup_size);
    n->tls_cooldown_secs    = H2_CONFIG_GET(add, base, tls_cooldown_secs);
    n->h2_push              = H2_CONFIG_GET(add, base, h2_push);
    if (add->priorities && base->priorities) {
        n->priorities       = apr_hash_overlay(pool, add->priorities, base->priorities);
    }
    else {
        n->priorities       = add->priorities? add->priorities : base->priorities;
    }
    n->push_diary_size      = H2_CONFIG_GET(add, base, push_diary_size);
    n->copy_files           = H2_CONFIG_GET(add, base, copy_files);
    n->output_buffered      = H2_CONFIG_GET(add, base, output_buffered);
    if (add->push_list && base->push_list) {
        n->push_list        = apr_array_append(pool, base->push_list, add->push_list);
    }
    else {
        n->push_list        = add->push_list? add->push_list : base->push_list;
    }
    n->early_hints          = H2_CONFIG_GET(add, base, early_hints);
    n->padding_bits         = H2_CONFIG_GET(add, base, padding_bits);
    n->padding_always       = H2_CONFIG_GET(add, base, padding_always);
    n->stream_timeout       = H2_CONFIG_GET(add, base, stream_timeout);
    return n;
}

void *h2_config_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    return h2_config_merge(pool, basev, addv);
}

void *h2_config_create_dir(apr_pool_t *pool, char *x)
{
    h2_dir_config *conf = (h2_dir_config *)apr_pcalloc(pool, sizeof(h2_dir_config));
    const char *s = x? x : "unknown";
    char *name = apr_pstrcat(pool, "dir[", s, "]", NULL);
    
    conf->name                 = name;
    conf->h2_upgrade           = DEF_VAL;
    conf->h2_push              = DEF_VAL;
    conf->early_hints          = DEF_VAL;
    conf->stream_timeout         = DEF_VAL;
    return conf;
}

void *h2_config_merge_dir(apr_pool_t *pool, void *basev, void *addv)
{
    h2_dir_config *base = (h2_dir_config *)basev;
    h2_dir_config *add = (h2_dir_config *)addv;
    h2_dir_config *n = (h2_dir_config *)apr_pcalloc(pool, sizeof(h2_dir_config));

    n->name = apr_pstrcat(pool, "merged[", add->name, ", ", base->name, "]", NULL);
    n->h2_upgrade           = H2_CONFIG_GET(add, base, h2_upgrade);
    n->h2_push              = H2_CONFIG_GET(add, base, h2_push);
    if (add->push_list && base->push_list) {
        n->push_list        = apr_array_append(pool, base->push_list, add->push_list);
    }
    else {
        n->push_list        = add->push_list? add->push_list : base->push_list;
    }
    n->early_hints          = H2_CONFIG_GET(add, base, early_hints);
    n->stream_timeout         = H2_CONFIG_GET(add, base, stream_timeout);
    return n;
}

static apr_int64_t h2_srv_config_geti64(const h2_config *conf, h2_config_var_t var)
{
    switch(var) {
        case H2_CONF_MAX_STREAMS:
            return H2_CONFIG_GET(conf, &defconf, h2_max_streams);
        case H2_CONF_WIN_SIZE:
            return H2_CONFIG_GET(conf, &defconf, h2_window_size);
        case H2_CONF_MIN_WORKERS:
            return H2_CONFIG_GET(conf, &defconf, min_workers);
        case H2_CONF_MAX_WORKERS:
            return H2_CONFIG_GET(conf, &defconf, max_workers);
        case H2_CONF_MAX_WORKER_IDLE_LIMIT:
            return H2_CONFIG_GET(conf, &defconf, idle_limit);
        case H2_CONF_STREAM_MAX_MEM:
            return H2_CONFIG_GET(conf, &defconf, stream_max_mem_size);
        case H2_CONF_MODERN_TLS_ONLY:
            return H2_CONFIG_GET(conf, &defconf, modern_tls_only);
        case H2_CONF_UPGRADE:
            return H2_CONFIG_GET(conf, &defconf, h2_upgrade);
        case H2_CONF_DIRECT:
            return H2_CONFIG_GET(conf, &defconf, h2_direct);
        case H2_CONF_TLS_WARMUP_SIZE:
            return H2_CONFIG_GET(conf, &defconf, tls_warmup_size);
        case H2_CONF_TLS_COOLDOWN_SECS:
            return H2_CONFIG_GET(conf, &defconf, tls_cooldown_secs);
        case H2_CONF_PUSH:
            return H2_CONFIG_GET(conf, &defconf, h2_push);
        case H2_CONF_PUSH_DIARY_SIZE:
            return H2_CONFIG_GET(conf, &defconf, push_diary_size);
        case H2_CONF_COPY_FILES:
            return H2_CONFIG_GET(conf, &defconf, copy_files);
        case H2_CONF_EARLY_HINTS:
            return H2_CONFIG_GET(conf, &defconf, early_hints);
        case H2_CONF_PADDING_BITS:
            return H2_CONFIG_GET(conf, &defconf, padding_bits);
        case H2_CONF_PADDING_ALWAYS:
            return H2_CONFIG_GET(conf, &defconf, padding_always);
        case H2_CONF_OUTPUT_BUFFER:
            return H2_CONFIG_GET(conf, &defconf, output_buffered);
        case H2_CONF_STREAM_TIMEOUT:
            return H2_CONFIG_GET(conf, &defconf, stream_timeout);
        default:
            return DEF_VAL;
    }
}

static void h2_srv_config_seti(h2_config *conf, h2_config_var_t var, int val)
{
    switch(var) {
        case H2_CONF_MAX_STREAMS:
            H2_CONFIG_SET(conf, h2_max_streams, val);
            break;
        case H2_CONF_WIN_SIZE:
            H2_CONFIG_SET(conf, h2_window_size, val);
            break;
        case H2_CONF_MIN_WORKERS:
            H2_CONFIG_SET(conf, min_workers, val);
            break;
        case H2_CONF_MAX_WORKERS:
            H2_CONFIG_SET(conf, max_workers, val);
            break;
        case H2_CONF_STREAM_MAX_MEM:
            H2_CONFIG_SET(conf, stream_max_mem_size, val);
            break;
        case H2_CONF_MODERN_TLS_ONLY:
            H2_CONFIG_SET(conf, modern_tls_only, val);
            break;
        case H2_CONF_UPGRADE:
            H2_CONFIG_SET(conf, h2_upgrade, val);
            break;
        case H2_CONF_DIRECT:
            H2_CONFIG_SET(conf, h2_direct, val);
            break;
        case H2_CONF_TLS_WARMUP_SIZE:
            H2_CONFIG_SET(conf, tls_warmup_size, val);
            break;
        case H2_CONF_TLS_COOLDOWN_SECS:
            H2_CONFIG_SET(conf, tls_cooldown_secs, val);
            break;
        case H2_CONF_PUSH:
            H2_CONFIG_SET(conf, h2_push, val);
            break;
        case H2_CONF_PUSH_DIARY_SIZE:
            H2_CONFIG_SET(conf, push_diary_size, val);
            break;
        case H2_CONF_COPY_FILES:
            H2_CONFIG_SET(conf, copy_files, val);
            break;
        case H2_CONF_EARLY_HINTS:
            H2_CONFIG_SET(conf, early_hints, val);
            break;
        case H2_CONF_PADDING_BITS:
            H2_CONFIG_SET(conf, padding_bits, val);
            break;
        case H2_CONF_PADDING_ALWAYS:
            H2_CONFIG_SET(conf, padding_always, val);
            break;
        case H2_CONF_OUTPUT_BUFFER:
            H2_CONFIG_SET(conf, output_buffered, val);
            break;
        default:
            break;
    }
}

static void h2_srv_config_seti64(h2_config *conf, h2_config_var_t var, apr_int64_t val)
{
    switch(var) {
        case H2_CONF_TLS_WARMUP_SIZE:
            H2_CONFIG_SET(conf, tls_warmup_size, val);
            break;
        case H2_CONF_STREAM_TIMEOUT:
            H2_CONFIG_SET(conf, stream_timeout, val);
            break;
        case H2_CONF_MAX_WORKER_IDLE_LIMIT:
            H2_CONFIG_SET(conf, idle_limit, val);
            break;
        default:
            h2_srv_config_seti(conf, var, (int)val);
            break;
    }
}

static h2_config *h2_config_sget(server_rec *s)
{
    h2_config *cfg = (h2_config *)ap_get_module_config(s->module_config, 
                                                       &http2_module);
    ap_assert(cfg);
    return cfg;
}

static const h2_dir_config *h2_config_rget(request_rec *r)
{
    h2_dir_config *cfg = (h2_dir_config *)ap_get_module_config(r->per_dir_config, 
                                                               &http2_module);
    ap_assert(cfg);
    return cfg;
}

static apr_int64_t h2_dir_config_geti64(const h2_dir_config *conf, h2_config_var_t var)
{
    switch(var) {
        case H2_CONF_UPGRADE:
            return H2_CONFIG_GET(conf, &defdconf, h2_upgrade);
        case H2_CONF_PUSH:
            return H2_CONFIG_GET(conf, &defdconf, h2_push);
        case H2_CONF_EARLY_HINTS:
            return H2_CONFIG_GET(conf, &defdconf, early_hints);
        case H2_CONF_STREAM_TIMEOUT:
            return H2_CONFIG_GET(conf, &defdconf, stream_timeout);

        default:
            return DEF_VAL;
    }
}

static void h2_config_seti(h2_dir_config *dconf, h2_config *conf, h2_config_var_t var, int val)
{
    int set_srv = !dconf;
    if (dconf) {
        switch(var) {
            case H2_CONF_UPGRADE:
                H2_CONFIG_SET(dconf, h2_upgrade, val);
                break;
            case H2_CONF_PUSH:
                H2_CONFIG_SET(dconf, h2_push, val);
                break;
            case H2_CONF_EARLY_HINTS:
                H2_CONFIG_SET(dconf, early_hints, val);
                break;
            default:
                /* not handled in dir_conf */
                set_srv = 1;
                break;
        }
    }

    if (set_srv) {
        h2_srv_config_seti(conf, var, val);
    }
}

static void h2_config_seti64(h2_dir_config *dconf, h2_config *conf, h2_config_var_t var, apr_int64_t val)
{
    int set_srv = !dconf;
    if (dconf) {
        switch(var) {
            case H2_CONF_STREAM_TIMEOUT:
                H2_CONFIG_SET(dconf, stream_timeout, val);
                break;
            default:
                /* not handled in dir_conf */
                set_srv = 1;
                break;
        }
    }

    if (set_srv) {
        h2_srv_config_seti64(conf, var, val);
    }
}

static const h2_config *h2_config_get(conn_rec *c)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);
    
    if (conn_ctx && conn_ctx->server) {
        return h2_config_sget(conn_ctx->server);
    }
    return h2_config_sget(c->base_server);
}

int h2_config_cgeti(conn_rec *c, h2_config_var_t var)
{
    return (int)h2_srv_config_geti64(h2_config_get(c), var);
}

apr_int64_t h2_config_cgeti64(conn_rec *c, h2_config_var_t var)
{
    return h2_srv_config_geti64(h2_config_get(c), var);
}

int h2_config_sgeti(server_rec *s, h2_config_var_t var)
{
    return (int)h2_srv_config_geti64(h2_config_sget(s), var);
}

apr_int64_t h2_config_sgeti64(server_rec *s, h2_config_var_t var)
{
    return h2_srv_config_geti64(h2_config_sget(s), var);
}

int h2_config_geti(request_rec *r, server_rec *s, h2_config_var_t var)
{
    return (int)h2_config_geti64(r, s, var);
}

apr_int64_t h2_config_geti64(request_rec *r, server_rec *s, h2_config_var_t var)
{
    apr_int64_t mode = r? (int)h2_dir_config_geti64(h2_config_rget(r), var) : DEF_VAL;
    return (mode != DEF_VAL)? mode : h2_config_sgeti64(s, var);
}

int h2_config_rgeti(request_rec *r, h2_config_var_t var)
{
    return h2_config_geti(r, r->server, var);
}

apr_int64_t h2_config_rgeti64(request_rec *r, h2_config_var_t var)
{
    return h2_config_geti64(r, r->server, var);
}

apr_array_header_t *h2_config_push_list(request_rec *r)
{
    const h2_config *sconf;
    const h2_dir_config *conf = h2_config_rget(r);
    
    if (conf && conf->push_list) {
        return conf->push_list;
    }
    sconf = h2_config_sget(r->server); 
    return sconf? sconf->push_list : NULL;
}

const struct h2_priority *h2_cconfig_get_priority(conn_rec *c, const char *content_type)
{
    const h2_config *conf = h2_config_get(c);
    if (content_type && conf->priorities) {
        apr_ssize_t len = (apr_ssize_t)strcspn(content_type, "; \t");
        h2_priority *prio = apr_hash_get(conf->priorities, content_type, len);
        return prio? prio : apr_hash_get(conf->priorities, "*", 1);
    }
    return NULL;
}

static const char *h2_conf_set_max_streams(cmd_parms *cmd,
                                           void *dirconf, const char *value)
{
    apr_int64_t ival = (int)apr_atoi64(value);
    if (ival < 1) {
        return "value must be > 0";
    }
    CONFIG_CMD_SET64(cmd, dirconf, H2_CONF_MAX_STREAMS, ival);
    return NULL;
}

static const char *h2_conf_set_window_size(cmd_parms *cmd,
                                           void *dirconf, const char *value)
{
    int val = (int)apr_atoi64(value);
    if (val < 1024) {
        return "value must be >= 1024";
    }
    CONFIG_CMD_SET(cmd, dirconf, H2_CONF_WIN_SIZE, val);
    return NULL;
}

static const char *h2_conf_set_min_workers(cmd_parms *cmd,
                                           void *dirconf, const char *value)
{
    int val = (int)apr_atoi64(value);
    if (val < 1) {
        return "value must be > 0";
    }
    CONFIG_CMD_SET(cmd, dirconf, H2_CONF_MIN_WORKERS, val);
    return NULL;
}

static const char *h2_conf_set_max_workers(cmd_parms *cmd,
                                           void *dirconf, const char *value)
{
    int val = (int)apr_atoi64(value);
    if (val < 1) {
        return "value must be > 0";
    }
    CONFIG_CMD_SET(cmd, dirconf, H2_CONF_MAX_WORKERS, val);
    return NULL;
}

static const char *h2_conf_set_max_worker_idle_limit(cmd_parms *cmd,
                                                     void *dirconf, const char *value)
{
    apr_interval_time_t timeout;
    apr_status_t rv = ap_timeout_parameter_parse(value, &timeout, "s");
    if (rv != APR_SUCCESS) {
        return "Invalid idle limit value";
    }
    if (timeout <= 0) {
        timeout = DEF_VAL;
    }
    CONFIG_CMD_SET64(cmd, dirconf, H2_CONF_MAX_WORKER_IDLE_LIMIT, timeout);
    return NULL;
}

static const char *h2_conf_set_stream_max_mem_size(cmd_parms *cmd,
                                                   void *dirconf, const char *value)
{
    int val = (int)apr_atoi64(value);
    if (val < 1024) {
        return "value must be >= 1024";
    }
    CONFIG_CMD_SET(cmd, dirconf, H2_CONF_STREAM_MAX_MEM, val);
    return NULL;
}

static const char *h2_conf_set_session_extra_files(cmd_parms *cmd,
                                                   void *dirconf, const char *value)
{
    /* deprecated, ignore */
    (void)dirconf;
    (void)value;
    ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, cmd->pool, /* NO LOGNO */
                  "H2SessionExtraFiles is obsolete and will be ignored");
    return NULL;
}

static const char *h2_conf_set_serialize_headers(cmd_parms *parms,
                                                 void *dirconf, const char *value)
{
    if (!strcasecmp(value, "On")) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, parms->server, APLOGNO(10307)
                     "%s: this feature has been disabled and the directive "
                     "to enable it is ignored.", parms->cmd->name);
    }
    return NULL;
}

static const char *h2_conf_set_direct(cmd_parms *cmd,
                                      void *dirconf, const char *value)
{
    if (!strcasecmp(value, "On")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_DIRECT, 1);
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_DIRECT, 0);
        return NULL;
    }
    return "value must be On or Off";
}

static const char *h2_conf_set_push(cmd_parms *cmd, void *dirconf, const char *value)
{
    if (!strcasecmp(value, "On")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_PUSH, 1);
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_PUSH, 0);
        return NULL;
    }
    return "value must be On or Off";
}

static const char *h2_conf_add_push_priority(cmd_parms *cmd, void *_cfg,
                                             const char *ctype, const char *sdependency,
                                             const char *sweight)
{
    h2_config *cfg = (h2_config *)h2_config_sget(cmd->server);
    const char *sdefweight = "16";         /* default AFTER weight */
    h2_dependency dependency;
    h2_priority *priority;
    int weight;
 
    (void)_cfg;
    if (!*ctype) {
        return "1st argument must be a mime-type, like 'text/css' or '*'";
    }
    
    if (!sweight) {
        /* 2 args only, but which one? */
        if (apr_isdigit(sdependency[0])) {
            sweight = sdependency;
            sdependency = "AFTER";        /* default dependency */
        }
    }
    
    if (!strcasecmp("AFTER", sdependency)) {
        dependency = H2_DEPENDANT_AFTER;
    } 
    else if (!strcasecmp("BEFORE", sdependency)) {
        dependency = H2_DEPENDANT_BEFORE;
        if (sweight) {
            return "dependency 'Before' does not allow a weight";
        }
    } 
    else if (!strcasecmp("INTERLEAVED", sdependency)) {
        dependency = H2_DEPENDANT_INTERLEAVED;
        sdefweight = "256";        /* default INTERLEAVED weight */
    }
    else {
        return "dependency must be one of 'After', 'Before' or 'Interleaved'";
    }
    
    weight = (int)apr_atoi64(sweight? sweight : sdefweight);
    if (weight < NGHTTP2_MIN_WEIGHT) {
        return apr_psprintf(cmd->pool, "weight must be a number >= %d",
                            NGHTTP2_MIN_WEIGHT);
    }
    
    priority = apr_pcalloc(cmd->pool, sizeof(*priority));
    priority->dependency = dependency;
    priority->weight = weight;
    
    if (!cfg->priorities) {
        cfg->priorities = apr_hash_make(cmd->pool);
    }
    apr_hash_set(cfg->priorities, ctype, (apr_ssize_t)strlen(ctype), priority);
    return NULL;
}

static const char *h2_conf_set_modern_tls_only(cmd_parms *cmd,
                                               void *dirconf, const char *value)
{
    if (!strcasecmp(value, "On")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_MODERN_TLS_ONLY, 1);
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_MODERN_TLS_ONLY, 0);
        return NULL;
    }
    return "value must be On or Off";
}

static const char *h2_conf_set_upgrade(cmd_parms *cmd,
                                       void *dirconf, const char *value)
{
    if (!strcasecmp(value, "On")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_UPGRADE, 1);
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_UPGRADE, 0);
        return NULL;
    }
    return "value must be On or Off";
}

static const char *h2_conf_set_tls_warmup_size(cmd_parms *cmd,
                                               void *dirconf, const char *value)
{
    apr_int64_t val = apr_atoi64(value);
    CONFIG_CMD_SET64(cmd, dirconf, H2_CONF_TLS_WARMUP_SIZE, val);
    return NULL;
}

static const char *h2_conf_set_tls_cooldown_secs(cmd_parms *cmd,
                                                 void *dirconf, const char *value)
{
    apr_int64_t val = (int)apr_atoi64(value);
    CONFIG_CMD_SET64(cmd, dirconf, H2_CONF_TLS_COOLDOWN_SECS, val);
    return NULL;
}

static const char *h2_conf_set_push_diary_size(cmd_parms *cmd,
                                               void *dirconf, const char *value)
{
    int val = (int)apr_atoi64(value);
    if (val < 0) {
        return "value must be >= 0";
    }
    if (val > 0 && (val & (val-1))) {
        return "value must a power of 2";
    }
    if (val > (1 << 15)) {
        return "value must <= 65536";
    }
    CONFIG_CMD_SET(cmd, dirconf, H2_CONF_PUSH_DIARY_SIZE, val);
    return NULL;
}

static const char *h2_conf_set_copy_files(cmd_parms *cmd,
                                          void *dirconf, const char *value)
{
    if (!strcasecmp(value, "On")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_COPY_FILES, 1);
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_COPY_FILES, 0);
        return NULL;
    }
    return "value must be On or Off";
}

static void add_push(apr_array_header_t **plist, apr_pool_t *pool, h2_push_res *push)
{
    h2_push_res *new;
    if (!*plist) {
        *plist = apr_array_make(pool, 10, sizeof(*push));
    }
    new = apr_array_push(*plist);
    new->uri_ref = push->uri_ref;
    new->critical = push->critical;
}

static const char *h2_conf_add_push_res(cmd_parms *cmd, void *dirconf,
                                        const char *arg1, const char *arg2,
                                        const char *arg3)
{
    h2_push_res push;
    const char *last = arg3;
    
    memset(&push, 0, sizeof(push));
    if (!strcasecmp("add", arg1)) {
        push.uri_ref = arg2;
    }
    else {
        push.uri_ref = arg1;
        last = arg2;
        if (arg3) {
            return "too many parameter";
        }
    }
    
    if (last) {
        if (!strcasecmp("critical", last)) {
            push.critical = 1;
        }
        else {
            return "unknown last parameter";
        }
    }

    if (cmd->path) {
        add_push(&(((h2_dir_config*)dirconf)->push_list), cmd->pool, &push);
    }
    else {
        add_push(&(h2_config_sget(cmd->server)->push_list), cmd->pool, &push);
    }
    return NULL;
}

static const char *h2_conf_set_early_hints(cmd_parms *cmd,
                                           void *dirconf, const char *value)
{
    int val;

    if (!strcasecmp(value, "On")) val = 1;
    else if (!strcasecmp(value, "Off")) val = 0;
    else return "value must be On or Off";
    
    CONFIG_CMD_SET(cmd, dirconf, H2_CONF_EARLY_HINTS, val);
    if (cmd->path) {
        ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, cmd->pool, 
                            "H2EarlyHints = %d on path %s", val, cmd->path);
    }
    return NULL;
}

static const char *h2_conf_set_padding(cmd_parms *cmd, void *dirconf, const char *value)
{
    int val;
    
    val = (int)apr_atoi64(value);
    if (val < 0) {
        return "number of bits must be >= 0";
    }
    if (val > 8) {
        return "number of bits must be <= 8";
    }
    CONFIG_CMD_SET(cmd, dirconf, H2_CONF_PADDING_BITS, val);
    return NULL;
}

static const char *h2_conf_set_output_buffer(cmd_parms *cmd,
                                      void *dirconf, const char *value)
{
    if (!strcasecmp(value, "On")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_OUTPUT_BUFFER, 1);
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        CONFIG_CMD_SET(cmd, dirconf, H2_CONF_OUTPUT_BUFFER, 0);
        return NULL;
    }
    return "value must be On or Off";
}

static const char *h2_conf_set_stream_timeout(cmd_parms *cmd,
                                            void *dirconf, const char *value)
{
    apr_status_t rv;
    apr_interval_time_t timeout;

    rv = ap_timeout_parameter_parse(value, &timeout, "s");
    if (rv != APR_SUCCESS) {
        return "Invalid timeout value";
    }
    CONFIG_CMD_SET64(cmd, dirconf, H2_CONF_STREAM_TIMEOUT, timeout);
    return NULL;
}

void h2_get_workers_config(server_rec *s, int *pminw, int *pmaxw,
                           apr_time_t *pidle_limit)
{
    int threads_per_child = 0;

    *pminw = h2_config_sgeti(s, H2_CONF_MIN_WORKERS);
    *pmaxw = h2_config_sgeti(s, H2_CONF_MAX_WORKERS);

    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threads_per_child);
    if (*pminw <= 0) {
        *pminw = threads_per_child;
    }
    if (*pmaxw <= 0) {
        *pmaxw = H2MAX(4, 3 * (*pminw) / 2);
    }
    *pidle_limit = h2_config_sgeti64(s, H2_CONF_MAX_WORKER_IDLE_LIMIT);
}

#define AP_END_CMD     AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)

const command_rec h2_cmds[] = {
    AP_INIT_TAKE1("H2MaxSessionStreams", h2_conf_set_max_streams, NULL,
                  RSRC_CONF, "maximum number of open streams per session"),
    AP_INIT_TAKE1("H2WindowSize", h2_conf_set_window_size, NULL,
                  RSRC_CONF, "window size on client DATA"),
    AP_INIT_TAKE1("H2MinWorkers", h2_conf_set_min_workers, NULL,
                  RSRC_CONF, "minimum number of worker threads per child"),
    AP_INIT_TAKE1("H2MaxWorkers", h2_conf_set_max_workers, NULL,
                  RSRC_CONF, "maximum number of worker threads per child"),
    AP_INIT_TAKE1("H2MaxWorkerIdleSeconds", h2_conf_set_max_worker_idle_limit, NULL,
                  RSRC_CONF, "maximum number of idle seconds before a worker shuts down"),
    AP_INIT_TAKE1("H2StreamMaxMemSize", h2_conf_set_stream_max_mem_size, NULL,
                  RSRC_CONF, "maximum number of bytes buffered in memory for a stream"),
    AP_INIT_TAKE1("H2SerializeHeaders", h2_conf_set_serialize_headers, NULL,
                  RSRC_CONF, "disabled, this directive has no longer an effect."),
    AP_INIT_TAKE1("H2ModernTLSOnly", h2_conf_set_modern_tls_only, NULL,
                  RSRC_CONF, "off to not impose RFC 7540 restrictions on TLS"),
    AP_INIT_TAKE1("H2Upgrade", h2_conf_set_upgrade, NULL,
                  RSRC_CONF|OR_AUTHCFG, "on to allow HTTP/1 Upgrades to h2/h2c"),
    AP_INIT_TAKE1("H2Direct", h2_conf_set_direct, NULL,
                  RSRC_CONF, "on to enable direct HTTP/2 mode"),
    AP_INIT_TAKE1("H2SessionExtraFiles", h2_conf_set_session_extra_files, NULL,
                  RSRC_CONF, "number of extra file a session might keep open (obsolete)"),
    AP_INIT_TAKE1("H2TLSWarmUpSize", h2_conf_set_tls_warmup_size, NULL,
                  RSRC_CONF, "number of bytes on TLS connection before doing max writes"),
    AP_INIT_TAKE1("H2TLSCoolDownSecs", h2_conf_set_tls_cooldown_secs, NULL,
                  RSRC_CONF, "seconds of idle time on TLS before shrinking writes"),
    AP_INIT_TAKE1("H2Push", h2_conf_set_push, NULL,
                  RSRC_CONF|OR_AUTHCFG, "off to disable HTTP/2 server push"),
    AP_INIT_TAKE23("H2PushPriority", h2_conf_add_push_priority, NULL,
                  RSRC_CONF, "define priority of PUSHed resources per content type"),
    AP_INIT_TAKE1("H2PushDiarySize", h2_conf_set_push_diary_size, NULL,
                  RSRC_CONF, "size of push diary"),
    AP_INIT_TAKE1("H2CopyFiles", h2_conf_set_copy_files, NULL,
                  OR_FILEINFO, "on to perform copy of file data"),
    AP_INIT_TAKE123("H2PushResource", h2_conf_add_push_res, NULL,
                   OR_FILEINFO|OR_AUTHCFG, "add a resource to be pushed in this location/on this server."),
    AP_INIT_TAKE1("H2EarlyHints", h2_conf_set_early_hints, NULL,
                  RSRC_CONF, "on to enable interim status 103 responses"),
    AP_INIT_TAKE1("H2Padding", h2_conf_set_padding, NULL,
                  RSRC_CONF, "set payload padding"),
    AP_INIT_TAKE1("H2OutputBuffering", h2_conf_set_output_buffer, NULL,
                  RSRC_CONF, "set stream output buffer on/off"),
    AP_INIT_TAKE1("H2StreamTimeout", h2_conf_set_stream_timeout, NULL,
                  RSRC_CONF, "set stream timeout"),
    AP_END_CMD
};


