/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_vhost.h>

#include <apr_strings.h>

#include "h2_alt_svc.h"
#include "h2_ctx.h"
#include "h2_conn.h"
#include "h2_config.h"
#include "h2_private.h"

#define DEF_VAL     (-1)

#define H2_CONFIG_GET(a, b, n) \
    (((a)->n == DEF_VAL)? (b) : (a))->n

static h2_config defconf = {
    "default",
    0,                /* enabled */
    100,              /* max_streams */
    16 * 1024,        /* max_hl_size */
    64 * 1024,        /* window_size */
    -1,               /* min workers */
    -1,               /* max workers */
    10 * 60,          /* max workers idle secs */
    64 * 1024,        /* stream max mem size */
    NULL,             /* no alt-svcs */
    -1,               /* alt-svc max age */
    0,                /* serialize headers */
    1,                /* hack mpm event */
    1,                /* h2 direct mode */
    -1,               /* buffer output, by default only for TLS */
    64*1024,          /* buffer size */
    16*1024,          /* out write max */
    5,                /* # session extra files */
};

static void *h2_config_create(apr_pool_t *pool,
                              const char *prefix, const char *x)
{
    h2_config *conf = (h2_config *)apr_pcalloc(pool, sizeof(h2_config));
    
    const char *s = x? x : "unknown";
    char *name = (char *)apr_pcalloc(pool, strlen(prefix) + strlen(s) + 20);
    strcpy(name, prefix);
    strcat(name, "[");
    strcat(name, s);
    strcat(name, "]");
    
    conf->name                 = name;
    conf->h2_enabled           = DEF_VAL;
    conf->h2_max_streams       = DEF_VAL;
    conf->h2_max_hl_size       = DEF_VAL;
    conf->h2_window_size       = DEF_VAL;
    conf->min_workers          = DEF_VAL;
    conf->max_workers          = DEF_VAL;
    conf->max_worker_idle_secs = DEF_VAL;
    conf->stream_max_mem_size  = DEF_VAL;
    conf->alt_svc_max_age      = DEF_VAL;
    conf->serialize_headers    = DEF_VAL;
    conf->hack_mpm_event       = DEF_VAL;
    conf->h2_direct            = DEF_VAL;
    conf->buffer_output        = DEF_VAL;
    conf->buffer_output        = DEF_VAL;
    conf->buffer_size          = DEF_VAL;
    conf->write_max            = DEF_VAL;
    conf->session_extra_files  = DEF_VAL;
    return conf;
}

void *h2_config_create_svr(apr_pool_t *pool, server_rec *s)
{
    return h2_config_create(pool, "srv", s->defn_name);
}

void *h2_config_create_dir(apr_pool_t *pool, char *x)
{
    return h2_config_create(pool, "dir", x);
}

void *h2_config_merge(apr_pool_t *pool, void *basev, void *addv)
{
    h2_config *base = (h2_config *)basev;
    h2_config *add = (h2_config *)addv;
    h2_config *n = (h2_config *)apr_pcalloc(pool, sizeof(h2_config));

    char *name = (char *)apr_pcalloc(pool,
        20 + strlen(add->name) + strlen(base->name));
    strcpy(name, "merged[");
    strcat(name, add->name);
    strcat(name, ", ");
    strcat(name, base->name);
    strcat(name, "]");
    n->name = name;

    n->h2_enabled     = H2_CONFIG_GET(add, base, h2_enabled);
    n->h2_max_streams = H2_CONFIG_GET(add, base, h2_max_streams);
    n->h2_max_hl_size = H2_CONFIG_GET(add, base, h2_max_hl_size);
    n->h2_window_size = H2_CONFIG_GET(add, base, h2_window_size);
    n->min_workers    = H2_CONFIG_GET(add, base, min_workers);
    n->max_workers    = H2_CONFIG_GET(add, base, max_workers);
    n->max_worker_idle_secs = H2_CONFIG_GET(add, base, max_worker_idle_secs);
    n->stream_max_mem_size = H2_CONFIG_GET(add, base, stream_max_mem_size);
    n->alt_svcs = add->alt_svcs? add->alt_svcs : base->alt_svcs;
    n->alt_svc_max_age = H2_CONFIG_GET(add, base, alt_svc_max_age);
    n->serialize_headers = H2_CONFIG_GET(add, base, serialize_headers);
    n->hack_mpm_event = H2_CONFIG_GET(add, base, hack_mpm_event);
    n->h2_direct      = H2_CONFIG_GET(add, base, h2_direct);
    n->buffer_output  = H2_CONFIG_GET(add, base, buffer_output);
    n->buffer_size    = H2_CONFIG_GET(add, base, buffer_size);
    n->write_max      = H2_CONFIG_GET(add, base, write_max);
    n->session_extra_files = H2_CONFIG_GET(add, base, session_extra_files);
    
    return n;
}

int h2_config_geti(h2_config *conf, h2_config_var_t var)
{
    switch(var) {
        case H2_CONF_ENABLED:
            return H2_CONFIG_GET(conf, &defconf, h2_enabled);
        case H2_CONF_MAX_STREAMS:
            return H2_CONFIG_GET(conf, &defconf, h2_max_streams);
        case H2_CONF_MAX_HL_SIZE:
            return H2_CONFIG_GET(conf, &defconf, h2_max_hl_size);
        case H2_CONF_WIN_SIZE:
            return H2_CONFIG_GET(conf, &defconf, h2_window_size);
        case H2_CONF_MIN_WORKERS:
            return H2_CONFIG_GET(conf, &defconf, min_workers);
        case H2_CONF_MAX_WORKERS:
            return H2_CONFIG_GET(conf, &defconf, max_workers);
        case H2_CONF_MAX_WORKER_IDLE_SECS:
            return H2_CONFIG_GET(conf, &defconf, max_worker_idle_secs);
        case H2_CONF_STREAM_MAX_MEM:
            return H2_CONFIG_GET(conf, &defconf, stream_max_mem_size);
        case H2_CONF_ALT_SVC_MAX_AGE:
            return H2_CONFIG_GET(conf, &defconf, alt_svc_max_age);
        case H2_CONF_SER_HEADERS:
            return H2_CONFIG_GET(conf, &defconf, serialize_headers);
        case H2_CONF_HACK_MPM_EVENT:
            return H2_CONFIG_GET(conf, &defconf, hack_mpm_event);
        case H2_CONF_DIRECT:
            return H2_CONFIG_GET(conf, &defconf, h2_direct);
        case H2_CONF_BUFFER_OUTPUT:
            return H2_CONFIG_GET(conf, &defconf, buffer_output);
        case H2_CONF_BUFFER_SIZE:
            return H2_CONFIG_GET(conf, &defconf, buffer_size);
        case H2_CONF_WRITE_MAX:
            return H2_CONFIG_GET(conf, &defconf, write_max);
        case H2_CONF_SESSION_FILES:
            return H2_CONFIG_GET(conf, &defconf, session_extra_files);
        default:
            return DEF_VAL;
    }
}

h2_config *h2_config_sget(server_rec *s)
{
    h2_config *cfg = (h2_config *)ap_get_module_config(s->module_config, 
                                                       &h2_module);
    AP_DEBUG_ASSERT(cfg);
    return cfg;
}


static const char *h2_conf_set_engine(cmd_parms *parms,
                                      void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    if (!strcasecmp(value, "On")) {
        cfg->h2_enabled = 1;
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        cfg->h2_enabled = 0;
        return NULL;
    }
    
    (void)arg;
    return "value must be On or Off";
}

static const char *h2_conf_set_max_streams(cmd_parms *parms,
                                           void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    cfg->h2_max_streams = (int)apr_atoi64(value);
    (void)arg;
    if (cfg->h2_max_streams < 1) {
        return "value must be > 0";
    }
    return NULL;
}

static const char *h2_conf_set_window_size(cmd_parms *parms,
                                           void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    cfg->h2_window_size = (int)apr_atoi64(value);
    (void)arg;
    if (cfg->h2_window_size < 1024) {
        return "value must be > 1k";
    }
    return NULL;
}

static const char *h2_conf_set_max_hl_size(cmd_parms *parms,
                                           void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    cfg->h2_max_hl_size = (int)apr_atoi64(value);
    (void)arg;
    if (cfg->h2_max_hl_size < 1024) {
        return "value must be > 1k";
    }
    return NULL;
}

static const char *h2_conf_set_min_workers(cmd_parms *parms,
                                           void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    cfg->min_workers = (int)apr_atoi64(value);
    (void)arg;
    if (cfg->min_workers < 1) {
        return "value must be > 1";
    }
    return NULL;
}

static const char *h2_conf_set_max_workers(cmd_parms *parms,
                                           void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    cfg->max_workers = (int)apr_atoi64(value);
    (void)arg;
    if (cfg->max_workers < 1) {
        return "value must be > 1";
    }
    return NULL;
}

static const char *h2_conf_set_max_worker_idle_secs(cmd_parms *parms,
                                                    void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    cfg->max_worker_idle_secs = (int)apr_atoi64(value);
    (void)arg;
    if (cfg->max_worker_idle_secs < 1) {
        return "value must be > 1";
    }
    return NULL;
}

static const char *h2_conf_set_stream_max_mem_size(cmd_parms *parms,
                                                   void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    
    
    cfg->stream_max_mem_size = (int)apr_atoi64(value);
    (void)arg;
    if (cfg->stream_max_mem_size < 1024) {
        return "value must be > 1k";
    }
    return NULL;
}

static const char *h2_add_alt_svc(cmd_parms *parms,
                                  void *arg, const char *value)
{
    if (value && strlen(value)) {
        h2_config *cfg = h2_config_sget(parms->server);
        h2_alt_svc *as = h2_alt_svc_parse(value, parms->pool);
        if (!as) {
            return "unable to parse alt-svc specifier";
        }
        if (!cfg->alt_svcs) {
            cfg->alt_svcs = apr_array_make(parms->pool, 5, sizeof(h2_alt_svc*));
        }
        APR_ARRAY_PUSH(cfg->alt_svcs, h2_alt_svc*) = as;
    }
    (void)arg;
    return NULL;
}

static const char *h2_conf_set_alt_svc_max_age(cmd_parms *parms,
                                               void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    cfg->alt_svc_max_age = (int)apr_atoi64(value);
    (void)arg;
    return NULL;
}

static const char *h2_conf_set_buffer_size(cmd_parms *parms,
                                           void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    apr_int64_t len = (int)apr_atoi64(value);
    if (len < (16*1024)) {
        return "value must be a positive number, at least 16k";
    }
    cfg->buffer_size = (int)len;
    (void)arg;
    return NULL;
}

static const char *h2_conf_set_write_max(cmd_parms *parms,
                                             void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    apr_int64_t max = (int)apr_atoi64(value);
    if (max <= 0) {
        return "value must be a positive number";
    }
    else if (max > cfg->buffer_size) {
        return "value must be less than H2BufferSize";
    }
    cfg->write_max = (int)max;
    (void)arg;
    return NULL;
}

static const char *h2_conf_set_session_extra_files(cmd_parms *parms,
                                                   void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    apr_int64_t max = (int)apr_atoi64(value);
    if (max <= 0) {
        return "value must be a positive number";
    }
    cfg->session_extra_files = (int)max;
    (void)arg;
    return NULL;
}

static const char *h2_conf_set_serialize_headers(cmd_parms *parms,
                                                 void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    if (!strcasecmp(value, "On")) {
        cfg->serialize_headers = 1;
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        cfg->serialize_headers = 0;
        return NULL;
    }
    
    (void)arg;
    return "value must be On or Off";
}

static const char *h2_conf_set_hack_mpm_event(cmd_parms *parms,
                                              void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    if (!strcasecmp(value, "On")) {
        cfg->hack_mpm_event = 1;
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        cfg->hack_mpm_event = 0;
        return NULL;
    }
    
    (void)arg;
    return "value must be On or Off";
}

static const char *h2_conf_set_direct(cmd_parms *parms,
                                      void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    if (!strcasecmp(value, "On")) {
        cfg->h2_direct = 1;
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        cfg->h2_direct = 0;
        return NULL;
    }
    
    (void)arg;
    return "value must be On or Off";
}

static const char *h2_conf_set_buffer_output(cmd_parms *parms,
                                             void *arg, const char *value)
{
    h2_config *cfg = h2_config_sget(parms->server);
    if (!strcasecmp(value, "On")) {
        cfg->buffer_output = 1;
        return NULL;
    }
    else if (!strcasecmp(value, "Off")) {
        cfg->buffer_output = 0;
        return NULL;
    }
    
    (void)arg;
    return "value must be On or Off";
}

#pragma GCC diagnostic ignored "-Wmissing-braces"
const command_rec h2_cmds[] = {
    AP_INIT_TAKE1("H2Engine", h2_conf_set_engine, NULL,
                  RSRC_CONF, "on to enable HTTP/2 protocol handling"),
    AP_INIT_TAKE1("H2MaxSessionStreams", h2_conf_set_max_streams, NULL,
                  RSRC_CONF, "maximum number of open streams per session"),
    AP_INIT_TAKE1("H2InitialWindowSize", h2_conf_set_window_size, NULL,
                  RSRC_CONF, "initial window size on client DATA"),
    AP_INIT_TAKE1("H2MaxHeaderListSize", h2_conf_set_max_hl_size, NULL, 
                  RSRC_CONF, "maximum acceptable size of request headers"),
    AP_INIT_TAKE1("H2MinWorkers", h2_conf_set_min_workers, NULL,
                  RSRC_CONF, "minimum number of worker threads per child"),
    AP_INIT_TAKE1("H2MaxWorkers", h2_conf_set_max_workers, NULL,
                  RSRC_CONF, "maximum number of worker threads per child"),
    AP_INIT_TAKE1("H2MaxWorkerIdleSeconds", h2_conf_set_max_worker_idle_secs, NULL,
                  RSRC_CONF, "maximum number of idle seconds before a worker shuts down"),
    AP_INIT_TAKE1("H2StreamMaxMemSize", h2_conf_set_stream_max_mem_size, NULL,
                  RSRC_CONF, "maximum number of bytes buffered in memory for a stream"),
    AP_INIT_TAKE1("H2AltSvc", h2_add_alt_svc, NULL,
                  RSRC_CONF, "adds an Alt-Svc for this server"),
    AP_INIT_TAKE1("H2AltSvcMaxAge", h2_conf_set_alt_svc_max_age, NULL,
                  RSRC_CONF, "set the maximum age (in seconds) that client can rely on alt-svc information"),
    AP_INIT_TAKE1("H2SerializeHeaders", h2_conf_set_serialize_headers, NULL,
                  RSRC_CONF, "on to enable header serialization for compatibility"),
    AP_INIT_TAKE1("H2HackMpmEvent", h2_conf_set_hack_mpm_event, NULL,
                  RSRC_CONF, "on to enable a hack that makes mpm_event working with mod_h2"),
    AP_INIT_TAKE1("H2Direct", h2_conf_set_direct, NULL,
                  RSRC_CONF, "on to enable direct HTTP/2 mode"),
    AP_INIT_TAKE1("H2BufferOutput", h2_conf_set_buffer_output, NULL,
                  RSRC_CONF, "on to enable output buffering, default for TLS"),
    AP_INIT_TAKE1("H2BufferSize", h2_conf_set_buffer_size, NULL,
                  RSRC_CONF, "size of outgoing buffer in bytes"),
    AP_INIT_TAKE1("H2BufferWriteMax", h2_conf_set_write_max, NULL,
                  RSRC_CONF, "maximum number of bytes in a outgoing write"),
    AP_INIT_TAKE1("H2SessionExtraFiles", h2_conf_set_session_extra_files, NULL,
                  RSRC_CONF, "number of extra file a session might keep open"),
    { NULL, NULL, NULL, 0, 0, NULL }
};


h2_config *h2_config_rget(request_rec *r)
{
    h2_config *cfg = (h2_config *)ap_get_module_config(r->per_dir_config, 
                                                       &h2_module);
    return cfg? cfg : h2_config_sget(r->server); 
}

h2_config *h2_config_get(conn_rec *c)
{
    h2_ctx *ctx = h2_ctx_get(c);
    if (ctx->config) {
        return ctx->config;
    }
    if (!ctx->server && ctx->hostname) {
        /* We have a host agreed upon via TLS SNI, but no request yet.
         * The sni host was accepted and therefore does match a server record
         * (vhost) for it. But we need to know which one.
         * Normally, it is enough to be set on the initial request on a
         * connection, but we need it earlier. Simulate a request and call
         * the vhost matching stuff.
         */
        apr_uri_t uri;
        memset(&uri, 0, sizeof(uri));
        uri.scheme = (char*)"https";
        uri.hostinfo = (char*)ctx->hostname;
        uri.hostname = (char*)ctx->hostname;
        uri.port_str = (char*)"";
        uri.port = c->local_addr->port;
        uri.path = (char*)"/";
        
        request_rec r;
        memset(&r, 0, sizeof(r));
        r.uri = (char*)"/";
        r.connection = c;
        r.pool = c->pool;
        r.hostname = ctx->hostname;
        r.headers_in = apr_table_make(c->pool, 1);
        r.parsed_uri = uri;
        r.status = HTTP_OK;
        r.server = r.connection->base_server;
        ap_update_vhost_from_headers(&r);
        ctx->server = r.server;
    }
    
    if (ctx->server) {
        ctx->config = h2_config_sget(ctx->server);
        return ctx->config;
    }
    
    return h2_config_sget(c->base_server);
}

