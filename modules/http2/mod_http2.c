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

#include <apr_optional.h>
#include <apr_optional_hooks.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_want.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include "mod_http2.h"

#include <nghttp2/nghttp2.h>
#include "h2_stream.h"
#include "h2_alt_svc.h"
#include "h2_conn.h"
#include "h2_filter.h"
#include "h2_task.h"
#include "h2_session.h"
#include "h2_config.h"
#include "h2_ctx.h"
#include "h2_h2.h"
#include "h2_mplx.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_switch.h"
#include "h2_version.h"


static void h2_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(http2) = {
    STANDARD20_MODULE_STUFF,
    h2_config_create_dir, /* func to create per dir config */
    h2_config_merge_dir,  /* func to merge per dir config */
    h2_config_create_svr, /* func to create per server config */
    h2_config_merge_svr,  /* func to merge per server config */
    h2_cmds,              /* command handlers */
    h2_hooks
};

static int h2_h2_fixups(request_rec *r);

typedef struct {
    unsigned int change_prio : 1;
    unsigned int sha256 : 1;
    unsigned int inv_headers : 1;
} features;

static features myfeats;

/* The module initialization. Called once as apache hook, before any multi
 * processing (threaded or not) happens. It is typically at least called twice, 
 * see
 * http://wiki.apache.org/httpd/ModuleLife
 * Since the first run is just a "practise" run, we want to initialize for real
 * only on the second try. This defeats the purpose of the first dry run a bit, 
 * since apache wants to verify that a new configuration actually will work. 
 * So if we have trouble with the configuration, this will only be detected 
 * when the server has already switched.
 * On the other hand, when we initialize lib nghttp2, all possible crazy things 
 * might happen and this might even eat threads. So, better init on the real 
 * invocation, for now at least.
 */
static int h2_post_config(apr_pool_t *p, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    const char *mod_h2_init_key = "mod_http2_init_counter";
    nghttp2_info *ngh2;
    apr_status_t status;
    
    (void)plog;(void)ptemp;
#ifdef H2_NG2_CHANGE_PRIO
    myfeats.change_prio = 1;
#endif
#ifdef H2_OPENSSL
    myfeats.sha256 = 1;
#endif
#ifdef H2_NG2_INVALID_HEADER_CB
    myfeats.inv_headers = 1;
#endif
    
    apr_pool_userdata_get(&data, mod_h2_init_key, s->process->pool);
    if ( data == NULL ) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03089)
                     "initializing post config dry run");
        apr_pool_userdata_set((const void *)1, mod_h2_init_key,
                              apr_pool_cleanup_null, s->process->pool);
        return APR_SUCCESS;
    }
    
    ngh2 = nghttp2_version(0);
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(03090)
                 "mod_http2 (v%s, feats=%s%s%s, nghttp2 %s), initializing...",
                 MOD_HTTP2_VERSION, 
                 myfeats.change_prio? "CHPRIO"  : "", 
                 myfeats.sha256?      "+SHA256" : "",
                 myfeats.inv_headers? "+INVHD"  : "",
                 ngh2?                ngh2->version_str : "unknown");
    
    switch (h2_conn_mpm_type()) {
        case H2_MPM_SIMPLE:
        case H2_MPM_MOTORZ:
        case H2_MPM_NETWARE:
        case H2_MPM_WINNT:
            /* not sure we need something extra for those. */
            break;
        case H2_MPM_EVENT:
        case H2_MPM_WORKER:
            /* all fine, we know these ones */
            break;
        case H2_MPM_PREFORK:
            /* ok, we now know how to handle that one */
            break;
        case H2_MPM_UNKNOWN:
            /* ??? */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03091)
                         "post_config: mpm type unknown");
            break;
    }
    
    status = h2_h2_init(p, s);
    if (status == APR_SUCCESS) {
        status = h2_switch_init(p, s);
    }
    if (status == APR_SUCCESS) {
        status = h2_task_init(p, s);
    }
    
    return status;
}

static char *http2_var_lookup(apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *, char *name);
static int http2_is_h2(conn_rec *);

static apr_status_t http2_req_engine_push(const char *ngn_type, 
                                          request_rec *r, 
                                          http2_req_engine_init *einit)
{
    return h2_mplx_req_engine_push(ngn_type, r, einit);
}

static apr_status_t http2_req_engine_pull(h2_req_engine *ngn, 
                                          apr_read_type_e block, 
                                          int capacity, 
                                          request_rec **pr)
{
    return h2_mplx_req_engine_pull(ngn, block, capacity, pr);
}

static void http2_req_engine_done(h2_req_engine *ngn, conn_rec *r_conn,
                                  apr_status_t status)
{
    h2_mplx_req_engine_done(ngn, r_conn, status);
}

/* Runs once per created child process. Perform any process 
 * related initionalization here.
 */
static void h2_child_init(apr_pool_t *pool, server_rec *s)
{
    /* Set up our connection processing */
    apr_status_t status = h2_conn_child_init(pool, s);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     APLOGNO(02949) "initializing connection handling");
    }
    
}

/* Install this module into the apache2 infrastructure.
 */
static void h2_hooks(apr_pool_t *pool)
{
    static const char *const mod_ssl[] = { "mod_ssl.c", NULL};
    
    APR_REGISTER_OPTIONAL_FN(http2_is_h2);
    APR_REGISTER_OPTIONAL_FN(http2_var_lookup);
    APR_REGISTER_OPTIONAL_FN(http2_req_engine_push);
    APR_REGISTER_OPTIONAL_FN(http2_req_engine_pull);
    APR_REGISTER_OPTIONAL_FN(http2_req_engine_done);

    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks");
    
    /* Run once after configuration is set, but before mpm children initialize.
     */
    ap_hook_post_config(h2_post_config, mod_ssl, NULL, APR_HOOK_MIDDLE);
    
    /* Run once after a child process has been created.
     */
    ap_hook_child_init(h2_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    h2_h2_register_hooks();
    h2_switch_register_hooks();
    h2_task_register_hooks();

    h2_alt_svc_register_hooks();
    
    /* Setup subprocess env for certain variables 
     */
    ap_hook_fixups(h2_h2_fixups, NULL,NULL, APR_HOOK_MIDDLE);
    
    /* test http2 connection status handler */
    ap_hook_handler(h2_filter_h2_status_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *val_HTTP2(apr_pool_t *p, server_rec *s,
                             conn_rec *c, request_rec *r, h2_ctx *ctx)
{
    return ctx? "on" : "off";
}

static const char *val_H2_PUSH(apr_pool_t *p, server_rec *s,
                               conn_rec *c, request_rec *r, h2_ctx *ctx)
{
    if (ctx) {
        if (r) {
            h2_task *task = h2_ctx_get_task(ctx);
            if (task) {
                h2_stream *stream = h2_mplx_stream_get(task->mplx, task->stream_id);
                if (stream && stream->push_policy != H2_PUSH_NONE) {
                    return "on";
                }
            }
        }
        else if (c && h2_session_push_enabled(ctx->session)) {
            return "on";
        }
    }
    else if (s) {
        const h2_config *cfg = h2_config_sget(s);
        if (cfg && h2_config_geti(cfg, H2_CONF_PUSH)) {
            return "on";
        }
    }
    return "off";
}

static const char *val_H2_PUSHED(apr_pool_t *p, server_rec *s,
                                 conn_rec *c, request_rec *r, h2_ctx *ctx)
{
    if (ctx) {
        h2_task *task = h2_ctx_get_task(ctx);
        if (task && !H2_STREAM_CLIENT_INITIATED(task->stream_id)) {
            return "PUSHED";
        }
    }
    return "";
}

static const char *val_H2_PUSHED_ON(apr_pool_t *p, server_rec *s,
                                    conn_rec *c, request_rec *r, h2_ctx *ctx)
{
    if (ctx) {
        h2_task *task = h2_ctx_get_task(ctx);
        if (task && !H2_STREAM_CLIENT_INITIATED(task->stream_id)) {
            h2_stream *stream = h2_mplx_stream_get(task->mplx, task->stream_id);
            if (stream) {
                return apr_itoa(p, stream->initiated_on);
            }
        }
    }
    return "";
}

static const char *val_H2_STREAM_TAG(apr_pool_t *p, server_rec *s,
                                     conn_rec *c, request_rec *r, h2_ctx *ctx)
{
    if (ctx) {
        h2_task *task = h2_ctx_get_task(ctx);
        if (task) {
            return task->id;
        }
    }
    return "";
}

static const char *val_H2_STREAM_ID(apr_pool_t *p, server_rec *s,
                                    conn_rec *c, request_rec *r, h2_ctx *ctx)
{
    const char *cp = val_H2_STREAM_TAG(p, s, c, r, ctx);
    if (cp && (cp = ap_strchr_c(cp, '-'))) {
        return ++cp;
    }
    return NULL;
}

typedef const char *h2_var_lookup(apr_pool_t *p, server_rec *s,
                                  conn_rec *c, request_rec *r, h2_ctx *ctx);
typedef struct h2_var_def {
    const char *name;
    h2_var_lookup *lookup;
    unsigned int  subprocess : 1;    /* should be set in r->subprocess_env */
} h2_var_def;

static h2_var_def H2_VARS[] = {
    { "HTTP2",               val_HTTP2,  1 },
    { "H2PUSH",              val_H2_PUSH, 1 },
    { "H2_PUSH",             val_H2_PUSH, 1 },
    { "H2_PUSHED",           val_H2_PUSHED, 1 },
    { "H2_PUSHED_ON",        val_H2_PUSHED_ON, 1 },
    { "H2_STREAM_ID",        val_H2_STREAM_ID, 1 },
    { "H2_STREAM_TAG",       val_H2_STREAM_TAG, 1 },
};

#ifndef H2_ALEN
#define H2_ALEN(a)          (sizeof(a)/sizeof((a)[0]))
#endif


static int http2_is_h2(conn_rec *c)
{
    return h2_ctx_get(c->master? c->master : c, 0) != NULL;
}

static char *http2_var_lookup(apr_pool_t *p, server_rec *s,
                              conn_rec *c, request_rec *r, char *name)
{
    int i;
    /* If the # of vars grow, we need to put definitions in a hash */
    for (i = 0; i < H2_ALEN(H2_VARS); ++i) {
        h2_var_def *vdef = &H2_VARS[i];
        if (!strcmp(vdef->name, name)) {
            h2_ctx *ctx = (r? h2_ctx_rget(r) : 
                           h2_ctx_get(c->master? c->master : c, 0));
            return (char *)vdef->lookup(p, s, c, r, ctx);
        }
    }
    return (char*)"";
}

static int h2_h2_fixups(request_rec *r)
{
    if (r->connection->master) {
        h2_ctx *ctx = h2_ctx_rget(r);
        int i;
        
        for (i = 0; ctx && i < H2_ALEN(H2_VARS); ++i) {
            h2_var_def *vdef = &H2_VARS[i];
            if (vdef->subprocess) {
                apr_table_setn(r->subprocess_env, vdef->name, 
                               vdef->lookup(r->pool, r->server, r->connection, 
                                            r, ctx));
            }
        }
    }
    return DECLINED;
}
