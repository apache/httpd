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

#include <nghttp2/nghttp2.h>

#include <httpd.h>
#include <mod_proxy.h>
#include "mod_http2.h"


#include "mod_proxy_http2.h"
#include "h2_request.h"
#include "h2_proxy_util.h"
#include "h2_version.h"
#include "h2_proxy_session.h"

static void register_hook(apr_pool_t *p);

AP_DECLARE_MODULE(proxy_http2) = {
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    NULL,              /* command apr_table_t */
    register_hook      /* register hooks */
};

/* Optional functions from mod_http2 */
static int (*is_h2)(conn_rec *c);
static apr_status_t (*req_engine_push)(const char *name, request_rec *r, 
                                       http2_req_engine_init *einit);
static apr_status_t (*req_engine_pull)(h2_req_engine *engine, 
                                       apr_read_type_e block, 
                                       int capacity, 
                                       request_rec **pr);
static void (*req_engine_done)(h2_req_engine *engine, conn_rec *r_conn,
                               apr_status_t status);
                                       
typedef struct h2_proxy_ctx {
    conn_rec *owner;
    apr_pool_t *pool;
    request_rec *rbase;
    server_rec *server;
    const char *proxy_func;
    char server_portstr[32];
    proxy_conn_rec *p_conn;
    proxy_worker *worker;
    proxy_server_conf *conf;
    
    h2_req_engine *engine;
    const char *engine_id;
    const char *engine_type;
    apr_pool_t *engine_pool;    
    apr_size_t req_buffer_size;
    request_rec *next;
    int capacity;
    
    unsigned standalone : 1;
    unsigned is_ssl : 1;
    unsigned flushall : 1;
    
    apr_status_t r_status;     /* status of our first request work */
    h2_proxy_session *session; /* current http2 session against backend */
} h2_proxy_ctx;

static int h2_proxy_post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    const char *init_key = "mod_proxy_http2_init_counter";
    nghttp2_info *ngh2;
    apr_status_t status = APR_SUCCESS;
    (void)plog;(void)ptemp;
    
    apr_pool_userdata_get(&data, init_key, s->process->pool);
    if ( data == NULL ) {
        apr_pool_userdata_set((const void *)1, init_key,
                              apr_pool_cleanup_null, s->process->pool);
        return APR_SUCCESS;
    }
    
    ngh2 = nghttp2_version(0);
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(03349)
                 "mod_proxy_http2 (v%s, nghttp2 %s), initializing...",
                 MOD_HTTP2_VERSION, ngh2? ngh2->version_str : "unknown");
    
    is_h2 = APR_RETRIEVE_OPTIONAL_FN(http2_is_h2);
    req_engine_push = APR_RETRIEVE_OPTIONAL_FN(http2_req_engine_push);
    req_engine_pull = APR_RETRIEVE_OPTIONAL_FN(http2_req_engine_pull);
    req_engine_done = APR_RETRIEVE_OPTIONAL_FN(http2_req_engine_done);
    
    /* we need all of them */
    if (!req_engine_push || !req_engine_pull || !req_engine_done) {
        req_engine_push = NULL;
        req_engine_pull = NULL;
        req_engine_done = NULL;
    }
    
    return status;
}

/**
 * canonicalize the url into the request, if it is meant for us.
 * slightly modified copy from mod_http
 */
static int proxy_http2_canon(request_rec *r, char *url)
{
    char *host, *path, sport[7];
    char *search = NULL;
    const char *err;
    const char *scheme;
    const char *http_scheme;
    apr_port_t port, def_port;

    /* ap_port_of_scheme() */
    if (ap_cstr_casecmpn(url, "h2c:", 4) == 0) {
        url += 4;
        scheme = "h2c";
        http_scheme = "http";
    }
    else if (ap_cstr_casecmpn(url, "h2:", 3) == 0) {
        url += 3;
        scheme = "h2";
        http_scheme = "https";
    }
    else {
        return DECLINED;
    }
    port = def_port = ap_proxy_port_of_scheme(http_scheme);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                  "HTTP2: canonicalising URL %s", url);

    /* do syntatic check.
     * We break the URL into host, port, path, search
     */
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(03350)
                      "error parsing URL %s: %s", url, err);
        return HTTP_BAD_REQUEST;
    }

    /*
     * now parse path/search args, according to rfc1738:
     * process the path.
     *
     * In a reverse proxy, our URL has been processed, so canonicalise
     * unless proxy-nocanon is set to say it's raw
     * In a forward proxy, we have and MUST NOT MANGLE the original.
     */
    switch (r->proxyreq) {
    default: /* wtf are we doing here? */
    case PROXYREQ_REVERSE:
        if (apr_table_get(r->notes, "proxy-nocanon")) {
            path = url;   /* this is the raw path */
        }
        else {
            path = ap_proxy_canonenc(r->pool, url, (int)strlen(url),
                                     enc_path, 0, r->proxyreq);
            search = r->args;
        }
        break;
    case PROXYREQ_PROXY:
        path = url;
        break;
    }

    if (path == NULL) {
        return HTTP_BAD_REQUEST;
    }

    if (port != def_port) {
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    }
    else {
        sport[0] = '\0';
    }

    if (ap_strchr_c(host, ':')) { /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "://", host, sport,
            "/", path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}

static void out_consumed(void *baton, conn_rec *c, apr_off_t bytes)
{
    h2_proxy_ctx *ctx = baton;
    
    if (ctx->session) {
        h2_proxy_session_update_window(ctx->session, c, bytes);
    }
}

static apr_status_t proxy_engine_init(h2_req_engine *engine, 
                                        const char *id, 
                                        const char *type,
                                        apr_pool_t *pool, 
                                        apr_size_t req_buffer_size,
                                        request_rec *r,
                                        http2_output_consumed **pconsumed,
                                        void **pctx)
{
    h2_proxy_ctx *ctx = ap_get_module_config(r->connection->conn_config, 
                                             &proxy_http2_module);
    if (ctx) {
        conn_rec *c = ctx->owner;
        h2_proxy_ctx *nctx;
        
        /* we need another lifetime for this. If we do not host
         * an engine, the context lives in r->pool. Since we expect
         * to server more than r, we need to live longer */
        nctx = apr_pcalloc(pool, sizeof(*nctx));
        if (nctx == NULL) {
            return APR_ENOMEM;
        }
        memcpy(nctx, ctx, sizeof(*nctx));
        ctx = nctx;
        ctx->pool = pool;
        ctx->engine = engine;
        ctx->engine_id = id;
        ctx->engine_type = type;
        ctx->engine_pool = pool;
        ctx->req_buffer_size = req_buffer_size;
        ctx->capacity = 100;

        ap_set_module_config(c->conn_config, &proxy_http2_module, ctx);

        *pconsumed = out_consumed;
        *pctx = ctx;
        return APR_SUCCESS;
    }
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(03368)
                  "h2_proxy_session, engine init, no ctx found");
    return APR_ENOTIMPL;
}

static apr_status_t add_request(h2_proxy_session *session, request_rec *r)
{
    h2_proxy_ctx *ctx = session->user_data;
    const char *url;
    apr_status_t status;

    url = apr_table_get(r->notes, H2_PROXY_REQ_URL_NOTE);
    apr_table_setn(r->notes, "proxy-source-port", apr_psprintf(r->pool, "%hu",
                   ctx->p_conn->connection->local_addr->port));
    status = h2_proxy_session_submit(session, url, r, ctx->standalone);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, r->connection, APLOGNO(03351)
                      "pass request body failed to %pI (%s) from %s (%s)",
                      ctx->p_conn->addr, ctx->p_conn->hostname ? 
                      ctx->p_conn->hostname: "", session->c->client_ip, 
                      session->c->remote_host ? session->c->remote_host: "");
    }
    return status;
}

static void request_done(h2_proxy_session *session, request_rec *r,
                         apr_status_t status, int touched)
{   
    h2_proxy_ctx *ctx = session->user_data;
    const char *task_id = apr_table_get(r->connection->notes, H2_TASK_ID_NOTE);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, r->connection, 
                  "h2_proxy_session(%s): request done %s, touched=%d",
                  ctx->engine_id, task_id, touched);
    if (status != APR_SUCCESS) {
        if (!touched) {
            /* untouched request, need rescheduling */
            if (req_engine_push && is_h2 && is_h2(ctx->owner)) {
                if (req_engine_push(ctx->engine_type, r, NULL) == APR_SUCCESS) {
                    /* push to engine */
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, r->connection, 
                                  APLOGNO(03369)
                                  "h2_proxy_session(%s): rescheduled request %s",
                                  ctx->engine_id, task_id);
                    return;
                }
            }
            else if (!ctx->next) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, r->connection, 
                              "h2_proxy_session(%s): retry untouched request",
                              ctx->engine_id);
                ctx->next = r;
            }
        }
        else {
            const char *uri;
            uri = apr_uri_unparse(r->pool, &r->parsed_uri, 0);
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, r->connection, 
                          APLOGNO(03471) "h2_proxy_session(%s): request %s -> %s "
                          "not complete, was touched",
                          ctx->engine_id, task_id, uri);
        }
    }
    
    if (r == ctx->rbase) {
        ctx->r_status = (status == APR_SUCCESS)? APR_SUCCESS : HTTP_SERVICE_UNAVAILABLE;
    }
    
    if (req_engine_done && ctx->engine) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, r->connection, 
                      APLOGNO(03370)
                      "h2_proxy_session(%s): finished request %s",
                      ctx->engine_id, task_id);
        req_engine_done(ctx->engine, r->connection, status);
    }
}    

static apr_status_t next_request(h2_proxy_ctx *ctx, int before_leave)
{
    if (ctx->next) {
        return APR_SUCCESS;
    }
    else if (req_engine_pull && ctx->engine) {
        apr_status_t status;
        status = req_engine_pull(ctx->engine, before_leave? 
                                 APR_BLOCK_READ: APR_NONBLOCK_READ, 
                                 ctx->capacity, &ctx->next);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, ctx->owner, 
                      "h2_proxy_engine(%s): pulled request (%s) %s", 
                      ctx->engine_id, 
                      before_leave? "before leave" : "regular", 
                      (ctx->next? ctx->next->the_request : "NULL"));
        return APR_STATUS_IS_EAGAIN(status)? APR_SUCCESS : status;
    }
    return APR_EOF;
}

static apr_status_t proxy_engine_run(h2_proxy_ctx *ctx) {
    apr_status_t status = OK;
    int h2_front;
    
    /* Step Four: Send the Request in a new HTTP/2 stream and
     * loop until we got the response or encounter errors.
     */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, ctx->owner, 
                  "eng(%s): setup session", ctx->engine_id);
    h2_front = is_h2? is_h2(ctx->owner) : 0;
    ctx->session = h2_proxy_session_setup(ctx->engine_id, ctx->p_conn, ctx->conf,
                                          h2_front, 30, 
                                          h2_proxy_log2((int)ctx->req_buffer_size), 
                                          request_done);
    if (!ctx->session) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->owner, 
                      APLOGNO(03372) "session unavailable");
        return HTTP_SERVICE_UNAVAILABLE;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->owner, APLOGNO(03373)
                  "eng(%s): run session %s", ctx->engine_id, ctx->session->id);
    ctx->session->user_data = ctx;
    
    while (1) {
        if (ctx->next) {
            add_request(ctx->session, ctx->next);
            ctx->next = NULL;
        }
        
        status = h2_proxy_session_process(ctx->session);
        
        if (status == APR_SUCCESS) {
            apr_status_t s2;
            /* ongoing processing, call again */
            if (ctx->session->remote_max_concurrent > 0
                && ctx->session->remote_max_concurrent != ctx->capacity) {
                ctx->capacity = (int)ctx->session->remote_max_concurrent;
            }
            s2 = next_request(ctx, 0);
            if (s2 == APR_ECONNABORTED) {
                /* master connection gone */
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, s2, ctx->owner, 
                              APLOGNO(03374) "eng(%s): pull request", 
                              ctx->engine_id);
                /* give notice that we're leaving and cancel all ongoing
                 * streams. */
                next_request(ctx, 1); 
                h2_proxy_session_cancel_all(ctx->session);
                h2_proxy_session_process(ctx->session);
                status = ctx->r_status = APR_SUCCESS;
                break;
            }
            if (!ctx->next && h2_proxy_ihash_empty(ctx->session->streams)) {
                break;
            }
        }
        else {
            /* end of processing, maybe error */
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, ctx->owner, 
                          APLOGNO(03375) "eng(%s): end of session %s", 
                          ctx->engine_id, ctx->session->id);
            /*
             * Any open stream of that session needs to
             * a) be reopened on the new session iff safe to do so
             * b) reported as done (failed) otherwise
             */
            h2_proxy_session_cleanup(ctx->session, request_done);
            break;
        }
    }
    
    ctx->session->user_data = NULL;
    ctx->session = NULL;
    
    return status;
}

static h2_proxy_ctx *push_request_somewhere(h2_proxy_ctx *ctx)
{
    conn_rec *c = ctx->owner;
    const char *engine_type, *hostname;
    
    hostname = (ctx->p_conn->ssl_hostname? 
                ctx->p_conn->ssl_hostname : ctx->p_conn->hostname);
    engine_type = apr_psprintf(ctx->pool, "proxy_http2 %s%s", hostname, 
                               ctx->server_portstr);
    
    if (c->master && req_engine_push && ctx->next && is_h2 && is_h2(c)) {
        /* If we are have req_engine capabilities, push the handling of this
         * request (e.g. slave connection) to a proxy_http2 engine which 
         * uses the same backend. We may be called to create an engine 
         * ourself. */
        if (req_engine_push(engine_type, ctx->next, proxy_engine_init)
            == APR_SUCCESS) {
            /* to renew the lifetime, we might have set a new ctx */
            ctx = ap_get_module_config(c->conn_config, &proxy_http2_module);
            if (ctx->engine == NULL) {
                /* Another engine instance has taken over processing of this
                 * request. */
                ctx->r_status = SUSPENDED;
                ctx->next = NULL;
                return ctx;
            }
        }
    }
    
    if (!ctx->engine) {
        /* No engine was available or has been initialized, handle this
         * request just by ourself. */
        ctx->engine_id = apr_psprintf(ctx->pool, "eng-proxy-%ld", c->id);
        ctx->engine_type = engine_type;
        ctx->engine_pool = ctx->pool;
        ctx->req_buffer_size = (32*1024);
        ctx->standalone = 1;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, 
                      "h2_proxy_http2(%ld): setup standalone engine for type %s", 
                      c->id, engine_type);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, 
                      "H2: hosting engine %s", ctx->engine_id);
    }
    return ctx;
}

static int proxy_http2_handler(request_rec *r, 
                               proxy_worker *worker,
                               proxy_server_conf *conf,
                               char *url, 
                               const char *proxyname,
                               apr_port_t proxyport)
{
    const char *proxy_func;
    char *locurl = url, *u;
    apr_size_t slen;
    int is_ssl = 0;
    apr_status_t status;
    h2_proxy_ctx *ctx;
    apr_uri_t uri;
    int reconnected = 0;
    
    /* find the scheme */
    if ((url[0] != 'h' && url[0] != 'H') || url[1] != '2') {
       return DECLINED;
    }
    u = strchr(url, ':');
    if (u == NULL || u[1] != '/' || u[2] != '/' || u[3] == '\0') {
       return DECLINED;
    }
    slen = (u - url);
    switch(slen) {
        case 2:
            proxy_func = "H2";
            is_ssl = 1;
            break;
        case 3:
            if (url[2] != 'c' && url[2] != 'C') {
                return DECLINED;
            }
            proxy_func = "H2C";
            break;
        default:
            return DECLINED;
    }
    ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    ctx->owner      = r->connection;
    ctx->pool       = r->pool;
    ctx->rbase      = r;
    ctx->server     = r->server;
    ctx->proxy_func = proxy_func;
    ctx->is_ssl     = is_ssl;
    ctx->worker     = worker;
    ctx->conf       = conf;
    ctx->flushall   = apr_table_get(r->subprocess_env, "proxy-flushall")? 1 : 0;
    ctx->r_status   = HTTP_SERVICE_UNAVAILABLE;
    ctx->next       = r;
    r = NULL;
    ap_set_module_config(ctx->owner->conn_config, &proxy_http2_module, ctx);

    /* scheme says, this is for us. */
    apr_table_setn(ctx->rbase->notes, H2_PROXY_REQ_URL_NOTE, url);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, ctx->rbase, 
                  "H2: serving URL %s", url);
    
run_connect:    
    /* Get a proxy_conn_rec from the worker, might be a new one, might
     * be one still open from another request, or it might fail if the
     * worker is stopped or in error. */
    if ((status = ap_proxy_acquire_connection(ctx->proxy_func, &ctx->p_conn,
                                              ctx->worker, ctx->server)) != OK) {
        goto cleanup;
    }

    ctx->p_conn->is_ssl = ctx->is_ssl;
    if (ctx->is_ssl && ctx->p_conn->connection) {
        /* If there are some metadata on the connection (e.g. TLS alert),
         * let mod_ssl detect them, and create a new connection below.
         */ 
        apr_bucket_brigade *tmp_bb;
        tmp_bb = apr_brigade_create(ctx->rbase->pool, 
                                    ctx->rbase->connection->bucket_alloc);
        status = ap_get_brigade(ctx->p_conn->connection->input_filters, tmp_bb,
                                AP_MODE_SPECULATIVE, APR_NONBLOCK_READ, 1);
        if (status != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(status)) {
            ctx->p_conn->close = 1;
        }
        apr_brigade_cleanup(tmp_bb);
    }   

    /* Step One: Determine the URL to connect to (might be a proxy),
     * initialize the backend accordingly and determine the server 
     * port string we can expect in responses. */
    if ((status = ap_proxy_determine_connection(ctx->pool, ctx->rbase, conf, worker, 
                                                ctx->p_conn, &uri, &locurl, 
                                                proxyname, proxyport, 
                                                ctx->server_portstr,
                                                sizeof(ctx->server_portstr))) != OK) {
        goto cleanup;
    }
    
    /* If we are not already hosting an engine, try to push the request 
     * to an already existing engine or host a new engine here. */
    if (!ctx->engine) {
        ctx = push_request_somewhere(ctx);
        if (ctx->r_status == SUSPENDED) {
            /* request was pushed to another engine */
            goto cleanup;
        }
    }
    
    /* Step Two: Make the Connection (or check that an already existing
     * socket is still usable). On success, we have a socket connected to
     * backend->hostname. */
    if (ap_proxy_connect_backend(ctx->proxy_func, ctx->p_conn, ctx->worker, 
                                 ctx->server)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->owner, APLOGNO(03352)
                      "H2: failed to make connection to backend: %s",
                      ctx->p_conn->hostname);
        goto cleanup;
    }
    
    /* Step Three: Create conn_rec for the socket we have open now. */
    if (!ctx->p_conn->connection) {
        if ((status = ap_proxy_connection_create(ctx->proxy_func, ctx->p_conn,
                                                 ctx->owner, 
                                                 ctx->server)) != OK) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, ctx->owner, APLOGNO(03353)
                          "setup new connection: is_ssl=%d %s %s %s", 
                          ctx->p_conn->is_ssl, ctx->p_conn->ssl_hostname, 
                          locurl, ctx->p_conn->hostname);
            goto cleanup;
        }
        
        if (!ctx->p_conn->data) {
            /* New conection: set a note on the connection what CN is
             * requested and what protocol we want */
            if (ctx->p_conn->ssl_hostname) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, ctx->owner, 
                              "set SNI to %s for (%s)", 
                              ctx->p_conn->ssl_hostname, 
                              ctx->p_conn->hostname);
                apr_table_setn(ctx->p_conn->connection->notes,
                               "proxy-request-hostname", ctx->p_conn->ssl_hostname);
            }
            if (ctx->is_ssl) {
                apr_table_setn(ctx->p_conn->connection->notes,
                               "proxy-request-alpn-protos", "h2");
            }
        }
    }

run_session:
    status = proxy_engine_run(ctx);
    if (status == APR_SUCCESS) {
        /* session and connection still ok */
        if (next_request(ctx, 1) == APR_SUCCESS) {
            /* more requests, run again */
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->owner, APLOGNO(03376)
                          "run_session, again");
            goto run_session;
        }
        /* done */
        ctx->engine = NULL;
    }

cleanup:
    if (!reconnected && next_request(ctx, 1) == APR_SUCCESS) {
        /* Still more to do, tear down old conn and start over */
        if (ctx->p_conn) {
            ctx->p_conn->close = 1;
            /*only in trunk so far */
            /*proxy_run_detach_backend(r, ctx->p_conn);*/
            ap_proxy_release_connection(ctx->proxy_func, ctx->p_conn, ctx->server);
            ctx->p_conn = NULL;
        }
        reconnected = 1; /* we do this only once, then fail */
        goto run_connect;
    }
    
    if (ctx->p_conn) {
        if (status != APR_SUCCESS) {
            /* close socket when errors happened or session shut down (EOF) */
            ctx->p_conn->close = 1;
        }
        /*only in trunk so far */
        /*proxy_run_detach_backend(ctx->rbase, ctx->p_conn);*/
        ap_proxy_release_connection(ctx->proxy_func, ctx->p_conn, ctx->server);
        ctx->p_conn = NULL;
    }

    ap_set_module_config(ctx->owner->conn_config, &proxy_http2_module, NULL);
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, ctx->owner, 
                  APLOGNO(03377) "leaving handler");
    return ctx->r_status;
}

static void register_hook(apr_pool_t *p)
{
    ap_hook_post_config(h2_proxy_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    proxy_hook_scheme_handler(proxy_http2_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_http2_canon, NULL, NULL, APR_HOOK_FIRST);
}

