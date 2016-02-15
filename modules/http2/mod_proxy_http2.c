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
#include <mod_http2.h>


#include "mod_proxy_http2.h"
#include "h2_request.h"
#include "h2_util.h"
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
                                       h2_req_engine_init *einit);
static apr_status_t (*req_engine_pull)(h2_req_engine *engine, 
                                       apr_time_t timeout, request_rec **pr);
static void (*req_engine_done)(h2_req_engine *engine, conn_rec *r_conn);
static void (*req_engine_exit)(h2_req_engine *engine);
                                       
typedef struct h2_proxy_ctx {
    conn_rec *owner;
    server_rec *server;
    const char *proxy_func;
    char server_portstr[32];
    proxy_conn_rec *p_conn;
    proxy_worker *worker;
    proxy_server_conf *conf;
    
    h2_req_engine *engine;
    unsigned standalone : 1;
    unsigned is_ssl : 1;
    unsigned flushall : 1;
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
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO()
                 "mod_proxy_http2 (v%s, nghttp2 %s), initializing...",
                 MOD_HTTP2_VERSION, ngh2? ngh2->version_str : "unknown");
    
    is_h2 = APR_RETRIEVE_OPTIONAL_FN(http2_is_h2);
    req_engine_push = APR_RETRIEVE_OPTIONAL_FN(http2_req_engine_push);
    req_engine_pull = APR_RETRIEVE_OPTIONAL_FN(http2_req_engine_pull);
    req_engine_done = APR_RETRIEVE_OPTIONAL_FN(http2_req_engine_done);
    req_engine_exit = APR_RETRIEVE_OPTIONAL_FN(http2_req_engine_exit);
    
    /* we need all of them */
    if (!req_engine_push || !req_engine_pull 
        || !req_engine_done || !req_engine_exit) {
        req_engine_push = NULL;
        req_engine_pull = NULL;
        req_engine_done = NULL;
        req_engine_exit = NULL;
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
    if (ap_casecmpstrn(url, "h2c:", 4) == 0) {
        url += 4;
        scheme = "h2c";
        http_scheme = "http";
    }
    else if (ap_casecmpstrn(url, "h2:", 3) == 0) {
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
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
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
            path = ap_proxy_canonenc(r->pool, url, strlen(url),
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

static apr_status_t proxy_engine_init(h2_req_engine *engine, request_rec *r)
{
    h2_proxy_ctx *ctx = ap_get_module_config(engine->c->conn_config, 
                                             &proxy_http2_module);
    if (ctx) {
        ctx->engine = engine;
        return APR_SUCCESS;
    }
    return APR_ENOTIMPL;
}

static int proxy_engine_run(h2_proxy_ctx *ctx, request_rec *r) {
    int status = OK;
    h2_proxy_session *session;
    h2_proxy_stream *stream;
    
    /* Step Two: Make the Connection (or check that an already existing
     * socket is still usable). On success, we have a socket connected to
     * backend->hostname. */
    if (ap_proxy_connect_backend(ctx->proxy_func, ctx->p_conn, ctx->worker, 
                                 ctx->server)) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, ctx->owner, APLOGNO()
                      "H2: failed to make connection to backend: %s",
                      ctx->p_conn->hostname);
        return HTTP_SERVICE_UNAVAILABLE;
    }
    
    /* Step Three: Create conn_rec for the socket we have open now. */
    if (!ctx->p_conn->connection) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, ctx->owner, APLOGNO()
                      "setup new connection: is_ssl=%d %s %s %s", 
                      ctx->p_conn->is_ssl, ctx->p_conn->ssl_hostname, 
                      r->hostname, ctx->p_conn->hostname);
        if ((status = ap_proxy_connection_create(ctx->proxy_func, ctx->p_conn,
                                                 ctx->owner, 
                                                 ctx->server)) != OK) {
            return status;
        }
        
        /*
         * On SSL connections set a note on the connection what CN is
         * requested, such that mod_ssl can check if it is requested to do
         * so.
         */
        if (ctx->p_conn->ssl_hostname) {
            apr_table_setn(ctx->p_conn->connection->notes,
                           "proxy-request-hostname", ctx->p_conn->ssl_hostname);
        }
        
        if (ctx->is_ssl) {
            apr_table_setn(ctx->p_conn->connection->notes,
                           "proxy-request-alpn-protos", "h2");
        }
    }

    /* Step Four: Send the Request in a new HTTP/2 stream and
     * loop until we got the response or encounter errors.
     */
    status = APR_ENOTIMPL;
    session = h2_proxy_session_setup(r, ctx->p_conn, ctx->conf);
    if (!session) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->p_conn->connection, 
                      "session unavailable");
        return HTTP_SERVICE_UNAVAILABLE;
    }
    
    while (r) {
        conn_rec *r_conn = r->connection;
        const char *url;
        
        url = apr_table_get(r->notes, H2_PROXY_REQ_URL_NOTE);
        status = h2_proxy_session_open_stream(session, url, r, &stream);
        if (status == OK) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, r_conn, 
                          "process stream(%d): %s %s%s, original: %s", 
                          stream->id, stream->req->method, 
                          stream->req->authority, stream->req->path, 
                          r->the_request);
            status = h2_proxy_stream_process(stream);
        }
        r = NULL;
        
        if (status != OK) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, r_conn, APLOGNO()
                          "pass request body failed to %pI (%s) from %s (%s)",
                          ctx->p_conn->addr, ctx->p_conn->hostname ? 
                          ctx->p_conn->hostname: "", session->c->client_ip, 
                          session->c->remote_host ? session->c->remote_host: "");
        }
        
        if (!ctx->standalone && req_engine_done && r_conn != ctx->owner) {
            req_engine_done(ctx->engine, r_conn);
        }
        r_conn = NULL;
        
        if (!ctx->standalone && req_engine_pull) {
            status = req_engine_pull(ctx->engine, ctx->server->timeout, &r);
            if (status != APR_SUCCESS) {
                status = APR_SUCCESS;
                break;
            }
        }
    }
    
    return status;
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
    conn_rec *c = r->connection;
    server_rec *s = r->server;
    apr_pool_t *p = c->pool;
    apr_uri_t *uri = apr_palloc(p, sizeof(*uri));
    h2_proxy_ctx *ctx;
    const char *engine_type, *hostname;

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

    ctx = apr_pcalloc(p, sizeof(*ctx));
    ctx->owner      = c;
    ctx->server     = s;
    ctx->proxy_func = proxy_func;
    ctx->is_ssl     = is_ssl;
    ctx->worker     = worker;
    ctx->conf       = conf;
    ctx->flushall   = apr_table_get(r->subprocess_env, "proxy-flushall")? 1 : 0;
    
    ap_set_module_config(c->conn_config, &proxy_http2_module, ctx);
    apr_table_setn(r->notes, H2_PROXY_REQ_URL_NOTE, url);

    /* scheme says, this is for us. */
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "H2: serving URL %s", url);

    /* Get a proxy_conn_rec from the worker, might be a new one, might
     * be one still open from another request, or it might fail if the
     * worker is stopped or in error. */
    if ((status = ap_proxy_acquire_connection(ctx->proxy_func, &ctx->p_conn,
                                              ctx->worker, s)) != OK) {
        goto cleanup;
    }

    ctx->p_conn->is_ssl = ctx->is_ssl;
    if (ctx->is_ssl) {
        /* If there is still some data on an existing ssl connection, now
         * would be a good timne to get rid of it. */
        ap_proxy_ssl_connection_cleanup(ctx->p_conn, r);
    }

    /* Step One: Determine the URL to connect to (might be a proxy),
     * initialize the backend accordingly and determine the server 
     * port string we can expect in responses. */
    if ((status = ap_proxy_determine_connection(p, r, conf, worker, ctx->p_conn,
                                                uri, &locurl, proxyname,
                                                proxyport, ctx->server_portstr,
                                                sizeof(ctx->server_portstr))) != OK) {
        goto cleanup;
    }
    
    hostname = (ctx->p_conn->ssl_hostname? 
                ctx->p_conn->ssl_hostname : ctx->p_conn->hostname);
    engine_type = apr_psprintf(p, "proxy_http2 %s%s", hostname, ctx->server_portstr);
    
    if (c->master && req_engine_push && is_h2 && is_h2(ctx->owner)) {
        /* If we are have req_engine capabilities, push the handling of this
         * request (e.g. slave connection) to a proxy_http2 engine which uses 
         * the same backend. We may be called to create an engine ourself.
         */
        status = req_engine_push(engine_type, r, proxy_engine_init);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, status, r, 
                      "H2: pushing request %s to engine type %s", 
                      url, engine_type);
        if (status == APR_SUCCESS && ctx->engine == NULL) {
            /* Another engine instance has taken over processing of this
             * request. */
            goto cleanup;
        }
    }
    
    if (!ctx->engine) {
        /* No engine was available or has been initialized, handle this
        * request just by ourself. */
        h2_req_engine *engine = apr_pcalloc(p, sizeof(*engine));
        engine->id = 0;
        engine->type = engine_type;
        engine->pool = p;
        engine->c = c;
        ctx->engine = engine;
        ctx->standalone = 1;
    }
    
    status = proxy_engine_run(ctx, r);    

cleanup:
    if (ctx->engine && !ctx->standalone && req_engine_exit) {
        req_engine_exit(ctx->engine);
    }
    ctx->engine = NULL;
    
    if (ctx) {
        if (ctx->p_conn) {
            if (status != OK) {
                ctx->p_conn->close = 1;
            }
            proxy_run_detach_backend(r, ctx->p_conn);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "cleanup, releasing connection");
            ap_proxy_release_connection(ctx->proxy_func, ctx->p_conn, ctx->server);
        }
        ctx->worker = NULL;
        ctx->conf = NULL;
        ctx->p_conn = NULL;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c, "leaving handler");
    return status;
}

static void register_hook(apr_pool_t *p)
{
    ap_hook_post_config(h2_proxy_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    proxy_hook_scheme_handler(proxy_http2_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_http2_canon, NULL, NULL, APR_HOOK_FIRST);
}

