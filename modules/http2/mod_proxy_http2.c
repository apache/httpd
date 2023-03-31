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
 
#include <nghttp2/nghttp2.h>

#include <ap_mmn.h>
#include <httpd.h>
#include <mod_proxy.h>
#include "mod_http2.h"


#include "mod_proxy_http2.h"
#include "h2.h"
#include "h2_proxy_util.h"
#include "h2_version.h"
#include "h2_proxy_session.h"

#define H2MIN(x,y) ((x) < (y) ? (x) : (y))

static void register_hook(apr_pool_t *p);

AP_DECLARE_MODULE(proxy_http2) = {
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    NULL,              /* command apr_table_t */
    register_hook,     /* register hooks */
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};

/* Optional functions from mod_http2 */
static int (*is_h2)(conn_rec *c);

typedef struct h2_proxy_ctx {
    const char *id;
    conn_rec *master;
    conn_rec *owner;
    apr_pool_t *pool;
    server_rec *server;
    const char *proxy_func;
    char server_portstr[32];
    proxy_conn_rec *p_conn;
    proxy_worker *worker;
    proxy_server_conf *conf;
    
    apr_size_t req_buffer_size;
    int capacity;
    
    unsigned is_ssl : 1;
    
    request_rec *r;            /* the request processed in this ctx */
    apr_status_t r_status;     /* status of request work */
    int r_done;                /* request was processed, not necessarily successfully */
    int r_may_retry;           /* request may be retried */
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
        else if (apr_table_get(r->notes, "proxy-noencode")) {
            path = url;   /* this is the encoded path already */
            search = r->args;
        }
        else {
            core_dir_config *d = ap_get_core_module_config(r->per_dir_config);
            int flags = d->allow_encoded_slashes && !d->decode_encoded_slashes ? PROXY_CANONENC_NOENCODEDSLASHENCODING : 0;

            path = ap_proxy_canonenc_ex(r->pool, url, (int)strlen(url),
                                        enc_path, flags, r->proxyreq);
            if (!path) {
                return HTTP_BAD_REQUEST;
            }
            search = r->args;
        }
        break;
    case PROXYREQ_PROXY:
        path = url;
        break;
    }
    /*
     * If we have a raw control character or a ' ' in nocanon path or
     * r->args, correct encoding was missed.
     */
    if (path == url && *ap_scan_vchar_obstext(path)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10420)
                      "To be forwarded path contains control "
                      "characters or spaces");
        return HTTP_FORBIDDEN;
    }
    if (search && *ap_scan_vchar_obstext(search)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10412)
                      "To be forwarded query string contains control "
                      "characters or spaces");
        return HTTP_FORBIDDEN;
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

static apr_status_t add_request(h2_proxy_session *session, request_rec *r)
{
    h2_proxy_ctx *ctx = session->user_data;
    const char *url;
    apr_status_t status;

    url = apr_table_get(r->notes, H2_PROXY_REQ_URL_NOTE);
    apr_table_setn(r->notes, "proxy-source-port", apr_psprintf(r->pool, "%hu",
                   ctx->p_conn->connection->local_addr->port));
    status = h2_proxy_session_submit(session, url, r, 1);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, r->connection, APLOGNO(03351)
                      "pass request body failed to %pI (%s) from %s (%s)",
                      ctx->p_conn->addr, ctx->p_conn->hostname ? 
                      ctx->p_conn->hostname: "", session->c->client_ip, 
                      session->c->remote_host ? session->c->remote_host: "");
    }
    return status;
}

static void request_done(h2_proxy_ctx *ctx, request_rec *r,
                         apr_status_t status, int touched)
{   
    if (r == ctx->r) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, r->connection, 
                      "h2_proxy_session(%s): request done, touched=%d",
                      ctx->id, touched);
        ctx->r_done = 1;
        if (touched) ctx->r_may_retry = 0;
        ctx->r_status = ((status == APR_SUCCESS)? APR_SUCCESS
                         : HTTP_SERVICE_UNAVAILABLE);
    }
}    

static void session_req_done(h2_proxy_session *session, request_rec *r,
                             apr_status_t status, int touched)
{
    request_done(session->user_data, r, status, touched);
}

static apr_status_t ctx_run(h2_proxy_ctx *ctx) {
    apr_status_t status = OK;
    int h2_front;
    
    /* Step Four: Send the Request in a new HTTP/2 stream and
     * loop until we got the response or encounter errors.
     */
    h2_front = is_h2? is_h2(ctx->owner) : 0;
    ctx->session = h2_proxy_session_setup(ctx->id, ctx->p_conn, ctx->conf,
                                          h2_front, 30, 
                                          h2_proxy_log2((int)ctx->req_buffer_size), 
                                          session_req_done);
    if (!ctx->session) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->owner, 
                      APLOGNO(03372) "session unavailable");
        return HTTP_SERVICE_UNAVAILABLE;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->owner, APLOGNO(03373)
                  "eng(%s): run session %s", ctx->id, ctx->session->id);
    ctx->session->user_data = ctx;
    
    ctx->r_done = 0;
    add_request(ctx->session, ctx->r);
    
    while (!ctx->owner->aborted && !ctx->r_done) {
    
        status = h2_proxy_session_process(ctx->session);
        if (status != APR_SUCCESS) {
            /* Encountered an error during session processing */
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, ctx->owner, 
                          APLOGNO(03375) "eng(%s): end of session %s", 
                          ctx->id, ctx->session->id);
            /* Any open stream of that session needs to
             * a) be reopened on the new session iff safe to do so
             * b) reported as done (failed) otherwise
             */
            h2_proxy_session_cleanup(ctx->session, session_req_done);
            goto out;
        }
    }
    
out:
    if (ctx->owner->aborted) {
        /* master connection gone */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, ctx->owner, 
                      APLOGNO(03374) "eng(%s): master connection gone", ctx->id);
        /* cancel all ongoing requests */
        h2_proxy_session_cancel_all(ctx->session);
        h2_proxy_session_process(ctx->session);
    }
    
    ctx->session->user_data = NULL;
    ctx->session = NULL;
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
    h2_proxy_ctx *ctx;
    apr_uri_t uri;
    int reconnects = 0;
    
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
    ctx->master = r->connection->master? r->connection->master : r->connection;
    ctx->id = apr_psprintf(r->pool, "%ld", (long)ctx->master->id);
    ctx->owner = r->connection;
    ctx->pool = r->pool;
    ctx->server = r->server;
    ctx->proxy_func = proxy_func;
    ctx->is_ssl = is_ssl;
    ctx->worker = worker;
    ctx->conf = conf;
    ctx->req_buffer_size = (32*1024);
    ctx->r = r;
    ctx->r_status = status = HTTP_SERVICE_UNAVAILABLE;
    ctx->r_done = 0;
    ctx->r_may_retry =  1;
    
    ap_set_module_config(ctx->owner->conn_config, &proxy_http2_module, ctx);

    /* scheme says, this is for us. */
    apr_table_setn(ctx->r->notes, H2_PROXY_REQ_URL_NOTE, url);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, ctx->r, 
                  "H2: serving URL %s", url);
    
run_connect:    
    if (ctx->owner->aborted) goto cleanup;

    /* Get a proxy_conn_rec from the worker, might be a new one, might
     * be one still open from another request, or it might fail if the
     * worker is stopped or in error. */
    if ((status = ap_proxy_acquire_connection(ctx->proxy_func, &ctx->p_conn,
                                              ctx->worker, ctx->server)) != OK) {
        goto cleanup;
    }

    ctx->p_conn->is_ssl = ctx->is_ssl;

    /* Step One: Determine the URL to connect to (might be a proxy),
     * initialize the backend accordingly and determine the server 
     * port string we can expect in responses. */
    if ((status = ap_proxy_determine_connection(ctx->pool, ctx->r, conf, worker, 
                                                ctx->p_conn, &uri, &locurl, 
                                                proxyname, proxyport, 
                                                ctx->server_portstr,
                                                sizeof(ctx->server_portstr))) != OK) {
        goto cleanup;
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
    status = ap_proxy_connection_create_ex(ctx->proxy_func, ctx->p_conn, ctx->r);
    if (status != OK) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, ctx->owner, APLOGNO(03353)
                      "setup new connection: is_ssl=%d %s %s %s", 
                      ctx->p_conn->is_ssl, ctx->p_conn->ssl_hostname, 
                      locurl, ctx->p_conn->hostname);
        ctx->r_status = status;
        goto cleanup;
    }
    
    if (!ctx->p_conn->data && ctx->is_ssl) {
        /* New SSL connection: set a note on the connection about what
         * protocol we need. */
        apr_table_setn(ctx->p_conn->connection->notes,
                       "proxy-request-alpn-protos", "h2");
    }

    if (ctx->owner->aborted) goto cleanup;
    status = ctx_run(ctx);

    if (ctx->r_status != APR_SUCCESS && ctx->r_may_retry && !ctx->owner->aborted) {
        /* Not successfully processed, but may retry, tear down old conn and start over */
        if (ctx->p_conn) {
            ctx->p_conn->close = 1;
#if AP_MODULE_MAGIC_AT_LEAST(20140207, 2)
            proxy_run_detach_backend(r, ctx->p_conn);
#endif
            ap_proxy_release_connection(ctx->proxy_func, ctx->p_conn, ctx->server);
            ctx->p_conn = NULL;
        }
        ++reconnects;
        if (reconnects < 2) {
            goto run_connect;
        } 
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->owner, APLOGNO(10023)
                      "giving up after %d reconnects, request-done=%d",
                      reconnects, ctx->r_done);
    }
    
cleanup:
    if (ctx->p_conn) {
        if (status != APR_SUCCESS) {
            /* close socket when errors happened or session shut down (EOF) */
            ctx->p_conn->close = 1;
        }
#if AP_MODULE_MAGIC_AT_LEAST(20140207, 2)
        proxy_run_detach_backend(ctx->r, ctx->p_conn);
#endif
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

