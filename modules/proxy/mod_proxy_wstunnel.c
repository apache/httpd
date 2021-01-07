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
#include "http_config.h"
#include "ap_mpm.h"

module AP_MODULE_DECLARE_DATA proxy_wstunnel_module;

typedef struct {
    int mpm_can_poll;
    apr_time_t idle_timeout;
    apr_time_t async_delay;
} proxyws_dir_conf;

typedef struct ws_baton_t {
    request_rec *r;
    proxy_conn_rec *backend;
    proxy_tunnel_rec *tunnel;
    apr_pool_t *async_pool;
    const char *scheme;
} ws_baton_t;

static int fallback_to_mod_proxy_http;

static void proxy_wstunnel_callback(void *b);

static int proxy_wstunnel_pump(ws_baton_t *baton, int async)
{
    int status = ap_proxy_tunnel_run(baton->tunnel);
    if (status == HTTP_GATEWAY_TIME_OUT) {
        if (!async) {
            /* ap_proxy_tunnel_run() didn't log this */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, baton->r, APLOGNO(10225)
                          "Tunnel timed out");
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, baton->r, APLOGNO(02542)
                          "Attempting to go async");
            status = SUSPENDED;
        }
    }
    return status;
}

static void proxy_wstunnel_finish(ws_baton_t *baton)
{ 
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, baton->r, "proxy_wstunnel_finish");
    ap_proxy_release_connection(baton->scheme, baton->backend, baton->r->server);
    ap_finalize_request_protocol(baton->r);
    ap_lingering_close(baton->r->connection);
    ap_mpm_resume_suspended(baton->r->connection);
    ap_process_request_after_handler(baton->r); /* don't touch baton or r after here */
}

/* If neither socket becomes readable in the specified timeout,
 * this callback will kill the request.  We do not have to worry about
 * having a cancel and a IO both queued.
 */
static void proxy_wstunnel_cancel_callback(void *b)
{ 
    ws_baton_t *baton = (ws_baton_t*)b;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, baton->r,
                  "proxy_wstunnel_cancel_callback, IO timed out");
    proxy_wstunnel_finish(baton);
}

/* Invoked by the event loop when data is ready on either end. 
 *  Pump both ends until they'd block and then start over again 
 *  We don't need the invoke_mtx, since we never put multiple callback events
 *  in the queue.
 */
static void proxy_wstunnel_callback(void *b)
{ 
    ws_baton_t *baton = (ws_baton_t*)b;

    /* Clear MPM's temporary data */
    AP_DEBUG_ASSERT(baton->async_pool != NULL);
    apr_pool_clear(baton->async_pool);

    if (proxy_wstunnel_pump(baton, 1) == SUSPENDED) {
        proxyws_dir_conf *dconf = ap_get_module_config(baton->r->per_dir_config,
                                                       &proxy_wstunnel_module);

        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, baton->r,
                      "proxy_wstunnel_callback suspend");

        ap_mpm_register_poll_callback_timeout(baton->async_pool,
                                              baton->tunnel->pfds,
                                              proxy_wstunnel_callback, 
                                              proxy_wstunnel_cancel_callback, 
                                              baton, dconf->idle_timeout);
    }
    else { 
        proxy_wstunnel_finish(baton);
    }
}

static int proxy_wstunnel_check_trans(request_rec *r, const char *url)
{
    if (fallback_to_mod_proxy_http) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "check_trans fallback");
        return DECLINED;
    }

    if (ap_cstr_casecmpn(url, "ws:", 3) != 0
            && ap_cstr_casecmpn(url, "wss:", 4) != 0) {
        return DECLINED;
    }

    if (!apr_table_get(r->headers_in, "Upgrade")) {
        /* No Upgrade, let mod_proxy_http handle it (for instance).
         * Note: anything but OK/DECLINED will do (i.e. bypass wstunnel w/o
         * aborting the request), HTTP_UPGRADE_REQUIRED is documentary...
         */
        return HTTP_UPGRADE_REQUIRED;
    }

    return OK;
}

/*
 * Canonicalise http-like URLs.
 * scheme is the scheme for the URL
 * url is the URL starting with the first '/'
 * def_port is the default port for this scheme.
 */
static int proxy_wstunnel_canon(request_rec *r, char *url)
{
    char *host, *path, sport[7];
    char *search = NULL;
    const char *err;
    char *scheme;
    apr_port_t port, def_port;

    if (fallback_to_mod_proxy_http) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "canon fallback");
        return DECLINED;
    }

    /* ap_port_of_scheme() */
    if (ap_cstr_casecmpn(url, "ws:", 3) == 0) {
        url += 3;
        scheme = "ws:";
        def_port = apr_uri_port_of_scheme("http");
    }
    else if (ap_cstr_casecmpn(url, "wss:", 4) == 0) {
        url += 4;
        scheme = "wss:";
        def_port = apr_uri_port_of_scheme("https");
    }
    else {
        return DECLINED;
    }

    port = def_port;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "canonicalising URL %s", url);

    /*
     * do syntactic check.
     * We break the URL into host, port, path, search
     */
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02439) "error parsing URL %s: %s",
                      url, err);
        return HTTP_BAD_REQUEST;
    }

    /*
     * now parse path/search args, according to rfc1738:
     * process the path. With proxy-nocanon set (by
     * mod_proxy) we use the raw, unparsed uri
     */
    if (apr_table_get(r->notes, "proxy-nocanon")) {
        path = url;   /* this is the raw path */
    }
    else {
        path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, 0,
                                 r->proxyreq);
        search = r->args;
    }
    if (path == NULL)
        return HTTP_BAD_REQUEST;

    if (port != def_port)
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    else
        sport[0] = '\0';

    if (ap_strchr_c(host, ':')) {
        /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "//", host, sport,
                              "/", path, (search) ? "?" : "",
                              (search) ? search : "", NULL);
    return OK;
}

/*
 * process the request and write the response.
 */
static int proxy_wstunnel_request(apr_pool_t *p, request_rec *r,
                                proxy_conn_rec *conn,
                                proxy_worker *worker,
                                proxy_server_conf *conf,
                                apr_uri_t *uri,
                                char *url, char *server_portstr, char *scheme,
                                const char *upgrade)
{
    apr_status_t rv;
    conn_rec *c = r->connection;
    conn_rec *backconn = conn->connection;
    proxyws_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                   &proxy_wstunnel_module);
    proxy_tunnel_rec *tunnel = NULL;
    char *buf;
    apr_bucket_brigade *header_brigade;
    apr_bucket *e;
    char *old_cl_val = NULL;
    char *old_te_val = NULL;
    ws_baton_t *baton;
    int status;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "sending request");

    header_brigade = apr_brigade_create(p, backconn->bucket_alloc);
    rv = ap_proxy_create_hdrbrgd(p, header_brigade, r, conn,
                                 worker, conf, uri, url, server_portstr,
                                 &old_cl_val, &old_te_val);
    if (rv != OK) {
        return rv;
    }

    buf = apr_pstrcat(p, "Upgrade: ", upgrade, CRLF
                         "Connection: Upgrade" CRLF
                         CRLF, NULL);
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);

    if ((rv = ap_proxy_pass_brigade(backconn->bucket_alloc, r, conn, backconn,
                                    header_brigade, 1)) != OK)
        return rv;

    apr_brigade_cleanup(header_brigade);

    rv = ap_proxy_tunnel_create(&tunnel, r, backconn, scheme);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02543)
                      "error creating websocket tunnel");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    baton = apr_pcalloc(r->pool, sizeof(*baton));
    baton->r = r;
    baton->backend = conn;
    baton->tunnel = tunnel;
    baton->scheme = scheme;

    if (!dconf->mpm_can_poll) {
        tunnel->timeout = dconf->idle_timeout;
        status = proxy_wstunnel_pump(baton, 0);
    }  
    else { 
        tunnel->timeout = dconf->async_delay;
        status = proxy_wstunnel_pump(baton, 1);
        if (status == SUSPENDED) {
            /* Create the subpool used by the MPM to alloc its own
             * temporary data, which we want to clear on the next
             * round (above) to avoid leaks.
             */
            apr_pool_create(&baton->async_pool, baton->r->pool);

            rv = ap_mpm_register_poll_callback_timeout(
                         baton->async_pool,
                         baton->tunnel->pfds,
                         proxy_wstunnel_callback, 
                         proxy_wstunnel_cancel_callback, 
                         baton, 
                         dconf->idle_timeout);
            if (rv == APR_SUCCESS) { 
                return SUSPENDED;
            }

            if (APR_STATUS_IS_ENOTIMPL(rv)) { 
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(02544) "No async support");
                tunnel->timeout = dconf->idle_timeout;
                status = proxy_wstunnel_pump(baton, 0); /* force no async */
            }
            else { 
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10211)
                              "error registering websocket tunnel");
                status = HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    if (ap_is_HTTP_ERROR(status)) {
        /* Don't send an error page down an upgraded connection */
        if (!tunnel->replied) {
            return status;
        }
        /* Custom log may need this, still */
        r->status = status;
    }
    return OK;
}    

/*
 */
static int proxy_wstunnel_handler(request_rec *r, proxy_worker *worker,
                             proxy_server_conf *conf,
                             char *url, const char *proxyname,
                             apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    proxy_conn_rec *backend = NULL;
    const char *upgrade;
    char *scheme;
    apr_pool_t *p = r->pool;
    char *locurl = url;
    apr_uri_t *uri;
    int is_ssl = 0;

    if (fallback_to_mod_proxy_http) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "handler fallback");
        return DECLINED;
    }

    if (ap_cstr_casecmpn(url, "wss:", 4) == 0) {
        scheme = "WSS";
        is_ssl = 1;
    }
    else if (ap_cstr_casecmpn(url, "ws:", 3) == 0) {
        scheme = "WS";
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02450)
                      "declining URL %s", url);
        return DECLINED;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "serving URL %s", url);

    upgrade = apr_table_get(r->headers_in, "Upgrade");
    if (!upgrade || !ap_proxy_worker_can_upgrade(p, worker, upgrade,
                                                 "WebSocket")) {
        const char *worker_upgrade = *worker->s->upgrade ? worker->s->upgrade
                                                         : "WebSocket";
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02900)
                      "require upgrade for URL %s "
                      "(Upgrade header is %s, expecting %s)", 
                      url, upgrade ? upgrade : "missing", worker_upgrade);
        apr_table_setn(r->err_headers_out, "Connection", "Upgrade");
        apr_table_setn(r->err_headers_out, "Upgrade", worker_upgrade);
        return HTTP_UPGRADE_REQUIRED;
    }

    uri = apr_palloc(p, sizeof(*uri));
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02451) "serving URL %s", url);

    /* create space for state information */
    status = ap_proxy_acquire_connection(scheme, &backend, worker, r->server);
    if (status != OK) {
        goto cleanup;
    }

    backend->is_ssl = is_ssl;

    /* Step One: Determine Who To Connect To */
    status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                           uri, &locurl, proxyname, proxyport,
                                           server_portstr,
                                           sizeof(server_portstr));
    if (status != OK) {
        goto cleanup;
    }

    /* Step Two: Make the Connection */
    if (ap_proxy_connect_backend(scheme, backend, worker, r->server)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02452)
                      "failed to make connection to backend: %s",
                      backend->hostname);
        status = HTTP_SERVICE_UNAVAILABLE;
        goto cleanup;
    }

    /* Step Three: Create conn_rec */
    status = ap_proxy_connection_create_ex(scheme, backend, r);
    if (status != OK) {
        goto cleanup;
    }

    /* Step Four: Process the Request */
    status = proxy_wstunnel_request(p, r, backend, worker, conf, uri, locurl,
                                  server_portstr, scheme, upgrade);

cleanup:
    /* Do not close the socket */
    if (backend) {
        backend->close = 1;
        if (status != SUSPENDED) { 
            ap_proxy_release_connection(scheme, backend, r->server);
        }
    }
    return status;
}

static void *create_proxyws_dir_config(apr_pool_t *p, char *dummy)
{
    proxyws_dir_conf *new =
        (proxyws_dir_conf *) apr_pcalloc(p, sizeof(proxyws_dir_conf));

    new->idle_timeout = -1; /* no timeout */

    ap_mpm_query(AP_MPMQ_CAN_POLL, &new->mpm_can_poll);

    return (void *) new;
}

static const char * proxyws_set_idle(cmd_parms *cmd, void *conf, const char *val)
{
    proxyws_dir_conf *dconf = conf;
    if (ap_timeout_parameter_parse(val, &(dconf->idle_timeout), "s") != APR_SUCCESS)
        return "ProxyWebsocketIdleTimeout timeout has wrong format";
    return NULL;
}

static const char * proxyws_set_asynch_delay(cmd_parms *cmd, void *conf, const char *val)
{
    proxyws_dir_conf *dconf = conf;
    if (ap_timeout_parameter_parse(val, &(dconf->async_delay), "s") != APR_SUCCESS)
        return "ProxyWebsocketAsyncDelay timeout has wrong format";
    return NULL;
}

static int proxy_wstunnel_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                                      apr_pool_t *ptemp, server_rec *s)
{
    fallback_to_mod_proxy_http =
        (ap_find_linked_module("mod_proxy_http.c") != NULL);

    return OK;
}

static const command_rec ws_proxy_cmds[] =
{
    AP_INIT_TAKE1("ProxyWebsocketIdleTimeout", proxyws_set_idle, NULL,
                  RSRC_CONF|ACCESS_CONF,
                  "timeout for activity in either direction, unlimited by default"),

    AP_INIT_TAKE1("ProxyWebsocketAsyncDelay", proxyws_set_asynch_delay, NULL,
                 RSRC_CONF|ACCESS_CONF,
                 "amount of time to poll before going asynchronous"),
    {NULL}
};

static void ws_proxy_hooks(apr_pool_t *p)
{
    static const char * const aszSucc[] = { "mod_proxy_http.c", NULL};
    ap_hook_post_config(proxy_wstunnel_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    proxy_hook_scheme_handler(proxy_wstunnel_handler, NULL, aszSucc, APR_HOOK_FIRST);
    proxy_hook_check_trans(proxy_wstunnel_check_trans, NULL, aszSucc, APR_HOOK_MIDDLE);
    proxy_hook_canon_handler(proxy_wstunnel_canon, NULL, aszSucc, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(proxy_wstunnel) = {
    STANDARD20_MODULE_STUFF,
    create_proxyws_dir_config,  /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    ws_proxy_cmds,              /* command apr_table_t */
    ws_proxy_hooks              /* register hooks */
};
