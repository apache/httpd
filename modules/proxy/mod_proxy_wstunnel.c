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
#include "ap_mpm.h"

module AP_MODULE_DECLARE_DATA proxy_wstunnel_module;

typedef struct {
    signed char is_async;
    apr_time_t idle_timeout;
    apr_time_t async_delay;
} proxyws_dir_conf;

typedef struct ws_baton_t {
    request_rec *r;
    proxy_conn_rec *proxy_connrec;
    apr_socket_t *server_soc;
    apr_socket_t *client_soc;
    apr_pollset_t *pollset;
    apr_bucket_brigade *bb;
    apr_pool_t *subpool;        /* cleared before each suspend, destroyed when request ends */
    char *scheme;               /* required to release the proxy connection */
} ws_baton_t;

static apr_status_t proxy_wstunnel_transfer(request_rec *r,
                                            conn_rec *c_i, conn_rec *c_o,
                                            apr_bucket_brigade *bb,
                                            const char *name, int *sent);
static void proxy_wstunnel_callback(void *b);

static int proxy_wstunnel_pump(ws_baton_t *baton, apr_time_t timeout, int try_async) {
    request_rec *r = baton->r;
    conn_rec *c = r->connection;
    proxy_conn_rec *conn = baton->proxy_connrec;
    apr_socket_t *sock = conn->sock;
    conn_rec *backconn = conn->connection;
    const apr_pollfd_t *signalled;
    apr_int32_t pollcnt, pi;
    apr_int16_t pollevent;
    apr_pollset_t *pollset = baton->pollset;
    apr_socket_t *client_socket = baton->client_soc;
    apr_status_t rv;
    apr_bucket_brigade *bb = baton->bb;
    int done = 0, replied = 0;

    do { 
        rv = apr_pollset_poll(pollset, timeout, &pollcnt, &signalled);
        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_EINTR(rv)) {
                continue;
            }
            else if (APR_STATUS_IS_TIMEUP(rv)) { 
                if (try_async) { 
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(02542) "Attempting to go async");
                    return SUSPENDED;
                }
                else { 
                    return HTTP_REQUEST_TIME_OUT;
                }
            }
            else { 
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02444) "error apr_poll()");
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(02445)
                "woke from poll(), i=%d", pollcnt);

        for (pi = 0; pi < pollcnt; pi++) {
            const apr_pollfd_t *cur = &signalled[pi];

            if (cur->desc.s == sock) {
                pollevent = cur->rtnevents;
                if (pollevent & (APR_POLLIN | APR_POLLHUP)) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(02446)
                            "sock was readable");
                    done |= proxy_wstunnel_transfer(r, backconn, c, bb, "sock",
                                                    NULL) != APR_SUCCESS;
                }
                else if (pollevent & APR_POLLERR) {
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO(02447)
                            "error on backconn");
                    backconn->aborted = 1;
                    done = 1;
                }
                else { 
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO(02605)
                            "unknown event on backconn %d", pollevent);
                    done = 1;
                }
            }
            else if (cur->desc.s == client_socket) {
                pollevent = cur->rtnevents;
                if (pollevent & (APR_POLLIN | APR_POLLHUP)) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(02448)
                            "client was readable");
                    done |= proxy_wstunnel_transfer(r, c, backconn, bb, "client",
                                                    &replied) != APR_SUCCESS;
                }
                else if (pollevent & APR_POLLERR) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(02607)
                            "error on client conn");
                    c->aborted = 1;
                    done = 1;
                }
                else { 
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO(02606)
                            "unknown event on client conn %d", pollevent);
                    done = 1;
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02449)
                        "unknown socket in pollset");
                done = 1;
            }

        }
    } while (!done);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
            "finished with poll() - cleaning up");

    if (!replied) {
        return HTTP_BAD_GATEWAY;
    }
    else {
        return OK;
    }
}

static void proxy_wstunnel_finish(ws_baton_t *baton) { 
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, baton->r, "proxy_wstunnel_finish");
    baton->proxy_connrec->close = 1; /* new handshake expected on each back-conn */
    baton->r->connection->keepalive = AP_CONN_CLOSE;
    ap_proxy_release_connection(baton->scheme, baton->proxy_connrec, baton->r->server);
    ap_finalize_request_protocol(baton->r);
    ap_lingering_close(baton->r->connection);
    apr_socket_close(baton->client_soc);
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
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, baton->r, "proxy_wstunnel_cancel_callback, IO timed out");
    proxy_wstunnel_finish(baton);
    return;
}

/* Invoked by the event loop when data is ready on either end. 
 *  Pump both ends until they'd block and then start over again 
 *  We don't need the invoke_mtx, since we never put multiple callback events
 *  in the queue.
 */
static void proxy_wstunnel_callback(void *b) { 
    int status;
    apr_socket_t *sockets[3] = {NULL, NULL, NULL};
    ws_baton_t *baton = (ws_baton_t*)b;
    proxyws_dir_conf *dconf = ap_get_module_config(baton->r->per_dir_config, &proxy_wstunnel_module);
    apr_pool_clear(baton->subpool);
    status = proxy_wstunnel_pump(baton, dconf->async_delay, dconf->is_async);
    if (status == SUSPENDED) {
        sockets[0] = baton->client_soc;
        sockets[1] = baton->server_soc;
        ap_mpm_register_socket_callback_timeout(sockets, baton->subpool, 1, 
            proxy_wstunnel_callback, 
            proxy_wstunnel_cancel_callback, 
            baton, 
            dconf->idle_timeout);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, baton->r, "proxy_wstunnel_callback suspend");
    }
    else { 
        proxy_wstunnel_finish(baton);
    }
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

    /* ap_port_of_scheme() */
    if (strncasecmp(url, "ws:", 3) == 0) {
        url += 3;
        scheme = "ws:";
        def_port = apr_uri_port_of_scheme("http");
    }
    else if (strncasecmp(url, "wss:", 4) == 0) {
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

    apr_snprintf(sport, sizeof(sport), ":%d", port);

    if (ap_strchr_c(host, ':')) {
        /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "//", host, sport,
                              "/", path, (search) ? "?" : "",
                              (search) ? search : "", NULL);
    return OK;
}


static apr_status_t proxy_wstunnel_transfer(request_rec *r,
                                            conn_rec *c_i, conn_rec *c_o,
                                            apr_bucket_brigade *bb,
                                            const char *name, int *sent)
{
    apr_status_t rv;
#ifdef DEBUGGING
    apr_off_t len;
#endif

    do {
        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(c_i->input_filters, bb, AP_MODE_READBYTES,
                            APR_NONBLOCK_READ, AP_IOBUFSIZE);
        if (rv == APR_SUCCESS) {
            if (c_o->aborted) {
                return APR_EPIPE;
            }
            if (APR_BRIGADE_EMPTY(bb)) {
                break;
            }
#ifdef DEBUGGING
            len = -1;
            apr_brigade_length(bb, 0, &len);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02440)
                          "read %" APR_OFF_T_FMT
                          " bytes from %s", len, name);
#endif
            if (sent) {
                *sent = 1;
            }
            rv = ap_pass_brigade(c_o->output_filters, bb);
            if (rv == APR_SUCCESS) {
                ap_fflush(c_o->output_filters, bb);
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02441)
                              "error on %s - ap_pass_brigade",
                              name);
            }
        } else if (!APR_STATUS_IS_EAGAIN(rv) && !APR_STATUS_IS_EOF(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(02442)
                          "error on %s - ap_get_brigade",
                          name);
        }
    } while (rv == APR_SUCCESS);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, rv, r, "wstunnel_transfer complete");

    if (APR_STATUS_IS_EAGAIN(rv)) {
        rv = APR_SUCCESS;
    }

    return rv;
}

/*
 * process the request and write the response.
 */
static int proxy_wstunnel_request(apr_pool_t *p, request_rec *r,
                                proxy_conn_rec *conn,
                                proxy_worker *worker,
                                proxy_server_conf *conf,
                                apr_uri_t *uri,
                                char *url, char *server_portstr, char *scheme)
{
    apr_status_t rv;
    apr_pollset_t *pollset;
    apr_pollfd_t pollfd;
    conn_rec *c = r->connection;
    apr_socket_t *sock = conn->sock;
    conn_rec *backconn = conn->connection;
    char *buf;
    apr_bucket_brigade *header_brigade;
    apr_bucket *e;
    char *old_cl_val = NULL;
    char *old_te_val = NULL;
    apr_bucket_brigade *bb = apr_brigade_create(p, c->bucket_alloc);
    apr_socket_t *client_socket = ap_get_conn_socket(c);
    ws_baton_t *baton = apr_pcalloc(r->pool, sizeof(ws_baton_t));
    apr_socket_t *sockets[3] = {NULL, NULL, NULL};
    int status;
    proxyws_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &proxy_wstunnel_module);

    header_brigade = apr_brigade_create(p, backconn->bucket_alloc);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "sending request");

    rv = ap_proxy_create_hdrbrgd(p, header_brigade, r, conn,
                                 worker, conf, uri, url, server_portstr,
                                 &old_cl_val, &old_te_val);
    if (rv != OK) {
        return rv;
    }

    buf = apr_pstrcat(p, "Upgrade: WebSocket", CRLF, "Connection: Upgrade", CRLF, CRLF, NULL);
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);

    if ((rv = ap_proxy_pass_brigade(c->bucket_alloc, r, conn, backconn,
                                    header_brigade, 1)) != OK)
        return rv;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "setting up poll()");

    if ((rv = apr_pollset_create(&pollset, 2, p, 0)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02443)
                      "error apr_pollset_create()");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#if 0
    apr_socket_opt_set(sock, APR_SO_NONBLOCK, 1);
    apr_socket_opt_set(sock, APR_SO_KEEPALIVE, 1);
    apr_socket_opt_set(client_socket, APR_SO_NONBLOCK, 1);
    apr_socket_opt_set(client_socket, APR_SO_KEEPALIVE, 1);
#endif

    pollfd.p = p;
    pollfd.desc_type = APR_POLL_SOCKET;
    pollfd.reqevents = APR_POLLIN | APR_POLLHUP;
    pollfd.desc.s = sock;
    pollfd.client_data = NULL;
    apr_pollset_add(pollset, &pollfd);

    pollfd.desc.s = client_socket;
    apr_pollset_add(pollset, &pollfd);

    ap_remove_input_filter_byhandle(c->input_filters, "reqtimeout");

    r->output_filters = c->output_filters;
    r->proto_output_filters = c->output_filters;
    r->input_filters = c->input_filters;
    r->proto_input_filters = c->input_filters;

    /* This handler should take care of the entire connection; make it so that
     * nothing else is attempted on the connection after returning. */
    c->keepalive = AP_CONN_CLOSE;

    baton->r = r;
    baton->pollset = pollset;
    baton->client_soc = client_socket;
    baton->server_soc = sock;
    baton->proxy_connrec = conn;
    baton->bb = bb;
    baton->scheme = scheme;
    apr_pool_create(&baton->subpool, r->pool);

    if (!dconf->is_async) { 
        status = proxy_wstunnel_pump(baton, dconf->idle_timeout, dconf->is_async);
    }  
    else { 
        status = proxy_wstunnel_pump(baton, dconf->async_delay, dconf->is_async); 
        apr_pool_clear(baton->subpool);
        if (status == SUSPENDED) {
            sockets[0] = baton->client_soc;
            sockets[1] = baton->server_soc;
            rv = ap_mpm_register_socket_callback_timeout(sockets, baton->subpool, 1, 
                         proxy_wstunnel_callback, 
                         proxy_wstunnel_cancel_callback, 
                         baton, 
                         dconf->idle_timeout);
            if (rv == APR_SUCCESS) { 
                return SUSPENDED;
            }
            else if (APR_STATUS_IS_ENOTIMPL(rv)) { 
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(02544) "No async support");
                status = proxy_wstunnel_pump(baton, dconf->idle_timeout, 0); /* force no async */
            }
            else { 
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              APLOGNO(02543) "error creating websockets tunnel");
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    if (status != OK) { 
        /* Avoid sending error pages down an upgraded connection */
        if (status != HTTP_REQUEST_TIME_OUT) {
            r->status = status;
        }
        status = OK;
    }
    return status;
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
    char *scheme;
    int retry;
    conn_rec *c = r->connection;
    apr_pool_t *p = r->pool;
    apr_uri_t *uri;
    int is_ssl = 0;

    if (strncasecmp(url, "wss:", 4) == 0) {
        scheme = "WSS";
        is_ssl = 1;
    }
    else if (strncasecmp(url, "ws:", 3) == 0) {
        scheme = "WS";
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02450) "declining URL %s", url);
        return DECLINED;
    }

    uri = apr_palloc(p, sizeof(*uri));
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02451) "serving URL %s", url);

    /* create space for state information */
    status = ap_proxy_acquire_connection(scheme, &backend, worker,
                                         r->server);
    if (status != OK) {
        if (backend) {
            backend->close = 1;
            ap_proxy_release_connection(scheme, backend, r->server);
        }
        return status;
    }

    backend->is_ssl = is_ssl;
    backend->close = 0;

    retry = 0;
    while (retry < 2) {
        char *locurl = url;
        /* Step One: Determine Who To Connect To */
        status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                               uri, &locurl, proxyname, proxyport,
                                               server_portstr,
                                               sizeof(server_portstr));

        if (status != OK)
            break;

        /* Step Two: Make the Connection */
        if (ap_proxy_connect_backend(scheme, backend, worker, r->server)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02452)
                          "failed to make connection to backend: %s",
                          backend->hostname);
            status = HTTP_SERVICE_UNAVAILABLE;
            break;
        }
        /* Step Three: Create conn_rec */
        if (!backend->connection) {
            if ((status = ap_proxy_connection_create(scheme, backend,
                                                     c, r->server)) != OK)
                break;
        }

        backend->close = 1; /* must be after ap_proxy_determine_connection */

        /* Step Three: Process the Request */
        status = proxy_wstunnel_request(p, r, backend, worker, conf, uri, locurl,
                                      server_portstr, scheme);
        break;
    }

    /* Do not close the socket */
    if (status != SUSPENDED) { 
        ap_proxy_release_connection(scheme, backend, r->server);
    }
    return status;
}

static void *create_proxyws_dir_config(apr_pool_t *p, char *dummy)
{
    proxyws_dir_conf *new =
        (proxyws_dir_conf *) apr_pcalloc(p, sizeof(proxyws_dir_conf));

    new->idle_timeout = -1; /* no timeout */

    return (void *) new;
}

static const char * proxyws_set_idle(cmd_parms *cmd, void *conf, const char *val)
{
    proxyws_dir_conf *dconf = conf;
    if (ap_timeout_parameter_parse(val, &(dconf->idle_timeout), "s") != APR_SUCCESS)
        return "ProxyWebsocketIdleTimeout timeout has wrong format";
    return NULL;
}
static const char * proxyws_set_aysnch_delay(cmd_parms *cmd, void *conf, const char *val)
{
    proxyws_dir_conf *dconf = conf;
    if (ap_timeout_parameter_parse(val, &(dconf->async_delay), "s") != APR_SUCCESS)
        return "ProxyWebsocketAsyncDelay timeout has wrong format";
    return NULL;
}

static const command_rec ws_proxy_cmds[] =
{
    AP_INIT_FLAG("ProxyWebsocketAsync", ap_set_flag_slot_char, (void*)APR_OFFSETOF(proxyws_dir_conf, is_async), 
                 RSRC_CONF|ACCESS_CONF,
                 "on if idle websockets connections should be monitored asyncronously"),

    AP_INIT_TAKE1("ProxyWebsocketIdleTimeout", proxyws_set_idle, NULL, RSRC_CONF|ACCESS_CONF,
                 "timeout for activity in either direction, unlimited by default"),

    AP_INIT_TAKE1("ProxyWebsocketAsyncDelay", proxyws_set_aysnch_delay, NULL, RSRC_CONF|ACCESS_CONF,
                 "amount of time to poll before going asyncronous"),
    {NULL}
};

static void ap_proxy_http_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_wstunnel_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_wstunnel_canon, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(proxy_wstunnel) = {
    STANDARD20_MODULE_STUFF,
    create_proxyws_dir_config,  /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    ws_proxy_cmds,              /* command apr_table_t */
    ap_proxy_http_register_hook /* register hooks */
};
