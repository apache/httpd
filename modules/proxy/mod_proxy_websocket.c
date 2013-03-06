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

module AP_MODULE_DECLARE_DATA proxy_websocket_module;

/*
 * Canonicalise http-like URLs.
 * scheme is the scheme for the URL
 * url is the URL starting with the first '/'
 * def_port is the default port for this scheme.
 */
static int proxy_websocket_canon(request_rec *r, char *url)
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
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO() "error parsing URL %s: %s",
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


static int proxy_websocket_transfer(request_rec *r, conn_rec *c_i, conn_rec *c_o,
                                     apr_bucket_brigade *bb, char *name)
{
    int rv;
#ifdef DEBUGGING
    apr_off_t len;
#endif

    do {
        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(c_i->input_filters, bb, AP_MODE_READBYTES,
                            APR_NONBLOCK_READ, AP_IOBUFSIZE);
        if (rv == APR_SUCCESS) {
            if (c_o->aborted)
                return APR_EPIPE;
            if (APR_BRIGADE_EMPTY(bb))
                break;
#ifdef DEBUGGING
            len = -1;
            apr_brigade_length(bb, 0, &len);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                          "read %" APR_OFF_T_FMT
                          " bytes from %s", len, name);
#endif
            rv = ap_pass_brigade(c_o->output_filters, bb);
            if (rv == APR_SUCCESS) {
                ap_fflush(c_o->output_filters, bb);
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                              "error on %s - ap_pass_brigade",
                              name);
            }
        } else if (!APR_STATUS_IS_EAGAIN(rv) && !APR_STATUS_IS_EOF(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO()
                          "error on %s - ap_get_brigade",
                          name);
        }
    } while (rv == APR_SUCCESS);

    if (APR_STATUS_IS_EAGAIN(rv)) {
        rv = APR_SUCCESS;
    }
    return rv;
}

static int sendall(proxy_conn_rec *conn, const char *buf, apr_size_t length,
                   request_rec *r)
{
    apr_status_t rv;
    apr_size_t written;

    while (length > 0) {
        written = length;
        if ((rv = apr_socket_send(conn->sock, buf, &written)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                          "sending data to %s:%u failed",
                          conn->hostname, conn->port);
            return HTTP_SERVICE_UNAVAILABLE;
        }

        /* count for stats */
        conn->worker->s->transferred += written;
        buf += written;
        length -= written;
    }

    return OK;
}

/* Clear all connection-based headers from the incoming headers table */
typedef struct header_dptr {
    apr_pool_t *pool;
    apr_table_t *table;
    apr_time_t time;
} header_dptr;

static int clear_conn_headers(void *data, const char *key, const char *val)
{
    apr_table_t *headers = ((header_dptr*)data)->table;
    apr_pool_t *pool = ((header_dptr*)data)->pool;
    const char *name;
    char *next = apr_pstrdup(pool, val);
    while (*next) {
        name = next;
        while (*next && !apr_isspace(*next) && (*next != ',')) {
            ++next;
        }
        while (*next && (apr_isspace(*next) || (*next == ','))) {
            *next++ = '\0';
        }
        apr_table_unset(headers, name);
    }
    return 1;
}

static void ap_proxy_clear_connection(apr_pool_t *p, apr_table_t *headers)
{
    header_dptr x;
    x.pool = p;
    x.table = headers;
    apr_table_unset(headers, "Proxy-Connection");
    apr_table_do(clear_conn_headers, &x, headers, "Connection", NULL);
    apr_table_unset(headers, "Connection");
}

/*
 * process the request and write the response.
 */
static int ap_proxy_websocket_request(apr_pool_t *p, request_rec *r,
                                proxy_conn_rec *conn,
                                conn_rec *origin,
                                proxy_dir_conf *conf,
                                apr_uri_t *uri,
                                char *url, char *server_portstr)
{
    apr_status_t rv = APR_SUCCESS;
    apr_pollset_t *pollset;
    apr_pollfd_t pollfd;
    const apr_pollfd_t *signalled;
    apr_int32_t pollcnt, pi;
    apr_int16_t pollevent;
    conn_rec *c = r->connection;
    apr_socket_t *sock = conn->sock;
    conn_rec *backconn = conn->connection;
    int client_error = 0;
    int force10;
    int counter;
    char *buf;
    void *sconf = r->server->module_config;
    proxy_server_conf *psc;
    const apr_array_header_t *headers_in_array;
    const apr_table_entry_t *headers_in;
    apr_table_t *headers_in_copy;
    const char *old_cl_val = NULL;
    const char *old_te_val = NULL;
    apr_size_t blen;
    apr_bucket_brigade *bb = apr_brigade_create(p, c->bucket_alloc);
    apr_socket_t *client_socket = ap_get_conn_socket(c);

    psc = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "sending request");

    /*
     * pulled from mod_proxy_http... (maybe pull out to ap_get_header_brigade()?)
     */
    if (apr_table_get(r->subprocess_env, "force-proxy-request-1.0")) {
        /*
         * According to RFC 2616 8.2.3 we are not allowed to forward an
         * Expect: 100-continue to an HTTP/1.0 server. Instead we MUST return
         * a HTTP_EXPECTATION_FAILED
         */
        if (r->expecting_100) {
            return HTTP_EXPECTATION_FAILED;
        }
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.0" CRLF, NULL);
        force10 = 1;
        conn->close = 1;
    } else {
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.1" CRLF, NULL);
        force10 = 0;
    }
    if (apr_table_get(r->subprocess_env, "proxy-nokeepalive")) {
        origin->keepalive = AP_CONN_CLOSE;
        conn->close = 1;
    }
    blen = strlen(buf);
    ap_xlate_proto_to_ascii(buf, blen);
    if ((rv = sendall(conn, buf, blen, r)) != OK)
        return rv;
    if (conf->preserve_host == 0) {
        if (ap_strchr_c(uri->hostname, ':')) { /* if literal IPv6 address */
            if (uri->port_str && uri->port != DEFAULT_HTTP_PORT) {
                buf = apr_pstrcat(p, "Host: [", uri->hostname, "]:",
                                  uri->port_str, CRLF, NULL);
            } else {
                buf = apr_pstrcat(p, "Host: [", uri->hostname, "]", CRLF, NULL);
            }
        } else {
            if (uri->port_str && uri->port != DEFAULT_HTTP_PORT) {
                buf = apr_pstrcat(p, "Host: ", uri->hostname, ":",
                                  uri->port_str, CRLF, NULL);
            } else {
                buf = apr_pstrcat(p, "Host: ", uri->hostname, CRLF, NULL);
            }
        }
    }
    else {
        /* don't want to use r->hostname, as the incoming header might have a
         * port attached
         */
        const char* hostname = apr_table_get(r->headers_in,"Host");
        if (!hostname) {
            hostname =  r->server->server_hostname;
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO()
                          "no HTTP 0.9 request (with no host line) "
                          "on incoming request and preserve host set "
                          "forcing hostname to be %s for uri %s",
                          hostname, r->uri);
        }
        buf = apr_pstrcat(p, "Host: ", hostname, CRLF, NULL);
    }
    blen = strlen(buf);
    ap_xlate_proto_to_ascii(buf, blen);
    if ((rv = sendall(conn, buf, blen, r)) != OK)
        return rv;

    /* handle Via */
    if (psc->viaopt == via_block) {
        /* Block all outgoing Via: headers */
        apr_table_unset(r->headers_in, "Via");
    } else if (psc->viaopt != via_off) {
        const char *server_name = ap_get_server_name(r);
        /* If USE_CANONICAL_NAME_OFF was configured for the proxy virtual host,
         * then the server name returned by ap_get_server_name() is the
         * origin server name (which does make too much sense with Via: headers)
         * so we use the proxy vhost's name instead.
         */
        if (server_name == r->hostname)
            server_name = r->server->server_hostname;
        /* Create a "Via:" request header entry and merge it */
        /* Generate outgoing Via: header with/without server comment: */
        apr_table_mergen(r->headers_in, "Via",
                         (psc->viaopt == via_full)
                         ? apr_psprintf(p, "%d.%d %s%s (%s)",
                                        HTTP_VERSION_MAJOR(r->proto_num),
                                        HTTP_VERSION_MINOR(r->proto_num),
                                        server_name, server_portstr,
                                        AP_SERVER_BASEVERSION)
                         : apr_psprintf(p, "%d.%d %s%s",
                                        HTTP_VERSION_MAJOR(r->proto_num),
                                        HTTP_VERSION_MINOR(r->proto_num),
                                        server_name, server_portstr)
                         );
    }

    if (conf->add_forwarded_headers) {
        if (PROXYREQ_REVERSE == r->proxyreq) {
            const char *buf;

            /* Add X-Forwarded-For: so that the upstream has a chance to
             * determine, where the original request came from.
             */
            apr_table_mergen(r->headers_in, "X-Forwarded-For",
                             r->useragent_ip);

            /* Add X-Forwarded-Host: so that upstream knows what the
             * original request hostname was.
             */
            if ((buf = apr_table_get(r->headers_in, "Host"))) {
                apr_table_mergen(r->headers_in, "X-Forwarded-Host", buf);
            }

            /* Add X-Forwarded-Server: so that upstream knows what the
             * name of this proxy server is (if there are more than one)
             * XXX: This duplicates Via: - do we strictly need it?
             */
            apr_table_mergen(r->headers_in, "X-Forwarded-Server",
                             r->server->server_hostname);
        }
    }

    proxy_run_fixups(r);
    /*
     * Make a copy of the headers_in table before clearing the connection
     * headers as we need the connection headers later in the http output
     * filter to prepare the correct response headers.
     *
     * Note: We need to take r->pool for apr_table_copy as the key / value
     * pairs in r->headers_in have been created out of r->pool and
     * p might be (and actually is) a longer living pool.
     * This would trigger the bad pool ancestry abort in apr_table_copy if
     * apr is compiled with APR_POOL_DEBUG.
     */
    headers_in_copy = apr_table_copy(r->pool, r->headers_in);
    ap_proxy_clear_connection(p, headers_in_copy);
    /* send request headers */
    headers_in_array = apr_table_elts(headers_in_copy);
    headers_in = (const apr_table_entry_t *) headers_in_array->elts;
    for (counter = 0; counter < headers_in_array->nelts; counter++) {
        if (headers_in[counter].key == NULL
            || headers_in[counter].val == NULL

            /* Already sent */
            || !strcasecmp(headers_in[counter].key, "Host")

            /* Clear out hop-by-hop request headers not to send
             * RFC2616 13.5.1 says we should strip these headers
             */
            || !strcasecmp(headers_in[counter].key, "Keep-Alive")
            || !strcasecmp(headers_in[counter].key, "TE")
            || !strcasecmp(headers_in[counter].key, "Trailer")
            || !strcasecmp(headers_in[counter].key, "Upgrade")

            ) {
            continue;
        }
        /* Do we want to strip Proxy-Authorization ?
         * If we haven't used it, then NO
         * If we have used it then MAYBE: RFC2616 says we MAY propagate it.
         * So let's make it configurable by env.
         */
        if (!strcasecmp(headers_in[counter].key,"Proxy-Authorization")) {
            if (r->user != NULL) { /* we've authenticated */
                if (!apr_table_get(r->subprocess_env, "Proxy-Chain-Auth")) {
                    continue;
                }
            }
        }

        /* Skip Transfer-Encoding and Content-Length for now.
         */
        if (!strcasecmp(headers_in[counter].key, "Transfer-Encoding")) {
            old_te_val = headers_in[counter].val;
            continue;
        }
        if (!strcasecmp(headers_in[counter].key, "Content-Length")) {
            old_cl_val = headers_in[counter].val;
            continue;
        }

        /* for sub-requests, ignore freshness/expiry headers */
        if (r->main) {
            if (    !strcasecmp(headers_in[counter].key, "If-Match")
                || !strcasecmp(headers_in[counter].key, "If-Modified-Since")
                || !strcasecmp(headers_in[counter].key, "If-Range")
                || !strcasecmp(headers_in[counter].key, "If-Unmodified-Since")
                || !strcasecmp(headers_in[counter].key, "If-None-Match")) {
                continue;
            }
        }

        buf = apr_pstrcat(p, headers_in[counter].key, ": ",
                          headers_in[counter].val, CRLF,
                          NULL);
        blen = strlen(buf);
        ap_xlate_proto_to_ascii(buf, blen);
        if ((rv = sendall(conn, buf, blen, r)) != OK)
            return rv;
    }

    buf = CRLF;
    blen = strlen(buf);
    ap_xlate_proto_to_ascii(buf, blen);
    if ((rv = sendall(conn, buf, blen, r)) != OK)
        return rv;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "setting up poll()");

    if ((rv = apr_pollset_create(&pollset, 2, p, 0)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                      "error apr_pollset_create()");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_socket_opt_set(sock, APR_SO_NONBLOCK, 1);
    apr_socket_opt_set(sock, APR_SO_KEEPALIVE, 1);
    apr_socket_opt_set(client_socket, APR_SO_NONBLOCK, 1);
    apr_socket_opt_set(client_socket, APR_SO_KEEPALIVE, 1);

    pollfd.p = p;
    pollfd.desc_type = APR_POLL_SOCKET;
    pollfd.reqevents = APR_POLLIN;
    pollfd.desc.s = sock;
    pollfd.client_data = NULL;
    apr_pollset_add(pollset, &pollfd);

    pollfd.desc.s = client_socket;
    apr_pollset_add(pollset, &pollfd);


    r->output_filters = c->output_filters;
    r->proto_output_filters = c->output_filters;
    r->input_filters = c->input_filters;
    r->proto_input_filters = c->input_filters;

    while (1) { /* Infinite loop until error (one side closes the connection) */
        if ((rv = apr_pollset_poll(pollset, -1, &pollcnt, &signalled))
            != APR_SUCCESS) {
            if (APR_STATUS_IS_EINTR(rv)) {
                continue;
            }
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO() "error apr_poll()");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                      "woke from poll(), i=%d", pollcnt);

        for (pi = 0; pi < pollcnt; pi++) {
            const apr_pollfd_t *cur = &signalled[pi];

            if (cur->desc.s == sock) {
                pollevent = cur->rtnevents;
                if (pollevent & APR_POLLIN) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                                  "sock was readable");
                    rv = proxy_websocket_transfer(r, backconn, c, bb, "sock");
                    }
                else if ((pollevent & APR_POLLERR)
                         || (pollevent & APR_POLLHUP)) {
                         rv = APR_EPIPE;
                         ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO()
                                       "err/hup on backconn");
                }
                if (rv != APR_SUCCESS)
                    client_error = 1;
            }
            else if (cur->desc.s == client_socket) {
                pollevent = cur->rtnevents;
                if (pollevent & APR_POLLIN) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                                  "client was readable");
                    rv = proxy_websocket_transfer(r, c, backconn, bb, "client");
                }
            }
            else {
                rv = APR_EBADF;
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO()
                              "unknown socket in pollset");
            }

        }
        if (rv != APR_SUCCESS) {
            break;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "finished with poll() - cleaning up");

    if (client_error) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    return OK;
}

/*
 */
static int proxy_websocket_handler(request_rec *r, proxy_worker *worker,
                             proxy_server_conf *conf,
                             char *url, const char *proxyname,
                             apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    conn_rec *origin = NULL;
    proxy_conn_rec *backend = NULL;
    char *scheme;
    int retry;
    conn_rec *c = r->connection;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);
    apr_pool_t *p = r->pool;
    apr_uri_t *uri;

    if (strncasecmp(url, "wss:", 4) == 0) {
        scheme = "WSS";
    }
    else if (strncasecmp(url, "ws:", 3) == 0) {
        scheme = "WS";
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO() "declining URL %s", url);
        return DECLINED;
    }

    uri = apr_palloc(p, sizeof(*uri));
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO() "serving URL %s", url);

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

    backend->is_ssl = 0;
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
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

        /* Step Three: Process the Request */
        status = ap_proxy_websocket_request(p, r, backend, origin, dconf, uri, locurl,
                                      server_portstr);
        break;
    }

    /* Do not close the socket */
    ap_proxy_release_connection(scheme, backend, r->server);
    return status;
}

static void ap_proxy_http_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_websocket_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_websocket_canon, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(proxy_websocket) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    ap_proxy_http_register_hook /* register hooks */
};
