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

/* CONNECT method for Apache proxy */

#include "mod_proxy.h"
#include "apr_poll.h"

#define CONN_BLKSZ AP_IOBUFSIZE

module AP_MODULE_DECLARE_DATA proxy_connect_module;

/*
 * This handles Netscape CONNECT method secure proxy requests.
 * A connection is opened to the specified host and data is
 * passed through between the WWW site and the browser.
 *
 * This code is based on the INTERNET-DRAFT document
 * "Tunneling SSL Through a WWW Proxy" currently at
 * http://www.mcom.com/newsref/std/tunneling_ssl.html.
 *
 * If proxyhost and proxyport are set, we send a CONNECT to
 * the specified proxy..
 *
 * FIXME: this doesn't log the number of bytes sent, but
 *        that may be okay, since the data is supposed to
 *        be transparent. In fact, this doesn't log at all
 *        yet. 8^)
 * FIXME: doesn't check any headers initally sent from the
 *        client.
 * FIXME: should allow authentication, but hopefully the
 *        generic proxy authentication is good enough.
 * FIXME: no check for r->assbackwards, whatever that is.
 */

typedef struct {
    apr_array_header_t *allowed_connect_ports;
} connect_conf;

typedef struct {
    int first;
    int last;
} port_range;

static void *create_config(apr_pool_t *p, server_rec *s)
{
    connect_conf *c = apr_pcalloc(p, sizeof(connect_conf));
    c->allowed_connect_ports = apr_array_make(p, 10, sizeof(port_range));
    return c;
}

static void *merge_config(apr_pool_t *p, void *basev, void *overridesv)
{
    connect_conf *c = apr_pcalloc(p, sizeof(connect_conf));
    connect_conf *base = (connect_conf *) basev;
    connect_conf *overrides = (connect_conf *) overridesv;

    c->allowed_connect_ports = apr_array_append(p,
                                                base->allowed_connect_ports,
                                                overrides->allowed_connect_ports);
    
    return c;
}


/*
 * Set the ports CONNECT can use
 */
static const char *
    set_allowed_ports(cmd_parms *parms, void *dummy, const char *arg)
{
    server_rec *s = parms->server;
    int first, last;
    connect_conf *conf =
        ap_get_module_config(s->module_config, &proxy_connect_module);
    port_range *New;
    char *endptr;
    const char *p = arg;

    if (!apr_isdigit(arg[0]))
        return "AllowCONNECT: port numbers must be numeric";

    first = strtol(p, &endptr, 10);
    if (*endptr == '-') {
        p = endptr + 1;
        last = strtol(p, &endptr, 10);
    }
    else {
        last = first;
    }

    if (endptr == p || *endptr != '\0')  {
        return apr_psprintf(parms->temp_pool,
                            "Cannot parse '%s' as port number", p);
    }

    New = apr_array_push(conf->allowed_connect_ports);
    New->first = first;
    New->last  = last;
    return NULL;
}


static int allowed_port(connect_conf *conf, int port)
{
    int i;
    port_range *list = (port_range *) conf->allowed_connect_ports->elts;
    
    if (apr_is_empty_array(conf->allowed_connect_ports)){
        return port == APR_URI_HTTPS_DEFAULT_PORT
               || port == APR_URI_SNEWS_DEFAULT_PORT;
    }

    for (i = 0; i < conf->allowed_connect_ports->nelts; i++) {
        if (port >= list[i].first && port <= list[i].last)
            return 1;
    }
    return 0;
}

/* canonicalise CONNECT URLs. */
static int proxy_connect_canon(request_rec *r, char *url)
{

    if (r->method_number != M_CONNECT) {
    return DECLINED;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
         "proxy: CONNECT: canonicalising URL %s", url);

    return OK;
}

/* read available data (in blocks of CONN_BLKSZ) from c_i and copy to c_o */
static int proxy_connect_transfer(request_rec *r, conn_rec *c_i, conn_rec *c_o,
                                  apr_bucket_brigade *bb, char *name)
{
    int rv;
#ifdef DEBUGGING
    apr_off_t len;
#endif

    do {
        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(c_i->input_filters, bb, AP_MODE_READBYTES,
                            APR_NONBLOCK_READ, CONN_BLKSZ);
        if (rv == APR_SUCCESS) {
            if (c_o->aborted)
                return APR_EPIPE;
            if (APR_BRIGADE_EMPTY(bb))
                break;
#ifdef DEBUGGING
            len = -1;
            apr_brigade_length(bb, 0, &len);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "proxy: CONNECT: read %" APR_OFF_T_FMT
                          " bytes from %s", len, name);
#endif
            rv = ap_pass_brigade(c_o->output_filters, bb);
            if (rv == APR_SUCCESS) {
                ap_fflush(c_o->output_filters, bb);
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "proxy: CONNECT: error on %s - ap_pass_brigade",
                              name);
            }
        } else if (!APR_STATUS_IS_EAGAIN(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                          "proxy: CONNECT: error on %s - ap_get_brigade",
                          name);
        }
    } while (rv == APR_SUCCESS);

    if (APR_STATUS_IS_EAGAIN(rv)) {
        rv = APR_SUCCESS;
    }
    return rv;
}

/* CONNECT handler */
static int proxy_connect_handler(request_rec *r, proxy_worker *worker,
                                 proxy_server_conf *conf,
                                 char *url, const char *proxyname,
                                 apr_port_t proxyport)
{
    connect_conf *c_conf =
        ap_get_module_config(r->server->module_config, &proxy_connect_module);

    apr_pool_t *p = r->pool;
    apr_socket_t *sock;
    conn_rec *c = r->connection;
    conn_rec *backconn;

    apr_bucket_brigade *bb = apr_brigade_create(p, c->bucket_alloc);
    apr_status_t err, rv;
    apr_size_t nbytes;
    char buffer[HUGE_STRING_LEN];
    apr_socket_t *client_socket = ap_get_module_config(c->conn_config, &core_module);
    int failed, rc;
    int client_error = 0;
    apr_pollset_t *pollset;
    apr_pollfd_t pollfd;
    const apr_pollfd_t *signalled;
    apr_int32_t pollcnt, pi;
    apr_int16_t pollevent;
    apr_sockaddr_t *uri_addr, *connect_addr;

    apr_uri_t uri;
    const char *connectname;
    int connectport = 0;

    /* is this for us? */
    if (r->method_number != M_CONNECT) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: CONNECT: declining URL %s", url);
        return DECLINED;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: CONNECT: serving URL %s", url);


    /*
     * Step One: Determine Who To Connect To
     *
     * Break up the URL to determine the host to connect to
     */

    /* we break the URL into host, port, uri */
    if (APR_SUCCESS != apr_uri_parse_hostinfo(p, url, &uri)) {
        return ap_proxyerror(r, HTTP_BAD_REQUEST,
                             apr_pstrcat(p, "URI cannot be parsed: ", url,
                                         NULL));
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: CONNECT: connecting %s to %s:%d", url, uri.hostname,
                 uri.port);

    /* do a DNS lookup for the destination host */
    err = apr_sockaddr_info_get(&uri_addr, uri.hostname, APR_UNSPEC, uri.port,
                                0, p);
    if (APR_SUCCESS != err) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             apr_pstrcat(p, "DNS lookup failure for: ",
                                         uri.hostname, NULL));
    }

    /* are we connecting directly, or via a proxy? */
    if (proxyname) {
        connectname = proxyname;
        connectport = proxyport;
        err = apr_sockaddr_info_get(&connect_addr, proxyname, APR_UNSPEC,
                                    proxyport, 0, p);
    }
    else {
        connectname = uri.hostname;
        connectport = uri.port;
        connect_addr = uri_addr;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: CONNECT: connecting to remote proxy %s on port %d",
                 connectname, connectport);

    /* check if ProxyBlock directive on this host */
    if (OK != ap_proxy_checkproxyblock(r, conf, uri_addr)) {
        return ap_proxyerror(r, HTTP_FORBIDDEN,
                             "Connect to remote machine blocked");
    }

    /* Check if it is an allowed port */
    if(!allowed_port(c_conf, uri.port)) {
              return ap_proxyerror(r, HTTP_FORBIDDEN,
                                   "Connect to remote machine blocked");
    }

    /*
     * Step Two: Make the Connection
     *
     * We have determined who to connect to. Now make the connection.
     */

    /* get all the possible IP addresses for the destname and loop through them
     * until we get a successful connection
     */
    if (APR_SUCCESS != err) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             apr_pstrcat(p, "DNS lookup failure for: ",
                                         connectname, NULL));
    }

    /*
     * At this point we have a list of one or more IP addresses of
     * the machine to connect to. If configured, reorder this
     * list so that the "best candidate" is first try. "best
     * candidate" could mean the least loaded server, the fastest
     * responding server, whatever.
     *
     * For now we do nothing, ie we get DNS round robin.
     * XXX FIXME
     */
    failed = ap_proxy_connect_to_backend(&sock, "CONNECT", connect_addr,
                                         connectname, conf, r);

    /* handle a permanent error from the above loop */
    if (failed) {
        if (proxyname) {
            return DECLINED;
        }
        else {
            return HTTP_SERVICE_UNAVAILABLE;
        }
    }

    /* setup polling for connection */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "proxy: CONNECT: setting up poll()");

    if ((rv = apr_pollset_create(&pollset, 2, r->pool, 0)) != APR_SUCCESS) {
        apr_socket_close(sock);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "proxy: CONNECT: error apr_pollset_create()");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Add client side to the poll */
    pollfd.p = r->pool;
    pollfd.desc_type = APR_POLL_SOCKET;
    pollfd.reqevents = APR_POLLIN;
    pollfd.desc.s = client_socket;
    pollfd.client_data = NULL;
    apr_pollset_add(pollset, &pollfd);

    /* Add the server side to the poll */
    pollfd.desc.s = sock;
    apr_pollset_add(pollset, &pollfd);

    /*
     * Step Three: Send the Request
     *
     * Send the HTTP/1.1 CONNECT request to the remote server
     */

    backconn = ap_run_create_connection(c->pool, r->server, sock,
                                        c->id, c->sbh, c->bucket_alloc);
    if (!backconn) {
        /* peer reset */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "proxy: an error occurred creating a new connection "
                      "to %pI (%s)", connect_addr, connectname);
        apr_socket_close(sock);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_proxy_ssl_disable(backconn);
    rc = ap_run_pre_connection(backconn, sock);
    if (rc != OK && rc != DONE) {
        backconn->aborted = 1;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "proxy: CONNECT: pre_connection setup failed (%d)", rc);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "proxy: CONNECT: connection complete to %pI (%s)",
                  connect_addr, connectname);


    /* If we are connecting through a remote proxy, we need to pass
     * the CONNECT request on to it.
     */
    if (proxyport) {
    /* FIXME: Error checking ignored.
     */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: CONNECT: sending the CONNECT request"
                     " to the remote proxy");
        ap_fprintf(backconn->output_filters, bb,
                   "CONNECT %s HTTP/1.0" CRLF, r->uri);
        ap_fprintf(backconn->output_filters, bb,
                   "Proxy-agent: %s" CRLF CRLF, ap_get_server_banner());
        ap_fflush(backconn->output_filters, bb);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: CONNECT: Returning 200 OK Status");
        nbytes = apr_snprintf(buffer, sizeof(buffer),
                              "HTTP/1.0 200 Connection Established" CRLF);
        ap_xlate_proto_to_ascii(buffer, nbytes);
        ap_fwrite(c->output_filters, bb, buffer, nbytes); 
        nbytes = apr_snprintf(buffer, sizeof(buffer),
                              "Proxy-agent: %s" CRLF CRLF,
                              ap_get_server_banner());
        ap_xlate_proto_to_ascii(buffer, nbytes);
        ap_fwrite(c->output_filters, bb, buffer, nbytes);
        ap_fflush(c->output_filters, bb);
#if 0
        /* This is safer code, but it doesn't work yet.  I'm leaving it
         * here so that I can fix it later.
         */
        r->status = HTTP_OK;
        r->header_only = 1;
        apr_table_set(r->headers_out, "Proxy-agent: %s", ap_get_server_banner());
        ap_rflush(r);
#endif
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: CONNECT: setting up poll()");

    /*
     * Step Four: Handle Data Transfer
     *
     * Handle two way transfer of data over the socket (this is a tunnel).
     */

    /* we are now acting as a tunnel - the input/output filter stacks should
     * not contain any non-connection filters.
     */
    r->output_filters = c->output_filters;
    r->proto_output_filters = c->output_filters;
    r->input_filters = c->input_filters;
    r->proto_input_filters = c->input_filters;
/*    r->sent_bodyct = 1;*/

    while (1) { /* Infinite loop until error (one side closes the connection) */
        if ((rv = apr_pollset_poll(pollset, -1, &pollcnt, &signalled))
            != APR_SUCCESS) {
            apr_socket_close(sock);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "proxy: CONNECT: error apr_poll()");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
#ifdef DEBUGGING
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: CONNECT: woke from poll(), i=%d", pollcnt);
#endif

        for (pi = 0; pi < pollcnt; pi++) {
            const apr_pollfd_t *cur = &signalled[pi];

            if (cur->desc.s == sock) {
                pollevent = cur->rtnevents;
                if (pollevent & APR_POLLIN) {
#ifdef DEBUGGING
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "proxy: CONNECT: sock was readable");
#endif
                    rv = proxy_connect_transfer(r, backconn, c, bb, "sock");
                    }
                else if ((pollevent & APR_POLLERR)
                         || (pollevent & APR_POLLHUP)) {
                         rv = APR_EPIPE;
                         ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                                       "proxy: CONNECT: err/hup on backconn");
                }
                if (rv != APR_SUCCESS)
                    client_error = 1;
            }
            else if (cur->desc.s == client_socket) {
                pollevent = cur->rtnevents;
                if (pollevent & APR_POLLIN) {
#ifdef DEBUGGING
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "proxy: CONNECT: client was readable");
#endif
                    rv = proxy_connect_transfer(r, c, backconn, bb, "client");
                }
            }
            else {
                rv = APR_EBADF;
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "proxy: CONNECT: unknown socket in pollset");
            }

        }
        if (rv != APR_SUCCESS) {
            break;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: CONNECT: finished with poll() - cleaning up");

    /*
     * Step Five: Clean Up
     *
     * Close the socket and clean up
     */

    if (client_error)
        apr_socket_close(sock);
    else
        ap_lingering_close(backconn);

    c->aborted = 1;

    return OK;
}

static void ap_proxy_connect_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_connect_handler, NULL, NULL, APR_HOOK_MIDDLE);
    proxy_hook_canon_handler(proxy_connect_canon, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec cmds[] =
{
    AP_INIT_ITERATE("AllowCONNECT", set_allowed_ports, NULL, RSRC_CONF,
     "A list of ports or port ranges which CONNECT may connect to"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA proxy_connect_module = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    create_config,       /* create per-server config structure */
    merge_config,       /* merge per-server config structures */
    cmds,       /* command apr_table_t */
    ap_proxy_connect_register_hook  /* register hooks */
};
