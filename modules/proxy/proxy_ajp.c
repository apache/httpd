/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* HTTP routines for Apache proxy */

#include "mod_proxy.h"

module AP_MODULE_DECLARE_DATA proxy_ajp_module;

int ap_proxy_ajp_canon(request_rec *r, char *url);
int ap_proxy_ajp_handler(request_rec *r, proxy_server_conf *conf,
                          char *url, const char *proxyname, 
                          apr_port_t proxyport);

typedef struct {
    const char     *name;
    apr_port_t      port;
    apr_sockaddr_t *addr;
    apr_socket_t   *sock;
    int             close;
    void           *data;  /* To store ajp data */
} proxy_ajp_conn_t;

static apr_status_t ap_proxy_http_cleanup(request_rec *r,
                                          proxy_ajp_conn_t *p_conn,
                                          proxy_conn_rec *backend);

/*
 * Canonicalise http-like URLs.
 *  scheme is the scheme for the URL
 *  url    is the URL starting with the first '/'
 *  def_port is the default port for this scheme.
 */
int ap_proxy_ajp_canon(request_rec *r, char *url)
{
    char *host, *path, *search, sport[7];
    const char *err;
    const char *scheme;
    apr_port_t port, def_port;

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
             "proxy: AJP: canonicalising URL %s", url);

    /* ap_port_of_scheme() */
    if (strncasecmp(url, "http:", 5) == 0) {
        url += 5;
        scheme = "http";
    }
    else if (strncasecmp(url, "https:", 6) == 0) {
        url += 6;
        scheme = "https";
    }
    else {
        return DECLINED;
    }
    def_port = apr_uri_port_of_scheme(scheme);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "proxy: AJP: canonicalising URL %s", url);

    /* do syntatic check.
     * We break the URL into host, port, path, search
     */
    port = def_port;
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error parsing URL %s: %s",
                      url, err);
        return HTTP_BAD_REQUEST;
    }

    /* now parse path/search args, according to rfc1738 */
    /* N.B. if this isn't a true proxy request, then the URL _path_
     * has already been decoded.  True proxy requests have r->uri
     * == r->unparsed_uri, and no others have that property.
     */
    if (r->uri == r->unparsed_uri) {
        search = strchr(url, '?');
        if (search != NULL)
            *(search++) = '\0';
    }
    else
        search = r->args;

    /* process path */
    path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, r->proxyreq);
    if (path == NULL)
        return HTTP_BAD_REQUEST;

    if (port != def_port)
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    else
        sport[0] = '\0';

    if (ap_strchr_c(host, ':')) { /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "://", host, sport, 
            "/", path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}
 
static
apr_status_t ap_proxy_http_determine_connection(apr_pool_t *p, request_rec *r,
                                                proxy_ajp_conn_t *p_conn,
                                                conn_rec *c,
                                                proxy_server_conf *conf,
                                                apr_uri_t *uri,
                                                char **url,
                                                const char *proxyname,
                                                apr_port_t proxyport,
                                                char *server_portstr,
                                                int server_portstr_size) {
    int server_port;
    apr_status_t err;
    apr_sockaddr_t *uri_addr;
    /*
     * Break up the URL to determine the host to connect to
     */

    /* we break the URL into host, port, uri */
    if (APR_SUCCESS != apr_uri_parse(p, *url, uri)) {
        return ap_proxyerror(r, HTTP_BAD_REQUEST,
                             apr_pstrcat(p,"URI cannot be parsed: ", *url,
                                         NULL));
    }
    if (!uri->port) {
        uri->port = apr_uri_port_of_scheme(uri->scheme);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: AJP connecting %s to %s:%d", *url, uri->hostname,
                 uri->port);

    /* do a DNS lookup for the destination host */
    /* see memory note above */
    err = apr_sockaddr_info_get(&uri_addr, apr_pstrdup(c->pool, uri->hostname),
                                APR_UNSPEC, uri->port, 0, c->pool);

    /* allocate these out of the connection pool - the check on
     * r->connection->id makes sure that this string does not get accessed
     * past the connection lifetime */
    /* are we connecting directly, or via a proxy? */
    if (proxyname) {
        p_conn->name = apr_pstrdup(c->pool, proxyname);
        p_conn->port = proxyport;
        /* see memory note above */
        err = apr_sockaddr_info_get(&p_conn->addr, p_conn->name, APR_UNSPEC,
                                    p_conn->port, 0, c->pool);
    } else {
        p_conn->name = apr_pstrdup(c->pool, uri->hostname);
        p_conn->port = uri->port;
        p_conn->addr = uri_addr;
        *url = apr_pstrcat(p, uri->path, uri->query ? "?" : "",
                           uri->query ? uri->query : "",
                           uri->fragment ? "#" : "",
                           uri->fragment ? uri->fragment : "", NULL);
    }

    if (err != APR_SUCCESS) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             apr_pstrcat(p, "DNS lookup failure for: ",
                                         p_conn->name, NULL));
    }

    /* Get the server port for the Via headers */
    {
        server_port = ap_get_server_port(r);
        if (ap_is_default_port(server_port, r)) {
            strcpy(server_portstr,"");
        } else {
            apr_snprintf(server_portstr, server_portstr_size, ":%d",
                         server_port);
        }
    }

    /* check if ProxyBlock directive on this host */
    if (OK != ap_proxy_checkproxyblock(r, conf, uri_addr)) {
        return ap_proxyerror(r, HTTP_FORBIDDEN,
                             "Connect to remote machine blocked");
    }
    return OK;
}

static
apr_status_t ap_proxy_http_create_connection(apr_pool_t *p, request_rec *r,
                                             proxy_ajp_conn_t *p_conn,
                                             conn_rec *c, conn_rec **origin,
                                             proxy_conn_rec *backend,
                                             proxy_server_conf *conf,
                                             const char *proxyname) {
    int failed=0, new=0;
    apr_socket_t *client_socket = NULL;

    /* We have determined who to connect to. Now make the connection, supporting
     * a KeepAlive connection.
     */

    /* get all the possible IP addresses for the destname and loop through them
     * until we get a successful connection
     */

    /* if a keepalive socket is already open, check whether it must stay
     * open, or whether it should be closed and a new socket created.
     */
    /* see memory note above */
    if (backend->connection) {
        client_socket = ap_get_module_config(backend->connection->conn_config, &core_module);
        if ((backend->connection->id == c->id) &&
            (backend->port == p_conn->port) &&
            (backend->hostname) &&
            (!apr_strnatcasecmp(backend->hostname, p_conn->name))) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: keepalive address match (keep original socket)");
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: keepalive address mismatch / connection has"
                         " changed (close old socket (%s/%s, %d/%d))", 
                         p_conn->name, backend->hostname, p_conn->port,
                         backend->port);
            apr_socket_close(client_socket);
            backend->connection = NULL;
        }
    }

    /* get a socket - either a keepalive one, or a new one */
    new = 1;
    if ((backend->connection) && (backend->connection->id == c->id)) {
        apr_size_t buffer_len = 1;
        char test_buffer[1]; 
        apr_status_t socket_status;
        apr_interval_time_t current_timeout;

        /* use previous keepalive socket */
        *origin = backend->connection;
        p_conn->sock = client_socket;
        new = 0;

        /* save timeout */
        apr_socket_timeout_get(p_conn->sock, &current_timeout);
        /* set no timeout */
        apr_socket_timeout_set(p_conn->sock, 0);
        socket_status = apr_socket_recv(p_conn->sock, test_buffer, &buffer_len);
        /* put back old timeout */
        apr_socket_timeout_set(p_conn->sock, current_timeout);
        if ( APR_STATUS_IS_EOF(socket_status) ) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "proxy: AJP: previous connection is closed");
            new = 1;
        }
    }
    if (new) {

        /* create a new socket */
        backend->connection = NULL;

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
        failed = ap_proxy_connect_to_backend(&p_conn->sock, "HTTP",
                                             p_conn->addr, p_conn->name,
                                             conf, r->server, c->pool);

        /* handle a permanent error on the connect */
        if (failed) {
            if (proxyname) {
                return DECLINED;
            } else {
                return HTTP_BAD_GATEWAY;
            }
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: socket is connected");

        /* the socket is now open, create a new backend server connection */
        *origin = ap_run_create_connection(c->pool, r->server, p_conn->sock,
                                           r->connection->id,
                                           r->connection->sbh, c->bucket_alloc);
        if (!*origin) {
        /* the peer reset the connection already; ap_run_create_connection() 
         * closed the socket
         */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                         r->server, "proxy: an error occurred creating a "
                         "new connection to %pI (%s)", p_conn->addr,
                         p_conn->name);
            apr_socket_close(p_conn->sock);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        backend->connection = *origin;
        backend->hostname = apr_pstrdup(c->pool, p_conn->name);
        backend->port = p_conn->port;

        if (backend->is_ssl) {
            if (!ap_proxy_ssl_enable(backend->connection)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                             r->server, "proxy: failed to enable ssl support "
                             "for %pI (%s)", p_conn->addr, p_conn->name);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
        else {
            ap_proxy_ssl_disable(backend->connection);
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: connection complete to %pI (%s)",
                     p_conn->addr, p_conn->name);

        /* set up the connection filters */
        ap_run_pre_connection(*origin, p_conn->sock);
    }
    return OK;
}


static
apr_status_t ap_proxy_ajp_request(apr_pool_t *p, request_rec *r,
                                   proxy_ajp_conn_t *p_conn, conn_rec *origin, 
                                   proxy_server_conf *conf,
                                   apr_uri_t *uri,
                                   char *url, char *server_portstr)
{
    apr_status_t status;
    int result;
    apr_bucket_brigade *input_brigade;

    /*
     * Send the AJP request to the remote server
     */

    /* send request headers */
    status = ajp_send_header(p_conn->sock,r);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: request failed to %pI (%s)",
                     p_conn->addr, p_conn->name);
        return status;
    }

    /* read the first bloc of data */
    input_brigade = apr_brigade_create(p, r->connection->bucket_alloc);
    status = ap_get_brigade(r->input_filters, input_brigade,
                            AP_MODE_READBYTES, APR_BLOCK_READ,
                            8186);
 
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: ap_get_brigade failed");
        apr_brigade_destroy(input_brigade);
        return status;
    }

    /* have something */
    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: APR_BUCKET_IS_EOS");
    }

    if (1) { /* XXXX only when something to send ? */
        void *msg;
        apr_size_t bufsiz;
        char *buff;
        long len;
        status = ajp_alloc_data_msg(r, &buff, &bufsiz, &msg);
        if (status != APR_SUCCESS) {
            return status;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: data to read (max %d at %08x)", bufsiz, buff);

        /* XXXX calls apr_brigade_flatten... */
        status = apr_brigade_flatten(input_brigade, buff, &bufsiz);
        if (status != APR_SUCCESS) {
             ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: apr_brigade_flatten");
            return status;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: got %d byte of data", bufsiz);
        if (bufsiz > 0) {
            status = ajp_send_data_msg(p_conn->sock, r, msg, bufsiz);
            if (status != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                             "proxy: request failed to %pI (%s)",
                             p_conn->addr, p_conn->name);
                return status;
            }
        }
    }

    /* read the response */
    status = ajp_read_header(p_conn->sock, r, &(p_conn->data));
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: request failed to %pI (%s)",
                     p_conn->addr, p_conn->name);
        return status;
    }

    /* parse the reponse */
    result = ajp_parse_type(r,p_conn->data);
    if (result == 4) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: got response from %pI (%s)",
                     p_conn->addr, p_conn->name);
        return APR_SUCCESS;
    }

    /* XXXX: need logic to send the rest of the data */
/*
    status = ajp_send_data(p_conn->sock,r);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: request failed to %pI (%s)",
                     p_conn->addr, p_conn->name);
        return status;
    }
 */

    return APR_SUCCESS;
}

/*
 * Process the AJP response, data already contains the first part of it.
 */
static
apr_status_t ap_proxy_ajp_process_response(apr_pool_t * p, request_rec *r,
                                            proxy_ajp_conn_t *p_conn,
                                            conn_rec *origin,
                                            proxy_conn_rec *backend,
                                            proxy_server_conf *conf,
                                            char *server_portstr) {
    conn_rec *c = r->connection;
    apr_bucket *e;
    apr_bucket_brigade *bb;
    int type;
    apr_status_t status;

    bb = apr_brigade_create(p, c->bucket_alloc);
    
    type = ajp_parse_type(r, p_conn->data);
    status = APR_SUCCESS;
    while (type != 5) {
        if (type == 4) {
            /* AJP13_SEND_HEADERS: process them */
            status = ajp_parse_headers(r, p_conn->data); 
            if (status != APR_SUCCESS) {
                break;
            }
        } else if  (type == 3) {
            /* AJP13_SEND_BODY_CHUNK: piece of data */
            apr_size_t size;
            char *buff;

            status = ajp_parse_data(r, p_conn->data, &size, &buff);
            e = apr_bucket_transient_create(buff, size, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
        } else {
            status = APR_EGENERAL;
            break;
        }
        /* Read the next message */
        status = ajp_read_header(p_conn->sock, r, &(p_conn->data));
        if (status != APR_SUCCESS) {
            break;
        }
        type = ajp_parse_type(r, p_conn->data);
    }
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "proxy: error reading headers from remote "
                      "server %s:%d", p_conn->name, p_conn->port);
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Error reading from remote server");
    }

    /* The page is ready give it to the rest of the logic */
    e = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "proxy: error processing body");
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Error reading from remote server");
    } 

    return OK;
}

static
apr_status_t ap_proxy_http_cleanup(request_rec *r, proxy_ajp_conn_t *p_conn,
                                   proxy_conn_rec *backend) {
    /* If there are no KeepAlives, or if the connection has been signalled
     * to close, close the socket and clean up
     */

    /* if the connection is < HTTP/1.1, or Connection: close,
     * we close the socket, otherwise we leave it open for KeepAlive support
     */
    if (p_conn->close || (r->proto_num < HTTP_VERSION(1,1))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "ap_proxy_http_cleanup closing %d %d %d %s",
                       p_conn->sock, p_conn->close, r->proto_num, apr_table_get(r->headers_out, "Connection"));
        if (p_conn->sock) {
            apr_socket_close(p_conn->sock);
            p_conn->sock = NULL;
            backend->connection = NULL;
        }
    }
    return OK;
}

/*
 * This handles http:// URLs, and other URLs using a remote proxy over http
 * If proxyhost is NULL, then contact the server directly, otherwise
 * go via the proxy.
 * Note that if a proxy is used, then URLs other than http: can be accessed,
 * also, if we have trouble which is clearly specific to the proxy, then
 * we return DECLINED so that we can try another proxy. (Or the direct
 * route.)
 */
int ap_proxy_ajp_handler(request_rec *r, proxy_server_conf *conf,
                          char *url, const char *proxyname, 
                          apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    conn_rec *origin = NULL;
    proxy_conn_rec *backend = NULL;
    int is_ssl = 0;

    /* Note: Memory pool allocation.
     * A downstream keepalive connection is always connected to the existence
     * (or not) of an upstream keepalive connection. If this is not done then
     * load balancing against multiple backend servers breaks (one backend
     * server ends up taking 100% of the load), and the risk is run of
     * downstream keepalive connections being kept open unnecessarily. This
     * keeps webservers busy and ties up resources.
     *
     * As a result, we allocate all sockets out of the upstream connection
     * pool, and when we want to reuse a socket, we check first whether the
     * connection ID of the current upstream connection is the same as that
     * of the connection when the socket was opened.
     */
    apr_pool_t *p = r->connection->pool;
    conn_rec *c = r->connection;
    apr_uri_t *uri = apr_palloc(r->connection->pool, sizeof(*uri));
    proxy_ajp_conn_t *p_conn = apr_pcalloc(r->connection->pool,
                                           sizeof(*p_conn));

    
    /* only use stored info for top-level pages. Sub requests don't share 
     * in keepalives
     */
    if (!r->main) {
        backend = (proxy_conn_rec *) ap_get_module_config(c->conn_config,
                                                      &proxy_ajp_module);
    }
    /* create space for state information */
    if (!backend) {
        backend = apr_pcalloc(c->pool, sizeof(proxy_conn_rec));
        backend->connection = NULL;
        backend->hostname = NULL;
        backend->port = 0;
        if (!r->main) {
            ap_set_module_config(c->conn_config, &proxy_ajp_module, backend);
        }
    }

    if (strncasecmp(url, "ajp:", 4) != 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: AJP: declining URL %s", url);
        return DECLINED;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "proxy: AJP: serving URL %s", url);
    
    
    /* only use stored info for top-level pages. Sub requests don't share 
     * in keepalives
     */
    if (!r->main) {
        backend = (proxy_conn_rec *) ap_get_module_config(c->conn_config,
                                                      &proxy_ajp_module);
    }
    /* create space for state information */
    if (!backend) {
        backend = apr_pcalloc(c->pool, sizeof(proxy_conn_rec));
        backend->connection = NULL;
        backend->hostname = NULL;
        backend->port = 0;
        if (!r->main) {
            ap_set_module_config(c->conn_config, &proxy_ajp_module, backend);
        }
    }

    backend->is_ssl = is_ssl;

    /* Step One: Determine Who To Connect To */
    status = ap_proxy_http_determine_connection(p, r, p_conn, c, conf, uri,
                                                &url, proxyname, proxyport,
                                                server_portstr,
                                                sizeof(server_portstr));
    if ( status != OK ) {
        return status;
    }

    /* Step Two: Make the Connection */
    status = ap_proxy_http_create_connection(p, r, p_conn, c, &origin, backend,
                                             conf, proxyname);
    if ( status != OK ) {
        return status;
    }
   
    /* Step Three: Send the Request */
    status = ap_proxy_ajp_request(p, r, p_conn, origin, conf, uri, url,
                                   server_portstr);
    if ( status != OK ) {
        return status;
    }

    /* Step Four: Receive the Response */
    status = ap_proxy_ajp_process_response(p, r, p_conn, origin, backend, conf,
                                            server_portstr);
    if ( status != OK ) {
        /* clean up even if there is an error */
        ap_proxy_http_cleanup(r, p_conn, backend);
        return status;
    }

    /* Step Five: Clean Up */
    status = ap_proxy_http_cleanup(r, p_conn, backend);
    if ( status != OK ) {
        return status;
    }

    return OK;
}

static void ap_proxy_http_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(ap_proxy_ajp_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(ap_proxy_ajp_canon, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA proxy_ajp_module = {
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    NULL,              /* command apr_table_t */
    ap_proxy_http_register_hook/* register hooks */
};

