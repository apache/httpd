/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/* HTTP routines for Apache proxy */

#include "mod_proxy.h"

module AP_MODULE_DECLARE_DATA proxy_http_module;

int ap_proxy_http_canon(request_rec *r, char *url);
int ap_proxy_http_handler(request_rec *r, proxy_server_conf *conf,
                          char *url, const char *proxyname, 
                          apr_port_t proxyport);


/*
 * Canonicalise http-like URLs.
 *  scheme is the scheme for the URL
 *  url    is the URL starting with the first '/'
 *  def_port is the default port for this scheme.
 */
int ap_proxy_http_canon(request_rec *r, char *url)
{
    char *host, *path, *search, sport[7];
    const char *err;
    const char *scheme;
    apr_port_t port, def_port;

    /* ap_default_port_for_scheme() */
    if (strncasecmp(url, "http:", 5) == 0) {
	url += 5;
	scheme = "http";
    }
    else if (strncasecmp(url, "https:", 6) == 0) {
	url += 6;
	scheme = "https:";
    }
    else {
	return DECLINED;
    }
    def_port = apr_uri_default_port_for_scheme(scheme);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		 "proxy: HTTP: canonicalising URL %s", url);

    /* do syntatic check.
     * We break the URL into host, port, path, search
     */
    port = def_port;
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err)
	return HTTP_BAD_REQUEST;

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

    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "://", host, sport, "/",
		   path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}
 
static const char *ap_proxy_location_reverse_map(request_rec *r, proxy_server_conf *conf, const char *url)
{
    struct proxy_alias *ent;
    int i, l1, l2;
    char *u;

    /* XXX FIXME: Make sure this handled the ambiguous case of the :80
     * after the hostname */

    l1 = strlen(url);
    ent = (struct proxy_alias *)conf->raliases->elts;
    for (i = 0; i < conf->raliases->nelts; i++) {
        l2 = strlen(ent[i].real);
        if (l1 >= l2 && strncmp(ent[i].real, url, l2) == 0) {
            u = apr_pstrcat(r->pool, ent[i].fake, &url[l2], NULL);
            return ap_construct_url(r->pool, u, r);
        }
    }
    return url;
}

/* Clear all connection-based headers from the incoming headers table */
static void ap_proxy_clear_connection(apr_pool_t *p, apr_table_t *headers)
{
    const char *name;
    char *next = apr_pstrdup(p, apr_table_get(headers, "Connection"));

    apr_table_unset(headers, "Proxy-Connection");
    if (!next)
		return;

    while (*next) {
	name = next;
	while (*next && !apr_isspace(*next) && (*next != ','))
	    ++next;
	while (*next && (apr_isspace(*next) || (*next == ','))) {
	    *next = '\0';
	    ++next;
	}
	apr_table_unset(headers, name);
    }
    apr_table_unset(headers, "Connection");
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
int ap_proxy_http_handler(request_rec *r, proxy_server_conf *conf,
                          char *url, const char *proxyname, 
                          apr_port_t proxyport)
{
    request_rec *rp;
    const char *connectname;
    int connectport = 0;
    apr_sockaddr_t *uri_addr;
    apr_sockaddr_t *connect_addr;
    char server_portstr[32];
    apr_socket_t *sock;
    int i, len, backasswards, eos, close=0, failed=0, new=0;
    apr_status_t err, rv;
    apr_array_header_t *headers_in_array;
    apr_table_entry_t *headers_in;
    char buffer[HUGE_STRING_LEN];
    char *buf;
    conn_rec *origin = NULL;
    apr_uri_components uri;
    proxy_conn_rec *backend;

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
    apr_bucket *e;
    apr_bucket_brigade *bb = apr_brigade_create(p);

    /* is it for us? */
    if (strncasecmp(url, "http:", 5)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: HTTP: rejecting URL %s", url);
	return DECLINED; /* only interested in HTTP */
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		 "proxy: HTTP: serving URL %s", url);
    
    /* create space for state information */
    backend = (proxy_conn_rec *) ap_get_module_config(c->conn_config, &proxy_http_module);
    if (!backend) {
	backend = ap_pcalloc(c->pool, sizeof(proxy_conn_rec));
	backend->connection = NULL;
	backend->hostname = NULL;
	backend->port = 0;
	ap_set_module_config(c->conn_config, &proxy_http_module, backend);
    }

    /*
     * Step One: Determine Who To Connect To
     *
     * Break up the URL to determine the host to connect to
     */

    /* we break the URL into host, port, uri */
    if (APR_SUCCESS != apr_uri_parse_components(p, url, &uri)) {
	return ap_proxyerror(r, HTTP_BAD_REQUEST,
			     apr_pstrcat(p,"URI cannot be parsed: ", url, NULL));
    }
    if (!uri.port) {
	uri.port = apr_uri_default_port_for_scheme(uri.scheme);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		 "proxy: HTTP connecting %s to %s:%d", url, uri.hostname, uri.port);

    /* do a DNS lookup for the destination host */
    /* see memory note above */
    err = apr_sockaddr_info_get(&uri_addr, apr_pstrdup(c->pool, uri.hostname), APR_UNSPEC, uri.port, 0, c->pool);

    /* allocate these out of the connection pool - the check on r->connection->id makes
     * sure that this string does not get accessed past the connection lifetime */
    /* are we connecting directly, or via a proxy? */
    if (proxyname) {
	connectname = apr_pstrdup(c->pool,proxyname);
	connectport = proxyport;
	/* see memory note above */
        err = apr_sockaddr_info_get(&connect_addr, connectname, APR_UNSPEC, connectport, 0, c->pool);
    }
    else {
	connectname = apr_pstrdup(c->pool, uri.hostname);
	connectport = uri.port;
	connect_addr = uri_addr;
	url = apr_pstrcat(p, uri.path, uri.query ? "?" : "",
			  uri.query ? uri.query : "", uri.fragment ? "#" : "",
			  uri.fragment ? uri.fragment : "", NULL);
    }


    /* Get the server port for the Via headers */
    {
	i = ap_get_server_port(r);
	if (ap_is_default_port(i,r)) {
	    strcpy(server_portstr,"");
	} else {
	    apr_snprintf(server_portstr, sizeof server_portstr, ":%d", i);
	}
    }

    /* check if ProxyBlock directive on this host */
    if (OK != ap_proxy_checkproxyblock(r, conf, uri_addr)) {
	return ap_proxyerror(r, HTTP_FORBIDDEN,
			     "Connect to remote machine blocked");
    }


    /*
     * Step Two: Make the Connection
     *
     * We have determined who to connect to. Now make the connection, supporting
     * a KeepAlive connection.
     */

    /* get all the possible IP addresses for the destname and loop through them
     * until we get a successful connection
     */
    if (APR_SUCCESS != err) {
	return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_pstrcat(p,
                             "DNS lookup failure for: ",
                             connectname, NULL));
    }

    /* if a keepalive socket is already open, check whether it must stay
     * open, or whether it should be closed and a new socket created.
     */
    /* see memory note above */
    if (backend->connection) {
	if ((backend->connection->id == c->id) &&
	    (backend->port == connectport) &&
	    (backend->hostname) &&
            (!apr_strnatcasecmp(backend->hostname,connectname))) {
	    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
			 "proxy: keepalive address match (keep original socket)");
        }
	else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
			 "proxy: keepalive address mismatch / connection has"
			 " changed (close old socket (%s/%s, %d/%d))", 
			 connectname, backend->hostname, 
			 connectport, backend->port);
            apr_socket_close(backend->connection->client_socket);
            backend->connection = NULL;
	}
    }

    /* get a socket - either a keepalive one, or a new one */
    new = 1;
    if ((backend->connection) && (backend->connection->id == c->id)) {

	/* use previous keepalive socket */
	origin = backend->connection;
	sock = origin->client_socket;
	new = 0;

	/* reset the connection filters */
	ap_proxy_reset_output_filters(origin);

	/* XXX FIXME: If the socket has since closed, change new to 1 so
	 * a new socket is opened */
    }
    if (new) {

	/* create a new socket */
	backend->connection = NULL;

	/* see memory note above */
	if ((rv = apr_socket_create(&sock, APR_INET, SOCK_STREAM, c->pool)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
			 "proxy: error creating socket");
	    return HTTP_INTERNAL_SERVER_ERROR;
	}

#if !defined(TPF) && !defined(BEOS)
	if (conf->recv_buffer_size > 0 && (rv = apr_setsocketopt(sock, APR_SO_RCVBUF,
	    conf->recv_buffer_size))) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
			  "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
	}
#endif

        /* Set a timeout on the socket */
        apr_setsocketopt(sock, APR_SO_TIMEOUT, (int)(r->server->timeout * APR_USEC_PER_SEC));

	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: socket has been created");

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


	/* try each IP address until we connect successfully */
	failed = 1;
	while (connect_addr) {

	    /* make the connection out of the socket */
	    rv = apr_connect(sock, connect_addr);

	    /* if an error occurred, loop round and try again */
            if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
			     "proxy: attempt to connect to %pI (%s) failed", 
			     connect_addr, connectname);
		connect_addr = connect_addr->next;
		continue;
            }

	    /* if we get here, all is well */
	    failed = 0;
	    break;
	}

	/* handle a permanent error from the above loop */
	if (failed) {
	    apr_socket_close(sock);
	    if (proxyname) {
		return DECLINED;
	    }
	    else {
		return HTTP_BAD_GATEWAY;
	    }
	}

	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: socket is connected");

	/* the socket is now open, create a new backend server connection */
	origin = ap_new_connection(c->pool, r->server, sock, r->connection->id);
	if (!origin) {
	    /* the peer reset the connection already; ap_new_connection() 
	     * closed the socket */
	    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
			 "proxy: an error occurred creating a new connection to %pI (%s)", connect_addr, connectname);
	    apr_socket_close(sock);
	    return HTTP_INTERNAL_SERVER_ERROR;
	}
	backend->connection = origin;
	backend->hostname = apr_pstrdup(c->pool, connectname);
	backend->port = connectport;

	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: connection complete");

	/* set up the connection filters */
	ap_proxy_pre_http_connection(origin, NULL);

    }


    /*
     * Step Three: Send the Request
     *
     * Send the HTTP/1.1 request to the remote server
     */


    /* strip connection listed hop-by-hop headers from the request */
    /* even though in theory a connection: close coming from the client
     * should not affect the connection to the server, it's unlikely
     * that subsequent client requests will hit this thread/process, so
     * we cancel server keepalive if the client does.
     */
    close += ap_proxy_liststr(apr_table_get(r->headers_in, "Connection"), "close");
    ap_proxy_clear_connection(p, r->headers_in);
    if (close) {
	apr_table_setn(r->headers_in, "Connection", "close");
	origin->keepalive = 0;
    }

    buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.1" CRLF, NULL);
    e = apr_bucket_pool_create(buf, strlen(buf), p);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    if (uri.port_str && uri.port != DEFAULT_HTTP_PORT) {
        buf = apr_pstrcat(p, "Host: ", uri.hostname, ":", uri.port_str, CRLF, NULL);
        e = apr_bucket_pool_create(buf, strlen(buf), p);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }
    else {
        buf = apr_pstrcat(p, "Host: ", uri.hostname, CRLF, NULL);
        e = apr_bucket_pool_create(buf, strlen(buf), p);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }

    /* handle Via */
    if (conf->viaopt == via_block) {
	/* Block all outgoing Via: headers */
	apr_table_unset(r->headers_in, "Via");
    } else if (conf->viaopt != via_off) {
	/* Create a "Via:" request header entry and merge it */
	/* Generate outgoing Via: header with/without server comment: */
	apr_table_mergen(r->headers_in, "Via",
		    (conf->viaopt == via_full)
			? apr_psprintf(p, "%d.%d %s%s (%s)",
				HTTP_VERSION_MAJOR(r->proto_num),
				HTTP_VERSION_MINOR(r->proto_num),
				ap_get_server_name(r), server_portstr,
				AP_SERVER_BASEVERSION)
			: apr_psprintf(p, "%d.%d %s%s",
				HTTP_VERSION_MAJOR(r->proto_num),
				HTTP_VERSION_MINOR(r->proto_num),
				ap_get_server_name(r), server_portstr)
			);
    }

    /* X-Forwarded-*: handling
     *
     * XXX Privacy Note:
     * -----------------
     *
     * These request headers are only really useful when the mod_proxy
     * is used in a reverse proxy configuration, so that useful info
     * about the client can be passed through the reverse proxy and on
     * to the backend server, which may require the information to
     * function properly.
     *
     * In a forward proxy situation, these options are a potential
     * privacy violation, as information about clients behind the proxy
     * are revealed to arbitrary servers out there on the internet.
     *
     * The HTTP/1.1 Via: header is designed for passing client
     * information through proxies to a server, and should be used in
     * a forward proxy configuation instead of X-Forwarded-*. See the
     * ProxyVia option for details.
     */

    if (PROXYREQ_REVERSE == r->proxyreq) {
        const char *buf;

        /* Add X-Forwarded-For: so that the upstream has a chance to
         * determine, where the original request came from.
         */
        apr_table_setn(r->headers_in, "X-Forwarded-For", r->connection->remote_ip);

        /* Add X-Forwarded-Host: so that upstream knows what the
         * original request hostname was.
         */
        if ((buf = apr_table_get(r->headers_in, "Host"))) {
            apr_table_setn(r->headers_in, "X-Forwarded-Host", buf);
        }

        /* Add X-Forwarded-Server: so that upstream knows what the
         * name of this proxy server is (if there are more than one)
         * XXX: This duplicates Via: - do we strictly need it?
         */
        apr_table_setn(r->headers_in, "X-Forwarded-Server",
                         r->server->server_hostname);
    }

    /* send request headers */
    headers_in_array = apr_table_elts(r->headers_in);
    headers_in = (apr_table_entry_t *) headers_in_array->elts;
    for (i = 0; i < headers_in_array->nelts; i++) {
	if (headers_in[i].key == NULL || headers_in[i].val == NULL

	/* Clear out hop-by-hop request headers not to send
	 * RFC2616 13.5.1 says we should strip these headers
	 */
	    || !apr_strnatcasecmp(headers_in[i].key, "Host")	/* Already sent */
            || !apr_strnatcasecmp(headers_in[i].key, "Keep-Alive")
            || !apr_strnatcasecmp(headers_in[i].key, "TE")
            || !apr_strnatcasecmp(headers_in[i].key, "Trailer")
            || !apr_strnatcasecmp(headers_in[i].key, "Transfer-Encoding")
            || !apr_strnatcasecmp(headers_in[i].key, "Upgrade")

	    /* XXX: @@@ FIXME: "Proxy-Authorization" should *only* be 
	     * suppressed if THIS server requested the authentication,
	     * not when a frontend proxy requested it!
             *
             * The solution to this problem is probably to strip out
             * the Proxy-Authorisation header in the authorisation
             * code itself, not here. This saves us having to signal
             * somehow whether this request was authenticated or not.
	     */
	    || !apr_strnatcasecmp(headers_in[i].key, "Proxy-Authorization")
	    || !apr_strnatcasecmp(headers_in[i].key, "Proxy-Authenticate"))
	    continue;

        buf = apr_pstrcat(p, headers_in[i].key, ": ", headers_in[i].val, CRLF, NULL);
        e = apr_bucket_pool_create(buf, strlen(buf), p);
        APR_BRIGADE_INSERT_TAIL(bb, e);

    }

    /* add empty line at the end of the headers */
    e = apr_bucket_pool_create(CRLF, strlen(CRLF), p);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    e = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);

    ap_pass_brigade(origin->output_filters, bb);

    /* send the request data, if any. */
    if (ap_should_client_block(r)) {
	while ((i = ap_get_client_block(r, buffer, sizeof buffer)) > 0) {
            e = apr_bucket_pool_create(buffer, i, p);
            APR_BRIGADE_INSERT_TAIL(bb, e);
	    e = apr_bucket_flush_create();
	    APR_BRIGADE_INSERT_TAIL(bb, e);
	    ap_pass_brigade(origin->output_filters, bb);
	    apr_brigade_cleanup(bb);
        }
    }


    /*
     * Step Four: Receive the Response
     *
     * Get response from the remote server, and pass it up the
     * filter chain
     */

    rp = ap_proxy_make_fake_req(origin, r);

    apr_brigade_cleanup(bb);

    if (APR_SUCCESS != (rv = ap_proxy_string_read(origin, bb, buffer, sizeof(buffer), &eos))) {
	apr_socket_close(sock);
	backend->connection = NULL;
	ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
	     "proxy: error reading status line from remote server %s",
	     connectname);
	return ap_proxyerror(r, HTTP_BAD_GATEWAY,
			     "Error reading from remote server");
    }
    len = strlen(buffer);

    /* Is it an HTTP/1 response?  This is buggy if we ever see an HTTP/1.10 */
    if (apr_date_checkmask(buffer, "HTTP/#.# ###*")) {
	int major, minor;

	if (2 != sscanf(buffer, "HTTP/%u.%u", &major, &minor)) {
	    major = 1;
	    minor = 1;
	}

        /* If not an HTTP/1 message or if the status line was > 8192 bytes */
	else if ((buffer[5] != '1') || (len >= sizeof(buffer)-1)) {
	    apr_socket_close(sock);
	    backend->connection = NULL;
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY,
				 apr_pstrcat(p, "Corrupt status line returned by remote server: ", buffer, NULL));
	}
	backasswards = 0;
	buffer[--len] = '\0';

	buffer[12] = '\0';
	r->status = atoi(&buffer[9]);

	buffer[12] = ' ';
	r->status_line = apr_pstrdup(p, &buffer[9]);

        /* read the headers. */
        /* N.B. for HTTP/1.0 clients, we have to fold line-wrapped headers */
        /* Also, take care with headers with multiple occurences. */

	r->headers_out = ap_proxy_read_headers(r, rp, buffer, sizeof(buffer), origin);
	if (r->headers_out == NULL) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r->server,
			 "proxy: bad HTTP/%d.%d header returned by %s (%s)",
			 major, minor, r->uri, r->method);
	    close += 1;
	}
        else
        {
	    /* strip connection listed hop-by-hop headers from response */
	    const char *buf;
            close += ap_proxy_liststr(apr_table_get(r->headers_out, "Connection"), "close");
            ap_proxy_clear_connection(p, r->headers_out);
            if ((buf = apr_table_get(r->headers_out, "Content-Type"))) {
                r->content_type = apr_pstrdup(p, buf);
            }
        }

        /* handle Via header in response */
	if (conf->viaopt != via_off && conf->viaopt != via_block) {
	    /* create a "Via:" response header entry and merge it */
            ap_table_mergen(r->headers_out, "Via",
			    (conf->viaopt == via_full)
			    ? apr_psprintf(p, "%d.%d %s%s (%s)",
				    HTTP_VERSION_MAJOR(r->proto_num),
				    HTTP_VERSION_MINOR(r->proto_num),
				    ap_get_server_name(r), server_portstr,
				    AP_SERVER_BASEVERSION)
			    : apr_psprintf(p, "%d.%d %s%s",
				    HTTP_VERSION_MAJOR(r->proto_num),
				    HTTP_VERSION_MINOR(r->proto_num),
				    ap_get_server_name(r), server_portstr)
                            );
	}

	/* cancel keepalive if HTTP/1.0 or less */
	if ((major < 1) || (minor < 1)) {
	    close += 1;
	    origin->keepalive = 0;
	}
    }
    else {
	/* an http/0.9 response */
	backasswards = 1;
	r->status = 200;
	r->status_line = "200 OK";
	close += 1;
    }

    /* we must accept 3 kinds of date, but generate only 1 kind of date */
    {
	const char *buf;
        if ((buf = apr_table_get(r->headers_out, "Date")) != NULL) {
	    apr_table_set(r->headers_out, "Date", ap_proxy_date_canon(p, buf));
	}
        if ((buf = apr_table_get(r->headers_out, "Expires")) != NULL) {
	    apr_table_set(r->headers_out, "Expires", ap_proxy_date_canon(p, buf));
	}
        if ((buf = apr_table_get(r->headers_out, "Last-Modified")) != NULL) {
	    apr_table_set(r->headers_out, "Last-Modified", ap_proxy_date_canon(p, buf));
	}
    }

    /* munge the Location and URI response headers according to ProxyPassReverse */
    {
	const char *buf;
        if ((buf = apr_table_get(r->headers_out, "Location")) != NULL) {
	    apr_table_set(r->headers_out, "Location", ap_proxy_location_reverse_map(r, conf, buf));
	}
        if ((buf = apr_table_get(r->headers_out, "Content-Location")) != NULL) {
	    apr_table_set(r->headers_out, "Content-Location", ap_proxy_location_reverse_map(r, conf, buf));
	}
        if ((buf = apr_table_get(r->headers_out, "URI")) != NULL) {
	    apr_table_set(r->headers_out, "URI", ap_proxy_location_reverse_map(r, conf, buf));
	}
    }

    r->sent_bodyct = 1;
    /* Is it an HTTP/0.9 response? If so, send the extra data */
    if (backasswards) {
        apr_ssize_t cntr = len;
        e = apr_bucket_heap_create(buffer, cntr, 0, NULL);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }

    /* send body - but only if a body is expected */
    if ((!r->header_only) &&			/* not HEAD request */
        (r->status > 199) &&			/* not any 1xx response */
        (r->status != HTTP_NO_CONTENT) &&	/* not 204 */
        (r->status != HTTP_RESET_CONTENT) &&	/* not 205 */
        (r->status != HTTP_NOT_MODIFIED)) {	/* not 304 */

	const char *buf;
	apr_size_t readbytes;

	/* if chunked - insert DECHUNK filter */
	if (ap_proxy_liststr((buf = apr_table_get(r->headers_out, "Transfer-Encoding")), "chunked")) {
	    rp->read_chunked = 1;
	    apr_table_unset(r->headers_out, "Transfer-Encoding");
	    if ((buf = ap_proxy_removestr(r->pool, buf, "chunked"))) {
		apr_table_set(r->headers_out, "Transfer-Encoding", buf);
	    }
	    ap_add_input_filter("DECHUNK", NULL, rp, origin);
	    readbytes = -1;
	}

	/* if content length - set the length to read */
	else if ((buf = apr_table_get(r->headers_out, "Content-Length"))) {
	    readbytes = atol(buf);
	}

	/* no chunked / no length therefore read till EOF and cancel keepalive */
	else {
	    close += 1;
	}

	/* if keepalive cancelled, read to EOF */
	if (close) {
	    readbytes = -1;
	}

	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: start body send");

	/* read the body, pass it to the output filters */
	while (ap_get_brigade(rp->input_filters, bb, AP_MODE_BLOCKING, &readbytes) == APR_SUCCESS) {
	    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
		ap_pass_brigade(r->output_filters, bb);
		break;
	    }
            if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS) {
                /* Ack! Phbtt! Die! User aborted! */
                close = 1;  /* this causes socket close below */
                break;
            }
            apr_brigade_cleanup(bb);
	}
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: end body send");
    }
    else {
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: header only");
    }


    /*
     * Step Five: Clean Up
     *
     * If there are no KeepAlives, or if the connection has been signalled
     * to close, close the socket and clean up
     */

    /* if the connection is < HTTP/1.1, or Connection: close,
     * we close the socket, otherwise we leave it open for KeepAlive support
     */
    if (close || (r->proto_num < HTTP_VERSION(1,1))) {
        apr_socket_close(sock);
	backend->connection = NULL;
    }

    return OK;
}

static void ap_proxy_http_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(ap_proxy_http_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(ap_proxy_http_canon, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA proxy_http_module = {
    STANDARD20_MODULE_STUFF,
    NULL,		/* create per-directory config structure */
    NULL,		/* merge per-directory config structures */
    NULL,		/* create per-server config structure */
    NULL,		/* merge per-server config structures */
    NULL,		/* command apr_table_t */
    ap_proxy_http_register_hook	/* register hooks */
};

