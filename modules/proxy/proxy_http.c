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

#define CORE_PRIVATE

#include "mod_proxy.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "util_filter.h"
#include "ap_config.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_connection.h"
#include "util_date.h"

/*
 * Canonicalise http-like URLs.
 *  scheme is the scheme for the URL
 *  url    is the URL starting with the first '/'
 *  def_port is the default port for this scheme.
 */
int ap_proxy_http_canon(request_rec *r, char *url, const char *scheme, int def_port)
{
    char *host, *path, *search, sport[7];
    const char *err;
    int port;

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
 
static const char *ap_proxy_location_reverse_map(request_rec *r, const char *url)
{
    void *sconf;
    proxy_server_conf *conf;
    struct proxy_alias *ent;
    int i, l1, l2;
    char *u;

    /* XXX FIXME: Make sure this handled the ambiguous case of the :80
     * after the hostname */

    sconf = r->server->module_config;
    conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
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
int ap_proxy_http_handler(request_rec *r, char *url,
		       const char *proxyhost, int proxyport)
{
    apr_pool_t *p = r->pool;
    char *desthost;
    int destport = 0;
    char *destportstr = NULL;
    char server_portstr[32];
    const char *uri = NULL;
    apr_socket_t *sock;
    int i, len, backasswards;
    apr_status_t err;
    apr_array_header_t *headers_in_array;
    apr_table_entry_t *headers_in;
    struct sockaddr_in server;
    struct in_addr destaddr;
    char buffer[HUGE_STRING_LEN];
    char *response;
    char *buf;
    conn_rec *origin;
    apr_bucket *e;
    apr_bucket_brigade *bb = apr_brigade_create(p);

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    struct noproxy_entry *npent = (struct noproxy_entry *) conf->noproxies->elts;

    memset(&server, '\0', sizeof(server));
    server.sin_family = AF_INET;

    /* We break the URL into host, port, uri */
    {
        const char *buf;

        uri = strstr(url, "://");
        if (uri == NULL)
	    return HTTP_BAD_REQUEST;
        uri += 3;
        destport = DEFAULT_HTTP_PORT;
        buf = ap_strchr_c(uri, '/');
        if (buf == NULL) {
	    desthost = apr_pstrdup(p, uri);
	    uri = "/";
        }
        else {
	    char *q = apr_palloc(p, buf - uri + 1);
	    memcpy(q, uri, buf - uri);
	    q[buf - uri] = '\0';
	    uri = buf;
            desthost = q;
        }
    }

    /* Get the port number - put it in destport and destportstr */
    {
        char *buf;
        buf = ap_strchr(desthost, ':');
        if (buf != NULL) {
	    *(buf++) = '\0';
	    if (apr_isdigit(*buf)) {
	        destport = atoi(buf);
	        destportstr = buf;
	    }
        }
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
    destaddr.s_addr = apr_inet_addr(desthost);
    for (i = 0; i < conf->noproxies->nelts; i++) {
	if ((npent[i].name != NULL
            && ap_strstr_c(desthost, npent[i].name) != NULL)
	    || destaddr.s_addr == npent[i].addr.s_addr
            || npent[i].name[0] == '*')
	    return ap_proxyerror(r, HTTP_FORBIDDEN,
				 "Connect to remote machine blocked");
    }

    if ((apr_socket_create(&sock, APR_INET, SOCK_STREAM, p)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "proxy: error creating socket");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#if !defined(TPF) && !defined(BEOS)
    if (conf->recv_buffer_size > 0 && apr_setsocketopt(sock, APR_SO_RCVBUF,
       conf->recv_buffer_size)) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
    }
#endif

    if (proxyhost != NULL) {
        err = ap_proxy_doconnect(sock, (char *)proxyhost, proxyport, r);
    }
    else {
        err = ap_proxy_doconnect(sock, (char *)desthost, destport, r);
    }

    if (err != APR_SUCCESS) {
	if (proxyhost != NULL)
	    return DECLINED;	/* try again another way */
	else
	    return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_pstrcat(p,
				"Could not connect to remote machine: ",
				desthost, NULL));
    }

    origin = ap_new_connection(p, r->server, sock, 0);
    if (!origin) {
        /* the peer reset the connection already; ap_new_connection() 
         * closed the socket */
        /* XXX somebody that knows what they're doing add an error path */
	/* XXX how's this? */
	return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_pstrcat(p,
			     "Connection reset by peer: ",
			     desthost, NULL));
    }

    ap_add_output_filter("CORE", NULL, NULL, origin);

    /* strip connection listed hop-by-hop headers from the request */
    ap_proxy_clear_connection(p, r->headers_in);

    buf = apr_pstrcat(p, r->method, " ", proxyhost ? url : uri,
                      " HTTP/1.1" CRLF, NULL);
    e = apr_bucket_pool_create(buf, strlen(buf), p);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    if (destportstr != NULL && destport != DEFAULT_HTTP_PORT) {
        buf = apr_pstrcat(p, "Host: ", desthost, ":", destportstr, CRLF, NULL);
        e = apr_bucket_pool_create(buf, strlen(buf), p);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }
    else {
        buf = apr_pstrcat(p, "Host: ", desthost, CRLF, NULL);
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
        apr_table_mergen(r->headers_in, "X-Forwarded-For", r->connection->remote_ip);

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

    /* send request headers */
    headers_in_array = apr_table_elts(r->headers_in);
    headers_in = (apr_table_entry_t *) headers_in_array->elts;
    for (i = 0; i < headers_in_array->nelts; i++) {
	if (headers_in[i].key == NULL || headers_in[i].val == NULL

	/* Clear out hop-by-hop request headers not to send
	 * RFC2616 13.5.1 says we should strip these headers
	 */
	    || !strcasecmp(headers_in[i].key, "Host")	/* Already sent */
            || !strcasecmp(headers_in[i].key, "Keep-Alive")
            || !strcasecmp(headers_in[i].key, "TE")
            || !strcasecmp(headers_in[i].key, "Trailer")
            || !strcasecmp(headers_in[i].key, "Transfer-Encoding")
            || !strcasecmp(headers_in[i].key, "Upgrade")

	    /* XXX: @@@ FIXME: "Proxy-Authorization" should *only* be 
	     * suppressed if THIS server requested the authentication,
	     * not when a frontend proxy requested it!
             *
             * The solution to this problem is probably to strip out
             * the Proxy-Authorisation header in the authorisation
             * code itself, not here. This saves us having to signal
             * somehow whether this request was authenticated or not.
	     */
	    || !strcasecmp(headers_in[i].key, "Proxy-Authorization")
	    || !strcasecmp(headers_in[i].key, "Proxy-Authenticate"))
	    continue;

        buf = apr_pstrcat(p, headers_in[i].key, ": ", headers_in[i].val, CRLF, NULL);
        e = apr_bucket_pool_create(buf, strlen(buf), p);
        APR_BRIGADE_INSERT_TAIL(bb, e);

    }

    /* we don't yet support keepalives - but we will soon, I promise! */
    buf = apr_pstrcat(p, "Connection: close", CRLF, NULL);
    e = apr_bucket_pool_create(buf, strlen(buf), p);
    APR_BRIGADE_INSERT_TAIL(bb, e);

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
        }
    }
    /* Flush the data to the origin server */
    e = apr_bucket_flush_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);
    ap_pass_brigade(origin->output_filters, bb);

    ap_add_input_filter("HTTP_IN", NULL, NULL, origin);
    ap_add_input_filter("CORE_IN", NULL, NULL, origin);

    apr_brigade_destroy(bb);
    bb = apr_brigade_create(p);
    
    /* Tell http_filter to grab the data one line at a time. */
    origin->remain = 0;

    ap_get_brigade(origin->input_filters, bb, AP_MODE_BLOCKING);
    e = APR_BRIGADE_FIRST(bb);
    apr_bucket_read(e, (const char **)&response, &len, APR_BLOCK_READ);
    if (len == -1) {
	apr_socket_close(sock);
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	     "ap_get_brigade() - proxy receive - Error reading from remote server %s (length %d)",
	     proxyhost ? proxyhost : desthost, len);
	return ap_proxyerror(r, HTTP_BAD_GATEWAY,
			     "Error reading from remote server");
    } else if (len == 0) {
	apr_socket_close(sock);
	return ap_proxyerror(r, HTTP_BAD_GATEWAY,
			     "Document contains no data");
    }
    APR_BUCKET_REMOVE(e);
    apr_bucket_destroy(e);

    /* Is it an HTTP/1 response?  This is buggy if we ever see an HTTP/1.10 */
    if (ap_checkmask(response, "HTTP/#.# ###*")) {
	int major, minor;
	if (2 != sscanf(response, "HTTP/%u.%u", &major, &minor)) {
	    major = 1;
	    minor = 1;
	}

        /* If not an HTTP/1 message or if the status line was > 8192 bytes */
	if (response[5] != '1' || response[len - 1] != '\n') {
	    apr_socket_close(sock);
	    return HTTP_BAD_GATEWAY;
	}
	backasswards = 0;
	response[--len] = '\0';

	response[12] = '\0';
	r->status = atoi(&response[9]);

	response[12] = ' ';
	r->status_line = apr_pstrdup(p, &response[9]);

        /* read the headers. */
        /* N.B. for HTTP/1.0 clients, we have to fold line-wrapped headers */
        /* Also, take care with headers with multiple occurences. */

	r->headers_out = ap_proxy_read_headers(r, buffer, HUGE_STRING_LEN, origin);
	if (r->headers_out == NULL) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r->server,
		 "proxy: Bad HTTP/%d.%d header returned by %s (%s)",
		 major, minor, r->uri, r->method);
	}
        else
        {
	    /* strip connection listed hop-by-hop headers from response */
	    const char *buf;
            ap_proxy_clear_connection(p, r->headers_out);
            if ((buf = apr_table_get(r->headers_out, "Content-type"))) {
                r->content_type = apr_pstrdup(p, buf);
            }
        }

        /* handle Via header in response */
	if (conf->viaopt != via_off && conf->viaopt != via_block) {
	    /* Create a "Via:" response header entry and merge it */
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
    }
    else {
        /* an http/0.9 response */
	backasswards = 1;
	r->status = 200;
	r->status_line = "200 OK";
    }

    /* munge the Location and URI response headers according to ProxyPassReverse */
    {
	const char *buf;
        if ((buf = apr_table_get(r->headers_out, "Location")) != NULL)
            apr_table_set(r->headers_out, "Location", ap_proxy_location_reverse_map(r, buf));
        if ((buf = apr_table_get(r->headers_out, "Content-Location")) != NULL)
            apr_table_set(r->headers_out, "Content-Location", ap_proxy_location_reverse_map(r, buf));
        if ((buf = apr_table_get(r->headers_out, "URI")) != NULL)
            apr_table_set(r->headers_out, "URI", ap_proxy_location_reverse_map(r, buf));
    }

    r->sent_bodyct = 1;
    /* Is it an HTTP/0.9 response? If so, send the extra data */
    if (backasswards) {
        apr_ssize_t cntr = len;
        /* FIXME: what is buffer used for here? It is of limited size */
        e = apr_bucket_heap_create(buffer, cntr, 0, NULL);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }

    /* send body */
    /* HTTP/1.0 tells us to read to EOF, rather than content-length bytes */
    if (!r->header_only) {
        origin->remain = -1;
        while (ap_get_brigade(origin->input_filters, bb, AP_MODE_BLOCKING) == APR_SUCCESS) {
            if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
                ap_pass_brigade(r->output_filters, bb);
                break;
            }
            ap_pass_brigade(r->output_filters, bb);
            apr_brigade_destroy(bb);
            bb = apr_brigade_create(p);
        }
    }

    apr_socket_close(sock);
    return OK;
}
