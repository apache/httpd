/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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

/* CONNECT method for Apache proxy */

#define CORE_PRIVATE

#include "mod_proxy.h"
#include "apr_poll.h"

module AP_MODULE_DECLARE_DATA proxy_connect_module;

int ap_proxy_connect_canon(request_rec *r, char *url);
int ap_proxy_connect_handler(request_rec *r, proxy_server_conf *conf, 
                             char *url, const char *proxyname, 
                             apr_port_t proxyport);

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

static int
allowed_port(proxy_server_conf *conf, int port)
{
    int i;
    int *list = (int *) conf->allowed_connect_ports->elts;

    for(i = 0; i < conf->allowed_connect_ports->nelts; i++) {
	if(port == list[i])
	    return 1;
    }
    return 0;
}

/* canonicalise CONNECT URLs. */
int ap_proxy_connect_canon(request_rec *r, char *url)
{

    if (r->method_number != M_CONNECT) {
	return DECLINED;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		 "proxy: CONNECT: canonicalising URL %s", url);

    return OK;
}

/* CONNECT handler */
int ap_proxy_connect_handler(request_rec *r, proxy_server_conf *conf, 
                             char *url, const char *proxyname, 
                             apr_port_t proxyport)
{
    apr_pool_t *p = r->pool;
    apr_socket_t *sock;
    apr_status_t err, rv;
    apr_size_t i, o, nbytes;
    char buffer[HUGE_STRING_LEN];
    apr_socket_t *client_socket = ap_get_module_config(r->connection->conn_config, &core_module);
    int failed;
    apr_pollset_t *pollset;
    apr_pollfd_t pollfd;
    const apr_pollfd_t *signalled;
    apr_int32_t pollcnt;
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
			     apr_pstrcat(p, "URI cannot be parsed: ", url, NULL));
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		 "proxy: CONNECT: connecting %s to %s:%d", url, uri.hostname, uri.port);

    /* do a DNS lookup for the destination host */
    err = apr_sockaddr_info_get(&uri_addr, uri.hostname, APR_UNSPEC, uri.port, 0, p);

    /* are we connecting directly, or via a proxy? */
    if (proxyname) {
	connectname = proxyname;
	connectport = proxyport;
        err = apr_sockaddr_info_get(&connect_addr, proxyname, APR_UNSPEC, proxyport, 0, p);
    }
    else {
	connectname = uri.hostname;
	connectport = uri.port;
	connect_addr = uri_addr;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		 "proxy: CONNECT: connecting to remote proxy %s on port %d", connectname, connectport);

    /* check if ProxyBlock directive on this host */
    if (OK != ap_proxy_checkproxyblock(r, conf, uri_addr)) {
	return ap_proxyerror(r, HTTP_FORBIDDEN,
			     "Connect to remote machine blocked");
    }

    /* Check if it is an allowed port */
    if (conf->allowed_connect_ports->nelts == 0) {
	/* Default setting if not overridden by AllowCONNECT */
	switch (uri.port) {
	    case APR_URI_HTTPS_DEFAULT_PORT:
	    case APR_URI_SNEWS_DEFAULT_PORT:
		break;
	    default:
                /* XXX can we call ap_proxyerror() here to get a nice log message? */
		return HTTP_FORBIDDEN;
	}
    } else if(!allowed_port(conf, uri.port)) {
        /* XXX can we call ap_proxyerror() here to get a nice log message? */
	return HTTP_FORBIDDEN;
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
	return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_pstrcat(p,
                             "DNS lookup failure for: ",
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
                                         connectname, conf, r->server,
                                         r->pool);

    /* handle a permanent error from the above loop */
    if (failed) {
        if (proxyname) {
            return DECLINED;
        }
        else {
            return HTTP_BAD_GATEWAY;
        }
    }

    /*
     * Step Three: Send the Request
     *
     * Send the HTTP/1.1 CONNECT request to the remote server
     */

    /* we are acting as a tunnel - the output filter stack should
     * be completely empty, because when we are done here we are done completely.
     * We add the NULL filter to the stack to do this...
     */
    r->output_filters = NULL;
    r->connection->output_filters = NULL;


    /* If we are connecting through a remote proxy, we need to pass
     * the CONNECT request on to it.
     */
    if (proxyport) {
	/* FIXME: Error checking ignored.
	 */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		     "proxy: CONNECT: sending the CONNECT request to the remote proxy");
        nbytes = apr_snprintf(buffer, sizeof(buffer),
			      "CONNECT %s HTTP/1.0" CRLF, r->uri);
        apr_socket_send(sock, buffer, &nbytes);
        nbytes = apr_snprintf(buffer, sizeof(buffer),
			      "Proxy-agent: %s" CRLF CRLF, ap_get_server_version());
        apr_socket_send(sock, buffer, &nbytes);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		     "proxy: CONNECT: Returning 200 OK Status");
        nbytes = apr_snprintf(buffer, sizeof(buffer),
			      "HTTP/1.0 200 Connection Established" CRLF);
        ap_xlate_proto_to_ascii(buffer, nbytes);
        apr_socket_send(client_socket, buffer, &nbytes);
        nbytes = apr_snprintf(buffer, sizeof(buffer),
			      "Proxy-agent: %s" CRLF CRLF, ap_get_server_version());
        ap_xlate_proto_to_ascii(buffer, nbytes);
        apr_socket_send(client_socket, buffer, &nbytes);
#if 0
        /* This is safer code, but it doesn't work yet.  I'm leaving it 
         * here so that I can fix it later.
         */
        r->status = HTTP_OK;
        r->header_only = 1;
        apr_table_set(r->headers_out, "Proxy-agent: %s", ap_get_server_version());
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

/*    r->sent_bodyct = 1;*/

    if ((rv = apr_pollset_create(&pollset, 2, r->pool, 0)) != APR_SUCCESS)
    {
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

    while (1) { /* Infinite loop until error (one side closes the connection) */
        if ((rv = apr_pollset_poll(pollset, -1, &pollcnt, &signalled)) != APR_SUCCESS) {
	    apr_socket_close(sock);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "proxy: CONNECT: error apr_poll()");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
/*	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: CONNECT: woke from select(), i=%d", pollcnt);*/

        for (i = 0; i < pollcnt; i++) {
            const apr_pollfd_t *cur = &signalled[i];

            if (cur->desc.s == sock) {
                pollevent = cur->rtnevents;
                if (pollevent & APR_POLLIN) {
/*		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                             "proxy: CONNECT: sock was set");*/
                    nbytes = sizeof(buffer);
                    if (apr_socket_recv(sock, buffer, &nbytes) == APR_SUCCESS) {
                        o = 0;
                        i = nbytes;
                        while(i > 0)
                        {
                            nbytes = i;
    /* This is just plain wrong.  No module should ever write directly
     * to the client.  For now, this works, but this is high on my list of
     * things to fix.  The correct line is:
     * if ((nbytes = ap_rwrite(buffer + o, nbytes, r)) < 0)
     * rbb
     */
                            if (apr_socket_send(client_socket, buffer + o, &nbytes) != APR_SUCCESS)
                                break;
                            o += nbytes;
                            i -= nbytes;
                        }
                    }
                    else
                        break;
                }
                else if ((pollevent & APR_POLLERR) || (pollevent & APR_POLLHUP))
                    break;
            }
            else if (cur->desc.s == client_socket) {
                pollevent = cur->rtnevents;
                if (pollevent & APR_POLLIN) {
/*		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                             "proxy: CONNECT: client was set");*/
                    nbytes = sizeof(buffer);
                    if (apr_socket_recv(client_socket, buffer, &nbytes) == APR_SUCCESS) {
                        o = 0;
                        i = nbytes;
                        while(i > 0)
                        {
                            nbytes = i;
                            if (apr_socket_send(sock, buffer + o, &nbytes) != APR_SUCCESS)
                                break;
                            o += nbytes;
                            i -= nbytes;
                        }
                    }
                    else
                        break;
                }
                else if ((pollevent & APR_POLLERR) || (pollevent & APR_POLLHUP))
                    break;
            }
            else
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

    apr_socket_close(sock);

    return OK;
}

static void ap_proxy_connect_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(ap_proxy_connect_handler, NULL, NULL, APR_HOOK_MIDDLE);
    proxy_hook_canon_handler(ap_proxy_connect_canon, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA proxy_connect_module = {
    STANDARD20_MODULE_STUFF,
    NULL,		/* create per-directory config structure */
    NULL,		/* merge per-directory config structures */
    NULL,		/* create per-server config structure */
    NULL,		/* merge per-server config structures */
    NULL,		/* command apr_table_t */
    ap_proxy_connect_register_hook	/* register hooks */
};
