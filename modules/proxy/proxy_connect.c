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

/* CONNECT method for Apache proxy */

#include "mod_proxy.h"

#if 0
#ifdef HAVE_BSTRING_H
#include <bstring.h>		/* for IRIX, FD_SET calls bzero() */
#endif
#endif

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


int ap_proxy_connect_handler(request_rec *r, char *url,
			  const char *proxyname, int proxyport)
{
    apr_pool_t *p = r->pool;
    apr_socket_t *sock;
    char buffer[HUGE_STRING_LEN];
    int nbytes, i, err;

    apr_socket_t *client_sock = NULL;
    apr_pollfd_t *pollfd;
    apr_int32_t pollcnt;
    apr_int16_t pollevent;
    apr_sockaddr_t *uri_addr, *connect_addr;

    uri_components uri;
    const char *connectname;
    int connectport = 0;

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);


    /*
     * Step One: Determine Who To Connect To
     *
     * Break up the URL to determine the host to connect to
     */

    /* we break the URL into host, port, uri */
    if (HTTP_OK != ap_parse_hostinfo_components(p, url, &uri)) {
	return ap_proxyerror(r, HTTP_BAD_REQUEST,
			     apr_pstrcat(p, "URI cannot be parsed: ", url, NULL));
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
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
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
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
	    case DEFAULT_HTTPS_PORT:
	    case DEFAULT_SNEWS_PORT:
		break;
	    default:
		return HTTP_FORBIDDEN;
	}
    } else if(!allowed_port(conf, uri.port))
	return HTTP_FORBIDDEN;


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

    /* create a new socket */
    if ((apr_socket_create(&sock, APR_INET, SOCK_STREAM, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "proxy: error creating socket");
        return HTTP_INTERNAL_SERVER_ERROR;
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


    /* try each IP address until we connect successfully */
    {
	int failed = 1;
	while (connect_addr) {

	    /* make the connection out of the socket */
	    err = apr_connect(sock, connect_addr);

	    /* if an error occurred, loop round and try again */
            if (err != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, err, r->server,
			     "proxy: CONNECT: attempt to connect to %pI (%s) failed", connect_addr, connectname);
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
    }


    /*
     * Step Three: Send the Request
     *
     * Send the HTTP/1.1 CONNECT request to the remote server
     */

    /* If we are connecting through a remote proxy, we need to pass
     * the CONNECT request on to it.
     */
    if (proxyport) {
	/* FIXME: Error checking ignored.  Also, we force
	 * a HTTP/1.0 request to keep things simple.
	 */
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
		     "proxy: CONNECT: sending the CONNECT request to the remote proxy");
        nbytes = apr_snprintf(buffer, sizeof(buffer),
			      "CONNECT %s HTTP/1.1" CRLF, r->uri);
        apr_send(sock, buffer, &nbytes);
        nbytes = apr_snprintf(buffer, sizeof(buffer),
			      "Proxy-agent: %s" CRLF CRLF, ap_get_server_version());
        apr_send(sock, buffer, &nbytes);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
		     "proxy: CONNECT: Returning 200 OK Status");
        ap_rvputs(r, "HTTP/1.0 200 Connection established" CRLF, NULL);
        ap_rvputs(r, "Proxy-agent: ", ap_get_server_version(), CRLF CRLF, NULL);
        ap_rflush(r);
    }


    /*
     * Step Four: Handle Data Transfer
     *
     * Handle two way transfer of data over the socket (this is a tunnel).
     */

    if(apr_poll_setup(&pollfd, 2, r->pool) != APR_SUCCESS)
    {
	apr_socket_close(sock);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "proxy: CONNECT: error apr_poll_setup()");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Add client side to the poll */
#if 0
/* FIXME !!!! SDM !!! If someone can figure out how to turn a conn_rec into a ap_sock_t or something
   this code might work. However if we must we can change r->connection->client to non-blocking and
   just see if a recv gives us anything and do the same to sock (server) side, I'll leave this as TBD so
   one can decide the best path to take
*/
    if(apr_os_sock_put(&client_sock,
        (apr_os_sock_t *)get_socket(r->connection->client),
                      r->pool) != APR_SUCCESS)
    {
	apr_socket_close(sock);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "proxy: CONNECT: error creating client apr_socket_t");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_poll_socket_add(pollfd, client_sock, APR_POLLIN);
#endif

    /* Add the server side to the poll */
    apr_poll_socket_add(pollfd, sock, APR_POLLIN);

    while (1) { /* Infinite loop until error (one side closes the connection) */
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL, "proxy: CONNECT: going to sleep (poll)");
        if(apr_poll(pollfd, &pollcnt, -1) != APR_SUCCESS)
        {
	    apr_socket_close(sock);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "proxy: CONNECT: error apr_poll()");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "proxy: CONNECT: woke from select(), i=%d", pollcnt);

        if (pollcnt) {
            apr_poll_revents_get(&pollevent, sock, pollfd);
            if (pollevent & APR_POLLIN) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                             "proxy: CONNECT: sock was set");
                nbytes = HUGE_STRING_LEN;
                if(apr_recv(sock, buffer, &nbytes) == APR_SUCCESS) {
                    int o = 0;
                    while(nbytes)
                    {
                        i = nbytes;
                        apr_send(r->connection->client_socket, buffer + o, &i);
                        o += i;
                        nbytes -= i;
                    }
                    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
				 "proxy: CONNECT: wrote %d bytes to client", nbytes);
                }
                else
                    break;
            }

            apr_poll_revents_get(&pollevent, client_sock, pollfd);
            if (pollevent & APR_POLLIN) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                             "proxy: CONNECT: client was set");
                nbytes = HUGE_STRING_LEN;
                if(apr_recv(r->connection->client_socket, buffer, &nbytes) == APR_SUCCESS) {
                    int o = 0;
                    while(nbytes)
                    {
                        i = nbytes;
                        apr_send(sock, buffer + o, &i);
                        o += i;
                        nbytes -= i;
                    }
                    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
                        NULL, "proxy: CONNECT: wrote %d bytes to server", nbytes);
                }
                else
                    break;
            }
        }
        else
            break;
    }


    /*
     * Step Five: Clean Up
     *
     * Close the socket and clean up
     */

    apr_socket_close(sock);

    return OK;
}
