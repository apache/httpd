/* ====================================================================
 * Copyright (c) 1996-1998 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/* CONNECT method for Apache proxy */

#include "mod_proxy.h"
#include "http_log.h"
#include "http_main.h"

#ifdef HAVE_BSTRING_H
#include <bstring.h>		/* for IRIX, FD_SET calls bzero() */
#endif

DEF_Explain

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
 * FIXME: this is bad, because it does its own socket I/O
 *        instead of using the I/O in buff.c.  However,
 *        the I/O in buff.c blocks on reads, and because
 *        this function doesn't know how much data will
 *        be sent either way (or when) it can't use blocking
 *        I/O.  This may be very implementation-specific
 *        (to Linux).  Any suggestions?
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


int ap_proxy_connect_handler(request_rec *r, cache_req *c, char *url,
			  const char *proxyhost, int proxyport)
{
    struct sockaddr_in server;
    struct in_addr destaddr;
    struct hostent server_hp;
    const char *host, *err;
    char *p;
    int port, sock;
    char buffer[HUGE_STRING_LEN];
    int nbytes, i, j;
    fd_set fds;

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    struct noproxy_entry *npent = (struct noproxy_entry *) conf->noproxies->elts;

    memset(&server, '\0', sizeof(server));
    server.sin_family = AF_INET;

    /* Break the URL into host:port pairs */

    host = url;
    p = strchr(url, ':');
    if (p == NULL)
	port = DEFAULT_HTTPS_PORT;
    else {
	port = atoi(p + 1);
	*p = '\0';
    }

/* check if ProxyBlock directive on this host */
    destaddr.s_addr = ap_inet_addr(host);
    for (i = 0; i < conf->noproxies->nelts; i++) {
	if ((npent[i].name != NULL && strstr(host, npent[i].name) != NULL)
	    || destaddr.s_addr == npent[i].addr.s_addr || npent[i].name[0] == '*')
	    return ap_proxyerror(r, "Connect to remote machine blocked");
    }

    /* Check if it is an allowed port */
    if (conf->allowed_connect_ports->nelts == 0) {
	/* Default setting if not overridden by AllowCONNECT */
	switch (port) {
	    case DEFAULT_HTTPS_PORT:
	    case DEFAULT_SNEWS_PORT:
		break;
	    default:
		return HTTP_FORBIDDEN;
	}
    } else if(!allowed_port(conf, port))
	return HTTP_FORBIDDEN;

    if (proxyhost) {
	Explain2("CONNECT to remote proxy %s on port %d", proxyhost, proxyport);
    }
    else {
	Explain2("CONNECT to %s on port %d", host, port);
    }

    server.sin_port = (proxyport ? htons(proxyport) : htons(port));
    err = ap_proxy_host2addr(proxyhost ? proxyhost : host, &server_hp);

    if (err != NULL)
	return ap_proxyerror(r, err);	/* give up */

    sock = ap_psocket(r->pool, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "proxy: error creating socket");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

#ifndef WIN32
    if (sock >= FD_SETSIZE) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, NULL,
	    "proxy_connect_handler: filedescriptor (%u) "
	    "larger than FD_SETSIZE (%u) "
	    "found, you probably need to rebuild Apache with a "
	    "larger FD_SETSIZE", sock, FD_SETSIZE);
	ap_pclosesocket(r->pool, sock);
	return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif

    j = 0;
    while (server_hp.h_addr_list[j] != NULL) {
	memcpy(&server.sin_addr, server_hp.h_addr_list[j],
	       sizeof(struct in_addr));
	i = ap_proxy_doconnect(sock, &server, r);
	if (i == 0)
	    break;
	j++;
    }
    if (i == -1) {
	ap_pclosesocket(r->pool, sock);
	return ap_proxyerror(r, ap_pstrcat(r->pool,
					"Could not connect to remote machine:<br>",
					strerror(errno), NULL));
    }

    /* If we are connecting through a remote proxy, we need to pass
     * the CONNECT request on to it.
     */
    if (proxyport) {
	/* FIXME: We should not be calling write() directly, but we currently
	 * have no alternative.  Error checking ignored.  Also, we force
	 * a HTTP/1.0 request to keep things simple.
	 */
	Explain0("Sending the CONNECT request to the remote proxy");
	ap_snprintf(buffer, sizeof(buffer), "CONNECT %s HTTP/1.0" CRLF,
		    r->uri);
	write(sock, buffer, strlen(buffer));
	ap_snprintf(buffer, sizeof(buffer),
		    "Proxy-agent: %s" CRLF CRLF, ap_get_server_version());
	write(sock, buffer, strlen(buffer));
    }
    else {
	Explain0("Returning 200 OK Status");
	ap_rvputs(r, "HTTP/1.0 200 Connection established" CRLF, NULL);
	ap_rvputs(r, "Proxy-agent: ", ap_get_server_version(), CRLF CRLF, NULL);
	ap_bflush(r->connection->client);
    }

    while (1) {			/* Infinite loop until error (one side closes the connection) */
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	FD_SET(r->connection->client->fd, &fds);

	Explain0("Going to sleep (select)");
	i = ap_select((r->connection->client->fd > sock ?
		       r->connection->client->fd + 1 :
		       sock + 1), &fds, NULL, NULL, NULL);
	Explain1("Woke from select(), i=%d", i);

	if (i) {
	    if (FD_ISSET(sock, &fds)) {
		Explain0("sock was set");
		if ((nbytes = read(sock, buffer, HUGE_STRING_LEN)) != 0) {
		    if (nbytes == -1)
			break;
		    if (write(r->connection->client->fd, buffer, nbytes) == EOF)
			break;
		    Explain1("Wrote %d bytes to client", nbytes);
		}
		else
		    break;
	    }
	    else if (FD_ISSET(r->connection->client->fd, &fds)) {
		Explain0("client->fd was set");
		if ((nbytes = read(r->connection->client->fd, buffer,
				   HUGE_STRING_LEN)) != 0) {
		    if (nbytes == -1)
			break;
		    if (write(sock, buffer, nbytes) == EOF)
			break;
		    Explain1("Wrote %d bytes to server", nbytes);
		}
		else
		    break;
	    }
	    else
		break;		/* Must be done waiting */
	}
	else
	    break;
    }

    ap_pclosesocket(r->pool, sock);

    return OK;
}
