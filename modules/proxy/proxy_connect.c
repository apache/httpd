/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
#include "http_log.h"
#include "http_main.h"
#include "ap_iol.h"

#ifdef HAVE_BSTRING_H
#include <bstring.h>        /* for IRIX, FD_SET calls bzero() */
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


int ap_proxy_connect_handler(request_rec *r, ap_cache_el  *c, char *url,
              const char *proxyhost, int proxyport)
{
    struct in_addr destaddr;
    const char *host;
    char *p;
    int port;
    apr_socket_t *sock;
    char buffer[HUGE_STRING_LEN];
    int nbytes, i;

    BUFF *sock_buff;
    apr_socket_t *client_sock=NULL;
    apr_pollfd_t *pollfd;
    apr_int32_t pollcnt;
    apr_int16_t pollevent;
    
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    struct noproxy_entry *npent = (struct noproxy_entry *) conf->noproxies->elts;

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
        return ap_proxyerror(r, HTTP_FORBIDDEN,
                 "Connect to remote machine blocked");
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "CONNECT to remote proxy %s on port %d", proxyhost, proxyport);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "CONNECT to %s on port %d", host, port);
    }

    if ((apr_create_tcp_socket(&sock, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "proxy: error creating socket");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ap_proxy_doconnect(sock, (char *)(proxyhost ? proxyhost : host), proxyport ? proxyport : port, r) == -1) {
        apr_close_socket(sock);
        return ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                             apr_pstrcat(r->pool, "Could not connect to remote machine:<br>",
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "Sending the CONNECT request to the remote proxy");
        nbytes = apr_snprintf(buffer, sizeof(buffer), "CONNECT %s HTTP/1.0" CRLF, r->uri);
        apr_send(sock, buffer, &nbytes);
        nbytes = apr_snprintf(buffer, sizeof(buffer),"Proxy-agent: %s" CRLF CRLF, ap_get_server_version());
        apr_send(sock, buffer, &nbytes);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "Returning 200 OK Status");
    ap_rvputs(r, "HTTP/1.0 200 Connection established" CRLF, NULL);
    ap_rvputs(r, "Proxy-agent: ", ap_get_server_version(), CRLF CRLF, NULL);
    ap_bflush(r->connection->client);
    }

    sock_buff = ap_bcreate(r->pool, B_RDWR);
    ap_bpush_iol(sock_buff, ap_iol_attach_socket(sock));

    if(apr_setup_poll(&pollfd, 2, r->pool) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "proxy: error apr_setup_poll()");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Add client side to the poll */
#if 0
/* FIXME !!!! SDM !!! If someone can figure out how to turn a conn_rec into a ap_sock_t or something
   this code might work. However if we must we can change r->connection->client to non-blocking and
   just see if a recv gives us anything and do the same to sock (server) side, I'll leave this as TBD so
   one can decide the best path to take
*/
    if(apr_put_os_sock(&client_sock, (apr_os_sock_t *)get_socket(r->connection->client),
                      r->pool) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "proxy: error creating client apr_socket_t");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_add_poll_socket(pollfd, client_sock, APR_POLLIN);
#endif
    
    
    /* Add the server side to the poll */
    apr_add_poll_socket(pollfd, sock, APR_POLLIN);
    
    while (1) {            /* Infinite loop until error (one side closes the connection) */
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL, "Going to sleep (poll)");
        if(apr_poll(pollfd, &pollcnt, -1) != APR_SUCCESS)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "proxy: error apr_poll()");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                     "Woke from select(), i=%d", pollcnt);

        if (pollcnt) {
            apr_get_revents(&pollevent, sock, pollfd);
            if (pollevent & APR_POLLIN) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                             "sock was set");
                if(ap_bread(sock_buff, buffer, HUGE_STRING_LEN, &nbytes) == APR_SUCCESS) {
                    int o = 0;
                    while(nbytes)
                    {
                        ap_bwrite(r->connection->client, buffer + o, nbytes, &i);
                        o += i;
                        nbytes -= i;
                    }
                    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                                 "Wrote %d bytes to client", nbytes);
                }
                else
                    break;
            }

            apr_get_revents(&pollevent, client_sock, pollfd);
            if (pollevent & APR_POLLIN) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                             "client was set");
                if(ap_bread(r->connection->client, buffer, HUGE_STRING_LEN, &nbytes) == APR_SUCCESS) {
                    int o = 0;
                    while(nbytes)
                    {
                        ap_bwrite(sock_buff, buffer + o, nbytes, &i);
                        o += i;
                        nbytes -= i;
                    }
                    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL,
                                 "Wrote %d bytes to server", nbytes);
                }
                else
                    break;
            }
        }
        else
            break;
    }
    
    apr_close_socket(sock);

    return OK;
}
