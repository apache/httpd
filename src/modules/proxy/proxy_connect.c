/* ====================================================================
 * Copyright (c) 1996,1997 The Apache Group.  All rights reserved.
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
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
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

/* CONNECT method SSL handling for Apache proxy */

#include "mod_proxy.h"
#include "http_log.h"
#include "http_main.h"

#ifdef HAVE_BSTRING_H
#include <bstring.h>            /* for IRIX, FD_SET calls bzero() */
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
 *	  yet. 8^)
 * FIXME: doesn't check any headers initally sent from the
 *        client.
 * FIXME: should allow authentication, but hopefully the
 *        generic proxy authentication is good enough.
 * FIXME: no check for r->assbackwards, whatever that is.
 */ 
 
int
proxy_connect_handler(request_rec *r, struct cache_req *c, char *url)
{
    struct sockaddr_in server;
    struct in_addr destaddr;
    struct hostent server_hp;
    const char *host, *err;
    char *p;
    int   port, sock;
    char buffer[HUGE_STRING_LEN];
    int  nbytes, i, j;
    fd_set fds;

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
        (proxy_server_conf *)get_module_config(sconf, &proxy_module);
    struct noproxy_entry *npent=(struct noproxy_entry *)conf->noproxies->elts;

    memset(&server, '\0', sizeof(server));
    server.sin_family=AF_INET;
 
    /* Break the URL into host:port pairs */

    host = url;
    p = strchr(url, ':');
    if (p==NULL)
	port = DEFAULT_HTTPS_PORT;
    else
    {
      port = atoi(p+1);
      *p='\0';
    }
 
/* check if ProxyBlock directive on this host */
    destaddr.s_addr = inet_addr(host);
    for (i=0; i < conf->noproxies->nelts; i++)
    {
        if ((npent[i].name != NULL && strstr(host, npent[i].name) != NULL)
          || destaddr.s_addr == npent[i].addr.s_addr || npent[i].name[0] == '*')
            return proxyerror(r, "Connect to remote machine blocked");
    }

    switch (port)
    {
	case DEFAULT_HTTPS_PORT:
	case DEFAULT_SNEWS_PORT:
	    break;
	default:
	    return HTTP_SERVICE_UNAVAILABLE;
    }

    Explain2("CONNECT to %s on port %d", host, port);
 
    server.sin_port = htons(port);
    err = proxy_host2addr(host, &server_hp);
    if (err != NULL)
	return proxyerror(r, err); /* give up */
 
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);  
    if (sock == -1)
    {     
        log_error("proxy: error creating socket", r->server);
        return SERVER_ERROR;
    }     
    note_cleanups_for_fd(r->pool, sock);
 
    j = 0;
    while (server_hp.h_addr_list[j] != NULL) {
        memcpy(&server.sin_addr, server_hp.h_addr_list[j],
            sizeof(struct in_addr));
        i = proxy_doconnect(sock, &server, r);
        if (i == 0)
            break; 
        j++;
    }   
    if (i == -1 )
        return proxyerror(r, "Could not connect to remote machine");
 
    Explain0("Returning 200 OK Status");
 
    rvputs(r, "HTTP/1.0 200 Connection established\015\012", NULL);
    rvputs(r, "Proxy-agent: ", SERVER_VERSION, "\015\012\015\012", NULL);
    bflush(r->connection->client);

    while (1) /* Infinite loop until error (one side closes the connection) */
    {
      FD_ZERO(&fds);
      FD_SET(sock, &fds);
      FD_SET(r->connection->client->fd, &fds);
    
      Explain0("Going to sleep (select)");
      i = select((r->connection->client->fd > sock ?
	r->connection->client->fd+1 :
#ifdef HPUX
	sock+1), (int*)&fds, NULL, NULL, NULL);
#else
	sock+1), &fds, NULL, NULL, NULL);
#endif
      Explain1("Woke from select(), i=%d",i);
    
      if (i)
      {
        if (FD_ISSET(sock, &fds))
        {
           Explain0("sock was set");
           if((nbytes=read(sock,buffer,HUGE_STRING_LEN))!=0)
           {
              if (nbytes==-1)
		  break;
              if (write(r->connection->client->fd, buffer, nbytes)==EOF)
		  break;
              Explain1("Wrote %d bytes to client", nbytes);
           }
           else break;
        }
        else if (FD_ISSET(r->connection->client->fd, &fds))
        { 
           Explain0("client->fd was set");
           if((nbytes=read(r->connection->client->fd,buffer,
		HUGE_STRING_LEN))!=0)   
           {
              if (nbytes==-1)
		  break;
              if (write(sock,buffer,nbytes)==EOF)
		  break;
              Explain1("Wrote %d bytes to server", nbytes);
           }
           else break;
        }
        else break; /* Must be done waiting */
      }
      else break;
    }

    pclosef(r->pool,sock);
    
    return OK;
}     

