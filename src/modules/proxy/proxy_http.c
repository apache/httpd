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

/* HTTP routines for Apache proxy */

#include "mod_proxy.h"
#include "http_log.h"
#include "http_main.h"
#include "util_date.h"

/*
 * Canonicalise http-like URLs.
 *  scheme is the scheme for the URL
 *  url    is the URL starting with the first '/'
 *  def_port is the default port for this scheme.
 */
int
proxy_http_canon(request_rec *r, char *url, const char *scheme, int def_port)
{
    char *host, *path, *search, *p, sport[7];
    const char *err;
    int port;

/* do syntatic check.
 * We break the URL into host, port, path, search
 */
    port = def_port;
    err = proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) return BAD_REQUEST;

/* now parse path/search args, according to rfc1738 */
/* N.B. if this isn't a true proxy request, then the URL _path_
 * has already been decoded
 */
    if (r->proxyreq)
    {
	p = strchr(url, '?');
	if (p != NULL) *(p++) = '\0';
    } else
	p = r->args;

/* process path */
    path = proxy_canonenc(r->pool, url, strlen(url), enc_path, r->proxyreq);
    if (path == NULL) return BAD_REQUEST;

/* process search */
    if (p != NULL)
    {
	search = p;
	if (search == NULL) return BAD_REQUEST;
    } else
	search = NULL;

    if (port != def_port) ap_snprintf(sport, sizeof(sport), ":%d", port);
    else sport[0] = '\0';

    r->filename = pstrcat(r->pool, "proxy:", scheme, "://", host, sport, "/",
	path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}

/* Clear all connection-based headers from the incoming headers table */
static void clear_connection (table *headers)
{
    char *name;
    char *next = table_get(headers, "Connection");

    if (!next) return;

    while (*next) {
        name = next;
        while (*next && !isspace(*next) && (*next != ',')) ++next;
        while (*next && (isspace(*next) || (*next == ','))) {
            *next = '\0';
            ++next;
        }
        table_unset(headers, name);
    }
    table_unset(headers, "Connection");
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
int
proxy_http_handler(request_rec *r, struct cache_req *c, char *url,
	     const char *proxyhost, int proxyport)
{
    char *p;
    const char *err, *desthost;
    int i, j, sock, len, backasswards;
    array_header *reqhdrs_arr, *resp_hdrs;
    table_entry *reqhdrs;
    struct sockaddr_in server;
    struct in_addr destaddr;
    struct hostent server_hp;
    BUFF *f, *cache;
    struct hdr_entry *hdr;
    char buffer[HUGE_STRING_LEN];
    pool *pool=r->pool;
    const long int zero=0L;
    int destport = 0;
    char *destportstr = NULL;
    char *urlptr = NULL;

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
        (proxy_server_conf *)get_module_config(sconf, &proxy_module);
    struct noproxy_entry *npent=(struct noproxy_entry *)conf->noproxies->elts;
    struct nocache_entry *ncent=(struct nocache_entry *)conf->nocaches->elts;
    int nocache = 0;

    memset(&server, '\0', sizeof(server));
    server.sin_family = AF_INET;

/* We break the URL into host, port, path-search */

    urlptr = strstr(url,"://");
    if (urlptr == NULL) return BAD_REQUEST;
    urlptr += 3;
    destport = DEFAULT_PORT;
    p = strchr(urlptr, '/');
    if (p == NULL)
    {
        desthost = pstrdup(pool, urlptr);
        urlptr = "/";
    } else
    {
        char *q = palloc(pool, p-urlptr+1);
        memcpy(q, urlptr, p-urlptr);
        q[p-urlptr] = '\0';
        urlptr = p;
        desthost = q;
    }

    p = strchr(desthost, ':');
    if (p != NULL)
    {
        *(p++) = '\0';
	if (isdigit(*p))
	{
            destport = atoi(p);
            destportstr = p;
	}
    }

/* check if ProxyBlock directive on this host */
    destaddr.s_addr = ap_inet_addr(desthost);
    for (i=0; i < conf->noproxies->nelts; i++)
    {
        if ((npent[i].name != NULL && strstr(desthost, npent[i].name) != NULL)
	  || destaddr.s_addr == npent[i].addr.s_addr || npent[i].name[0] == '*')
	    return proxyerror(r, "Connect to remote machine blocked");
    }

    if (proxyhost != NULL)
    {
	server.sin_port = htons(proxyport);
	err = proxy_host2addr(proxyhost, &server_hp);
	if (err != NULL) return DECLINED;  /* try another */
    } else
    {
	server.sin_port = htons(destport);
	err = proxy_host2addr(desthost, &server_hp);
	if (err != NULL) return proxyerror(r, err); /* give up */
    }

    sock = psocket(pool, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1)
    {
	log_error("proxy: error creating socket", r->server);
	return SERVER_ERROR;
    }
    
    if (conf->recv_buffer_size) {
      if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
		     (const char *)&conf->recv_buffer_size, sizeof(int))
	  == -1) {
	proxy_log_uerror("setsockopt", "(SO_RCVBUF)",
			 "Failed to set RecvBufferSize, using default",
			 r->server);
      }
    }

#ifdef SINIX_D_RESOLVER_BUG
    { struct in_addr *ip_addr = (struct in_addr *) *server_hp.h_addr_list;

	for ( ; ip_addr->s_addr != 0; ++ip_addr) {
	    memcpy(&server.sin_addr, ip_addr, sizeof(struct in_addr));
	    i = proxy_doconnect(sock, &server, r);
	    if (i == 0)
		break;
	}
    }
#else
    j = 0;
    while (server_hp.h_addr_list[j] != NULL) {
	memcpy(&server.sin_addr, server_hp.h_addr_list[j],
	    sizeof(struct in_addr));
        i = proxy_doconnect(sock, &server, r);
	if (i == 0)
	    break;
	j++;
    }
#endif
    if (i == -1)
    {
	if (proxyhost != NULL) return DECLINED; /* try again another way */
	else return proxyerror(r, "Could not connect to remote machine");
    }

    clear_connection(r->headers_in);	/* Strip connection-based headers */

    f = bcreate(pool, B_RDWR | B_SOCKET);
    bpushfd(f, sock, sock);

    hard_timeout ("proxy send", r);
    bvputs(f, r->method, " ", url, " HTTP/1.0\015\012", NULL);
    bvputs(f, "Host: ", desthost, NULL);
    if (destportstr != NULL && destport != DEFAULT_PORT)
	bvputs(f, ":", destportstr, "\015\012", NULL);
    else
	bputs("\015\012", f);

    reqhdrs_arr = table_elts (r->headers_in);
    reqhdrs = (table_entry *)reqhdrs_arr->elts;
    for (i=0; i < reqhdrs_arr->nelts; i++)
    {
	if (reqhdrs[i].key == NULL || reqhdrs[i].val == NULL
	    /* Clear out headers not to send */
	  || !strcasecmp(reqhdrs[i].key, "Host") /* Already sent */
	  || !strcasecmp(reqhdrs[i].key, "Proxy-Authorization"))
	    continue;
	bvputs(f, reqhdrs[i].key, ": ", reqhdrs[i].val, "\015\012", NULL);
    }

    bputs("\015\012", f);
/* send the request data, if any. N.B. should we trap SIGPIPE ? */

    if (should_client_block(r))
    {
	while ((i = get_client_block(r, buffer, HUGE_STRING_LEN)) > 0)
            bwrite(f, buffer, i);
    }
    bflush(f);
    kill_timeout(r);

    hard_timeout ("proxy receive", r);
    
    len = bgets(buffer, HUGE_STRING_LEN-1, f);
    if (len == -1 || len == 0)
    {
	bclose(f);
	kill_timeout(r);
	return proxyerror(r, "Error reading from remote server");
    }

/* Is it an HTTP/1 response?  This is buggy if we ever see an HTTP/1.10 */
    if (checkmask(buffer,  "HTTP/#.# ###*"))
    {
/* If not an HTTP/1 messsage or if the status line was > 8192 bytes */
	if (buffer[5] != '1' || buffer[len-1] != '\n')
	{
	    bclose(f);
	    kill_timeout(r);
	    return BAD_GATEWAY;
	}
	backasswards = 0;
	buffer[--len] = '\0';

	buffer[12] = '\0';
	r->status = atoi(&buffer[9]);
	buffer[12] = ' ';
	r->status_line = pstrdup(pool, &buffer[9]);

/* read the headers. */
/* N.B. for HTTP/1.0 clients, we have to fold line-wrapped headers */
/* Also, take care with headers with multiple occurences. */

	resp_hdrs = proxy_read_headers(pool, buffer, HUGE_STRING_LEN, f);

	clear_connection((table *)resp_hdrs);  /* Strip Connection hdrs */
    }
    else
    {
/* an http/0.9 response */
	backasswards = 1;
	r->status = 200;
	r->status_line = "200 OK";

/* no headers */
	resp_hdrs = make_array(pool, 2, sizeof(struct hdr_entry));
    }

    kill_timeout(r);

/*
 * HTTP/1.0 requires us to accept 3 types of dates, but only generate
 * one type
 */
    
    hdr = (struct hdr_entry *)resp_hdrs->elts;
    for (i=0; i < resp_hdrs->nelts; i++)
    {
	if (hdr[i].value[0] == '\0') continue;
	p = hdr[i].field;
	if (strcasecmp(p, "Date") == 0 ||
	    strcasecmp(p, "Last-Modified") == 0 ||
	    strcasecmp(p, "Expires") == 0)
	    hdr[i].value = proxy_date_canon(pool, hdr[i].value);
    }

/* check if NoCache directive on this host */
    for (i=0; i < conf->nocaches->nelts; i++)
    {
        if ((ncent[i].name != NULL && strstr(desthost, ncent[i].name) != NULL)
	  || destaddr.s_addr == ncent[i].addr.s_addr || ncent[i].name[0] == '*')
	    nocache = 1; 
    }

    i = proxy_cache_update(c, resp_hdrs, !backasswards, nocache);
    if (i != DECLINED)
    {
	bclose(f);
	return i;
    }

    cache = c->fp;

    hard_timeout ("proxy receive", r);

/* write status line */
    if (!r->assbackwards)
        rvputs(r, "HTTP/1.0 ", r->status_line, "\015\012", NULL);
    if (cache != NULL)
	if (bvputs(cache, "HTTP/1.0 ", r->status_line, "\015\012", NULL) == -1)
	    cache = proxy_cache_error(c);

/* send headers */
    for (i=0; i < resp_hdrs->nelts; i++)
    {
	if (hdr[i].field == NULL || hdr[i].value == NULL ||
	    hdr[i].value[0] == '\0') continue;
	if (!r->assbackwards)
	    rvputs(r, hdr[i].field, ": ", hdr[i].value, "\015\012", NULL);
	if (cache != NULL)
	    if (bvputs(cache, hdr[i].field, ": ", hdr[i].value, "\015\012",
		       NULL) == -1)
		cache = proxy_cache_error(c);
    }

    if (!r->assbackwards) rputs("\015\012", r);
    if (cache != NULL)
	if (bputs("\015\012", cache) == -1) cache = proxy_cache_error(c);

    bsetopt(r->connection->client, BO_BYTECT, &zero);
    r->sent_bodyct = 1;
/* Is it an HTTP/0.9 respose? If so, send the extra data */
    if (backasswards)
    {
	bwrite(r->connection->client, buffer, len);
	if (cache != NULL)
	    if (bwrite(f, buffer, len) != len) cache = proxy_cache_error(c);
    }
    kill_timeout(r);

/* send body */
/* if header only, then cache will be NULL */
/* HTTP/1.0 tells us to read to EOF, rather than content-length bytes */
    if (!r->header_only) proxy_send_fb(f, r, cache, c);

    proxy_cache_tidy(c);

    bclose(f);

    proxy_garbage_coll(r);
    return OK;
}

