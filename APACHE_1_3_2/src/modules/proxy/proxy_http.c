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

/* HTTP routines for Apache proxy */

#include "mod_proxy.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
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
	ap_snprintf(sport, sizeof(sport), ":%d", port);
    else
	sport[0] = '\0';

    r->filename = ap_pstrcat(r->pool, "proxy:", scheme, "://", host, sport, "/",
		   path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}
 
static const char *proxy_location_reverse_map(request_rec *r, const char *url)
{
    void *sconf;
    proxy_server_conf *conf;
    struct proxy_alias *ent;
    int i, l1, l2;
    char *u;

    sconf = r->server->module_config;
    conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
    l1 = strlen(url);
    ent = (struct proxy_alias *)conf->raliases->elts;
    for (i = 0; i < conf->raliases->nelts; i++) {
        l2 = strlen(ent[i].real);
        if (l1 >= l2 && strncmp(ent[i].real, url, l2) == 0) {
            u = ap_pstrcat(r->pool, ent[i].fake, &url[l2], NULL);
            return ap_construct_url(r->pool, u, r);
        }
    }
    return url;
}

/* Clear all connection-based headers from the incoming headers table */
static void clear_connection(pool *p, table *headers)
{
    const char *name;
    char *next = ap_pstrdup(p, ap_table_get(headers, "Connection"));

    ap_table_unset(headers, "Proxy-Connection");
    if (!next)
	return;

    while (*next) {
	name = next;
	while (*next && !ap_isspace(*next) && (*next != ','))
	    ++next;
	while (*next && (ap_isspace(*next) || (*next == ','))) {
	    *next = '\0';
	    ++next;
	}
	ap_table_unset(headers, name);
    }
    ap_table_unset(headers, "Connection");
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
int ap_proxy_http_handler(request_rec *r, cache_req *c, char *url,
		       const char *proxyhost, int proxyport)
{
    const char *strp;
    char *strp2;
    const char *err, *desthost;
    int i, j, sock, len, backasswards;
    array_header *reqhdrs_arr;
    table *resp_hdrs;
    table_entry *reqhdrs;
    struct sockaddr_in server;
    struct in_addr destaddr;
    struct hostent server_hp;
    BUFF *f;
    char buffer[HUGE_STRING_LEN];
    char portstr[32];
    pool *p = r->pool;
    const long int zero = 0L;
    int destport = 0;
    char *destportstr = NULL;
    const char *urlptr = NULL;
    const char *datestr;
    struct tbl_do_args tdo;

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    struct noproxy_entry *npent = (struct noproxy_entry *) conf->noproxies->elts;
    struct nocache_entry *ncent = (struct nocache_entry *) conf->nocaches->elts;
    int nocache = 0;

    memset(&server, '\0', sizeof(server));
    server.sin_family = AF_INET;

/* We break the URL into host, port, path-search */

    urlptr = strstr(url, "://");
    if (urlptr == NULL)
	return HTTP_BAD_REQUEST;
    urlptr += 3;
    destport = DEFAULT_HTTP_PORT;
    strp = strchr(urlptr, '/');
    if (strp == NULL) {
	desthost = ap_pstrdup(p, urlptr);
	urlptr = "/";
    }
    else {
	char *q = ap_palloc(p, strp - urlptr + 1);
	memcpy(q, urlptr, strp - urlptr);
	q[strp - urlptr] = '\0';
	urlptr = strp;
	desthost = q;
    }

    strp2 = strchr(desthost, ':');
    if (strp2 != NULL) {
	*(strp2++) = '\0';
	if (ap_isdigit(*strp2)) {
	    destport = atoi(strp2);
	    destportstr = strp2;
	}
    }

/* check if ProxyBlock directive on this host */
    destaddr.s_addr = ap_inet_addr(desthost);
    for (i = 0; i < conf->noproxies->nelts; i++) {
	if ((npent[i].name != NULL && strstr(desthost, npent[i].name) != NULL)
	    || destaddr.s_addr == npent[i].addr.s_addr || npent[i].name[0] == '*')
	    return ap_proxyerror(r, "Connect to remote machine blocked");
    }

    if (proxyhost != NULL) {
	server.sin_port = htons(proxyport);
	err = ap_proxy_host2addr(proxyhost, &server_hp);
	if (err != NULL)
	    return DECLINED;	/* try another */
    }
    else {
	server.sin_port = htons(destport);
	err = ap_proxy_host2addr(desthost, &server_hp);
	if (err != NULL)
	    return ap_proxyerror(r, err);	/* give up */
    }

    sock = ap_psocket(p, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "proxy: error creating socket");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (conf->recv_buffer_size) {
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
		       (const char *) &conf->recv_buffer_size, sizeof(int))
	    == -1) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			 "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
	}
    }

#ifdef SINIX_D_RESOLVER_BUG
    {
	struct in_addr *ip_addr = (struct in_addr *) *server_hp.h_addr_list;

	for (; ip_addr->s_addr != 0; ++ip_addr) {
	    memcpy(&server.sin_addr, ip_addr, sizeof(struct in_addr));
	    i = ap_proxy_doconnect(sock, &server, r);
	    if (i == 0)
		break;
	}
    }
#else
    j = 0;
    while (server_hp.h_addr_list[j] != NULL) {
	memcpy(&server.sin_addr, server_hp.h_addr_list[j],
	       sizeof(struct in_addr));
	i = ap_proxy_doconnect(sock, &server, r);
	if (i == 0)
	    break;
	j++;
    }
#endif
    if (i == -1) {
	if (proxyhost != NULL)
	    return DECLINED;	/* try again another way */
	else
	    return ap_proxyerror(r, /*HTTP_BAD_GATEWAY*/ ap_pstrcat(r->pool,
				"Could not connect to remote machine: ",
				strerror(errno), NULL));
    }

    clear_connection(r->pool, r->headers_in);	/* Strip connection-based headers */

    f = ap_bcreate(p, B_RDWR | B_SOCKET);
    ap_bpushfd(f, sock, sock);

    ap_hard_timeout("proxy send", r);
    ap_bvputs(f, r->method, " ", proxyhost ? url : urlptr, " HTTP/1.0" CRLF,
	   NULL);
    if (destportstr != NULL && destport != DEFAULT_HTTP_PORT)
	ap_bvputs(f, "Host: ", desthost, ":", destportstr, CRLF, NULL);
    else
	ap_bvputs(f, "Host: ", desthost, CRLF, NULL);

    if (conf->viaopt == via_block) {
	/* Block all outgoing Via: headers */
	ap_table_unset(r->headers_in, "Via");
    } else if (conf->viaopt != via_off) {
	/* Create a "Via:" request header entry and merge it */
	i = ap_get_server_port(r);
	if (ap_is_default_port(i,r)) {
	    strcpy(portstr,"");
	} else {
	    ap_snprintf(portstr, sizeof portstr, ":%d", i);
	}
	/* Generate outgoing Via: header with/without server comment: */
	ap_table_mergen(r->headers_in, "Via",
		    (conf->viaopt == via_full)
			? ap_psprintf(p, "%d.%d %s%s (%s)",
				HTTP_VERSION_MAJOR(r->proto_num),
				HTTP_VERSION_MINOR(r->proto_num),
				ap_get_server_name(r), portstr,
				SERVER_BASEVERSION)
			: ap_psprintf(p, "%d.%d %s%s",
				HTTP_VERSION_MAJOR(r->proto_num),
				HTTP_VERSION_MINOR(r->proto_num),
				ap_get_server_name(r), portstr)
			);
    }

    reqhdrs_arr = ap_table_elts(r->headers_in);
    reqhdrs = (table_entry *) reqhdrs_arr->elts;
    for (i = 0; i < reqhdrs_arr->nelts; i++) {
	if (reqhdrs[i].key == NULL || reqhdrs[i].val == NULL
	/* Clear out headers not to send */
	    || !strcasecmp(reqhdrs[i].key, "Host")	/* Already sent */
	    /* XXX: @@@ FIXME: "Proxy-Authorization" should *only* be 
	     * suppressed if THIS server requested the authentication,
	     * not when a frontend proxy requested it!
	     */
	    || !strcasecmp(reqhdrs[i].key, "Proxy-Authorization"))
	    continue;
	ap_bvputs(f, reqhdrs[i].key, ": ", reqhdrs[i].val, CRLF, NULL);
    }

    ap_bputs(CRLF, f);
/* send the request data, if any. N.B. should we trap SIGPIPE ? */

    if (ap_should_client_block(r)) {
	while ((i = ap_get_client_block(r, buffer, sizeof buffer)) > 0)
	    ap_bwrite(f, buffer, i);
    }
    ap_bflush(f);
    ap_kill_timeout(r);

    ap_hard_timeout("proxy receive", r);

    len = ap_bgets(buffer, sizeof buffer - 1, f);
    if (len == -1 || len == 0) {
	ap_bclose(f);
	ap_kill_timeout(r);
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		     "ap_bgets() - proxy receive - Error reading from remote server %s",
		     proxyhost ? proxyhost : desthost);
	return ap_proxyerror(r, "Error reading from remote server");
    }

/* Is it an HTTP/1 response?  This is buggy if we ever see an HTTP/1.10 */
    if (ap_checkmask(buffer, "HTTP/#.# ###*")) {
	int major, minor;
	if (2 != sscanf(buffer, "HTTP/%u.%u", &major, &minor)) {
	    major = 1;
	    minor = 0;
	}

/* If not an HTTP/1 message or if the status line was > 8192 bytes */
	if (buffer[5] != '1' || buffer[len - 1] != '\n') {
	    ap_bclose(f);
	    ap_kill_timeout(r);
	    return HTTP_BAD_GATEWAY;
	}
	backasswards = 0;
	buffer[--len] = '\0';

	buffer[12] = '\0';
	r->status = atoi(&buffer[9]);
	buffer[12] = ' ';
	r->status_line = ap_pstrdup(p, &buffer[9]);

/* read the headers. */
/* N.B. for HTTP/1.0 clients, we have to fold line-wrapped headers */
/* Also, take care with headers with multiple occurences. */

	resp_hdrs = ap_proxy_read_headers(r, buffer, HUGE_STRING_LEN, f);
	if (resp_hdrs == NULL) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, r->server,
		 "proxy: Bad HTTP/%d.%d header returned by %s (%s)",
		 major, minor, r->uri, r->method);
	    resp_hdrs = ap_make_table(p, 20);
	    nocache = 1;    /* do not cache this broken file */
	}

	if (conf->viaopt != via_off && conf->viaopt != via_block) {
	    /* Create a "Via:" response header entry and merge it */
	    i = ap_get_server_port(r);
	    if (ap_is_default_port(i,r)) {
		strcpy(portstr,"");
	    } else {
		ap_snprintf(portstr, sizeof portstr, ":%d", i);
	    }
	    ap_table_mergen((table *)resp_hdrs, "Via",
			    (conf->viaopt == via_full)
			    ? ap_psprintf(p, "%d.%d %s%s (%s)",
				major, minor,
				ap_get_server_name(r), portstr,
				SERVER_BASEVERSION)
			    : ap_psprintf(p, "%d.%d %s%s",
				major, minor,
				ap_get_server_name(r), portstr)
			    );
	}

	clear_connection(p, resp_hdrs);	/* Strip Connection hdrs */
    }
    else {
/* an http/0.9 response */
	backasswards = 1;
	r->status = 200;
	r->status_line = "200 OK";

/* no headers */
	resp_hdrs = ap_make_table(p, 20);
    }

    c->hdrs = resp_hdrs;

    ap_kill_timeout(r);

/*
 * HTTP/1.0 requires us to accept 3 types of dates, but only generate
 * one type
 */
    if ((datestr = ap_table_get(resp_hdrs, "Date")) != NULL)
	ap_table_set(resp_hdrs, "Date", ap_proxy_date_canon(p, datestr));
    if ((datestr = ap_table_get(resp_hdrs, "Last-Modified")) != NULL)
	ap_table_set(resp_hdrs, "Last-Modified", ap_proxy_date_canon(p, datestr));
    if ((datestr = ap_table_get(resp_hdrs, "Expires")) != NULL)
	ap_table_set(resp_hdrs, "Expires", ap_proxy_date_canon(p, datestr));

    if ((datestr = ap_table_get(resp_hdrs, "Location")) != NULL)
	ap_table_set(resp_hdrs, "Location", proxy_location_reverse_map(r, datestr));
    if ((datestr = ap_table_get(resp_hdrs, "URI")) != NULL)
	ap_table_set(resp_hdrs, "URI", proxy_location_reverse_map(r, datestr));

/* check if NoCache directive on this host */
    for (i = 0; i < conf->nocaches->nelts; i++) {
	if ((ncent[i].name != NULL && strstr(desthost, ncent[i].name) != NULL)
	    || destaddr.s_addr == ncent[i].addr.s_addr || ncent[i].name[0] == '*')
	    nocache = 1;
    }

    i = ap_proxy_cache_update(c, resp_hdrs, !backasswards, nocache);
    if (i != DECLINED) {
	ap_bclose(f);
	return i;
    }

    ap_hard_timeout("proxy receive", r);

/* write status line */
    if (!r->assbackwards)
	ap_rvputs(r, "HTTP/1.0 ", r->status_line, CRLF, NULL);
    if (c != NULL && c->fp != NULL &&
	ap_bvputs(c->fp, "HTTP/1.0 ", r->status_line, CRLF, NULL) == -1)
	c = ap_proxy_cache_error(c);

/* send headers */
    tdo.req = r;
    tdo.cache = c;
    ap_table_do(ap_proxy_send_hdr_line, &tdo, resp_hdrs, NULL);

    if (!r->assbackwards)
	ap_rputs(CRLF, r);
    if (c != NULL && c->fp != NULL && ap_bputs(CRLF, c->fp) == -1)
	c = ap_proxy_cache_error(c);

    ap_bsetopt(r->connection->client, BO_BYTECT, &zero);
    r->sent_bodyct = 1;
/* Is it an HTTP/0.9 respose? If so, send the extra data */
    if (backasswards) {
	ap_bwrite(r->connection->client, buffer, len);
	if (c != NULL && c->fp != NULL && ap_bwrite(c->fp, buffer, len) != len)
	    c = ap_proxy_cache_error(c);
    }
    ap_kill_timeout(r);

#ifdef CHARSET_EBCDIC
    /* What we read/write after the header should not be modified
     * (i.e., the cache copy is ASCII, not EBCDIC, even for text/html)
     */
    ap_bsetflag(f, B_ASCII2EBCDIC|B_EBCDIC2ASCII, 0);
    ap_bsetflag(r->connection->client, B_ASCII2EBCDIC|B_EBCDIC2ASCII, 0);
#endif

/* send body */
/* if header only, then cache will be NULL */
/* HTTP/1.0 tells us to read to EOF, rather than content-length bytes */
    if (!r->header_only) {
/* we need to set this for ap_proxy_send_fb()... */
	c->cache_completion = conf->cache.cache_completion;
	ap_proxy_send_fb(f, r, c);
    }

    ap_proxy_cache_tidy(c);

    ap_bclose(f);

    ap_proxy_garbage_coll(r);
    return OK;
}
