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

/* HTTP routines for Apache proxy */

#include "mod_proxy.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "util_date.h"
#include "ap_iol.h"

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
            u = apr_pstrcat(r->pool, ent[i].fake, &url[l2], NULL);
            return ap_construct_url(r->pool, u, r);
        }
    }
    return url;
}

/* Clear all connection-based headers from the incoming headers apr_table_t */
static void clear_connection(apr_pool_t *p, apr_table_t *headers)
{
    const char *name;
    char *next = apr_pstrdup(p, apr_table_get(headers, "Connection"));

    apr_table_unset(headers, "Proxy-Connection");
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
int ap_proxy_http_handler(request_rec *r, ap_cache_el  *c, char *url,
               const char *proxyhost, int proxyport)
{
    const char *strp;
    char *strp2;
    const char *desthost;
    apr_socket_t *sock;
    int i, len, backasswards, content_length=-1;
    apr_array_header_t *reqhdrs_arr;
    apr_table_t *resp_hdrs=NULL;
    apr_table_entry_t *reqhdrs;
    struct sockaddr_in server;
    struct in_addr destaddr;
    BUFF *f, *cachefp=NULL;
    char buffer[HUGE_STRING_LEN];
    char portstr[32];
    apr_pool_t *p = r->pool;
    const long int zero = 0L;
    int destport = 0;
    apr_ssize_t cntr;
    char *destportstr = NULL;
    const char *urlptr = NULL;
    char *datestr, *clen;

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
        desthost = apr_pstrdup(p, urlptr);
        urlptr = "/";
    }
    else {
        char *q = apr_palloc(p, strp - urlptr + 1);
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
            return ap_proxyerror(r, HTTP_FORBIDDEN,
                                 "Connect to remote machine blocked");
    }

    if ((apr_create_tcp_socket(&sock, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "proxy: error creating socket");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (conf->recv_buffer_size > 0 && apr_setsocketopt(sock, APR_SO_RCVBUF,conf->recv_buffer_size)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
    }
    
    if (proxyhost != NULL) {
        i = ap_proxy_doconnect(sock, (char *)proxyhost, proxyport, r);
    }
    else {
        i = ap_proxy_doconnect(sock, (char *)desthost, destport, r);
    }

    if (i == -1) {
        if (proxyhost != NULL)
            return DECLINED;    /* try again another way */
        else
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                apr_pstrcat(r->pool, "Could not connect to remote machine: ",
                    strerror(errno), NULL));
    }

    clear_connection(r->pool, r->headers_in);    /* Strip connection-based headers */

    f = ap_bcreate(p, B_RDWR);
    ap_bpush_iol(f, ap_iol_attach_socket(sock));

    ap_bvputs(f, r->method, " ", proxyhost ? url : urlptr, " HTTP/1.0" CRLF,
              NULL);
    if (destportstr != NULL && destport != DEFAULT_HTTP_PORT)
        ap_bvputs(f, "Host: ", desthost, ":", destportstr, CRLF, NULL);
    else
        ap_bvputs(f, "Host: ", desthost, CRLF, NULL);

    if (conf->viaopt == via_block) {
        /* Block all outgoing Via: headers */
        apr_table_unset(r->headers_in, "Via");
    } else if (conf->viaopt != via_off) {
        /* Create a "Via:" request header entry and merge it */
        i = ap_get_server_port(r);
        if (ap_is_default_port(i,r)) {
            strcpy(portstr,"");
        } else {
            apr_snprintf(portstr, sizeof portstr, ":%d", i);
        }
        /* Generate outgoing Via: header with/without server comment: */
        apr_table_mergen(r->headers_in, "Via",
                        (conf->viaopt == via_full)
                        ? apr_psprintf(p, "%d.%d %s%s (%s)",
                                      HTTP_VERSION_MAJOR(r->proto_num),
                                      HTTP_VERSION_MINOR(r->proto_num),
                                      ap_get_server_name(r), portstr,
                                      AP_SERVER_BASEVERSION)
                        : apr_psprintf(p, "%d.%d %s%s",
                                      HTTP_VERSION_MAJOR(r->proto_num),
                                      HTTP_VERSION_MINOR(r->proto_num),
                                      ap_get_server_name(r), portstr)
            );
    }

    reqhdrs_arr = ap_table_elts(r->headers_in);
    reqhdrs = (apr_table_entry_t *) reqhdrs_arr->elts;
    for (i = 0; i < reqhdrs_arr->nelts; i++) {
        if (reqhdrs[i].key == NULL || reqhdrs[i].val == NULL
            /* Clear out headers not to send */
            || !strcasecmp(reqhdrs[i].key, "Host")    /* Already sent */
            /* XXX: @@@ FIXME: "Proxy-Authorization" should *only* be 
             * suppressed if THIS server requested the authentication,
             * not when a frontend proxy requested it!
             */
            || !strcasecmp(reqhdrs[i].key, "Proxy-Authorization"))
            continue;
        ap_bvputs(f, reqhdrs[i].key, ": ", reqhdrs[i].val, CRLF, NULL);
    }

    ap_bputs(CRLF, f);
/* send the request data, if any. */

    if (ap_should_client_block(r)) {
        while ((i = ap_get_client_block(r, buffer, sizeof buffer)) > 0)
            ap_bwrite(f, buffer, i, &cntr);
    }
    ap_bflush(f);

    len = ap_bgets(buffer, sizeof buffer - 1, f);
    if (len == -1) {
        ap_bclose(f);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "ap_bgets() - proxy receive - Error reading from remote server %s (length %d)",
                      proxyhost ? proxyhost : desthost, len);
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Error reading from remote server");
    } else if (len == 0) {
        ap_bclose(f);
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Document contains no data");
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
            return HTTP_BAD_GATEWAY;
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
        resp_hdrs = ap_proxy_read_headers(r, buffer, HUGE_STRING_LEN, f);
        if (resp_hdrs == NULL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r->server,
                         "proxy: Bad HTTP/%d.%d header returned by %s (%s)",
                         major, minor, r->uri, r->method);
            nocache = 1;    /* do not cache this broken file */
        }
        else
        {
            clear_connection(p, resp_hdrs);    /* Strip Connection hdrs */
            ap_cache_el_header_merge(c, resp_hdrs);
        }
            
        if (conf->viaopt != via_off && conf->viaopt != via_block) {
            /* Create a "Via:" response header entry and merge it */
            i = ap_get_server_port(r);
            if (ap_is_default_port(i,r)) {
                strcpy(portstr,"");
            } else {
                apr_snprintf(portstr, sizeof portstr, ":%d", i);
            }
            ap_cache_el_header_add(c, "Via", (conf->viaopt == via_full)
                         ? apr_psprintf(p, "%d.%d %s%s (%s)", major, minor,
                                       ap_get_server_name(r), portstr, AP_SERVER_BASEVERSION)
                         : apr_psprintf(p, "%d.%d %s%s", major, minor, ap_get_server_name(r), portstr)
                );
        }
    }
    else {
/* an http/0.9 response */
        backasswards = 1;
        r->status = 200;
        r->status_line = "200 OK";
    }

/*
 * HTTP/1.0 requires us to accept 3 types of dates, but only generate
 * one type
 */
    if (ap_cache_el_header(c, "Date", &datestr) == APR_SUCCESS)
        ap_cache_el_header_set(c, "Date", ap_proxy_date_canon(p, datestr));
    if (ap_cache_el_header(c, "Last-Modified", &datestr) == APR_SUCCESS)
        ap_cache_el_header_set(c, "Last-Modified", ap_proxy_date_canon(p, datestr));
    if (ap_cache_el_header(c, "Expires", &datestr) == APR_SUCCESS)
        ap_cache_el_header_set(c, "Expires", ap_proxy_date_canon(p, datestr));

    if (ap_cache_el_header(c, "Location", &datestr) == APR_SUCCESS)
        ap_cache_el_header_set(c, "Location", proxy_location_reverse_map(r, datestr));
    if (ap_cache_el_header(c, "URI", &datestr) == APR_SUCCESS)
        ap_cache_el_header_set(c, "URI", proxy_location_reverse_map(r, datestr));

/* check if NoCache directive on this host */
    if (ap_cache_el_header(c, "Content-Length", &clen) == APR_SUCCESS)
        content_length = atoi(clen ? clen : "-1");

    for (i = 0; i < conf->nocaches->nelts; i++) {
        if ((ncent[i].name != NULL && strstr(desthost, ncent[i].name) != NULL)
            || destaddr.s_addr == ncent[i].addr.s_addr || ncent[i].name[0] == '*')
            nocache = 1;
    }

    if(nocache || !ap_proxy_cache_should_cache(r, resp_hdrs, !backasswards))
        ap_proxy_cache_error(&c);
    else
        ap_cache_el_data(c, &cachefp);
    
/* write status line */
    if (!r->assbackwards)
        ap_rvputs(r, "HTTP/1.0 ", r->status_line, CRLF, NULL);
    if (cachefp &&    ap_bvputs(cachefp, "HTTP/1.0 ", r->status_line, CRLF, NULL) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "proxy: error writing status line to cache");
        ap_proxy_cache_error(&c);
        cachefp = NULL;
    }

/* send headers */
    ap_cache_el_header_walk(c, ap_proxy_send_hdr_line, r, NULL);

    if (!r->assbackwards)
        ap_rputs(CRLF, r);

    ap_bsetopt(r->connection->client, BO_BYTECT, &zero);
    r->sent_bodyct = 1;
/* Is it an HTTP/0.9 respose? If so, send the extra data */
    if (backasswards) {
        ap_bwrite(r->connection->client, buffer, len, &cntr);
        if (cachefp && ap_bwrite(cachefp, buffer, len, &cntr) != len) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "proxy: error writing extra data to cache %ld",
                          (long)cachefp);
            ap_proxy_cache_error(&c);
        }
    }

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
        proxy_completion pc;
        pc.content_length = content_length;
        pc.cache_completion = conf->cache_completion;
        ap_proxy_send_fb(&pc, f, r, c);
    }

    ap_bclose(f);
    if(c) ap_proxy_cache_update(c);
    return OK;
}
