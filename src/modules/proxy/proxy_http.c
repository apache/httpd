/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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

    /*
     * do syntatic check. We break the URL into host, port, path, search
     */
    port = def_port;
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err)
        return HTTP_BAD_REQUEST;

    /* now parse path/search args, according to rfc1738 */
    /*
     * N.B. if this isn't a true proxy request, then the URL _path_ has
     * already been decoded.  True proxy requests have r->uri ==
     * r->unparsed_uri, and no others have that property.
     */
    if (r->uri == r->unparsed_uri) {
        search = strchr(url, '?');
        if (search != NULL)
            *(search++) = '\0';
    }
    else
        search = r->args;

    /* process path */
    path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path,
                             r->proxyreq);
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

/* handle the conversion of URLs in the ProxyPassReverse function */
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
    int i, j, sock,/* len,*/ backasswards;
    table *req_hdrs, *resp_hdrs;
    array_header *reqhdrs_arr;
    table_entry *reqhdrs_elts;
    struct sockaddr_in server;
    struct in_addr destaddr;
    struct hostent server_hp;
    BUFF *f;
    char buffer[HUGE_STRING_LEN];
    char portstr[32];
    pool *p = r->pool;
    int destport = 0;
    int chunked = 0;
    char *destportstr = NULL;
    const char *urlptr = NULL;
    const char *datestr, *urlstr;
    int result, major, minor;
    const char *content_length;

    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
    struct noproxy_entry *npent = (struct noproxy_entry *) conf->noproxies->elts;
    struct nocache_entry *ncent = (struct nocache_entry *) conf->nocaches->elts;
    int nocache = 0;

    if (conf->cache.root == NULL)
        nocache = 1;

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
        if (destaddr.s_addr == npent[i].addr.s_addr ||
            (npent[i].name != NULL &&
             (npent[i].name[0] == '*' || strstr(desthost, npent[i].name) != NULL)))
            return ap_proxyerror(r, HTTP_FORBIDDEN,
                                 "Connect to remote machine blocked");
    }

    if (proxyhost != NULL) {
        server.sin_port = htons((unsigned short)proxyport);
        err = ap_proxy_host2addr(proxyhost, &server_hp);
        if (err != NULL)
            return DECLINED;    /* try another */
    }
    else {
        server.sin_port = htons((unsigned short)destport);
        err = ap_proxy_host2addr(desthost, &server_hp);
        if (err != NULL)
            return ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR, err);
    }


    /*
     * we have worked out who exactly we are going to connect to, now make
     * that connection...
     */
    sock = ap_psocket_ex(p, PF_INET, SOCK_STREAM, IPPROTO_TCP, 1);
    if (sock == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                      "proxy: error creating socket");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#if !defined(TPF) && !defined(BEOS)
    if (conf->recv_buffer_size) {
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                       (const char *)&conf->recv_buffer_size, sizeof(int))
            == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                          "setsockopt(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
        }
    }
#endif

#ifdef SINIX_D_RESOLVER_BUG
    {
        struct in_addr *ip_addr = (struct in_addr *)*server_hp.h_addr_list;

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
            return DECLINED;    /* try again another way */
        else
            return ap_proxyerror(r, HTTP_BAD_GATEWAY, ap_pstrcat(r->pool,
                                    "Could not connect to remote machine: ",
                                                    strerror(errno), NULL));
    }

    /* record request_time for HTTP/1.1 age calculation */
    c->req_time = time(NULL);

    /*
     * build upstream-request headers by stripping r->headers_in from
     * connection specific headers. We must not remove the Connection: header
     * from r->headers_in, we still have to react to Connection: close
     */
    req_hdrs = ap_copy_table(r->pool, r->headers_in);
    ap_proxy_clear_connection(r->pool, req_hdrs);

    /*
     * At this point, we start sending the HTTP/1.1 request to the remote
     * server (proxy or otherwise).
     */
    f = ap_bcreate(p, B_RDWR | B_SOCKET);
    ap_bpushfd(f, sock, sock);

    ap_hard_timeout("proxy send", r);
    ap_bvputs(f, r->method, " ", proxyhost ? url : urlptr, " HTTP/1.1" CRLF,
              NULL);
    /* Send Host: now, adding it to req_hdrs wouldn't be much better */
    if (destportstr != NULL && destport != DEFAULT_HTTP_PORT)
        ap_bvputs(f, "Host: ", desthost, ":", destportstr, CRLF, NULL);
    else
        ap_bvputs(f, "Host: ", desthost, CRLF, NULL);

    if (conf->viaopt == via_block) {
        /* Block all outgoing Via: headers */
        ap_table_unset(req_hdrs, "Via");
    }
    else if (conf->viaopt != via_off) {
        /* Create a "Via:" request header entry and merge it */
        i = ap_get_server_port(r);
        if (ap_is_default_port(i, r)) {
            strcpy(portstr, "");
        }
        else {
            ap_snprintf(portstr, sizeof portstr, ":%d", i);
        }
        /* Generate outgoing Via: header with/without server comment: */
        ap_table_mergen(req_hdrs, "Via",
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

    /* the X-* headers are only added if we are a reverse
     * proxy, otherwise we would be giving away private information.
     */
    if (r->proxyreq == PROXY_PASS) {
        const char *buf;

        /*
         * Add X-Forwarded-For: so that the upstream has a chance to determine,
         * where the original request came from.
         */
        ap_table_mergen(req_hdrs, "X-Forwarded-For", r->connection->remote_ip);

        /* Add X-Forwarded-Host: so that upstream knows what the
         * original request hostname was.
         */
        if ((buf = ap_table_get(r->headers_in, "Host"))) {
            ap_table_mergen(req_hdrs, "X-Forwarded-Host", buf);
        }

        /* Add X-Forwarded-Server: so that upstream knows what the
         * name of this proxy server is (if there are more than one)
         * XXX: This duplicates Via: - do we strictly need it?
         */
        ap_table_mergen(req_hdrs, "X-Forwarded-Server", r->server->server_hostname);
    } 

    /* we don't yet support keepalives - but we will soon, I promise! */
    ap_table_set(req_hdrs, "Connection", "close");

    reqhdrs_arr = ap_table_elts(req_hdrs);
    reqhdrs_elts = (table_entry *)reqhdrs_arr->elts;
    for (i = 0; i < reqhdrs_arr->nelts; i++) {
        if (reqhdrs_elts[i].key == NULL || reqhdrs_elts[i].val == NULL

        /*
         * Clear out hop-by-hop request headers not to send: RFC2616 13.5.1
         * says we should strip these headers:
         */
            || !strcasecmp(reqhdrs_elts[i].key, "Host") /* Already sent */
            || !strcasecmp(reqhdrs_elts[i].key, "Keep-Alive")
            || !strcasecmp(reqhdrs_elts[i].key, "TE")
            || !strcasecmp(reqhdrs_elts[i].key, "Trailer")
            || !strcasecmp(reqhdrs_elts[i].key, "Transfer-Encoding")
            || !strcasecmp(reqhdrs_elts[i].key, "Upgrade")
        /*
         * XXX: @@@ FIXME: "Proxy-Authorization" should *only* be suppressed
         * if THIS server requested the authentication, not when a frontend
         * proxy requested it!
         * 
         * The solution to this problem is probably to strip out the
         * Proxy-Authorisation header in the authorisation code itself, not
         * here. This saves us having to signal somehow whether this request
         * was authenticated or not.
         */
            || !strcasecmp(reqhdrs_elts[i].key, "Proxy-Authorization"))
            continue;
        ap_bvputs(f, reqhdrs_elts[i].key, ": ", reqhdrs_elts[i].val, CRLF, NULL);
    }

    /* the obligatory empty line to mark the end of the headers */
    ap_bputs(CRLF, f);

    /* and flush the above away */
    ap_bflush(f);

    /* and kill the send timeout */
    ap_kill_timeout(r);


    /* read the request data, and pass it to the backend.
     * we might encounter a stray 100-continue reponse from a PUT or POST,
     * if this happens we ignore the 100 continue status line and read the
     * response again.
     */
    {
        /* send the request data, if any. */
        ap_hard_timeout("proxy receive request data", r);
        if (ap_should_client_block(r)) {
            while ((i = ap_get_client_block(r, buffer, sizeof buffer)) > 0) {
                ap_reset_timeout(r);
                ap_bwrite(f, buffer, i);
            }
        }
        ap_bflush(f);
        ap_kill_timeout(r);


        /* then, read a response line */
        ap_hard_timeout("proxy receive response status line", r);
        result = ap_proxy_read_response_line(f, r, buffer, sizeof(buffer)-1, &backasswards, &major, &minor);
        ap_kill_timeout(r);

        /* trap any errors */
        if (result != OK) {
            ap_bclose(f);
            return result;
        }

        /* if this response was 100-continue, a stray response has been caught.
         * read the line again for the real response
         */
        if (r->status == 100) {
            ap_hard_timeout("proxy receive response status line", r);
            result = ap_proxy_read_response_line(f, r, buffer, sizeof(buffer)-1, &backasswards, &major, &minor);
            ap_kill_timeout(r);

            /* trap any errors */
            if (result != OK) {
                ap_bclose(f);
                return result;
            }
        }
    }


    /*
     * We have our response status line from the convoluted code above,
     * now we read the headers to continue.
     */
    ap_hard_timeout("proxy receive response headers", r);

    /*
     * Is it an HTTP/1 response? Do some sanity checks on the response. (This
     * is buggy if we ever see an HTTP/1.10)
     */
    if (backasswards == 0) {

        /* read the response headers. */
        /* N.B. for HTTP/1.0 clients, we have to fold line-wrapped headers */
        /* Also, take care with headers with multiple occurences. */

        resp_hdrs = ap_proxy_read_headers(r, buffer, sizeof(buffer), f);
        if (resp_hdrs == NULL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, r->server,
                         "proxy: Bad HTTP/%d.%d header returned by %s (%s)",
                         major, minor, r->uri, r->method);
            resp_hdrs = ap_make_table(p, 20);
            nocache = 1;        /* do not cache this broken file */
        }

        /* handle Via header in the response */
        if (conf->viaopt != via_off && conf->viaopt != via_block) {
            /* Create a "Via:" response header entry and merge it */
            i = ap_get_server_port(r);
            if (ap_is_default_port(i, r)) {
                strcpy(portstr, "");
            }
            else {
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

        /* is this content chunked? */
        chunked = ap_find_last_token(r->pool,
                                     ap_table_get(resp_hdrs, "Transfer-Encoding"),
                                     "chunked");

        /* strip hop-by-hop headers defined by Connection and RFC2616 */
        ap_proxy_clear_connection(p, resp_hdrs);

        content_length = ap_table_get(resp_hdrs, "Content-Length");
        if (content_length != NULL) {
            c->len = ap_strtol(content_length, NULL, 10);
        }

    }
    else {
        /* an http/0.9 response */

        /* no headers */
        resp_hdrs = ap_make_table(p, 20);
    }

    ap_kill_timeout(r);

    /*
     * HTTP/1.1 requires us to accept 3 types of dates, but only generate one
     * type
     */
    /*
     * we SET the dates here, obliterating possible multiple dates, as only
     * one of each date makes sense in each response.
     */
    if ((datestr = ap_table_get(resp_hdrs, "Date")) != NULL)
        ap_table_set(resp_hdrs, "Date", ap_proxy_date_canon(p, datestr));
    if ((datestr = ap_table_get(resp_hdrs, "Last-Modified")) != NULL)
        ap_table_set(resp_hdrs, "Last-Modified", ap_proxy_date_canon(p, datestr));
    if ((datestr = ap_table_get(resp_hdrs, "Expires")) != NULL)
        ap_table_set(resp_hdrs, "Expires", ap_proxy_date_canon(p, datestr));

    /* handle the ProxyPassReverse mappings */
    if ((urlstr = ap_table_get(resp_hdrs, "Location")) != NULL)
        ap_table_set(resp_hdrs, "Location", proxy_location_reverse_map(r, urlstr));
    if ((urlstr = ap_table_get(resp_hdrs, "URI")) != NULL)
        ap_table_set(resp_hdrs, "URI", proxy_location_reverse_map(r, urlstr));
    if ((urlstr = ap_table_get(resp_hdrs, "Content-Location")) != NULL)
        ap_table_set(resp_hdrs, "Content-Location", proxy_location_reverse_map(r, urlstr));

/* check if NoCache directive on this host */
    if (nocache == 0) {
        for (i = 0; i < conf->nocaches->nelts; i++) {
            if (destaddr.s_addr == ncent[i].addr.s_addr ||
                (ncent[i].name != NULL &&
                 (ncent[i].name[0] == '*' ||
                  strstr(desthost, ncent[i].name) != NULL))) {
                nocache = 1;
                break;
            }
        }

        /*
         * update the cache file, possibly even fulfilling the request if it
         * turns out a conditional allowed us to serve the object from the
         * cache...
         */
        i = ap_proxy_cache_update(c, resp_hdrs, !backasswards, nocache);
        if (i != DECLINED) {
            ap_bclose(f);
            return i;
        }

        /* write status line and headers to the cache file */
        ap_proxy_write_headers(c, ap_pstrcat(p, "HTTP/1.1 ", r->status_line, NULL), resp_hdrs);
    }

    /* Setup the headers for our client from upstreams response-headers */
    ap_proxy_table_replace(r->headers_out, resp_hdrs);
    /* Add X-Cache header - be careful not to obliterate any upstream headers */
    ap_table_mergen(r->headers_out, "X-Cache",
                    ap_pstrcat(r->pool, "MISS from ",
                               ap_get_server_name(r), NULL));
    /* The Content-Type of this response is the upstream one. */
    r->content_type = ap_table_get(r->headers_out, "Content-Type");
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, r->server, "Content-Type: %s", r->content_type);

    /* finally output the headers to the client */
    ap_send_http_header(r);

    /*
     * Is it an HTTP/0.9 respose? If so, send the extra data we read from
     * upstream as the start of the reponse to client
     */
/* FIXME: This code is broken: we try and write a buffer and length that
 * were never intelligently initialised. Rather have a bit of broken protocol
 * handling for now than broken code.
 */
/*
    if (backasswards) {
        ap_hard_timeout("proxy send assbackward", r);

        ap_bwrite(r->connection->client, buffer, len);
        if (c != NULL && c->fp != NULL && ap_bwrite(c->fp, buffer, len) != len) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, c->req,
                      "proxy: error writing extra data to %s", c->tempfile);
            c = ap_proxy_cache_error(c);
        }
        ap_kill_timeout(r);
    }
*/

#ifdef CHARSET_EBCDIC
    /*
     * What we read/write after the header should not be modified (i.e., the
     * cache copy is ASCII, not EBCDIC, even for text/html)
     */
    r->ebcdic.conv_in = r->ebcdic.conv_out = 0;
    ap_bsetflag(f, B_ASCII2EBCDIC | B_EBCDIC2ASCII, 0);
    ap_bsetflag(r->connection->client, B_ASCII2EBCDIC | B_EBCDIC2ASCII, 0);
#endif

/* send body */
/* if header only, then cache will be NULL */
/* HTTP/1.0 tells us to read to EOF, rather than content-length bytes */
/* XXX CHANGEME: We want to eventually support keepalives, which means
 * we must read content-length bytes... */
    if (!r->header_only) {
/* we need to set this for ap_proxy_send_fb()... */
        c->cache_completion = conf->cache.cache_completion;

/* XXX CHECKME: c->len should be the expected content length, or -1 if the
 * content length is not known. We need to make 100% sure c->len is always
 * set correctly before we get here to correctly do keepalive.
 */
        ap_proxy_send_fb(f, r, c, c->len, 0, chunked, conf->io_buffer_size);
    }

    /* ap_proxy_send_fb() closes the socket f for us */

    ap_proxy_cache_tidy(c);

    ap_proxy_garbage_coll(r);
    return OK;
}
