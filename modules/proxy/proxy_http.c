/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* HTTP routines for Apache proxy */

#include "mod_proxy.h"

module AP_MODULE_DECLARE_DATA proxy_http_module;

int ap_proxy_http_canon(request_rec *r, char *url);
int ap_proxy_http_handler(request_rec *r, proxy_worker *worker,
                          proxy_server_conf *conf,
                          char *url, const char *proxyname, 
                          apr_port_t proxyport);

static apr_status_t ap_proxy_http_cleanup(const char *scheme,
                                          request_rec *r,
                                          proxy_conn_rec *backend);

/*
 * Canonicalise http-like URLs.
 *  scheme is the scheme for the URL
 *  url    is the URL starting with the first '/'
 *  def_port is the default port for this scheme.
 */
int ap_proxy_http_canon(request_rec *r, char *url)
{
    char *host, *path, *search, sport[7];
    const char *err;
    const char *scheme;
    apr_port_t port, def_port;

    /* ap_port_of_scheme() */
    if (strncasecmp(url, "http:", 5) == 0) {
        url += 5;
        scheme = "http";
    }
    else if (strncasecmp(url, "https:", 6) == 0) {
        url += 6;
        scheme = "https";
    }
    else {
        return DECLINED;
    }
    def_port = apr_uri_port_of_scheme(scheme);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "proxy: HTTP: canonicalising URL %s", url);

    /* do syntatic check.
     * We break the URL into host, port, path, search
     */
    port = def_port;
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error parsing URL %s: %s",
                      url, err);
        return HTTP_BAD_REQUEST;
    }

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

    if (ap_strchr_c(host, ':')) { /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "://", host, sport, 
            "/", path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}
 
static const char *ap_proxy_location_reverse_map(request_rec *r, proxy_server_conf *conf, const char *url)
{
    struct proxy_alias *ent;
    int i, l1, l2;
    char *u;

    /* XXX FIXME: Make sure this handled the ambiguous case of the :80
     * after the hostname */

    l1 = strlen(url);
    ent = (struct proxy_alias *)conf->raliases->elts;
    for (i = 0; i < conf->raliases->nelts; i++) {
        l2 = strlen(ent[i].real);
        if (l1 >= l2 && strncasecmp(ent[i].real, url, l2) == 0) {
            u = apr_pstrcat(r->pool, ent[i].fake, &url[l2], NULL);
            return ap_construct_url(r->pool, u, r);
        }
    }
    return url;
}
/* cookies are a bit trickier to match: we've got two substrings to worry
 * about, and we can't just find them with strstr 'cos of case.  Regexp
 * matching would be an easy fix, but for better consistency with all the
 * other matches we'll refrain and use apr_strmatch to find path=/domain=
 * and stick to plain strings for the config values.
 */
static const char *proxy_cookie_reverse_map(request_rec *r,
                          proxy_server_conf *conf, const char *str)
{
    struct proxy_alias *ent;
    size_t len = strlen(str);
    const char* newpath = NULL ;
    const char* newdomain = NULL ;
    const char* pathp ;
    const char* domainp ;
    const char* pathe = NULL;
    const char* domaine = NULL;
    size_t l1, l2, poffs = 0, doffs = 0 ;
    int i;
    int ddiff = 0 ;
    int pdiff = 0 ;
    char* ret ;

/* find the match and replacement, but save replacing until we've done
   both path and domain so we know the new strlen
*/
    if ( pathp = apr_strmatch(conf->cookie_path_str, str, len) , pathp ) {
        pathp += 5 ;
        poffs = pathp - str ;
        pathe = ap_strchr_c(pathp, ';') ;
        l1 = pathe ? (pathe-pathp) : strlen(pathp) ;
        pathe = pathp + l1 ;
        ent = (struct proxy_alias *)conf->cookie_paths->elts;
        for (i = 0; i < conf->cookie_paths->nelts; i++) {
            l2 = strlen(ent[i].fake);
            if (l1 >= l2 && strncmp(ent[i].fake, pathp, l2) == 0) {
                newpath = ent[i].real ;
                pdiff = strlen(newpath) - l1 ;
                break ;
            }
        }
    }
    if ( domainp = apr_strmatch(conf->cookie_domain_str, str, len) , domainp ) {
        domainp += 7 ;
        doffs = domainp - str ;
        domaine = ap_strchr_c(domainp, ';') ;
        l1 = domaine ? (domaine-domainp) : strlen(domainp) ;
        domaine = domainp + l1 ;
        ent = (struct proxy_alias *)conf->cookie_domains->elts;
        for (i = 0; i < conf->cookie_domains->nelts; i++) {
            l2 = strlen(ent[i].fake);
            if (l1 >= l2 && strncasecmp(ent[i].fake, domainp, l2) == 0) {
                newdomain = ent[i].real ;
                ddiff = strlen(newdomain) - l1 ;
                break ;
            }
        }
    }
    if ( newpath ) {
        ret = apr_palloc(r->pool, len+pdiff+ddiff+1) ;
        l1 = strlen(newpath) ;
        if ( newdomain ) {
            l2 = strlen(newdomain) ;
            if ( doffs > poffs ) {
                memcpy(ret, str, poffs) ;
                memcpy(ret+poffs, newpath, l1) ;
                memcpy(ret+poffs+l1, pathe, domainp-pathe) ;
                memcpy(ret+doffs+pdiff, newdomain, l2) ;
                strcpy(ret+doffs+pdiff+l2, domaine) ;
            } else {
                memcpy(ret, str, doffs) ;
                memcpy(ret+doffs, newdomain, l2) ;
                memcpy(ret+doffs+l2, domaine, pathp-domaine) ;
                memcpy(ret+poffs+ddiff, newpath, l1) ;
                strcpy(ret+poffs+ddiff+l1, pathe) ;
            }
        } else {
            memcpy(ret, str, poffs) ;
            memcpy(ret+poffs, newpath, l1) ;
            strcpy(ret+poffs+l1, pathe) ;
        }
    } else {
        if ( newdomain ) {
            ret = apr_palloc(r->pool, len+pdiff+ddiff+1) ;
            l2 = strlen(newdomain) ;
            memcpy(ret, str, doffs) ;
            memcpy(ret+doffs, newdomain, l2) ;
            strcpy(ret+doffs+l2, domaine) ;
        } else {
            ret = (char*) str ;        /* no change */
        }
    }
    return ret ;
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
        while (*next && !apr_isspace(*next) && (*next != ',')) {
            ++next;
        }
        while (*next && (apr_isspace(*next) || (*next == ','))) {
            *next = '\0';
            ++next;
        }
        apr_table_unset(headers, name);
    }
    apr_table_unset(headers, "Connection");
}

static
apr_status_t ap_proxy_http_request(apr_pool_t *p, request_rec *r,
                                   proxy_conn_rec *conn, conn_rec *origin, 
                                   proxy_server_conf *conf,
                                   apr_uri_t *uri,
                                   char *url, char *server_portstr)
{
    conn_rec *c = r->connection;
    char *buf;
    apr_bucket *e, *last_header_bucket = NULL;
    const apr_array_header_t *headers_in_array;
    const apr_table_entry_t *headers_in;
    int counter, seen_eos, send_chunks;
    apr_status_t status;
    apr_bucket_brigade *header_brigade, *body_brigade, *input_brigade;

    header_brigade = apr_brigade_create(p, origin->bucket_alloc);
    body_brigade = apr_brigade_create(p, origin->bucket_alloc);
    input_brigade = apr_brigade_create(p, origin->bucket_alloc);

    /*
     * Send the HTTP/1.1 request to the remote server
     */

    /* strip connection listed hop-by-hop headers from the request */
    /* even though in theory a connection: close coming from the client
     * should not affect the connection to the server, it's unlikely
     * that subsequent client requests will hit this thread/process, so
     * we cancel server keepalive if the client does.
     */
    conn->close += ap_proxy_liststr(apr_table_get(r->headers_in,
                                                  "Connection"), "close");

    /* sub-requests never use keepalives */
    if (r->main) {
        conn->close++;
    }

    ap_proxy_clear_connection(p, r->headers_in);
    if (conn->close) {
        apr_table_setn(r->headers_in, "Connection", "close");
        origin->keepalive = AP_CONN_CLOSE;
    }

    /* By default, we can not send chunks. That means we must buffer
     * the entire request before sending it along to ensure we have
     * the correct Content-Length attached.
     */
    send_chunks = 0;

    if (apr_table_get(r->subprocess_env, "force-proxy-request-1.0")) {
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.0" CRLF, NULL);
    } else {
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.1" CRLF, NULL);
        if (apr_table_get(r->subprocess_env, "proxy-sendchunks")) {
            send_chunks = 1;
        }
    }
    if (apr_table_get(r->subprocess_env, "proxy-nokeepalive")) {
        apr_table_unset(r->headers_in, "Connection");
        origin->keepalive = AP_CONN_CLOSE;
    }
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    if (conf->preserve_host == 0) {
        if (uri->port_str && uri->port != DEFAULT_HTTP_PORT) {
            buf = apr_pstrcat(p, "Host: ", uri->hostname, ":", uri->port_str,
                              CRLF, NULL);
        } else {
            buf = apr_pstrcat(p, "Host: ", uri->hostname, CRLF, NULL);
        }
    } 
    else {
        /* don't want to use r->hostname, as the incoming header might have a 
         * port attached 
         */
        const char* hostname = apr_table_get(r->headers_in,"Host");        
        if (!hostname) {
            hostname =  r->server->server_hostname;
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "proxy: no HTTP 0.9 request (with no host line) "
                          "on incoming request and preserve host set "
                          "forcing hostname to be %s for uri %s", 
                          hostname, 
                          r->uri );
        }
        buf = apr_pstrcat(p, "Host: ", hostname, CRLF, NULL);
    }
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);        
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);

    /* handle Via */
    if (conf->viaopt == via_block) {
        /* Block all outgoing Via: headers */
        apr_table_unset(r->headers_in, "Via");
    } else if (conf->viaopt != via_off) {
        const char *server_name = ap_get_server_name(r);
        /* If USE_CANONICAL_NAME_OFF was configured for the proxy virtual host,
         * then the server name returned by ap_get_server_name() is the
         * origin server name (which does make too much sense with Via: headers)
         * so we use the proxy vhost's name instead.
         */
        if (server_name == r->hostname)
            server_name = r->server->server_hostname;
        /* Create a "Via:" request header entry and merge it */
        /* Generate outgoing Via: header with/without server comment: */
        apr_table_mergen(r->headers_in, "Via",
                         (conf->viaopt == via_full)
                         ? apr_psprintf(p, "%d.%d %s%s (%s)",
                                        HTTP_VERSION_MAJOR(r->proto_num),
                                        HTTP_VERSION_MINOR(r->proto_num),
                                        server_name, server_portstr,
                                        AP_SERVER_BASEVERSION)
                         : apr_psprintf(p, "%d.%d %s%s",
                                        HTTP_VERSION_MAJOR(r->proto_num),
                                        HTTP_VERSION_MINOR(r->proto_num),
                                        server_name, server_portstr)
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
        apr_table_mergen(r->headers_in, "X-Forwarded-For",
                       r->connection->remote_ip);

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
    proxy_run_fixups(r);
    headers_in_array = apr_table_elts(r->headers_in);
    headers_in = (const apr_table_entry_t *) headers_in_array->elts;
    for (counter = 0; counter < headers_in_array->nelts; counter++) {
        if (headers_in[counter].key == NULL || headers_in[counter].val == NULL

        /* Clear out hop-by-hop request headers not to send
         * RFC2616 13.5.1 says we should strip these headers
         */
                /* Already sent */
            || !apr_strnatcasecmp(headers_in[counter].key, "Host")

            || !apr_strnatcasecmp(headers_in[counter].key, "Keep-Alive")
            || !apr_strnatcasecmp(headers_in[counter].key, "TE")
            || !apr_strnatcasecmp(headers_in[counter].key, "Trailer")
            || !apr_strnatcasecmp(headers_in[counter].key, "Transfer-Encoding")
            || !apr_strnatcasecmp(headers_in[counter].key, "Upgrade")

            /* We have no way of knowing whether this Content-Length will
             * be accurate, so we must not include it.
             */
            || !apr_strnatcasecmp(headers_in[counter].key, "Content-Length")
        /* XXX: @@@ FIXME: "Proxy-Authorization" should *only* be 
         * suppressed if THIS server requested the authentication,
         * not when a frontend proxy requested it!
         *
         * The solution to this problem is probably to strip out
         * the Proxy-Authorisation header in the authorisation
         * code itself, not here. This saves us having to signal
         * somehow whether this request was authenticated or not.
         */
            || !apr_strnatcasecmp(headers_in[counter].key,"Proxy-Authorization")
            || !apr_strnatcasecmp(headers_in[counter].key,"Proxy-Authenticate")) {
            continue;
        }
        /* for sub-requests, ignore freshness/expiry headers */
        if (r->main) {
                if (headers_in[counter].key == NULL || headers_in[counter].val == NULL
                     || !apr_strnatcasecmp(headers_in[counter].key, "If-Match")
                     || !apr_strnatcasecmp(headers_in[counter].key, "If-Modified-Since")
                     || !apr_strnatcasecmp(headers_in[counter].key, "If-Range")
                     || !apr_strnatcasecmp(headers_in[counter].key, "If-Unmodified-Since")                     
                     || !apr_strnatcasecmp(headers_in[counter].key, "If-None-Match")) {
                    continue;
                }
        }


        buf = apr_pstrcat(p, headers_in[counter].key, ": ",
                          headers_in[counter].val, CRLF,
                          NULL);
        ap_xlate_proto_to_ascii(buf, strlen(buf));
        e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    }

    /* If we can send chunks, do so! */
    if (send_chunks) {
        const char *te_hdr = "Transfer-Encoding: chunked" CRLF;

        buf = apr_pmemdup(p, te_hdr, sizeof(te_hdr)-1);
        ap_xlate_proto_to_ascii(buf, sizeof(te_hdr)-1);

        e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    }
    else {
        last_header_bucket = APR_BRIGADE_LAST(header_brigade);
    }

    /* add empty line at the end of the headers */
#if APR_CHARSET_EBCDIC
    e = apr_bucket_immortal_create("\015\012", 2, c->bucket_alloc);
#else
    e = apr_bucket_immortal_create(CRLF, sizeof(CRLF)-1, c->bucket_alloc);
#endif
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    e = apr_bucket_flush_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);

    if (send_chunks) {
        status = ap_pass_brigade(origin->output_filters, header_brigade);

        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                         "proxy: request failed to %pI (%s)",
                         conn->worker->cp->addr, conn->hostname);
            return status;
        }
    }

    /* send the request data, if any. */
    seen_eos = 0;
    do {
        char chunk_hdr[20];  /* must be here due to transient bucket. */

        status = ap_get_brigade(r->input_filters, input_brigade,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                HUGE_STRING_LEN);

        if (status != APR_SUCCESS) {
            return status;
        }

        /* If this brigade contain EOS, either stop or remove it. */
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            seen_eos = 1;

            /* As a shortcut, if this brigade is simply an EOS bucket,
             * don't send anything down the filter chain.
             */
            if (APR_BUCKET_IS_EOS(APR_BRIGADE_FIRST(input_brigade))) {
                break;
            }

            /* We can't pass this EOS to the output_filters. */
            e = APR_BRIGADE_LAST(input_brigade);
            apr_bucket_delete(e);
        }

        if (send_chunks) {
#define ASCII_CRLF  "\015\012"
#define ASCII_ZERO  "\060"
            apr_size_t hdr_len;
            apr_off_t bytes;

            apr_brigade_length(input_brigade, 1, &bytes);

            hdr_len = apr_snprintf(chunk_hdr, sizeof(chunk_hdr),
                                   "%" APR_UINT64_T_HEX_FMT CRLF, 
                                   (apr_uint64_t)bytes);

            ap_xlate_proto_to_ascii(chunk_hdr, hdr_len);
            e = apr_bucket_transient_create(chunk_hdr, hdr_len,
                                            body_brigade->bucket_alloc);
            APR_BRIGADE_INSERT_HEAD(input_brigade, e);

            /*
             * Append the end-of-chunk CRLF
             */
            e = apr_bucket_immortal_create(ASCII_CRLF, 2, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(input_brigade, e);
        }

        e = apr_bucket_flush_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(input_brigade, e);

        APR_BRIGADE_CONCAT(body_brigade, input_brigade);

        if (send_chunks) {
            status = ap_pass_brigade(origin->output_filters, body_brigade);

            if (status != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                             "proxy: pass request data failed to %pI (%s)",
                         conn->worker->cp->addr, conn->hostname);
                return status;
            }

            apr_brigade_cleanup(body_brigade);
        }

    } while (!seen_eos);

    if (send_chunks) {
        e = apr_bucket_immortal_create(ASCII_ZERO ASCII_CRLF
                                       /* <trailers> */
                                       ASCII_CRLF, 5, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(body_brigade, e);
    }

    if (!send_chunks) {
        apr_off_t bytes;

        apr_brigade_length(body_brigade, 1, &bytes);

        if (bytes) {
            const char *cl_hdr = "Content-Length", *cl_val;
            cl_val = apr_off_t_toa(c->pool, bytes);
            buf = apr_pstrcat(p, cl_hdr, ": ", cl_val, CRLF, NULL);
            ap_xlate_proto_to_ascii(buf, strlen(buf));
            e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
            APR_BUCKET_INSERT_AFTER(last_header_bucket, e);
        }
        status = ap_pass_brigade(origin->output_filters, header_brigade);
        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                         "proxy: pass request data failed to %pI (%s)",
                         conn->worker->cp->addr, conn->hostname);
            return status;
        }

        apr_brigade_cleanup(header_brigade);
    }

    status = ap_pass_brigade(origin->output_filters, body_brigade);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: pass request data failed to %pI (%s)",
                      conn->worker->cp->addr, conn->hostname);
        return status;
    }
 
    apr_brigade_cleanup(body_brigade);

    return APR_SUCCESS;
}
static void process_proxy_header(request_rec* r, proxy_server_conf* c,
                      const char* key, const char* value)
{
    static const char* date_hdrs[]
        = { "Date", "Expires", "Last-Modified", NULL } ;
    static const struct {
        const char* name ;
        const char* (*func)(request_rec*, proxy_server_conf*, const char*) ;
    } transform_hdrs[] = {
        { "Location", ap_proxy_location_reverse_map } ,
        { "Content-Location", ap_proxy_location_reverse_map } ,
        { "URI", ap_proxy_location_reverse_map } ,
        { "Set-Cookie", proxy_cookie_reverse_map } ,
        { NULL, NULL }
    } ;
    int i ;
    for ( i = 0 ; date_hdrs[i] ; ++i ) {
        if ( !strcasecmp(date_hdrs[i], key) ) {
            apr_table_add(r->headers_out, key,
                ap_proxy_date_canon(r->pool, value)) ;
            return ;
        }
    }
    for ( i = 0 ; transform_hdrs[i].name ; ++i ) {
        if ( !strcasecmp(transform_hdrs[i].name, key) ) {
            apr_table_add(r->headers_out, key,
                (*transform_hdrs[i].func)(r, c, value)) ;
            return ;
       }
    }
    apr_table_add(r->headers_out, key, value) ;
    return ;
}

static void ap_proxy_read_headers(request_rec *r, request_rec *rr, char *buffer, int size, conn_rec *c)
{
    int len;
    char *value, *end;
    char field[MAX_STRING_LEN];
    int saw_headers = 0;
    void *sconf = r->server->module_config;
    proxy_server_conf *psc;

    psc = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    r->headers_out = apr_table_make(r->pool, 20);

    /*
     * Read header lines until we get the empty separator line, a read error,
     * the connection closes (EOF), or we timeout.
     */
    while ((len = ap_getline(buffer, size, rr, 1)) > 0) {

        if (!(value = strchr(buffer, ':'))) {     /* Find the colon separator */

            /* We may encounter invalid headers, usually from buggy
             * MS IIS servers, so we need to determine just how to handle
             * them. We can either ignore them, assume that they mark the
             * start-of-body (eg: a missing CRLF) or (the default) mark
             * the headers as totally bogus and return a 500. The sole
             * exception is an extra "HTTP/1.0 200, OK" line sprinkled
             * in between the usual MIME headers, which is a favorite
             * IIS bug.
             */
             /* XXX: The mask check is buggy if we ever see an HTTP/1.10 */

            if (!apr_date_checkmask(buffer, "HTTP/#.# ###*")) {
                if (psc->badopt == bad_error) {
                    /* Nope, it wasn't even an extra HTTP header. Give up. */
                    return ;
                }
                else if (psc->badopt == bad_body) {
                    /* if we've already started loading headers_out, then
                     * return what we've accumulated so far, in the hopes
                     * that they are useful. Otherwise, we completely bail.
                     */
                    /* FIXME: We've already scarfed the supposed 1st line of
                     * the body, so the actual content may end up being bogus
                     * as well. If the content is HTML, we may be lucky.
                     */
                    if (saw_headers) {
                        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                         "proxy: Starting body due to bogus non-header in headers "
                         "returned by %s (%s)", r->uri, r->method);
                        return ;
                    } else {
                         ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                         "proxy: No HTTP headers "
                         "returned by %s (%s)", r->uri, r->method);
                        return ;
                    }
                }
            }
            /* this is the psc->badopt == bad_ignore case */
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                         "proxy: Ignoring bogus HTTP header "
                         "returned by %s (%s)", r->uri, r->method);
            continue;
        }

        *value = '\0';
        ++value;
        /* XXX: RFC2068 defines only SP and HT as whitespace, this test is
         * wrong... and so are many others probably.
         */
        while (apr_isspace(*value))
            ++value;            /* Skip to start of value   */

        /* should strip trailing whitespace as well */
        for (end = &value[strlen(value)-1]; end > value && apr_isspace(*end); --
end)
            *end = '\0';

        /* make sure we add so as not to destroy duplicated headers
         * Modify headers requiring canonicalisation and/or affected
         * by ProxyPassReverse and family with process_proxy_header
         */
        process_proxy_header(r, psc, buffer, value) ;
        saw_headers = 1;

        /* the header was too long; at the least we should skip extra data */
        if (len >= size - 1) {
            while ((len = ap_getline(field, MAX_STRING_LEN, rr, 1))
                    >= MAX_STRING_LEN - 1) {
                /* soak up the extra data */
            }
            if (len == 0) /* time to exit the larger loop as well */
                break;
        }
    }
}



static int addit_dammit(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

static
apr_status_t ap_proxy_http_process_response(apr_pool_t * p, request_rec *r,
                                            proxy_conn_rec *backend,
                                            conn_rec *origin,
                                            proxy_server_conf *conf,
                                            char *server_portstr) {
    conn_rec *c = r->connection;
    char buffer[HUGE_STRING_LEN];
    char keepchar;
    request_rec *rp;
    apr_bucket *e;
    apr_bucket_brigade *bb;
    int len, backasswards;
    int interim_response; /* non-zero whilst interim 1xx responses
                           * are being read. */
    apr_table_t *save_table;

    bb = apr_brigade_create(p, c->bucket_alloc);

    /* Get response from the remote server, and pass it up the
     * filter chain
     */

    rp = ap_proxy_make_fake_req(origin, r);
    /* In case anyone needs to know, this is a fake request that is really a
     * response.
     */
    rp->proxyreq = PROXYREQ_RESPONSE;

    do {
        apr_brigade_cleanup(bb);

        len = ap_getline(buffer, sizeof(buffer), rp, 0);
        if (len == 0) {
            /* handle one potential stray CRLF */
            len = ap_getline(buffer, sizeof(buffer), rp, 0);
        }
        if (len <= 0) {
            apr_socket_close(backend->sock);
            backend->sock = NULL;
//            backend->connection = NULL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "proxy: error reading status line from remote "
                          "server %s", backend->hostname);
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
        }

       /* Is it an HTTP/1 response?
        * This is buggy if we ever see an HTTP/1.10
        */
        if (apr_date_checkmask(buffer, "HTTP/#.# ###*")) {
            int major, minor;

            if (2 != sscanf(buffer, "HTTP/%u.%u", &major, &minor)) {
                major = 1;
                minor = 1;
            }
            /* If not an HTTP/1 message or
             * if the status line was > 8192 bytes
             */
            else if ((buffer[5] != '1') || (len >= sizeof(buffer)-1)) {
                apr_socket_close(backend->sock);
//                backend->connection = NULL;
                backend->sock = NULL;
                return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                apr_pstrcat(p, "Corrupt status line returned by remote "
                            "server: ", buffer, NULL));
            }
            backasswards = 0;

            keepchar = buffer[12];
            buffer[12] = '\0';
            r->status = atoi(&buffer[9]);

            if (keepchar != '\0') {
                buffer[12] = keepchar;
            } else {
                /* 2616 requires the space in Status-Line; the origin
                 * server may have sent one but ap_rgetline_core will
                 * have stripped it. */
                buffer[12] = ' ';
                buffer[13] = '\0';
            }
            r->status_line = apr_pstrdup(p, &buffer[9]);
            

            /* read the headers. */
            /* N.B. for HTTP/1.0 clients, we have to fold line-wrapped headers*/
            /* Also, take care with headers with multiple occurences. */

            /* First, tuck away all already existing cookies */
            save_table = apr_table_make(r->pool, 2);
            apr_table_do(addit_dammit, save_table, r->headers_out,
                         "Set-Cookie", NULL);

	    /* shove the headers direct into r->headers_out */
            ap_proxy_read_headers(r, rp, buffer, sizeof(buffer), origin);

            if (r->headers_out == NULL) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                             r->server, "proxy: bad HTTP/%d.%d header "
                             "returned by %s (%s)", major, minor, r->uri,
                             r->method);
                backend->close += 1;
                /*
                 * ap_send_error relies on a headers_out to be present. we
                 * are in a bad position here.. so force everything we send out
                 * to have nothing to do with the incoming packet
                 */
                r->headers_out = apr_table_make(r->pool,1);
                r->status = HTTP_BAD_GATEWAY;
                r->status_line = "bad gateway";
                return r->status;

            } else {
                const char *buf;

                /* Now, add in the just read cookies */
                apr_table_do(addit_dammit, save_table, r->headers_out,
        	             "Set-Cookie", NULL);

                /* and now load 'em all in */
                if (!apr_is_empty_table(save_table)) {
                    apr_table_unset(r->headers_out, "Set-Cookie");
                    r->headers_out = apr_table_overlay(r->pool,
                                                       r->headers_out,
                                                       save_table);
                }
                
                /* strip connection listed hop-by-hop headers from response */
                backend->close += ap_proxy_liststr(apr_table_get(r->headers_out,
                                                                 "Connection"),
                                                  "close");
                ap_proxy_clear_connection(p, r->headers_out);
                if ((buf = apr_table_get(r->headers_out, "Content-Type"))) {
                    ap_set_content_type(r, apr_pstrdup(p, buf));
                }            
                ap_proxy_pre_http_request(origin,rp);
            }

            /* handle Via header in response */
            if (conf->viaopt != via_off && conf->viaopt != via_block) {
                const char *server_name = ap_get_server_name(r);
                /* If USE_CANONICAL_NAME_OFF was configured for the proxy virtual host,
                 * then the server name returned by ap_get_server_name() is the
                 * origin server name (which does make too much sense with Via: headers)
                 * so we use the proxy vhost's name instead.
                 */
                if (server_name == r->hostname)
                    server_name = r->server->server_hostname;
                /* create a "Via:" response header entry and merge it */
                apr_table_mergen(r->headers_out, "Via",
                                 (conf->viaopt == via_full)
                                     ? apr_psprintf(p, "%d.%d %s%s (%s)",
                                           HTTP_VERSION_MAJOR(r->proto_num),
                                           HTTP_VERSION_MINOR(r->proto_num),
                                           server_name,
                                           server_portstr,
                                           AP_SERVER_BASEVERSION)
                                     : apr_psprintf(p, "%d.%d %s%s",
                                           HTTP_VERSION_MAJOR(r->proto_num),
                                           HTTP_VERSION_MINOR(r->proto_num),
                                           server_name,
                                           server_portstr)
                );
            }

            /* cancel keepalive if HTTP/1.0 or less */
            if ((major < 1) || (minor < 1)) {
                backend->close += 1;
                origin->keepalive = AP_CONN_CLOSE;
            }
        } else {
            /* an http/0.9 response */
            backasswards = 1;
            r->status = 200;
            r->status_line = "200 OK";
            backend->close += 1;
        }

        interim_response = ap_is_HTTP_INFO(r->status);
        if (interim_response) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                         "proxy: HTTP: received interim %d response",
                         r->status);
        }
        /* Moved the fixups of Date headers and those affected by
         * ProxyPassReverse/etc from here to ap_proxy_read_headers
         */

        if ((r->status == 401) && (conf->error_override != 0)) {
            const char *buf;
            const char *wa = "WWW-Authenticate";
            if ((buf = apr_table_get(r->headers_out, wa))) {
                apr_table_set(r->err_headers_out, wa, buf);
            } else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                             "proxy: origin server sent 401 without WWW-Authenticate header");
            }
        }

        r->sent_bodyct = 1;
        /* Is it an HTTP/0.9 response? If so, send the extra data */
        if (backasswards) {
            apr_ssize_t cntr = len;
            /*@@@FIXME:
             * At this point in response processing of a 0.9 response,
             * we don't know yet whether data is binary or not.
             * mod_charset_lite will get control later on, so it cannot
             * decide on the conversion of this buffer full of data.
             * However, chances are that we are not really talking to an
             * HTTP/0.9 server, but to some different protocol, therefore
             * the best guess IMHO is to always treat the buffer as "text/x":
             */
            ap_xlate_proto_to_ascii(buffer, len);
            e = apr_bucket_heap_create(buffer, cntr, NULL, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
        }

        /* send body - but only if a body is expected */
        if ((!r->header_only) &&                   /* not HEAD request */
            !interim_response &&                   /* not any 1xx response */
            (r->status != HTTP_NO_CONTENT) &&      /* not 204 */
            (r->status != HTTP_RESET_CONTENT) &&   /* not 205 */
            (r->status != HTTP_NOT_MODIFIED)) {    /* not 304 */

            /* We need to copy the output headers and treat them as input
             * headers as well.  BUT, we need to do this before we remove
             * TE, so that they are preserved accordingly for
             * ap_http_filter to know where to end.
             */
            rp->headers_in = apr_table_copy(r->pool, r->headers_out);

            apr_table_unset(r->headers_out,"Transfer-Encoding");

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: start body send");
             
            /*
             * if we are overriding the errors, we can't put the content
             * of the page into the brigade
             */
            if (conf->error_override == 0 || ap_is_HTTP_SUCCESS(r->status)) {

                /* read the body, pass it to the output filters */
                int finish = FALSE;
                while (ap_get_brigade(rp->input_filters, 
                                      bb, 
                                      AP_MODE_READBYTES, 
                                      APR_BLOCK_READ, 
                                      conf->io_buffer_size) == APR_SUCCESS) {
#if DEBUGGING
                    {
                    apr_off_t readbytes;
                    apr_brigade_length(bb, 0, &readbytes);
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                                 r->server, "proxy (PID %d): readbytes: %#x",
                                 getpid(), readbytes);
                    }
#endif
                    /* sanity check */
                    if (APR_BRIGADE_EMPTY(bb)) {
                        apr_brigade_cleanup(bb);
                        break;
                    }

                    /* found the last brigade? */
                    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
                        /* if this is the last brigade, cleanup the
                         * backend connection first to prevent the
                         * backend server from hanging around waiting
                         * for a slow client to eat these bytes
                         */
                        backend->close = 1;
                        /* signal that we must leave */
                        finish = TRUE;
                    }

                    /* try send what we read */
                    if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS) {
                        /* Ack! Phbtt! Die! User aborted! */
                        backend->close = 1;  /* this causes socket close below */
                        finish = TRUE;
                    }

                    /* make sure we always clean up after ourselves */
                    apr_brigade_cleanup(bb);

                    /* if we are done, leave */
                    if (TRUE == finish) {
                        break;
                    }
                }
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: end body send");
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: header only");
        }
    } while (interim_response);

    if (conf->error_override) {
        /* the code above this checks for 'OK' which is what the hook expects */
        if (ap_is_HTTP_SUCCESS(r->status))
            return OK;
        else {
            /* clear r->status for override error, otherwise ErrorDocument
             * thinks that this is a recursive error, and doesn't find the
             * custom error page
             */
            int status = r->status;
            r->status = HTTP_OK;
            /* Discard body, if one is expected */
            if ((status != HTTP_NO_CONTENT) && /* not 204 */
                (status != HTTP_RESET_CONTENT) && /* not 205 */
                (status != HTTP_NOT_MODIFIED)) { /* not 304 */
               ap_discard_request_body(rp);
           }
            return status;
        }
    } else 
        return OK;
}

static
apr_status_t ap_proxy_http_cleanup(const char *scheme, request_rec *r,
                                   proxy_conn_rec *backend)
{
    /* If there are no KeepAlives, or if the connection has been signalled
     * to close, close the socket and clean up
     */

    /* if the connection is < HTTP/1.1, or Connection: close,
     * we close the socket, otherwise we leave it open for KeepAlive support
     */
    if (backend->close || (r->proto_num < HTTP_VERSION(1,1))) {
        backend->close_on_recycle = 1;
        ap_set_module_config(r->connection->conn_config, &proxy_http_module, NULL);
        ap_proxy_release_connection(scheme, backend, r->server);    
    }
    return OK;
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
int ap_proxy_http_handler(request_rec *r, proxy_worker *worker,
                          proxy_server_conf *conf,
                          char *url, const char *proxyname, 
                          apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    char *scheme;
    const char *u;
    proxy_conn_rec *backend = NULL;
    int is_ssl = 0;

    /* Note: Memory pool allocation.
     * A downstream keepalive connection is always connected to the existence
     * (or not) of an upstream keepalive connection. If this is not done then
     * load balancing against multiple backend servers breaks (one backend
     * server ends up taking 100% of the load), and the risk is run of
     * downstream keepalive connections being kept open unnecessarily. This
     * keeps webservers busy and ties up resources.
     *
     * As a result, we allocate all sockets out of the upstream connection
     * pool, and when we want to reuse a socket, we check first whether the
     * connection ID of the current upstream connection is the same as that
     * of the connection when the socket was opened.
     */
    apr_pool_t *p = r->connection->pool;
    conn_rec *c = r->connection;
    apr_uri_t *uri = apr_palloc(r->connection->pool, sizeof(*uri));

    /* find the scheme */
    u = strchr(url, ':');
    if (u == NULL || u[1] != '/' || u[2] != '/' || u[3] == '\0')
       return DECLINED;
    if ((u - url) > 14)
        return HTTP_BAD_REQUEST;
    scheme = apr_pstrndup(c->pool, url, u - url);
    /* scheme is lowercase */
    apr_tolower(scheme);
    /* is it for us? */
    if (strcmp(scheme, "https") == 0) {
        if (!ap_proxy_ssl_enable(NULL)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: HTTPS: declining URL %s"
                         " (mod_ssl not configured?)", url);
            return DECLINED;
        }
        is_ssl = 1;
    }
    else if (!(strcmp(scheme, "http") == 0 || (strcmp(scheme, "ftp") == 0 && proxyname))) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: HTTP: declining URL %s", url);
        return DECLINED; /* only interested in HTTP, or FTP via proxy */
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "proxy: HTTP: serving URL %s", url);
    
    
    /* only use stored info for top-level pages. Sub requests don't share 
     * in keepalives
     */
    if (!r->main) {
        backend = (proxy_conn_rec *) ap_get_module_config(c->conn_config,
                                                      &proxy_http_module);
    }
    /* create space for state information */
    if (!backend) {
        status = ap_proxy_acquire_connection(scheme, &backend, worker, r->server);
        if (status != OK) {
            if (backend) {
                backend->close_on_recycle = 1;
                ap_proxy_release_connection(scheme, backend, r->server);
            }
            return status;
        }
        if (!r->main) {
            ap_set_module_config(c->conn_config, &proxy_http_module, backend);
        }
    }

    backend->is_ssl = is_ssl;
    backend->close_on_recycle = 1;

    /* Step One: Determine Who To Connect To */
    status = ap_proxy_determine_connection(p, r, conf, worker, backend, c->pool,
                                           uri, &url, proxyname, proxyport,
                                           server_portstr,
                                           sizeof(server_portstr));

    if ( status != OK ) {
        return status;
    }

    /* Step Two: Make the Connection */
    status = ap_proxy_connect_backend(scheme, backend, worker, r->server);
    if ( status != OK ) {
        return status;
    }

    /* Step Three: Create conn_rec */
    if (!backend->connection) {
        status = ap_proxy_connection_create(scheme, backend, c, r->server);
        if (status != OK)
            return status;
    }
   
    /* Step Four: Send the Request */
    status = ap_proxy_http_request(p, r, backend, backend->connection, conf, uri, url,
                                   server_portstr);
    if ( status != OK ) {
        return status;
    }

    /* Step Five: Receive the Response */
    status = ap_proxy_http_process_response(p, r, backend, backend->connection, conf,
                                            server_portstr);
    if (status != OK) {
        /* clean up even if there is an error */
        ap_proxy_http_cleanup(scheme, r, backend);
        return status;
    }

    /* Step Six: Clean Up */
    status = ap_proxy_http_cleanup(scheme, r, backend);
    if ( status != OK ) {
        return status;
    }

    return OK;
}

static void ap_proxy_http_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(ap_proxy_http_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(ap_proxy_http_canon, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA proxy_http_module = {
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    NULL,              /* command apr_table_t */
    ap_proxy_http_register_hook/* register hooks */
};

