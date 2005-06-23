/* Copyright 1999-2005 The Apache Software Foundation or its licensors, as
 * applicable.
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

static apr_status_t ap_proxy_http_cleanup(const char *scheme,
                                          request_rec *r,
                                          proxy_conn_rec *backend);

/*
 * Canonicalise http-like URLs.
 *  scheme is the scheme for the URL
 *  url    is the URL starting with the first '/'
 *  def_port is the default port for this scheme.
 */
static int proxy_http_canon(request_rec *r, char *url)
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
    path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, 0, r->proxyreq);
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

static void add_te_chunked(apr_pool_t *p,
                           apr_bucket_alloc_t *bucket_alloc,
                           apr_bucket_brigade *header_brigade)
{
    apr_bucket *e;
    char *buf;
    const char te_hdr[] = "Transfer-Encoding: chunked" CRLF;

    buf = apr_pmemdup(p, te_hdr, sizeof(te_hdr)-1);
    ap_xlate_proto_to_ascii(buf, sizeof(te_hdr)-1);

    e = apr_bucket_pool_create(buf, sizeof(te_hdr)-1, p, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}

static void add_cl(apr_pool_t *p,
                   apr_bucket_alloc_t *bucket_alloc,
                   apr_bucket_brigade *header_brigade,
                   const char *cl_val)
{
    apr_bucket *e;
    char *buf;

    buf = apr_pstrcat(p, "Content-Length: ",
                      cl_val,
                      CRLF,
                      NULL);
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}

#define ASCII_CRLF  "\015\012"
#define ASCII_ZERO  "\060"

static void terminate_headers(apr_bucket_alloc_t *bucket_alloc,
                              apr_bucket_brigade *header_brigade)
{
    apr_bucket *e;

    /* add empty line at the end of the headers */
    e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}

static apr_status_t pass_brigade(apr_bucket_alloc_t *bucket_alloc,
                                 request_rec *r, proxy_conn_rec *conn,
                                 conn_rec *origin, apr_bucket_brigade *b,
                                 int flush)
{
    apr_status_t status;
    apr_off_t transferred;

    if (flush) {
        apr_bucket *e = apr_bucket_flush_create(bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
    }
    apr_brigade_length(b, 0, &transferred);
    if (transferred != -1)
        conn->worker->s->transferred += transferred;
    status = ap_pass_brigade(origin->output_filters, b);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: pass request data failed to %pI (%s)",
                     conn->addr, conn->hostname);
        return status;
    }
    apr_brigade_cleanup(b);
    return APR_SUCCESS;
}

static apr_status_t stream_reqbody_chunked(apr_pool_t *p,
                                           request_rec *r,
                                           proxy_conn_rec *conn,
                                           conn_rec *origin,
                                           apr_bucket_brigade *header_brigade)
{
    int seen_eos = 0;
    apr_size_t hdr_len;
    apr_off_t bytes;
    apr_status_t status;
    apr_bucket_alloc_t *bucket_alloc = r->connection->bucket_alloc;
    apr_bucket_brigade *b, *input_brigade;
    apr_bucket *e;

    input_brigade = apr_brigade_create(p, bucket_alloc);

    do {
        char chunk_hdr[20];  /* must be here due to transient bucket. */

        status = ap_get_brigade(r->input_filters, input_brigade,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                HUGE_STRING_LEN);

        if (status != APR_SUCCESS) {
            return status;
        }

        /* If this brigade contains EOS, either stop or remove it. */
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

        apr_brigade_length(input_brigade, 1, &bytes);

        hdr_len = apr_snprintf(chunk_hdr, sizeof(chunk_hdr),
                               "%" APR_UINT64_T_HEX_FMT CRLF, 
                               (apr_uint64_t)bytes);
        
        ap_xlate_proto_to_ascii(chunk_hdr, hdr_len);
        e = apr_bucket_transient_create(chunk_hdr, hdr_len,
                                        bucket_alloc);
        APR_BRIGADE_INSERT_HEAD(input_brigade, e);
        
        /*
         * Append the end-of-chunk CRLF
         */
        e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(input_brigade, e);
        
        if (header_brigade) {
            /* we never sent the header brigade, so go ahead and
             * take care of that now
             */
            add_te_chunked(p, bucket_alloc, header_brigade);
            terminate_headers(bucket_alloc, header_brigade);
            b = header_brigade;
            APR_BRIGADE_CONCAT(b, input_brigade);
            header_brigade = NULL;
        }
        else {
            b = input_brigade;
        }
        
        status = pass_brigade(bucket_alloc, r, conn, origin, b, 0);
        if (status != APR_SUCCESS) {
            return status;
        }
    } while (!seen_eos);

    if (header_brigade) {
        /* we never sent the header brigade because there was no request body;
         * send it now without T-E
         */
        terminate_headers(bucket_alloc, header_brigade);
        b = header_brigade;
    }
    else {
        if (!APR_BRIGADE_EMPTY(input_brigade)) {
            /* input brigade still has an EOS which we can't pass to the output_filters. */
            e = APR_BRIGADE_LAST(input_brigade);
            AP_DEBUG_ASSERT(APR_BUCKET_IS_EOS(e));
            apr_bucket_delete(e);
        }
        e = apr_bucket_immortal_create(ASCII_ZERO ASCII_CRLF
                                       /* <trailers> */
                                       ASCII_CRLF,
                                       5, bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(input_brigade, e);
        b = input_brigade;
    }
    
    status = pass_brigade(bucket_alloc, r, conn, origin, b, 1);
    return status;
}

static apr_status_t stream_reqbody_cl(apr_pool_t *p,
                                      request_rec *r,
                                      proxy_conn_rec *conn,
                                      conn_rec *origin,
                                      apr_bucket_brigade *header_brigade,
                                      const char *old_cl_val)
{
    int seen_eos = 0;
    apr_status_t status;
    apr_bucket_alloc_t *bucket_alloc = r->connection->bucket_alloc;
    apr_bucket_brigade *b, *input_brigade;
    apr_bucket *e;

    input_brigade = apr_brigade_create(p, bucket_alloc);

    do {
        status = ap_get_brigade(r->input_filters, input_brigade,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                HUGE_STRING_LEN);

        if (status != APR_SUCCESS) {
            return status;
        }

        /* If this brigade contains EOS, either stop or remove it. */
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

        if (header_brigade) {
            /* we never sent the header brigade, so go ahead and
             * take care of that now
             */
            add_cl(p, bucket_alloc, header_brigade, old_cl_val);
            terminate_headers(bucket_alloc, header_brigade);
            b = header_brigade;
            APR_BRIGADE_CONCAT(b, input_brigade);
            header_brigade = NULL;
        }
        else {
            b = input_brigade;
        }
        
        status = pass_brigade(bucket_alloc, r, conn, origin, b, 0);
        if (status != APR_SUCCESS) {
            return status;
        }
    } while (!seen_eos);

    if (header_brigade) {
        /* we never sent the header brigade since there was no request
         * body; send it now, and only specify C-L if client specified
         * C-L: 0
         */
        if (!strcmp(old_cl_val, "0")) {
            add_cl(p, bucket_alloc, header_brigade, old_cl_val);
        }
        terminate_headers(bucket_alloc, header_brigade);
        b = header_brigade;
    }
    else {
        /* need to flush any pending data */
        b = input_brigade; /* empty now; pass_brigade() will add flush */
    }
    if (apr_table_get(r->subprocess_env, "proxy-sendextracrlf")) {
        e = apr_bucket_immortal_create(ASCII_CRLF, 2,
                                       r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(input_brigade, e);
    }

    status = pass_brigade(bucket_alloc, r, conn, origin, b, 1);
    return status;
}

#define MAX_MEM_SPOOL 16384

static apr_status_t spool_reqbody_cl(apr_pool_t *p,
                                     request_rec *r,
                                     proxy_conn_rec *conn,
                                     conn_rec *origin,
                                     apr_bucket_brigade *header_brigade)
{
    int seen_eos = 0;
    apr_status_t status;
    apr_bucket_alloc_t *bucket_alloc = r->connection->bucket_alloc;
    apr_bucket_brigade *body_brigade, *input_brigade;
    apr_bucket *e;
    apr_off_t bytes, bytes_spooled = 0, fsize = 0;
    apr_file_t *tmpfile = NULL;

    body_brigade = apr_brigade_create(p, bucket_alloc);
    input_brigade = apr_brigade_create(p, bucket_alloc);

    do {
        status = ap_get_brigade(r->input_filters, input_brigade,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                HUGE_STRING_LEN);

        if (status != APR_SUCCESS) {
            return status;
        }

        /* If this brigade contains EOS, either stop or remove it. */
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

        apr_brigade_length(input_brigade, 1, &bytes);

        if (bytes_spooled + bytes > MAX_MEM_SPOOL) {
            /* can't spool any more in memory; write latest brigade to disk;
             * what we read into memory before reaching our threshold will
             * remain there; we just write this and any subsequent data to disk
             */
            if (tmpfile == NULL) {
                const char *temp_dir;
                char *template;

                status = apr_temp_dir_get(&temp_dir, p);
                if (status != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                                 "proxy: search for temporary directory failed");
                    return status;
                }
                apr_filepath_merge(&template, temp_dir,
                                   "modproxy.tmp.XXXXXX",
                                   APR_FILEPATH_NATIVE, p);
                status = apr_file_mktemp(&tmpfile, template, 0, p);
                if (status != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                                 "proxy: creation of temporary file in directory %s failed",
                                 temp_dir);
                    return status;
                }
            }
            for (e = APR_BRIGADE_FIRST(input_brigade);
                 e != APR_BRIGADE_SENTINEL(input_brigade);
                 e = APR_BUCKET_NEXT(e)) {
                const char *data;
                apr_size_t bytes_read, bytes_written;

                apr_bucket_read(e, &data, &bytes_read, APR_BLOCK_READ);
                status = apr_file_write_full(tmpfile, data, bytes_read, &bytes_written);
                if (status != APR_SUCCESS) {
                    const char *tmpfile_name;

                    if (apr_file_name_get(&tmpfile_name, tmpfile) != APR_SUCCESS) {
                        tmpfile_name = "(unknown)";
                    }
                    ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                                 "proxy: write to temporary file %s failed",
                                 tmpfile_name);
                    return status;
                }
                AP_DEBUG_ASSERT(bytes_read == bytes_written);
                fsize += bytes_written;
            }
            apr_brigade_cleanup(input_brigade);
        }
        else {
            APR_BRIGADE_CONCAT(body_brigade, input_brigade);
        }
        
        bytes_spooled += bytes;

    } while (!seen_eos);

    if (bytes_spooled) {
        add_cl(p, bucket_alloc, header_brigade, apr_off_t_toa(p, bytes_spooled));
    }
    terminate_headers(bucket_alloc, header_brigade);
    APR_BRIGADE_CONCAT(header_brigade, body_brigade);
    if (tmpfile) {
        /* For platforms where the size of the file may be larger than
         * that which can be stored in a single bucket (where the
         * length field is an apr_size_t), split it into several
         * buckets: */
        if (sizeof(apr_off_t) > sizeof(apr_size_t)
            && fsize > AP_MAX_SENDFILE) {
            e = apr_bucket_file_create(tmpfile, 0, AP_MAX_SENDFILE, p,
                                       bucket_alloc);
            while (fsize > AP_MAX_SENDFILE) {
                apr_bucket *ce;
                apr_bucket_copy(e, &ce);
                APR_BRIGADE_INSERT_TAIL(header_brigade, ce);
                e->start += AP_MAX_SENDFILE;
                fsize -= AP_MAX_SENDFILE;
            }
            e->length = (apr_size_t)fsize; /* Resize just the last bucket */
        }
        else {
            e = apr_bucket_file_create(tmpfile, 0, (apr_size_t)fsize, p,
                                       bucket_alloc);
        }
        APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    }
    if (apr_table_get(r->subprocess_env, "proxy-sendextracrlf")) {
        e = apr_bucket_immortal_create(ASCII_CRLF, 2,
                                       r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    }
    status = pass_brigade(bucket_alloc, r, conn, origin, header_brigade, 1);
    return status;
}

static apr_status_t send_request_body(apr_pool_t *p,
                                      request_rec *r,
                                      proxy_conn_rec *conn,
                                      conn_rec *origin,
                                      apr_bucket_brigade *header_brigade,
                                      int force10)
{
    enum {RB_INIT, RB_STREAM_CL, RB_STREAM_CHUNKED, RB_SPOOL_CL} rb_method = RB_INIT;
    const char *old_cl_val, *te_val;
    int cl_zero; /* client sent "Content-Length: 0", which we forward on to server */
    apr_status_t status;

    /* send CL or use chunked encoding?
     *
     * . CL is the most friendly to the origin server since it is the
     *   most widely supported
     * . CL stinks if we don't know the length since we have to buffer
     *   the data in memory or on disk until we get the entire data
     *
     * special cases to check for:
     * . if we're using HTTP/1.0 to origin server, then we must send CL
     * . if client sent C-L and there are no input resource filters, the
     *   the body size can't change so we send the same CL and stream the
     *   body
     * . if client used chunked or proxy-sendchunks is set, we'll use
     *   chunked
     *
     * normal case:
     *   we have to compute content length by reading the entire request
     *   body; if request body is not small, we'll spool the remaining input
     *   to a temporary file
     *
     * special envvars to override the normal decision:
     * . proxy-sendchunks
     *   use chunked encoding; not compatible with force-proxy-request-1.0
     * . proxy-sendcl
     *   spool the request body to compute C-L
     * . proxy-sendunchangedcl
     *   use C-L from client and spool the request body
     */
    old_cl_val = apr_table_get(r->headers_in, "Content-Length");
    cl_zero = old_cl_val && !strcmp(old_cl_val, "0");

    if (!force10
        && !cl_zero
        && apr_table_get(r->subprocess_env, "proxy-sendchunks")) {
        rb_method = RB_STREAM_CHUNKED;
    }
    else if (!cl_zero
             && apr_table_get(r->subprocess_env, "proxy-sendcl")) {
        rb_method = RB_SPOOL_CL;
    }
    else {
        if (old_cl_val &&
            (r->input_filters == r->proto_input_filters
             || cl_zero
             || apr_table_get(r->subprocess_env, "proxy-sendunchangedcl"))) {
            rb_method = RB_STREAM_CL;
        }
        else if (force10) {
            rb_method = RB_SPOOL_CL;
        }
        else if ((te_val = apr_table_get(r->headers_in, "Transfer-Encoding"))
                  && !strcasecmp(te_val, "chunked")) {
            rb_method = RB_STREAM_CHUNKED;
        }
        else {
            rb_method = RB_SPOOL_CL;
        }
    }

    switch(rb_method) {
    case RB_STREAM_CHUNKED:
        status = stream_reqbody_chunked(p, r, conn, origin, header_brigade);
        break;
    case RB_STREAM_CL:
        status = stream_reqbody_cl(p, r, conn, origin, header_brigade, old_cl_val);
        break;
    case RB_SPOOL_CL:
        status = spool_reqbody_cl(p, r, conn, origin, header_brigade);
        break;
    default:
        ap_assert(1 != 1);
    }

    return status;
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
    apr_bucket *e;
    const apr_array_header_t *headers_in_array;
    const apr_table_entry_t *headers_in;
    int counter;
    apr_status_t status;
    apr_bucket_brigade *header_brigade;
    int force10;

    header_brigade = apr_brigade_create(p, origin->bucket_alloc);

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
     * the correct Content-Length attached.  A special case is when
     * the client specifies Content-Length and there are no filters
     * which muck with the request body.  In that situation, we don't
     * have to buffer the entire request and can still send the
     * Content-Length.  Another special case is when the client
     * specifies a C-L of 0.  Pass that through as well.
     */

    if (apr_table_get(r->subprocess_env, "force-proxy-request-1.0")) {
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.0" CRLF, NULL);
        force10 = 1;
    } else {
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.1" CRLF, NULL);
        force10 = 0;
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

            /* We'll add appropriate Content-Length later, if appropriate.
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

    /* send the request data, if any. */
    status = send_request_body(p, r, conn, origin, header_brigade, force10);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: pass request data failed to %pI (%s)",
                     conn->addr, conn->hostname);
        return status;
    }
    return APR_SUCCESS;
}

static void process_proxy_header(request_rec* r, proxy_server_conf* c,
                      const char* key, const char* value)
{
    static const char* date_hdrs[]
        = { "Date", "Expires", "Last-Modified", NULL } ;
    static const struct {
        const char* name;
        ap_proxy_header_reverse_map_fn func;
    } transform_hdrs[] = {
        { "Location", ap_proxy_location_reverse_map } ,
        { "Content-Location", ap_proxy_location_reverse_map } ,
        { "URI", ap_proxy_location_reverse_map } ,
        { "Destination", ap_proxy_location_reverse_map } ,
        { "Set-Cookie", ap_proxy_cookie_reverse_map } ,
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

/*
 * Note: pread_len is the length of the response that we've  mistakenly
 * read (assuming that we don't consider that an  error via
 * ProxyBadHeader StartBody). This depends on buffer actually being
 * local storage to the calling code in order for pread_len to make
 * any sense at all, since we depend on buffer still containing
 * what was read by ap_getline() upon return.
 */
static void ap_proxy_read_headers(request_rec *r, request_rec *rr,
                                  char *buffer, int size,
                                  conn_rec *c, int *pread_len)
{
    int len;
    char *value, *end;
    char field[MAX_STRING_LEN];
    int saw_headers = 0;
    void *sconf = r->server->module_config;
    proxy_server_conf *psc;

    psc = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    r->headers_out = apr_table_make(r->pool, 20);
    *pread_len = 0;

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
                    r->headers_out = NULL;
                    return ;
                }
                else if (psc->badopt == bad_body) {
                    /* if we've already started loading headers_out, then
                     * return what we've accumulated so far, in the hopes
                     * that they are useful; also note that we likely pre-read
                     * the first line of the response.
                     */
                    if (saw_headers) {
                        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                         "proxy: Starting body due to bogus non-header in headers "
                         "returned by %s (%s)", r->uri, r->method);
                        *pread_len = len;
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
    int pread_len = 0;
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
            ap_proxy_http_cleanup(NULL, r, backend);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "proxy: error reading status line from remote "
                          "server %s", backend->hostname);
            return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                 "Error reading from remote server");
        }
        /* XXX: Is this a real headers length send from remote? */
        backend->worker->s->read += len;

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
                ap_proxy_http_cleanup(NULL, r, backend);
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
            ap_proxy_read_headers(r, rp, buffer, sizeof(buffer), origin,
                                  &pread_len);

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

                /* can't have both Content-Length and Transfer-Encoding */
                if (apr_table_get(r->headers_out, "Transfer-Encoding")
                    && apr_table_get(r->headers_out, "Content-Length")) {
                    /* 2616 section 4.4, point 3: "if both Transfer-Encoding
                     * and Content-Length are received, the latter MUST be
                     * ignored"; so unset it here to prevent any confusion
                     * later. */
                    apr_table_unset(r->headers_out, "Content-Length");
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                                 r->server,
                                 "proxy: server %s returned Transfer-Encoding and Content-Length",
                                 backend->hostname);
                    backend->close += 1;
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
        /*
         * Is it an HTTP/0.9 response or did we maybe preread the 1st line of
         * the response? If so, load the extra data. These are 2 mutually
         * exclusive possibilities, that just happen to require very
         * similar behavior.
         */
        if (backasswards || pread_len) {
            apr_ssize_t cntr = (apr_ssize_t)pread_len;
            if (backasswards) {
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
                cntr = (apr_ssize_t)len;
            }
            e = apr_bucket_heap_create(buffer, cntr, NULL, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
        }

        /* send body - but only if a body is expected */
        if ((!r->header_only) &&                   /* not HEAD request */
            !interim_response &&                   /* not any 1xx response */
            (r->status != HTTP_NO_CONTENT) &&      /* not 204 */
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
                apr_read_type_e mode = APR_NONBLOCK_READ;
                int finish = FALSE;

                do {
                    apr_off_t readbytes;
                    apr_status_t rv;

                    rv = ap_get_brigade(rp->input_filters, bb, 
                                        AP_MODE_READBYTES, mode,
                                        conf->io_buffer_size);

                    /* ap_get_brigade will return success with an empty brigade
                     * for a non-blocking read which would block: */
                    if (APR_STATUS_IS_EAGAIN(rv)
                        || (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(bb))) {
                        /* flush to the client and switch to blocking mode */
                        e = apr_bucket_flush_create(c->bucket_alloc);
                        APR_BRIGADE_INSERT_TAIL(bb, e);
                        if (ap_pass_brigade(r->output_filters, bb) 
                            || c->aborted) {
                            backend->close = 1;
                            break;
                        }
                        apr_brigade_cleanup(bb);
                        mode = APR_BLOCK_READ;
                        continue;
                    }
                    else if (rv == APR_EOF) {
                        break;
                    }
                    else if (rv != APR_SUCCESS) {
                        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                                      "proxy: error reading response");
                        break;
                    }
                    /* next time try a non-blocking read */
                    mode = APR_NONBLOCK_READ;
                    
                    apr_brigade_length(bb, 0, &readbytes);
                    backend->worker->s->read += readbytes;
#if DEBUGGING
                    {
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
                    if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS
                        || c->aborted) {
                        /* Ack! Phbtt! Die! User aborted! */
                        backend->close = 1;  /* this causes socket close below */
                        finish = TRUE;
                    }

                    /* make sure we always clean up after ourselves */
                    apr_brigade_cleanup(bb);

                } while (!finish);
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: end body send");
        }
        else if (!interim_response) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: header only");

            /* Pass EOS bucket down the filter chain. */
            e = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS
                || c->aborted) {
                /* Ack! Phbtt! Die! User aborted! */
                backend->close = 1;  /* this causes socket close below */
            }

            apr_brigade_cleanup(bb);
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
static int proxy_http_handler(request_rec *r, proxy_worker *worker,
                              proxy_server_conf *conf,
                              char *url, const char *proxyname, 
                              apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    char *scheme;
    const char *proxy_function;
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
    ap_str_tolower(scheme);
    /* is it for us? */
    if (strcmp(scheme, "https") == 0) {
        if (!ap_proxy_ssl_enable(NULL)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: HTTPS: declining URL %s"
                         " (mod_ssl not configured?)", url);
            return DECLINED;
        }
        is_ssl = 1;
        proxy_function = "HTTPS";
    }
    else if (!(strcmp(scheme, "http") == 0 || (strcmp(scheme, "ftp") == 0 && proxyname))) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: HTTP: declining URL %s", url);
        return DECLINED; /* only interested in HTTP, or FTP via proxy */
    }
    else {
        if (*scheme == 'h')
            proxy_function = "HTTP";
        else
            proxy_function = "FTP";
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
        if ((status = ap_proxy_acquire_connection(proxy_function, &backend,
                                                  worker, r->server)) != OK)
            goto cleanup;

        if (!r->main) {
            ap_set_module_config(c->conn_config, &proxy_http_module, backend);
        }
    }

    backend->is_ssl = is_ssl;
    backend->close_on_recycle = 1;

    /* Step One: Determine Who To Connect To */
    if ((status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                                uri, &url, proxyname,
                                                proxyport, server_portstr,
                                                sizeof(server_portstr))) != OK)
        goto cleanup;

    /* Step Two: Make the Connection */
    if (ap_proxy_connect_backend(proxy_function, backend, worker, r->server)) {
        if (r->proxyreq == PROXYREQ_PROXY)
            status = HTTP_NOT_FOUND;
        else
            status = HTTP_SERVICE_UNAVAILABLE;
        goto cleanup;
    }

    /* Step Three: Create conn_rec */
    if (!backend->connection) {
        if ((status = ap_proxy_connection_create(proxy_function, backend,
                                                 c, r->server)) != OK)
            goto cleanup;
    }
   
    /* Step Four: Send the Request */
    if ((status = ap_proxy_http_request(p, r, backend, backend->connection,
                                        conf, uri, url, server_portstr)) != OK)
        goto cleanup;

    /* Step Five: Receive the Response */
    if ((status = ap_proxy_http_process_response(p, r, backend,
                                                 backend->connection,
                                                 conf, server_portstr)) != OK)
        goto cleanup;

    /* Step Six: Clean Up */

cleanup:
    if (backend) {
        if (status != OK) {
            backend->close = 1;
            backend->close_on_recycle = 1;
        }
        ap_proxy_http_cleanup(proxy_function, r, backend);
    }
    return status;
}

static void ap_proxy_http_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_http_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_http_canon, NULL, NULL, APR_HOOK_FIRST);
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

