/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_proxy.h"
#include "util_fcgi.h"
#include "util_script.h"
#include "ap_expr.h"

module AP_MODULE_DECLARE_DATA proxy_fcgi_module;

typedef struct {
    ap_expr_info_t *cond;
    ap_expr_info_t *subst;
    const char *envname;
} sei_entry;

typedef struct {
    int need_dirwalk;
} fcgi_req_config_t;

/* We will assume FPM, but still differentiate */
typedef enum {
    BACKEND_DEFAULT_UNKNOWN = 0,
    BACKEND_FPM,
    BACKEND_GENERIC,
} fcgi_backend_t;


#define FCGI_MAY_BE_FPM(dconf)                              \
        (dconf &&                                           \
        ((dconf->backend_type == BACKEND_DEFAULT_UNKNOWN) || \
        (dconf->backend_type == BACKEND_FPM)))

typedef struct {
    fcgi_backend_t backend_type;
    apr_array_header_t *env_fixups;
} fcgi_dirconf_t;

/*
 * Canonicalise http-like URLs.
 * scheme is the scheme for the URL
 * url is the URL starting with the first '/'
 * def_port is the default port for this scheme.
 */
static int proxy_fcgi_canon(request_rec *r, char *url)
{
    char *host, sport[7];
    const char *err;
    char *path;
    apr_port_t port, def_port;
    fcgi_req_config_t *rconf = NULL;
    const char *pathinfo_type = NULL;

    if (ap_cstr_casecmpn(url, "fcgi:", 5) == 0) {
        url += 5;
    }
    else {
        return DECLINED;
    }

    port = def_port = ap_proxy_port_of_scheme("fcgi");

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                 "canonicalising URL %s", url);
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01059)
                      "error parsing URL %s: %s", url, err);
        return HTTP_BAD_REQUEST;
    }

    if (port != def_port)
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    else
        sport[0] = '\0';

    if (ap_strchr_c(host, ':')) {
        /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }

    if (apr_table_get(r->notes, "proxy-nocanon")
        || apr_table_get(r->notes, "proxy-noencode")) {
        path = url;   /* this is the raw/encoded path */
    }
    else {
        core_dir_config *d = ap_get_core_module_config(r->per_dir_config);
        int flags = d->allow_encoded_slashes && !d->decode_encoded_slashes ? PROXY_CANONENC_NOENCODEDSLASHENCODING : 0;

        path = ap_proxy_canonenc_ex(r->pool, url, strlen(url), enc_path, flags,
                                    r->proxyreq);
        if (!path) {
            return HTTP_BAD_REQUEST;
        }
    }
    /*
     * If we have a raw control character or a ' ' in nocanon path,
     * correct encoding was missed.
     */
    if (path == url && *ap_scan_vchar_obstext(path)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10414)
                      "To be forwarded path contains control "
                      "characters or spaces");
        return HTTP_FORBIDDEN;
    }

    r->filename = apr_pstrcat(r->pool, "proxy:fcgi://", host, sport, "/",
                              path, NULL);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01060)
                  "set r->filename to %s", r->filename);

    rconf = ap_get_module_config(r->request_config, &proxy_fcgi_module);
    if (rconf == NULL) {
        rconf = apr_pcalloc(r->pool, sizeof(fcgi_req_config_t));
        ap_set_module_config(r->request_config, &proxy_fcgi_module, rconf);
    }

    if (NULL != (pathinfo_type = apr_table_get(r->subprocess_env, "proxy-fcgi-pathinfo"))) {
        /* It has to be on disk for this to work */
        if (!strcasecmp(pathinfo_type, "full")) {
            rconf->need_dirwalk = 1;
            ap_unescape_url_keep2f(path, 0);
        }
        else if (!strcasecmp(pathinfo_type, "first-dot")) {
            char *split = ap_strchr(path, '.');
            if (split) {
                char *slash = ap_strchr(split, '/');
                if (slash) {
                    r->path_info = apr_pstrdup(r->pool, slash);
                    ap_unescape_url_keep2f(r->path_info, 0);
                    *slash = '\0'; /* truncate path */
                }
            }
        }
        else if (!strcasecmp(pathinfo_type, "last-dot")) {
            char *split = ap_strrchr(path, '.');
            if (split) {
                char *slash = ap_strchr(split, '/');
                if (slash) {
                    r->path_info = apr_pstrdup(r->pool, slash);
                    ap_unescape_url_keep2f(r->path_info, 0);
                    *slash = '\0'; /* truncate path */
                }
            }
        }
        else {
            /* before proxy-fcgi-pathinfo had multi-values. This requires the
             * the FCGI server to fixup PATH_INFO because it's the entire path
             */
            r->path_info = apr_pstrcat(r->pool, "/", path, NULL);
            if (!strcasecmp(pathinfo_type, "unescape")) {
                ap_unescape_url_keep2f(r->path_info, 0);
            }
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01061)
                    "set r->path_info to %s", r->path_info);
        }
    }

    return OK;
}


/*
  ProxyFCGISetEnvIf "reqenv('PATH_INFO') =~ m#/foo(\d+)\.php$#" COVENV1 "$1"
  ProxyFCGISetEnvIf "reqenv('PATH_INFO') =~ m#/foo(\d+)\.php$#" PATH_INFO "/foo.php"
  ProxyFCGISetEnvIf "reqenv('PATH_TRANSLATED') =~ m#(/.*foo)(\d+)(.*)#" PATH_TRANSLATED "$1$3"
*/
static apr_status_t fix_cgivars(request_rec *r, fcgi_dirconf_t *dconf)
{
    sei_entry *entries;
    const char *err, *src;
    int i = 0, rc = 0;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];

    entries = (sei_entry *) dconf->env_fixups->elts;
    for (i = 0; i < dconf->env_fixups->nelts; i++) {
        sei_entry *entry = &entries[i];

        rc = ap_expr_exec_re(r, entry->cond, AP_MAX_REG_MATCH, regm, &src, &err);
        if (rc < 0) { 
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10241) 
                          "fix_cgivars: Condition eval returned %d: %s", 
                          rc, err);
            return APR_EGENERAL;
        }
        else if (rc == 0) { 
            continue; /* evaluated false */
        }

        if (entry->envname[0] == '!') {
            apr_table_unset(r->subprocess_env, entry->envname+1);
        }
        else {
            const char *val = ap_expr_str_exec_re(r, entry->subst, AP_MAX_REG_MATCH, regm, &src, &err);
            if (err) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(03514)
                              "Error evaluating expression for replacement of %s: '%s'",
                               entry->envname, err);
                continue;
            }
            if (APLOGrtrace4(r)) {
                const char *oldval = apr_table_get(r->subprocess_env, entry->envname);
                ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                              "fix_cgivars: override %s from '%s' to '%s'",
                              entry->envname, oldval, val);

            }
            apr_table_setn(r->subprocess_env, entry->envname, val);
        }
    }
    return APR_SUCCESS;
}

/* Wrapper for apr_socket_sendv that handles updating the worker stats. */
static apr_status_t send_data(proxy_conn_rec *conn,
                              struct iovec *vec,
                              int nvec,
                              apr_size_t *len)
{
    apr_status_t rv = APR_SUCCESS;
    apr_size_t written = 0, to_write = 0;
    int i, offset;
    apr_socket_t *s = conn->sock;

    for (i = 0; i < nvec; i++) {
        to_write += vec[i].iov_len;
    }

    offset = 0;
    while (to_write) {
        apr_size_t n = 0;
        rv = apr_socket_sendv(s, vec + offset, nvec - offset, &n);
        if (rv != APR_SUCCESS) {
            break;
        }
        if (n > 0) {
            written += n;
            if (written >= to_write)
                break;                 /* short circuit out */
            for (i = offset; i < nvec; ) {
                if (n >= vec[i].iov_len) {
                    offset++;
                    n -= vec[i++].iov_len;
                } else {
                    vec[i].iov_len -= n;
                    vec[i].iov_base = (char *) vec[i].iov_base + n;
                    break;
                }
            }
        }
    }

    conn->worker->s->transferred += written;
    *len = written;

    return rv;
}

/* Wrapper for apr_socket_recv that handles updating the worker stats. */
static apr_status_t get_data(proxy_conn_rec *conn,
                             char *buffer,
                             apr_size_t *buflen)
{
    apr_status_t rv = apr_socket_recv(conn->sock, buffer, buflen);

    if (rv == APR_SUCCESS) {
        conn->worker->s->read += *buflen;
    }

    return rv;
}

static apr_status_t get_data_full(proxy_conn_rec *conn,
                                  char *buffer,
                                  apr_size_t buflen)
{
    apr_size_t readlen;
    apr_size_t cumulative_len = 0;
    apr_status_t rv;

    do {
        readlen = buflen - cumulative_len;
        rv = get_data(conn, buffer + cumulative_len, &readlen);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        cumulative_len += readlen;
    } while (cumulative_len < buflen);

    return APR_SUCCESS;
}

static apr_status_t send_begin_request(proxy_conn_rec *conn,
                                       apr_uint16_t request_id)
{
    struct iovec vec[2];
    ap_fcgi_header header;
    unsigned char farray[AP_FCGI_HEADER_LEN];
    ap_fcgi_begin_request_body brb;
    unsigned char abrb[AP_FCGI_HEADER_LEN];
    apr_size_t len;

    ap_fcgi_fill_in_header(&header, AP_FCGI_BEGIN_REQUEST, request_id,
                           sizeof(abrb), 0);

    ap_fcgi_fill_in_request_body(&brb, AP_FCGI_RESPONDER,
                                 ap_proxy_connection_reusable(conn)
                                     ? AP_FCGI_KEEP_CONN : 0);

    ap_fcgi_header_to_array(&header, farray);
    ap_fcgi_begin_request_body_to_array(&brb, abrb);

    vec[0].iov_base = (void *)farray;
    vec[0].iov_len = sizeof(farray);
    vec[1].iov_base = (void *)abrb;
    vec[1].iov_len = sizeof(abrb);

    return send_data(conn, vec, 2, &len);
}

static apr_status_t send_environment(proxy_conn_rec *conn, request_rec *r,
                                     apr_pool_t *temp_pool,
                                     apr_uint16_t request_id)
{
    const apr_array_header_t *envarr;
    const apr_table_entry_t *elts;
    struct iovec vec[2];
    ap_fcgi_header header;
    unsigned char farray[AP_FCGI_HEADER_LEN];
    char *body;
    apr_status_t rv;
    apr_size_t avail_len, len, required_len;
    int next_elem, starting_elem;
    fcgi_req_config_t *rconf = ap_get_module_config(r->request_config, &proxy_fcgi_module);
    fcgi_dirconf_t *dconf = ap_get_module_config(r->per_dir_config, &proxy_fcgi_module);

    if (rconf) {
       if (rconf->need_dirwalk) {
          ap_directory_walk(r);
       }
    }

    /* Strip proxy: prefixes */
    if (r->filename) {
        char *newfname = NULL;

        if (!strncmp(r->filename, "proxy:balancer://", 17)) {
            newfname = apr_pstrdup(r->pool, r->filename+17);
        }

        if (!FCGI_MAY_BE_FPM(dconf))  {
            if (!strncmp(r->filename, "proxy:fcgi://", 13)) {
                /* If we strip this under FPM, and any internal redirect occurs
                 * on PATH_INFO, FPM may use PATH_TRANSLATED instead of
                 * SCRIPT_FILENAME (a la mod_fastcgi + Action).
                 */
                newfname = apr_pstrdup(r->pool, r->filename+13);
            }
            /* Query string in environment only */
            if (newfname && r->args && *r->args) {
                char *qs = strrchr(newfname, '?');
                if (qs && !strcmp(qs+1, r->args)) {
                    *qs = '\0';
                }
            }
        }

        if (newfname) {
            newfname = ap_strchr(newfname, '/');
            r->filename = newfname;
        }
    }

    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    /* XXX are there any FastCGI specific env vars we need to send? */

    /* Give admins final option to fine-tune env vars */
    if (APR_SUCCESS != (rv = fix_cgivars(r, dconf))) { 
        return rv;
    }

    /* XXX mod_cgi/mod_cgid use ap_create_environment here, which fills in
     *     the TZ value specially.  We could use that, but it would mean
     *     parsing the key/value pairs back OUT of the allocated env array,
     *     not to mention allocating a totally useless array in the first
     *     place, which would suck. */

    envarr = apr_table_elts(r->subprocess_env);
    elts = (const apr_table_entry_t *) envarr->elts;

    if (APLOGrtrace8(r)) {
        int i;

        for (i = 0; i < envarr->nelts; ++i) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, APLOGNO(01062)
                          "sending env var '%s' value '%s'",
                          elts[i].key, elts[i].val);
        }
    }

    /* Send envvars over in as many FastCGI records as it takes, */
    next_elem = 0; /* starting with the first one */

    avail_len = 16 * 1024; /* our limit per record, which could have been up
                            * to AP_FCGI_MAX_CONTENT_LEN
                            */

    while (next_elem < envarr->nelts) {
        starting_elem = next_elem;
        required_len = ap_fcgi_encoded_env_len(r->subprocess_env,
                                               avail_len,
                                               &next_elem);

        if (!required_len) {
            if (next_elem < envarr->nelts) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              APLOGNO(02536) "couldn't encode envvar '%s' in %"
                              APR_SIZE_T_FMT " bytes",
                              elts[next_elem].key, avail_len);
                /* skip this envvar and continue */
                ++next_elem;
                continue;
            }
            /* only an unused element at the end of the array */
            break;
        }

        body = apr_palloc(temp_pool, required_len);
        rv = ap_fcgi_encode_env(r, r->subprocess_env, body, required_len,
                                &starting_elem);
        /* we pre-compute, so we can't run out of space */
        ap_assert(rv == APR_SUCCESS);
        /* compute and encode must be in sync */
        ap_assert(starting_elem == next_elem);

        ap_fcgi_fill_in_header(&header, AP_FCGI_PARAMS, request_id,
                               (apr_uint16_t)required_len, 0);
        ap_fcgi_header_to_array(&header, farray);

        vec[0].iov_base = (void *)farray;
        vec[0].iov_len = sizeof(farray);
        vec[1].iov_base = body;
        vec[1].iov_len = required_len;

        rv = send_data(conn, vec, 2, &len);
        apr_pool_clear(temp_pool);

        if (rv) {
            return rv;
        }
    }

    /* Envvars sent, so say we're done */
    ap_fcgi_fill_in_header(&header, AP_FCGI_PARAMS, request_id, 0, 0);
    ap_fcgi_header_to_array(&header, farray);

    vec[0].iov_base = (void *)farray;
    vec[0].iov_len = sizeof(farray);

    return send_data(conn, vec, 1, &len);
}

enum {
  HDR_STATE_READING_HEADERS,
  HDR_STATE_GOT_CR,
  HDR_STATE_GOT_CRLF,
  HDR_STATE_GOT_CRLFCR,
  HDR_STATE_GOT_LF,
  HDR_STATE_DONE_WITH_HEADERS
};

/* Try to find the end of the script headers in the response from the back
 * end fastcgi server. STATE holds the current header parsing state for this
 * request.
 *
 * Returns 0 if it can't find the end of the headers, and 1 if it found the
 * end of the headers. */
static int handle_headers(request_rec *r, int *state,
                          const char *readbuf, apr_size_t readlen)
{
    const char *itr = readbuf;

    while (readlen--) {
        if (*itr == '\r') {
            switch (*state) {
                case HDR_STATE_GOT_CRLF:
                    *state = HDR_STATE_GOT_CRLFCR;
                    break;

                default:
                    *state = HDR_STATE_GOT_CR;
                    break;
            }
        }
        else if (*itr == '\n') {
            switch (*state) {
                 case HDR_STATE_GOT_LF:
                     *state = HDR_STATE_DONE_WITH_HEADERS;
                     break;

                 case HDR_STATE_GOT_CR:
                     *state = HDR_STATE_GOT_CRLF;
                     break;

                 case HDR_STATE_GOT_CRLFCR:
                     *state = HDR_STATE_DONE_WITH_HEADERS;
                     break;

                 default:
                     *state = HDR_STATE_GOT_LF;
                     break;
            }
        }
        else {
            *state = HDR_STATE_READING_HEADERS;
        }

        if (*state == HDR_STATE_DONE_WITH_HEADERS)
            break;

        ++itr;
    }

    if (*state == HDR_STATE_DONE_WITH_HEADERS) {
        return 1;
    }

    return 0;
}

static apr_status_t dispatch(proxy_conn_rec *conn, proxy_dir_conf *conf,
                             request_rec *r, apr_pool_t *setaside_pool,
                             apr_uint16_t request_id, const char **err,
                             int *bad_request, int *has_responded,
                             apr_bucket_brigade *input_brigade)
{
    apr_bucket_brigade *ib, *ob;
    int seen_end_of_headers = 0, done = 0, ignore_body = 0;
    apr_status_t rv = APR_SUCCESS;
    int script_error_status = HTTP_OK;
    conn_rec *c = r->connection;
    struct iovec vec[2];
    ap_fcgi_header header;
    unsigned char farray[AP_FCGI_HEADER_LEN];
    apr_pollfd_t pfd;
    apr_pollfd_t *flushpoll = NULL;
    apr_int32_t flushpoll_fd;
    int header_state = HDR_STATE_READING_HEADERS;
    char stack_iobuf[AP_IOBUFSIZE];
    apr_size_t iobuf_size = AP_IOBUFSIZE;
    char *iobuf = stack_iobuf;

    *err = NULL;
    if (conn->worker->s->io_buffer_size_set) {
        iobuf_size = conn->worker->s->io_buffer_size;
        iobuf = apr_palloc(r->pool, iobuf_size);
    }

    pfd.desc_type = APR_POLL_SOCKET;
    pfd.desc.s = conn->sock;
    pfd.p = r->pool;
    pfd.reqevents = APR_POLLIN | APR_POLLOUT;

    if (conn->worker->s->flush_packets == flush_auto) {
        flushpoll = apr_pcalloc(r->pool, sizeof(apr_pollfd_t));
        flushpoll->reqevents = APR_POLLIN;
        flushpoll->desc_type = APR_POLL_SOCKET;
        flushpoll->desc.s = conn->sock;
    }

    ib = apr_brigade_create(r->pool, c->bucket_alloc);
    ob = apr_brigade_create(r->pool, c->bucket_alloc);

    while (! done) {
        apr_interval_time_t timeout;
        apr_size_t len;
        int n;

        /* We need SOME kind of timeout here, or virtually anything will
         * cause timeout errors. */
        apr_socket_timeout_get(conn->sock, &timeout);

        rv = apr_poll(&pfd, 1, &n, timeout);
        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_EINTR(rv)) {
                continue;
            }
            *err = "polling";
            break;
        }

        if (pfd.rtnevents & APR_POLLOUT) {
            apr_size_t to_send, writebuflen;
            int last_stdin = 0;
            char *iobuf_cursor;

            if (APR_BRIGADE_EMPTY(input_brigade)) {
                rv = ap_get_brigade(r->input_filters, ib,
                                    AP_MODE_READBYTES, APR_BLOCK_READ,
                                    iobuf_size);
            }
            else {
                apr_bucket *e;
                APR_BRIGADE_CONCAT(ib, input_brigade);
                rv = apr_brigade_partition(ib, iobuf_size, &e);
                if (rv == APR_SUCCESS) {
                    while (e != APR_BRIGADE_SENTINEL(ib)
                           && APR_BUCKET_IS_METADATA(e)) {
                        e = APR_BUCKET_NEXT(e);
                    }
                    apr_brigade_split_ex(ib, e, input_brigade);
                }
                else if (rv == APR_INCOMPLETE) {
                    rv = APR_SUCCESS;
                }
            }
            if (rv != APR_SUCCESS) {
                *err = "reading input brigade";
                *bad_request = 1;
                break;
            }

            if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(ib))) {
                last_stdin = 1;
            }

            writebuflen = iobuf_size;

            rv = apr_brigade_flatten(ib, iobuf, &writebuflen);

            apr_brigade_cleanup(ib);

            if (rv != APR_SUCCESS) {
                *err = "flattening brigade";
                break;
            }

            to_send = writebuflen;
            iobuf_cursor = iobuf;
            while (to_send > 0) {
                int nvec = 0;
                apr_size_t write_this_time;

                write_this_time =
                    to_send < AP_FCGI_MAX_CONTENT_LEN ? to_send : AP_FCGI_MAX_CONTENT_LEN;

                ap_fcgi_fill_in_header(&header, AP_FCGI_STDIN, request_id,
                                       (apr_uint16_t)write_this_time, 0);
                ap_fcgi_header_to_array(&header, farray);

                vec[nvec].iov_base = (void *)farray;
                vec[nvec].iov_len = sizeof(farray);
                ++nvec;
                if (writebuflen) {
                    vec[nvec].iov_base = iobuf_cursor;
                    vec[nvec].iov_len = write_this_time;
                    ++nvec;
                }

                rv = send_data(conn, vec, nvec, &len);
                if (rv != APR_SUCCESS) {
                    *err = "sending stdin";
                    break;
                }

                to_send -= write_this_time;
                iobuf_cursor += write_this_time;
            }
            if (rv != APR_SUCCESS) {
                break;
            }

            if (last_stdin) {
                pfd.reqevents = APR_POLLIN; /* Done with input data */

                /* signal EOF (empty FCGI_STDIN) */
                ap_fcgi_fill_in_header(&header, AP_FCGI_STDIN, request_id,
                                       0, 0);
                ap_fcgi_header_to_array(&header, farray);

                vec[0].iov_base = (void *)farray;
                vec[0].iov_len = sizeof(farray);

                rv = send_data(conn, vec, 1, &len);
                if (rv != APR_SUCCESS) {
                    *err = "sending empty stdin";
                    break;
                }
            }
        }

        if (pfd.rtnevents & APR_POLLIN) {
            apr_size_t readbuflen;
            apr_uint16_t clen, rid;
            apr_bucket *b;
            unsigned char plen;
            unsigned char type, version;
            int mayflush = 0;

            /* First, we grab the header... */
            rv = get_data_full(conn, (char *) farray, AP_FCGI_HEADER_LEN);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01067)
                              "Failed to read FastCGI header");
                break;
            }

            ap_log_rdata(APLOG_MARK, APLOG_TRACE8, r, "FastCGI header",
                         farray, AP_FCGI_HEADER_LEN, 0);

            ap_fcgi_header_fields_from_array(&version, &type, &rid,
                                             &clen, &plen, farray);

            if (version != AP_FCGI_VERSION_1) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01068)
                              "Got bogus version %d", (int)version);
                rv = APR_EINVAL;
                break;
            }

            if (rid != request_id) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01069)
                              "Got bogus rid %d, expected %d",
                              rid, request_id);
                rv = APR_EINVAL;
                break;
            }

recv_again:
            if (clen > iobuf_size) {
                readbuflen = iobuf_size;
            } else {
                readbuflen = clen;
            }

            /* Now get the actual data.  Yes it sucks to do this in a second
             * recv call, this will eventually change when we move to real
             * nonblocking recv calls. */
            if (readbuflen != 0) {
                rv = get_data(conn, iobuf, &readbuflen);
                if (rv != APR_SUCCESS) {
                    *err = "reading response body";
                    break;
                }
            }

            switch (type) {
            case AP_FCGI_STDOUT:
                if (clen != 0) {
                    b = apr_bucket_transient_create(iobuf,
                                                    readbuflen,
                                                    c->bucket_alloc);

                    APR_BRIGADE_INSERT_TAIL(ob, b);

                    if (! seen_end_of_headers) {
                        int st = handle_headers(r, &header_state,
                                                iobuf, readbuflen);

                        if (st == 1) {
                            int status;
                            seen_end_of_headers = 1;

                            status = ap_scan_script_header_err_brigade_ex(r, ob,
                                NULL, APLOG_MODULE_INDEX);
                            /* suck in all the rest */
                            if (status != OK) {
                                apr_bucket *tmp_b;
                                apr_brigade_cleanup(ob);
                                tmp_b = apr_bucket_eos_create(c->bucket_alloc);
                                APR_BRIGADE_INSERT_TAIL(ob, tmp_b);

                                *has_responded = 1;
                                r->status = status;
                                rv = ap_pass_brigade(r->output_filters, ob);
                                if (rv != APR_SUCCESS) {
                                    *err = "passing headers brigade to output filters";
                                    break;
                                }
                                else if (status == HTTP_NOT_MODIFIED
                                         || status == HTTP_PRECONDITION_FAILED) {
                                    /* Special 'status' cases handled:
                                     * 1) HTTP 304 response MUST NOT contain
                                     *    a message-body, ignore it.
                                     * 2) HTTP 412 response.
                                     * The break is not added since there might
                                     * be more bytes to read from the FCGI
                                     * connection. Even if the message-body is
                                     * ignored (and the EOS bucket has already
                                     * been sent) we want to avoid subsequent
                                     * bogus reads. */
                                    ignore_body = 1;
                                }
                                else {
                                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01070)
                                                    "Error parsing script headers");
                                    rv = APR_EINVAL;
                                    break;
                                }
                            }

                            if (ap_proxy_should_override(conf, r->status) && ap_is_initial_req(r)) {
                                /*
                                 * set script_error_status to discard
                                 * everything after the headers
                                 */
                                script_error_status = r->status;
                                /*
                                 * prevent ap_die() from treating this as a
                                 * recursive error, initially:
                                 */
                                r->status = HTTP_OK;
                            }

                            if (script_error_status == HTTP_OK
                                && !APR_BRIGADE_EMPTY(ob) && !ignore_body) {
                                /* Send the part of the body that we read while
                                 * reading the headers.
                                 */
                                *has_responded = 1;
                                rv = ap_pass_brigade(r->output_filters, ob);
                                if (rv != APR_SUCCESS) {
                                    *err = "passing brigade to output filters";
                                    break;
                                }
                                mayflush = 1;
                            }
                            apr_brigade_cleanup(ob);

                            apr_pool_clear(setaside_pool);
                        }
                        else {
                            /* We're still looking for the end of the
                             * headers, so this part of the data will need
                             * to persist. */
                            apr_bucket_setaside(b, setaside_pool);
                        }
                    } else {
                        /* we've already passed along the headers, so now pass
                         * through the content.  we could simply continue to
                         * setaside the content and not pass until we see the
                         * 0 content-length (below, where we append the EOS),
                         * but that could be a huge amount of data; so we pass
                         * along smaller chunks
                         */
                        if (script_error_status == HTTP_OK && !ignore_body) {
                            *has_responded = 1;
                            rv = ap_pass_brigade(r->output_filters, ob);
                            if (rv != APR_SUCCESS) {
                                *err = "passing brigade to output filters";
                                break;
                            }
                            mayflush = 1;
                        }
                        apr_brigade_cleanup(ob);
                    }

                    /* If we didn't read all the data, go back and get the
                     * rest of it. */
                    if (clen > readbuflen) {
                        clen -= readbuflen;
                        goto recv_again;
                    }
                } else {
                    /* XXX what if we haven't seen end of the headers yet? */

                    if (script_error_status == HTTP_OK) {
                        b = apr_bucket_eos_create(c->bucket_alloc);
                        APR_BRIGADE_INSERT_TAIL(ob, b);

                        *has_responded = 1;
                        rv = ap_pass_brigade(r->output_filters, ob);
                        if (rv != APR_SUCCESS) {
                            *err = "passing brigade to output filters";
                            break;
                        }
                    }

                    /* XXX Why don't we cleanup here?  (logic from AJP) */
                }
                break;

            case AP_FCGI_STDERR:
                /* TODO: Should probably clean up this logging a bit... */
                if (clen) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01071)
                                  "Got error '%.*s'", (int)readbuflen, iobuf);
                }

                if (clen > readbuflen) {
                    clen -= readbuflen;
                    goto recv_again;
                }
                break;

            case AP_FCGI_END_REQUEST:
                done = 1;
                break;

            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01072)
                              "Got bogus record %d", type);
                break;
            }
            /* Leave on above switch's inner error. */
            if (rv != APR_SUCCESS) {
                break;
            }

            if (plen) {
                rv = get_data_full(conn, iobuf, plen);
                if (rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02537)
                                  "Error occurred reading padding");
                    break;
                }
            }

            if (mayflush && ((conn->worker->s->flush_packets == flush_on) ||
                             ((conn->worker->s->flush_packets == flush_auto) && 
                              (apr_poll(flushpoll, 1, &flushpoll_fd,
                               conn->worker->s->flush_wait) == APR_TIMEUP)))) {
                apr_bucket* flush_b = apr_bucket_flush_create(r->connection->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ob, flush_b);
                rv = ap_pass_brigade(r->output_filters, ob);
                if (rv != APR_SUCCESS) {
                    *err = "passing headers brigade to output filters";
                    break;
                }
                mayflush = 0;
            }
        }
    }

    apr_brigade_destroy(ib);
    apr_brigade_destroy(ob);

    if (script_error_status != HTTP_OK) {
        ap_die(script_error_status, r); /* send ErrorDocument */
        *has_responded = 1;
    }

    return rv;
}

/*
 * process the request and write the response.
 */
static int fcgi_do_request(apr_pool_t *p, request_rec *r,
                           proxy_conn_rec *conn,
                           conn_rec *origin,
                           proxy_dir_conf *conf,
                           apr_uri_t *uri,
                           char *url, char *server_portstr,
                           apr_bucket_brigade *input_brigade)
{
    /* Request IDs are arbitrary numbers that we assign to a
     * single request. This would allow multiplex/pipelining of
     * multiple requests to the same FastCGI connection, but
     * we don't support that, and always use a value of '1' to
     * keep things simple. */
    apr_uint16_t request_id = 1;
    apr_status_t rv;
    apr_pool_t *temp_pool;
    const char *err;
    int bad_request = 0,
        has_responded = 0;

    /* Step 1: Send AP_FCGI_BEGIN_REQUEST */
    rv = send_begin_request(conn, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01073)
                      "Failed Writing Request to %s:", server_portstr);
        conn->close = 1;
        return HTTP_SERVICE_UNAVAILABLE;
    }

    apr_pool_create(&temp_pool, r->pool);
    apr_pool_tag(temp_pool, "proxy_fcgi_do_request");

    /* Step 2: Send Environment via FCGI_PARAMS */
    rv = send_environment(conn, r, temp_pool, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01074)
                      "Failed writing Environment to %s:", server_portstr);
        conn->close = 1;
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* Step 3: Read records from the back end server and handle them. */
    rv = dispatch(conn, conf, r, temp_pool, request_id,
                  &err, &bad_request, &has_responded,
                  input_brigade);
    if (rv != APR_SUCCESS) {
        /* If the client aborted the connection during retrieval or (partially)
         * sending the response, don't return a HTTP_SERVICE_UNAVAILABLE, since
         * this is not a backend problem. */
        if (r->connection->aborted) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                          "The client aborted the connection.");
            conn->close = 1;
            return OK;
        }

        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01075)
                      "Error dispatching request to %s: %s%s%s",
                      server_portstr,
                      err ? "(" : "",
                      err ? err : "",
                      err ? ")" : "");
        conn->close = 1;
        if (has_responded) {
            return AP_FILTER_ERROR;
        }
        if (bad_request) {
            return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        }
        if (APR_STATUS_IS_TIMEUP(rv)) {
            return HTTP_GATEWAY_TIME_OUT;
        }
        return HTTP_SERVICE_UNAVAILABLE;
    }

    return OK;
}

#define FCGI_SCHEME "FCGI"

#define MAX_MEM_SPOOL 16384

/*
 * This handles fcgi:(dest) URLs
 */
static int proxy_fcgi_handler(request_rec *r, proxy_worker *worker,
                              proxy_server_conf *conf,
                              char *url, const char *proxyname,
                              apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    conn_rec *origin = NULL;
    proxy_conn_rec *backend = NULL;
    apr_bucket_brigade *input_brigade;
    apr_off_t input_bytes = 0;
    apr_uri_t *uri;

    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);

    apr_pool_t *p = r->pool;


    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01076)
                  "url: %s proxyname: %s proxyport: %d",
                  url, proxyname, proxyport);

    if (ap_cstr_casecmpn(url, "fcgi:", 5) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01077) "declining URL %s", url);
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01078) "serving URL %s", url);

    /* Create space for state information */
    status = ap_proxy_acquire_connection(FCGI_SCHEME, &backend, worker,
                                         r->server);
    if (status != OK) {
        if (backend) {
            backend->close = 1;
            ap_proxy_release_connection(FCGI_SCHEME, backend, r->server);
        }
        return status;
    }

    backend->is_ssl = 0;

    /* Step One: Determine Who To Connect To */
    uri = apr_palloc(p, sizeof(*uri));
    status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                           uri, &url, proxyname, proxyport,
                                           server_portstr,
                                           sizeof(server_portstr));
    if (status != OK) {
        goto cleanup;
    }

    /* We possibly reuse input data prefetched in previous call(s), e.g. for a
     * balancer fallback scenario.
     */
    apr_pool_userdata_get((void **)&input_brigade, "proxy-fcgi-input", p);
    if (input_brigade == NULL) {
        const char *old_te = apr_table_get(r->headers_in, "Transfer-Encoding");
        const char *old_cl = NULL;
        if (old_te) {
            apr_table_unset(r->headers_in, "Content-Length");
        }
        else {
            old_cl = apr_table_get(r->headers_in, "Content-Length");
        }

        input_brigade = apr_brigade_create(p, r->connection->bucket_alloc);
        apr_pool_userdata_setn(input_brigade, "proxy-fcgi-input", NULL, p);

        /* Prefetch (nonlocking) the request body so to increase the chance
         * to get the whole (or enough) body and determine Content-Length vs
         * chunked or spooled. By doing this before connecting or reusing the
         * backend, we want to minimize the delay between this connection is
         * considered alive and the first bytes sent (should the client's link
         * be slow or some input filter retain the data). This is a best effort
         * to prevent the backend from closing (from under us) what it thinks is
         * an idle connection, hence to reduce to the minimum the unavoidable
         * local is_socket_connected() vs remote keepalive race condition.
         */
        status = ap_proxy_prefetch_input(r, backend, input_brigade,
                                         APR_NONBLOCK_READ, &input_bytes,
                                         MAX_MEM_SPOOL);
        if (status != OK) {
            goto cleanup;
        }

        /*
         * The request body is streamed by default, using either C-L or
         * chunked T-E, like this:
         *
         *   The whole body (including no body) was received on prefetch, i.e.
         *   the input brigade ends with EOS => C-L = input_bytes.
         *
         *   C-L is known and reliable, i.e. only protocol filters in the input
         *   chain thus none should change the body => use C-L from client.
         *
         *   The administrator has not "proxy-sendcl" which prevents T-E => use
         *   T-E and chunks.
         *
         *   Otherwise we need to determine and set a content-length, so spool
         *   the entire request body to memory/temporary file (MAX_MEM_SPOOL),
         *   such that we finally know its length => C-L = input_bytes.
         */
        if (!APR_BRIGADE_EMPTY(input_brigade)
                && APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            /* The whole thing fit, so our decision is trivial, use the input
             * bytes for the Content-Length. If we expected no body, and read
             * no body, do not set the Content-Length.
             */
            if (old_cl || old_te || input_bytes) {
                apr_table_setn(r->headers_in, "Content-Length",
                               apr_off_t_toa(p, input_bytes));
                if (old_te) {
                    apr_table_unset(r->headers_in, "Transfer-Encoding");
                }
            }
        }
        else if (old_cl && r->input_filters == r->proto_input_filters) {
            /* Streaming is possible by preserving the existing C-L */
        }
        else if (!apr_table_get(r->subprocess_env, "proxy-sendcl")) {
            /* Streaming is possible using T-E: chunked */
        }
        else {
            /* No streaming, C-L is the only option so spool to memory/file */
            apr_bucket_brigade *tmp_bb;
            apr_off_t remaining_bytes = 0;

            AP_DEBUG_ASSERT(MAX_MEM_SPOOL >= input_bytes);
            tmp_bb = apr_brigade_create(p, r->connection->bucket_alloc);
            status = ap_proxy_spool_input(r, backend, tmp_bb, &remaining_bytes,
                                          MAX_MEM_SPOOL - input_bytes);
            if (status != OK) {
                goto cleanup;
            }

            APR_BRIGADE_CONCAT(input_brigade, tmp_bb);
            input_bytes += remaining_bytes;

            apr_table_setn(r->headers_in, "Content-Length",
                           apr_off_t_toa(p, input_bytes));
            if (old_te) {
                apr_table_unset(r->headers_in, "Transfer-Encoding");
            }
        }
    }

    /* This scheme handler does not reuse connections by default, to
     * avoid tying up a fastcgi that isn't expecting to work on
     * parallel requests.  But if the user went out of their way to
     * type the default value of disablereuse=off, we'll allow it.
     */
    backend->close = 1;
    if (worker->s->disablereuse_set && !worker->s->disablereuse) {
        backend->close = 0;
    }

    /* Step Two: Make the Connection */
    if (ap_proxy_check_connection(FCGI_SCHEME, backend, r->server, 0,
                                  PROXY_CHECK_CONN_EMPTY)
            && ap_proxy_connect_backend(FCGI_SCHEME, backend, worker,
                                        r->server)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01079)
                      "failed to make connection to backend: %s",
                      backend->hostname);
        status = HTTP_SERVICE_UNAVAILABLE;
        goto cleanup;
    }

    /* Step Three: Process the Request */
    status = fcgi_do_request(p, r, backend, origin, dconf, uri, url,
                             server_portstr, input_brigade);

cleanup:
    ap_proxy_release_connection(FCGI_SCHEME, backend, r->server);
    return status;
}

static void *fcgi_create_dconf(apr_pool_t *p, char *path)
{
    fcgi_dirconf_t *a;

    a = (fcgi_dirconf_t *)apr_pcalloc(p, sizeof(fcgi_dirconf_t));
    a->backend_type = BACKEND_DEFAULT_UNKNOWN;
    a->env_fixups = apr_array_make(p, 20, sizeof(sei_entry));

    return a;
}

static void *fcgi_merge_dconf(apr_pool_t *p, void *basev, void *overridesv)
{
    fcgi_dirconf_t *a, *base, *over;

    a     = (fcgi_dirconf_t *)apr_pcalloc(p, sizeof(fcgi_dirconf_t));
    base  = (fcgi_dirconf_t *)basev;
    over  = (fcgi_dirconf_t *)overridesv;

    a->backend_type = (over->backend_type != BACKEND_DEFAULT_UNKNOWN)
                      ? over->backend_type
                      : base->backend_type;
    a->env_fixups = apr_array_append(p, base->env_fixups, over->env_fixups);
    return a;
}

static const char *cmd_servertype(cmd_parms *cmd, void *in_dconf,
                                   const char *val)
{
    fcgi_dirconf_t *dconf = in_dconf;

    if (!strcasecmp(val, "GENERIC")) {
       dconf->backend_type = BACKEND_GENERIC;
    }
    else if (!strcasecmp(val, "FPM")) {
       dconf->backend_type = BACKEND_FPM;
    }
    else {
        return "ProxyFCGIBackendType requires one of the following arguments: "
               "'GENERIC', 'FPM'";
    }

    return NULL;
}


static const char *cmd_setenv(cmd_parms *cmd, void *in_dconf,
                              const char *arg1, const char *arg2,
                              const char *arg3)
{
    fcgi_dirconf_t *dconf = in_dconf;
    const char *err;
    sei_entry *new;
    const char *envvar = arg2;

    new = apr_array_push(dconf->env_fixups);
    new->cond = ap_expr_parse_cmd(cmd, arg1, 0, &err, NULL);
    if (err) {
        return apr_psprintf(cmd->pool, "Could not parse expression \"%s\": %s",
                            arg1, err);
    }

    if (envvar[0] == '!') {
        /* Unset mode. */
        if (arg3) {
            return apr_psprintf(cmd->pool, "Third argument (\"%s\") is not "
                                "allowed when using ProxyFCGISetEnvIf's unset "
                                "mode (%s)", arg3, envvar);
        }
        else if (!envvar[1]) {
            /* i.e. someone tried to give us a name of just "!" */
            return "ProxyFCGISetEnvIf: \"!\" is not a valid variable name";
        }

        new->subst = NULL;
    }
    else {
        /* Set mode. */
        if (!arg3) {
            /* A missing expr-value should be treated as empty. */
            arg3 = "";
        }

        new->subst = ap_expr_parse_cmd(cmd, arg3, AP_EXPR_FLAG_STRING_RESULT, &err, NULL);
        if (err) {
            return apr_psprintf(cmd->pool, "Could not parse expression \"%s\": %s",
                                arg3, err);
        }
    }

    new->envname = envvar;

    return NULL;
}
static void register_hooks(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_fcgi_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_fcgi_canon, NULL, NULL, APR_HOOK_FIRST);
}

static const command_rec command_table[] = {
    AP_INIT_TAKE1("ProxyFCGIBackendType", cmd_servertype, NULL, OR_FILEINFO,
                  "Specify the type of FastCGI server: 'Generic', 'FPM'"),
    AP_INIT_TAKE23("ProxyFCGISetEnvIf", cmd_setenv, NULL, OR_FILEINFO,
                  "expr-condition env-name expr-value"),
    { NULL }
};

AP_DECLARE_MODULE(proxy_fcgi) = {
    STANDARD20_MODULE_STUFF,
    fcgi_create_dconf,          /* create per-directory config structure */
    fcgi_merge_dconf,           /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    command_table,              /* command apr_table_t */
    register_hooks              /* register hooks */
};
