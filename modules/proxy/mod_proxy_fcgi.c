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
#include "fcgi_protocol.h"
#include "util_script.h"

module AP_MODULE_DECLARE_DATA proxy_fcgi_module;

/*
 * The below 3 functions serve to map the FCGI structs
 * back and forth between an 8 byte array. We do this to avoid
 * any potential padding issues when we send or read these
 * structures.
 *
 * NOTE: These have specific internal knowledge of the
 *       layout of the fcgi_header and fcgi_begin_request_body
 *       structs!
 */
static void fcgi_header_to_array(fcgi_header *h, unsigned char a[])
{
    a[FCGI_HDR_VERSION_OFFSET]        = h->version;
    a[FCGI_HDR_TYPE_OFFSET]           = h->type;
    a[FCGI_HDR_REQUEST_ID_B1_OFFSET]  = h->requestIdB1;
    a[FCGI_HDR_REQUEST_ID_B0_OFFSET]  = h->requestIdB0;
    a[FCGI_HDR_CONTENT_LEN_B1_OFFSET] = h->contentLengthB1;
    a[FCGI_HDR_CONTENT_LEN_B0_OFFSET] = h->contentLengthB0;
    a[FCGI_HDR_PADDING_LEN_OFFSET]    = h->paddingLength;
    a[FCGI_HDR_RESERVED_OFFSET]       = h->reserved;
}

static void fcgi_header_from_array(fcgi_header *h, unsigned char a[])
{
    h->version         = a[FCGI_HDR_VERSION_OFFSET];
    h->type            = a[FCGI_HDR_TYPE_OFFSET];
    h->requestIdB1     = a[FCGI_HDR_REQUEST_ID_B1_OFFSET];
    h->requestIdB0     = a[FCGI_HDR_REQUEST_ID_B0_OFFSET];
    h->contentLengthB1 = a[FCGI_HDR_CONTENT_LEN_B1_OFFSET];
    h->contentLengthB0 = a[FCGI_HDR_CONTENT_LEN_B0_OFFSET];
    h->paddingLength   = a[FCGI_HDR_PADDING_LEN_OFFSET];
    h->reserved        = a[FCGI_HDR_RESERVED_OFFSET];
}

static void fcgi_begin_request_body_to_array(fcgi_begin_request_body *h,
                                             unsigned char a[])
{
    a[FCGI_BRB_ROLEB1_OFFSET]    = h->roleB1;
    a[FCGI_BRB_ROLEB0_OFFSET]    = h->roleB0;
    a[FCGI_BRB_FLAGS_OFFSET]     = h->flags;
    a[FCGI_BRB_RESERVED0_OFFSET] = h->reserved[0];
    a[FCGI_BRB_RESERVED1_OFFSET] = h->reserved[1];
    a[FCGI_BRB_RESERVED2_OFFSET] = h->reserved[2];
    a[FCGI_BRB_RESERVED3_OFFSET] = h->reserved[3];
    a[FCGI_BRB_RESERVED4_OFFSET] = h->reserved[4];
}

/*
 * Canonicalise http-like URLs.
 * scheme is the scheme for the URL
 * url is the URL starting with the first '/'
 * def_port is the default port for this scheme.
 */
static int proxy_fcgi_canon(request_rec *r, char *url)
{
    char *host, sport[7];
    const char *err, *path;
    apr_port_t port = 8000;

    if (strncasecmp(url, "fcgi:", 5) == 0) {
        url += 5;
    }
    else {
        return DECLINED;
    }
    
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, r->server,
                 "proxy: FCGI: canonicalising URL %s", url);

    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error parsing URL %s: %s", url, err);
        return HTTP_BAD_REQUEST;
    }
        
    apr_snprintf(sport, sizeof(sport), ":%d", port);
        
    if (ap_strchr_c(host, ':')) {
        /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }

    if (apr_table_get(r->notes, "proxy-nocanon")) {
        path = url;   /* this is the raw path */
    }
    else {
        path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, 0,
                             r->proxyreq);
    }
    if (path == NULL)
        return HTTP_BAD_REQUEST;

    r->filename = apr_pstrcat(r->pool, "proxy:fcgi://", host, sport, "/",
                              path, NULL);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "proxy: FCGI: set r->filename to %s", r->filename);

    r->path_info = apr_pstrcat(r->pool, "/", path, NULL);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "proxy: FCGI: set r->path_info to %s", r->path_info);

    return OK;
}

/*
 * Fill in a fastcgi request header with the following type, request id,
 * content length, and padding length.
 *
 * The header array must be at least FCGI_HEADER_LEN bytes long.
 */
static void fill_in_header(fcgi_header *header,
                           unsigned char type,
                           apr_uint16_t request_id,
                           apr_uint16_t content_len,
                           unsigned char padding_len)
{
    header->version = FCGI_VERSION;

    header->type = type;

    header->requestIdB1 = ((request_id >> 8) & 0xff);
    header->requestIdB0 = ((request_id) & 0xff);

    header->contentLengthB1 = ((content_len >> 8) & 0xff);
    header->contentLengthB0 = ((content_len) & 0xff);

    header->paddingLength = padding_len;

    header->reserved = 0;
}

/* Wrapper for apr_socket_sendv that handles updating the worker stats. */
static apr_status_t send_data(proxy_conn_rec *conn,
                              struct iovec *vec,
                              int nvec,
                              apr_size_t *len,
                              int blocking)
{
    apr_status_t rv = APR_SUCCESS, arv;
    apr_size_t written = 0, to_write = 0;
    int i, offset;
    apr_interval_time_t old_timeout;
    apr_socket_t *s = conn->sock;

    if (!blocking) {
        arv = apr_socket_timeout_get(s, &old_timeout);
        if (arv != APR_SUCCESS) {
            return arv;
        }
        arv = apr_socket_timeout_set(s, 0);
        if (arv != APR_SUCCESS) {
            return arv;
        }
    }

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

    if (!blocking) {
        arv = apr_socket_timeout_set(s, old_timeout);
        if ((arv != APR_SUCCESS) && (rv == APR_SUCCESS)) {
            return arv;
        }
    }
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

static apr_status_t send_begin_request(proxy_conn_rec *conn, int request_id)
{
    struct iovec vec[2];
    fcgi_header header;
    unsigned char farray[FCGI_HEADER_LEN];
    fcgi_begin_request_body brb;
    unsigned char abrb[FCGI_HEADER_LEN];
    apr_size_t len;

    fill_in_header(&header, FCGI_BEGIN_REQUEST, request_id, sizeof(abrb), 0);

    brb.roleB1 = ((FCGI_RESPONDER >> 8) & 0xff);
    brb.roleB0 = ((FCGI_RESPONDER) & 0xff); 
    brb.flags = FCGI_KEEP_CONN;
    brb.reserved[0] = 0;
    brb.reserved[1] = 0;
    brb.reserved[2] = 0;
    brb.reserved[3] = 0;
    brb.reserved[4] = 0;

    fcgi_header_to_array(&header, farray);
    fcgi_begin_request_body_to_array(&brb, abrb);

    vec[0].iov_base = farray;
    vec[0].iov_len = sizeof(farray);
    vec[1].iov_base = abrb;
    vec[1].iov_len = sizeof(abrb);

    return send_data(conn, vec, 2, &len, 1);
}

static apr_status_t send_environment(proxy_conn_rec *conn, request_rec *r, 
                                     int request_id)
{
    const apr_array_header_t *envarr;
    const apr_table_entry_t *elts;
    struct iovec vec[2];
    fcgi_header header;
    unsigned char farray[FCGI_HEADER_LEN];
    apr_size_t bodylen, envlen;
    char *body, *itr;
    apr_status_t rv;
    apr_size_t len;
    int i, numenv;

    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    /* XXX are there any FastCGI specific env vars we need to send? */

    bodylen = envlen = 0;

    /* XXX mod_cgi/mod_cgid use ap_create_environment here, which fills in
     *     the TZ value specially.  We could use that, but it would mean
     *     parsing the key/value pairs back OUT of the allocated env array,
     *     not to mention allocating a totally useless array in the first
     *     place, which would suck. */

    envarr = apr_table_elts(r->subprocess_env);

    elts = (const apr_table_entry_t *) envarr->elts;

    for (i = 0; i < envarr->nelts; ++i) {
        apr_size_t keylen, vallen;

        if (! elts[i].key) {
            continue;
        }

        keylen = strlen(elts[i].key);

        if (keylen >> 7 == 0) {
            envlen += 1;
        }
        else {
            envlen += 4;
        }

        envlen += keylen;

        vallen = strlen(elts[i].val);

#ifdef FCGI_DUMP_ENV_VARS
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "proxy: FCGI: sending env var '%s' value '%s'",
                      elts[i].key, elts[i].val);
#endif

        if (vallen >> 7 == 0) {
            envlen += 1;
        }
        else {
            envlen += 4;
        }

        envlen += vallen;

	/* The cast of bodylen is safe since FCGI_MAX_ENV_SIZE is for sure an int */
        if (envlen > FCGI_MAX_ENV_SIZE) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "proxy: FCGI: truncating environment to %d bytes and %d elements",
                          (int)bodylen, i);
            break;
        }

        bodylen = envlen;
    }

    numenv = i;

    body = apr_pcalloc(r->pool, bodylen);

    itr = body;

    for (i = 0; i < numenv; ++i) {
        apr_size_t keylen, vallen;
       
        if (! elts[i].key) {
            continue;
        }

        keylen = strlen(elts[i].key);

        if (keylen >> 7 == 0) {
            itr[0] = keylen & 0xff;
            itr += 1;
        }
        else {
            itr[0] = ((keylen >> 24) & 0xff) | 0x80;
            itr[1] = ((keylen >> 16) & 0xff);
            itr[2] = ((keylen >> 8) & 0xff);
            itr[3] = ((keylen) & 0xff);
            itr += 4;
        }

        vallen = strlen(elts[i].val);

        if (vallen >> 7 == 0) {
            itr[0] = vallen & 0xff;
            itr += 1;
        }
        else {
            itr[0] = ((vallen >> 24) & 0xff) | 0x80;
            itr[1] = ((vallen >> 16) & 0xff);
            itr[2] = ((vallen >> 8) & 0xff);
            itr[3] = ((vallen) & 0xff);
            itr += 4;
        }

        memcpy(itr, elts[i].key, keylen);
        itr += keylen;

        memcpy(itr, elts[i].val, vallen);
        itr += vallen;
    }

    fill_in_header(&header, FCGI_PARAMS, request_id, bodylen, 0);
    fcgi_header_to_array(&header, farray);

    vec[0].iov_base = farray;
    vec[0].iov_len = sizeof(farray);
    vec[1].iov_base = body;
    vec[1].iov_len = bodylen;

    rv = send_data(conn, vec, 2, &len, 1);
    if (rv) {
        return rv;
    }

    fill_in_header(&header, FCGI_PARAMS, request_id, 0, 0);
    fcgi_header_to_array(&header, farray);

    vec[0].iov_base = farray;
    vec[0].iov_len = sizeof(farray);

    return send_data(conn, vec, 1, &len, 1);
}

enum {
  HDR_STATE_READING_HEADERS,
  HDR_STATE_GOT_CR,
  HDR_STATE_GOT_CRLF,
  HDR_STATE_GOT_CRLFCR,
  HDR_STATE_GOT_LF,
  HDR_STATE_DONE_WITH_HEADERS
};

/* Try to parse the script headers in the response from the back end fastcgi
 * server.  Assumes that the contents of READBUF have already been added to
 * the end of OB.  STATE holds the current header parsing state for this
 * request.
 *
 * Returns -1 on error, 0 if it can't find the end of the headers, and 1 if
 * it found the end of the headers and scans them successfully. */
static int handle_headers(request_rec *r,
                          int *state,
                          char *readbuf,
                          apr_bucket_brigade *ob)
{
    conn_rec *c = r->connection;
    const char *itr = readbuf;

    while (*itr) {
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
        int status = ap_scan_script_header_err_brigade(r, ob, NULL);
        if (status != OK) {
            apr_bucket *b;

            r->status = status;

            apr_brigade_cleanup(ob);

            b = apr_bucket_eos_create(c->bucket_alloc);

            APR_BRIGADE_INSERT_TAIL(ob, b);

            ap_pass_brigade(r->output_filters, ob);

            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "proxy: FCGI: Error parsing script headers");

            return -1;
        }
        else {
            return 1;
        }
    }

    return 0;
}

static void dump_header_to_log(request_rec *r, unsigned char fheader[],
                               apr_size_t length)
{
#ifdef FCGI_DUMP_HEADERS
    apr_size_t posn = 0;
    char asc_line[20];
    char hex_line[60];
    int i = 0;

    memset(asc_line, 0, sizeof(asc_line));
    memset(hex_line, 0, sizeof(hex_line));

    while (posn < length) {
        unsigned char c = fheader[posn]; 
        char hexval[3];

        if (i >= 20) {
            i = 0;

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "HEADER: %s %s", asc_line, hex_line);

            memset(asc_line, 0, sizeof(asc_line));
            memset(hex_line, 0, sizeof(hex_line));
        }

        if (isprint(c)) {
            asc_line[i] = c;
        }
        else {
            asc_line[i] = '.';
        }

        if ((c >> 4) >= 10) {
            hex_line[i * 3] = 'a' + ((c >> 4) - 10);
        }
        else {
            hex_line[i * 3] = '0' + (c >> 4);
        }

        if ((c & 0x0F) >= 10) {
            hex_line[i * 3 + 1] = 'a' + ((c & 0x0F) - 10);
        }
        else {
            hex_line[i * 3 + 1] = '0' + (c & 0xF);
        }

        hex_line[i * 3 + 2] = ' ';

        i++;
        posn++;
    }

    if (i != 1) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "HEADER: %s %s",
                     asc_line, hex_line);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "HEADER: -EOH-");
#endif
}

static apr_status_t dispatch(proxy_conn_rec *conn, request_rec *r,
                             int request_id)
{
    apr_bucket_brigade *ib, *ob;
    int seen_end_of_headers = 0, done = 0;
    apr_status_t rv = APR_SUCCESS;
    conn_rec *c = r->connection;
    struct iovec vec[2];
    fcgi_header header;
    unsigned char farray[FCGI_HEADER_LEN];
    apr_pollfd_t pfd;
    int header_state = HDR_STATE_READING_HEADERS;
    apr_pool_t *setaside_pool;

    apr_pool_create(&setaside_pool, r->pool);

    pfd.desc_type = APR_POLL_SOCKET;
    pfd.desc.s = conn->sock;
    pfd.p = r->pool;
    pfd.reqevents = APR_POLLIN | APR_POLLOUT;

    ib = apr_brigade_create(r->pool, c->bucket_alloc);
    ob = apr_brigade_create(r->pool, c->bucket_alloc);

    while (! done) {
        apr_interval_time_t timeout = conn->worker->timeout;
        apr_size_t len;
        int n;

        /* We need SOME kind of timeout here, or virtually anything will
         * cause timeout errors. */
        if (! conn->worker->timeout_set) {
            timeout = apr_time_from_sec(30);
        }

        rv = apr_poll(&pfd, 1, &n, timeout);
        if (rv != APR_SUCCESS) {
            break;
        }

        if (pfd.rtnevents & APR_POLLOUT) {
            char writebuf[AP_IOBUFSIZE];
            apr_size_t writebuflen;
            int last_stdin = 0;

            rv = ap_get_brigade(r->input_filters, ib,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                sizeof(writebuf));
            if (rv != APR_SUCCESS) {
                break;
            }

            if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(ib))) {
                last_stdin = 1;
            }

            writebuflen = sizeof(writebuf);

            rv = apr_brigade_flatten(ib, writebuf, &writebuflen);

            apr_brigade_cleanup(ib);

            if (rv != APR_SUCCESS) {
                break;
            }

            fill_in_header(&header, FCGI_STDIN, request_id,
                           (apr_uint16_t) writebuflen, 0);
            fcgi_header_to_array(&header, farray);

            vec[0].iov_base = farray;
            vec[0].iov_len = sizeof(farray);
            vec[1].iov_base = writebuf;
            vec[1].iov_len = writebuflen;

            rv = send_data(conn, vec, 2, &len, 0);
            if (rv != APR_SUCCESS) {
                break;
            }

            if (last_stdin) {
                pfd.reqevents = APR_POLLIN; /* Done with input data */

                fill_in_header(&header, FCGI_STDIN, request_id, 0, 0);
                fcgi_header_to_array(&header, farray);

                vec[0].iov_base = farray;
                vec[0].iov_len = sizeof(farray);

                rv = send_data(conn, vec, 1, &len, 1);
            }
        }

        if (pfd.rtnevents & APR_POLLIN) {
            /* readbuf has one byte on the end that is always 0, so it's
             * able to work with a strstr when we search for the end of
             * the headers, even if we fill the entire length in the recv. */
            char readbuf[AP_IOBUFSIZE + 1];
            apr_size_t readbuflen;
            apr_size_t clen;
            int rid, type;
            apr_bucket *b;
            char plen;

            memset(readbuf, 0, sizeof(readbuf));
            memset(farray, 0, sizeof(farray));

            /* First, we grab the header... */
            readbuflen = FCGI_HEADER_LEN;

            rv = get_data(conn, (char *) farray, &readbuflen);
            if (rv != APR_SUCCESS) {
                break;
            }

            dump_header_to_log(r, farray, readbuflen);
            
            if (readbuflen != FCGI_HEADER_LEN) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "proxy: FCGI: Failed to read entire header "
                             "got %" APR_SIZE_T_FMT " wanted %d", 
                             readbuflen, FCGI_HEADER_LEN);
                rv = APR_EINVAL;
                break;
            }

            fcgi_header_from_array(&header, farray);

            if (header.version != FCGI_VERSION) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "proxy: FCGI: Got bogus version %d",
                             (int) header.version);
                rv = APR_EINVAL;
                break;
            }

            type = header.type;

            rid = header.requestIdB1 << 8;
            rid |= header.requestIdB0;

            if (rid != request_id) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "proxy: FCGI: Got bogus rid %d, expected %d",
                             rid, request_id);
                rv = APR_EINVAL;
                break;
            }

            clen = header.contentLengthB1 << 8;
            clen |= header.contentLengthB0;

            plen = header.paddingLength;

recv_again:
            if (clen > sizeof(readbuf) - 1) {
                readbuflen = sizeof(readbuf) - 1;
            } else {
                readbuflen = clen;
            }

            /* Now get the actual data.  Yes it sucks to do this in a second
             * recv call, this will eventually change when we move to real
             * nonblocking recv calls. */
            if (readbuflen != 0) {
                rv = get_data(conn, readbuf, &readbuflen);
                if (rv != APR_SUCCESS) {
                    break;
                }
                readbuf[readbuflen] = 0;
            }

            switch (type) {
            case FCGI_STDOUT:
                if (clen != 0) {
                    b = apr_bucket_transient_create(readbuf,
                                                    readbuflen,
                                                    c->bucket_alloc);

                    APR_BRIGADE_INSERT_TAIL(ob, b);

                    if (! seen_end_of_headers) {
                        int st = handle_headers(r, &header_state, readbuf, ob);

                        if (st == 1) {
                            seen_end_of_headers = 1;

                            rv = ap_pass_brigade(r->output_filters, ob);
                            if (rv != APR_SUCCESS) {
                                break;
                            }

                            apr_brigade_cleanup(ob);

                            apr_pool_clear(setaside_pool);
                        }
                        else if (st == -1) {
                            rv = APR_EINVAL;
                            break;
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
                        rv = ap_pass_brigade(r->output_filters, ob);
                        if (rv != APR_SUCCESS) {
                            break;
                        }
                        apr_brigade_cleanup(ob);
                    }

                    /* If we didn't read all the data go back and get the
                     * rest of it. */
                    if (clen > readbuflen) {
                        clen -= readbuflen;
                        goto recv_again;
                    }
                } else {
                    /* XXX what if we haven't seen end of the headers yet? */

                    b = apr_bucket_eos_create(c->bucket_alloc);

                    APR_BRIGADE_INSERT_TAIL(ob, b);

                    rv = ap_pass_brigade(r->output_filters, ob);
                    if (rv != APR_SUCCESS) {
                        break;
                    }

                    /* XXX Why don't we cleanup here?  (logic from AJP) */
                }
                break;

            case FCGI_STDERR:
                /* TODO: Should probably clean up this logging a bit... */
                if (clen) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                                 "proxy: FCGI: Got error '%s'", readbuf);
                }

                if (clen > readbuflen) {
                    clen -= readbuflen;
                    goto recv_again;
                }
                break;

            case FCGI_END_REQUEST:
                done = 1;
                break;

            default:
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "proxy: FCGI: Got bogus record %d", type);
                break;
            }

            if (plen) {
                readbuflen = plen;

                rv = get_data(conn, readbuf, &readbuflen);
                if (rv != APR_SUCCESS) {
                    break;
                }
            }
        }
    }

    apr_brigade_destroy(ib);
    apr_brigade_destroy(ob);

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
                           char *url, char *server_portstr)
{
    /* Request IDs are arbitrary numbers that we assign to a
     * single request. This would allow multiplex/pipelinig of 
     * multiple requests to the same FastCGI connection, but 
     * we don't support that, and always use a value of '1' to
     * keep things simple. */
    int request_id = 1; 
    apr_status_t rv;
   
    /* Step 1: Send FCGI_BEGIN_REQUEST */
    rv = send_begin_request(conn, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy: FCGI: Failed Writing Request to %s:",
                     server_portstr);
        conn->close = 1;
        return HTTP_SERVICE_UNAVAILABLE;
    }
    
    /* Step 2: Send Environment via FCGI_PARAMS */
    rv = send_environment(conn, r, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy: FCGI: Failed writing Environment to %s:",
                     server_portstr);
        conn->close = 1;
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* Step 3: Read records from the back end server and handle them. */
    rv = dispatch(conn, r, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy: FCGI: Error dispatching request to %s:",
                     server_portstr);
        conn->close = 1;
        return HTTP_SERVICE_UNAVAILABLE;
    }

    return OK;
}

#define FCGI_SCHEME "FCGI"

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

    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);

    apr_pool_t *p = r->pool;

    apr_uri_t *uri = apr_palloc(r->pool, sizeof(*uri));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: FCGI: url: %s proxyname: %s proxyport: %d",
                 url, proxyname, proxyport);

    if (strncasecmp(url, "fcgi:", 5) == 0) {
        url += 5;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: FCGI: declining URL %s", url);
        return DECLINED;
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: FCGI: serving URL %s", url);

    /* Create space for state information */
    if (! backend) {
        status = ap_proxy_acquire_connection(FCGI_SCHEME, &backend, worker,
                                             r->server);
        if (status != OK) {
            if (backend) {
                backend->close = 1;
                ap_proxy_release_connection(FCGI_SCHEME, backend, r->server);
            }
            return status;
        }
    }

    backend->is_ssl = 0;

    /* XXX Setting close to 0 is a great way to end up with
     *     timeouts at this point, since we lack good ways to manage the
     *     back end fastcgi processes.  This should be revisited when we
     *     have a better story on that part of things. */

    backend->close = 1;

    /* Step One: Determine Who To Connect To */
    status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                           uri, &url, proxyname, proxyport,
                                           server_portstr,
                                           sizeof(server_portstr));
    if (status != OK) {
        goto cleanup;
    }

    /* Step Two: Make the Connection */
    if (ap_proxy_connect_backend(FCGI_SCHEME, backend, worker, r->server)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "proxy: FCGI: failed to make connection to backend: %s",
                     backend->hostname);
        status = HTTP_SERVICE_UNAVAILABLE;
        goto cleanup;
    }

    /* Step Three: Process the Request */
    status = fcgi_do_request(p, r, backend, origin, dconf, uri, url,
                             server_portstr);

cleanup:
    /* Do not close the socket */
    ap_proxy_release_connection(FCGI_SCHEME, backend, r->server);
    return status;
}

static void register_hooks(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_fcgi_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_fcgi_canon, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(proxy_fcgi) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
