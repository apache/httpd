/* Copyright 2005 The Apache Software Foundation or its licensors, as
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

#include "mod_proxy.h"
#include "fcgi_protocol.h"

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
    const char *err, *scheme, *path;
    apr_port_t port = 8000;

    if (strncasecmp(url, "fcgi-", 5) == 0) {
        url += 5;
    }
    else {
        return DECLINED;
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: FCGI: canonicalising URL %s", url);

    if (strncmp(url, "tcp://", 6) == 0) {
        url += 4;
        
        scheme = "fcgi-tcp://";

        err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
        if (err) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "error parsing URL %s: %s",
                          url, err);
            return HTTP_BAD_REQUEST;
        }
        
        apr_snprintf(sport, sizeof(sport), ":%d", port);
        
        if (ap_strchr_c(host, ':')) {
            /* if literal IPv6 address */
            host = apr_pstrcat(r->pool, "[", host, "]", NULL);
        }

        path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, 0,
                                 r->proxyreq);
        if (path == NULL)
            return HTTP_BAD_REQUEST;

        r->filename = apr_pstrcat(r->pool, "proxy:", scheme, host, sport, "/",
                                  path, NULL);

        r->path_info = apr_pstrcat(r->pool, "/", path, NULL);
    }
    else if (strncmp(url, "local://", 8) == 0) {
        url += 6;
        scheme = "fcgi-local:";
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "proxy: FCGI: Local FastCGI not supported.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
             "proxy: FCGI: mallformed destination: %s", url);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

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
    header->version = 1;

    header->type = type;

    header->requestIdB1 = ((request_id >> 8) & 0xff);
    header->requestIdB0 = ((request_id) & 0xff);

    header->contentLengthB1 = ((content_len >> 8) & 0xff);
    header->contentLengthB0 = ((content_len) & 0xff);

    header->paddingLength = padding_len;

    header->reserved = 0;
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

    fcgi_header_to_array(&header, farray);
    fcgi_begin_request_body_to_array(&brb, abrb);

    vec[0].iov_base = farray;
    vec[0].iov_len = sizeof(farray);
    vec[1].iov_base = abrb;
    vec[1].iov_len = sizeof(abrb);

    return apr_socket_sendv(conn->sock, vec, 2, &len);
}

static apr_status_t send_environment(proxy_conn_rec *conn, request_rec *r, 
                                     int request_id)
{
    const apr_array_header_t *envarr;
    const apr_table_entry_t *elts;
    struct iovec vec[2];
    fcgi_header header;
    unsigned char farray[FCGI_HEADER_LEN];
    apr_size_t bodylen;
    char *body, *itr;
    apr_status_t rv;
    apr_size_t len;
    int i;

    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    /* XXX are there any FastCGI specific env vars we need to send? */

    /* XXX What if there is over 64k worth of data in the env? */
    bodylen = 0;

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
            bodylen += 1;
        }
        else {
            bodylen += 4;
        }

        bodylen += keylen;

        vallen = strlen(elts[i].val);

        if (vallen >> 7 == 0) {
            bodylen += 1;
        }
        else {
            bodylen += 4;
        }

        bodylen += vallen;
    }

    body = apr_pcalloc(r->pool, bodylen);

    itr = body;

    for (i = 0; i < envarr->nelts; ++i) {
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

    rv = apr_socket_sendv(conn->sock, vec, 2, &len);
    if (rv) {
        return rv;
    }

    fill_in_header(&header, FCGI_PARAMS, request_id, 0, 0);
    fcgi_header_to_array(&header, farray);

    vec[0].iov_base = farray;
    vec[0].iov_len = sizeof(farray);

    return apr_socket_sendv(conn->sock, vec, 1, &len);
}

/* Try to parse the script headers in the response from the back end fastcgi
 * server.  Assumes that the contents of READBUF have already been added to
 * the end of OB.
 *
 * Returns -1 on error, 0 if it can't find the end of the headers, and 1 if
 * it found the end of the headers and scans them successfully. */
static int handle_headers(request_rec *r,
                          char *readbuf,
                          apr_bucket_brigade *ob)
{
    conn_rec *c = r->connection;

    /* XXX This is both slightly wrong and overly strict.  It's wrong
     *     cause if we get part of the \r\n\r\n in one record, and the
     *     rest in the next, we'll miss it, and it's too strict because
     *     if a CGI uses just \n instead of \r\n we'll miss it, which
     *     is bad. */

    if (strstr(readbuf, "\r\n\r\n")) {
        int status = ap_scan_script_header_err_brigade(r, ob,
                                                       NULL);
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

typedef struct {
    apr_pool_t *scratch_pool;
} proxy_fcgi_baton_t;

static void dump_header_to_log(request_rec *r, unsigned char fheader[],
                               apr_size_t length)
{
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
}

static apr_status_t dispatch(proxy_conn_rec *conn, request_rec *r,
                             int request_id)
{
    apr_bucket_brigade *ib, *ob;
    int seen_end_of_headers = 0, done = 0;
    proxy_fcgi_baton_t *pfb = conn->data;
    apr_status_t rv = APR_SUCCESS;
    conn_rec *c = r->connection;
    struct iovec vec[2];
    fcgi_header header;
    unsigned char farray[FCGI_HEADER_LEN];
    apr_pollfd_t pfd;

    pfd.desc_type = APR_POLL_SOCKET;
    pfd.desc.s = conn->sock;
    pfd.p = r->pool;
    pfd.reqevents = APR_POLLIN | APR_POLLOUT;

    ib = apr_brigade_create(r->pool, c->bucket_alloc);
    ob = apr_brigade_create(r->pool, c->bucket_alloc);

    while (! done) {
        apr_size_t len;
        int n;

        rv = apr_poll(&pfd, 1, &n, -1);
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

            /* XXX This should be nonblocking, and if we don't write all
             *     the data we need to keep track of that fact so we can
             *     get to it next time through. */
            rv = apr_socket_sendv(conn->sock, vec, 2, &len);
            if (rv != APR_SUCCESS) {
                break;
            }

            /* XXX AJP updates conn->worker->s->transferred here, do we need
             *     to? */

            if (last_stdin) {
                pfd.reqevents = APR_POLLIN; /* Done with input data */

                fill_in_header(&header, FCGI_STDIN, request_id, 0, 0);
                fcgi_header_to_array(&header, farray);

                vec[0].iov_base = farray;
                vec[0].iov_len = sizeof(farray);

                rv = apr_socket_sendv(conn->sock, vec, 1, &len);
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

            rv = apr_socket_recv(conn->sock, (char *) farray, &readbuflen);
            if (rv != APR_SUCCESS) {
                break;
            }

            dump_header_to_log(r, farray, readbuflen);
            
            if (readbuflen != FCGI_HEADER_LEN) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "proxy: FCGI: Failed to read entire header "
                             "got %d wanted %d", 
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
                rv = apr_socket_recv(conn->sock, readbuf, &readbuflen);
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
                        int st = handle_headers(r, readbuf, ob);

                        if (st == 1) {
                            seen_end_of_headers = 1;
                        }
                        else if (st == -1) {
                            rv = APR_EINVAL;
                            break;
                        }
                    }

                    /* XXX Update conn->worker->s->read like AJP does */

                    if (seen_end_of_headers) {
                        rv = ap_pass_brigade(r->output_filters, ob);
                        if (rv != APR_SUCCESS) {
                            break;
                        }

                        apr_brigade_cleanup(ob);

                        apr_pool_clear(pfb->scratch_pool);
                    } else {
                        /* We're still looking for the end of the headers,
                         * so this part of the data will need to persist. */
                        apr_bucket_setaside(b, pfb->scratch_pool);
                    }

                    /* If we didn't read all the data go back and get the
                     * rest of it. */
                    if (clen > readbuflen) {
                        clen -= readbuflen;
                        goto recv_again;
                    }
                } else {
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

                rv = apr_socket_recv(conn->sock, readbuf, &readbuflen);
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "proxy: FCGI: Failed Writing Request to %s:",
                     server_portstr);
        conn->close = 1;
        return HTTP_SERVICE_UNAVAILABLE;
    }
    
    /* Step 2: Send Enviroment via FCGI_PARAMS */
    rv = send_environment(conn, r, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "proxy: FCGI: Failed writing Environment to %s:",
                     server_portstr);
        conn->close = 1;
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* Step 3: Read records from the back end server and handle them. */
    rv = dispatch(conn, r, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "proxy: FCGI: Error dispatching request to %s:",
                     server_portstr);
        conn->close = 1;
        return HTTP_SERVICE_UNAVAILABLE;
    }

    return OK;
}

/*
 * This handles fcgi:(type):(dest) URLs
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
    const char *scheme;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);

    apr_pool_t *p = r->pool;

    apr_uri_t *uri = apr_palloc(r->pool, sizeof(*uri));


    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                 "proxy: FCGI: url: %s proxyname: %s proxyport: %d",
                 url, proxyname, proxyport);

    if (strncasecmp(url, "fcgi-", 5) == 0) {
        url += 5;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: FCGI: declining URL %s", url);
        return DECLINED;
    }
    
    if (strncmp(url, "tcp://", 6) == 0) {
        scheme = "FCGI_TCP";
    }
    else if (strncmp(url, "local://", 8) == 0) {
        scheme = "FCGI_LOCAL";
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "proxy: FCGI: local FastCGI not supported.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
             "proxy: FCGI: mallformed destination: %s", url);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: FCGI: serving URL %s via %s", url, scheme);

    /* Create space for state information */
    if (! backend) {
        status = ap_proxy_acquire_connection(scheme, &backend, worker,
                                             r->server);
        if (status != OK) {
            if (backend) {
                backend->close_on_recycle = 1;
                ap_proxy_release_connection(scheme, backend, r->server);
            }
            return status;
        }

        {
            proxy_fcgi_baton_t *pfb = apr_pcalloc(r->pool, sizeof(*pfb));

            apr_pool_create(&pfb->scratch_pool, r->pool);

            backend->data = pfb;
        }
    }

    backend->is_ssl = 0;
    backend->close_on_recycle = 0;

    /* Step One: Determine Who To Connect To */
    status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                           uri, &url, proxyname, proxyport,
                                           server_portstr,
                                           sizeof(server_portstr));
    if (status != OK) {
        goto cleanup;
    }

    /* Step Two: Make the Connection */
    if (ap_proxy_connect_backend(scheme, backend, worker, r->server)) {
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
    ap_proxy_release_connection(scheme, backend, r->server);
    return status;
}

static void register_hooks(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_fcgi_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_fcgi_canon, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA proxy_fcgi_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};

