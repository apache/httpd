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

/* This file implements an OCSP client including a toy HTTP/1.0
 * client.  Once httpd depends on a real HTTP client library, most of
 * this can be thrown away. */

#include "ssl_private.h"

#ifdef HAVE_OCSP

#include "apr_buckets.h"
#include "apr_uri.h"

/* Serialize an OCSP request which will be sent to the responder at
 * given URI to a memory BIO object, which is returned. */
static BIO *serialize_request(OCSP_REQUEST *req, const apr_uri_t *uri)
{
    BIO *bio;
    int len;

    len = i2d_OCSP_REQUEST(req, NULL);

    bio = BIO_new(BIO_s_mem());

    BIO_printf(bio, "POST %s%s%s HTTP/1.0\r\n"
               "Host: %s:%d\r\n"
               "Content-Type: application/ocsp-request\r\n"
               "Content-Length: %d\r\n"
               "\r\n", 
               uri->path ? uri->path : "/",
               uri->query ? "?" : "", uri->query ? uri->query : "",
               uri->hostname, uri->port, len);

    if (i2d_OCSP_REQUEST_bio(bio, req) != 1) {
        BIO_free(bio);
        return NULL;
    }

    return bio;
}

/* Send the OCSP request serialized into BIO 'request' to the
 * responder at given server given by URI.  Returns socket object or
 * NULL on error. */
static apr_socket_t *send_request(BIO *request, const apr_uri_t *uri, 
                                  apr_interval_time_t timeout,
                                  conn_rec *c, apr_pool_t *p)
{
    apr_status_t rv;
    apr_sockaddr_t *sa;
    apr_socket_t *sd;
    char buf[HUGE_STRING_LEN];
    int len;

    rv = apr_sockaddr_info_get(&sa, uri->hostname, APR_UNSPEC, uri->port, 0, p);
    if (rv) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                      "could not resolve address of OCSP responder %s", 
                      uri->hostinfo);
        return NULL;
    }
    
    /* establish a connection to the OCSP responder */ 
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, 
                  "connecting to OCSP responder '%s'", uri->hostinfo);

    /* Cycle through address until a connect() succeeds. */
    for (; sa; sa = sa->next) {
        rv = apr_socket_create(&sd, sa->family, SOCK_STREAM, APR_PROTO_TCP, p);
        if (rv == APR_SUCCESS) {
            apr_socket_timeout_set(sd, timeout);

            rv = apr_socket_connect(sd, sa);
            if (rv == APR_SUCCESS) {
                break;
            }
            apr_socket_close(sd);
        }
    }

    if (sa == NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                      "could not connect to OCSP responder '%s'",
                      uri->hostinfo);
        apr_socket_close(sd);
        return NULL;
    }

    /* send the request and get a response */ 
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, 
                 "sending request to OCSP responder");

    while ((len = BIO_read(request, buf, sizeof buf)) > 0) {
        char *wbuf = buf;
        apr_size_t remain = len;
        
        do {
            apr_size_t wlen = remain;

            rv = apr_socket_send(sd, wbuf, &wlen);
            wbuf += remain;
            remain -= wlen;
        } while (rv == APR_SUCCESS && remain > 0);

        if (rv) {
            apr_socket_close(sd);
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                          "failed to send request to OCSP responder '%s'",
                          uri->hostinfo);
            return NULL;
        }
    }

    return sd;
}

/* Return a pool-allocated NUL-terminated line, with CRLF stripped,
 * read from brigade 'bbin' using 'bbout' as temporary storage. */
static char *get_line(apr_bucket_brigade *bbout, apr_bucket_brigade *bbin,
                      conn_rec *c, apr_pool_t *p)
{
    apr_status_t rv;
    apr_size_t len;
    char *line;

    apr_brigade_cleanup(bbout);

    rv = apr_brigade_split_line(bbout, bbin, APR_BLOCK_READ, 8192);
    if (rv) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                      "failed reading line from OCSP server");
        return NULL;
    }
    
    rv = apr_brigade_pflatten(bbout, &line, &len, p);
    if (rv) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                      "failed reading line from OCSP server");
        return NULL;
    }

    if (len && line[len-1] != APR_ASCII_LF) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                      "response header line too long from OCSP server");
        return NULL;
    }

    line[len-1] = '\0';
    if (len > 1 && line[len-2] == APR_ASCII_CR) {
        line[len-2] = '\0';
    }

    return line;
}

/* Maximum values to prevent eating RAM forever. */
#define MAX_HEADERS (256)
#define MAX_CONTENT (2048 * 1024)

/* Read the OCSP response from the socket 'sd', using temporary memory
 * BIO 'bio', and return the decoded OCSP response object, or NULL on
 * error. */
static OCSP_RESPONSE *read_response(apr_socket_t *sd, BIO *bio, conn_rec *c,
                                    apr_pool_t *p)
{
    apr_bucket_brigade *bb, *tmpbb;
    OCSP_RESPONSE *response;
    char *line;
    apr_size_t count;
    apr_int64_t code;

    /* Using brigades for response parsing is much simpler than using
     * apr_socket_* directly. */
    bb = apr_brigade_create(p, c->bucket_alloc);
    tmpbb = apr_brigade_create(p, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_socket_create(sd, c->bucket_alloc));

    line = get_line(tmpbb, bb, c, p);
    if (!line || strncmp(line, "HTTP/", 5)
        || (line = ap_strchr(line, ' ')) == NULL
        || (code = apr_atoi64(++line)) < 200 || code > 299) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "bad response from OCSP server: %s",
                      line ? line : "(none)");
        return NULL;
    }

    /* Read till end of headers; don't have to even bother parsing the
     * Content-Length since the server is obliged to close the
     * connection after the response anyway for HTTP/1.0. */
    count = 0;
    while ((line = get_line(tmpbb, bb, c, p)) != NULL && line[0]
           && ++count < MAX_HEADERS) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                      "OCSP response header: %s", line);
    }

    if (count == MAX_HEADERS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "could not read response headers from OCSP server, "
                      "exceeded maximum count (%u)", MAX_HEADERS);
        return NULL;
    }
    else if (!line) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "could not read response header from OCSP server");
        return NULL;
    }

    /* Read the response body into the memory BIO. */
    count = 0;
    while (!APR_BRIGADE_EMPTY(bb)) {
        const char *data;
        apr_size_t len;
        apr_status_t rv;
        apr_bucket *e = APR_BRIGADE_FIRST(bb);

        rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
        if (rv == APR_EOF || (rv == APR_SUCCESS && len == 0)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                          "OCSP response: got EOF");
            break;
        }
        if (rv != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                          "error reading response from OCSP server");
            return NULL;
        }
        count += len;
        if (count > MAX_CONTENT) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                          "OCSP response size exceeds %u byte limit",
                          MAX_CONTENT);
            return NULL;
        }
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                      "OCSP response: got %" APR_SIZE_T_FMT 
                      " bytes, %" APR_SIZE_T_FMT " total", len, count);

        BIO_write(bio, data, (int)len);
        apr_bucket_delete(e);
    }

    apr_brigade_destroy(bb);
    apr_brigade_destroy(tmpbb);

    /* Finally decode the OCSP response from what's stored in the
     * bio. */
    response = d2i_OCSP_RESPONSE_bio(bio, NULL);
    if (response == NULL) {
        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, mySrvFromConn(c));
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "failed to decode OCSP response data");
    }

    return response;
}

OCSP_RESPONSE *modssl_dispatch_ocsp_request(const apr_uri_t *uri,
                                            apr_interval_time_t timeout,
                                            OCSP_REQUEST *request,
                                            conn_rec *c, apr_pool_t *p) 
{
    OCSP_RESPONSE *response = NULL;
    apr_socket_t *sd;
    BIO *bio;

    bio = serialize_request(request, uri);
    if (bio == NULL) {
        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, mySrvFromConn(c));
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "could not serialize OCSP request");
        return NULL;
    }
    
    sd = send_request(bio, uri, timeout, c, p);
    if (sd == NULL) {
        /* Errors already logged. */
        BIO_free(bio);
        return NULL;
    }

    /* Clear the BIO contents, ready for the response. */
    (void)BIO_reset(bio);

    response = read_response(sd, bio, c, p);

    apr_socket_close(sd);
    BIO_free(bio);

    return response;
}

#endif /* HAVE_OCSP */
