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

/*
 * http_protocol.c --- routines which directly communicate with the client.
 *
 * Code originally by Rob McCool; much redone by Robert S. Thau
 * and the Apache Software Foundation.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_signal.h"

#define APR_WANT_STDIO          /* for sscanf */
#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#include "util_filter.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_request.h"
#include "http_vhost.h"
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "apr_date.h"           /* For apr_date_parse_http and APR_DATE_BAD */
#include "util_charset.h"
#include "util_ebcdic.h"
#include "util_time.h"
#include "ap_mpm.h"

#include "mod_core.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "mod_http1.h"


APLOG_USE_MODULE(http1);


static int is_mpm_running(void)
{
    int mpm_state = 0;

    if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state)) {
      return 0;
    }

    if (mpm_state == AP_MPMQ_STOPPING) {
      return 0;
    }

    return 1;
}


/* Send a request's HTTP response headers to the client.
 */
AP_DECLARE(apr_status_t) ap_http1_append_headers(apr_bucket_brigade *bb,
                                                 request_rec *r,
                                                 apr_table_t *headers)
{
    const apr_array_header_t *elts;
    const apr_table_entry_t *t_elt;
    const apr_table_entry_t *t_end;
    struct iovec *vec;
    struct iovec *vec_next;

    elts = apr_table_elts(headers);
    if (elts->nelts == 0) {
        return APR_SUCCESS;
    }
    t_elt = (const apr_table_entry_t *)(elts->elts);
    t_end = t_elt + elts->nelts;
    vec = (struct iovec *)apr_palloc(r->pool, 4 * elts->nelts *
                                     sizeof(struct iovec));
    vec_next = vec;

    /* For each field, generate
     *    name ": " value CRLF
     */
    do {
        if (t_elt->key && t_elt->val) {
            vec_next->iov_base = (void*)(t_elt->key);
            vec_next->iov_len = strlen(t_elt->key);
            vec_next++;
            vec_next->iov_base = ": ";
            vec_next->iov_len = sizeof(": ") - 1;
            vec_next++;
            vec_next->iov_base = (void*)(t_elt->val);
            vec_next->iov_len = strlen(t_elt->val);
            vec_next++;
            vec_next->iov_base = CRLF;
            vec_next->iov_len = sizeof(CRLF) - 1;
            vec_next++;
        }
        t_elt++;
    } while (t_elt < t_end);

    if (APLOGrtrace4(r)) {
        t_elt = (const apr_table_entry_t *)(elts->elts);
        do {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "  %s: %s",
                          t_elt->key, t_elt->val);
            t_elt++;
        } while (t_elt < t_end);
    }

#if APR_CHARSET_EBCDIC
    {
        apr_size_t len;
        char *tmp = apr_pstrcatv(r->pool, vec, vec_next - vec, &len);
        ap_xlate_proto_to_ascii(tmp, len);
        return apr_brigade_write(bb, NULL, NULL, tmp, len);
    }
#else
    return apr_brigade_writev(bb, NULL, NULL, vec, vec_next - vec);
#endif
}


AP_DECLARE(apr_status_t) ap_http1_terminate_header(apr_bucket_brigade *bb)
{
    char crlf[] = CRLF;
    apr_size_t buflen;

    buflen = strlen(crlf);
    ap_xlate_proto_to_ascii(crlf, buflen);
    return apr_brigade_write(bb, NULL, NULL, crlf, buflen);
}


AP_DECLARE(void) ap_http1_add_end_chunk(apr_bucket_brigade *b,
                                        apr_bucket *eos,
                                        request_rec *r,
                                        apr_table_t *trailers)
{
    if (!trailers || apr_is_empty_table(trailers)) {
        apr_bucket *e;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "append empty end chunk");
        e = apr_bucket_immortal_create(ZERO_ASCII CRLF_ASCII
                                       CRLF_ASCII, 5, b->bucket_alloc);
        if (eos) {
            APR_BUCKET_INSERT_BEFORE(eos, e);
        }
        else {
            APR_BRIGADE_INSERT_TAIL(b, e);
        }
    }
    else {
        apr_bucket_brigade *tmp;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "append end chunk with trailers");
        tmp = eos? apr_brigade_split_ex(b, eos, NULL) : NULL;
        apr_brigade_write(b, NULL, NULL, ZERO_ASCII CRLF_ASCII, 3);
        ap_http1_append_headers(b, r, trailers);
        ap_http1_terminate_header(b);
        if (tmp) APR_BRIGADE_CONCAT(b, tmp);
    }
}


int http1_set_keepalive(request_rec *r, ap_bucket_response *resp)
{
    int ka_sent, left = 0, wimpy;
    const char *conn;

    if (r->proto_num >= HTTP_VERSION(2,0)) {
        goto update_keepalives;
    }

    ka_sent = 0;
    left = r->server->keep_alive_max - r->connection->keepalives;
    wimpy = ap_find_token(r->pool,
                          apr_table_get(resp->headers, "Connection"),
                          "close");
    conn = apr_table_get(r->headers_in, "Connection");

    /* The following convoluted conditional determines whether or not
     * the current connection should remain persistent after this response
     * (a.k.a. HTTP Keep-Alive) and whether or not the output message
     * body should use the HTTP/1.1 chunked transfer-coding.  In English,
     *
     *   IF  we have not marked this connection as errored;
     *   and the client isn't expecting 100-continue (PR47087 - more
     *       input here could be the client continuing when we're
     *       closing the request).
     *   and the response body has a defined length due to the status code
     *       being 304 or 204, the request method being HEAD, already
     *       having defined Content-Length or Transfer-Encoding: chunked, or
     *       the request version being HTTP/1.1 and thus capable of being set
     *       as chunked [we know the (r->chunked = 1) side-effect is ugly];
     *   and the server configuration enables keep-alive;
     *   and the server configuration has a reasonable inter-request timeout;
     *   and there is no maximum # requests or the max hasn't been reached;
     *   and the response status does not require a close;
     *   and the response generator has not already indicated close;
     *   and the client did not request non-persistence (Connection: close);
     *   and    we haven't been configured to ignore the buggy twit
     *       or they're a buggy twit coming through a HTTP/1.1 proxy
     *   and    the client is requesting an HTTP/1.0-style keep-alive
     *       or the client claims to be HTTP/1.1 compliant (perhaps a proxy);
     *   and this MPM process is not already exiting
     *   THEN we can be persistent, which requires more headers be output.
     *
     * Note that the condition evaluation order is extremely important.
     */
    if ((r->connection->keepalive != AP_CONN_CLOSE)
        && !r->expecting_100
        && (r->header_only
            || AP_STATUS_IS_HEADER_ONLY(resp->status)
            || apr_table_get(resp->headers, "Content-Length")
            || ap_is_chunked(r->pool,
                             apr_table_get(resp->headers, "Transfer-Encoding"))
            || ((r->proto_num >= HTTP_VERSION(1,1))
                && (r->chunked = 1))) /* THIS CODE IS CORRECT, see above. */
        && r->server->keep_alive
        && (r->server->keep_alive_timeout > 0)
        && ((r->server->keep_alive_max == 0)
            || (left > 0))
        && !ap_status_drops_connection(resp->status)
        && !wimpy
        && !ap_find_token(r->pool, conn, "close")
        && (!apr_table_get(r->subprocess_env, "nokeepalive")
            || apr_table_get(r->headers_in, "Via"))
        && ((ka_sent = ap_find_token(r->pool, conn, "keep-alive"))
            || (r->proto_num >= HTTP_VERSION(1,1)))
        && is_mpm_running()) {

        r->connection->keepalive = AP_CONN_KEEPALIVE;
        r->connection->keepalives++;

        /* If they sent a Keep-Alive token, send one back */
        if (ka_sent) {
            if (r->server->keep_alive_max) {
                apr_table_setn(resp->headers, "Keep-Alive",
                       apr_psprintf(r->pool, "timeout=%d, max=%d",
                            (int)apr_time_sec(r->server->keep_alive_timeout),
                            left));
            }
            else {
                apr_table_setn(resp->headers, "Keep-Alive",
                      apr_psprintf(r->pool, "timeout=%d",
                            (int)apr_time_sec(r->server->keep_alive_timeout)));
            }
            apr_table_mergen(resp->headers, "Connection", "Keep-Alive");
        }

        return 1;
    }

    /* Otherwise, we need to indicate that we will be closing this
     * connection immediately after the current response.
     *
     * We only really need to send "close" to HTTP/1.1 clients, but we
     * always send it anyway, because a broken proxy may identify itself
     * as HTTP/1.0, but pass our request along with our HTTP/1.1 tag
     * to a HTTP/1.1 client. Better safe than sorry.
     */
    if (!wimpy) {
        apr_table_mergen(resp->headers, "Connection", "close");
    }

update_keepalives:
    /*
     * If we had previously been a keepalive connection and this
     * is the last one, then bump up the number of keepalives
     * we've had
     */
    if ((r->connection->keepalive != AP_CONN_CLOSE)
        && r->server->keep_alive_max
        && !left) {
        r->connection->keepalives++;
    }
    r->connection->keepalive = AP_CONN_CLOSE;

    return 0;
}

AP_DECLARE(int) ap_set_keepalive(request_rec *r)
{
    ap_bucket_response resp;

    memset(&resp, 0, sizeof(resp));
    resp.status = r->status;
    resp.headers = r->headers_out;
    resp.notes = r->notes;
    return http1_set_keepalive(r, &resp);
}

int http1_write_header_field(http1_out_ctx_t *out,
                             const char *fieldname, const char *fieldval)
{
#if APR_CHARSET_EBCDIC
    char *headfield;
    apr_size_t len;

    headfield = apr_pstrcat(out->pool, fieldname, ": ", fieldval, CRLF, NULL);
    len = strlen(headfield);

    ap_xlate_proto_to_ascii(headfield, len);
    apr_brigade_write(out->bb, NULL, NULL, headfield, len);
#else
    struct iovec vec[4];
    struct iovec *v = vec;
    v->iov_base = (void *)fieldname;
    v->iov_len = strlen(fieldname);
    v++;
    v->iov_base = ": ";
    v->iov_len = sizeof(": ") - 1;
    v++;
    v->iov_base = (void *)fieldval;
    v->iov_len = strlen(fieldval);
    v++;
    v->iov_base = CRLF;
    v->iov_len = sizeof(CRLF) - 1;
    apr_brigade_writev(out->bb, NULL, NULL, vec, 4);
#endif /* !APR_CHARSET_EBCDIC */
    return 1;
}

/* fill "bb" with a barebones/initial HTTP response header */
static void http1_append_response_head(request_rec *r,
                                       ap_bucket_response *resp,
                                       const char *protocol,
                                       apr_bucket_brigade *bb)
{
    char *date = NULL;
    const char *proxy_date = NULL;
    const char *server = NULL;
    const char *us = ap_get_server_banner();
    const char *status_line;
    http1_out_ctx_t out;
    struct iovec vec[4];

    if (r->assbackwards) {
        /* there are no headers to send */
        return;
    }

    /* Output the HTTP/1.x Status-Line and the Date and Server fields */
    if (resp->reason) {
        status_line =  apr_psprintf(r->pool, "%d %s", resp->status, resp->reason);
    }
    else {
        status_line = ap_get_status_line_ex(r->pool, resp->status);
    }

    vec[0].iov_base = (void *)protocol;
    vec[0].iov_len  = strlen(protocol);
    vec[1].iov_base = (void *)" ";
    vec[1].iov_len  = sizeof(" ") - 1;
    vec[2].iov_base = (void *)(status_line);
    vec[2].iov_len  = strlen(status_line);
    vec[3].iov_base = (void *)CRLF;
    vec[3].iov_len  = sizeof(CRLF) - 1;
#if APR_CHARSET_EBCDIC
    {
        char *tmp;
        apr_size_t len;
        tmp = apr_pstrcatv(r->pool, vec, 4, &len);
        ap_xlate_proto_to_ascii(tmp, len);
        apr_brigade_write(bb, NULL, NULL, tmp, len);
    }
#else
    apr_brigade_writev(bb, NULL, NULL, vec, 4);
#endif

    out.pool = r->pool;
    out.bb = bb;

    /*
     * keep the set-by-proxy server and date headers, otherwise
     * generate a new server header / date header
     */
    if (r->proxyreq != PROXYREQ_NONE) {
        proxy_date = apr_table_get(resp->headers, "Date");
        if (!proxy_date) {
            /*
             * proxy_date needs to be const. So use date for the creation of
             * our own Date header and pass it over to proxy_date later to
             * avoid a compiler warning.
             */
            date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
            ap_recent_rfc822_date(date, r->request_time);
        }
        server = apr_table_get(resp->headers, "Server");
    }
    else {
        date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
        ap_recent_rfc822_date(date, r->request_time);
    }

    http1_write_header_field(&out, "Date", proxy_date ? proxy_date : date );

    if (!server && *us)
        server = us;
    if (server)
        http1_write_header_field(&out, "Server", server);

    if (APLOGrtrace3(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                      "Response sent with status %d%s",
                      r->status,
                      APLOGrtrace4(r) ? ", headers:" : "");

        /*
         * Date and Server are less interesting, use TRACE5 for them while
         * using TRACE4 for the other headers.
         */
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "  Date: %s",
                      proxy_date ? proxy_date : date );
        if (server)
            ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "  Server: %s",
                          server);
    }


    /* unset so we don't send them again */
    apr_table_unset(resp->headers, "Date");        /* Avoid bogosity */
    if (server) {
        apr_table_unset(resp->headers, "Server");
    }
}

void http1_write_response(request_rec *r,
                          ap_bucket_response *resp,
                          apr_bucket_brigade *bb)
{
    const char *proto = AP_SERVER_PROTOCOL;

    /* kludge around broken browsers when indicated by force-response-1.0
     */
    if (r->proto_num == HTTP_VERSION(1,0)
        && apr_table_get(r->subprocess_env, "force-response-1.0")) {
        r->connection->keepalive = AP_CONN_CLOSE;
        proto = "HTTP/1.0";
    }
    http1_append_response_head(r, resp, proto, bb);
    ap_http1_append_headers(bb, r, resp->headers);
    ap_http1_terminate_header(bb);
}

AP_DECLARE_NONSTD(int) ap_send_http_trace(request_rec *r)
{
    core_server_config *conf;
    int rv;
    apr_bucket_brigade *bb;
    http1_out_ctx_t out;
    apr_bucket *b;
    int body;
    char *bodyread = NULL, *bodyoff;
    apr_size_t bodylen = 0;
    apr_size_t bodybuf;
    long res = -1; /* init to avoid gcc -Wall warning */

    if (r->method_number != M_TRACE) {
        return DECLINED;
    }

    /* Get the original request */
    while (r->prev) {
        r = r->prev;
    }
    conf = ap_get_core_module_config(r->server->module_config);

    if (conf->trace_enable == AP_TRACE_DISABLE) {
        apr_table_setn(r->notes, "error-notes",
                      "TRACE denied by server configuration");
        return HTTP_METHOD_NOT_ALLOWED;
    }

    if (conf->trace_enable == AP_TRACE_EXTENDED)
        /* XXX: should be = REQUEST_CHUNKED_PASS */
        body = REQUEST_CHUNKED_DECHUNK;
    else
        body = REQUEST_NO_BODY;

    if ((rv = ap_setup_client_block(r, body))) {
        if (rv == HTTP_REQUEST_ENTITY_TOO_LARGE)
            apr_table_setn(r->notes, "error-notes",
                          "TRACE with a request body is not allowed");
        return rv;
    }

    if (ap_should_client_block(r)) {

        if (r->remaining > 0) {
            if (r->remaining > 65536) {
                apr_table_setn(r->notes, "error-notes",
                       "Extended TRACE request bodies cannot exceed 64k\n");
                return HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
            /* always 32 extra bytes to catch chunk header exceptions */
            bodybuf = (apr_size_t)r->remaining + 32;
        }
        else {
            /* Add an extra 8192 for chunk headers */
            bodybuf = 73730;
        }

        bodyoff = bodyread = apr_palloc(r->pool, bodybuf);

        /* only while we have enough for a chunked header */
        while ((!bodylen || bodybuf >= 32) &&
               (res = ap_get_client_block(r, bodyoff, bodybuf)) > 0) {
            bodylen += res;
            bodybuf -= res;
            bodyoff += res;
        }
        if (res > 0 && bodybuf < 32) {
            /* discard_rest_of_request_body into our buffer */
            while (ap_get_client_block(r, bodyread, bodylen) > 0)
                ;
            apr_table_setn(r->notes, "error-notes",
                   "Extended TRACE request bodies cannot exceed 64k\n");
            return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        if (res < 0) {
            return HTTP_BAD_REQUEST;
        }
    }

    ap_set_content_type(r, "message/http");

    /* Now we recreate the request, and echo it back */

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
#if APR_CHARSET_EBCDIC
    {
        char *tmp;
        apr_size_t len;
        len = strlen(r->the_request);
        tmp = apr_pmemdup(r->pool, r->the_request, len);
        ap_xlate_proto_to_ascii(tmp, len);
        apr_brigade_putstrs(bb, NULL, NULL, tmp, CRLF_ASCII, NULL);
    }
#else
    apr_brigade_putstrs(bb, NULL, NULL, r->the_request, CRLF, NULL);
#endif
    out.pool = r->pool;
    out.bb = bb;
    apr_table_do((int (*) (void *, const char *, const char *))
                 http1_write_header_field, (void *) &out, r->headers_in, NULL);
    apr_brigade_puts(bb, NULL, NULL, CRLF_ASCII);

    /* If configured to accept a body, echo the body */
    if (bodylen) {
        b = apr_bucket_pool_create(bodyread, bodylen,
                                   r->pool, bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
    }

    ap_pass_brigade(r->output_filters,  bb);

    return DONE;
}

typedef enum {
    rrl_none, rrl_badprotocol, rrl_badmethod, rrl_badwhitespace, rrl_excesswhitespace,
    rrl_missinguri, rrl_baduri, rrl_trailingtext,
} rrl_error;

/* get the length of a name for logging, but no more than 80 bytes */
#define LOG_NAME_MAX_LEN 80
static int log_name_len(const char *name)
{
    apr_size_t len = strlen(name);
    return (len > LOG_NAME_MAX_LEN)? LOG_NAME_MAX_LEN : (int)len;
}

static void rrl_log_error(request_rec *r, rrl_error error, char *etoken)
{
    if (error == rrl_badprotocol)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02418)
                      "HTTP Request Line; Unrecognized protocol '%.*s' "
                      "(perhaps whitespace was injected?)",
                      log_name_len(etoken), etoken);
    else if (error == rrl_badmethod)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03445)
                      "HTTP Request Line; Invalid method token: '%.*s'",
                      log_name_len(etoken), etoken);
    else if (error == rrl_missinguri)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03446)
                      "HTTP Request Line; Missing URI");
    else if (error == rrl_baduri)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03454)
                      "HTTP Request Line; URI incorrectly encoded: '%.*s'",
                      log_name_len(etoken), etoken);
    else if (error == rrl_badwhitespace)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03447)
                      "HTTP Request Line; Invalid whitespace");
    else if (error == rrl_excesswhitespace)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03448)
                      "HTTP Request Line; Excess whitespace "
                      "(disallowed by HttpProtocolOptions Strict)");
    else if (error == rrl_trailingtext)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03449)
                      "HTTP Request Line; Extraneous text found '%.*s' "
                      "(perhaps whitespace was injected?)",
                      log_name_len(etoken), etoken);
}

/* remember the first error we encountered during tokenization */
#define RRL_ERROR(e, et, y, yt)     \
    do { \
        if (e == rrl_none) {\
            e = y; et = yt;\
        }\
    } while (0)

static rrl_error tokenize_request_line(
        char *line, int strict,
        char **pmethod, char **puri, char **pprotocol,
        char **perror_token)
{
    char *method, *protocol, *uri, *ll;
    rrl_error e = rrl_none;
    char *etoken = NULL;
    apr_size_t len = 0;

    method = line;
    /* If there is whitespace before a method, skip it and mark in error */
    if (apr_isspace(*method)) {
        RRL_ERROR(e, etoken, rrl_badwhitespace, method);
        for ( ; apr_isspace(*method); ++method)
            ;
    }

    /* Scan the method up to the next whitespace, ensure it contains only
     * valid http-token characters, otherwise mark in error
     */
    if (strict) {
        ll = (char*) ap_scan_http_token(method);
    }
    else {
        ll = (char*) ap_scan_vchar_obstext(method);
    }

    if ((ll == method) || (*ll && !apr_isspace(*ll))) {
        RRL_ERROR(e, etoken, rrl_badmethod, ll);
        ll = strpbrk(ll, "\t\n\v\f\r ");
    }

    /* Verify method terminated with a single SP, or mark as specific error */
    if (!ll) {
        RRL_ERROR(e, etoken, rrl_missinguri, NULL);
        protocol = uri = "";
        goto done;
    }
    else if (strict && ll[0] && apr_isspace(ll[1])) {
        RRL_ERROR(e, etoken, rrl_excesswhitespace, ll);
    }

    /* Advance uri pointer over leading whitespace, NUL terminate the method
     * If non-SP whitespace is encountered, mark as specific error
     */
    for (uri = ll; apr_isspace(*uri); ++uri)
        if (*uri != ' ')
            RRL_ERROR(e, etoken, rrl_badwhitespace, uri);
    *ll = '\0';

    if (!*uri)
        RRL_ERROR(e, etoken, rrl_missinguri, NULL);

    /* Scan the URI up to the next whitespace, ensure it contains no raw
     * control characters, otherwise mark in error
     */
    ll = (char*) ap_scan_vchar_obstext(uri);
    if (ll == uri || (*ll && !apr_isspace(*ll))) {
        RRL_ERROR(e, etoken, rrl_baduri, ll);
        ll = strpbrk(ll, "\t\n\v\f\r ");
    }

    /* Verify URI terminated with a single SP, or mark as specific error */
    if (!ll) {
        protocol = "";
        goto done;
    }
    else if (strict && ll[0] && apr_isspace(ll[1])) {
        RRL_ERROR(e, etoken, rrl_excesswhitespace, ll);
    }

    /* Advance protocol pointer over leading whitespace, NUL terminate the uri
     * If non-SP whitespace is encountered, mark as specific error
     */
    for (protocol = ll; apr_isspace(*protocol); ++protocol)
        if (*protocol != ' ')
            RRL_ERROR(e, etoken, rrl_badwhitespace, protocol);
    *ll = '\0';

    /* Scan the protocol up to the next whitespace, validation comes later */
    if (!(ll = (char*) ap_scan_vchar_obstext(protocol))) {
        len = strlen(protocol);
        goto done;
    }
    len = ll - protocol;

    /* Advance over trailing whitespace, if found mark in error,
     * determine if trailing text is found, unconditionally mark in error,
     * finally NUL terminate the protocol string
     */
    if (*ll && !apr_isspace(*ll)) {
        RRL_ERROR(e, etoken, rrl_badprotocol, ll);
    }
    else if (strict && *ll) {
        RRL_ERROR(e, etoken, rrl_excesswhitespace, ll);
    }
    else {
        for ( ; apr_isspace(*ll); ++ll)
            if (*ll != ' ') {
                RRL_ERROR(e, etoken, rrl_badwhitespace, ll);
                break;
            }
        if (*ll)
            RRL_ERROR(e, etoken, rrl_trailingtext, ll);
    }
    *((char *)protocol + len) = '\0';

done:
    *pmethod = method;
    *puri = uri;
    *pprotocol = protocol;
    *perror_token = etoken;
    return e;
}

int http1_tokenize_request_line(
        request_rec *r, const char *line,
        char **pmethod, char **puri, char **pprotocol)
{
    core_server_config *conf = ap_get_core_module_config(r->server->module_config);
    int strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);
    rrl_error error;
    char *error_token;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                  "ap_tokenize_request_line: '%s'", line);
    error = tokenize_request_line(apr_pstrdup(r->pool, line), strict, pmethod,
                                  puri, pprotocol, &error_token);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                  "ap_tokenize_request: error=%d, method=%s, uri=%s, protocol=%s",
                  error, *pmethod, *puri, *pprotocol);
    if (error != rrl_none) {
        rrl_log_error(r, error, error_token);
        return 0;
    }
    return 1;
}

AP_DECLARE(int) ap_parse_request_line(request_rec *r)
{
    char *method, *uri, *protocol;

    return http1_tokenize_request_line(r, r->the_request,
                                       &method, &uri, &protocol)
        && ap_assign_request(r, method, uri, protocol);
}
