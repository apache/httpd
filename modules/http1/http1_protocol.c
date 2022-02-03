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


int http1_set_keepalive(request_rec *r, ap_bucket_headers *resp)
{
    int ka_sent, left, wimpy;
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
    ap_bucket_headers resp;

    memset(&resp, 0, sizeof(resp));
    resp.status = r->status;
    resp.headers = r->headers_out;
    resp.notes = r->notes;
    return http1_set_keepalive(r, &resp);
}

