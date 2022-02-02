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
 * http_filter.c --- HTTP routines which either filters or deal with filters.
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
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "apr_date.h"           /* For apr_date_parse_http and APR_DATE_BAD */
#include "util_charset.h"
#include "util_ebcdic.h"
#include "util_time.h"

#include "mod_core.h"
#include "mod_http1.h"


APLOG_USE_MODULE(http1);


/* Send a request's HTTP response headers to the client.
 */
apr_status_t http1_append_headers(apr_bucket_brigade *bb,
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

void http1_terminate_header(apr_bucket_brigade *bb)
{
    char crlf[] = CRLF;
    apr_size_t buflen;

    buflen = strlen(crlf);
    ap_xlate_proto_to_ascii(crlf, buflen);
    apr_brigade_write(bb, NULL, NULL, crlf, buflen);
}

typedef struct header_struct {
    apr_pool_t *pool;
    apr_bucket_brigade *bb;
} header_struct;

/* Send a single HTTP header field to the client.  Note that this function
 * is used in calls to apr_table_do(), so don't change its interface.
 * It returns true unless there was a write error of some kind.
 */
static int form_header_field(header_struct *h,
                             const char *fieldname, const char *fieldval)
{
#if APR_CHARSET_EBCDIC
    char *headfield;
    apr_size_t len;

    headfield = apr_pstrcat(h->pool, fieldname, ": ", fieldval, CRLF, NULL);
    len = strlen(headfield);

    ap_xlate_proto_to_ascii(headfield, len);
    apr_brigade_write(h->bb, NULL, NULL, headfield, len);
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
    apr_brigade_writev(h->bb, NULL, NULL, vec, 4);
#endif /* !APR_CHARSET_EBCDIC */
    return 1;
}

/* fill "bb" with a barebones/initial HTTP response header */
static void append_http1_response_head(request_rec *r,
                                       ap_bucket_headers *resp,
                                       const char *protocol,
                                       apr_bucket_brigade *bb)
{
    char *date = NULL;
    const char *proxy_date = NULL;
    const char *server = NULL;
    const char *us = ap_get_server_banner();
    const char *status_line;
    header_struct h;
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

    h.pool = r->pool;
    h.bb = bb;

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

    form_header_field(&h, "Date", proxy_date ? proxy_date : date );

    if (!server && *us)
        server = us;
    if (server)
        form_header_field(&h, "Server", server);

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

static void append_http1_response(request_rec *r,
                                  ap_bucket_headers *resp,
                                  apr_bucket_brigade *b)
{
    const char *proto = AP_SERVER_PROTOCOL;

    /* kludge around broken browsers when indicated by force-response-1.0
     */
    if (r->proto_num == HTTP_VERSION(1,0)
        && apr_table_get(r->subprocess_env, "force-response-1.0")) {
        r->connection->keepalive = AP_CONN_CLOSE;
        proto = "HTTP/1.0";
    }
    append_http1_response_head(r, resp, proto, b);
    http1_append_headers(b, r, resp->headers);
    http1_terminate_header(b);
}


typedef struct response_filter_ctx {
    int final_response_sent;    /* strict: a response status >= 200 was sent */
    int discard_body;           /* the response is header only, discard body */
    apr_bucket_brigade *tmpbb;
} response_filter_ctx;

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http1_transcode_out_filter(ap_filter_t *f,
                                                                   apr_bucket_brigade *b)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *e, *next = NULL;
    response_filter_ctx *ctx = f->ctx;
    apr_status_t rv = APR_SUCCESS;
    core_server_config *conf = ap_get_core_module_config(r->server->module_config);
    int strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);

    AP_DEBUG_ASSERT(!r->main);

    if (!ctx) {
        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    }

    for (e = APR_BRIGADE_FIRST(b);
         e != APR_BRIGADE_SENTINEL(b);
         e = next)
    {
        next = APR_BUCKET_NEXT(e);

        if (APR_BUCKET_IS_METADATA(e)) {

            if (APR_BUCKET_IS_EOS(e)) {
                if (!ctx->final_response_sent) {
                    /* should not happen. do we generate a 500 here? */
                }
                ap_remove_output_filter(f);
                goto pass;
            }
            else if (AP_BUCKET_IS_HEADERS(e)) {
                ap_bucket_headers *resp = e->data;

                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                              "ap_http1_transcode_out_filter seeing headers bucket status=%d",
                              resp->status);
                if (!resp->status) {
                    /* footer, is either processed in chunk filter
                     * or ignored otherwise. never processed here. */
                }
                else if (strict && resp->status < 100) {
                    /* error, not a valid http status */
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                                  "ap_http1_transcode_out_filter seeing headers "
                                  "status=%d in strict mode",
                                  resp->status);
                    rv = AP_FILTER_ERROR;
                    goto cleanup;
                }
                else if (ctx->final_response_sent) {
                    /* already sent the final response for the request.
                     */
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                                  "ap_http1_transcode_out_filter seeing headers "
                                  "status=%d after final response already sent",
                                  resp->status);
                    rv = AP_FILTER_ERROR;
                    goto cleanup;
                }
                else {
                    /* a response status to transcode, might be final or interim
                     */
                    ctx->final_response_sent = (resp->status >= 200)
                        || (!strict && resp->status < 100);
                    ctx->discard_body = ctx->final_response_sent &&
                        (r->header_only || AP_STATUS_IS_HEADER_ONLY(resp->status));

                    if (!ctx->tmpbb) {
                        ctx->tmpbb = apr_brigade_create(r->pool, c->bucket_alloc);
                    }
                    if (next != APR_BRIGADE_SENTINEL(b)) {
                        apr_brigade_split_ex(b, next, ctx->tmpbb);
                    }

                    if (ctx->final_response_sent) {
                        http1_set_keepalive(r, resp);

                        if (AP_STATUS_IS_HEADER_ONLY(resp->status)) {
                            apr_table_unset(resp->headers, "Transfer-Encoding");
                        }
                        else if (r->chunked) {
                            apr_table_mergen(resp->headers, "Transfer-Encoding", "chunked");
                            apr_table_unset(resp->headers, "Content-Length");
                        }
                    }

                    append_http1_response(r, resp, b);
                    apr_bucket_delete(e);

                    if (ctx->final_response_sent && r->chunked) {
                        /* We can't add this filter until we have already sent the headers.
                         * If we add it before this point, then the headers will be chunked
                         * as well, and that is just wrong.
                         */
                        rv = ap_pass_brigade(f->next, b);
                        apr_brigade_cleanup(b);
                        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, rv, r,
                                      "ap_http1_transcode_out_filter passed response"
                                      ", add CHUNK filter");
                        if (APR_SUCCESS != rv) {
                            apr_brigade_cleanup(ctx->tmpbb);
                            goto cleanup;
                        }
                        ap_add_output_filter("CHUNK", NULL, r, r->connection);
                    }

                    APR_BRIGADE_CONCAT(b, ctx->tmpbb);
                }
            }
        }
        else if (!ctx->final_response_sent && strict) {
            /* data buckets before seeing the final response are in error.
             */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "ap_http1_transcode_out_filter seeing data before headers, %ld bytes ",
                          (long)e->length);
            rv = AP_FILTER_ERROR;
            goto cleanup;
        }
        else if (ctx->discard_body) {
            apr_bucket_delete(e);
        }
    }

pass:
    rv = ap_pass_brigade(f->next, b);
cleanup:
    return rv;
}

AP_DECLARE_NONSTD(int) ap_send_http_trace(request_rec *r)
{
    core_server_config *conf;
    int rv;
    apr_bucket_brigade *bb;
    header_struct h;
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
    h.pool = r->pool;
    h.bb = bb;
    apr_table_do((int (*) (void *, const char *, const char *))
                 form_header_field, (void *) &h, r->headers_in, NULL);
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
