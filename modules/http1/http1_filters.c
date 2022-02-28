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



typedef struct response_filter_ctx {
    int final_response_sent;    /* strict: a response status >= 200 was sent */
    int discard_body;           /* the response is header only, discard body */
    apr_bucket_brigade *tmpbb;
} response_filter_ctx;

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http1_response_out_filter(ap_filter_t *f,
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

                    http1_write_response(r, resp, b);
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

