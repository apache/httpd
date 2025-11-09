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

#include <apr_optional.h>
#include <apr_optional_hooks.h>
#include <apr_strings.h>
#include <apr_cstr.h>
#include <apr_time.h>
#include <apr_want.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

static void h1test_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(h1test) = {
    STANDARD20_MODULE_STUFF,
    NULL, /* func to create per dir config */
    NULL,  /* func to merge per dir config */
    NULL, /* func to create per server config */
    NULL,  /* func to merge per server config */
    NULL,              /* command handlers */
    h1test_hooks,
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};


static int h1test_echo_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    apr_status_t rv;
    char buffer[8192];
    const char *ct;
    long l;

    if (strcmp(r->handler, "h1test-echo")) {
        return DECLINED;
    }
    if (r->method_number != M_GET && r->method_number != M_POST) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "echo_handler: processing request");
    r->status = 200;
    r->clength = -1;
    r->chunked = 1;
    ct = apr_table_get(r->headers_in, "content-type");
    ap_set_content_type(r, ct? ct : "application/octet-stream");

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    /* copy any request body into the response */
    if ((rv = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK))) goto cleanup;
    if (ap_should_client_block(r)) {
        while (0 < (l = ap_get_client_block(r, &buffer[0], sizeof(buffer)))) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                          "echo_handler: copying %ld bytes from request body", l);
            rv = apr_brigade_write(bb, NULL, NULL, buffer, l);
            if (APR_SUCCESS != rv) goto cleanup;
            rv = ap_pass_brigade(r->output_filters, bb);
            if (APR_SUCCESS != rv) goto cleanup;
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                          "echo_handler: passed %ld bytes from request body", l);
        }
    }
    /* we are done */
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "echo_handler: request read");

    if (r->trailers_in && !apr_is_empty_table(r->trailers_in)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "echo_handler: seeing incoming trailers");
        apr_table_setn(r->trailers_out, "h1test-trailers-in",
                       apr_itoa(r->pool, 1));
    }
    if (apr_table_get(r->headers_in, "Add-Trailer")) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "echo_handler: seeing incoming Add-Trailer header");
        apr_table_setn(r->trailers_out, "h1test-add-trailer",
                       apr_table_get(r->headers_in, "Add-Trailer"));
    }

    rv = ap_pass_brigade(r->output_filters, bb);

cleanup:
    if (rv == APR_SUCCESS
        || r->status != HTTP_OK
        || c->aborted) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "echo_handler: request handled");
        return OK;
    }
    else {
        /* no way to know what type of error occurred */
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "h1test_echo_handler failed");
        return AP_FILTER_ERROR;
    }
    return DECLINED;
}


/* Install this module into the apache2 infrastructure.
 */
static void h1test_hooks(apr_pool_t *pool)
{
    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks and handlers");

    /* test h1 handlers */
    ap_hook_handler(h1test_echo_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

