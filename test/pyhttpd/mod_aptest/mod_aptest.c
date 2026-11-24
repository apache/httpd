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
#include <apr_want.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

static void aptest_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(aptest) = {
    STANDARD20_MODULE_STUFF,
    NULL, /* func to create per dir config */
    NULL,  /* func to merge per dir config */
    NULL, /* func to create per server config */
    NULL,  /* func to merge per server config */
    NULL,              /* command handlers */
    aptest_hooks,
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};


static int aptest_post_read_request(request_rec *r)
{
    const char *test_name = apr_table_get(r->headers_in, "AP-Test-Name");
    if (test_name) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "test[%s]: %s",
                      test_name, r->the_request);
    }
    return DECLINED;
}

/*
 * Register the methods named in an "AP-Test-Allow-Methods" request header
 * via ap_allow_methods(), so a test can check how they are reflected in the
 * Allow response header.
 */
static int aptest_allow_methods(request_rec *r)
{
    const char *methods = apr_table_get(r->headers_in, "AP-Test-Allow-Methods");
    char *list, *name, *last;

    if (methods == NULL) {
        return DECLINED;
    }

    list = apr_pstrdup(r->pool, methods);
    for (name = apr_strtok(list, ", ", &last); name != NULL;
         name = apr_strtok(NULL, ", ", &last)) {
        ap_allow_methods(r, MERGE_ALLOW, name, NULL);
    }

    return DECLINED;
}

/*
 * Handler "aptest-getline-echo": echo the request body back, reading it
 * with AP_MODE_GETLINE rather than AP_MODE_READBYTES.  The Content-Length
 * request header left once the body has been read, if any, is returned in
 * an "AP-Test-Content-Length" response header.
 */
static int aptest_getline_echo(request_rec *r)
{
    apr_bucket_brigade *bb, *body;
    const char *clen;
    char *data;
    apr_size_t len;
    apr_status_t rv;
    int seen_eos = 0;

    if (strcmp(r->handler, "aptest-getline-echo")) {
        return DECLINED;
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    body = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    while (!seen_eos) {
        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_GETLINE,
                            APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "aptest-getline-echo: reading body failed");
            return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        }
        if (!APR_BRIGADE_EMPTY(bb)
            && APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
            seen_eos = 1;
        }
        rv = apr_brigade_pflatten(bb, &data, &len, r->pool);
        if (rv == APR_SUCCESS) {
            rv = apr_brigade_write(body, NULL, NULL, data, len);
        }
        if (rv != APR_SUCCESS) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_brigade_cleanup(bb);
    }

    clen = apr_table_get(r->headers_in, "Content-Length");
    if (clen) {
        apr_table_setn(r->headers_out, "AP-Test-Content-Length", clen);
    }
    ap_set_content_type(r, "text/plain");
    if (apr_brigade_pflatten(body, &data, &len, r->pool) != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_rwrite(data, len, r);

    return OK;
}

/* Install this module into the apache2 infrastructure.
 */
static void aptest_hooks(apr_pool_t *pool)
{
    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool,
                  "installing hooks and handlers");

    /* test case monitoring */
    ap_hook_post_read_request(aptest_post_read_request, NULL,
                              NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(aptest_allow_methods, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(aptest_getline_echo, NULL, NULL, APR_HOOK_MIDDLE);

}

