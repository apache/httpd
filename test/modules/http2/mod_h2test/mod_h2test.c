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
#include <apr_time.h>
#include <apr_want.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include "mod_h2test.h"

static void h2test_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(h2test) = {
    STANDARD20_MODULE_STUFF,
    NULL, /* func to create per dir config */
    NULL,  /* func to merge per dir config */
    NULL, /* func to create per server config */
    NULL,  /* func to merge per server config */
    NULL,              /* command handlers */
    h2test_hooks,
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};


static int h2test_post_config(apr_pool_t *p, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    const char *mod_h2_init_key = "mod_h2test_init_counter";
    
    (void)plog;(void)ptemp;

    apr_pool_userdata_get(&data, mod_h2_init_key, s->process->pool);
    if ( data == NULL ) {
        /* dry run */
        apr_pool_userdata_set((const void *)1, mod_h2_init_key,
                              apr_pool_cleanup_null, s->process->pool);
        return APR_SUCCESS;
    }
    
    
    return APR_SUCCESS;
}

static void h2test_child_init(apr_pool_t *pool, server_rec *s)
{
    (void)pool;
    (void)s;
}

static int h2test_echo_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    apr_status_t rv;
    char buffer[8192];
    const char *ct;
    long l;
    
    if (strcmp(r->handler, "h2test-echo")) {
        return DECLINED;
    }
    if (r->method_number != M_GET && r->method_number != M_POST) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "echo_handler: processing request");
    r->status = 200;
    r->clength = -1;
    r->chunked = 1;
    apr_table_unset(r->headers_out, "Content-Length");
    /* Discourage content-encodings */
    apr_table_unset(r->headers_out, "Content-Encoding");
    apr_table_setn(r->subprocess_env, "no-brotli", "1");
    apr_table_setn(r->subprocess_env, "no-gzip", "1");

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
        apr_table_setn(r->trailers_out, "h2test-trailers-in", 
                       apr_itoa(r->pool, 1));
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
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "h2test_echo_handler failed");
        return AP_FILTER_ERROR;
    }
    return DECLINED;
}

/* Install this module into the apache2 infrastructure.
 */
static void h2test_hooks(apr_pool_t *pool)
{
    static const char *const mod_h2[] = { "mod_h2.c", NULL};
    
    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks and handlers");
    
    /* Run once after configuration is set, but before mpm children initialize.
     */
    ap_hook_post_config(h2test_post_config, mod_h2, NULL, APR_HOOK_MIDDLE);
    
    /* Run once after a child process has been created.
     */
    ap_hook_child_init(h2test_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    /* test h2 echo handler */
    ap_hook_handler(h2test_echo_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

