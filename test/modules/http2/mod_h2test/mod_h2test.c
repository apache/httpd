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

#define SECS_PER_HOUR      (60*60)
#define SECS_PER_DAY       (24*SECS_PER_HOUR)

static apr_status_t duration_parse(apr_interval_time_t *ptimeout, const char *value,
                                   const char *def_unit)
{
    char *endp;
    apr_int64_t n;

    n = apr_strtoi64(value, &endp, 10);
    if (errno) {
        return errno;
    }
    if (!endp || !*endp) {
        if (!def_unit) def_unit = "s";
    }
    else if (endp == value) {
        return APR_EINVAL;
    }
    else {
        def_unit = endp;
    }

    switch (*def_unit) {
    case 'D':
    case 'd':
        *ptimeout = apr_time_from_sec(n * SECS_PER_DAY);
        break;
    case 's':
    case 'S':
        *ptimeout = (apr_interval_time_t) apr_time_from_sec(n);
        break;
    case 'h':
    case 'H':
        /* Time is in hours */
        *ptimeout = (apr_interval_time_t) apr_time_from_sec(n * SECS_PER_HOUR);
        break;
    case 'm':
    case 'M':
        switch (*(++def_unit)) {
        /* Time is in milliseconds */
        case 's':
        case 'S':
            *ptimeout = (apr_interval_time_t) n * 1000;
            break;
        /* Time is in minutes */
        case 'i':
        case 'I':
            *ptimeout = (apr_interval_time_t) apr_time_from_sec(n * 60);
            break;
        default:
            return APR_EGENERAL;
        }
        break;
    default:
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

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
    int i;
    apr_time_t chunk_delay = 0;
    apr_array_header_t *args = NULL;
    apr_size_t blen, fail_after = 0;
    int fail_requested = 0, error_bucket = 1;

    if (strcmp(r->handler, "h2test-echo")) {
        return DECLINED;
    }
    if (r->method_number != M_GET && r->method_number != M_POST) {
        return DECLINED;
    }

    if(r->args) {
        args = apr_cstr_split(r->args, "&", 1, r->pool);
        for(i = 0; i < args->nelts; ++i) {
            char *s, *val, *arg = APR_ARRAY_IDX(args, i, char*);
            s = strchr(arg, '=');
            if(s) {
                *s = '\0';
                val = s + 1;
                if(!strcmp("id", arg)) {
                    /* accepted, but not processed */
                    continue;
                }
                else if(!strcmp("chunk_delay", arg)) {
                    rv = duration_parse(&chunk_delay, val, "s");
                    if(APR_SUCCESS == rv) {
                        continue;
                    }
                }
                else if(!strcmp("fail_after", arg)) {
                    fail_after = (int)apr_atoi64(val);
                    if(fail_after >= 0) {
                      fail_requested = 1;
                      continue;
                    }
                }
            }
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "query parameter not "
                          "understood: '%s' in %s",
                          arg, r->args);
            ap_die(HTTP_BAD_REQUEST, r);
            return OK;
        }
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
            blen = (apr_size_t)l;
            if (fail_requested) {
              if (blen > fail_after) {
                blen = fail_after;
              }
              fail_after -= blen;
            }
            rv = apr_brigade_write(bb, NULL, NULL, buffer, blen);
            if (APR_SUCCESS != rv) goto cleanup;
            if (chunk_delay) {
                apr_sleep(chunk_delay);
            }
            rv = ap_pass_brigade(r->output_filters, bb);
            if (APR_SUCCESS != rv) goto cleanup;
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                          "echo_handler: passed %ld bytes from request body", l);
            if (fail_requested && fail_after == 0) {
              rv = APR_EINVAL;
              goto cleanup;
            }
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
    else if (error_bucket) {
        int status = ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        b = ap_bucket_error_create(status, NULL, r->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        ap_pass_brigade(r->output_filters, bb);
    }
    else {
        /* no way to know what type of error occurred */
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "h2test_echo_handler failed");
        return AP_FILTER_ERROR;
    }
    return DECLINED;
}

static int h2test_delay_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    apr_status_t rv;
    char buffer[8192];
    int i, chunks = 3;
    long l;
    apr_time_t delay = 0;

    if (strcmp(r->handler, "h2test-delay")) {
        return DECLINED;
    }
    if (r->method_number != M_GET && r->method_number != M_POST) {
        return DECLINED;
    }

    if (r->args) {
        rv = duration_parse(&delay, r->args, "s");
        if (APR_SUCCESS != rv) {
            ap_die(HTTP_BAD_REQUEST, r);
            return OK;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "delay_handler: processing request, %ds delay",
                  (int)apr_time_sec(delay));
    r->status = 200;
    r->clength = -1;
    r->chunked = 1;
    apr_table_unset(r->headers_out, "Content-Length");
    /* Discourage content-encodings */
    apr_table_unset(r->headers_out, "Content-Encoding");
    apr_table_setn(r->subprocess_env, "no-brotli", "1");
    apr_table_setn(r->subprocess_env, "no-gzip", "1");

    ap_set_content_type(r, "application/octet-stream");

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    /* copy any request body into the response */
    if ((rv = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK))) goto cleanup;
    if (ap_should_client_block(r)) {
        do {
            l = ap_get_client_block(r, &buffer[0], sizeof(buffer));
            if (l > 0) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                              "delay_handler: reading %ld bytes from request body", l);
            }
        } while (l > 0);
        if (l < 0) {
            return AP_FILTER_ERROR;
        }
    }

    memset(buffer, 0, sizeof(buffer));
    l = sizeof(buffer);
    for (i = 0; i < chunks; ++i) {
        rv = apr_brigade_write(bb, NULL, NULL, buffer, l);
        if (APR_SUCCESS != rv) goto cleanup;
        rv = ap_pass_brigade(r->output_filters, bb);
        if (APR_SUCCESS != rv) goto cleanup;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "delay_handler: passed %ld bytes as response body", l);
        if (delay) {
            apr_sleep(delay);
        }
    }
    /* we are done */
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    rv = ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "delay_handler: response passed");

cleanup:
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                  "delay_handler: request cleanup, r->status=%d, aborte=%d",
                  r->status, c->aborted);
    if (rv == APR_SUCCESS
        || r->status != HTTP_OK
        || c->aborted) {
        return OK;
    }
    return AP_FILTER_ERROR;
}

static int h2test_trailer_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    apr_status_t rv;
    char buffer[8192];
    long l;
    int body_len = 0;

    if (strcmp(r->handler, "h2test-trailer")) {
        return DECLINED;
    }
    if (r->method_number != M_GET && r->method_number != M_POST) {
        return DECLINED;
    }

    if (r->args) {
        body_len = (int)apr_atoi64(r->args);
        if (body_len < 0) body_len = 0;
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "trailer_handler: processing request, %d body length",
                  body_len);
    r->status = 200;
    r->clength = body_len;
    ap_set_content_length(r, body_len);

    ap_set_content_type(r, "application/octet-stream");
    apr_table_mergen(r->headers_out, "Trailer", "trailer-content-length");
    apr_table_set(r->trailers_out, "trailer-content-length",
                  apr_psprintf(r->pool, "%d", body_len));

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    memset(buffer, 0, sizeof(buffer));
    while (body_len > 0) {
        l = (sizeof(buffer) > body_len)? body_len : sizeof(buffer);
        body_len -= l;
        rv = apr_brigade_write(bb, NULL, NULL, buffer, l);
        if (APR_SUCCESS != rv) goto cleanup;
        rv = ap_pass_brigade(r->output_filters, bb);
        if (APR_SUCCESS != rv) goto cleanup;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "trailer_handler: passed %ld bytes as response body", l);
    }
    /* we are done */
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    rv = ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "trailer_handler: response passed");

cleanup:
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                  "trailer_handler: request cleanup, r->status=%d, aborte=%d",
                  r->status, c->aborted);
    if (rv == APR_SUCCESS
        || r->status != HTTP_OK
        || c->aborted) {
        return OK;
    }
    return AP_FILTER_ERROR;
}

static int status_from_str(const char *s, apr_status_t *pstatus)
{
    if (!strcmp("timeout", s)) {
        *pstatus = APR_TIMEUP;
        return 1;
    }
    else if (!strcmp("reset", s)) {
        *pstatus = APR_ECONNRESET;
        return 1;
    }
    return 0;
}

static int h2test_error_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    apr_status_t rv;
    char buffer[8192];
    int i, chunks = 3, error_bucket = 1;
    long l;
    apr_time_t delay = 0, body_delay = 0;
    apr_array_header_t *args = NULL;
    int http_status = 200;
    apr_status_t error = APR_SUCCESS, body_error = APR_SUCCESS;

    if (strcmp(r->handler, "h2test-error")) {
        return DECLINED;
    }
    if (r->method_number != M_GET && r->method_number != M_POST) {
        return DECLINED;
    }

    if (r->args) {
        args = apr_cstr_split(r->args, "&", 1, r->pool);
        for (i = 0; i < args->nelts; ++i) {
            char *s, *val, *arg = APR_ARRAY_IDX(args, i, char*);
            s = strchr(arg, '=');
            if (s) {
                *s = '\0';
                val = s + 1;
                if (!strcmp("status", arg)) {
                    http_status = (int)apr_atoi64(val);
                    if (val > 0) {
                        continue;
                    }
                }
                else if (!strcmp("error", arg)) {
                    if (status_from_str(val, &error)) {
                        continue;
                    }
                }
                else if (!strcmp("error_bucket", arg)) {
                    error_bucket = (int)apr_atoi64(val);
                    if (val >= 0) {
                        continue;
                    }
                }
                else if (!strcmp("body_error", arg)) {
                    if (status_from_str(val, &body_error)) {
                        continue;
                    }
                }
                else if (!strcmp("delay", arg)) {
                    rv = duration_parse(&delay, val, "s");
                    if (APR_SUCCESS == rv) {
                        continue;
                    }
                }
                else if (!strcmp("body_delay", arg)) {
                    rv = duration_parse(&body_delay, val, "s");
                    if (APR_SUCCESS == rv) {
                        continue;
                    }
                }
            }
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "error_handler: "
                  "did not understand '%s'", arg);
            ap_die(HTTP_BAD_REQUEST, r);
            return OK;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "error_handler: processing request, %s",
                  r->args? r->args : "(no args)");
    r->status = http_status;
    r->clength = -1;
    r->chunked = 1;
    apr_table_unset(r->headers_out, "Content-Length");
    /* Discourage content-encodings */
    apr_table_unset(r->headers_out, "Content-Encoding");
    apr_table_setn(r->subprocess_env, "no-brotli", "1");
    apr_table_setn(r->subprocess_env, "no-gzip", "1");

    ap_set_content_type(r, "application/octet-stream");
    bb = apr_brigade_create(r->pool, c->bucket_alloc);

    if (delay) {
        apr_sleep(delay);
    }
    if (error != APR_SUCCESS) {
        return ap_map_http_request_error(error, HTTP_BAD_REQUEST);
    }
    /* flush response */
    b = apr_bucket_flush_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    rv = ap_pass_brigade(r->output_filters, bb);
    if (APR_SUCCESS != rv) goto cleanup;

    memset(buffer, 'X', sizeof(buffer));
    l = sizeof(buffer);
    for (i = 0; i < chunks; ++i) {
        if (body_delay) {
            apr_sleep(body_delay);
        }
        rv = apr_brigade_write(bb, NULL, NULL, buffer, l);
        if (APR_SUCCESS != rv) goto cleanup;
        rv = ap_pass_brigade(r->output_filters, bb);
        if (APR_SUCCESS != rv) goto cleanup;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "error_handler: passed %ld bytes as response body", l);
        if (body_error != APR_SUCCESS) {
            rv = body_error;
            goto cleanup;
        }
    }
    /* we are done */
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    rv = ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "error_handler: response passed");

cleanup:
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                  "error_handler: request cleanup, r->status=%d, aborted=%d",
                  r->status, c->aborted);
    if (rv == APR_SUCCESS) {
        return OK;
    }
    if (error_bucket) {
        http_status = ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        b = ap_bucket_error_create(http_status, NULL, r->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        ap_pass_brigade(r->output_filters, bb);
    }
    return AP_FILTER_ERROR;
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

    /* test h2 handlers */
    ap_hook_handler(h2test_echo_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(h2test_delay_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(h2test_trailer_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(h2test_error_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

