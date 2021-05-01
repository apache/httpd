/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_ssl.h"

#include "mod_log_config.h"

#include "apr_strings.h"

/* jansson thinks everyone compiles with the platform's cc in its fullest capabilities
 * when undefining their INLINEs, we get static, unused functions, arg 
 */
#if defined(__GNUC__)
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunreachable-code"
#elif defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif

#include <jansson_config.h>
#undef  JSON_INLINE
#define JSON_INLINE
#include <jansson.h>

APLOG_USE_MODULE(log_json);

module AP_MODULE_DECLARE_DATA log_json_module;

static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_json_register = NULL;

static const char *crit_error =
    "{\"mod_log_json_error\": \"critical error during serialization: see error "
    "log\"}";

static int
log_json_dump_bb(const char *buffer, size_t size, void *baton)
{
    apr_bucket_brigade *bb = baton;
    apr_brigade_write(bb, NULL, NULL, buffer, size);
    return 0;
}

static const char *
log_json(request_rec *r, char *a)
{
    apr_size_t olen;
    apr_status_t rv;
    int err;
    char *out;
    apr_bucket_brigade *bb;
    json_t *obj;
    json_t *hdrs;

    obj = json_object();

    json_object_set_new_nocheck(obj, "log_id",
        r->log_id != NULL ? json_string(r->log_id) : json_null());
    json_object_set_new_nocheck(
        obj, "vhost", json_string(r->server->server_hostname));
    json_object_set_new_nocheck(
        obj, "status", json_string(apr_itoa(r->pool, r->status)));
    json_object_set_new_nocheck(obj, "proto", json_string(r->protocol));
    json_object_set_new_nocheck(obj, "method", json_string(r->method));
    json_object_set_new_nocheck(obj, "uri", json_string(r->uri));
    json_object_set_new_nocheck(obj, "srcip", json_string(r->useragent_ip));
    json_object_set_new_nocheck(obj, "bytes_sent", json_integer(r->bytes_sent));

    if (r->user != NULL) {
        json_object_set_new_nocheck(obj, "user", json_string(r->user));
    }

    hdrs = json_object();
    json_object_set_new_nocheck(hdrs, "user-agent",
        json_string(apr_table_get(r->headers_in, "User-Agent")));
    json_object_set_new_nocheck(obj, "hdrs", hdrs);

    if (ap_ssl_conn_is_ssl(r->connection)) {
        json_t *tls = json_object();

        json_object_set_new_nocheck(tls, "v",
            json_string(ap_ssl_var_lookup(
                r->pool, r->server, r->connection, r, "SSL_PROTOCOL")));
        json_object_set_new_nocheck(tls, "cipher",
            json_string(ap_ssl_var_lookup(
                r->pool, r->server, r->connection, r, "SSL_CIPHER")));
        json_object_set_new_nocheck(tls, "client_verify",
            json_string(ap_ssl_var_lookup(
                r->pool, r->server, r->connection, r, "SSL_CLIENT_VERIFY")));
        json_object_set_new_nocheck(tls, "sni",
            json_string(ap_ssl_var_lookup(
                r->pool, r->server, r->connection, r, "SSL_TLS_SNI")));

        json_object_set_new_nocheck(obj, "tls", tls);
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    err = json_dump_callback(
        obj, log_json_dump_bb, bb, JSON_ENSURE_ASCII | JSON_COMPACT);
    if (err != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            APLOGNO(10125) "json_dump_callback failed: %d", err);
        apr_brigade_destroy(bb);
        return crit_error;
    }

    rv = apr_brigade_pflatten(bb, &out, &olen, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            APLOGNO(10126) "apr_brigade_pflatten failed");
        apr_brigade_destroy(bb);
        return crit_error;
    }
    apr_brigade_destroy(bb);
    return out;
}

static int
log_json_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    log_json_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);
    log_json_register(p, "^JS", log_json, 0);
    return OK;
}

static int
log_json_post_config(
    apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    void *userdata_data = NULL;
    const char *userdata_key = "log_json_init";

    apr_pool_userdata_get(&userdata_data, userdata_key, s->process->pool);
    if (userdata_data == NULL) {
        apr_pool_userdata_set((const void *)1, userdata_key,
            apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    /* https://jansson.readthedocs.io/en/2.8/portability.html#portability-thread-safety
     */
    json_object_seed(0);

    return OK;
}

static const command_rec directives[] = {{NULL}};

static void
register_hooks(apr_pool_t *pool)
{
    ap_hook_pre_config(log_json_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(log_json_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA log_json_module = {STANDARD20_MODULE_STUFF, NULL,
    NULL, NULL, NULL, directives, register_hooks};
