/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>

#include <apr_strings.h>
#include <apr_optional.h>
#include <apr_optional_hooks.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_log.h>

#include "h2_private.h"

#include "h2_stream.h"
#include "h2_task.h"
#include "h2_config.h"
#include "h2_ctx.h"
#include "h2_conn.h"
#include "h2_alpn.h"
#include "h2_h2.h"

const char *h2_alpn_protos[] = {
    "h2", "h2-16", "h2-14"
};
apr_size_t h2_alpn_protos_len = (sizeof(h2_alpn_protos)
                                 / sizeof(h2_alpn_protos[0]));

const char *h2_upgrade_protos[] = {
    "h2c", "h2c-16", "h2c-14",
};
apr_size_t h2_upgrade_protos_len = (sizeof(h2_upgrade_protos)
                                    / sizeof(h2_upgrade_protos[0]));

const char *H2_MAGIC_TOKEN = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/*******************************************************************************
 * The optional mod_ssl functions we need. 
 */
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec*));
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec*));

static int (*opt_ssl_engine_disable)(conn_rec*);
static int (*opt_ssl_is_https)(conn_rec*);
/*******************************************************************************
 * Hooks for processing incoming connections:
 * - pre_conn_before_tls switches SSL off for stream connections
 * - process_conn take over connection in case of h2
 */
static int h2_h2_process_conn(conn_rec* c);
static int h2_h2_remove_timeout(conn_rec* c);
static int h2_h2_post_read_req(request_rec *r);


/*******************************************************************************
 * Once per lifetime init, retrieve optional functions
 */
apr_status_t h2_h2_init(apr_pool_t *pool, server_rec *s)
{
    (void)pool;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "h2_h2, child_init");
    opt_ssl_engine_disable = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_disable);
    opt_ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
    
    if (!opt_ssl_is_https) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "mod_ssl does not seem to be enabled");
    }
    
    return APR_SUCCESS;
}

int h2_h2_is_tls(conn_rec *c)
{
    return opt_ssl_is_https && opt_ssl_is_https(c);
}

int h2_tls_disable(conn_rec *c)
{
    if (opt_ssl_engine_disable) {
        return opt_ssl_engine_disable(c);
    }
    return 0;
}

/*******************************************************************************
 * Register various hooks
 */
static const char *const mod_reqtimeout[] = { "reqtimeout.c", NULL};

void h2_h2_register_hooks(void)
{
    /* When the connection processing actually starts, we might to
     * take over, if h2* was selected by ALPN on a TLS connection.
     */
    ap_hook_process_connection(h2_h2_process_conn, 
                               NULL, NULL, APR_HOOK_FIRST);
    /* Perform connection cleanup before the actual processing happens.
     */
    ap_hook_process_connection(h2_h2_remove_timeout, 
                               mod_reqtimeout, NULL, APR_HOOK_LAST);
    
    ap_hook_post_read_request(h2_h2_post_read_req, NULL, NULL, APR_HOOK_MIDDLE);
}

int h2_h2_remove_timeout(conn_rec* c)
{
    h2_ctx *ctx = h2_ctx_get(c);
    
    if (h2_ctx_is_task(ctx)) {
        /* cleanup on task connections */
        /* we once removed the reqtimeout filter on task connections,
         * but timeouts here might have been a side effect of other things.
         * Ideally mod_reqtimeout would do its work on task connections
         * as it basically is a HTTP/1.1 request/response and it's made
         * for that.
         * So, let the filter stay for now and see if we ever encounter
         * unexpected timeouts on tasks again.
         */
        //ap_remove_input_filter_byhandle(c->input_filters, "reqtimeout");
    }
    else if (h2_ctx_is_active(ctx)) {
        /* cleanup on master h2 connections */
        ap_remove_input_filter_byhandle(c->input_filters, "reqtimeout");
    }
    
    return DECLINED;
}

int h2_h2_process_conn(conn_rec* c)
{
    h2_ctx *ctx = h2_ctx_get(c);
    h2_config *cfg = h2_config_get(c);
    apr_bucket_brigade* temp;

    if (h2_ctx_is_task(ctx)) {
        /* out stream pseudo connection */
        return DECLINED;
    }

    /* Protocol negoation, if started, may need some speculative reading
     * to get triggered.
     */
    if (h2_ctx_pnego_is_ongoing(ctx)) {
        temp = apr_brigade_create(c->pool, c->bucket_alloc);
        ap_get_brigade(c->input_filters, temp,
                       AP_MODE_SPECULATIVE, APR_BLOCK_READ, 1);
        apr_brigade_destroy(temp);
    }

    /* If we still do not know the protocol and H2Direct is enabled, check
     * if we receive the magic PRIamble. A client sending this on connection
     * start should know what it is doing.
     */
    if (!h2_ctx_pnego_is_done(ctx) && h2_config_geti(cfg, H2_CONF_DIRECT)) {
        apr_status_t status;
        temp = apr_brigade_create(c->pool, c->bucket_alloc);
        status = ap_get_brigade(c->input_filters, temp,
                                AP_MODE_SPECULATIVE, APR_BLOCK_READ, 24);
        if (status == APR_SUCCESS) {
            char *s = NULL;
            apr_size_t slen;
            
            apr_brigade_pflatten(temp, &s, &slen, c->pool);
            if ((slen == 24) && !memcmp(H2_MAGIC_TOKEN, s, 24)) {
                h2_ctx_pnego_set_done(ctx, "h2");
            }
        }
        apr_brigade_destroy(temp);
    }

    /* If "h2" was selected as protocol (by whatever mechanism), take over
     * the connection.
     */
    if (h2_ctx_is_active(ctx)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                      "h2_h2, connection, h2 active");
        
        return h2_conn_main(c);
    }
    
    return DECLINED;
}

static int h2_h2_post_read_req(request_rec *r)
{
    h2_ctx *ctx = h2_ctx_rget(r);
    struct h2_task_env *env = h2_ctx_get_task(ctx);
    if (env) {
        /* h2_task connection for a stream, not for h2c */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "adding h1_to_h2_resp output filter");
        if (env->serialize_headers) {
            ap_add_output_filter("H1_TO_H2_RESP", env, r, r->connection);
        }
        else {
            /* replace the core http filter that formats response headers
             * in HTTP/1 with our own that collects status and headers */
            ap_remove_output_filter_byhandle(r->output_filters, "HTTP_HEADER");
            ap_add_output_filter("H2_RESPONSE", env, r, r->connection);
        }
    }
    return DECLINED;
}


