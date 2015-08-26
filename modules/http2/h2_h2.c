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
#include "h2_h2.h"

const char *h2_tls_protos[] = {
    "h2", NULL
};

const char *h2_clear_protos[] = {
    "h2c", NULL
};

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
                     APLOGNO(02951) "mod_ssl does not seem to be enabled");
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
     * take over, if h2* was selected as protocol.
     */
    ap_hook_process_connection(h2_h2_process_conn, 
                               NULL, NULL, APR_HOOK_FIRST);
    /* Perform connection cleanup before the actual processing happens.
     */
    ap_hook_process_connection(h2_h2_remove_timeout, 
                               mod_reqtimeout, NULL, APR_HOOK_LAST);
    
    /* With "H2SerializeHeaders On", we install the filter in this hook
     * that parses the response. This needs to happen before any other post
     * read function terminates the request with an error. Otherwise we will
     * never see the response.
     */
    ap_hook_post_read_request(h2_h2_post_read_req, NULL, NULL, APR_HOOK_REALLY_FIRST);
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
    int is_tls = h2_h2_is_tls(c);
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "h2_h2, process_conn");
    if (h2_ctx_is_task(ctx)) {
        /* our stream pseudo connection */
        return DECLINED;
    }

    /* If we have not already switched to a h2* protocol and the connection 
     * is on "http/1.1"
     * -> sniff for the magic PRIamble. On TLS, this might trigger the ALPN.
     */
    if (!h2_ctx_protocol_get(c) 
        && !strcmp(AP_PROTOCOL_HTTP1, ap_get_protocol(c))) {
        apr_status_t status;
        
        temp = apr_brigade_create(c->pool, c->bucket_alloc);
        status = ap_get_brigade(c->input_filters, temp,
                                AP_MODE_SPECULATIVE, APR_BLOCK_READ, 24);

        if (status == APR_SUCCESS) {
            if (h2_ctx_protocol_get(c) 
                || strcmp(AP_PROTOCOL_HTTP1, ap_get_protocol(c))) {
                /* h2 or another protocol has been selected. */
            }
            else {
                /* ALPN might have been triggered, but we're still on
                 * http/1.1. Check the actual bytes read for the H2 Magic
                 * Token, *if* H2Direct mode is enabled here. 
                 */
                int direct_mode = h2_config_geti(cfg, H2_CONF_DIRECT);
                if (direct_mode > 0 || (direct_mode < 0 && !is_tls)) {
                    char *s = NULL;
                    apr_size_t slen;
                    
                    apr_brigade_pflatten(temp, &s, &slen, c->pool);
                    if ((slen >= 24) && !memcmp(H2_MAGIC_TOKEN, s, 24)) {
                        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                                      "h2_h2, direct mode detected");
                        h2_ctx_protocol_set(ctx, is_tls? "h2" : "h2c");
                    }
                    else {
                        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                                      "h2_h2, not detected in %d bytes: %s", 
                                      (int)slen, s);
                    }
                }
            }
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c,
                          "h2_h2, error reading 24 bytes speculative");
        }
        apr_brigade_destroy(temp);
    }

    /* If "h2" was selected as protocol (by whatever mechanism), take over
     * the connection.
     */
    if (h2_ctx_is_active(ctx)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_h2, connection, h2 active");
        
        return h2_conn_main(c);
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "h2_h2, declined");
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
            ap_remove_output_filter_byhandle(r->output_filters, "H1_TO_H2_RESP");
            ap_add_output_filter("H1_TO_H2_RESP", env, r, r->connection);
        }
        else {
            /* replace the core http filter that formats response headers
             * in HTTP/1 with our own that collects status and headers */
            ap_remove_output_filter_byhandle(r->output_filters, "HTTP_HEADER");
            ap_remove_output_filter_byhandle(r->output_filters, "H2_RESPONSE");
            ap_add_output_filter("H2_RESPONSE", env, r, r->connection);
        }
    }
    return DECLINED;
}


