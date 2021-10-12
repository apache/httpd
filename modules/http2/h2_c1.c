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
 
#include <assert.h>
#include <apr_strings.h>

#include <ap_mpm.h>
#include <ap_mmn.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_ssl.h>

#include <mpm_common.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_bucket_beam.h"
#include "h2_config.h"
#include "h2_conn_ctx.h"
#include "h2_headers.h"
#include "h2_mplx.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_protocol.h"
#include "h2_workers.h"
#include "h2_c1.h"
#include "h2_version.h"
#include "h2_util.h"

static struct h2_workers *workers;

static int async_mpm;

apr_status_t h2_c1_child_init(apr_pool_t *pool, server_rec *s)
{
    apr_status_t status = APR_SUCCESS;
    int minw, maxw;
    int max_threads_per_child = 0;
    int idle_secs = 0;

    ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads_per_child);
    
    status = ap_mpm_query(AP_MPMQ_IS_ASYNC, &async_mpm);
    if (status != APR_SUCCESS) {
        /* some MPMs do not implemnent this */
        async_mpm = 0;
        status = APR_SUCCESS;
    }

    h2_config_init(pool);

    h2_get_num_workers(s, &minw, &maxw);
    idle_secs = h2_config_sgeti(s, H2_CONF_MAX_WORKER_IDLE_SECS);
    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
                 "h2_workers: min=%d max=%d, mthrpchild=%d, idle_secs=%d", 
                 minw, maxw, max_threads_per_child, idle_secs);
    workers = h2_workers_create(s, pool, minw, maxw, idle_secs);
 
    return h2_mplx_c1_child_init(pool, s);
}

void h2_c1_child_stopping(apr_pool_t *pool, int graceful)
{
    if (workers && graceful) {
        h2_workers_graceful_shutdown(workers);
    }
}


apr_status_t h2_c1_setup(conn_rec *c, request_rec *r, server_rec *s)
{
    h2_session *session;
    h2_conn_ctx_t *ctx;
    apr_status_t rv;
    
    if (!workers) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02911) 
                      "workers not initialized");
        rv = APR_EGENERAL;
        goto cleanup;
    }

    rv = h2_session_create(&session, c, r, s, workers);
    if (APR_SUCCESS != rv) goto cleanup;

    ctx = h2_conn_ctx_get(c);
    ap_assert(ctx);
    ctx->session = session;
    /* remove the input filter of mod_reqtimeout, now that the connection
     * is established and we have switched to h2. reqtimeout has supervised
     * possibly configured handshake timeouts and needs to get out of the way
     * now since the rest of its state handling assumes http/1.x to take place. */
    ap_remove_input_filter_byhandle(c->input_filters, "reqtimeout");

cleanup:
    return rv;
}

apr_status_t h2_c1_run(conn_rec *c)
{
    apr_status_t status;
    int mpm_state = 0;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);
    
    ap_assert(conn_ctx);
    ap_assert(conn_ctx->session);
    do {
        if (c->cs) {
            c->cs->sense = CONN_SENSE_DEFAULT;
            c->cs->state = CONN_STATE_HANDLER;
        }
    
        status = h2_session_process(conn_ctx->session, async_mpm);
        
        if (APR_STATUS_IS_EOF(status)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c, 
                          H2_SSSN_LOG(APLOGNO(03045), conn_ctx->session,
                          "process, closing conn"));
            c->keepalive = AP_CONN_CLOSE;
        }
        else {
            c->keepalive = AP_CONN_KEEPALIVE;
        }
        
        if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state)) {
            break;
        }
    } while (!async_mpm
             && c->keepalive == AP_CONN_KEEPALIVE 
             && mpm_state != AP_MPMQ_STOPPING);

    if (c->cs) {
        switch (conn_ctx->session->state) {
            case H2_SESSION_ST_INIT:
            case H2_SESSION_ST_IDLE:
            case H2_SESSION_ST_BUSY:
            case H2_SESSION_ST_WAIT:
                c->cs->state = CONN_STATE_WRITE_COMPLETION;
                if (c->cs && !conn_ctx->session->remote.emitted_count) {
                    /* let the MPM know that we are not done and want
                     * the Timeout behaviour instead of a KeepAliveTimeout
                     * See PR 63534. 
                     */
                    c->cs->sense = CONN_SENSE_WANT_READ;
                }
                break;
            case H2_SESSION_ST_CLEANUP:
            case H2_SESSION_ST_DONE:
            default:
                c->cs->state = CONN_STATE_LINGER;
            break;
        }
    }

    return APR_SUCCESS;
}

apr_status_t h2_c1_pre_close(struct h2_conn_ctx_t *ctx, conn_rec *c)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);

    if (conn_ctx && conn_ctx->session) {
        apr_status_t status = h2_session_pre_close(conn_ctx->session, async_mpm);
        return (status == APR_SUCCESS)? DONE : status;
    }
    return DONE;
}

int h2_c1_allows_direct(conn_rec *c)
{
    if (!c->master) {
        int is_tls = ap_ssl_conn_is_ssl(c);
        const char *needed_protocol = is_tls? "h2" : "h2c";
        int h2_direct = h2_config_cgeti(c, H2_CONF_DIRECT);

        if (h2_direct < 0) {
            h2_direct = is_tls? 0 : 1;
        }
        return (h2_direct && ap_is_allowed_protocol(c, NULL, NULL, needed_protocol));
    }
    return 0;
}

int h2_c1_can_upgrade(request_rec *r)
{
    if (!r->connection->master) {
        int h2_upgrade = h2_config_rgeti(r, H2_CONF_UPGRADE);
        return h2_upgrade > 0 || (h2_upgrade < 0 && !ap_ssl_conn_is_ssl(r->connection));
    }
    return 0;
}

static int h2_c1_hook_process_connection(conn_rec* c)
{
    apr_status_t status;
    h2_conn_ctx_t *ctx;

    if (c->master) goto declined;
    ctx = h2_conn_ctx_get(c);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "h2_h2, process_conn");
    if (!ctx && c->keepalives == 0) {
        const char *proto = ap_get_protocol(c);

        if (APLOGctrace1(c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "h2_h2, process_conn, "
                          "new connection using protocol '%s', direct=%d, "
                          "tls acceptable=%d", proto, h2_c1_allows_direct(c),
                          h2_protocol_is_acceptable_c1(c, NULL, 1));
        }

        if (!strcmp(AP_PROTOCOL_HTTP1, proto)
            && h2_c1_allows_direct(c)
            && h2_protocol_is_acceptable_c1(c, NULL, 1)) {
            /* Fresh connection still is on http/1.1 and H2Direct is enabled.
             * Otherwise connection is in a fully acceptable state.
             * -> peek at the first 24 incoming bytes
             */
            apr_bucket_brigade *temp;
            char *peek = NULL;
            apr_size_t peeklen;

            temp = apr_brigade_create(c->pool, c->bucket_alloc);
            status = ap_get_brigade(c->input_filters, temp,
                                    AP_MODE_SPECULATIVE, APR_BLOCK_READ, 24);

            if (status != APR_SUCCESS) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c, APLOGNO(03054)
                              "h2_h2, error reading 24 bytes speculative");
                apr_brigade_destroy(temp);
                return DECLINED;
            }

            apr_brigade_pflatten(temp, &peek, &peeklen, c->pool);
            if ((peeklen >= 24) && !memcmp(H2_MAGIC_TOKEN, peek, 24)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                              "h2_h2, direct mode detected");
                ctx = h2_conn_ctx_create_for_c1(c, c->base_server,
                                                ap_ssl_conn_is_ssl(c)? "h2" : "h2c");
            }
            else if (APLOGctrace2(c)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                              "h2_h2, not detected in %d bytes(base64): %s",
                              (int)peeklen, h2_util_base64url_encode(peek, peeklen, c->pool));
            }
            apr_brigade_destroy(temp);
        }
    }

    if (!ctx) goto declined;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "process_conn");
    if (!ctx->session) {
        status = h2_c1_setup(c, NULL, ctx->server? ctx->server : c->base_server);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c, "conn_setup");
        if (status != APR_SUCCESS) {
            h2_conn_ctx_detach(c);
            return !OK;
        }
    }
    h2_c1_run(c);
    return OK;

declined:
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "h2_h2, declined");
    return DECLINED;
}

static int h2_c1_hook_pre_close(conn_rec *c)
{
    h2_conn_ctx_t *ctx;

    /* secondary connection? */
    if (c->master) {
        return DECLINED;
    }

    ctx = h2_conn_ctx_get(c);
    if (ctx) {
        /* If the session has been closed correctly already, we will not
         * find a h2_conn_ctx_there. The presence indicates that the session
         * is still ongoing. */
        return h2_c1_pre_close(ctx, c);
    }
    return DECLINED;
}

static const char* const mod_ssl[]        = { "mod_ssl.c", NULL};
static const char* const mod_reqtimeout[] = { "mod_ssl.c", "mod_reqtimeout.c", NULL};

void h2_c1_register_hooks(void)
{
    /* Our main processing needs to run quite late. Definitely after mod_ssl,
     * as we need its connection filters, but also before reqtimeout as its
     * method of timeouts is specific to HTTP/1.1 (as of now).
     * The core HTTP/1 processing run as REALLY_LAST, so we will have
     * a chance to take over before it.
     */
    ap_hook_process_connection(h2_c1_hook_process_connection,
                               mod_reqtimeout, NULL, APR_HOOK_LAST);

    /* One last chance to properly say goodbye if we have not done so
     * already. */
    ap_hook_pre_close_connection(h2_c1_hook_pre_close, NULL, mod_ssl, APR_HOOK_LAST);

    /* special bucket type transfer through a h2_bucket_beam */
    h2_register_bucket_beamer(h2_bucket_headers_beam);
}

