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
#include <apr_atomic.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>

#include "h2_private.h"
#include "h2_session.h"
#include "h2_bucket_beam.h"
#include "h2_c2.h"
#include "h2_mplx.h"
#include "h2_stream.h"
#include "h2_util.h"
#include "h2_conn_ctx.h"


void h2_conn_ctx_detach(conn_rec *c)
{
    ap_set_module_config(c->conn_config, &http2_module, NULL);
}

static h2_conn_ctx_t *ctx_create(conn_rec *c, const char *id)
{
    h2_conn_ctx_t *conn_ctx = apr_pcalloc(c->pool, sizeof(*conn_ctx));
    conn_ctx->id = id;
    conn_ctx->server = c->base_server;
    apr_atomic_set32(&conn_ctx->started, 1);
    conn_ctx->started_at = apr_time_now();

    ap_set_module_config(c->conn_config, &http2_module, conn_ctx);
    return conn_ctx;
}

h2_conn_ctx_t *h2_conn_ctx_create_for_c1(conn_rec *c1, server_rec *s, const char *protocol)
{
    h2_conn_ctx_t *ctx;

    ctx = ctx_create(c1, apr_psprintf(c1->pool, "%ld", c1->id));
    ctx->server = s;
    ctx->protocol = apr_pstrdup(c1->pool, protocol);

    ctx->pfd.desc_type = APR_POLL_SOCKET;
    ctx->pfd.desc.s = ap_get_conn_socket(c1);
    ctx->pfd.reqevents = APR_POLLIN | APR_POLLERR | APR_POLLHUP;
    ctx->pfd.client_data = ctx;
    apr_socket_opt_set(ctx->pfd.desc.s, APR_SO_NONBLOCK, 1);

    return ctx;
}

void h2_conn_ctx_assign_session(h2_conn_ctx_t *ctx, struct h2_session *session)
{
    ctx->session = session;
    ctx->id = apr_psprintf(session->pool, "%d-%lu", session->child_num, (unsigned long)session->id);
}

apr_status_t h2_conn_ctx_init_for_c2(h2_conn_ctx_t **pctx, conn_rec *c2,
                                     struct h2_mplx *mplx, struct h2_stream *stream,
                                     struct h2_c2_transit *transit)
{
    h2_conn_ctx_t *conn_ctx;
    apr_status_t rv = APR_SUCCESS;

    ap_assert(c2->master);
    conn_ctx = h2_conn_ctx_get(c2);
    if (!conn_ctx) {
        h2_conn_ctx_t *c1_ctx;

        c1_ctx = h2_conn_ctx_get(c2->master);
        ap_assert(c1_ctx);
        ap_assert(c1_ctx->session);

        conn_ctx = ctx_create(c2, c1_ctx->id);
        conn_ctx->server = c2->master->base_server;
    }

    conn_ctx->mplx = mplx;
    conn_ctx->transit = transit;
    conn_ctx->stream_id = stream->id;
    apr_pool_create(&conn_ctx->req_pool, c2->pool);
    apr_pool_tag(conn_ctx->req_pool, "H2_C2_REQ");
    conn_ctx->request = stream->request;
    apr_atomic_set32(&conn_ctx->started, 1);
    conn_ctx->started_at = apr_time_now();
    conn_ctx->done = 0;
    conn_ctx->done_at = 0;

    *pctx = conn_ctx;
    return rv;
}

void h2_conn_ctx_set_timeout(h2_conn_ctx_t *conn_ctx, apr_interval_time_t timeout)
{
    if (conn_ctx->beam_out) {
        h2_beam_timeout_set(conn_ctx->beam_out, timeout);
    }
    if (conn_ctx->beam_in) {
        h2_beam_timeout_set(conn_ctx->beam_in, timeout);
    }
    if (conn_ctx->pipe_in[H2_PIPE_OUT]) {
        apr_file_pipe_timeout_set(conn_ctx->pipe_in[H2_PIPE_OUT], timeout);
    }
}
