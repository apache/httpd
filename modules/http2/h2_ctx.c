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

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>

#include "h2_private.h"
#include "h2_session.h"
#include "h2_task.h"
#include "h2_ctx.h"

static h2_ctx *h2_ctx_create(const conn_rec *c)
{
    h2_ctx *ctx = apr_pcalloc(c->pool, sizeof(h2_ctx));
    ap_assert(ctx);
    h2_ctx_server_update(ctx, c->base_server);
    ap_set_module_config(c->conn_config, &http2_module, ctx);
    return ctx;
}

void h2_ctx_clear(const conn_rec *c)
{
    ap_assert(c);
    ap_set_module_config(c->conn_config, &http2_module, NULL);
}

h2_ctx *h2_ctx_create_for(const conn_rec *c, h2_task *task)
{
    h2_ctx *ctx = h2_ctx_create(c);
    if (ctx) {
        ctx->task = task;
    }
    return ctx;
}

h2_ctx *h2_ctx_get(const conn_rec *c, int create)
{
    h2_ctx *ctx = (h2_ctx*)ap_get_module_config(c->conn_config, &http2_module);
    if (ctx == NULL && create) {
        ctx = h2_ctx_create(c);
    }
    return ctx;
}

h2_ctx *h2_ctx_rget(const request_rec *r)
{
    return h2_ctx_get(r->connection, 0);
}

const char *h2_ctx_protocol_get(const conn_rec *c)
{
    h2_ctx *ctx;
    if (c->master) {
        c = c->master;
    }
    ctx = (h2_ctx*)ap_get_module_config(c->conn_config, &http2_module);
    return ctx? ctx->protocol : NULL;
}

h2_ctx *h2_ctx_protocol_set(h2_ctx *ctx, const char *proto)
{
    ctx->protocol = proto;
    return ctx;
}

h2_session *h2_ctx_get_session(conn_rec *c)
{
    h2_ctx *ctx = h2_ctx_get(c, 0);
    return ctx? ctx->session : NULL;
}

void h2_ctx_session_set(h2_ctx *ctx, struct h2_session *session)
{
    ctx->session = session;
}

h2_ctx *h2_ctx_server_update(h2_ctx *ctx, server_rec *s)
{
    if (ctx->server != s) {
        ctx->server = s;
    }
    return ctx;
}

h2_task *h2_ctx_get_task(conn_rec *c)
{
    h2_ctx *ctx = h2_ctx_get(c, 0);
    return ctx? ctx->task : NULL;
}

