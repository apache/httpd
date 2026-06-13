/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <httpd.h>

#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include <apr_pools.h>

#include "h3_conn.h"
#include "h3_request.h"
#include "h3_ssl.h"

struct h3_request* get_h3_request(struct h3ssl* h3ssl, int64_t stream_id)
{
    struct h3_request* h3req = h3ssl->h3req;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "get_h3_request for %ld (%p)", (long)stream_id, (void*)h3req);
    while (h3req)
    {
        if (h3req->id_bidi == stream_id)
            return h3req;
        h3req = h3req->next;
    }
    return h3req;
}

struct h3_request* create_h3_request(struct h3ssl* h3ssl, int64_t stream_id)
{
    struct h3_request* h3req = h3ssl->h3req;
    struct h3_request* previous = h3ssl->h3req;
    apr_pool_t* pool;
    request_rec* r;
    h3_conn_ctx_t* h3ctx;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "create_h3_request for %ld (%p)", (long)stream_id, (void*)h3req);
    while (h3req)
    {
        previous = h3req;
        h3req = h3req->next;
    }
    /* allocate a new one from the httpd connection pool */
    apr_pool_create(&pool, h3ssl->c->pool);
    apr_pool_tag(pool, "h3_request");
    h3req = apr_pcalloc(pool, sizeof(struct h3_request));
    if (previous)
        previous->next = h3req;
    else
        h3ssl->h3req = h3req;

    h3req->h3reqpool = pool;
    h3req->id_bidi = stream_id;
    r = ap_create_request(h3ssl->c);
    r->request_time = apr_time_now();
    r->per_dir_config = r->server->lookup_defaults;
    r->connection->keepalive = AP_CONN_KEEPALIVE;
    r->protocol = (char*)"HTTP/3.0";
    r->proto_num = HTTP_VERSION(3, 0);
    h3req->r = r;

    h3ctx = apr_pcalloc(pool, sizeof(h3_conn_ctx_t));
    h3ctx->c3reqpool = pool;
    h3ctx->s = h3ssl->s;
    h3req->h3ctx = h3ctx;
    apr_table_set(r->notes, "H3CTX", (char*)h3ctx);
    return h3req;
}

void cleanup_h3_request(struct h3ssl* h3ssl, struct h3_request* h3req, int64_t stream_id)
{
    struct h3_request* previous = h3ssl->h3req;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "cleanup_h3_request for %ld (%p)", (long)stream_id, (void*)h3req);
    while (previous)
    {
        if (previous->id_bidi == stream_id)
        {
            break;
        }
        previous = previous->next;
    }
    if (!previous)
        abort(); // logical error somewhere.
    previous = h3req->next;
    apr_pool_clear(h3req->h3reqpool); // the apr_pool_destroy() is for the connection...
}
