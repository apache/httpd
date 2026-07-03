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
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include <apr_buckets.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include <string.h>

#include <nghttp3/nghttp3.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_filter.h"
#include "h3_session.h"
#include "mod_http3.h"

ap_filter_rec_t* h3_net_in_filter_handle;
ap_filter_rec_t* h3_net_out_filter_handle;
ap_filter_rec_t* h3_proto_out_filter_handle;
ap_filter_rec_t* h3_proto_in_filter_handle;

apr_status_t h3_filter_out(ap_filter_t* /*f*/, apr_bucket_brigade* bb)
{
    CHECK(bb);
    apr_brigade_cleanup(bb);
    return APR_SUCCESS;
}

static apr_status_t input_filter_eos(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE)
    {
        if (!f->next)
        {
            return APR_EOF;
        }
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    if (!APR_BRIGADE_EMPTY(bb))
    {
        return APR_SUCCESS;
    }
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->c->bucket_alloc));
    return APR_SUCCESS;
}

apr_status_t h3_filter_in(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    return input_filter_eos(f, bb, mode, block, readbytes);
}

/* Serve request body. */
static apr_status_t serve_request_body(ap_filter_t* f, h3_stream* h3s, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e /*block*/, apr_off_t readbytes)
{
    apr_bucket_alloc_t* ba = f->c->bucket_alloc;

    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE && mode != AP_MODE_EXHAUSTIVE && mode != AP_MODE_SPECULATIVE)
    {
        /* AP_MODE_INIT, AP_MODE_EATCRLF: nothing for us to do. */
        return APR_SUCCESS;
    }

    apr_size_t avail = h3s->request_body_len - h3s->request_body_offset;
    if (avail == 0)
    {
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(ba));
        return APR_SUCCESS;
    }

    const uint8_t* unread = h3s->request_body + h3s->request_body_offset;
    apr_size_t want = avail;
    if (mode == AP_MODE_READBYTES || mode == AP_MODE_SPECULATIVE)
    {
        if (readbytes > 0 && (apr_size_t)readbytes < want)
        {
            want = (apr_size_t)readbytes;
        }
    }
    else if (mode == AP_MODE_GETLINE)
    {
        const void* nl = memchr(unread, '\n', avail);
        if (nl)
        {
            want = (apr_size_t)((const uint8_t*)nl - unread) + 1;
        }
    }
    /* AP_MODE_EXHAUSTIVE: take everything remaining, as already set above. */

    apr_bucket* b = apr_bucket_pool_create((const char*)unread, want, h3s->pool, ba);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    if (mode != AP_MODE_SPECULATIVE)
    {
        h3s->request_body_offset += want;
        if (h3s->request_body_offset >= h3s->request_body_len)
        {
            APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(ba));
        }
    }
    return APR_SUCCESS;
}

static void capture_body_bucket(h3_conn_ctx_t* ctx, apr_bucket* b)
{
    CHECK(ctx);
    CHECK(b);
    const char* data = NULL;
    apr_size_t len = 0;
    if (apr_bucket_read(b, &data, &len, APR_BLOCK_READ) != APR_SUCCESS || !data || !len)
    {
        return;
    }
    apr_size_t old = ctx->dataheaplen;
    char* combined = apr_palloc(ctx->c3reqpool, old + len);
    if (old)
    {
        memcpy(combined, ctx->dataheap, old);
    }
    memcpy(combined + old, data, len);
    ctx->dataheap = combined;
    ctx->dataheaplen = old + len;
}

apr_status_t h3_filter_out_proto(ap_filter_t* f, apr_bucket_brigade* bb)
{
    CHECK(f);
    CHECK(bb);
    h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)f->ctx;
    if (!ctx || f->r->main != NULL)
    {
        return ap_pass_brigade(f->next, bb);
    }

    for (apr_bucket* b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
    {
        if (AP_BUCKET_IS_ERROR(b))
        {
            ap_send_error_response(f->r, 0);
            return OK;
        }
        if (AP_BUCKET_IS_RESPONSE(b))
        {
            ctx->resp = b->data;
            if (ctx->resp->headers)
            {
                apr_table_t* dup = apr_table_make(ctx->c3reqpool, apr_table_elts(ctx->resp->headers)->nelts);
                const apr_array_header_t* src_arr = apr_table_elts(ctx->resp->headers);
                const apr_table_entry_t* src = (const apr_table_entry_t*)src_arr->elts;
                for (int i = 0; i < src_arr->nelts; i++)
                {
                    if (src[i].key && src[i].val)
                    {
                        apr_table_add(dup, apr_pstrdup(ctx->c3reqpool, src[i].key), apr_pstrdup(ctx->c3reqpool, src[i].val));
                    }
                }
                ctx->resp->headers = dup;
            }
            ctx->resp->pool = ctx->c3reqpool;
            APR_BUCKET_REMOVE(b);
        }
        else if (APR_BUCKET_IS_FILE(b) || APR_BUCKET_IS_MMAP(b) || APR_BUCKET_IS_HEAP(b) || APR_BUCKET_IS_TRANSIENT(b))
        {
            capture_body_bucket(ctx, b);
        }
    }

    apr_brigade_cleanup(bb);
    return OK;
}

apr_status_t h3_filter_in_proto(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
    h3_stream* h3s = ctx ? ctx->stream : NULL;
    if (!h3s)
    {
        return input_filter_eos(f, bb, mode, block, readbytes);
    }
    return serve_request_body(f, h3s, bb, mode, block, readbytes);
}

void h3_filter_last(request_rec* r)
{
    if (r->main != NULL)
    {
        return;
    }
    h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(r->request_config, &http3_module);
    if (apr_table_get(r->connection->notes, "IS_mod_http3") == NULL || ctx == NULL)
    {
        return;
    }
    ap_add_output_filter_handle(h3_proto_out_filter_handle, ctx, r, r->connection);
}
