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
#include "h3_config.h"
#include "h3_filter.h"
#include "h3_request.h"
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
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, f->c->base_server, "serve_request_body started, h3s=%p", (void*)h3s);
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

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, f->c->base_server, "serve_request_body: unread=%p, want=%" APR_SIZE_T_FMT, (void*)unread, want);
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
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, f->c->base_server, "serve_request_body done, want=%" APR_SIZE_T_FMT ", offset=%" APR_SIZE_T_FMT, want, h3s->request_body_offset);
    return APR_SUCCESS;
}

static apr_status_t capture_body_bucket(request_rec* r, h3_conn_ctx_t* ctx, apr_bucket* b)
{
    CHECK(ctx);
    CHECK(b);
    if (ctx->response_too_large)
    {
        return APR_SUCCESS;
    }
    const char* data = NULL;
    apr_size_t len = 0;
    if (apr_bucket_read(b, &data, &len, APR_BLOCK_READ) != APR_SUCCESS || !data || !len)
    {
        return APR_SUCCESS;
    }
    /* Read from the H3-owning vhost (ctx->s), not r->server: only it is defaulted in h3_post_config. */
    h3_server_conf* conf = ap_get_module_config(ctx->s->module_config, &http3_module);
    apr_size_t limit = conf ? conf->h3_max_response_body_size : H3_MAX_RESPONSE_BODY_SIZE_DEFAULT;
    if (ctx->dataheaplen > limit || len > limit - ctx->dataheaplen)
    {
        ctx->response_too_large = 1;
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "HTTP/3 response body for %s exceeds H3MaxResponseBodySize (%" APR_SIZE_T_FMT " bytes); aborting response with 500", r->uri, limit);
        return APR_SUCCESS;
    }
    apr_size_t new_len = ctx->dataheaplen + len;
    if (new_len > ctx->dataheapcap)
    {
        apr_size_t new_cap = ctx->dataheapcap ? ctx->dataheapcap * 2 : H3_BODY_BUF_INIT_CAP;
        while (new_cap < new_len)
        {
            new_cap *= 2;
        }
        char* new_heap = apr_palloc(ctx->c3reqpool, new_cap);
        if (ctx->dataheaplen > 0)
        {
            memcpy(new_heap, ctx->dataheap, ctx->dataheaplen);
        }
        ctx->dataheap = new_heap;
        ctx->dataheapcap = new_cap;
    }
    memcpy(ctx->dataheap + ctx->dataheaplen, data, len);
    ctx->dataheaplen = new_len;
    return APR_SUCCESS;
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

    for (apr_bucket* b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb);)
    {
        apr_bucket* next = APR_BUCKET_NEXT(b);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, f->c->base_server, "h3_filter_out_proto: received bucket type=%s length=%" APR_SIZE_T_FMT, b->type->name, b->length);
        if (AP_BUCKET_IS_ERROR(b))
        {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, f->c->base_server, "h3_filter_out_proto: generating error response");
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
            if (ctx->streaming)
            {
                apr_status_t rv = h3_response_start(f->r, ctx);
                if (rv != APR_SUCCESS)
                {
                    apr_brigade_cleanup(bb);
                    return rv;
                }
            }
        }
        else if (!APR_BUCKET_IS_METADATA(b))
        {
            apr_status_t rv;
            if (ctx->streaming)
            {
                rv = h3_response_start(f->r, ctx);
                if (rv == APR_SUCCESS)
                {
                    const char* data = NULL;
                    apr_size_t len = 0;
                    rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
                    if (rv == APR_SUCCESS && data && len > 0)
                    {
                        rv = h3_stream_response_append(ctx->stream, (const uint8_t*)data, len);
                    }
                }
            }
            else
            {
                rv = capture_body_bucket(f->r, ctx, b);
            }
            if (rv != APR_SUCCESS)
            {
                apr_brigade_cleanup(bb);
                return rv;
            }
            next = APR_BUCKET_NEXT(b);
        }
        else if (ctx->streaming && (APR_BUCKET_IS_EOS(b) || APR_BUCKET_IS_FLUSH(b)))
        {
            apr_status_t rv = h3_response_start(f->r, ctx);
            if (rv != APR_SUCCESS)
            {
                apr_brigade_cleanup(bb);
                return rv;
            }
            if (APR_BUCKET_IS_EOS(b))
            {
                h3_stream_response_complete(ctx->stream);
            }
        }
        b = next;
    }

    apr_brigade_cleanup(bb);
    return OK;
}

apr_status_t h3_filter_in_proto(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, f->c->base_server, "h3_filter_in_proto called, readbytes=%" APR_OFF_T_FMT, readbytes);
    h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
    h3_stream* h3s = ctx ? ctx->stream : NULL;
    if (!h3s)
    {
        return input_filter_eos(f, bb, mode, block, readbytes);
    }
    return serve_request_body(f, h3s, bb, mode, block, readbytes);
}
