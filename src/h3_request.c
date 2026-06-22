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

#include <apr_atomic.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include <nghttp3/nghttp3.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_filter.h"
#include "h3_request.h"
#include "h3_session.h"
#include "mod_http3.h"

static volatile apr_uint32_t h3_conn_id_seq = 0;

conn_rec* h3_synth_conn(h3_session* session)
{
    CHECK(session);
    server_rec* s = session->s;
    apr_pool_t* cpool = NULL;
    if (apr_pool_create(&cpool, session->pool) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "h3_synth_conn: apr_pool_create failed");
        return NULL;
    }

    conn_rec* c = apr_pcalloc(cpool, sizeof(conn_rec));
    c->pool = cpool;
    c->base_server = s;
    c->master = c;
    c->conn_config = ap_create_conn_config(cpool);
    c->notes = apr_table_make(cpool, 5);
    c->id = (long)apr_atomic_inc32(&h3_conn_id_seq);
    c->local_ip = apr_pstrdup(cpool, "0.0.0.0");
    c->client_ip = apr_pstrdup(cpool, "0.0.0.0");
    c->remote_host = apr_pstrdup(cpool, "unknown");
    c->bucket_alloc = apr_bucket_alloc_create(cpool);
    c->log = &s->log;
    c->slaves = apr_array_make(cpool, 4, sizeof(void*));
    c->requests = apr_array_make(cpool, 4, sizeof(void*));
    c->async_filter = -1;
    c->clogging_input_filters = 1;
#if APR_HAS_THREADS
    c->current_thread = ap_thread_current();
#endif
    apr_table_setn(c->notes, "IS_mod_http3", "1");
    apr_table_setn(c->notes, "ssl-bypass", "1");
    session->c = c;
    return c;
}

static size_t build_response_nva(nghttp3_nv* nva, size_t nva_cap, request_rec* r, h3_conn_ctx_t* h3ctx, apr_pool_t* dst_pool)
{
    apr_table_t* hdrs = (h3ctx->resp && h3ctx->resp->headers) ? h3ctx->resp->headers : r->headers_out;
    int status = (h3ctx->resp && h3ctx->resp->status) ? h3ctx->resp->status : r->status;
    char* status_str = apr_psprintf(dst_pool, "%d", status);
    NV_SET(nva, 0, ":status", status_str);
    size_t nvlen = 1;

    if (hdrs != NULL)
    {
        const apr_array_header_t* tarr = apr_table_elts(hdrs);
        const apr_table_entry_t* telts = (const apr_table_entry_t*)tarr->elts;
        for (int i = 0; i < tarr->nelts && nvlen < nva_cap; i++)
        {
            const char* k = telts[i].key;
            const char* v = telts[i].val;
            if (!k || !v)
            {
                continue;
            }
            NV_SET(nva, nvlen, apr_pstrdup(dst_pool, k), apr_pstrdup(dst_pool, v));
            nvlen++;
        }
    }
    return nvlen;
}

static void capture_response_body(h3_stream* stream, h3_conn_ctx_t* h3ctx, apr_pool_t* body_pool)
{
    CHECK(stream);
    CHECK(h3ctx);
    CHECK(body_pool);
    stream->response_data = NULL;
    stream->response_len = 0;
    stream->response_offset = 0;
    if (!h3ctx->dataheap)
    {
        return;
    }
    uint8_t* copy = apr_palloc(body_pool, h3ctx->dataheaplen);
    memcpy(copy, h3ctx->dataheap, h3ctx->dataheaplen);
    stream->response_data = copy;
    stream->response_len = h3ctx->dataheaplen;
}

void h3_process_request(h3_session* session, h3_stream* h3s)
{
    CHECK(session);
    CHECK(h3s);
    server_rec* s = session->s;
    conn_rec* c = session->c;

    request_rec* r = ap_create_request(c);
    if (!r)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "h3_process_request: ap_create_request returned NULL");
        return;
    }
    if (!c)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "h3_process_request: session->c is NULL");
        return;
    }
    r->log = c->log ? c->log : &s->log;
    r->request_time = apr_time_now();
    r->per_dir_config = r->server->lookup_defaults;
    r->connection->keepalive = AP_CONN_KEEPALIVE;
    r->protocol = "HTTP/3.0";
    r->proto_num = HTTP_VERSION(3, 0);
    r->method = apr_pstrdup(r->pool, h3s->method ? h3s->method : "GET");
    r->method_number = ap_method_number_of(r->method);
    r->server = s;
    r->connection->base_server = s;
    h3s->r = r;

    if (h3s->path)
    {
        ap_parse_uri(r, h3s->path);
        r->the_request = apr_pstrcat(r->pool, r->method, " ", r->unparsed_uri, " ", r->protocol, NULL);
    }
    if (h3s->authority)
    {
        const char* port = NULL;
        if (h3s->authority[0] == '[')
        {
            const char* rb = ap_strchr(h3s->authority, ']');
            if (rb && rb[1] == ':')
            {
                port = rb + 1;
            }
        }
        else
        {
            port = ap_strchr(h3s->authority, ':');
        }
        if (port)
        {
            char* end = NULL;
            long pval = strtol(port + 1, &end, 10);
            if (*end == '\0' && pval > 0 && pval <= 65535)
            {
                r->parsed_uri.port = (apr_port_t)pval;
                r->parsed_uri.port_str = apr_pstrdup(r->pool, port + 1);
            }
        }
        apr_table_setn(r->headers_in, "Host", apr_pstrdup(r->pool, h3s->authority));
    }
    if (h3s->scheme)
    {
        apr_table_setn(r->headers_in, "Scheme", apr_pstrdup(r->pool, h3s->scheme));
    }
    if (h3s->headers)
    {
        apr_table_overlap(r->headers_in, h3s->headers, APR_OVERLAP_TABLES_SET);
    }

    apr_pool_t* c3reqpool = NULL;
    if (apr_pool_create(&c3reqpool, session->pool) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_pool_create for h3ctx failed");
        return;
    }
    h3_conn_ctx_t* h3ctx = apr_pcalloc(c3reqpool, sizeof(h3_conn_ctx_t));
    h3ctx->c3reqpool = c3reqpool;
    h3ctx->s = s;
    ap_set_module_config(r->request_config, &http3_module, h3ctx);

    ap_process_request(r);

    apr_thread_mutex_lock(session->lock);
    h3s->dispatched = 1;
    capture_response_body(h3s, h3ctx, session->pool);
    int status = (h3ctx->resp && h3ctx->resp->status) ? h3ctx->resp->status : HTTP_INTERNAL_SERVER_ERROR;
    size_t body_len = h3s->response_len;
    int64_t sid = h3s->stream_id;
    nghttp3_nv nva[64] = {0};
    size_t nvlen = build_response_nva(nva, OSSL_NELEM(nva), r, h3ctx, session->pool);
    nghttp3_data_reader dr = {.read_data = h3_session_read_data};
    int rv = nghttp3_conn_submit_response(session->ngh3, sid, nva, nvlen, body_len > 0 ? &dr : NULL);
    apr_thread_mutex_unlock(session->lock);
    (void)r;
    if (rv)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "nghttp3_conn_submit_response failed: %d", rv);
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "queued response for stream %lld status=%d body=%zu", (long long)sid, status, body_len);
    }
}
