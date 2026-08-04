/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is derived from code originally distributed as part of
 * the OpenSSL project and has been modified for use in mod_http3.
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

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include <string.h>

#include <nghttp3/nghttp3.h>

#include "quic/h3q_stream.h"

#include "h3.h"
#include "h3_callbacks.h"
#include "h3_check.h"
#include "h3_config.h"
#include "h3_session.h"
#include "mod_http3.h"

static int set_pseudo(h3_stream* stream, h3_session* session, int32_t token, nghttp3_vec* value)
{
    CHECK(session);
    CHECK(stream);
    CHECK(value);

    if (value->len == 0 || value->len >= 8192)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, session->s, "pseudo-header length %zu invalid", value->len);
        return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
    }
    char* copy = apr_pstrndup(stream->pool, (const char*)value->base, value->len);
    switch (token)
    {
    case NGHTTP3_QPACK_TOKEN__METHOD:
        stream->method = copy;
        break;
    case NGHTTP3_QPACK_TOKEN__SCHEME:
        stream->scheme = copy;
        break;
    case NGHTTP3_QPACK_TOKEN__PATH:
        stream->path = copy;
        break;
    case NGHTTP3_QPACK_TOKEN__AUTHORITY:
        stream->authority = copy;
        break;
    default:
        return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
    }
    return 0;
}

int on_begin_headers(nghttp3_conn* conn, int64_t stream_id, void* user_data, void* stream_user_data)
{
    h3_session* session = user_data;
    CHECK(session);
    h3_stream* stream = stream_user_data;
    if (!stream && session->pending.sid == stream_id)
    {
        stream = session->pending.h3s;
    }
    if (!stream)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, session->s, "on_begin_headers for untracked sid=%lld", (long long)stream_id);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    if (stream->is_bidi && !stream->headers)
    {
        stream->headers = apr_table_make(stream->pool, 10);
    }
    nghttp3_conn_set_stream_user_data(conn, stream_id, stream);
    return 0;
}

int on_recv_header(nghttp3_conn* /*conn*/, int64_t /*stream_id*/, int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t /*flags*/, void* user_data, void* stream_user_data)
{
    h3_stream* stream = stream_user_data;
    h3_session* session = user_data;
    CHECK(session);
    if (!stream)
    {
        return 0;
    }
    nghttp3_vec nv = nghttp3_rcbuf_get_buf(value);
    if (IS_PSEUDO_TOKEN(token))
    {
        return set_pseudo(stream, session, token, &nv);
    }
    if (!stream->headers)
    {
        return 0;
    }
    apr_table_addn(stream->headers, apr_pstrndup(stream->pool, (const char*)nghttp3_rcbuf_get_buf(name).base, nghttp3_rcbuf_get_buf(name).len), apr_pstrndup(stream->pool, (const char*)nv.base, nv.len));
    return 0;
}

int on_end_headers(nghttp3_conn* /*conn*/, int64_t /*stream_id*/, int fin, void* /*user_data*/, void* stream_user_data)
{
    h3_stream* stream = stream_user_data;
    if (stream && stream->is_bidi)
    {
        stream->headers_complete = 1;
        if (fin)
        {
            /* Request has no body. */
            stream->body_complete = 1;
        }
    }
    return 0;
}

int on_recv_data(nghttp3_conn* /*conn*/, int64_t stream_id, const uint8_t* data, size_t datalen, void* /*user_data*/, void* stream_user_data)
{
    h3_stream* stream = stream_user_data;
    if (!stream || !stream->is_bidi || !data || datalen == 0)
    {
        return 0;
    }
    if (stream->request_body_overflow)
    {
        /* Discard over-budget bytes. */
        return 0;
    }
    h3_server_conf* conf = ap_get_module_config(stream->session->s->module_config, &http3_module);
    if (stream->request_body_len + datalen > conf->h3_max_request_body_size)
    {
        stream->request_body_overflow = 1;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, stream->session->s,
                     "HTTP/3 request body for stream %" APR_INT64_T_FMT " exceeds H3MaxRequestBodySize "
                     "(%" APR_SIZE_T_FMT " bytes); remaining body bytes will be discarded",
                     stream_id, conf->h3_max_request_body_size);
        return 0;
    }
    /* Grow the body buffer using a doubling strategy to avoid O(n^2) copies. */
    size_t needed = stream->request_body_len + datalen;
    if (needed > stream->request_body_capacity)
    {
        size_t new_cap = stream->request_body_capacity ? stream->request_body_capacity : H3_BODY_BUF_INIT_CAP;
        while (new_cap < needed)
        {
            new_cap *= 2;
        }
        if (new_cap > conf->h3_max_request_body_size)
        {
            new_cap = conf->h3_max_request_body_size;
        }
        uint8_t* grown = apr_palloc(stream->pool, new_cap);
        if (stream->request_body_len)
        {
            memcpy(grown, stream->request_body, stream->request_body_len);
        }
        stream->request_body = grown;
        stream->request_body_capacity = new_cap;
    }
    memcpy((uint8_t*)stream->request_body + stream->request_body_len, data, datalen);
    stream->request_body_len += datalen;
    return 0;
}

int on_acked_stream_data(nghttp3_conn* conn, int64_t stream_id, uint64_t datalen, void* user_data, void* stream_user_data)
{
    (void)conn;
    (void)stream_id;
    (void)user_data;
    h3_stream_response_ack_locked((h3_stream*)stream_user_data, datalen);
    return 0;
}

int on_stop_sending(nghttp3_conn* /*conn*/, int64_t /*stream_id*/, uint64_t /*app_error_code*/, void* user_data, void* stream_user_data)
{
    /* Send STOP_SENDING by freeing the stream object. */
    h3_session* session = user_data;
    CHECK(session);
    h3_stream* stream = stream_user_data;
    if (stream)
    {
        h3_stream_response_cancel_locked(stream);
        if (stream->qstream)
        {
            h3_session_queue_free(session, stream->qstream);
            stream->qstream = NULL;
        }
        stream->done = 1;
        stream->body_complete = 1;
        stream->body_truncated = 1;
    }
    return 0;
}

int on_reset_stream(nghttp3_conn* /*conn*/, int64_t /*stream_id*/, uint64_t app_error_code, void* /*user_data*/, void* stream_user_data)
{
    h3_stream* stream = stream_user_data;
    if (stream)
    {
        h3_stream_response_cancel_locked(stream);
        h3q_stream_reset(stream->qstream, app_error_code);
        stream->done = 1;
    }
    return 0;
}

int on_stream_close(nghttp3_conn* /*conn*/, int64_t /* stream_id */, uint64_t /*app_error_code*/, void* user_data, void* stream_user_data)
{
    h3_session* session = user_data;
    CHECK(session);
    h3_stream* stream = stream_user_data;
    if (stream)
    {
        h3_stream_response_cancel_locked(stream);
        stream->done = 1;
        if (stream->qstream)
        {
            h3_session_queue_free(session, stream->qstream);
            stream->qstream = NULL;
        }
    }
    return 0;
}
