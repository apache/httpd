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

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_thread_mutex.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <nghttp3/nghttp3.h>

#include "h3.h"
#include "h3_callbacks.h"
#include "h3_check.h"
#include "h3_session.h"
#include "h3_stream.h"
#include "mod_http3.h"

static SSL* open_uni_stream(SSL* ssl_conn, int64_t* out_id, server_rec* s, const char* label)
{
    CHECK(ssl_conn);
    CHECK(out_id);
    CHECK(s);
    CHECK(label);
    SSL* stream = SSL_new_stream(ssl_conn, SSL_STREAM_FLAG_UNI);
    if (!stream)
    {
        char buf[256] = {0};
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "SSL_new_stream(%s) failed: %s", label, buf);
        return NULL;
    }
    *out_id = (int64_t)SSL_get_stream_id(stream);
    return stream;
}

apr_status_t h3_session_create(h3_session** psession, server_rec* s, SSL* ssl_listener, SSL* ssl_conn, apr_pool_t* pool)
{
    CHECK(psession);
    CHECK(s);
    CHECK(pool);
    h3_session* session = apr_pcalloc(pool, sizeof(*session));
    session->s = s;
    session->pool = pool;
    session->ssl_listener = ssl_listener;
    session->ssl_conn = ssl_conn;
    session->streams = apr_hash_make(pool);
    session->pending_free = apr_array_make(pool, 8, sizeof(SSL*));

    apr_status_t rv = apr_thread_mutex_create(&session->lock, APR_THREAD_MUTEX_DEFAULT, pool);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_thread_mutex_create failed");
        return rv;
    }

    nghttp3_callbacks cb = {.acked_stream_data = on_acked_stream_data, .recv_header = on_recv_header, .end_headers = on_end_headers, .recv_data = on_recv_data, .stream_close = on_stream_close, .begin_headers = on_begin_headers, .stop_sending = on_stop_sending, .reset_stream = on_reset_stream};
    nghttp3_settings settings = {0};
    nghttp3_settings_default(&settings);
    if (nghttp3_conn_server_new(&session->ngh3, &cb, &settings, nghttp3_mem_default(), session) != 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "nghttp3_conn_server_new failed");
        return APR_EGENERAL;
    }
    *psession = session;
    return APR_SUCCESS;
}

apr_status_t h3_session_create_control_streams(h3_session* session)
{
    CHECK(session);
    if (session->control_streams_created)
    {
        return APR_SUCCESS;
    }
    server_rec* s = session->s;
    SSL* ssl_conn = session->ssl_conn;

    struct
    {
        const char* name;
        int64_t id;
        SSL* ssl;
    } cs[] = {
        {"control", 0, NULL},
        {"qpack_enc", 0, NULL},
        {"qpack_dec", 0, NULL},
    };
    for (int i = 0; i < 3; i++)
    {
        cs[i].ssl = open_uni_stream(ssl_conn, &cs[i].id, s, cs[i].name);
    }

    if (!cs[0].ssl || !cs[1].ssl || !cs[2].ssl || nghttp3_conn_bind_control_stream(session->ngh3, cs[0].id) != 0 || nghttp3_conn_bind_qpack_streams(session->ngh3, cs[1].id, cs[2].id) != 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "failed to initialize or bind control/qpack streams");
        for (int i = 0; i < 3; i++)
        {
            if (cs[i].ssl)
            {
                SSL_free(cs[i].ssl);
            }
        }
        if (session->ngh3)
        {
            nghttp3_conn_del(session->ngh3);
            session->ngh3 = NULL;
        }
        return APR_EGENERAL;
    }

    track_stream(session, cs[0].id, cs[0].ssl);
    track_stream(session, cs[1].id, cs[1].ssl);
    track_stream(session, cs[2].id, cs[2].ssl);
    session->control_streams_created = 1;
    return APR_SUCCESS;
}

void h3_session_destroy(h3_session* session)
{
    if (!session)
    {
        return;
    }
    apr_thread_mutex_lock(session->lock);
    if (session->ngh3)
    {
        nghttp3_conn_del(session->ngh3);
        session->ngh3 = NULL;
    }
    while (session->pending_free->nelts > 0)
    {
        SSL_free(*(SSL**)apr_array_pop(session->pending_free));
    }
    if (session->ssl_conn)
    {
        SSL_free(session->ssl_conn);
        session->ssl_conn = NULL;
    }
    apr_thread_mutex_unlock(session->lock);
    apr_thread_mutex_destroy(session->lock);
}

void h3_session_queue_free(h3_session* session, SSL* ssl)
{
    if (!session || !ssl)
    {
        return;
    }
    APR_ARRAY_PUSH(session->pending_free, SSL*) = ssl;
}

nghttp3_ssize h3_session_read_data(nghttp3_conn* /*conn*/, int64_t /*stream_id*/, nghttp3_vec* vec, size_t /*veccnt*/, uint32_t* pflags, void* /*user_data*/, void* stream_user_data)
{
    h3_stream* stream = (h3_stream*)stream_user_data;
    if (!stream || !stream->response_data || stream->response_offset >= stream->response_len)
    {
        *pflags = NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    size_t remaining = stream->response_len - stream->response_offset;
    size_t to_send = remaining < STREAM_CHUNK_BYTES ? remaining : STREAM_CHUNK_BYTES;
    vec[0].base = (uint8_t*)&stream->response_data[stream->response_offset];
    vec[0].len = to_send;
    stream->response_offset += to_send;
    *pflags = (stream->response_offset >= stream->response_len) ? NGHTTP3_DATA_FLAG_EOF : NGHTTP3_DATA_FLAG_NONE;
    return 1;
}
