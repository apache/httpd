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

#include <apr_hash.h>
#include <apr_pools.h>

#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_config.h"
#include "h3_session.h"
#include "mod_http3.h"

h3_stream* h3_stream_find(h3_session* session, int64_t sid)
{
    CHECK(session);
    return apr_hash_get(session->streams, &sid, sizeof(sid));
}

void flush_nghttp3(h3_session* session)
{
    CHECK(session);
    CHECK(!session->ngh3_dead, return;);
    for (;;)
    {
        nghttp3_vec vec[16] = {0};
        int64_t sid = -1;
        int fin = 0;
        nghttp3_ssize nvec = nghttp3_conn_writev_stream(session->ngh3, &sid, &fin, vec, 16);
        if (nvec <= 0)
        {
            break;
        }
        h3_stream* h3s = h3_stream_find(session, sid);
        if (!h3s || !h3s->ssl_stream)
        {
            break;
        }
        size_t total = 0;
        for (nghttp3_ssize k = 0; k < nvec; k++)
        {
            size_t w = 0;
            if (SSL_write_ex(h3s->ssl_stream, vec[k].base, vec[k].len, &w) <= 0)
            {
                break;
            }
            total += w;
        }
        if (total > 0)
        {
            nghttp3_conn_add_write_offset(session->ngh3, sid, total);
        }
        if (fin)
        {
            SSL_stream_conclude(h3s->ssl_stream, 0);
        }
    }
    if (session->pending_free->nelts > 0)
    {
        while (session->pending_free->nelts > 0)
        {
            SSL* ssl = *(SSL**)apr_array_pop(session->pending_free);
            if (ssl)
            {
                SSL_free(ssl);
            }
        }
    }
}

h3_stream* track_stream(h3_session* session, int64_t sid, SSL* stream_ssl)
{
    CHECK(session);
    CHECK(stream_ssl);
    h3_stream* h3s = h3_stream_find(session, sid);
    if (h3s)
    {
        h3s->ssl_stream = stream_ssl;
        SSL_set_app_data(stream_ssl, h3s);
        return h3s;
    }
    apr_pool_t* stream_pool = NULL;
    CHECK(apr_pool_create(&stream_pool, session->pool) == APR_SUCCESS);
    h3s = apr_pcalloc(session->pool, sizeof(*h3s));
    h3s->session = session;
    h3s->pool = stream_pool;
    h3s->stream_id = sid;
    h3s->ssl_stream = stream_ssl;
    h3s->is_bidi = H3_SID_IS_BIDI(sid);
    apr_hash_set(session->streams, &h3s->stream_id, sizeof(h3s->stream_id), h3s);
    SSL_set_app_data(stream_ssl, h3s);
    return h3s;
}

static void mark_ngh3_dead(h3_session* session, int64_t stream_id, nghttp3_ssize liberr)
{
    session->ngh3_dead = 1;
    session->abort_quic_error_code = nghttp3_err_infer_quic_app_error_code((int)liberr);
    session->abort_reason = nghttp3_strerror((int)liberr);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, session->s, "read_stream failed for stream %" APR_INT64_T_FMT " (%s, err=%" APR_INT64_T_FMT "); closing with QUIC error 0x%" APR_UINT64_T_HEX_FMT, stream_id, session->abort_reason, (apr_int64_t)liberr, session->abort_quic_error_code);
}

static int drain_one_stream(h3_session* session, h3_stream* h3s)
{
    CHECK(session);
    CHECK(h3s);

    h3_server_conf* conf = ap_get_module_config(session->s->module_config, &http3_module);
    apr_size_t buf_size = conf->h3_stream_buffer_size;
    if (!session->stream_read_buf || session->stream_read_buf_size < buf_size)
    {
        session->stream_read_buf = apr_palloc(session->pool, buf_size);
        session->stream_read_buf_size = buf_size;
    }
    unsigned char* buf = session->stream_read_buf;

    for (;;)
    {
        size_t nread = 0;
        int rv = SSL_read_ex(h3s->ssl_stream, buf, buf_size, &nread);
        if (rv == 1 && nread > 0)
        {
            session->pending.sid = h3s->stream_id;
            session->pending.h3s = h3s;
            nghttp3_ssize consumed = nghttp3_conn_read_stream(session->ngh3, h3s->stream_id, buf, nread, 0);
            session->pending.sid = -1;
            session->pending.h3s = NULL;
            if (consumed < 0)
            {
                /* Mark dead if read fails. */
                mark_ngh3_dead(session, h3s->stream_id, consumed);
                h3s->done = 1;
                break;
            }
            if (h3s->done)
            {
                break;
            }
            continue;
        }
        if (SSL_get_error(h3s->ssl_stream, rv) == SSL_ERROR_ZERO_RETURN)
        {
            nghttp3_ssize consumed = nghttp3_conn_read_stream(session->ngh3, h3s->stream_id, NULL, 0, 1);
            if (consumed < 0)
            {
                mark_ngh3_dead(session, h3s->stream_id, consumed);
            }
            h3s->done = 1;
            h3s->body_complete = 1;
        }
        break;
    }
    return h3s->is_bidi && h3s->headers_complete && h3s->body_complete && !h3s->dispatched;
}

apr_array_header_t* drain_ready_streams(h3_session* session, apr_pool_t* loop_pool)
{
    CHECK(session);
    CHECK(loop_pool);
    apr_array_header_t* completed = apr_array_make(loop_pool, 4, sizeof(h3_stream*));

    apr_array_header_t* snapshot = apr_array_make(loop_pool, 8, sizeof(h3_stream*));
    for (apr_hash_index_t* hi = apr_hash_first(NULL, session->streams); hi; hi = apr_hash_next(hi))
    {
        h3_stream* h3s = apr_hash_this_val(hi);
        if (h3s)
        {
            *(h3_stream**)apr_array_push(snapshot) = h3s;
        }
    }

    for (int i = 0; i < snapshot->nelts; i++)
    {
        if (session->ngh3_dead)
        {
            break;
        }
        h3_stream* h3s = ((h3_stream**)snapshot->elts)[i];

        if (!h3s->ssl_stream || h3s->done)
        {
            continue;
        }
        if (H3_SID_IS_SERVER(h3s->stream_id))
        {
            continue;
        }
        if (drain_one_stream(session, h3s) && !session->ngh3_dead)
        {
            h3_stream** slot = (h3_stream**)apr_array_push(completed);
            *slot = h3s;
        }
    }
    return completed;
}
