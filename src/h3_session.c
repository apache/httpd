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
#include <apr_time.h>

#include <stdlib.h>
#include <string.h>

#include <nghttp3/nghttp3.h>

#include "h3.h"
#include "h3_callbacks.h"
#include "h3_check.h"
#include "h3_config.h"
#include "h3_io.h"
#include "h3_os.h"
#include "h3_session.h"
#include "h3_stream.h"
#include "mod_http3.h"
#include "quic/h3q_conn.h"
#include "quic/h3q_stream.h"

struct h3_response_chunk
{
    h3_response_chunk* next;
    size_t len;
    size_t acked;
    uint8_t data[];
};

static void wake_event_thread(void)
{
    if (child_h3_io)
    {
        h3_wakeup_signal(&child_h3_io->wakeup);
    }
}

apr_status_t h3_session_create(h3_session** psession, server_rec* s, h3q_conn* qconn, apr_pool_t* pool)
{
    CHECK(psession);
    CHECK(s);
    CHECK(pool);
    h3_session* session = apr_pcalloc(pool, sizeof(*session));
    session->s = s;
    session->pool = pool;
    session->qconn = qconn;
    session->streams = apr_hash_make(pool);
    session->pending_free = apr_array_make(pool, 8, sizeof(h3q_stream*));
    session->last_activity = apr_time_now();

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

    h3_server_conf* conf = ap_get_module_config(s->module_config, &http3_module);
    nghttp3_conn_set_max_concurrent_streams(session->ngh3, conf->h3_max_concurrent_streams);
    nghttp3_conn_set_max_client_streams_bidi(session->ngh3, conf->h3_max_concurrent_streams);

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
    h3q_conn* qconn = session->qconn;

    struct
    {
        const char* name;
        int64_t id;
        h3q_stream* st;
    } cs[] = {
        {"control", 0, NULL},
        {"qpack_enc", 0, NULL},
        {"qpack_dec", 0, NULL},
    };
    for (int i = 0; i < 3; i++)
    {
        cs[i].st = h3q_conn_open_uni_stream(qconn, &cs[i].id);
        if (!cs[i].st)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "opening the %s stream failed", cs[i].name);
        }
    }

    if (!cs[0].st || !cs[1].st || !cs[2].st || nghttp3_conn_bind_control_stream(session->ngh3, cs[0].id) != 0 || nghttp3_conn_bind_qpack_streams(session->ngh3, cs[1].id, cs[2].id) != 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "failed to initialize or bind control/qpack streams");
        for (int i = 0; i < 3; i++)
        {
            if (cs[i].st)
            {
                h3q_stream_free(cs[i].st);
            }
        }
        if (session->ngh3)
        {
            nghttp3_conn_del(session->ngh3);
            session->ngh3 = NULL;
        }
        return APR_EGENERAL;
    }

    track_stream(session, cs[0].id, cs[0].st);
    track_stream(session, cs[1].id, cs[1].st);
    track_stream(session, cs[2].id, cs[2].st);
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
    for (apr_hash_index_t* hi = apr_hash_first(NULL, session->streams); hi; hi = apr_hash_next(hi))
    {
        h3_stream* stream = apr_hash_this_val(hi);
        if (stream)
        {
            h3_stream_response_cancel_locked(stream);
            h3_stream_response_cleanup_locked(stream);
        }
    }
    while (session->pending_free->nelts > 0)
    {
        h3q_stream_free(*(h3q_stream**)apr_array_pop(session->pending_free));
    }
    if (session->qconn)
    {
        h3q_conn_free(session->qconn);
        session->qconn = NULL;
    }
    apr_thread_mutex_unlock(session->lock);
    apr_thread_mutex_destroy(session->lock);
    apr_pool_destroy(session->pool);
}

void h3_session_queue_free(h3_session* session, h3q_stream* st)
{
    if (!session || !st)
    {
        return;
    }
    APR_ARRAY_PUSH(session->pending_free, h3q_stream*) = st;
}

apr_status_t h3_stream_response_append(h3_stream* stream, const uint8_t* data, size_t len)
{
    if (!stream || (!data && len != 0))
    {
        return APR_EINVAL;
    }
    h3_session* session = stream->session;
    size_t offset = 0;
    while (offset < len)
    {
        apr_thread_mutex_lock(session->lock);
        while (stream->response_buffered >= stream->response_buffer_limit && !stream->response_cancelled && !session->aborted && !session->ngh3_dead)
        {
            apr_status_t rv = apr_thread_cond_timedwait(stream->response_cond, session->lock, apr_time_from_msec(100));
            if (rv != APR_SUCCESS && !APR_STATUS_IS_TIMEUP(rv))
            {
                apr_thread_mutex_unlock(session->lock);
                return rv;
            }
        }
        if (stream->response_cancelled || session->aborted || session->ngh3_dead || !session->ngh3)
        {
            apr_thread_mutex_unlock(session->lock);
            return APR_ECONNABORTED;
        }

        size_t room = stream->response_buffer_limit - stream->response_buffered;
        size_t chunk_len = len - offset;
        if (chunk_len > room)
        {
            chunk_len = room;
        }
        if (chunk_len > STREAM_CHUNK_BYTES)
        {
            chunk_len = STREAM_CHUNK_BYTES;
        }
        if (chunk_len == 0 || stream->response_len > SIZE_MAX - chunk_len)
        {
            h3_stream_response_cancel_locked(stream);
            apr_thread_mutex_unlock(session->lock);
            return APR_EGENERAL;
        }

        h3_response_chunk* chunk = malloc(sizeof(*chunk) + chunk_len);
        if (!chunk)
        {
            h3_stream_response_cancel_locked(stream);
            apr_thread_mutex_unlock(session->lock);
            return APR_ENOMEM;
        }
        chunk->next = NULL;
        chunk->len = chunk_len;
        chunk->acked = 0;
        memcpy(chunk->data, data + offset, chunk_len);
        if (stream->response_tail)
        {
            stream->response_tail->next = chunk;
        }
        else
        {
            stream->response_head = chunk;
        }
        stream->response_tail = chunk;
        if (!stream->response_submit_chunk)
        {
            stream->response_submit_chunk = chunk;
            stream->response_submit_offset = 0;
        }
        stream->response_buffered += chunk_len;
        stream->response_len += chunk_len;
        if (stream->response_submitted)
        {
            (void)nghttp3_conn_resume_stream(session->ngh3, stream->stream_id);
        }
        apr_thread_mutex_unlock(session->lock);

        offset += chunk_len;
        wake_event_thread();
    }
    return APR_SUCCESS;
}

void h3_stream_response_complete(h3_stream* stream)
{
    if (!stream)
    {
        return;
    }
    h3_session* session = stream->session;
    apr_thread_mutex_lock(session->lock);
    stream->response_complete = 1;
    if (stream->response_submitted && session->ngh3 && !session->ngh3_dead)
    {
        (void)nghttp3_conn_resume_stream(session->ngh3, stream->stream_id);
    }
    apr_thread_cond_broadcast(stream->response_cond);
    apr_thread_mutex_unlock(session->lock);
    wake_event_thread();
}

void h3_stream_response_ack_locked(h3_stream* stream, uint64_t datalen)
{
    if (!stream)
    {
        return;
    }
    int released = 0;
    while (datalen > 0 && stream->response_head)
    {
        h3_response_chunk* chunk = stream->response_head;
        size_t available = chunk->len - chunk->acked;
        size_t consumed = datalen < (uint64_t)available ? (size_t)datalen : available;
        chunk->acked += consumed;
        stream->response_buffered -= consumed;
        datalen -= (uint64_t)consumed;
        released = 1;
        if (chunk->acked == chunk->len)
        {
            stream->response_head = chunk->next;
            if (!stream->response_head)
            {
                stream->response_tail = NULL;
            }
            free(chunk);
        }
    }
    if (released)
    {
        apr_thread_cond_broadcast(stream->response_cond);
    }
}

void h3_stream_response_cancel_locked(h3_stream* stream)
{
    if (!stream)
    {
        return;
    }
    stream->response_cancelled = 1;
    stream->response_complete = 1;
    if (stream->response_cond)
    {
        apr_thread_cond_broadcast(stream->response_cond);
    }
}

void h3_stream_response_cleanup_locked(h3_stream* stream)
{
    if (!stream)
    {
        return;
    }
    h3_response_chunk* chunk = stream->response_head;
    while (chunk)
    {
        h3_response_chunk* next = chunk->next;
        free(chunk);
        chunk = next;
    }
    stream->response_head = NULL;
    stream->response_tail = NULL;
    stream->response_submit_chunk = NULL;
    stream->response_submit_offset = 0;
    stream->response_buffered = 0;
}

nghttp3_ssize h3_session_read_data(nghttp3_conn* conn H3_UNUSED, int64_t stream_id H3_UNUSED, nghttp3_vec* vec, size_t veccnt, uint32_t* pflags, void* user_data H3_UNUSED, void* stream_user_data)
{
    h3_stream* stream = (h3_stream*)stream_user_data;
    if (!stream || !vec || veccnt == 0 || !pflags)
    {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    *pflags = NGHTTP3_DATA_FLAG_NONE;
    if (stream->response_cancelled)
    {
        *pflags = NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }

    size_t count = 0;
    while (stream->response_submit_chunk && count < veccnt)
    {
        h3_response_chunk* chunk = stream->response_submit_chunk;
        size_t remaining = chunk->len - stream->response_submit_offset;
        vec[count].base = chunk->data + stream->response_submit_offset;
        vec[count].len = remaining;
        count++;
        stream->response_submit_chunk = chunk->next;
        stream->response_submit_offset = 0;
    }
    if (count > 0)
    {
        if (!stream->response_submit_chunk && stream->response_complete)
        {
            *pflags = NGHTTP3_DATA_FLAG_EOF;
        }
        return (nghttp3_ssize)count;
    }
    if (stream->response_complete)
    {
        *pflags = NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    return NGHTTP3_ERR_WOULDBLOCK;
}
