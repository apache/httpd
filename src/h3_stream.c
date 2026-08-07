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

#include <apr_atomic.h>
#include <apr_hash.h>
#include <apr_pools.h>

#include <stdlib.h>

#include <nghttp3/nghttp3.h>

#include "quic/h3q_stream.h"

#include "h3.h"
#include "h3_check.h"
#include "h3_config.h"
#include "h3_io.h"
#include "h3_session.h"
#include "h3_stream.h"
#include "mod_http3.h"

/* Per-pass read budget so one busy stream cannot starve the others. */
#define H3_STREAM_DRAIN_READ_BUDGET 256
#define H3_STREAM_DRAIN_BYTE_BUDGET (1024 * 1024)

h3_stream* h3_stream_find(h3_session* session, int64_t sid)
{
    CHECK(session);
    return apr_hash_get(session->streams, &sid, sizeof(sid));
}

static void mark_ngh3_dead(h3_session* session, const char* op, int64_t stream_id, nghttp3_ssize liberr);

/* Re-enable write-blocked streams once their QUIC send buffer has room. */
static void unblock_writable_streams(h3_session* session)
{
    if (session->blocked_streams <= 0)
    {
        return;
    }
    for (apr_hash_index_t* hi = apr_hash_first(NULL, session->streams); hi; hi = apr_hash_next(hi))
    {
        h3_stream* h3s = apr_hash_this_val(hi);
        if (!h3s || !h3s->write_blocked)
        {
            continue;
        }
        if (h3s->qstream && h3q_stream_is_write_blocked(h3s->qstream))
        {
            continue; /* still full */
        }
        h3s->write_blocked = 0;
        session->blocked_streams--;
        nghttp3_conn_unblock_stream(session->ngh3, h3s->stream_id);
    }
}

void flush_nghttp3(h3_session* session)
{
    CHECK(session);
    CHECK(!session->ngh3_dead, return;);
    unblock_writable_streams(session);
    for (;;)
    {
        nghttp3_vec vec[16] = {0};
        int64_t sid = -1;
        int fin = 0;
        nghttp3_ssize nvec = nghttp3_conn_writev_stream(session->ngh3, &sid, &fin, vec, 16);
        if (nvec < 0)
        {
            mark_ngh3_dead(session, "nghttp3_conn_writev_stream", sid, nvec);
            break;
        }
        if (nvec == 0 && sid < 0)
        {
            break; /* nothing left to send */
        }
        size_t expected = 0;
        for (nghttp3_ssize k = 0; k < nvec; k++)
        {
            expected += vec[k].len;
        }
        h3_stream* h3s = h3_stream_find(session, sid);
        if (!h3s || !h3s->qstream)
        {
            /* Stream is gone; swallow its queued bytes so the send queue keeps draining. */
            nghttp3_conn_add_write_offset(session->ngh3, sid, expected);
            nghttp3_conn_add_ack_offset(session->ngh3, sid, expected);
            continue;
        }
        h3q_write_result res = h3q_stream_write(h3s->qstream, (const h3q_vec*)vec, (size_t)nvec, fin);
        if (res.accepted > 0 && child_h3_io)
        {
            apr_atomic_add64(&child_h3_io->total_bytes_written, res.accepted);
        }
        if (res.broken)
        {
            /* Peer reset: drop the remainder; teardown happens via the nghttp3 callbacks. */
            nghttp3_conn_add_write_offset(session->ngh3, sid, expected);
            nghttp3_conn_add_ack_offset(session->ngh3, sid, expected);
            continue;
        }
        nghttp3_conn_add_write_offset(session->ngh3, sid, res.accepted);
        nghttp3_conn_add_ack_offset(session->ngh3, sid, res.accepted);
        if (res.blocked)
        {
            /* Send buffer full: skip this stream instead of busy-looping on the same vec. */
            if (!h3s->write_blocked)
            {
                h3s->write_blocked = 1;
                session->blocked_streams++;
                nghttp3_conn_block_stream(session->ngh3, sid);
            }
            continue;
        }
    }
    if (session->pending_free->nelts > 0)
    {
        while (session->pending_free->nelts > 0)
        {
            h3q_stream* st = *(h3q_stream**)apr_array_pop(session->pending_free);
            if (st)
            {
                h3q_stream_free(st);
            }
        }
    }
}

h3_stream* track_stream(h3_session* session, int64_t sid, h3q_stream* qstream)
{
    CHECK(session);
    CHECK(qstream);
    h3_stream* h3s = h3_stream_find(session, sid);
    if (h3s)
    {
        h3s->qstream = qstream;
        return h3s;
    }
    apr_pool_t* stream_pool = NULL;
    CHECK(apr_pool_create(&stream_pool, session->pool) == APR_SUCCESS);
    h3s = apr_pcalloc(session->pool, sizeof(*h3s));
    h3s->session = session;
    h3s->pool = stream_pool;
    h3s->stream_id = sid;
    h3s->qstream = qstream;
    h3s->is_bidi = H3_SID_IS_BIDI(sid);
    h3_server_conf* conf = ap_get_module_config(session->s->module_config, &http3_module);
    h3s->response_buffer_limit = conf && conf->h3_stream_buffer_size ? (size_t)conf->h3_stream_buffer_size : (size_t)H3_STREAM_BUFFER_SIZE_DEFAULT;
    if (apr_thread_cond_create(&h3s->response_cond, stream_pool) != APR_SUCCESS)
    {
        apr_pool_destroy(stream_pool);
        return NULL;
    }
    apr_hash_set(session->streams, &h3s->stream_id, sizeof(h3s->stream_id), h3s);
    return h3s;
}

static void mark_ngh3_dead(h3_session* session, const char* op, int64_t stream_id, nghttp3_ssize liberr)
{
    session->ngh3_dead = 1;
    session->abort_quic_error_code = nghttp3_err_infer_quic_app_error_code((int)liberr);
    session->abort_reason = nghttp3_strerror((int)liberr);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, session->s, "%s failed for stream %" APR_INT64_T_FMT " (%s, err=%" APR_INT64_T_FMT "); closing with QUIC error 0x%" APR_UINT64_T_HEX_FMT, op, stream_id, session->abort_reason, (apr_int64_t)liberr, session->abort_quic_error_code);
}

static void feed_stream_fin(h3_session* session, h3_stream* h3s)
{
    nghttp3_ssize consumed = nghttp3_conn_read_stream(session->ngh3, h3s->stream_id, NULL, 0, 1);
    if (consumed < 0)
    {
        mark_ngh3_dead(session, "nghttp3_conn_read_stream", h3s->stream_id, consumed);
    }
    h3s->body_complete = 1;
}

static int drain_one_stream(h3_session* session, h3_stream* h3s, int* data_read, size_t* reads_remaining, size_t* bytes_remaining)
{
    CHECK(session);
    CHECK(h3s);
    CHECK(data_read);

    h3_server_conf* conf = ap_get_module_config(session->s->module_config, &http3_module);
    apr_size_t buf_size = conf->h3_stream_buffer_size;
    if (!session->stream_read_buf || session->stream_read_buf_size < buf_size)
    {
        session->stream_read_buf = apr_palloc(session->pool, buf_size);
        session->stream_read_buf_size = buf_size;
    }
    unsigned char* buf = session->stream_read_buf;

    int read_finished = 0;
    int write_finished = 0;
    if (h3s->qstream)
    {
        h3q_stream_is_read_finished(h3s->qstream, &read_finished, &write_finished);
    }
    if (read_finished)
    {
        if (!h3s->body_complete)
        {
            feed_stream_fin(session, h3s);
        }
        if (h3s->qstream && write_finished)
        {
            nghttp3_conn_close_stream(session->ngh3, h3s->stream_id, NGHTTP3_H3_NO_ERROR);
        }
        return h3s->is_bidi && h3s->headers_complete && h3s->body_complete && !h3s->dispatched;
    }

    while (*reads_remaining > 0 && *bytes_remaining > 0)
    {
        if (!h3s->qstream)
        {
            h3s->done = 1;
            break;
        }

        size_t nread = 0;
        size_t read_size = buf_size < *bytes_remaining ? buf_size : *bytes_remaining;
        int fin = 0;
        int ok = h3q_stream_read(h3s->qstream, buf, read_size, &nread, &fin);
        if (ok && nread > 0)
        {
            (*reads_remaining)--;
            *bytes_remaining -= nread;
            if (child_h3_io)
            {
                apr_atomic_add64(&child_h3_io->total_bytes_read, nread);
            }
            *data_read = 1;
            session->pending.sid = h3s->stream_id;
            session->pending.h3s = h3s;
            nghttp3_ssize consumed = nghttp3_conn_read_stream(session->ngh3, h3s->stream_id, buf, nread, 0);
            session->pending.sid = -1;
            session->pending.h3s = NULL;
            if (consumed < 0)
            {
                /* Mark dead if read fails. */
                mark_ngh3_dead(session, "nghttp3_conn_read_stream", h3s->stream_id, consumed);
                h3s->done = 1;
                break;
            }
            if (h3s->done)
            {
                break;
            }
            continue;
        }
        if (fin)
        {
            feed_stream_fin(session, h3s);
        }
        break;
    }
    return h3s->is_bidi && h3s->headers_complete && h3s->body_complete && !h3s->dispatched;
}

apr_array_header_t* drain_ready_streams(h3_session* session, apr_pool_t* loop_pool, int* data_read)
{
    CHECK(session);
    CHECK(loop_pool);
    CHECK(data_read);
    *data_read = 0;
    apr_array_header_t* completed = apr_array_make(loop_pool, 4, sizeof(h3_stream*));

    unsigned int total_streams = apr_hash_count(session->streams);
    unsigned int iterations = 0;
    apr_array_header_t* snapshot = apr_array_make(loop_pool, 8, sizeof(h3_stream*));
    for (apr_hash_index_t* hi = apr_hash_first(NULL, session->streams); hi; hi = apr_hash_next(hi))
    {
        if (++iterations > total_streams + 100)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, session->s, "hash iteration did not terminate after %u entries (hash reports %u) - hash corruption, aborting connection", iterations, total_streams);
            session->aborted = 1;
            break;
        }
        h3_stream* h3s = apr_hash_this_val(hi);
        if (h3s)
        {
            *(h3_stream**)apr_array_push(snapshot) = h3s;
        }
    }

    size_t reads_remaining = H3_STREAM_DRAIN_READ_BUDGET;
    size_t bytes_remaining = H3_STREAM_DRAIN_BYTE_BUDGET;
    size_t start = snapshot->nelts > 0 ? session->stream_drain_cursor % (size_t)snapshot->nelts : 0;
    for (int offset = 0; offset < snapshot->nelts; offset++)
    {
        if (session->ngh3_dead)
        {
            break;
        }
        size_t i = (start + (size_t)offset) % (size_t)snapshot->nelts;
        h3_stream* h3s = ((h3_stream**)snapshot->elts)[i];

        if (h3s->done || !h3s->qstream)
        {
            continue;
        }
        if (H3_SID_IS_SERVER(h3s->stream_id))
        {
            continue;
        }
        if (drain_one_stream(session, h3s, data_read, &reads_remaining, &bytes_remaining) && !session->ngh3_dead)
        {
            h3_stream** slot = (h3_stream**)apr_array_push(completed);
            *slot = h3s;
        }
        if (reads_remaining == 0 || bytes_remaining == 0)
        {
            /* Budget spent: resume from the next stream on the following pass. */
            session->stream_drain_cursor = (i + 1) % (size_t)snapshot->nelts;
            break;
        }
    }

    int done_but_has_stream = 0;
    for (int i = 0; i < snapshot->nelts; i++)
    {
        h3_stream* h3s = ((h3_stream**)snapshot->elts)[i];
        if (h3s)
        {
            /* Only request streams are reclaimed; control streams live for the connection. */
            if (h3s->is_bidi && !H3_SID_IS_SERVER(h3s->stream_id))
            {
                if (h3s->done && h3s->qstream == NULL && h3s->dispatched && h3s->worker_done)
                {
                    /* Closed, QUIC stream freed, worker returned: no other thread can reach its pool. */
                    if (h3s->write_blocked)
                    {
                        h3s->write_blocked = 0;
                        session->blocked_streams--;
                    }
                    apr_hash_set(session->streams, &h3s->stream_id, sizeof(h3s->stream_id), NULL);
                    h3_stream_response_cleanup_locked(h3s);
                    if (h3s->pool)
                    {
                        apr_pool_destroy(h3s->pool);
                    }
                }
                else if (h3s->done && h3s->qstream != NULL)
                {
                    done_but_has_stream++;
                }
            }
        }
    }
    if (done_but_has_stream > 0)
    {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, session->s, "%d stream(s) marked done but still holding a qstream (total=%u, remaining=%u)", done_but_has_stream, total_streams, apr_hash_count(session->streams));
    }

    return completed;
}
