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

#ifndef H3_SESSION_H
#define H3_SESSION_H

#include <httpd.h>

#include <apr_hash.h>
#include <apr_pools.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_thread_proc.h>

#include <nghttp3/nghttp3.h>

#include "quic/h3q.h"

typedef struct h3_session h3_session;
typedef struct h3_stream h3_stream;
typedef struct h3_response_chunk h3_response_chunk;

/// mod_ssl-compatible TLS environment for one connection, all members are NULL when TLS details are unavailable.
typedef struct h3_tls_env
{
    const char* protocol;
    const char* cipher;
    const char* cipher_usekeysize;
    const char* cipher_algkeysize;
    const char* cipher_export;
    const char* session_resumed;
} h3_tls_env;

struct h3_session
{
    conn_rec* c;
    server_rec* s;
    apr_pool_t* pool;

    h3_tls_env tls_env;

    h3q_conn* qconn;
    nghttp3_conn* ngh3;

    apr_thread_mutex_t* lock;

    apr_hash_t* streams;
    int aborted;
    /* Number of streams write-blocked in nghttp3 (see flush_nghttp3). */
    int blocked_streams;

    int ngh3_dead;
    uint64_t abort_quic_error_code;
    const char* abort_reason;

    apr_array_header_t* pending_free;

    unsigned char* stream_read_buf;
    apr_size_t stream_read_buf_size;
    size_t stream_drain_cursor;

    int control_streams_created;
    int goaway_sent;
    apr_time_t goaway_deadline;

    apr_time_t last_activity;

    volatile apr_uint32_t active_tasks;

    struct
    {
        int64_t sid;
        h3_stream* h3s;
    } pending;
};

struct h3_stream
{
    h3_session* session;
    apr_pool_t* pool;
    int64_t stream_id;
    h3q_stream* qstream;
    int done;
    /* QUIC stream send buffer was full; nghttp3 told to skip the stream. */
    int write_blocked;

    request_rec* r;
    int is_bidi;

    int headers_complete;
    int dispatched;
    int worker_done;

    int body_complete;
    int body_truncated;

    const uint8_t* request_body;
    size_t request_body_len;
    size_t request_body_offset;
    size_t request_body_capacity;
    int request_body_overflow;

    int malformed;

    const char* method;
    const char* scheme;
    const char* authority;
    const char* path;
    apr_table_t* headers;

    apr_thread_cond_t* response_cond;
    h3_response_chunk* response_head;
    h3_response_chunk* response_tail;
    h3_response_chunk* response_submit_chunk;
    size_t response_submit_offset;
    size_t response_buffered;
    size_t response_len;
    size_t response_buffer_limit;
    int response_submitted;
    int response_complete;
    int response_cancelled;
};

/**
 * Allocate and initialize a new HTTP/3 session.
 * @param psession Out parameter for the new session.
 * @param s        The virtual host this session is bound to.
 * @param qconn    The accepted QUIC connection.
 * @param pool     Pool used for all session allocations.
 * @return APR_SUCCESS on success, error code otherwise.
 */
apr_status_t h3_session_create(h3_session** psession, server_rec* s, h3q_conn* qconn, apr_pool_t* pool);

/**
 * Create the HTTP/3 control streams (unidirectional, RFC 9114 7.2).
 * @param session The session.
 * @return APR_SUCCESS on success, error code otherwise.
 */
apr_status_t h3_session_create_control_streams(h3_session* session);

/**
 * Tear down a session: closes the QUIC connection, frees the nghttp3 connection,
 * and destroys the session pool. Safe to call with NULL.
 * @param session The session to destroy (may be NULL).
 */
void h3_session_destroy(h3_session* session);

/**
 * Queue a QUIC stream object to be freed when the session lock is next
 * released. Used to defer frees that must not happen while another thread
 * is mid-call.
 * @param session The owning session.
 * @param st      The QUIC stream object to free.
 */
void h3_session_queue_free(h3_session* session, h3q_stream* st);

/**
 * nghttp3 data reader callback. Called by nghttp3 to pull the next chunks of
 * the response body off the stream's bounded queue (h3_stream::response_head,
 * walked via response_submit_chunk).
 * @return Number of vectors filled, NGHTTP3_ERR_WOULDBLOCK when the queue is
 *         empty but the response is not finished, or an nghttp3 error code.
 */
nghttp3_ssize h3_session_read_data(nghttp3_conn* conn, int64_t stream_id, nghttp3_vec* vec, size_t veccnt, uint32_t* pflags, void* user_data, void* stream_user_data);

/**
 * Copy response bytes into the stream's bounded producer/consumer queue.
 * Blocks the Apache request worker when the queue is full and wakes when the
 * QUIC event thread accepts bytes or the stream is cancelled.
 */
apr_status_t h3_stream_response_append(h3_stream* stream, const uint8_t* data, size_t len);

/** Mark the response producer complete and resume a blocked nghttp3 reader. */
void h3_stream_response_complete(h3_stream* stream);

/**
 * Account application response bytes acknowledged by nghttp3. The session
 * mutex must already be held.
 */
void h3_stream_response_ack_locked(h3_stream* stream, uint64_t datalen);

/** Cancel a response producer and wake it. The session mutex must be held. */
void h3_stream_response_cancel_locked(h3_stream* stream);

/** Free queued response chunks. The session mutex must be held. */
void h3_stream_response_cleanup_locked(h3_stream* stream);

#endif /* H3_SESSION_H */
