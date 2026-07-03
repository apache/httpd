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
#include <apr_thread_mutex.h>
#include <apr_thread_proc.h>

#include <openssl/ssl.h>

#include <nghttp3/nghttp3.h>

typedef struct h3_session h3_session;
typedef struct h3_stream h3_stream;

struct h3_session
{
    conn_rec* c;
    server_rec* s;
    apr_pool_t* pool;

    SSL* ssl_listener;
    SSL* ssl_conn;
    nghttp3_conn* ngh3;

    apr_thread_mutex_t* lock;

    apr_hash_t* streams;
    int aborted;

    int ngh3_dead;
    uint64_t abort_quic_error_code;
    const char* abort_reason;

    apr_array_header_t* pending_free;

    int control_streams_created;

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
    SSL* ssl_stream;
    int done;

    request_rec* r;
    int is_bidi;

    int headers_complete;
    int dispatched;

    int body_complete;
    int body_truncated;

    const uint8_t* request_body;
    size_t request_body_len;
    size_t request_body_offset;
    int request_body_overflow;

    const char* method;
    const char* scheme;
    const char* authority;
    const char* path;
    apr_table_t* headers;

    const uint8_t* response_data;
    size_t response_len;
    size_t response_offset;
};

/**
 * Allocate and initialize a new HTTP/3 session.
 * @param psession Out parameter for the new session.
 * @param s        The virtual host this session is bound to.
 * @param ssl_listener The QUIC listener SSL (used to clone the ctx).
 * @param ssl_conn The accepted QUIC connection SSL.
 * @param pool     Pool used for all session allocations.
 * @return APR_SUCCESS on success, error code otherwise.
 */
apr_status_t h3_session_create(h3_session** psession, server_rec* s, SSL* ssl_listener, SSL* ssl_conn, apr_pool_t* pool);

/**
 * Create the HTTP/3 control streams (unidirectional, RFC 9114 7.2).
 * @param session The session.
 * @return APR_SUCCESS on success, error code otherwise.
 */
apr_status_t h3_session_create_control_streams(h3_session* session);

/**
 * Tear down a session: stops the SSL object, frees the nghttp3 connection,
 * and destroys the session pool. Safe to call with NULL.
 * @param session The session to destroy (may be NULL).
 */
void h3_session_destroy(h3_session* session);

/**
 * Queue an SSL stream object to be freed when the session lock is next
 * released. Used to defer frees that must not happen while another thread
 * is mid-call.
 * @param session The owning session.
 * @param ssl     The SSL stream object to free.
 */
void h3_session_queue_free(h3_session* session, SSL* ssl);

/**
 * nghttp3 data reader callback. Called by nghttp3 to pull the next chunk of
 * the response body. Backs onto h3_stream::response_data.
 * @return Number of bytes placed in @p vec, or an nghttp3 error code.
 */
nghttp3_ssize h3_session_read_data(nghttp3_conn* conn, int64_t stream_id, nghttp3_vec* vec, size_t veccnt, uint32_t* pflags, void* user_data, void* stream_user_data);

#endif /* H3_SESSION_H */
