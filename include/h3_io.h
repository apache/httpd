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

#ifndef H3_IO_H
#define H3_IO_H

#include <httpd.h>

#include <mpm_common.h>

#include <apr_atomic.h>
#include <apr_optional.h>
#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_thread_proc.h>

#include <openssl/ssl.h>

#include "h3_config.h"

typedef struct h3_session h3_session;

typedef struct h3_io_t
{
    SSL_CTX* ssl_ctx;
    SSL* ssl_listener;
    apr_pool_t* pool;
    server_rec* server;
    int udp_fd;
    apr_thread_t* event_thread;
    apr_thread_mutex_t* workers_lock;
    apr_array_header_t* workers;
    volatile apr_uint32_t live_workers;
    volatile int thread_running;

    APR_OPTIONAL_FN_TYPE(ap_mpm_note_extra_connection_added) * note_conn_added;
    APR_OPTIONAL_FN_TYPE(ap_mpm_note_extra_connection_removed) * note_conn_removed;
} h3_io_t;

extern h3_io_t* child_h3_io;

/**
 * Build the SSL listener, bind the UDP socket via @p udp_fd, and spawn the
 * event thread. Idempotent on the same port: returns APR_EAGAIN if another
 * child already owns it.
 * @param pchild  Child process pool.
 * @param s       The server_rec this listener is associated with.
 * @param conf    The vhost's h3_server_conf (cert/key paths, port).
 * @param udp_fd  Pre-opened non-blocking UDP socket bound to the listen port.
 * @return APR_SUCCESS on success, APR_EAGAIN if the port is already owned,
 *         or another APR error code.
 */
apr_status_t h3_io_listen_start(apr_pool_t* pchild, server_rec* s, h3_server_conf* conf, int udp_fd);

/**
 * Stop the event thread, join all worker threads, and release the UDP fd
 * and SSL context. Safe to call with NULL.
 * @param io The h3_io_t to tear down.
 */
void h3_io_listen_stop(h3_io_t* io);

/**
 * Spawn a worker thread that services a freshly accepted QUIC session.
 * @param io      The owning h3_io_t (used to register the new thread).
 * @param session The accepted session, already populated.
 * @return APR_SUCCESS on success, error code otherwise.
 */
apr_status_t h3_io_spawn_worker(h3_io_t* io, h3_session* session);

/** apr_thread_t entry point: drives OpenSSL's QUIC event loop for this child. */
void* APR_THREAD_FUNC quic_event_thread(apr_thread_t* thread, void* data);

#endif /* H3_IO_H */
