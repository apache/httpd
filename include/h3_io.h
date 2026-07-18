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

/// Optional MPM hooks; crash at runtime if unsupported.
APR_DECLARE_OPTIONAL_FN(void, ap_mpm_note_extra_connection_added, (void));
APR_DECLARE_OPTIONAL_FN(void, ap_mpm_note_extra_connection_removed, (void));

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
    volatile apr_uint32_t total_connections;
    volatile apr_uint32_t total_streams;
    volatile apr_uint64_t total_bytes_read;
    volatile apr_uint64_t total_bytes_written;
    volatile int thread_running;

    APR_OPTIONAL_FN_TYPE(ap_mpm_note_extra_connection_added) * note_conn_added;
    APR_OPTIONAL_FN_TYPE(ap_mpm_note_extra_connection_removed) * note_conn_removed;

    apr_array_header_t* pending_handshakes;
} h3_io_t;

typedef struct h3_pending_handshake
{
    SSL* conn;
    apr_time_t accepted_at;
} h3_pending_handshake;

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

/**
 * Check if the active connection limit (H3MaxConnections) is reached.
 * @param io The h3_io_t instance to check.
 * @return Non-zero if at the limit, zero otherwise.
 */
int h3_io_at_connection_limit(h3_io_t* io);

/**
 * Service the newly established session connection. Drives HTTP/3 request processing.
 * @param io      The owning h3_io_t listener instance.
 * @param session The h3_session to service.
 */
void service_connection(h3_io_t* io, h3_session* session);

/**
 * Wait for network read/write events using select().
 * @param fd         The socket file descriptor.
 * @param ssl        The SSL connection instance.
 * @param want_write Unused parameter.
 */
void wait_for_event(int fd, SSL* ssl, int want_write);

/**
 * Handle engine events and progress the SSL listener.
 * @param conn The SSL connection instance.
 * @return 1 on success, 0 otherwise.
 */
int tick_engine(SSL* conn);

/**
 * Remove a connection from the pending handshake array.
 * @param io        The owning h3_io_t listener instance.
 * @param index     The index of the connection in the array.
 * @param free_conn If non-zero, the connection's SSL object is freed.
 */
void remove_pending_handshake(h3_io_t* io, int index, int free_conn);

/**
 * Prepare a newly accepted connection before starting the handshake.
 * Sets stream modes, Incoming Stream policies, and pushes it to the pending array.
 * @param io   The owning h3_io_t listener instance.
 * @param conn The newly accepted SSL connection instance.
 * @return 1 on success, 0 otherwise.
 */
int prepare_accepted_connection(h3_io_t* io, SSL* conn);

/**
 * Progress handshakes for all pending connections, timing out stalled connections
 * and spawning worker threads for completed handshakes.
 * @param io The owning h3_io_t listener instance.
 */
void progress_pending_handshakes(h3_io_t* io);

#endif /* H3_IO_H */
