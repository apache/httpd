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
#include <apr_thread_proc.h>
#include <apr_thread_pool.h>

#include <openssl/ssl.h>

#include "h3_config.h"

/// Optional MPM hooks; crash at runtime if unsupported.
APR_DECLARE_OPTIONAL_FN(void, ap_mpm_note_extra_connection_added, (void));
APR_DECLARE_OPTIONAL_FN(void, ap_mpm_note_extra_connection_removed, (void));

typedef struct h3_session h3_session;
typedef struct h3_peer_datagram h3_peer_datagram;

typedef struct h3_io_t
{
    SSL_CTX* ssl_ctx;
    SSL* ssl_listener;
    BIO_METHOD* peer_addr_bio_method;
    BIO_ADDR* current_peer_addr;
    int peer_addr_ex_index;
    h3_peer_datagram* peer_rx_head;
    h3_peer_datagram* peer_rx_tail;
    apr_pool_t* pool;
    server_rec* server;
    int udp_fd;
    apr_thread_t* event_thread;
    apr_array_header_t* active_sessions;
    volatile apr_uint32_t active_session_count;
    volatile apr_uint32_t total_connections;
    volatile apr_uint32_t total_streams;
    volatile apr_uint64_t total_bytes_read;
    volatile apr_uint64_t total_bytes_written;
    volatile int thread_running;
    apr_file_t* wakeup_pipe[2];

    APR_OPTIONAL_FN_TYPE(ap_mpm_note_extra_connection_added) * note_conn_added;
    APR_OPTIONAL_FN_TYPE(ap_mpm_note_extra_connection_removed) * note_conn_removed;

    apr_array_header_t* pending_handshakes;
    apr_thread_pool_t* h3_worker_pool;
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
 * Check if the active connection limit (H3MaxConnections) is reached.
 * @param io The h3_io_t instance to check.
 * @return Non-zero if at the limit, zero otherwise.
 */
int h3_io_at_connection_limit(h3_io_t* io);

/** Return non-zero while the address-aware BIO has buffered received datagrams. */
int h3_io_has_buffered_datagrams(h3_io_t* io);

/**
 * Retrieve the UDP peer address captured when OpenSSL created a pending QUIC
 * connection. OpenSSL 3.5 does not otherwise expose an accepted connection's
 * peer address through its public API.
 * @param io        The owning listener instance.
 * @param conn      The accepted QUIC connection.
 * @param pool      Pool used for the APR address and numeric IP string.
 * @param addr      Receives the client's socket address.
 * @param client_ip Receives the client's numeric IP string.
 * @return APR_SUCCESS when an address is available, or an APR error.
 */
apr_status_t h3_io_get_client_addr(h3_io_t* io, SSL* conn, apr_pool_t* pool, apr_sockaddr_t** addr, char** client_ip);

/**
 * Service the newly established session connection. Drives HTTP/3 request processing.
 * @param io      The owning h3_io_t listener instance.
 * @param session The h3_session to service.
 * @return Non-zero when stream input made progress and another pass should run without polling.
 */
int service_session_pass(h3_io_t* io, h3_session* session);

/**
 * Wait for network read/write events using poll().
 * @param io The listener whose socket and wakeup pipe should be polled.
 */
void wait_for_event(h3_io_t* io);

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
 * and adding completed connections to the event loop.
 * @param io The owning h3_io_t listener instance.
 */
void progress_pending_handshakes(h3_io_t* io);

#endif /* H3_IO_H */
