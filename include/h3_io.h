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
#include <apr_thread_pool.h>
#include <apr_thread_proc.h>

#include "h3_config.h"
#include "h3_socket.h"
#include "quic/h3q.h"

typedef struct h3_session h3_session;

typedef struct h3_io_t
{
    h3q_engine* qengine;
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
    /* Set by a graceful stop: keep servicing the sessions we already have,
     * but accept no new ones.  The event thread keeps running so in-flight
     * streams can finish; the MPM bounds how long the child waits for them. */
    volatile int draining;
    h3_wakeup wakeup;

    APR_OPTIONAL_FN_TYPE(ap_mpm_note_extra_connection_added) * note_conn_added;
    APR_OPTIONAL_FN_TYPE(ap_mpm_note_extra_connection_removed) * note_conn_removed;

    apr_array_header_t* pending_handshakes;
    apr_thread_pool_t* h3_worker_pool;
} h3_io_t;

typedef struct h3_pending_handshake
{
    h3q_conn* conn;
    apr_time_t accepted_at;
} h3_pending_handshake;

extern h3_io_t* child_h3_io;

/**
 * Build the listener, bind the UDP socket via @p udp_fd, and spawn the
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
 * Begin a graceful drain: stop accepting connections and send GOAWAY on the
 * live ones, letting their in-flight streams finish. Returns immediately;
 * every session is noted with the MPM, so the child stays up while they
 * drain and the MPM bounds the wait. Safe to call with NULL.
 * @param io The h3_io_t to drain.
 */
void h3_io_listen_drain(h3_io_t* io);

/**
 * Stop the event thread, join all worker threads, and release the UDP fd
 * and engine. Sessions still alive are given H3_GOAWAY_GRACE_SECS to finish
 * before being cut. Safe to call with NULL, and safe to call twice.
 * @param io The h3_io_t to tear down.
 */
void h3_io_listen_stop(h3_io_t* io);

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
 * @return Non-zero when stream input made progress and another pass should run without polling.
 */
int service_session_pass(h3_io_t* io, h3_session* session);

/**
 * Wait for network read/write events using poll().
 * @param io The listener whose socket and wakeup pipe should be polled.
 */
void wait_for_event(h3_io_t* io);

/**
 * Remove a connection from the pending handshake array.
 * @param io        The owning h3_io_t listener instance.
 * @param index     The index of the connection in the array.
 * @param free_conn If non-zero, the connection object is freed.
 */
void remove_pending_handshake(h3_io_t* io, int index, int free_conn);

/**
 * Prepare a newly accepted connection before starting the handshake.
 * Sets stream modes, Incoming Stream policies, and pushes it to the pending array.
 * @param io   The owning h3_io_t listener instance.
 * @param conn The newly accepted QUIC connection instance.
 * @return 1 on success, 0 otherwise.
 */
int prepare_accepted_connection(h3_io_t* io, h3q_conn* conn);

/**
 * Progress handshakes for all pending connections, timing out stalled connections
 * and adding completed connections to the event loop.
 * @param io The owning h3_io_t listener instance.
 */
void progress_pending_handshakes(h3_io_t* io);

#endif /* H3_IO_H */
