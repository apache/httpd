/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef H3Q_H
#define H3Q_H

#include <stddef.h>
#include <stdint.h>

#include <apr_pools.h>

#include "h3_os.h"

typedef struct h3q_engine h3q_engine;
typedef struct h3q_conn h3q_conn;
typedef struct h3q_stream h3q_stream;

#define H3Q_ERRLEN 256

/** Everything the listener needs to exist. */
typedef struct h3q_config
{
    /** TLS context from h3q_tls_ctx_create(); the engine takes its own reference. */
    struct ssl_ctx_st* ssl_ctx;
    /** Parent of the engine's own pool. */
    apr_pool_t* pool;
    /** Called when the peer acknowledges @p len bytes of stream @p stream_id. */
    void (*stream_acked)(void* user, int64_t stream_id, size_t len);
    /** QUIC max_idle_timeout, applied to every connection. */
    uint32_t idle_timeout_secs;
    /** Bidirectional streams a client may have open at once. */
    uint32_t max_streams_bidi;
    /** Cap for flow-control window autotuning, per connection and per stream. */
    size_t max_window;
    unsigned address_validation : 1;
    /** Accept 0-RTT request data on resumed connections. */
    unsigned early_data : 1;
} h3q_config;

/**
 * Build the QUIC listener on @p udp_fd.
 * @param cfg    TLS context, limits, callbacks and feature flags.
 * @param udp_fd Pre-opened non-blocking UDP socket bound to the listen port,
 *               borrowed for the engine's lifetime.
 * @param err    Buffer receiving the reason on failure; may be NULL.
 * @param errlen Capacity of @p err.
 * @return New engine, or NULL on failure.
 */
h3q_engine* h3q_engine_create(const h3q_config* cfg, int udp_fd, char* err, size_t errlen);

/**
 * Tear down the listener, its TLS context and any connections still open.
 * @param engine Engine to destroy; NULL is ignored.
 */
void h3q_engine_destroy(h3q_engine* engine);

/**
 * Drive one round of listener work: read datagrams, run timers, send.
 * @param engine Engine to pump; NULL reports no work.
 * @return 1 if work was done and another pass may be useful, 0 if idle, and
 *         -1 if the socket stopped delivering datagrams.
 */
int h3q_engine_pump(h3q_engine* engine);

/**
 * Report what the engine needs from the next event-loop wait.
 * @param engine     Engine to query; NULL keeps the defaults: reads, on a
 *                   one-second wait.
 * @param want_read  Out: non-zero if the socket should be polled for reads.
 * @param want_write Out: non-zero if the socket should be polled for writes.
 * @param timeout_ms In/out: lowered to the next timer when one is due sooner,
 *                   never below one millisecond.
 */
void h3q_engine_want(h3q_engine* engine, int* want_read, int* want_write, int* timeout_ms);

/**
 * Take the next new connection off the accept queue.
 * @param engine Engine to accept from; NULL yields NULL.
 * @return Accepted connection, or NULL if none is ready.
 */
h3q_conn* h3q_engine_accept_conn(h3q_engine* engine);

/**
 * Copy the peer address from the connection's network path.
 * @param engine   Engine owning @p conn; NULL reports failure.
 * @param conn     Connection to inspect.
 * @param addr     Out: peer socket address.
 * @param addr_len Out: bytes of @p addr that are meaningful.
 * @return 1 if the address was recovered, 0 otherwise.
 */
int h3q_engine_peer_addr(h3q_engine* engine, h3q_conn* conn, struct sockaddr_storage* addr, socklen_t* addr_len);

#endif /* H3Q_H */
