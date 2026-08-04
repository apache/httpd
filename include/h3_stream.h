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

#ifndef H3_STREAM_H
#define H3_STREAM_H

#include <httpd.h>

#include <apr_pools.h>

#include "quic/h3q.h"

#include "h3_session.h"

/**
 * Drive the nghttp3 connection: build any pending outbound frames and write
 * them onto the QUIC connection. Safe to call repeatedly; no-ops if there
 * is nothing to send.
 * @param session The session whose nghttp3 state to flush.
 */
void flush_nghttp3(h3_session* session);

/**
 * Allocate and register a new h3_stream for the given stream id.
 * @param session  The session that owns the stream.
 * @param sid      The QUIC stream id (RFC 9000).
 * @param qstream  The QUIC stream object backing the new stream.
 * @return The new h3_stream, or NULL on allocation failure.
 */
h3_stream* track_stream(h3_session* session, int64_t sid, h3q_stream* qstream);

/**
 * Read whatever's available on the underlying QUIC stream and drive the
 * matching nghttp3 stream state machine. Returns the set of streams that
 * became fully readable (HEADERS+DATA complete) and ready for the request
 * dispatcher.
 * @param session   The session.
 * @param loop_pool Scratch pool for per-iteration allocations.
 * @param data_read Out: set to non-zero if any stream data was read, else zero.
 * @return Array of h3_stream* (possibly empty), allocated in loop_pool.
 */
apr_array_header_t* drain_ready_streams(h3_session* session, apr_pool_t* loop_pool, int* data_read);

/**
 * Look up an existing h3_stream by stream id.
 * @param session The owning session.
 * @param sid     The QUIC stream id to find.
 * @return The matching h3_stream, or NULL if not present.
 */
h3_stream* h3_stream_find(h3_session* session, int64_t sid);

#endif /* H3_STREAM_H */
