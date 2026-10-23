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

#ifndef H3Q_STREAM_H
#define H3Q_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "quic/h3q.h"

/** One buffer to send; layout-compatible with nghttp3_vec. */
typedef struct h3q_vec
{
    const uint8_t* base;
    size_t len;
} h3q_vec;

/** What a stream write achieved, and how it stopped. */
typedef struct h3q_write_result
{
    size_t accepted;
    unsigned blocked : 1;
    unsigned broken : 1;
} h3q_write_result;

/**
 * Stream id.
 * @param st Stream to query.
 * @return The stream's id, or -1 when @p st is NULL.
 */
int64_t h3q_stream_id(h3q_stream* st);

/**
 * Write buffers to a stream, optionally closing it.
 * @param st   Stream to write to.
 * @param vec  Buffers to send.
 * @param nvec Number of buffers in @p vec.
 * @param fin  Non-zero to close the stream after these bytes.
 * @return What was accepted, and whether the write blocked or broke.
 * @note Bytes count as acknowledged once accepted: OpenSSL reports no
 *       per-stream acknowledgements.
 */
h3q_write_result h3q_stream_write(h3q_stream* st, const h3q_vec* vec, size_t nvec, int fin);

/**
 * Whether the stream can currently accept more bytes.
 * @param st Stream to query.
 * @return Non-zero when blocked.
 */
int h3q_stream_is_write_blocked(h3q_stream* st);

/**
 * Read from a stream.
 * @param st        Stream to read from.
 * @param buf       Destination buffer.
 * @param read_size Capacity of @p buf.
 * @param nread     Out: bytes written to @p buf.
 * @param fin       Out: non-zero once the peer has finished sending.
 * @return 1 if bytes were read, 0 otherwise.
 */
int h3q_stream_read(h3q_stream* st, unsigned char* buf, size_t read_size, size_t* nread, int* fin);

/**
 * Report whether each direction of a stream has finished.
 * @param st             Stream to query.
 * @param read_finished  Out: non-zero if reading is finished or reset.
 * @param write_finished Out: non-zero if writing is finished or reset.
 */
void h3q_stream_is_read_finished(h3q_stream* st, int* read_finished, int* write_finished);

/**
 * Abort the sending half of a stream.
 * @param st  Stream to reset; NULL is ignored.
 * @param err Application error code to report.
 */
void h3q_stream_reset(h3q_stream* st, uint64_t err);

/**
 * Free a stream handle.
 * @param st Stream to free; NULL is ignored.
 */
void h3q_stream_free(h3q_stream* st);

#endif /* H3Q_STREAM_H */
