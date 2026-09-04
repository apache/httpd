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

#ifndef H3Q_CONN_H
#define H3Q_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "quic/h3q.h"

/// Negotiated TLS parameters of one connection
typedef struct h3q_tls_info
{
    const char* protocol;
    const char* cipher;
    int cipher_bits;
    int cipher_alg_bits;
    unsigned resumed : 1;
} h3q_tls_info;

/**
 * Read the negotiated TLS parameters of a connection.
 * @param conn Connection to query; NULL reports failure.
 * @param out  Filled in on success; untouched otherwise.
 * @return 1 when @p out was filled, 0 when the cipher is not yet known.
 */
int h3q_conn_tls_info(h3q_conn* conn, h3q_tls_info* out);

/**
 * Apply the stream modes, incoming-stream policy and idle timeout a freshly
 * accepted connection needs before its handshake is driven.
 * @param conn              Connection to prepare; NULL reports failure.
 * @param idle_timeout_secs Idle timeout to apply, in seconds.
 * @return 1 on success, 0 on failure.
 */
int h3q_conn_prepare(h3q_conn* conn, uint32_t idle_timeout_secs);

/**
 * Open a server-initiated unidirectional stream.
 * @param conn   Connection to open on.
 * @param out_id Out: the new stream's id.
 * @return New stream, or NULL on failure.
 */
h3q_stream* h3q_conn_open_uni_stream(h3q_conn* conn, int64_t* out_id);

/**
 * Take the next peer-initiated stream.
 * @param conn Connection to accept from; NULL yields NULL.
 * @return Accepted stream, or NULL if none is ready.
 */
h3q_stream* h3q_conn_accept_stream(h3q_conn* conn);

/**
 * Whether the TLS handshake has completed.
 * @param conn Connection to query; NULL counts as unfinished.
 * @return Non-zero once the handshake is done.
 */
int h3q_conn_is_handshake_done(h3q_conn* conn);

/**
 * Whether the connection has finished closing.
 * @param conn Connection to query; NULL counts as closed.
 * @return Non-zero once closed.
 */
int h3q_conn_is_closed(h3q_conn* conn);

/**
 * Begin or continue connection shutdown.
 * @param conn      Connection to close; NULL counts as already closed.
 * @param is_rapid  Non-zero to skip the drain, as on server exit.
 * @param app_error Application error code to report to the peer.
 * @param reason    Text accompanying @p app_error, or NULL to close cleanly.
 * @return 1 when shutdown has completed, 0 while still in progress.
 */
int h3q_conn_shutdown(h3q_conn* conn, int is_rapid, uint64_t app_error, const char* reason);

/**
 * Release a connection handle.
 * @param conn Connection to free; NULL is ignored.
 */
void h3q_conn_free(h3q_conn* conn);

/**
 * Describe why a connection closed, for logging. Reports the peer's error
 * code, frame type and reason string where OpenSSL has them, and whatever the
 * error queue holds otherwise.
 * @param conn   Connection to inspect; NULL reports the error queue alone.
 * @param buf    Buffer receiving the description, always NUL-terminated.
 * @param buflen Capacity of @p buf; zero is ignored.
 */
void h3q_conn_close_reason(h3q_conn* conn, char* buf, size_t buflen);

#endif /* H3Q_CONN_H */
