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

#ifndef H3_CALLBACKS_H
#define H3_CALLBACKS_H

#include <nghttp3/nghttp3.h>

/**
 * nghttp3 begin_headers callback. Allocates the h3_stream tracking
 * structure for @p stream_id (or binds the session's pending one) and
 * records it as nghttp3's stream user data.
 * @param conn            The nghttp3 connection.
 * @param stream_id       QUIC stream id the headers are arriving on.
 * @param user_data       The h3_session (set via nghttp3_conn_set_user_data).
 * @param stream_user_data Pre-allocated h3_stream from the session's
 *                        pending slot, or NULL.
 * @return 0 on success, NGHTTP3_ERR_CALLBACK_FAILURE on missing session.
 */
int on_begin_headers(nghttp3_conn* conn, int64_t stream_id, void* user_data, void* stream_user_data);

/**
 * nghttp3 recv_header callback. Stores a single header field on the
 * stream. Pseudo-headers (:method, :scheme, :path, :authority) go into
 * dedicated slots; other headers go into the stream's headers table.
 * @param conn            The nghttp3 connection.
 * @param stream_id       QUIC stream id the header belongs to.
 * @param token           QPACK token id, or -1 for a non-indexed field.
 * @param name            Header name (raw, for non-indexed fields).
 * @param value           Header value bytes.
 * @param flags           nghttp3 header flags (e.g. NGHTTP3_NVA_FLAG_NEVER_INDEX).
 * @param user_data       The h3_session.
 * @param stream_user_data The h3_stream.
 * @return 0 on success, NGHTTP3_ERR_MALFORMED_HTTP_HEADER on a bad
 *         pseudo-header, NGHTTP3_ERR_CALLBACK_FAILURE on missing stream.
 */
int on_recv_header(nghttp3_conn* conn, int64_t stream_id, int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t flags, void* user_data, void* stream_user_data);

/**
 * nghttp3 end_headers callback. Marks the stream as having complete
 * request headers, so subsequent DATA frames can be dispatched.
 * @param conn            The nghttp3 connection.
 * @param stream_id       QUIC stream id whose headers just ended.
 * @param fin             Non-zero if a DATA frame immediately follows
 *                        (i.e. the request has no body).
 * @param user_data       The h3_session.
 * @param stream_user_data The h3_stream.
 * @return 0 on success, NGHTTP3_ERR_CALLBACK_FAILURE on missing stream.
 */
int on_end_headers(nghttp3_conn* conn, int64_t stream_id, int fin, void* user_data, void* stream_user_data);

/**
 * nghttp3 recv_data callback. Consumes @p datalen bytes for @p stream_id.
 * The request dispatcher is invoked once a stream becomes fully readable
 * (HEADERS + DATA complete).
 * @param conn            The nghttp3 connection.
 * @param stream_id       QUIC stream id receiving data.
 * @param data            The DATA payload bytes.
 * @param datalen         Length of @p data in bytes.
 * @param user_data       The h3_session.
 * @param stream_user_data The h3_stream.
 * @return 0 on success, NGHTTP3_ERR_CALLBACK_FAILURE on missing stream.
 */
int on_recv_data(nghttp3_conn* conn, int64_t stream_id, const uint8_t* data, size_t datalen, void* user_data, void* stream_user_data);

/**
 * nghttp3 acked_stream_data callback. The peer has acknowledged
 * @p datalen bytes of response data; advance the per-stream read offset.
 * @param conn            The nghttp3 connection.
 * @param stream_id       QUIC stream id whose response data was acked.
 * @param datalen         Number of bytes the peer has acknowledged.
 * @param user_data       The h3_session.
 * @param stream_user_data The h3_stream.
 * @return 0 on success, NGHTTP3_ERR_CALLBACK_FAILURE on nghttp3 error.
 */
int on_acked_stream_data(nghttp3_conn* conn, int64_t stream_id, uint64_t datalen, void* user_data, void* stream_user_data);

/**
 * nghttp3 stop_sending callback. Peer issued STOP_SENDING; mark the
 * stream aborted so the dispatcher skips it.
 * @param conn            The nghttp3 connection.
 * @param stream_id       QUIC stream id being stopped.
 * @param app_error_code  Application error code from STOP_SENDING.
 * @param user_data       The h3_session.
 * @param stream_user_data The h3_stream.
 * @return 0 on success, NGHTTP3_ERR_CALLBACK_FAILURE on missing stream.
 */
int on_stop_sending(nghttp3_conn* conn, int64_t stream_id, uint64_t app_error_code, void* user_data, void* stream_user_data);

/**
 * nghttp3 reset_stream callback. Peer reset the stream (RESET_STREAM);
 * mark the stream aborted.
 * @param conn            The nghttp3 connection.
 * @param stream_id       QUIC stream id being reset.
 * @param app_error_code  Application error code from RESET_STREAM.
 * @param user_data       The h3_session.
 * @param stream_user_data The h3_stream.
 * @return 0 on success, NGHTTP3_ERR_CALLBACK_FAILURE on missing stream.
 */
int on_reset_stream(nghttp3_conn* conn, int64_t stream_id, uint64_t app_error_code, void* user_data, void* stream_user_data);

/**
 * nghttp3 stream_close callback. Stream is fully closed; release per-stream
 * resources (SSL object, request_rec pool, etc.).
 * @param conn            The nghttp3 connection.
 * @param stream_id       QUIC stream id that closed.
 * @param app_error_code  Final application error code (0 for clean close).
 * @param user_data       The h3_session.
 * @param stream_user_data The h3_stream.
 * @return 0 on success, NGHTTP3_ERR_CALLBACK_FAILURE on missing stream.
 */
int on_stream_close(nghttp3_conn* conn, int64_t stream_id, uint64_t app_error_code, void* user_data, void* stream_user_data);

#endif /* H3_CALLBACKS_H */
