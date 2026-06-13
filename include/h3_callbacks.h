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

int on_recv_header(nghttp3_conn* conn, int64_t stream_id, int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t flags, void* user_data, void* stream_user_data);
int on_end_headers(nghttp3_conn* conn, int64_t stream_id, int fin, void* user_data, void* stream_user_data);
int on_recv_data(nghttp3_conn* conn, int64_t stream_id, const uint8_t* data, size_t datalen, void* conn_user_data, void* stream_user_data);
int on_end_stream(nghttp3_conn* h3conn, int64_t stream_id, void* conn_user_data, void* stream_user_data);
int on_stream_close(nghttp3_conn* h3conn, int64_t stream_id, uint64_t app_error_code, void* conn_user_data, void* stream_user_data);

#endif /* H3_CALLBACKS_H */
