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

#ifndef H3_QUIC_IO_H
#define H3_QUIC_IO_H

#include <openssl/ssl.h>

#include <nghttp3/nghttp3.h>

#include "h3_ssl.h"

int quic_server_read(nghttp3_conn* h3conn, SSL* stream, uint64_t id, struct h3ssl* h3ssl, struct ssl_id* ssl_ids);
int quic_server_h3streams(nghttp3_conn* h3conn, struct h3ssl* h3ssl, struct ssl_id* ssl_ids);
nghttp3_ssize step_read_data(nghttp3_conn* conn, int64_t stream_id, nghttp3_vec* vec, size_t veccnt, uint32_t* pflags, void* user_data, void* stream_user_data);
int quic_server_write(struct ssl_id* ssl_ids, uint64_t streamid, uint8_t* buff, size_t len, uint64_t flags, size_t* written);

#endif /* H3_QUIC_IO_H */
