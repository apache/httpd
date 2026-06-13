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

#ifndef H3_RESPONSE_H
#define H3_RESPONSE_H

#include <httpd.h>

#include <apr_pools.h>

#include <nghttp3/nghttp3.h>

#include "h3_conn.h"
#include "h3_request.h"
#include "h3_ssl.h"

void build_nv_from_response(nghttp3_nv* resp, size_t* num_nv, size_t max_nv, h3_conn_ctx_t* h3ctx);
int quic_server_write_response(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* p);
int process_h3response(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, struct h3_request* h3req, server_rec* s, apr_pool_t* p);

#endif /* H3_RESPONSE_H */
