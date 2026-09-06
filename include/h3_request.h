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

#ifndef H3_REQUEST_H
#define H3_REQUEST_H

#include <httpd.h>

#include "h3_session.h"

typedef struct h3_conn_ctx_t h3_conn_ctx_t;

/**
 * Resolve what the request path needs from other modules, once, at post_config.
 */
void h3_request_init(void);

/**
 * Build a synthetic conn_rec for a freshly accepted QUIC session. The
 * returned conn_rec has no underlying socket; it's used as a parent for
 * request_recs handed to ap_process_request.
 * @param session The owning session (provides server, pool, etc.).
 * @return A new conn_rec, or NULL on pool allocation failure.
 */
conn_rec* h3_synth_conn(h3_session* session);

/**
 * Take a fully-readable h3_stream and run it through Apache's request
 * pipeline: build request_rec, invoke ap_process_request, capture the
 * response, and submit it back to nghttp3.
 * @param session The owning session.
 * @param h3s     The stream (must have complete request headers + body).
 */
void h3_process_request(h3_session* session, h3_stream* h3s);

/**
 * Submit the final response headers to nghttp3 exactly once. The response body
 * remains open and is supplied by h3_session_read_data.
 */
apr_status_t h3_response_start(request_rec* r, h3_conn_ctx_t* h3ctx);

#endif /* H3_REQUEST_H */
