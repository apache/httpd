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

#ifndef H3_HOOKS_H
#define H3_HOOKS_H

#include <httpd.h>

/**
 * ap_hook_post_read_request. No-op for H3; reserved for future
 * per-request initialisation. Always returns OK.
 * @param r The request (unused).
 * @return OK.
 */
int h3_hook_post_read_request(request_rec* r);

/**
 * ap_hook_pre_read_request. No-op for H3 — the request is already
 * fully parsed by nghttp3 before the dispatcher runs.
 * @param r The request (unused).
 * @param c The connection (unused).
 */
void h3_hook_pre_read_request(request_rec* r, conn_rec* c);

/**
 * ap_hook_access_checker. Returns OK for H3 requests (already vetted
 * by the QUIC handshake / HTTP/3 framing), DECLINED for HTTP/1.x so
 * the standard access checker chain runs.
 * @param r The request being checked.
 * @return OK if the request is H3, DECLINED otherwise.
 */
int h3_hook_access_checker(request_rec* r);

/**
 * ap_hook_http_create_request. Installs the H3 input and output
 * filter chain (protocol + network) on a freshly created H3 request.
 * Skips subrequests (r->main != NULL) and non-H3 requests.
 * @param r The newly created request.
 * @return OK on install, DECLINED to skip.
 */
int h3_hook_http_create_request(request_rec* r);

#endif /* H3_HOOKS_H */
