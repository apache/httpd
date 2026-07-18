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
 * ap_hook_fixups. For H3 requests, runs the fixups chain and returns OK. For
 * non-H3 requests, returns DECLINED so the standard fixups chain runs.
 * @param r The request being fixed up.
 * @return OK for an H3 request, DECLINED for a non-H3 request.
 */
int h3_hook_fixups(request_rec* r);

/**
 * ap_hook_http_scheme. H3 connections are always TLS, but mod_ssl does not
 * manage them and declines; without this hook self-referential URLs
 * (redirects, REQUEST_SCHEME) would claim "http".
 * @param r The request.
 * @return "https" for an H3 request, NULL to decline otherwise.
 */
const char* h3_hook_http_scheme(const request_rec* r);

/**
 * ap_hook_default_port. Companion to the scheme hook: keeps the default
 * port for H3 request URLs at 443 instead of 80.
 * @param r The request.
 * @return 443 for an H3 request, 0 to decline otherwise.
 */
apr_port_t h3_hook_default_port(const request_rec* r);

/**
 * ap_hook_ssl_conn_is_ssl. Marks H3 connections as TLS-protected for
 * ap_ssl_conn_is_ssl() consumers (mod_rewrite %{HTTPS}, expression parser).
 * @param c The connection.
 * @return OK for an H3 connection, DECLINED otherwise.
 */
int h3_hook_ssl_conn_is_ssl(conn_rec* c);

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
 * ap_hook_access_checker. DECLINED for HTTP/1.x, otherwise OK/413/400.
 * @param r The request being checked.
 * @return OK/413/400 for H3, DECLINED otherwise.
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

/**
 * ap_hook_handler for the "http3-status" handler. Emits a JSON snapshot of
 * this child's HTTP/3 metrics (live workers, connection/stream counts, and
 * byte totals). Declines any other handler or a non-GET method.
 * @param r The request being handled.
 * @return OK when it serves "http3-status", DECLINED otherwise.
 */
int h3_status_handler(request_rec* r);

#endif /* H3_HOOKS_H */
