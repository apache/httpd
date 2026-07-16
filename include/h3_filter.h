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

#ifndef H3_FILTER_H
#define H3_FILTER_H

#include <httpd.h>

#include <http_protocol.h>

#include <apr_buckets.h>
#include <apr_pools.h>

struct h3_stream;

typedef struct h3_conn_ctx_t
{
    ap_bucket_response* resp;
    char* dataheap;
    apr_size_t dataheaplen;
    apr_pool_t* c3reqpool;
    server_rec* s;
    /// Set once the response body exceeds H3MaxResponseBodySize.
    int response_too_large;
    /// Back-reference to the h3_stream.
    struct h3_stream* stream;
} h3_conn_ctx_t;

extern ap_filter_rec_t* h3_net_out_filter_handle;
extern ap_filter_rec_t* h3_net_in_filter_handle;
extern ap_filter_rec_t* h3_proto_out_filter_handle;
extern ap_filter_rec_t* h3_proto_in_filter_handle;

/**
 * Network-layer output filter callback. Discards the brigade (the
 * response is captured by the protocol-layer filter and submitted to
 * nghttp3).
 * @param f  The filter handle (unused).
 * @param bb The outbound brigade to dispose of.
 * @return APR_SUCCESS.
 */
apr_status_t h3_filter_out(ap_filter_t* f, apr_bucket_brigade* bb);

/**
 * Protocol-layer output filter callback. Captures the response into the
 * per-request h3_conn_ctx_t: deep-copies headers from r->pool into
 * c3reqpool, appends body bytes to dataheap, and stores the
 * ap_bucket_response pointer.
 * @param f  The filter handle.
 * @param bb The outbound brigade.
 * @return APR_SUCCESS, or an APR error if pool/brigade access fails.
 */
apr_status_t h3_filter_out_proto(ap_filter_t* f, apr_bucket_brigade* bb);

/**
 * Protocol-layer input filter callback. Serves the request body.
 * @return APR_SUCCESS, with data and/or an EOS bucket inserted into @p bb.
 */
apr_status_t h3_filter_in_proto(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);

/**
 * Network-layer input filter callback. Unconditional EOS stub.
 * @return APR_SUCCESS (with EOS bucket inserted) or APR_EOF.
 */
apr_status_t h3_filter_in(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);

/**
 * ap_hook_insert_filter callback. Attaches h3_proto_out_filter to the
 * main request (skipping subrequests) so the response is captured
 * before the network filter discards it.
 * @param r The main request.
 */
void h3_filter_last(request_rec* r);

#endif /* H3_FILTER_H */
