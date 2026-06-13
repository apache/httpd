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

#include <apr_pools.h>

#include "h3_conn.h"

struct h3_request
{
    int64_t id_bidi;       /* streamid used to read request and send response */
    apr_pool_t* h3reqpool; /* sub pool of the h3ssl->c->pool */
    request_rec* r;        /* request to Apache HTTPD */

    uint64_t totalsendbyte; /* for nghttp3_conn_add_ack_offset */
    int finsend;            /* server has send a packet with fin=1 */
    int endstream;          /* on_end_stream() was called */
    int closestream;        /* on_stream_close() was called */

    int num_headers;          /* number of headers received (for debugging purpose) */
    int end_headers_received; /* h3 header received call back called */
    int datadone;             /* h3 has given openssl all the data of the response */

    uint8_t* ptr_data; /* pointer to the data to send */
    size_t ldata;      /* amount of bytes to send */
    int offset_data;   /* offset to next data to send */

    struct h3_request* next; /* the next request in the list */

    h3_conn_ctx_t* h3ctx; /* pointer to request/response we are processing */
};

struct h3ssl;

struct h3_request* get_h3_request(struct h3ssl* h3ssl, int64_t stream_id);
struct h3_request* create_h3_request(struct h3ssl* h3ssl, int64_t stream_id);
void cleanup_h3_request(struct h3ssl* h3ssl, struct h3_request* h3req, int64_t stream_id);

#endif /* H3_REQUEST_H */
