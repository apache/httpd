/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2024-2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is derived from code originally distributed as part of
 * the OpenSSL project and has been modified for use in mod_http3.
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

#ifndef H3_CONN_H
#define H3_CONN_H

#include <httpd.h>

#include <http_protocol.h>

#include <apr_pools.h>

#include <nghttp3/nghttp3.h>

/* Context for the request to response logic */
struct h3_conn_ctx_t
{
    ap_bucket_response* resp; /* Header part of the response */
    apr_bucket* otherpart;    /* file bucket or something the like */
    char* dataheap;           /* data from the heap bucket (page response built im memory, like error pages) */
    apr_size_t dataheaplen;   /* length of the data head */
    apr_pool_t* c3reqpool;    /* a pool that lives a bit more than the request pool (until the next request for the moment) */
    server_rec* s;            /* mostly for log */
};
typedef struct h3_conn_ctx_t h3_conn_ctx_t;

struct h3_nvs_t
{
    nghttp3_nv* resp;
    size_t cur_nv;
    size_t max_nv;
    apr_pool_t* p;
    server_rec* s;
};
typedef struct h3_nvs_t h3_nvs_t;

struct h3_conn_rec_t
{
    conn_rec* c;          /* The httpd one */
    h3_conn_ctx_t* h3ctx; /* our h3ctx context */
};
typedef struct h3_conn_rec_t h3_conn_rec_t;

h3_conn_rec_t* create_connection(apr_pool_t* p, server_rec* s);
apr_status_t process_connection(apr_pool_t* p, server_rec* s, conn_rec* c);
apr_status_t process_request(request_rec* r, h3_conn_ctx_t* h3ctx);
extern apr_socket_t* dummy_socket;

#endif /* H3_CONN_H */
