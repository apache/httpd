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

#ifndef H3_SSL_H
#define H3_SSL_H

#include <httpd.h>

#include <apr_pools.h>

#include <openssl/ssl.h>

#include <nghttp3/nghttp3.h>

#include "h3.h"

struct h3_request;

/* 3 streams created by the server and 4 by the client (one is bidi) */
struct ssl_id
{
    SSL* s;              /* the stream openssl uses in SSL_read(),  SSL_write etc */
    uint64_t id;         /* the stream identifier the nghttp3 uses */
    int status;          /* 0 or one the below status and origin */
    int has607;          /* work around nghttp3_conn_read_stream returning  -607 on stream */
    struct h3ssl* h3ssl; /* pointer to the h3ssl structure */
};

struct h3ssl
{
    struct h3_request* h3req; /* pointer to the first h3req hack for the moment */
    int has_uni;              /* we have the 3 uni directional stream needed */
    int c_terminated;         /* connection is terminated EVENT_ECD or EVENT_EC or something else */
    int done;                 /* connection terminated EVENT_ECD, after EVENT_EC */
    server_rec* s;            /* server for log and other stuff */
    conn_rec* c;              /* connect to Apache HTTPD */
    apr_pool_t* p;            /* pool from the pchild */
    nghttp3_conn* h3conn;     /* pointer to nghttp3 connection */
};

/* h3ssl with events, 10 max for the moment */
struct activeh3ssl
{
    struct h3ssl* receivedh3ssl[10]; /* pointer to the h3ssl with events, 10 max for the moment */
    int current;
};

SSL_CTX* create_ctx(server_rec* s, const char* cert_path, const char* key_path);
int create_socket(server_rec* s, uint16_t port);

#endif /* H3_SSL_H */
