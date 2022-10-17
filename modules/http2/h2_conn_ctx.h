/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __mod_h2__h2_conn_ctx__
#define __mod_h2__h2_conn_ctx__

#include "h2.h"

struct h2_session;
struct h2_stream;
struct h2_mplx;
struct h2_bucket_beam;
struct h2_response_parser;
struct h2_c2_transit;

#define H2_PIPE_OUT     0
#define H2_PIPE_IN      1

/**
 * The h2 module context associated with a connection.
 *
 * It keeps track of the different types of connections:
 * - those from clients that use HTTP/2 protocol
 * - those from clients that do not use HTTP/2
 * - those created by ourself to perform work on HTTP/2 streams
 */
struct h2_conn_ctx_t {
    const char *id;                 /* c*: our identifier of this connection */
    server_rec *server;             /* c*: httpd server selected. */
    const char *protocol;           /* c1: the protocol negotiated */
    struct h2_session *session;     /* c1: the h2 session established */
    struct h2_mplx *mplx;           /* c2: the multiplexer */
    struct h2_c2_transit *transit;  /* c2: transit pool and bucket_alloc */

#if !AP_HAS_RESPONSE_BUCKETS
    int pre_conn_done;               /* has pre_connection setup run? */
#endif
    int stream_id;                  /* c1: 0, c2: stream id processed */
    apr_pool_t *req_pool;            /* c2: a c2 child pool for a request */
    const struct h2_request *request; /* c2: the request to process */
    struct h2_bucket_beam *beam_out; /* c2: data out, created from req_pool */
    struct h2_bucket_beam *beam_in;  /* c2: data in or NULL, borrowed from request stream */
    unsigned int input_chunked;      /* c2: if input needs HTTP/1.1 chunking applied */

    apr_file_t *pipe_in[2];          /* c2: input produced notification pipe */
    apr_pollfd_t pfd;                /* c1: poll socket input, c2: NUL */

    int has_final_response;          /* final HTTP response passed on out */
    apr_status_t last_err;           /* APR_SUCCES or last error encountered in filters */

    /* atomic */ apr_uint32_t started; /* c2: processing was started */
    apr_time_t started_at;           /* c2: when processing started */
    /* atomic */ apr_uint32_t done;  /* c2: processing has finished */
    apr_time_t done_at;              /* c2: when processing was done */
};
typedef struct h2_conn_ctx_t h2_conn_ctx_t;

/**
 * Get the h2 connection context.
 * @param c the connection to look at
 * @return h2 context of this connection
 */
#define h2_conn_ctx_get(c) \
    ((c)? (h2_conn_ctx_t*)ap_get_module_config((c)->conn_config, &http2_module) : NULL)

/**
 * Create the h2 connection context.
 * @param c the connection to create it at
 * @param s the server in use
 * @param protocol the protocol selected
 * @return created h2 context of this connection
 */
h2_conn_ctx_t *h2_conn_ctx_create_for_c1(conn_rec *c, server_rec *s, const char *protocol);

void h2_conn_ctx_assign_session(h2_conn_ctx_t *ctx, struct h2_session *session);

apr_status_t h2_conn_ctx_init_for_c2(h2_conn_ctx_t **pctx, conn_rec *c,
                                     struct h2_mplx *mplx, struct h2_stream *stream,
                                     struct h2_c2_transit *transit);

void h2_conn_ctx_detach(conn_rec *c);

void h2_conn_ctx_set_timeout(h2_conn_ctx_t *conn_ctx, apr_interval_time_t timeout);

#endif /* defined(__mod_h2__h2_conn_ctx__) */
