/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __mod_h2__h2_stream__
#define __mod_h2__h2_stream__

/**
 * A HTTP/2 stream, e.g. a client request+response in HTTP/1.1 terms.
 * 
 * Ok, not quite, but close enough, since we do not implement server
 * pushes yet.
 *
 * A stream always belongs to a h2_session, the one managing the
 * connection to the client. The h2_session writes to the h2_stream,
 * adding HEADERS and DATA and finally an EOS. When headers are done,
 * h2_stream can create a h2_task that can be scheduled to fullfill the
 * request.
 * 
 * This response headers are added directly to the h2_mplx of the session,
 * but the response DATA can be read via h2_stream. Reading data will
 * never block but return APR_EAGAIN when there currently is no data (and
 * no eos) in the multiplexer for this stream.
 */
#include "h2_io.h"

typedef enum {
    H2_STREAM_ST_IDLE,
    H2_STREAM_ST_OPEN,
    H2_STREAM_ST_RESV_LOCAL,
    H2_STREAM_ST_RESV_REMOTE,
    H2_STREAM_ST_CLOSED_INPUT,
    H2_STREAM_ST_CLOSED_OUTPUT,
    H2_STREAM_ST_CLOSED,
} h2_stream_state_t;

struct h2_mplx;
struct h2_request;
struct h2_response;
struct h2_session;
struct h2_task;

typedef struct h2_stream h2_stream;

struct h2_stream {
    int id;                     /* http2 stream id */
    h2_stream_state_t state;    /* http/2 state of this stream */
    struct h2_session *session; /* the session this stream belongs to */
    
    int aborted;                /* was aborted */
    int suspended;              /* DATA sending has been suspended */
    int rst_error;              /* stream error for RST_STREAM */
    
    apr_pool_t *pool;           /* the memory pool for this stream */
    struct h2_request *request; /* the request made in this stream */
    
    struct h2_response *response; /* the response, once ready */
    
    apr_bucket_brigade *bbout;  /* output DATA */
    apr_size_t data_frames_sent;/* # of DATA frames sent out for this stream */
};


#define H2_STREAM_RST(s, def)    (s->rst_error? s->rst_error : (def))

h2_stream *h2_stream_create(int id, apr_pool_t *pool, struct h2_session *session);

apr_status_t h2_stream_destroy(h2_stream *stream);

void h2_stream_cleanup(h2_stream *stream);

void h2_stream_rst(h2_stream *streamm, int error_code);

apr_pool_t *h2_stream_detach_pool(h2_stream *stream);

apr_status_t h2_stream_rwrite(h2_stream *stream, request_rec *r);

apr_status_t h2_stream_write_eos(h2_stream *stream);

apr_status_t h2_stream_write_header(h2_stream *stream,
                                    const char *name, size_t nlen,
                                    const char *value, size_t vlen);

apr_status_t h2_stream_schedule(h2_stream *stream, int eos,
                                h2_stream_pri_cmp *cmp, void *ctx);

apr_status_t h2_stream_write_data(h2_stream *stream,
                                  const char *data, size_t len);

apr_status_t h2_stream_set_response(h2_stream *stream, 
                                    struct h2_response *response,
                                    apr_bucket_brigade *bb);

apr_status_t h2_stream_prep_read(h2_stream *stream, 
                                 apr_size_t *plen, int *peos);

apr_status_t h2_stream_readx(h2_stream *stream, h2_io_data_cb *cb, 
                             void *ctx, apr_size_t *plen, int *peos);

apr_status_t h2_stream_read_to(h2_stream *stream, apr_bucket_brigade *bb, 
                               apr_size_t *plen, int *peos);


void h2_stream_set_suspended(h2_stream *stream, int suspended);
int h2_stream_is_suspended(h2_stream *stream);

#endif /* defined(__mod_h2__h2_stream__) */
