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
 * A stream always belongs to a h2_session, the one managing the
 * connection to the client. The h2_session writes to the h2_stream,
 * adding HEADERS and DATA and finally an EOS. When headers are done,
 * h2_stream is scheduled for handling, which is expected to produce
 * a h2_response.
 * 
 * The h2_response gives the HEADER frames to sent to the client, followed
 * by DATA frames read from the h2_stream until EOS is reached.
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
struct h2_priority;
struct h2_request;
struct h2_response;
struct h2_session;
struct h2_task;

typedef struct h2_stream h2_stream;

struct h2_stream {
    int id;                     /* http2 stream id */
    int initiated_on;           /* http2 stream id this was initiated on or 0 */
    h2_stream_state_t state;    /* http/2 state of this stream */
    struct h2_session *session; /* the session this stream belongs to */
    
    apr_pool_t *pool;           /* the memory pool for this stream */
    struct h2_request *request; /* the request made in this stream */
    struct h2_response *response; /* the response, once ready */
    int rst_error;              /* stream error for RST_STREAM */
    
    unsigned int aborted   : 1; /* was aborted */
    unsigned int suspended : 1; /* DATA sending has been suspended */
    unsigned int scheduled : 1; /* stream has been scheduled */
    unsigned int submitted : 1; /* response HEADER has been sent */
    
    apr_off_t input_remaining;  /* remaining bytes on input as advertised via content-length */
    apr_bucket_brigade *bbin;   /* input DATA */
    
    apr_bucket_brigade *bbout;  /* output DATA */
    apr_off_t data_frames_sent; /* # of DATA frames sent out for this stream */
};


#define H2_STREAM_RST(s, def)    (s->rst_error? s->rst_error : (def))

/**
 * Create a stream in IDLE state.
 * @param id      the stream identifier
 * @param pool    the memory pool to use for this stream
 * @param session the session this stream belongs to
 * @return the newly created IDLE stream
 */
h2_stream *h2_stream_create(int id, apr_pool_t *pool, struct h2_session *session);

/**
 * Create a stream in OPEN state.
 * @param id      the stream identifier
 * @param pool    the memory pool to use for this stream
 * @param session the session this stream belongs to
 * @return the newly opened stream
 */
h2_stream *h2_stream_open(int id, apr_pool_t *pool, struct h2_session *session);

/**
 * Destroy any resources held by this stream. Will destroy memory pool
 * if still owned by the stream.
 *
 * @param stream the stream to destroy
 */
apr_status_t h2_stream_destroy(h2_stream *stream);

/**
 * Removes stream from h2_session and destroys it.
 *
 * @param stream the stream to cleanup
 */
void h2_stream_cleanup(h2_stream *stream);

/**
 * Detach the memory pool from the stream. Will prevent stream
 * destruction to take the pool with it.
 *
 * @param stream the stream to detach the pool from
 * @param the detached memmory pool or NULL if stream no longer has one
 */
apr_pool_t *h2_stream_detach_pool(h2_stream *stream);


/**
 * Initialize stream->request with the given request_rec.
 * 
 * @param stream stream to write request to
 * @param r the request with all the meta data
 */
apr_status_t h2_stream_set_request(h2_stream *stream, request_rec *r);

/**
 * Initialize stream->request with the given h2_request.
 * 
 * @param stream the stream to init the request for
 * @param req the request for initializing, will be copied
 */
void h2_stream_set_h2_request(h2_stream *stream, int initiated_on,
                              const struct h2_request *req);

/*
 * Add a HTTP/2 header (including pseudo headers) or trailer 
 * to the given stream, depending on stream state.
 *
 * @param stream stream to write the header to
 * @param name the name of the HTTP/2 header
 * @param nlen the number of characters in name
 * @param value the header value
 * @param vlen the number of characters in value
 */
apr_status_t h2_stream_add_header(h2_stream *stream,
                                  const char *name, size_t nlen,
                                  const char *value, size_t vlen);

/**
 * Closes the stream's input.
 *
 * @param stream stream to close intput of
 */
apr_status_t h2_stream_close_input(h2_stream *stream);

/*
 * Write a chunk of DATA to the stream.
 *
 * @param stream stream to write the data to
 * @param data the beginning of the bytes to write
 * @param len the number of bytes to write
 */
apr_status_t h2_stream_write_data(h2_stream *stream,
                                  const char *data, size_t len);

/**
 * Reset the stream. Stream write/reads will return errors afterwards.
 *
 * @param stream the stream to reset
 * @param error_code the HTTP/2 error code
 */
void h2_stream_rst(h2_stream *streamm, int error_code);

/**
 * Schedule the stream for execution. All header information must be
 * present. Use the given priority comparision callback to determine 
 * order in queued streams.
 * 
 * @param stream the stream to schedule
 * @param eos    != 0 iff no more input will arrive
 * @param cmp    priority comparision
 * @param ctx    context for comparision
 */
apr_status_t h2_stream_schedule(h2_stream *stream, int eos, int push_enabled,
                                h2_stream_pri_cmp *cmp, void *ctx);

/**
 * Determine if stream has been scheduled already.
 * @param stream the stream to check on
 * @return != 0 iff stream has been scheduled
 */
int h2_stream_is_scheduled(h2_stream *stream);

/**
 * Set the response for this stream. Invoked when all meta data for
 * the stream response has been collected.
 * 
 * @param stream the stream to set the response for
 * @param resonse the response data for the stream
 * @param bb bucket brigade with output data for the stream. Optional,
 *        may be incomplete.
 */
apr_status_t h2_stream_set_response(h2_stream *stream, 
                                    struct h2_response *response,
                                    apr_bucket_brigade *bb);

/**
 * Do a speculative read on the stream output to determine the 
 * amount of data that can be read.
 * 
 * @param stream the stream to speculatively read from
 * @param plen (in-/out) number of bytes requested and on return amount of bytes that
 *        may be read without blocking
 * @param peos (out) != 0 iff end of stream will be reached when reading plen
 *        bytes (out value).
 * @return APR_SUCCESS if out information was computed successfully.
 *         APR_EAGAIN if not data is available and end of stream has not been
 *         reached yet.
 */
apr_status_t h2_stream_prep_read(h2_stream *stream, 
                                 apr_off_t *plen, int *peos);

/**
 * Read data from the stream output.
 * 
 * @param stream the stream to read from
 * @param cb callback to invoke for byte chunks read. Might be invoked
 *        multiple times (with different values) for one read operation.
 * @param ctx context data for callback
 * @param plen (in-/out) max. number of bytes to read and on return actual
 *        number of bytes read
 * @param peos (out) != 0 iff end of stream has been reached while reading
 * @return APR_SUCCESS if out information was computed successfully.
 *         APR_EAGAIN if not data is available and end of stream has not been
 *         reached yet.
 */
apr_status_t h2_stream_readx(h2_stream *stream, h2_io_data_cb *cb, 
                             void *ctx, apr_off_t *plen, int *peos);

/**
 * Read a maximum number of bytes into the bucket brigade.
 * 
 * @param stream the stream to read from
 * @param bb the brigade to append output to
 * @param plen (in-/out) max. number of bytes to append and on return actual
 *        number of bytes appended to brigade
 * @param peos (out) != 0 iff end of stream has been reached while reading
 * @return APR_SUCCESS if out information was computed successfully.
 *         APR_EAGAIN if not data is available and end of stream has not been
 *         reached yet.
 */
apr_status_t h2_stream_read_to(h2_stream *stream, apr_bucket_brigade *bb, 
                               apr_off_t *plen, int *peos);

/**
 * Set the suspended state of the stream.
 * @param stream the stream to change state on
 * @param suspended boolean value if stream is suspended
 */
void h2_stream_set_suspended(h2_stream *stream, int suspended);

/**
 * Check if the stream has been suspended.
 * @param stream the stream to check
 * @return != 0 iff stream is suspended.
 */
int h2_stream_is_suspended(h2_stream *stream);

/**
 * Check if the stream has open input.
 * @param stream the stream to check
 * @return != 0 iff stream has open input.
 */
int h2_stream_input_is_open(h2_stream *stream);

/**
 * Check if the stream has not submitted a response or RST yet.
 * @param stream the stream to check
 * @return != 0 iff stream has not submitted a response or RST.
 */
int h2_stream_needs_submit(h2_stream *stream);

/**
 * Submit any server push promises on this stream and schedule
 * the tasks connection with these.
 *
 * @param stream the stream for which to submit
 */
apr_status_t h2_stream_submit_pushes(h2_stream *stream);

/**
 * Get optional trailers for this stream, may be NULL. Meaningful
 * results can only be expected when the end of the response body has
 * been reached.
 *
 * @param stream to ask for trailers
 * @return trailers for NULL
 */
apr_table_t *h2_stream_get_trailers(h2_stream *stream);

/**
 * Get priority information set for this stream.
 */
const struct h2_priority *h2_stream_get_priority(h2_stream *stream);

#endif /* defined(__mod_h2__h2_stream__) */
