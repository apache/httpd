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

#ifndef __mod_h2__h2_io__
#define __mod_h2__h2_io__

struct h2_bucket_beam;
struct h2_response;
struct apr_thread_cond_t;
struct h2_mplx;
struct h2_request;
struct h2_task;


typedef apr_status_t h2_io_data_cb(void *ctx, const char *data, apr_off_t len);

typedef int h2_stream_pri_cmp(int stream_id1, int stream_id2, void *ctx);

typedef enum {
    H2_IO_READ,
    H2_IO_WRITE,
    H2_IO_ANY,
} h2_io_op;

typedef struct h2_io h2_io;

struct h2_io {
    int id;                          /* stream identifier */
    apr_pool_t *pool;                /* io pool */
    
    const struct h2_request *request;/* request to process */
    struct h2_response *response;    /* response to submit */

    struct h2_bucket_beam *beam_in;  /* request body buckets */
    struct h2_bucket_beam *beam_out; /* response body buckets */

    struct h2_task *task;            /* the task once started */
    apr_time_t started_at;           /* when processing started */
    apr_time_t done_at;              /* when processing was done */
    
    int rst_error;                   /* h2 related stream abort error */
    unsigned int orphaned       : 1; /* h2_stream is gone for this io */    
    unsigned int submitted      : 1; /* response has been submitted to client */
    unsigned int worker_started : 1; /* h2_worker started processing for this io */
    unsigned int worker_done    : 1; /* h2_worker finished for this io */
};

/*******************************************************************************
 * Object lifecycle and information.
 ******************************************************************************/

/**
 * Creates a new h2_io for the given stream id. 
 */
h2_io *h2_io_create(int id, apr_pool_t *pool, const struct h2_request *request);

/**
 * Set the response of this stream.
 */
void h2_io_set_response(h2_io *io, struct h2_response *response,
                        struct h2_bucket_beam *output);

/**
 * Reset the stream with the given error code.
 */
void h2_io_rst(h2_io *io, int error);

int h2_io_can_redo(h2_io *io);
void h2_io_redo(h2_io *io);

/**
 * Shuts all input/output down. Clears any buckets buffered and closes.
 */
void h2_io_shutdown(h2_io *io);

#endif /* defined(__mod_h2__h2_io__) */
