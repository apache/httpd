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

struct h2_response;
struct apr_thread_cond_t;
struct h2_mplx;
struct h2_request;


typedef apr_status_t h2_io_data_cb(void *ctx, const char *data, apr_off_t len);

typedef int h2_stream_pri_cmp(int stream_id1, int stream_id2, void *ctx);

typedef enum {
    H2_IO_READ,
    H2_IO_WRITE,
    H2_IO_ANY,
}
h2_io_op;

typedef struct h2_io h2_io;

struct h2_io {
    int id;                          /* stream identifier */
    apr_pool_t *pool;                /* stream pool */
    apr_bucket_alloc_t *bucket_alloc;
    
    const struct h2_request *request;/* request on this io */
    struct h2_response *response;    /* response to request */
    int rst_error;                   /* h2 related stream abort error */

    apr_bucket_brigade *bbin;        /* input data for stream */
    apr_bucket_brigade *bbout;       /* output data from stream */
    apr_bucket_brigade *tmp;         /* temporary data for chunking */

    unsigned int orphaned       : 1; /* h2_stream is gone for this io */    
    unsigned int worker_started : 1; /* h2_worker started processing for this io */
    unsigned int worker_done    : 1; /* h2_worker finished for this io */
    unsigned int request_body   : 1; /* iff request has body */
    unsigned int eos_in         : 1; /* input eos has been seen */
    unsigned int eos_in_written : 1; /* input eos has been forwarded */
    unsigned int eos_out        : 1; /* output eos has been seen */
    
    h2_io_op timed_op;               /* which operation is waited on, if any */
    struct apr_thread_cond_t *timed_cond; /* condition to wait on, maybe NULL */
    apr_time_t timeout_at;           /* when IO wait will time out */
    
    apr_size_t input_consumed;       /* how many bytes have been read */
        
    int files_handles_owned;
};

/*******************************************************************************
 * Object lifecycle and information.
 ******************************************************************************/

/**
 * Creates a new h2_io for the given stream id. 
 */
h2_io *h2_io_create(int id, apr_pool_t *pool);

/**
 * Frees any resources hold by the h2_io instance. 
 */
void h2_io_destroy(h2_io *io);

/**
 * Set the response of this stream.
 */
void h2_io_set_response(h2_io *io, struct h2_response *response);

/**
 * Reset the stream with the given error code.
 */
void h2_io_rst(h2_io *io, int error);

/**
 * The input data is completely queued. Blocked reads will return immediately
 * and give either data or EOF.
 */
int h2_io_in_has_eos_for(h2_io *io);
/**
 * Output data is available.
 */
int h2_io_out_has_data(h2_io *io);

void h2_io_signal(h2_io *io, h2_io_op op);
void h2_io_signal_init(h2_io *io, h2_io_op op, int timeout_secs, 
                       struct apr_thread_cond_t *cond);
void h2_io_signal_exit(h2_io *io);
apr_status_t h2_io_signal_wait(struct h2_mplx *m, h2_io *io);

void h2_io_make_orphaned(h2_io *io, int error);

/*******************************************************************************
 * Input handling of streams.
 ******************************************************************************/
/**
 * Reads the next bucket from the input. Returns APR_EAGAIN if none
 * is currently available, APR_EOF if end of input has been reached.
 */
apr_status_t h2_io_in_read(h2_io *io, apr_bucket_brigade *bb, 
                           apr_size_t maxlen, apr_table_t *trailers);

/**
 * Appends given bucket to the input.
 */
apr_status_t h2_io_in_write(h2_io *io, apr_bucket_brigade *bb);

/**
 * Closes the input. After existing data has been read, APR_EOF will
 * be returned.
 */
apr_status_t h2_io_in_close(h2_io *io);

/**
 * Shuts all input down. Will close input and mark any data buffered
 * as consumed.
 */
apr_status_t h2_io_in_shutdown(h2_io *io);

/*******************************************************************************
 * Output handling of streams.
 ******************************************************************************/

/**
 * Read a bucket from the output head. Return APR_EAGAIN if non is available,
 * APR_EOF if none available and output has been closed. 
 * May be called with buffer == NULL in order to find out how much data
 * is available.
 * @param io the h2_io to read output from
 * @param buffer the buffer to copy the data to, may be NULL
 * @param plen the requested max len, set to amount of data on return
 * @param peos != 0 iff the end of stream has been reached
 */
apr_status_t h2_io_out_readx(h2_io *io,  
                             h2_io_data_cb *cb, void *ctx, 
                             apr_off_t *plen, int *peos);

apr_status_t h2_io_out_read_to(h2_io *io, 
                               apr_bucket_brigade *bb, 
                               apr_off_t *plen, int *peos);

apr_status_t h2_io_out_write(h2_io *io, apr_bucket_brigade *bb, 
                             apr_size_t maxlen, apr_table_t *trailers,
                             apr_size_t *pfile_buckets_allowed);

/**
 * Closes the input. After existing data has been read, APR_EOF will
 * be returned.
 */
apr_status_t h2_io_out_close(h2_io *io, apr_table_t *trailers);

/**
 * Gives the overall length of the data that is currently queued for
 * output.
 */
apr_off_t h2_io_out_length(h2_io *io);


#endif /* defined(__mod_h2__h2_io__) */
