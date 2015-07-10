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
struct h2_task;


typedef apr_status_t h2_io_data_cb(void *ctx, 
                                   const char *data, apr_size_t len);


typedef struct h2_io h2_io;

struct h2_io {
    int id;                      /* stream identifier */
    apr_bucket_brigade *bbin;    /* input data for stream */
    int eos_in;
    int task_done;
    
    apr_size_t input_consumed;   /* how many bytes have been read */
    struct apr_thread_cond_t *input_arrived; /* block on reading */
    
    apr_bucket_brigade *bbout;   /* output data from stream */
    struct apr_thread_cond_t *output_drained; /* block on writing */
    
    struct h2_response *response;/* submittable response created */
    int files_handles_owned;
};

/*******************************************************************************
 * Object lifecycle and information.
 ******************************************************************************/

/**
 * Creates a new h2_io for the given stream id. 
 */
h2_io *h2_io_create(int id, apr_pool_t *pool, apr_bucket_alloc_t *bucket_alloc);

/**
 * Frees any resources hold by the h2_io instance. 
 */
void h2_io_destroy(h2_io *io);

/**
 * The input data is completely queued. Blocked reads will return immediately
 * and give either data or EOF.
 */
int h2_io_in_has_eos_for(h2_io *io);
/**
 * Output data is available.
 */
int h2_io_out_has_data(h2_io *io);

/*******************************************************************************
 * Input handling of streams.
 ******************************************************************************/
/**
 * Reads the next bucket from the input. Returns APR_EAGAIN if none
 * is currently available, APR_EOF if end of input has been reached.
 */
apr_status_t h2_io_in_read(h2_io *io, apr_bucket_brigade *bb, 
                           apr_size_t maxlen);

/**
 * Appends given bucket to the input.
 */
apr_status_t h2_io_in_write(h2_io *io, apr_bucket_brigade *bb);

/**
 * Closes the input. After existing data has been read, APR_EOF will
 * be returned.
 */
apr_status_t h2_io_in_close(h2_io *io);

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
                             apr_size_t *plen, int *peos);

apr_status_t h2_io_out_write(h2_io *io, apr_bucket_brigade *bb, 
                             apr_size_t maxlen, int *pfile_buckets_allowed);

/**
 * Closes the input. After existing data has been read, APR_EOF will
 * be returned.
 */
apr_status_t h2_io_out_close(h2_io *io);

/**
 * Gives the overall length of the data that is currently queued for
 * output.
 */
apr_size_t h2_io_out_length(h2_io *io);


#endif /* defined(__mod_h2__h2_io__) */
