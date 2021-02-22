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

#ifndef __mod_h2__h2_task__
#define __mod_h2__h2_task__

#include <http_core.h>

/**
 * A h2_task fakes a HTTP/1.1 request from the data in a HTTP/2 stream 
 * (HEADER+CONT.+DATA) the module receives.
 *
 * In order to answer a HTTP/2 stream, we want all Apache httpd infrastructure
 * to be involved as usual, as if this stream can as a separate HTTP/1.1
 * request. The basic trickery to do so was derived from google's mod_spdy
 * source. Basically, we fake a new conn_rec object, even with its own
 * socket and give it to ap_process_connection().
 *
 * Since h2_task instances are executed in separate threads, we may have
 * different lifetimes than our h2_stream or h2_session instances. Basically,
 * we would like to be as standalone as possible.
 *
 * Finally, to keep certain connection level filters, such as ourselves and
 * especially mod_ssl ones, from messing with our data, we need a filter
 * of our own to disable those.
 */

struct h2_bucket_beam;
struct h2_conn;
struct h2_mplx;
struct h2_task;
struct h2_request;
struct h2_response_parser;
struct h2_stream;
struct h2_worker;

typedef struct h2_task h2_task;

struct h2_task {
    const char *id;
    int stream_id;
    conn_rec *c;
    apr_pool_t *pool;
    
    const struct h2_request *request;
    apr_interval_time_t timeout;
    int rst_error;                   /* h2 related stream abort error */
    
    struct {
        struct h2_bucket_beam *beam;
        unsigned int eos : 1;
        apr_bucket_brigade *bb;
        apr_bucket_brigade *bbchunk;
        apr_off_t chunked_total;
    } input;
    struct {
        struct h2_bucket_beam *beam;
        unsigned int opened : 1;
        unsigned int sent_response : 1;
        unsigned int copy_files : 1;
        unsigned int buffered : 1;
        struct h2_response_parser *rparser;
        apr_bucket_brigade *bb;
        apr_size_t max_buffer;
    } output;
    
    struct h2_mplx *mplx;
    
    unsigned int filters_set    : 1;
    unsigned int worker_started : 1; /* h2_worker started processing */
    unsigned int redo : 1;           /* was throttled, should be restarted later */
    
    int worker_done;                 /* h2_worker finished */
    int done_done;                   /* task_done has been handled */
    
    apr_time_t started_at;           /* when processing started */
    apr_time_t done_at;              /* when processing was done */
    apr_bucket *eor;
};

h2_task *h2_task_create(conn_rec *secondary, int stream_id,
                        const h2_request *req, struct h2_mplx *m, 
                        struct h2_bucket_beam *input, 
                        apr_interval_time_t timeout,
                        apr_size_t output_max_mem);

void h2_task_destroy(h2_task *task);

apr_status_t h2_task_do(h2_task *task, apr_thread_t *thread, int worker_id);

void h2_task_redo(h2_task *task);
int h2_task_can_redo(h2_task *task);
int h2_task_has_started(h2_task *task);

/**
 * Reset the task with the given error code, resets all input/output.
 */
void h2_task_rst(h2_task *task, int error);

void h2_task_register_hooks(void);
/*
 * One time, post config initialization.
 */
apr_status_t h2_task_init(apr_pool_t *pool, server_rec *s);

extern APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_in) *h2_task_logio_add_bytes_in;
extern APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *h2_task_logio_add_bytes_out;

#endif /* defined(__mod_h2__h2_task__) */
