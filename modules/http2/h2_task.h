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

#ifndef __mod_h2__h2_task__
#define __mod_h2__h2_task__

#include <http_core.h>

/**
 * A h2_task fakes a HTTP/1.1 request from the data in a HTTP/2 stream 
 * (HEADER+CONT.+DATA) the module recieves.
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
 * of our own to disble those.
 */

struct apr_thread_cond_t;
struct h2_bucket_beam;
struct h2_conn;
struct h2_mplx;
struct h2_task;
struct h2_req_engine;
struct h2_request;
struct h2_response;
struct h2_worker;

typedef struct h2_task h2_task;

struct h2_task {
    const char *id;
    int stream_id;
    conn_rec *c;
    apr_pool_t *pool;
    
    const struct h2_request *request;
    struct h2_response *response;
    
    struct {
        struct h2_bucket_beam *beam;
        apr_bucket_brigade *bb;
        apr_bucket_brigade *tmp;
        apr_read_type_e block;
        unsigned int chunked : 1;
        unsigned int eos : 1;
        unsigned int eos_written : 1;
    } input;
    struct {
        struct h2_bucket_beam *beam;
        struct h2_from_h1 *from_h1;
        unsigned int response_open : 1;
        apr_off_t written;
        apr_bucket_brigade *bb;
    } output;
    
    struct h2_mplx *mplx;
    struct apr_thread_cond_t *cond;
    
    int rst_error;                   /* h2 related stream abort error */
    unsigned int filters_set    : 1;
    unsigned int ser_headers    : 1;
    unsigned int frozen         : 1;
    unsigned int blocking       : 1;
    unsigned int detached       : 1;
    unsigned int submitted      : 1; /* response has been submitted to client */
    unsigned int worker_started : 1; /* h2_worker started processing for this io */
    unsigned int worker_done    : 1; /* h2_worker finished for this io */
    
    apr_time_t started_at;           /* when processing started */
    apr_time_t done_at;              /* when processing was done */
    apr_bucket *eor;
    
    struct h2_req_engine *engine;   /* engine hosted by this task */
    struct h2_req_engine *assigned; /* engine that task has been assigned to */
    request_rec *r;                 /* request being processed in this task */
};

h2_task *h2_task_create(conn_rec *c, const struct h2_request *req, 
                        struct h2_bucket_beam *input, struct h2_mplx *mplx);

void h2_task_destroy(h2_task *task);

apr_status_t h2_task_do(h2_task *task, apr_thread_t *thread);

void h2_task_set_response(h2_task *task, struct h2_response *response);

void h2_task_redo(h2_task *task);
int h2_task_can_redo(h2_task *task);

/**
 * Reset the task with the given error code, resets all input/output.
 */
void h2_task_rst(h2_task *task, int error);

/**
 * Shuts all input/output down. Clears any buckets buffered and closes.
 */
apr_status_t h2_task_shutdown(h2_task *task, int block);

void h2_task_register_hooks(void);
/*
 * One time, post config intialization.
 */
apr_status_t h2_task_init(apr_pool_t *pool, server_rec *s);

extern APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_in) *h2_task_logio_add_bytes_in;
extern APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *h2_task_logio_add_bytes_out;

apr_status_t h2_task_freeze(h2_task *task);
apr_status_t h2_task_thaw(h2_task *task);
int h2_task_is_detached(h2_task *task);

void h2_task_set_io_blocking(h2_task *task, int blocking);

#endif /* defined(__mod_h2__h2_task__) */
