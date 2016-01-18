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
struct h2_conn;
struct h2_mplx;
struct h2_task;
struct h2_request;
struct h2_resp_head;
struct h2_worker;

typedef struct h2_task h2_task;

struct h2_task {
    const char *id;
    int stream_id;
    struct h2_mplx *mplx;    
    const struct h2_request *request;
    
    unsigned int filters_set : 1;
    unsigned int input_eos   : 1;
    unsigned int ser_headers : 1;
    
    struct h2_task_input *input;
    struct h2_task_output *output;
    struct apr_thread_cond_t *io;   /* used to wait for events on */
};

h2_task *h2_task_create(long session_id, const struct h2_request *req, 
                        apr_pool_t *pool, struct h2_mplx *mplx);

apr_status_t h2_task_do(h2_task *task, conn_rec *c, 
                        struct apr_thread_cond_t *cond, apr_socket_t *socket);

void h2_task_register_hooks(void);

#endif /* defined(__mod_h2__h2_task__) */
