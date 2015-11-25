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

#ifndef __mod_h2__h2_conn__
#define __mod_h2__h2_conn__

struct h2_task;

/**
 * Process the connection that is now starting the HTTP/2
 * conversation. Return when the HTTP/2 session is done
 * and the connection will close.
 *
 * @param c the connection HTTP/2 is starting on
 * @param r the upgrade request that still awaits an answer, optional
 * @param s the server selected by request or, if NULL, connection
 */
apr_status_t h2_conn_process(conn_rec *c, request_rec *r, server_rec *s);

/* Initialize this child process for h2 connection work,
 * to be called once during child init before multi processing
 * starts.
 */
apr_status_t h2_conn_child_init(apr_pool_t *pool, server_rec *s);


typedef enum {
    H2_MPM_UNKNOWN,
    H2_MPM_WORKER,
    H2_MPM_EVENT,
    H2_MPM_PREFORK,
} h2_mpm_type_t;

/* Returns the type of MPM module detected */
h2_mpm_type_t h2_conn_mpm_type(void);


conn_rec *h2_conn_create(conn_rec *master, apr_pool_t *stream_pool);

apr_status_t h2_conn_setup(struct h2_task *task, apr_bucket_alloc_t *bucket_alloc,
                           apr_thread_t *thread, apr_socket_t *socket);

#endif /* defined(__mod_h2__h2_conn__) */
