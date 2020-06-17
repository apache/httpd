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

#ifndef __mod_h2__h2_conn__
#define __mod_h2__h2_conn__

struct h2_ctx;
struct h2_task;

/**
 * Setup the connection and our context for HTTP/2 processing
 *
 * @param c the connection HTTP/2 is starting on
 * @param r the upgrade request that still awaits an answer, optional
 * @param s the server selected for this connection (can be != c->base_server)
 */
apr_status_t h2_conn_setup(conn_rec *c, request_rec *r, server_rec *s);

/**
 * Run the HTTP/2 connection in synchronous fashion. 
 * Return when the HTTP/2 session is done
 * and the connection will close or a fatal error occurred.
 *
 * @param c the http2 connection to run
 * @return APR_SUCCESS when session is done.
 */
apr_status_t h2_conn_run(conn_rec *c);

/**
 * The connection is about to close. If we have not send a GOAWAY
 * yet, this is the last chance.
 */
apr_status_t h2_conn_pre_close(struct h2_ctx *ctx, conn_rec *c);

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
    H2_MPM_MOTORZ,
    H2_MPM_SIMPLE,
    H2_MPM_NETWARE,
    H2_MPM_WINNT,
} h2_mpm_type_t;

/* Returns the type of MPM module detected */
h2_mpm_type_t h2_conn_mpm_type(void);
const char *h2_conn_mpm_name(void);
int h2_mpm_supported(void);

conn_rec *h2_secondary_create(conn_rec *master, int sec_id, apr_pool_t *parent);
void h2_secondary_destroy(conn_rec *secondary);

apr_status_t h2_secondary_run_pre_connection(conn_rec *secondary, apr_socket_t *csd);
void h2_secondary_run_connection(conn_rec *secondary);

#endif /* defined(__mod_h2__h2_conn__) */
