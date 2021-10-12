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

#ifndef __mod_h2__h2_c1__
#define __mod_h2__h2_c1__

struct h2_conn_ctx_t;

/* Initialize this child process for h2 primary connection work,
 * to be called once during child init before multi processing
 * starts.
 */
apr_status_t h2_c1_child_init(apr_pool_t *pool, server_rec *s);

/**
 * Setup the primary connection and our context for HTTP/2 processing
 *
 * @param c the connection HTTP/2 is starting on
 * @param r the upgrade request that still awaits an answer, optional
 * @param s the server selected for this connection (can be != c->base_server)
 */
apr_status_t h2_c1_setup(conn_rec *c, request_rec *r, server_rec *s);

/**
 * Run the HTTP/2 primary connection in synchronous fashion.
 * Return when the HTTP/2 session is done
 * and the connection will close or a fatal error occurred.
 *
 * @param c the http2 connection to run
 * @return APR_SUCCESS when session is done.
 */
apr_status_t h2_c1_run(conn_rec *c);

/**
 * The primary connection is about to close. If we have not send a GOAWAY
 * yet, this is the last chance.
 */
apr_status_t h2_c1_pre_close(struct h2_conn_ctx_t *ctx, conn_rec *c);

/**
 * Check if the connection allows a direct detection of HTTPP/2,
 * as configurable by the H2Direct directive.
 * @param c the connection to check on
 * @return != 0 if direct detection is enabled
 */
int h2_c1_allows_direct(conn_rec *c);

/**
 * Check if the "Upgrade" HTTP/1.1 mode of protocol switching is enabled
 * for the given request.
 * @param r the request to check
 * @return != 0 iff Upgrade switching is enabled
 */
int h2_c1_can_upgrade(request_rec *r);

/* Register hooks for h2 handling on primary connections.
 */
void h2_c1_register_hooks(void);

/**
 * Child is about to be stopped, release unused resources
 */
void h2_c1_child_stopping(apr_pool_t *pool, int graceful);

#endif /* defined(__mod_h2__h2_c1__) */
