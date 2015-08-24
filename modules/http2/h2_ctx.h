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

#ifndef __mod_h2__h2_ctx__
#define __mod_h2__h2_ctx__

struct h2_task_env;
struct h2_config;

/**
 * The h2 module context associated with a connection. 
 *
 * It keeps track of the different types of connections:
 * - those from clients that use HTTP/2 protocol
 * - those from clients that do not use HTTP/2
 * - those created by ourself to perform work on HTTP/2 streams
 */
typedef struct h2_ctx {
    int is_h2;                    /* h2 engine is used */
    const char *protocol;         /* the protocol negotiated */
    struct h2_task_env *task_env; /* the h2_task environment or NULL */
    const char *hostname;         /* hostname negotiated via SNI, optional */
    server_rec *server;           /* httpd server config selected. */
    struct h2_config *config;     /* effective config in this context */
} h2_ctx;

h2_ctx *h2_ctx_get(const conn_rec *c);
h2_ctx *h2_ctx_rget(const request_rec *r);
h2_ctx *h2_ctx_create_for(const conn_rec *c, struct h2_task_env *env);


/* Set the h2 protocol established on this connection context or
 * NULL when other protocols are in place.
 */
h2_ctx *h2_ctx_protocol_set(h2_ctx *ctx, const char *proto);

/**
 * Get the h2 protocol negotiated for this connection, or NULL.
 */
const char *h2_ctx_protocol_get(const conn_rec *c);

int h2_ctx_is_task(h2_ctx *ctx);
int h2_ctx_is_active(h2_ctx *ctx);

struct h2_task_env *h2_ctx_get_task(h2_ctx *ctx);

#endif /* defined(__mod_h2__h2_ctx__) */
