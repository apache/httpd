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

#ifndef H3_THREADS_H
#define H3_THREADS_H

#include "h3_io.h"
#include <apr_pools.h>
#include <apr_thread_proc.h>

/**
 * Arguments passed to the worker thread when spawned.
 */
struct worker_args
{
    h3_io_t* io;
    h3_session* session;
};

/**
 * The entry point for the session worker thread. Services a single
 * accepted HTTP/3 session, driving the HTTP/3 request processing and
 * network I/O loop until completion or abort.
 *
 * @param thread The APR thread context.
 * @param data   Pointer to the struct worker_args arguments.
 * @return NULL.
 */
void* APR_THREAD_FUNC worker_thread(apr_thread_t* thread, void* data);

/**
 * The entry point for the child listener event thread. Drives the main
 * non-blocking select/event loop for accepting QUIC connections and
 * processing handshakes for all pending connections.
 *
 * @param thread The APR thread context.
 * @param data   Pointer to the h3_io_t listener instance.
 * @return NULL.
 */
void* APR_THREAD_FUNC h3_event_thread(apr_thread_t* thread, void* data);

/**
 * Create a pool that may be allocated from by more than one thread: it has
 * an allocator of its own, with a mutex. Pools such as the child pool may
 * have an allocator without one; prefork shares it, unlocked, with the
 * pool of every request.
 *
 * @param parent The parent pool.
 * @param tag    The tag for the new pool.
 * @param out    Receives the new pool.
 * @return APR_SUCCESS, or the error from APR.
 */
apr_status_t h3_thread_safe_pool_create(apr_pool_t* parent, const char* tag, apr_pool_t** out);

#endif /* H3_THREADS_H */
