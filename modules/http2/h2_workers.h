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

#ifndef __mod_h2__h2_workers__
#define __mod_h2__h2_workers__

/* Thread pool specific to executing secondary connections.
 * Has a minimum and maximum number of workers it creates.
 * Starts with minimum workers and adds some on load,
 * reduces the number again when idle.
 */
struct apr_thread_mutex_t;
struct apr_thread_cond_t;
struct h2_mplx;
struct h2_request;
struct h2_fifo;

typedef struct h2_workers h2_workers;


/**
 * Create a worker set with a maximum number of 'slots', e.g. worker
 * threads to run. Always keep `min_active` workers running. Shutdown
 * any additional workers after `idle_secs` seconds of doing nothing.
 *
 * @oaram s the base server
 * @param pool for allocations
 * @param min_active minimum number of workers to run
 * @param max_slots maximum number of worker slots
 * @param idle_limit upper duration of idle after a non-minimal slots shuts down
 */
h2_workers *h2_workers_create(server_rec *s, apr_pool_t *pool,
                              int max_slots, int min_active, apr_time_t idle_limit);

/**
 *  Shut down processing.
 */
void h2_workers_shutdown(h2_workers *workers, int graceful);

/**
 * Get the maximum number of workers.
 */
apr_uint32_t h2_workers_get_max_workers(h2_workers *workers);

/**
 * ap_conn_producer_t is the source of connections (conn_rec*) to run.
 *
 * Active producers are queried by idle workers for connections.
 * If they do not hand one back, they become inactive and are not
 * queried further. `h2_workers_activate()` places them on the active
 * list again.
 *
 * A producer finishing MUST call `h2_workers_join()` which removes
 * it completely from workers processing and waits for all ongoing
 * work for this producer to be done.
 */
typedef struct ap_conn_producer_t ap_conn_producer_t;

/**
 * Ask a producer for the next connection to process.
 * @param baton value from producer registration
 * @param pconn holds the connection to process on return
 * @param pmore if the producer has more connections that may be retrieved
 * @return APR_SUCCESS for a connection to process, APR_EAGAIN for no
 *         connection being available at the time.
 */
typedef conn_rec *ap_conn_producer_next(void *baton, int *pmore);

/**
 * Tell the producer that processing the connection is done.
 * @param baton value from producer registration
 * @param conn the connection that has been processed.
 */
typedef void ap_conn_producer_done(void *baton, conn_rec *conn);

/**
 * Tell the producer that the workers are shutting down.
 * @param baton value from producer registration
 * @param graceful != 0 iff shutdown is graceful
 */
typedef void ap_conn_producer_shutdown(void *baton, int graceful);

/**
 * Register a new producer with the given `baton` and callback functions.
 * Will allocate internal structures from the given pool (but make no use
 * of the pool after registration).
 * Producers are inactive on registration. See `h2_workers_activate()`.
 * @param producer_pool to allocate the producer from
 * @param name descriptive name of the producer, must not be unique
 * @param fn_next callback for retrieving connections to process
 * @param fn_done callback for processed connections
 * @param baton provided value passed on in callbacks
 * @return the producer instance created
 */
ap_conn_producer_t *h2_workers_register(h2_workers *workers,
                                        apr_pool_t *producer_pool,
                                        const char *name,
                                        ap_conn_producer_next *fn_next,
                                        ap_conn_producer_done *fn_done,
                                        ap_conn_producer_shutdown *fn_shutdown,
                                        void *baton);

/**
 * Stop retrieving more connection from the producer and wait
 * for all ongoing for from that producer to be done.
 */
apr_status_t h2_workers_join(h2_workers *workers, ap_conn_producer_t *producer);

/**
 * Activate a producer. A worker will query the producer for a connection
 * to process, once a worker is available.
 * This may be called, irregardless of the producers active/inactive.
 */
apr_status_t h2_workers_activate(h2_workers *workers, ap_conn_producer_t *producer);

#endif /* defined(__mod_h2__h2_workers__) */
