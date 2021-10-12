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

#ifndef __mod_h2__h2_mplx__
#define __mod_h2__h2_mplx__

/**
 * The stream multiplexer. It performs communication between the
 * primary HTTP/2 connection (c1) to the secondary connections (c2)
 * that process the requests, aka. HTTP/2 streams.
 *
 * There is one h2_mplx instance for each h2_session.
 *
 * Naming Convention:
 * "h2_mplx_c1_" are methods only to be called by the primary connection
 * "h2_mplx_c2_" are methods only to be called by a secondary connection
 * "h2_mplx_worker_" are methods only to be called by a h2 worker thread
 */

struct apr_pool_t;
struct apr_thread_mutex_t;
struct apr_thread_cond_t;
struct h2_bucket_beam;
struct h2_config;
struct h2_ihash_t;
struct h2_stream;
struct h2_request;
struct apr_thread_cond_t;
struct h2_workers;
struct h2_iqueue;

#include <apr_queue.h>

typedef struct h2_mplx h2_mplx;

struct h2_mplx {
    long id;
    conn_rec *c1;                   /* the main connection */
    apr_pool_t *pool;
    struct h2_stream *stream0;      /* HTTP/2's stream 0 */
    server_rec *s;                  /* server for master conn */

    int aborted;
    int polling;                    /* is waiting/processing pollset events */
    int is_registered;              /* is registered at h2_workers */

    struct h2_ihash_t *streams;     /* all streams active */
    struct h2_ihash_t *shold;       /* all streams done with c2 processing ongoing */
    apr_array_header_t *spurge;     /* all streams done, ready for destroy */
    
    struct h2_iqueue *q;            /* all stream ids that need to be started */

    apr_size_t stream_max_mem;      /* max memory to buffer for a stream */
    int max_streams;                /* max # of concurrent streams */
    int max_stream_id_started;      /* highest stream id that started processing */

    int processing_count;           /* # of c2 working for this mplx */
    int processing_limit;           /* current limit on processing c2s, dynamic */
    int processing_max;             /* max, hard limit of processing c2s */
    
    apr_time_t last_mood_change;    /* last time, processing limit changed */
    apr_interval_time_t mood_update_interval; /* how frequent we update at most */
    int irritations_since; /* irritations (>0) or happy events (<0) since last mood change */

    apr_thread_mutex_t *lock;
    struct apr_thread_cond_t *join_wait;
    
    apr_pollset_t *pollset;         /* pollset for c1/c2 IO events */
    apr_array_header_t *streams_to_poll; /* streams to add to the pollset */
    apr_array_header_t *streams_ev_in;
    apr_array_header_t *streams_ev_out;

#if !H2_POLL_STREAMS
    apr_thread_mutex_t *poll_lock; /* not the painter */
    struct h2_iqueue *streams_input_read;  /* streams whose input has been read from */
    struct h2_iqueue *streams_output_written; /* streams whose output has been written to */
#endif
    struct h2_workers *workers;     /* h2 workers process wide instance */
};

apr_status_t h2_mplx_c1_child_init(apr_pool_t *pool, server_rec *s);

/**
 * Create the multiplexer for the given HTTP2 session. 
 * Implicitly has reference count 1.
 */
h2_mplx *h2_mplx_c1_create(struct h2_stream *stream0, server_rec *s, apr_pool_t *master,
                           struct h2_workers *workers);

/**
 * Destroy the mplx, shutting down all ongoing processing.
 * @param m the mplx destroyed
 * @param wait condition var to wait on for ref counter == 0
 */ 
void h2_mplx_c1_destroy(h2_mplx *m);

/**
 * Shut down the multiplexer gracefully. Will no longer schedule new streams
 * but let the ongoing ones finish normally.
 * @return the highest stream id being/been processed
 */
int h2_mplx_c1_shutdown(h2_mplx *m);

/**
 * Notifies mplx that a stream has been completely handled on the main
 * connection and is ready for cleanup.
 * 
 * @param m the mplx itself
 * @param stream the stream ready for cleanup
 * @param pstream_count return the number of streams active
 */
apr_status_t h2_mplx_c1_stream_cleanup(h2_mplx *m, struct h2_stream *stream,
                                       int *pstream_count);

int h2_mplx_c1_stream_is_running(h2_mplx *m, struct h2_stream *stream);

/**
 * Process a stream request.
 * 
 * @param m the multiplexer
 * @param read_to_process
 * @param input_pending
 * @param cmp the stream priority compare function
 * @param pstream_count on return the number of streams active in mplx
 */
apr_status_t h2_mplx_c1_process(h2_mplx *m,
                                struct h2_iqueue *read_to_process,
                                h2_stream_get_fn *get_stream,
                                h2_stream_pri_cmp_fn *cmp,
                                struct h2_session *session,
                                int *pstream_count);

apr_status_t h2_mplx_c1_fwd_input(h2_mplx *m, struct h2_iqueue *input_pending,
                                  h2_stream_get_fn *get_stream,
                                  struct h2_session *session);


/**
 * Stream priorities have changed, reschedule pending requests.
 * 
 * @param m the multiplexer
 * @param cmp the stream priority compare function
 * @param ctx context data for the compare function
 */
apr_status_t h2_mplx_c1_reprioritize(h2_mplx *m, h2_stream_pri_cmp_fn *cmp,
                                    struct h2_session *session);

typedef apr_status_t stream_ev_callback(void *ctx, struct h2_stream *stream);

/**
 * Poll the primary connection for input and the active streams for output.
 * Invoke the callback for any stream where an event happened.
 */
apr_status_t h2_mplx_c1_poll(h2_mplx *m, apr_interval_time_t timeout,
                            stream_ev_callback *on_stream_input,
                            stream_ev_callback *on_stream_output,
                            void *on_ctx);

void h2_mplx_c2_input_read(h2_mplx *m, conn_rec *c2);
void h2_mplx_c2_output_written(h2_mplx *m, conn_rec *c2);

typedef int h2_mplx_stream_cb(struct h2_stream *s, void *userdata);

/**
 * Iterate over all streams known to mplx from the primary connection.
 * @param m the mplx
 * @param cb the callback to invoke on each stream
 * @param ctx userdata passed to the callback
 */
apr_status_t h2_mplx_c1_streams_do(h2_mplx *m, h2_mplx_stream_cb *cb, void *ctx);

/**
 * A stream has been RST_STREAM by the client. Abort
 * any processing going on and remove from processing
 * queue.
 */
apr_status_t h2_mplx_c1_client_rst(h2_mplx *m, int stream_id);

/**
 * Get readonly access to a stream for a secondary connection.
 */
const struct h2_stream *h2_mplx_c2_stream_get(h2_mplx *m, int stream_id);

/**
 * A h2 worker asks for a secondary connection to process.
 * @param out_c2 non-NULL, a pointer where to reveive the next
 *               secondary connection to process.
 */
apr_status_t h2_mplx_worker_pop_c2(h2_mplx *m, conn_rec **out_c2);

/**
 * A h2 worker reports a secondary connection processing done.
 * If it is will to do more work for this mplx (this c1 connection),
 * it provides `out_c`. Otherwise it passes NULL.
 * @param c2 the secondary connection finished processing
 * @param out_c2 NULL or a pointer where to reveive the next
 *               secondary connection to process.
 */
void h2_mplx_worker_c2_done(conn_rec *c2, conn_rec **out_c2);

#endif /* defined(__mod_h2__h2_mplx__) */
