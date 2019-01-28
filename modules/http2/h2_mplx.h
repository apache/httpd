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
 * The stream multiplexer. It pushes buckets from the connection
 * thread to the stream threads and vice versa. It's thread-safe
 * to use.
 *
 * There is one h2_mplx instance for each h2_session, which sits on top
 * of a particular httpd conn_rec. Input goes from the connection to
 * the stream tasks. Output goes from the stream tasks to the connection,
 * e.g. the client.
 *
 * For each stream, there can be at most "H2StreamMaxMemSize" output bytes
 * queued in the multiplexer. If a task thread tries to write more
 * data, it is blocked until space becomes available.
 *
 * Writing input is never blocked. In order to use flow control on the input,
 * the mplx can be polled for input data consumption.
 */

struct apr_pool_t;
struct apr_thread_mutex_t;
struct apr_thread_cond_t;
struct h2_bucket_beam;
struct h2_config;
struct h2_ihash_t;
struct h2_task;
struct h2_stream;
struct h2_request;
struct apr_thread_cond_t;
struct h2_workers;
struct h2_iqueue;
struct h2_ngn_shed;
struct h2_req_engine;

#include <apr_queue.h>

typedef struct h2_mplx h2_mplx;

struct h2_mplx {
    long id;
    conn_rec *c;
    apr_pool_t *pool;
    server_rec *s;                  /* server for master conn */

    unsigned int event_pending;
    unsigned int aborted;
    unsigned int is_registered;     /* is registered at h2_workers */

    struct h2_ihash_t *streams;     /* all streams currently processing */
    struct h2_ihash_t *sredo;       /* all streams that need to be re-started */
    struct h2_ihash_t *shold;       /* all streams done with task ongoing */
    struct h2_ihash_t *spurge;      /* all streams done, ready for destroy */
    
    struct h2_iqueue *q;            /* all stream ids that need to be started */
    struct h2_ififo *readyq;        /* all stream ids ready for output */
        
    struct h2_ihash_t *redo_tasks;  /* all tasks that need to be redone */
    
    int max_streams;        /* max # of concurrent streams */
    int max_stream_started; /* highest stream id that started processing */
    int tasks_active;       /* # of tasks being processed from this mplx */
    int limit_active;       /* current limit on active tasks, dynamic */
    int max_active;         /* max, hard limit # of active tasks in a process */
    apr_time_t last_idle_block;      /* last time, this mplx entered IDLE while
                                      * streams were ready */
    apr_time_t last_limit_change;    /* last time, worker limit changed */
    apr_interval_time_t limit_change_interval;

    apr_thread_mutex_t *lock;
    struct apr_thread_cond_t *added_output;
    struct apr_thread_cond_t *task_thawed;
    struct apr_thread_cond_t *join_wait;
    
    apr_size_t stream_max_mem;
    
    apr_pool_t *spare_io_pool;
    apr_array_header_t *spare_slaves; /* spare slave connections */
    
    struct h2_workers *workers;
    
    struct h2_ngn_shed *ngn_shed;
};



/*******************************************************************************
 * Object lifecycle and information.
 ******************************************************************************/

apr_status_t h2_mplx_child_init(apr_pool_t *pool, server_rec *s);

/**
 * Create the multiplexer for the given HTTP2 session. 
 * Implicitly has reference count 1.
 */
h2_mplx *h2_mplx_create(conn_rec *c, server_rec *s, apr_pool_t *master, 
                        struct h2_workers *workers);

/**
 * Decreases the reference counter of this mplx and waits for it
 * to reached 0, destroy the mplx afterwards.
 * This is to be called from the thread that created the mplx in
 * the first place.
 * @param m the mplx to be released and destroyed
 * @param wait condition var to wait on for ref counter == 0
 */ 
void h2_mplx_release_and_join(h2_mplx *m, struct apr_thread_cond_t *wait);

apr_status_t h2_mplx_pop_task(h2_mplx *m, struct h2_task **ptask);

void h2_mplx_task_done(h2_mplx *m, struct h2_task *task, struct h2_task **ptask);

/**
 * Shut down the multiplexer gracefully. Will no longer schedule new streams
 * but let the ongoing ones finish normally.
 * @return the highest stream id being/been processed
 */
int h2_mplx_shutdown(h2_mplx *m);

int h2_mplx_is_busy(h2_mplx *m);

/*******************************************************************************
 * IO lifetime of streams.
 ******************************************************************************/

struct h2_stream *h2_mplx_stream_get(h2_mplx *m, int id);

/**
 * Notifies mplx that a stream has been completely handled on the main
 * connection and is ready for cleanup.
 * 
 * @param m the mplx itself
 * @param stream the stream ready for cleanup
 */
apr_status_t h2_mplx_stream_cleanup(h2_mplx *m, struct h2_stream *stream);

/**
 * Waits on output data from any stream in this session to become available. 
 * Returns APR_TIMEUP if no data arrived in the given time.
 */
apr_status_t h2_mplx_out_trywait(h2_mplx *m, apr_interval_time_t timeout,
                                 struct apr_thread_cond_t *iowait);

apr_status_t h2_mplx_keep_active(h2_mplx *m, struct h2_stream *stream);

/*******************************************************************************
 * Stream processing.
 ******************************************************************************/

/**
 * Process a stream request.
 * 
 * @param m the multiplexer
 * @param stream the identifier of the stream
 * @param r the request to be processed
 * @param cmp the stream priority compare function
 * @param ctx context data for the compare function
 */
apr_status_t h2_mplx_process(h2_mplx *m, struct h2_stream *stream, 
                             h2_stream_pri_cmp *cmp, void *ctx);

/**
 * Stream priorities have changed, reschedule pending requests.
 * 
 * @param m the multiplexer
 * @param cmp the stream priority compare function
 * @param ctx context data for the compare function
 */
apr_status_t h2_mplx_reprioritize(h2_mplx *m, h2_stream_pri_cmp *cmp, void *ctx);

typedef apr_status_t stream_ev_callback(void *ctx, struct h2_stream *stream);

/**
 * Check if the multiplexer has events for the master connection pending.
 * @return != 0 iff there are events pending
 */
int h2_mplx_has_master_events(h2_mplx *m);

/**
 * Dispatch events for the master connection, such as
 ± @param m the multiplexer
 * @param on_resume new output data has arrived for a suspended stream 
 * @param ctx user supplied argument to invocation.
 */
apr_status_t h2_mplx_dispatch_master_events(h2_mplx *m, 
                                            stream_ev_callback *on_resume, 
                                            void *ctx);

int h2_mplx_awaits_data(h2_mplx *m);

typedef int h2_mplx_stream_cb(struct h2_stream *s, void *ctx);

apr_status_t h2_mplx_stream_do(h2_mplx *m, h2_mplx_stream_cb *cb, void *ctx);

/*******************************************************************************
 * Output handling of streams.
 ******************************************************************************/

/**
 * Opens the output for the given stream with the specified response.
 */
apr_status_t h2_mplx_out_open(h2_mplx *mplx, int stream_id,
                              struct h2_bucket_beam *beam);

/*******************************************************************************
 * h2_mplx list Manipulation.
 ******************************************************************************/

/**
 * The magic pointer value that indicates the head of a h2_mplx list
 * @param  b The mplx list
 * @return The magic pointer value
 */
#define H2_MPLX_LIST_SENTINEL(b)	APR_RING_SENTINEL((b), h2_mplx, link)

/**
 * Determine if the mplx list is empty
 * @param b The list to check
 * @return true or false
 */
#define H2_MPLX_LIST_EMPTY(b)	APR_RING_EMPTY((b), h2_mplx, link)

/**
 * Return the first mplx in a list
 * @param b The list to query
 * @return The first mplx in the list
 */
#define H2_MPLX_LIST_FIRST(b)	APR_RING_FIRST(b)

/**
 * Return the last mplx in a list
 * @param b The list to query
 * @return The last mplx int he list
 */
#define H2_MPLX_LIST_LAST(b)	APR_RING_LAST(b)

/**
 * Insert a single mplx at the front of a list
 * @param b The list to add to
 * @param e The mplx to insert
 */
#define H2_MPLX_LIST_INSERT_HEAD(b, e) do {				\
h2_mplx *ap__b = (e);                                        \
APR_RING_INSERT_HEAD((b), ap__b, h2_mplx, link);	\
} while (0)

/**
 * Insert a single mplx at the end of a list
 * @param b The list to add to
 * @param e The mplx to insert
 */
#define H2_MPLX_LIST_INSERT_TAIL(b, e) do {				\
h2_mplx *ap__b = (e);					\
APR_RING_INSERT_TAIL((b), ap__b, h2_mplx, link);	\
} while (0)

/**
 * Get the next mplx in the list
 * @param e The current mplx
 * @return The next mplx
 */
#define H2_MPLX_NEXT(e)	APR_RING_NEXT((e), link)
/**
 * Get the previous mplx in the list
 * @param e The current mplx
 * @return The previous mplx
 */
#define H2_MPLX_PREV(e)	APR_RING_PREV((e), link)

/**
 * Remove a mplx from its list
 * @param e The mplx to remove
 */
#define H2_MPLX_REMOVE(e)	APR_RING_REMOVE((e), link)

/*******************************************************************************
 * h2_mplx DoS protection
 ******************************************************************************/

/**
 * Master connection has entered idle mode.
 * @param m the mplx instance of the master connection
 * @return != SUCCESS iff connection should be terminated
 */
apr_status_t h2_mplx_idle(h2_mplx *m);

/*******************************************************************************
 * h2_req_engine handling
 ******************************************************************************/

typedef void h2_output_consumed(void *ctx, conn_rec *c, apr_off_t consumed);
typedef apr_status_t h2_mplx_req_engine_init(struct h2_req_engine *engine, 
                                             const char *id, 
                                             const char *type,
                                             apr_pool_t *pool, 
                                             apr_size_t req_buffer_size,
                                             request_rec *r,
                                             h2_output_consumed **pconsumed,
                                             void **pbaton);

apr_status_t h2_mplx_req_engine_push(const char *ngn_type, 
                                     request_rec *r, 
                                     h2_mplx_req_engine_init *einit);
apr_status_t h2_mplx_req_engine_pull(struct h2_req_engine *ngn, 
                                     apr_read_type_e block, 
                                     int capacity, 
                                     request_rec **pr);
void h2_mplx_req_engine_done(struct h2_req_engine *ngn, conn_rec *r_conn,
                             apr_status_t status);

#endif /* defined(__mod_h2__h2_mplx__) */
