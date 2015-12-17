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

#ifndef __mod_h2__h2_session__
#define __mod_h2__h2_session__

#include "h2_conn_io.h"

/**
 * A HTTP/2 connection, a session with a specific client.
 * 
 * h2_session sits on top of a httpd conn_rec* instance and takes complete
 * control of the connection data. It receives protocol frames from the
 * client. For new HTTP/2 streams it creates h2_task(s) that are sent
 * via callback to a dispatcher (see h2_conn.c).
 * h2_session keeps h2_io's for each ongoing stream which buffer the
 * payload for that stream.
 *
 * New incoming HEADER frames are converted into a h2_stream+h2_task instance
 * that both represent a HTTP/2 stream, but may have separate lifetimes. This
 * allows h2_task to be scheduled in other threads without semaphores
 * all over the place. It allows task memory to be freed independant of
 * session lifetime and sessions may close down while tasks are still running.
 *
 *
 */

struct apr_thread_mutext_t;
struct apr_thread_cond_t;
struct h2_ctx;
struct h2_config;
struct h2_mplx;
struct h2_priority;
struct h2_push;
struct h2_response;
struct h2_session;
struct h2_stream;
struct h2_task;
struct h2_workers;

struct nghttp2_session;

typedef struct h2_session h2_session;

struct h2_session {
    long id;                        /* identifier of this session, unique
                                     * inside a httpd process */
    conn_rec *c;                    /* the connection this session serves */
    request_rec *r;                 /* the request that started this in case
                                     * of 'h2c', NULL otherwise */
    server_rec *s;                  /* server/vhost we're starting on */
    const struct h2_config *config; /* Relevant config for this session */
    
    int started;
    int aborted;                    /* this session is being aborted */
    int reprioritize;               /* scheduled streams priority needs to 
                                     * be re-evaluated */
                                     
    apr_interval_time_t  wait_micros;
    int unsent_submits;             /* number of submitted, but not yet sent
                                       responses. */
    int unsent_promises;            /* number of submitted, but not yet sent
                                     * push promised */
                                     
    apr_size_t frames_received;     /* number of http/2 frames received */
    apr_size_t frames_sent;         /* number of http/2 frames sent */
    apr_size_t max_stream_count;    /* max number of open streams */
    apr_size_t max_stream_mem;      /* max buffer memory for a single stream */
    
    apr_pool_t *pool;               /* pool to use in session handling */
    apr_bucket_brigade *bbtmp;      /* brigade for keeping temporary data */
    struct apr_thread_cond_t *iowait; /* our cond when trywaiting for data */
    
    h2_conn_io io;                  /* io on httpd conn filters */

    struct h2_mplx *mplx;           /* multiplexer for stream data */
    
    struct h2_stream *last_stream;  /* last stream worked with */
    struct h2_stream_set *streams;  /* streams handled by this session */
    
    int max_stream_received;        /* highest stream id created */
    int max_stream_handled;         /* highest stream id handled successfully */
    
    apr_pool_t *spare;              /* spare stream pool */
    
    struct nghttp2_session *ngh2;   /* the nghttp2 session (internal use) */
    struct h2_workers *workers;     /* for executing stream tasks */
};


/**
 * Create a new h2_session for the given connection.
 * The session will apply the configured parameter.
 * @param c       the connection to work on
 * @param cfg     the module config to apply
 * @param workers the worker pool to use
 * @return the created session
 */
h2_session *h2_session_create(conn_rec *c, struct h2_ctx *ctx, 
                              struct h2_workers *workers);

/**
 * Create a new h2_session for the given request.
 * The session will apply the configured parameter.
 * @param r       the request that was upgraded
 * @param cfg     the module config to apply
 * @param workers the worker pool to use
 * @return the created session
 */
h2_session *h2_session_rcreate(request_rec *r, struct h2_ctx *ctx,
                               struct h2_workers *workers);

/**
 * Recieve len bytes of raw HTTP/2 input data. Return the amount
 * consumed and if the session is done.
 */
apr_status_t h2_session_receive(h2_session *session, 
                                const char *data, apr_size_t len,
                                apr_size_t *readlen);

/**
 * Process the given HTTP/2 session until it is ended or a fatal
 * error occured.
 *
 * @param session the sessionm to process
 */
apr_status_t h2_session_process(h2_session *session, int async);

/**
 * Destroy the session and all objects it still contains. This will not
 * destroy h2_task instances that have not finished yet. 
 * @param session the session to destroy
 */
void h2_session_destroy(h2_session *session);

/**
 * Cleanup the session and all objects it still contains. This will not
 * destroy h2_task instances that have not finished yet. 
 * @param session the session to destroy
 */
void h2_session_eoc_callback(h2_session *session);

/**
 * Called when an error occured and the session needs to shut down.
 * @param session the session to shut down
 * @param reason  the apache status that caused the shutdown
 * @param rv      the nghttp2 reason for shutdown, set to 0 if you have none.
 *
 */
apr_status_t h2_session_abort(h2_session *session, apr_status_t reason, int rv);

/**
 * Called before a session gets destroyed, might flush output etc. 
 */
apr_status_t h2_session_close(h2_session *session);

/* Start submitting the response to a stream request. This is possible
 * once we have all the response headers. */
apr_status_t h2_session_handle_response(h2_session *session,
                                        struct h2_stream *stream);

/* Get the h2_stream for the given stream idenrtifier. */
struct h2_stream *h2_session_get_stream(h2_session *session, int stream_id);

/**
 * Create and register a new stream under the given id.
 * 
 * @param session the session to register in
 * @param stream_id the new stream identifier
 * @return the new stream
 */
struct h2_stream *h2_session_open_stream(h2_session *session, int stream_id);

/**
 * Returns if client settings have push enabled.
 * @param != 0 iff push is enabled in client settings
 */
int h2_session_push_enabled(h2_session *session);

/**
 * Destroy the stream and release it everywhere. Reclaim all resources.
 * @param session the session to which the stream belongs
 * @param stream the stream to destroy
 */
apr_status_t h2_session_stream_destroy(h2_session *session, 
                                       struct h2_stream *stream);

/**
 * Submit a push promise on the stream and schedule the new steam for
 * processing..
 * 
 * @param session the session to work in
 * @param is the stream initiating the push
 * @param push the push to promise
 * @return the new promised stream or NULL
 */
struct h2_stream *h2_session_push(h2_session *session, 
                                  struct h2_stream *is, struct h2_push *push);

apr_status_t h2_session_set_prio(h2_session *session, 
                                 struct h2_stream *stream, 
                                 const struct h2_priority *prio);


#endif /* defined(__mod_h2__h2_session__) */
