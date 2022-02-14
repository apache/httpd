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

#ifndef __mod_h2__h2_session__
#define __mod_h2__h2_session__

#include "h2_c1_io.h"

/**
 * A HTTP/2 connection, a session with a specific client.
 * 
 * h2_session sits on top of a httpd conn_rec* instance and takes complete
 * control of the connection data. It receives protocol frames from the
 * client. For new HTTP/2 streams it creates secondary connections
 * to execute the requests in h2 workers.
 */

#include "h2.h"

struct apr_thread_mutext_t;
struct apr_thread_cond_t;
struct h2_ctx;
struct h2_config;
struct h2_ihash_t;
struct h2_mplx;
struct h2_priority;
struct h2_push;
struct h2_push_diary;
struct h2_session;
struct h2_stream;
struct h2_stream_monitor;
struct h2_workers;

struct nghttp2_session;

typedef enum {
    H2_SESSION_EV_INIT,             /* session was initialized */
    H2_SESSION_EV_INPUT_PENDING,    /* c1 input may have data pending */
    H2_SESSION_EV_INPUT_EXHAUSTED,  /* c1 input exhausted */
    H2_SESSION_EV_LOCAL_GOAWAY,     /* we send a GOAWAY */
    H2_SESSION_EV_REMOTE_GOAWAY,    /* remote send us a GOAWAY */
    H2_SESSION_EV_CONN_ERROR,       /* connection error */
    H2_SESSION_EV_PROTO_ERROR,      /* protocol error */
    H2_SESSION_EV_CONN_TIMEOUT,     /* connection timeout */
    H2_SESSION_EV_NGH2_DONE,        /* nghttp2 wants neither read nor write anything */
    H2_SESSION_EV_MPM_STOPPING,     /* the process is stopping */
    H2_SESSION_EV_PRE_CLOSE,        /* connection will close after this */
    H2_SESSION_EV_NO_MORE_STREAMS,  /* no more streams to process */
} h2_session_event_t;

typedef struct h2_session {
    long id;                        /* identifier of this session, unique
                                     * inside a httpd process */
    conn_rec *c1;                   /* the main connection this session serves */
    request_rec *r;                 /* the request that started this in case
                                     * of 'h2c', NULL otherwise */
    server_rec *s;                  /* server/vhost we're starting on */
    apr_pool_t *pool;               /* pool to use in session */
    struct h2_mplx *mplx;           /* multiplexer for stream data */
    struct h2_workers *workers;     /* for executing streams */
    struct h2_c1_io_in_ctx_t *cin;  /* connection input filter context */
    h2_c1_io io;                    /* io on httpd conn filters */
    int padding_max;                /* max number of padding bytes */
    int padding_always;             /* padding has precedence over I/O optimizations */
    struct nghttp2_session *ngh2;   /* the nghttp2 session (internal use) */

    h2_session_state state;         /* state session is in */
    
    h2_session_props local;         /* properties of local session */
    h2_session_props remote;        /* properites of remote session */
    
    unsigned int reprioritize  : 1; /* scheduled streams priority changed */
    unsigned int flush         : 1; /* flushing output necessary */
    apr_interval_time_t  wait_us;   /* timeout during BUSY_WAIT state, micro secs */
    
    struct h2_push_diary *push_diary; /* remember pushes, avoid duplicates */
    
    struct h2_stream_monitor *monitor;/* monitor callbacks for streams */
    int open_streams;               /* number of streams processing */

    int streams_done;               /* number of http/2 streams handled */
    int responses_submitted;        /* number of http/2 responses submitted */
    int streams_reset;              /* number of http/2 streams reset by client */
    int pushes_promised;            /* number of http/2 push promises submitted */
    int pushes_submitted;           /* number of http/2 pushed responses submitted */
    int pushes_reset;               /* number of http/2 pushed reset by client */
    
    apr_size_t frames_received;     /* number of http/2 frames received */
    apr_size_t frames_sent;         /* number of http/2 frames sent */
    
    apr_size_t max_stream_count;    /* max number of open streams */
    apr_size_t max_stream_mem;      /* max buffer memory for a single stream */
    
    apr_size_t idle_frames;         /* number of rcvd frames that kept session in idle state */
    apr_interval_time_t idle_delay; /* Time we delay processing rcvd frames in idle state */
    
    apr_bucket_brigade *bbtmp;      /* brigade for keeping temporary data */

    char status[64];                /* status message for scoreboard */
    int last_status_code;           /* the one already reported */
    const char *last_status_msg;    /* the one already reported */
    
    struct h2_iqueue *in_pending;   /* all streams with input pending */
    struct h2_iqueue *out_c1_blocked;  /* all streams with output blocked on c1 buffer full */
    struct h2_iqueue *ready_to_process;  /* all streams ready for processing */

} h2_session;

const char *h2_session_state_str(h2_session_state state);

/**
 * Create a new h2_session for the given connection.
 * The session will apply the configured parameter.
 * @param psession pointer receiving the created session on success or NULL
 * @param c       the connection to work on
 * @param r       optional request when protocol was upgraded
 * @param cfg     the module config to apply
 * @param workers the worker pool to use
 * @return the created session
 */
apr_status_t h2_session_create(h2_session **psession,
                               conn_rec *c, request_rec *r, server_rec *, 
                               struct h2_workers *workers);

void h2_session_event(h2_session *session, h2_session_event_t ev, 
                      int err, const char *msg);

/**
 * Process the given HTTP/2 session until it is ended or a fatal
 * error occurred.
 *
 * @param session the sessionm to process
 */
apr_status_t h2_session_process(h2_session *session, int async);

/**
 * Last chance to do anything before the connection is closed.
 */
apr_status_t h2_session_pre_close(h2_session *session, int async);

/**
 * Called when a serious error occurred and the session needs to terminate
 * without further connection io.
 * @param session the session to abort
 * @param reason  the apache status that caused the abort
 */
void h2_session_abort(h2_session *session, apr_status_t reason);

/**
 * Returns if client settings have push enabled.
 * @param != 0 iff push is enabled in client settings
 */
int h2_session_push_enabled(h2_session *session);

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

/**
 * Dispatch a event happending during session processing.
 * @param session the sessiont
 * @param ev the event that happened
 * @param arg integer argument (event type dependant)
 * @param msg destriptive message
 */
void h2_session_dispatch_event(h2_session *session, h2_session_event_t ev,
                               int arg, const char *msg);


#define H2_SSSN_MSG(s, msg)     \
    "h2_session(%ld,%s,%d): "msg, s->id, h2_session_state_str(s->state), \
                            s->open_streams

#define H2_SSSN_LOG(aplogno, s, msg)    aplogno H2_SSSN_MSG(s, msg)

#endif /* defined(__mod_h2__h2_session__) */
