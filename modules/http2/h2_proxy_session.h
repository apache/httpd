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

#ifndef h2_proxy_session_h
#define h2_proxy_session_h

#define H2_ALEN(a)          (sizeof(a)/sizeof((a)[0]))

#include <nghttp2/nghttp2.h>

struct h2_proxy_iqueue;
struct h2_proxy_ihash_t;

typedef enum {
    H2_STREAM_ST_IDLE,
    H2_STREAM_ST_OPEN,
    H2_STREAM_ST_RESV_LOCAL,
    H2_STREAM_ST_RESV_REMOTE,
    H2_STREAM_ST_CLOSED_INPUT,
    H2_STREAM_ST_CLOSED_OUTPUT,
    H2_STREAM_ST_CLOSED,
} h2_proxy_stream_state_t;

typedef enum {
    H2_PROXYS_ST_INIT,             /* send initial SETTINGS, etc. */
    H2_PROXYS_ST_DONE,             /* finished, connection close */
    H2_PROXYS_ST_IDLE,             /* no streams to process */
    H2_PROXYS_ST_BUSY,             /* read/write without stop */
    H2_PROXYS_ST_WAIT,             /* waiting for tasks reporting back */
    H2_PROXYS_ST_LOCAL_SHUTDOWN,   /* we announced GOAWAY */
    H2_PROXYS_ST_REMOTE_SHUTDOWN,  /* client announced GOAWAY */
} h2_proxys_state;

typedef enum {
    H2_PROXYS_EV_INIT,             /* session was initialized */
    H2_PROXYS_EV_LOCAL_GOAWAY,     /* we send a GOAWAY */
    H2_PROXYS_EV_REMOTE_GOAWAY,    /* remote send us a GOAWAY */
    H2_PROXYS_EV_CONN_ERROR,       /* connection error */
    H2_PROXYS_EV_PROTO_ERROR,      /* protocol error */
    H2_PROXYS_EV_CONN_TIMEOUT,     /* connection timeout */
    H2_PROXYS_EV_NO_IO,            /* nothing has been read or written */
    H2_PROXYS_EV_STREAM_SUBMITTED, /* stream has been submitted */
    H2_PROXYS_EV_STREAM_DONE,      /* stream has been finished */
    H2_PROXYS_EV_STREAM_RESUMED,   /* stream signalled availability of headers/data */
    H2_PROXYS_EV_DATA_READ,        /* connection data has been read */
    H2_PROXYS_EV_NGH2_DONE,        /* nghttp2 wants neither read nor write anything */
    H2_PROXYS_EV_PRE_CLOSE,        /* connection will close after this */
} h2_proxys_event_t;

typedef enum {
    H2_PING_ST_NONE,               /* normal connection mode, ProxyTimeout rules */
    H2_PING_ST_AWAIT_ANY,          /* waiting for any frame from backend */
    H2_PING_ST_AWAIT_PING,         /* waiting for PING frame from backend */
} h2_ping_state_t;

typedef struct h2_proxy_session h2_proxy_session;
typedef void h2_proxy_request_done(h2_proxy_session *s, request_rec *r,
                                   apr_status_t status, int touched);

struct h2_proxy_session {
    const char *id;
    conn_rec *c;
    proxy_conn_rec *p_conn;
    proxy_server_conf *conf;
    apr_pool_t *pool;
    nghttp2_session *ngh2;   /* the nghttp2 session itself */
    
    unsigned int aborted : 1;
    unsigned int h2_front : 1; /* if front-end connection is HTTP/2 */

    h2_proxy_request_done *done;
    void *user_data;
    
    unsigned char window_bits_stream;
    unsigned char window_bits_connection;

    h2_proxys_state state;
    apr_interval_time_t wait_timeout;

    struct h2_proxy_ihash_t *streams;
    struct h2_proxy_iqueue *suspended;
    apr_size_t remote_max_concurrent;
    int last_stream_id;     /* last stream id processed by backend, or 0 */
    apr_time_t last_frame_received;
    
    apr_bucket_brigade *input;
    apr_bucket_brigade *output;

    h2_ping_state_t ping_state;
    apr_time_t ping_timeout;
    apr_time_t save_timeout;
};

h2_proxy_session *h2_proxy_session_setup(const char *id, proxy_conn_rec *p_conn,
                                         proxy_server_conf *conf,
                                         int h2_front, 
                                         unsigned char window_bits_connection,
                                         unsigned char window_bits_stream,
                                         h2_proxy_request_done *done);

apr_status_t h2_proxy_session_submit(h2_proxy_session *s, const char *url,
                                     request_rec *r, int standalone);
                       
/** 
 * Perform a step in processing the proxy session. Will return aftert
 * one read/write cycle and indicate session status by status code.
 * @param s the session to process
 * @return APR_EAGAIN  when processing needs to be invoked again
 *         APR_SUCCESS when all streams have been processed, session still live
 *         APR_EOF     when the session has been terminated
 */
apr_status_t h2_proxy_session_process(h2_proxy_session *s);

void h2_proxy_session_cancel_all(h2_proxy_session *s);

void h2_proxy_session_cleanup(h2_proxy_session *s, h2_proxy_request_done *done);

#define H2_PROXY_REQ_URL_NOTE   "h2-proxy-req-url"

#endif /* h2_proxy_session_h */
