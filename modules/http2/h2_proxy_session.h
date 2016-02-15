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

#ifndef h2_proxy_session_h
#define h2_proxy_session_h

#define H2_ALEN(a)          (sizeof(a)/sizeof((a)[0]))

#include <nghttp2/nghttp2.h>

typedef struct h2_proxy_session {
    conn_rec *c;
    proxy_conn_rec *p_conn;
    proxy_server_conf *conf;
    apr_pool_t *pool;
    nghttp2_session *ngh2;   /* the nghttp2 session itself */
    
    int window_bits_default;
    int window_bits_connection;

    unsigned int goaway_recvd : 1;
    unsigned int goaway_sent : 1;
    
    int max_stream_recv;
    
    apr_bucket_brigade *input;
    apr_bucket_brigade *output;
} h2_proxy_session;

typedef struct h2_proxy_stream {
    int id;
    apr_pool_t *pool;
    h2_proxy_session *session;

    const char *url;
    request_rec *r;
    h2_request *req;

    h2_stream_state_t state;
    unsigned int data_received : 1;

    apr_bucket_brigade *input;
    apr_bucket_brigade *output;
    
    apr_table_t *saves;
} h2_proxy_stream;


h2_proxy_session *h2_proxy_session_setup(request_rec *r, proxy_conn_rec *p_connm,
                                         proxy_server_conf *conf);

apr_status_t h2_proxy_session_open_stream(h2_proxy_session *s, const char *url,
                                          request_rec *r, h2_proxy_stream **pstream);
apr_status_t h2_proxy_stream_process(h2_proxy_stream *stream);

#define H2_PROXY_REQ_URL_NOTE   "h2-proxy-req-url"

#endif /* h2_proxy_session_h */
