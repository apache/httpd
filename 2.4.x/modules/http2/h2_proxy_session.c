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

#include <stddef.h>
#include <apr_strings.h>
#include <nghttp2/nghttp2.h>

#include <mpm_common.h>
#include <httpd.h>
#include <mod_proxy.h>

#include "mod_http2.h"
#include "h2.h"
#include "h2_proxy_util.h"
#include "h2_proxy_session.h"

APLOG_USE_MODULE(proxy_http2);

typedef struct h2_proxy_stream {
    int id;
    apr_pool_t *pool;
    h2_proxy_session *session;

    const char *url;
    request_rec *r;
    h2_proxy_request *req;
    const char *real_server_uri;
    const char *p_server_uri;
    int standalone;

    h2_stream_state_t state;
    unsigned int suspended : 1;
    unsigned int waiting_on_100 : 1;
    unsigned int waiting_on_ping : 1;
    uint32_t error_code;

    apr_bucket_brigade *input;
    apr_off_t data_sent;
    apr_bucket_brigade *output;
    apr_off_t data_received;
    
    apr_table_t *saves;
} h2_proxy_stream;


static void dispatch_event(h2_proxy_session *session, h2_proxys_event_t ev, 
                           int arg, const char *msg);
static void ping_arrived(h2_proxy_session *session);
static apr_status_t check_suspended(h2_proxy_session *session);
static void stream_resume(h2_proxy_stream *stream);


static apr_status_t proxy_session_pre_close(void *theconn)
{
    proxy_conn_rec *p_conn = (proxy_conn_rec *)theconn;
    h2_proxy_session *session = p_conn->data;

    if (session && session->ngh2) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c, 
                      "proxy_session(%s): pool cleanup, state=%d, streams=%d",
                      session->id, session->state, 
                      (int)h2_proxy_ihash_count(session->streams));
        session->aborted = 1;
        dispatch_event(session, H2_PROXYS_EV_PRE_CLOSE, 0, NULL);
        nghttp2_session_del(session->ngh2);
        session->ngh2 = NULL;
        p_conn->data = NULL;
    }
    return APR_SUCCESS;
}

static int proxy_pass_brigade(apr_bucket_alloc_t *bucket_alloc,
                              proxy_conn_rec *p_conn,
                              conn_rec *origin, apr_bucket_brigade *bb,
                              int flush)
{
    apr_status_t status;
    apr_off_t transferred;

    if (flush) {
        apr_bucket *e = apr_bucket_flush_create(bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }
    apr_brigade_length(bb, 0, &transferred);
    if (transferred != -1)
        p_conn->worker->s->transferred += transferred;
    status = ap_pass_brigade(origin->output_filters, bb);
    /* Cleanup the brigade now to avoid buckets lifetime
     * issues in case of error returned below. */
    apr_brigade_cleanup(bb);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, origin, APLOGNO(03357)
                      "pass output failed to %pI (%s)",
                      p_conn->addr, p_conn->hostname);
    }
    return status;
}

static ssize_t raw_send(nghttp2_session *ngh2, const uint8_t *data,
                        size_t length, int flags, void *user_data)
{
    h2_proxy_session *session = user_data;
    apr_bucket *b;
    apr_status_t status;
    int flush = 1;

    if (data) {
        b = apr_bucket_transient_create((const char*)data, length, 
                                        session->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(session->output, b);
    }

    status = proxy_pass_brigade(session->c->bucket_alloc,  
                                session->p_conn, session->c, 
                                session->output, flush);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c, 
                  "h2_proxy_sesssion(%s): raw_send %d bytes, flush=%d", 
                  session->id, (int)length, flush);
    if (status != APR_SUCCESS) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return length;
}

static int on_frame_recv(nghttp2_session *ngh2, const nghttp2_frame *frame,
                         void *user_data) 
{
    h2_proxy_session *session = user_data;
    h2_proxy_stream *stream;
    request_rec *r;
    int n;
    
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        h2_proxy_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03341)
                      "h2_proxy_session(%s): recv FRAME[%s]",
                      session->id, buffer);
    }

    session->last_frame_received = apr_time_now();
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            stream = nghttp2_session_get_stream_user_data(ngh2, frame->hd.stream_id);
            if (!stream) {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            r = stream->r;
            if (r->status >= 100 && r->status < 200) {
                /* By default, we will forward all interim responses when
                 * we are sitting on a HTTP/2 connection to the client */
                int forward = session->h2_front;
                switch(r->status) {
                    case 100:
                        if (stream->waiting_on_100) {
                            stream->waiting_on_100 = 0;
                            r->status_line = ap_get_status_line(r->status);
                            forward = 1;
                        } 
                        break;
                    case 103:
                        /* workaround until we get this into http protocol base
                         * parts. without this, unknown codes are converted to
                         * 500... */
                        r->status_line = "103 Early Hints";
                        break;
                    default:
                        r->status_line = ap_get_status_line(r->status);
                        break;
                }
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03487) 
                              "h2_proxy_session(%s): got interim HEADERS, "
                              "status=%d, will forward=%d",
                              session->id, r->status, forward);
                if (forward) {
                    ap_send_interim_response(r, 1);
                }
            }
            stream_resume(stream);
            break;
        case NGHTTP2_PING:
            if (session->check_ping) {
                session->check_ping = 0;
                ping_arrived(session);
            }
            break;
        case NGHTTP2_PUSH_PROMISE:
            break;
        case NGHTTP2_SETTINGS:
            if (frame->settings.niv > 0) {
                n = nghttp2_session_get_remote_settings(ngh2, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
                if (n > 0) {
                    session->remote_max_concurrent = n;
                }
            }
            break;
        case NGHTTP2_GOAWAY:
            /* we expect the remote server to tell us the highest stream id
             * that it has started processing. */
            session->last_stream_id = frame->goaway.last_stream_id;
            dispatch_event(session, H2_PROXYS_EV_REMOTE_GOAWAY, 0, NULL);
            break;
        default:
            break;
    }
    return 0;
}

static int before_frame_send(nghttp2_session *ngh2,
                             const nghttp2_frame *frame, void *user_data)
{
    h2_proxy_session *session = user_data;
    if (APLOGcdebug(session->c)) {
        char buffer[256];

        h2_proxy_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03343)
                      "h2_proxy_session(%s): sent FRAME[%s]",
                      session->id, buffer);
    }
    return 0;
}

static int add_header(void *table, const char *n, const char *v)
{
    apr_table_addn(table, n, v);
    return 1;
}

static void process_proxy_header(h2_proxy_stream *stream, const char *n, const char *v)
{
    request_rec *r = stream->r;
    static const struct {
        const char *name;
        ap_proxy_header_reverse_map_fn func;
    } transform_hdrs[] = {
        { "Location", ap_proxy_location_reverse_map },
        { "Content-Location", ap_proxy_location_reverse_map },
        { "URI", ap_proxy_location_reverse_map },
        { "Destination", ap_proxy_location_reverse_map },
        { "Set-Cookie", ap_proxy_cookie_reverse_map },
        { NULL, NULL }
    };
    proxy_dir_conf *dconf;
    int i;
    
    for (i = 0; transform_hdrs[i].name; ++i) {
        if (!ap_cstr_casecmp(transform_hdrs[i].name, n)) {
            dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
            apr_table_add(r->headers_out, n,
                          (*transform_hdrs[i].func)(r, dconf, v));
            return;
       }
    }
    if (!ap_cstr_casecmp("Link", n)) {
        dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
        apr_table_add(r->headers_out, n,
                      h2_proxy_link_reverse_map(r, dconf, 
                      stream->real_server_uri, stream->p_server_uri, v));
        return;
    }
    apr_table_add(r->headers_out, n, v);
}

static apr_status_t h2_proxy_stream_add_header_out(h2_proxy_stream *stream,
                                                   const char *n, apr_size_t nlen,
                                                   const char *v, apr_size_t vlen)
{
    if (n[0] == ':') {
        if (!stream->data_received && !strncmp(":status", n, nlen)) {
            char *s = apr_pstrndup(stream->r->pool, v, vlen);
            
            apr_table_setn(stream->r->notes, "proxy-status", s);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c, 
                          "h2_proxy_stream(%s-%d): got status %s", 
                          stream->session->id, stream->id, s);
            stream->r->status = (int)apr_atoi64(s);
            if (stream->r->status <= 0) {
                stream->r->status = 500;
                return APR_EGENERAL;
            }
        }
        return APR_SUCCESS;
    }
    
    if (!h2_proxy_res_ignore_header(n, nlen)) {
        char *hname, *hvalue;
    
        hname = apr_pstrndup(stream->pool, n, nlen);
        h2_proxy_util_camel_case_header(hname, nlen);
        hvalue = apr_pstrndup(stream->pool, v, vlen);
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c, 
                      "h2_proxy_stream(%s-%d): got header %s: %s", 
                      stream->session->id, stream->id, hname, hvalue);
        process_proxy_header(stream, hname, hvalue);
    }
    return APR_SUCCESS;
}

static int log_header(void *ctx, const char *key, const char *value)
{
    h2_proxy_stream *stream = ctx;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, stream->r, 
                  "h2_proxy_stream(%s-%d), header_out %s: %s", 
                  stream->session->id, stream->id, key, value);
    return 1;
}

static void h2_proxy_stream_end_headers_out(h2_proxy_stream *stream) 
{
    h2_proxy_session *session = stream->session;
    request_rec *r = stream->r;
    apr_pool_t *p = r->pool;
    
    /* Now, add in the cookies from the response to the ones already saved */
    apr_table_do(add_header, stream->saves, r->headers_out, "Set-Cookie", NULL);
    
    /* and now load 'em all in */
    if (!apr_is_empty_table(stream->saves)) {
        apr_table_unset(r->headers_out, "Set-Cookie");
        r->headers_out = apr_table_overlay(p, r->headers_out, stream->saves);
    }
    
    /* handle Via header in response */
    if (session->conf->viaopt != via_off 
        && session->conf->viaopt != via_block) {
        const char *server_name = ap_get_server_name(stream->r);
        apr_port_t port = ap_get_server_port(stream->r);
        char portstr[32];
        
        /* If USE_CANONICAL_NAME_OFF was configured for the proxy virtual host,
         * then the server name returned by ap_get_server_name() is the
         * origin server name (which does make too much sense with Via: headers)
         * so we use the proxy vhost's name instead.
         */
        if (server_name == stream->r->hostname) {
            server_name = stream->r->server->server_hostname;
        }
        if (ap_is_default_port(port, stream->r)) {
            portstr[0] = '\0';
        }
        else {
            apr_snprintf(portstr, sizeof(portstr), ":%d", port);
        }

        /* create a "Via:" response header entry and merge it */
        apr_table_addn(r->headers_out, "Via",
                       (session->conf->viaopt == via_full)
                       ? apr_psprintf(p, "%d.%d %s%s (%s)",
                                      HTTP_VERSION_MAJOR(r->proto_num),
                                      HTTP_VERSION_MINOR(r->proto_num),
                                      server_name, portstr,
                                      AP_SERVER_BASEVERSION)
                       : apr_psprintf(p, "%d.%d %s%s",
                                      HTTP_VERSION_MAJOR(r->proto_num),
                                      HTTP_VERSION_MINOR(r->proto_num),
                                      server_name, portstr)
                       );
    }
    
    if (APLOGrtrace2(stream->r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, stream->r, 
                      "h2_proxy_stream(%s-%d), header_out after merging", 
                      stream->session->id, stream->id);
        apr_table_do(log_header, stream, stream->r->headers_out, NULL);
    }
}

static int stream_response_data(nghttp2_session *ngh2, uint8_t flags,
                                int32_t stream_id, const uint8_t *data,
                                size_t len, void *user_data) 
{
    h2_proxy_session *session = user_data;
    h2_proxy_stream *stream;
    apr_bucket *b;
    apr_status_t status;
    
    stream = nghttp2_session_get_stream_user_data(ngh2, stream_id);
    if (!stream) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03358)
                     "h2_proxy_session(%s): recv data chunk for "
                     "unknown stream %d, ignored", 
                     session->id, stream_id);
        return 0;
    }
    
    if (!stream->data_received) {
        /* last chance to manipulate response headers.
         * after this, only trailers */
        h2_proxy_stream_end_headers_out(stream);
    }
    stream->data_received += len;
    
    b = apr_bucket_transient_create((const char*)data, len, 
                                    stream->r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(stream->output, b);
    /* always flush after a DATA frame, as we have no other indication
     * of buffer use */
    b = apr_bucket_flush_create(stream->r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(stream->output, b);
    
    status = ap_pass_brigade(stream->r->output_filters, stream->output);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, stream->r, APLOGNO(03359)
                  "h2_proxy_session(%s): stream=%d, response DATA %ld, %ld"
                  " total", session->id, stream_id, (long)len,
                  (long)stream->data_received);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, APLOGNO(03344)
                      "h2_proxy_session(%s): passing output on stream %d", 
                      session->id, stream->id);
        nghttp2_submit_rst_stream(ngh2, NGHTTP2_FLAG_NONE,
                                  stream_id, NGHTTP2_STREAM_CLOSED);
        return NGHTTP2_ERR_STREAM_CLOSING;
    }
    if (stream->standalone) {
        nghttp2_session_consume(ngh2, stream_id, len);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, stream->r,
                      "h2_proxy_session(%s): stream %d, win_update %d bytes",
                      session->id, stream_id, (int)len);
    }
    return 0;
}

static int on_stream_close(nghttp2_session *ngh2, int32_t stream_id,
                           uint32_t error_code, void *user_data) 
{
    h2_proxy_session *session = user_data;
    h2_proxy_stream *stream;
    if (!session->aborted) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03360)
                      "h2_proxy_session(%s): stream=%d, closed, err=%d", 
                      session->id, stream_id, error_code);
        stream = h2_proxy_ihash_get(session->streams, stream_id);
        if (stream) {
            stream->error_code = error_code;
        }
        dispatch_event(session, H2_PROXYS_EV_STREAM_DONE, stream_id, NULL);
    }
    return 0;
}

static int on_header(nghttp2_session *ngh2, const nghttp2_frame *frame,
                     const uint8_t *namearg, size_t nlen,
                     const uint8_t *valuearg, size_t vlen, uint8_t flags,
                     void *user_data) 
{
    h2_proxy_session *session = user_data;
    h2_proxy_stream *stream;
    const char *n = (const char*)namearg;
    const char *v = (const char*)valuearg;
    
    (void)session;
    if (frame->hd.type == NGHTTP2_HEADERS && nlen) {
        stream = nghttp2_session_get_stream_user_data(ngh2, frame->hd.stream_id);
        if (stream) {
            if (h2_proxy_stream_add_header_out(stream, n, nlen, v, vlen)) {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
        }
    }
    else if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
    }
    
    return 0;
}

static ssize_t stream_request_data(nghttp2_session *ngh2, int32_t stream_id, 
                                   uint8_t *buf, size_t length,
                                   uint32_t *data_flags, 
                                   nghttp2_data_source *source, void *user_data)
{
    h2_proxy_stream *stream;
    apr_status_t status = APR_SUCCESS;
    
    *data_flags = 0;
    stream = nghttp2_session_get_stream_user_data(ngh2, stream_id);
    if (!stream) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03361)
                     "h2_proxy_stream(%s): data_read, stream %d not found", 
                     stream->session->id, stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (stream->session->check_ping) {
        /* suspend until we hear from the other side */
        stream->waiting_on_ping = 1;
        status = APR_EAGAIN;
    }
    else if (stream->r->expecting_100) {
        /* suspend until the answer comes */
        stream->waiting_on_100 = 1;
        status = APR_EAGAIN;
    }
    else if (APR_BRIGADE_EMPTY(stream->input)) {
        status = ap_get_brigade(stream->r->input_filters, stream->input,
                                AP_MODE_READBYTES, APR_NONBLOCK_READ,
                                H2MAX(APR_BUCKET_BUFF_SIZE, length));
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, status, stream->r, 
                      "h2_proxy_stream(%s-%d): request body read", 
                      stream->session->id, stream->id);
    }

    if (status == APR_SUCCESS) {
        ssize_t readlen = 0;
        while (status == APR_SUCCESS 
               && (readlen < length)
               && !APR_BRIGADE_EMPTY(stream->input)) {
            apr_bucket* b = APR_BRIGADE_FIRST(stream->input);
            if (APR_BUCKET_IS_METADATA(b)) {
                if (APR_BUCKET_IS_EOS(b)) {
                    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                }
                else {
                    /* we do nothing more regarding any meta here */
                }
            }
            else {
                const char *bdata = NULL;
                apr_size_t blen = 0;
                status = apr_bucket_read(b, &bdata, &blen, APR_BLOCK_READ);
                
                if (status == APR_SUCCESS && blen > 0) {
                    ssize_t copylen = H2MIN(length - readlen, blen);
                    memcpy(buf, bdata, copylen);
                    buf += copylen;
                    readlen += copylen;
                    if (copylen < blen) {
                        /* We have data left in the bucket. Split it. */
                        status = apr_bucket_split(b, copylen);
                    }
                }
            }
            apr_bucket_delete(b);
        }

        stream->data_sent += readlen;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, stream->r, APLOGNO(03468) 
                      "h2_proxy_stream(%d): request DATA %ld, %ld"
                      " total, flags=%d", 
                      stream->id, (long)readlen, (long)stream->data_sent,
                      (int)*data_flags);
        return readlen;
    }
    else if (APR_STATUS_IS_EAGAIN(status)) {
        /* suspended stream, needs to be re-awakened */
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, status, stream->r, 
                      "h2_proxy_stream(%s-%d): suspending", 
                      stream->session->id, stream_id);
        stream->suspended = 1;
        h2_proxy_iq_add(stream->session->suspended, stream->id, NULL, NULL);
        return NGHTTP2_ERR_DEFERRED;
    }
    else {
        nghttp2_submit_rst_stream(ngh2, NGHTTP2_FLAG_NONE, 
                                  stream_id, NGHTTP2_STREAM_CLOSED);
        return NGHTTP2_ERR_STREAM_CLOSING;
    }
}

#ifdef H2_NG2_INVALID_HEADER_CB
static int on_invalid_header_cb(nghttp2_session *ngh2, 
                                const nghttp2_frame *frame, 
                                const uint8_t *name, size_t namelen, 
                                const uint8_t *value, size_t valuelen, 
                                uint8_t flags, void *user_data)
{
    h2_proxy_session *session = user_data;
    if (APLOGcdebug(session->c)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03469)
                      "h2_proxy_session(%s-%d): denying stream with invalid header "
                      "'%s: %s'", session->id, (int)frame->hd.stream_id,
                      apr_pstrndup(session->pool, (const char *)name, namelen),
                      apr_pstrndup(session->pool, (const char *)value, valuelen));
    }
    return nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE,
                                     frame->hd.stream_id, 
                                     NGHTTP2_PROTOCOL_ERROR);
}
#endif

h2_proxy_session *h2_proxy_session_setup(const char *id, proxy_conn_rec *p_conn,
                                         proxy_server_conf *conf,
                                         int h2_front, 
                                         unsigned char window_bits_connection,
                                         unsigned char window_bits_stream,
                                         h2_proxy_request_done *done)
{
    if (!p_conn->data) {
        apr_pool_t *pool = p_conn->scpool;
        h2_proxy_session *session;
        nghttp2_session_callbacks *cbs;
        nghttp2_option *option;

        session = apr_pcalloc(pool, sizeof(*session));
        apr_pool_pre_cleanup_register(pool, p_conn, proxy_session_pre_close);
        p_conn->data = session;
        
        session->id = apr_pstrdup(p_conn->scpool, id);
        session->c = p_conn->connection;
        session->p_conn = p_conn;
        session->conf = conf;
        session->pool = p_conn->scpool;
        session->state = H2_PROXYS_ST_INIT;
        session->h2_front = h2_front;
        session->window_bits_stream = window_bits_stream;
        session->window_bits_connection = window_bits_connection;
        session->streams = h2_proxy_ihash_create(pool, offsetof(h2_proxy_stream, id));
        session->suspended = h2_proxy_iq_create(pool, 5);
        session->done = done;
    
        session->input = apr_brigade_create(session->pool, session->c->bucket_alloc);
        session->output = apr_brigade_create(session->pool, session->c->bucket_alloc);
    
        nghttp2_session_callbacks_new(&cbs);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, stream_response_data);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close);
        nghttp2_session_callbacks_set_on_header_callback(cbs, on_header);
        nghttp2_session_callbacks_set_before_frame_send_callback(cbs, before_frame_send);
        nghttp2_session_callbacks_set_send_callback(cbs, raw_send);
#ifdef H2_NG2_INVALID_HEADER_CB
        nghttp2_session_callbacks_set_on_invalid_header_callback(cbs, on_invalid_header_cb);
#endif
        
        nghttp2_option_new(&option);
        nghttp2_option_set_peer_max_concurrent_streams(option, 100);
        nghttp2_option_set_no_auto_window_update(option, 1);
        
        nghttp2_session_client_new2(&session->ngh2, cbs, session, option);
        
        nghttp2_option_del(option);
        nghttp2_session_callbacks_del(cbs);

        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03362)
                      "setup session for %s", p_conn->hostname);
    }
    else {
        h2_proxy_session *session = p_conn->data;
        apr_interval_time_t age = apr_time_now() - session->last_frame_received;
        if (age > apr_time_from_sec(1)) {
            session->check_ping = 1;
            nghttp2_submit_ping(session->ngh2, 0, (const uint8_t *)"nevergonnagiveyouup");
        }
    }
    return p_conn->data;
}

static apr_status_t session_start(h2_proxy_session *session) 
{
    nghttp2_settings_entry settings[2];
    int rv, add_conn_window;
    apr_socket_t *s;
    
    s = ap_get_conn_socket(session->c);
#if (!defined(WIN32) && !defined(NETWARE)) || defined(DOXYGEN)
    if (s) {
        ap_sock_disable_nagle(s);
    }
#endif
    
    settings[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
    settings[0].value = 0;
    settings[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
    settings[1].value = (1 << session->window_bits_stream) - 1;
    
    rv = nghttp2_submit_settings(session->ngh2, NGHTTP2_FLAG_NONE, settings, 
                                 H2_ALEN(settings));
    
    /* If the connection window is larger than our default, trigger a WINDOW_UPDATE */
    add_conn_window = ((1 << session->window_bits_connection) - 1 -
                       NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE);
    if (!rv && add_conn_window != 0) {
        rv = nghttp2_submit_window_update(session->ngh2, NGHTTP2_FLAG_NONE, 0, add_conn_window);
    }
    return rv? APR_EGENERAL : APR_SUCCESS;
}

static apr_status_t open_stream(h2_proxy_session *session, const char *url,
                                request_rec *r, int standalone,
                                h2_proxy_stream **pstream)
{
    h2_proxy_stream *stream;
    apr_uri_t puri;
    const char *authority, *scheme, *path;
    apr_status_t status;

    stream = apr_pcalloc(r->pool, sizeof(*stream));

    stream->pool = r->pool;
    stream->url = url;
    stream->r = r;
    stream->standalone = standalone;
    stream->session = session;
    stream->state = H2_STREAM_ST_IDLE;
    
    stream->input = apr_brigade_create(stream->pool, session->c->bucket_alloc);
    stream->output = apr_brigade_create(stream->pool, session->c->bucket_alloc);
    
    stream->req = h2_proxy_req_create(1, stream->pool, 0);

    status = apr_uri_parse(stream->pool, url, &puri);
    if (status != APR_SUCCESS)
        return status;

    scheme = (strcmp(puri.scheme, "h2")? "http" : "https");
    authority = puri.hostname;
    if (!ap_strchr_c(authority, ':') && puri.port
        && apr_uri_port_of_scheme(scheme) != puri.port) {
        /* port info missing and port is not default for scheme: append */
        authority = apr_psprintf(stream->pool, "%s:%d", authority, puri.port);
    }
    /* we need this for mapping relative uris in headers ("Link") back
     * to local uris */
    stream->real_server_uri = apr_psprintf(stream->pool, "%s://%s", scheme, authority); 
    stream->p_server_uri = apr_psprintf(stream->pool, "%s://%s", puri.scheme, authority); 
    path = apr_uri_unparse(stream->pool, &puri, APR_URI_UNP_OMITSITEPART);
    h2_proxy_req_make(stream->req, stream->pool, r->method, scheme,
                authority, path, r->headers_in);

    /* Tuck away all already existing cookies */
    stream->saves = apr_table_make(r->pool, 2);
    apr_table_do(add_header, stream->saves, r->headers_out, "Set-Cookie", NULL);

    *pstream = stream;
    
    return APR_SUCCESS;
}

static apr_status_t submit_stream(h2_proxy_session *session, h2_proxy_stream *stream)
{
    h2_proxy_ngheader *hd;
    nghttp2_data_provider *pp = NULL;
    nghttp2_data_provider provider;
    int rv, may_have_request_body = 1;
    apr_status_t status;

    hd = h2_proxy_util_nghd_make_req(stream->pool, stream->req);
    
    /* If we expect a 100-continue response, we must refrain from reading
       any input until we get it. Reading the input will possibly trigger
       HTTP_IN filter to generate the 100-continue itself. */
    if (stream->waiting_on_100 || stream->waiting_on_ping) {
        /* make a small test if we get an EOF/EOS immediately */
        status = ap_get_brigade(stream->r->input_filters, stream->input,
                                AP_MODE_READBYTES, APR_NONBLOCK_READ,
                                APR_BUCKET_BUFF_SIZE);
        may_have_request_body = APR_STATUS_IS_EAGAIN(status)
                                || (status == APR_SUCCESS 
                                    && !APR_BUCKET_IS_EOS(APR_BRIGADE_FIRST(stream->input)));
    }
    
    if (may_have_request_body) {
        provider.source.fd = 0;
        provider.source.ptr = NULL;
        provider.read_callback = stream_request_data;
        pp = &provider;
    }

    rv = nghttp2_submit_request(session->ngh2, NULL, 
                                hd->nv, hd->nvlen, pp, stream);
                                
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03363)
                  "h2_proxy_session(%s): submit %s%s -> %d", 
                  session->id, stream->req->authority, stream->req->path,
                  rv);
    if (rv > 0) {
        stream->id = rv;
        stream->state = H2_STREAM_ST_OPEN;
        h2_proxy_ihash_add(session->streams, stream);
        dispatch_event(session, H2_PROXYS_EV_STREAM_SUBMITTED, rv, NULL);
        
        return APR_SUCCESS;
    }
    return APR_EGENERAL;
}

static apr_status_t feed_brigade(h2_proxy_session *session, apr_bucket_brigade *bb)
{
    apr_status_t status = APR_SUCCESS;
    apr_size_t readlen = 0;
    ssize_t n;
    
    while (status == APR_SUCCESS && !APR_BRIGADE_EMPTY(bb)) {
        apr_bucket* b = APR_BRIGADE_FIRST(bb);
        
        if (APR_BUCKET_IS_METADATA(b)) {
            /* nop */
        }
        else {
            const char *bdata = NULL;
            apr_size_t blen = 0;
            
            status = apr_bucket_read(b, &bdata, &blen, APR_BLOCK_READ);
            if (status == APR_SUCCESS && blen > 0) {
                n = nghttp2_session_mem_recv(session->ngh2, (const uint8_t *)bdata, blen);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c, 
                              "h2_proxy_session(%s): feeding %ld bytes -> %ld", 
                              session->id, (long)blen, (long)n);
                if (n < 0) {
                    if (nghttp2_is_fatal((int)n)) {
                        status = APR_EGENERAL;
                    }
                }
                else {
                    readlen += n;
                    if (n < blen) {
                        apr_bucket_split(b, n);
                    }
                }
            }
        }
        apr_bucket_delete(b);
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c, 
                  "h2_proxy_session(%s): fed %ld bytes of input to session", 
                  session->id, (long)readlen);
    if (readlen == 0 && status == APR_SUCCESS) {
        return APR_EAGAIN;
    }
    return status;
}

static apr_status_t h2_proxy_session_read(h2_proxy_session *session, int block, 
                                          apr_interval_time_t timeout)
{
    apr_status_t status = APR_SUCCESS;
    
    if (APR_BRIGADE_EMPTY(session->input)) {
        apr_socket_t *socket = NULL;
        apr_time_t save_timeout = -1;
        
        if (block) {
            socket = ap_get_conn_socket(session->c);
            if (socket) {
                apr_socket_timeout_get(socket, &save_timeout);
                apr_socket_timeout_set(socket, timeout);
            }
            else {
                /* cannot block on timeout */
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, session->c, APLOGNO(03379)
                              "h2_proxy_session(%s): unable to get conn socket", 
                              session->id);
                return APR_ENOTIMPL;
            }
        }
        
        status = ap_get_brigade(session->c->input_filters, session->input, 
                                AP_MODE_READBYTES, 
                                block? APR_BLOCK_READ : APR_NONBLOCK_READ, 
                                64 * 1024);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, session->c, 
                      "h2_proxy_session(%s): read from conn", session->id);
        if (socket && save_timeout != -1) {
            apr_socket_timeout_set(socket, save_timeout);
        }
    }
    
    if (status == APR_SUCCESS) {
        status = feed_brigade(session, session->input);
    }
    else if (APR_STATUS_IS_TIMEUP(status)) {
        /* nop */
    }
    else if (!APR_STATUS_IS_EAGAIN(status)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, APLOGNO(03380)
                      "h2_proxy_session(%s): read error", session->id);
        dispatch_event(session, H2_PROXYS_EV_CONN_ERROR, status, NULL);
    }

    return status;
}

apr_status_t h2_proxy_session_submit(h2_proxy_session *session, 
                                     const char *url, request_rec *r,
                                     int standalone)
{
    h2_proxy_stream *stream;
    apr_status_t status;
    
    status = open_stream(session, url, r, standalone, &stream);
    if (status == APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03381)
                      "process stream(%d): %s %s%s, original: %s", 
                      stream->id, stream->req->method, 
                      stream->req->authority, stream->req->path, 
                      r->the_request);
        status = submit_stream(session, stream);
    }
    return status;
}

static void stream_resume(h2_proxy_stream *stream)
{
    h2_proxy_session *session = stream->session;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c, 
                  "h2_proxy_stream(%s-%d): resuming", 
                  session->id, stream->id);
    stream->suspended = 0;
    h2_proxy_iq_remove(session->suspended, stream->id);
    nghttp2_session_resume_data(session->ngh2, stream->id);
    dispatch_event(session, H2_PROXYS_EV_STREAM_RESUMED, 0, NULL);
}

static apr_status_t check_suspended(h2_proxy_session *session)
{
    h2_proxy_stream *stream;
    int i, stream_id;
    apr_status_t status;
    
    for (i = 0; i < session->suspended->nelts; ++i) {
        stream_id = session->suspended->elts[i];
        stream = nghttp2_session_get_stream_user_data(session->ngh2, stream_id);
        if (stream) {
            if (stream->waiting_on_100 || stream->waiting_on_ping) {
                status = APR_EAGAIN;
            }
            else {
                status = ap_get_brigade(stream->r->input_filters, stream->input,
                                        AP_MODE_READBYTES, APR_NONBLOCK_READ,
                                        APR_BUCKET_BUFF_SIZE);
            }
            if (status == APR_SUCCESS && !APR_BRIGADE_EMPTY(stream->input)) {
                stream_resume(stream);
                check_suspended(session);
                return APR_SUCCESS;
            }
            else if (status != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(status)) {
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, status, session->c, 
                              APLOGNO(03382) "h2_proxy_stream(%s-%d): check input", 
                              session->id, stream_id);
                stream_resume(stream);
                check_suspended(session);
                return APR_SUCCESS;
            }
        }
        else {
            /* gone? */
            h2_proxy_iq_remove(session->suspended, stream_id);
            check_suspended(session);
            return APR_SUCCESS;
        }
    }
    return APR_EAGAIN;
}

static apr_status_t session_shutdown(h2_proxy_session *session, int reason, 
                                     const char *msg)
{
    apr_status_t status = APR_SUCCESS;
    const char *err = msg;
    
    ap_assert(session);
    if (!err && reason) {
        err = nghttp2_strerror(reason);
    }
    nghttp2_submit_goaway(session->ngh2, NGHTTP2_FLAG_NONE, 0, 
                          reason, (uint8_t*)err, err? strlen(err):0);
    status = nghttp2_session_send(session->ngh2);
    dispatch_event(session, H2_PROXYS_EV_LOCAL_GOAWAY, reason, err);
    return status;
}


static const char *StateNames[] = {
    "INIT",      /* H2_PROXYS_ST_INIT */
    "DONE",      /* H2_PROXYS_ST_DONE */
    "IDLE",      /* H2_PROXYS_ST_IDLE */
    "BUSY",      /* H2_PROXYS_ST_BUSY */
    "WAIT",      /* H2_PROXYS_ST_WAIT */
    "LSHUTDOWN", /* H2_PROXYS_ST_LOCAL_SHUTDOWN */
    "RSHUTDOWN", /* H2_PROXYS_ST_REMOTE_SHUTDOWN */
};

static const char *state_name(h2_proxys_state state)
{
    if (state >= (sizeof(StateNames)/sizeof(StateNames[0]))) {
        return "unknown";
    }
    return StateNames[state];
}

static int is_accepting_streams(h2_proxy_session *session)
{
    switch (session->state) {
        case H2_PROXYS_ST_IDLE:
        case H2_PROXYS_ST_BUSY:
        case H2_PROXYS_ST_WAIT:
            return 1;
        default:
            return 0;
    }
}

static void transit(h2_proxy_session *session, const char *action, 
                    h2_proxys_state nstate)
{
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03345)
                  "h2_proxy_session(%s): transit [%s] -- %s --> [%s]", session->id,
                  state_name(session->state), action, state_name(nstate));
    session->state = nstate;
}

static void ev_init(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_INIT:
            if (h2_proxy_ihash_empty(session->streams)) {
                transit(session, "init", H2_PROXYS_ST_IDLE);
            }
            else {
                transit(session, "init", H2_PROXYS_ST_BUSY);
            }
            break;

        default:
            /* nop */
            break;
    }
}

static void ev_local_goaway(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_LOCAL_SHUTDOWN:
            /* already did that? */
            break;
        case H2_PROXYS_ST_IDLE:
        case H2_PROXYS_ST_REMOTE_SHUTDOWN:
            /* all done */
            transit(session, "local goaway", H2_PROXYS_ST_DONE);
            break;
        default:
            transit(session, "local goaway", H2_PROXYS_ST_LOCAL_SHUTDOWN);
            break;
    }
}

static void ev_remote_goaway(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_REMOTE_SHUTDOWN:
            /* already received that? */
            break;
        case H2_PROXYS_ST_IDLE:
        case H2_PROXYS_ST_LOCAL_SHUTDOWN:
            /* all done */
            transit(session, "remote goaway", H2_PROXYS_ST_DONE);
            break;
        default:
            transit(session, "remote goaway", H2_PROXYS_ST_REMOTE_SHUTDOWN);
            break;
    }
}

static void ev_conn_error(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_INIT:
        case H2_PROXYS_ST_DONE:
        case H2_PROXYS_ST_LOCAL_SHUTDOWN:
            /* just leave */
            transit(session, "conn error", H2_PROXYS_ST_DONE);
            break;
        
        default:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, arg, session->c,
                          "h2_proxy_session(%s): conn error -> shutdown", session->id);
            session_shutdown(session, arg, msg);
            break;
    }
}

static void ev_proto_error(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_DONE:
        case H2_PROXYS_ST_LOCAL_SHUTDOWN:
            /* just leave */
            transit(session, "proto error", H2_PROXYS_ST_DONE);
            break;
        
        default:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                          "h2_proxy_session(%s): proto error -> shutdown", session->id);
            session_shutdown(session, arg, msg);
            break;
    }
}

static void ev_conn_timeout(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_LOCAL_SHUTDOWN:
            transit(session, "conn timeout", H2_PROXYS_ST_DONE);
            break;
        default:
            session_shutdown(session, arg, msg);
            transit(session, "conn timeout", H2_PROXYS_ST_DONE);
            break;
    }
}

static void ev_no_io(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_BUSY:
        case H2_PROXYS_ST_LOCAL_SHUTDOWN:
        case H2_PROXYS_ST_REMOTE_SHUTDOWN:
            /* nothing for input and output to do. If we remain
             * in this state, we go into a tight loop and suck up
             * CPU cycles. Ideally, we'd like to do a blocking read, but that
             * is not possible if we have scheduled tasks and wait
             * for them to produce something. */
            if (h2_proxy_ihash_empty(session->streams)) {
                if (!is_accepting_streams(session)) {
                    /* We are no longer accepting new streams and have
                     * finished processing existing ones. Time to leave. */
                    session_shutdown(session, arg, msg);
                    transit(session, "no io", H2_PROXYS_ST_DONE);
                }
                else {
                    /* When we have no streams, no task events are possible,
                     * switch to blocking reads */
                    transit(session, "no io", H2_PROXYS_ST_IDLE);
                }
            }
            else {
                /* Unable to do blocking reads, as we wait on events from
                 * task processing in other threads. Do a busy wait with
                 * backoff timer. */
                transit(session, "no io", H2_PROXYS_ST_WAIT);
            }
            break;
        default:
            /* nop */
            break;
    }
}

static void ev_stream_submitted(h2_proxy_session *session, int stream_id, 
                                const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_IDLE:
        case H2_PROXYS_ST_WAIT:
            transit(session, "stream submitted", H2_PROXYS_ST_BUSY);
            break;
        default:
            /* nop */
            break;
    }
}

static void ev_stream_done(h2_proxy_session *session, int stream_id, 
                           const char *msg)
{
    h2_proxy_stream *stream;
    
    stream = nghttp2_session_get_stream_user_data(session->ngh2, stream_id);
    if (stream) {
        int touched = (stream->data_sent || 
                       stream_id <= session->last_stream_id);
        apr_status_t status = (stream->error_code == 0)? APR_SUCCESS : APR_EINVAL;
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03364)
                      "h2_proxy_sesssion(%s): stream(%d) closed "
                      "(touched=%d, error=%d)", 
                      session->id, stream_id, touched, stream->error_code);
        
        if (status != APR_SUCCESS) {
            stream->r->status = 500;
        }
        else if (!stream->data_received) {
            apr_bucket *b;
            /* if the response had no body, this is the time to flush
             * an empty brigade which will also write the resonse
             * headers */
            h2_proxy_stream_end_headers_out(stream);
            stream->data_received = 1;
            b = apr_bucket_flush_create(stream->r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(stream->output, b);
            b = apr_bucket_eos_create(stream->r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(stream->output, b);
            ap_pass_brigade(stream->r->output_filters, stream->output);
        }
        
        stream->state = H2_STREAM_ST_CLOSED;
        h2_proxy_ihash_remove(session->streams, stream_id);
        h2_proxy_iq_remove(session->suspended, stream_id);
        if (session->done) {
            session->done(session, stream->r, status, touched);
        }
    }
    
    switch (session->state) {
        default:
            /* nop */
            break;
    }
}

static void ev_stream_resumed(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_WAIT:
            transit(session, "stream resumed", H2_PROXYS_ST_BUSY);
            break;
        default:
            /* nop */
            break;
    }
}

static void ev_data_read(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_IDLE:
        case H2_PROXYS_ST_WAIT:
            transit(session, "data read", H2_PROXYS_ST_BUSY);
            break;
        default:
            /* nop */
            break;
    }
}

static void ev_ngh2_done(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_DONE:
            /* nop */
            break;
        default:
            transit(session, "nghttp2 done", H2_PROXYS_ST_DONE);
            break;
    }
}

static void ev_pre_close(h2_proxy_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_PROXYS_ST_DONE:
        case H2_PROXYS_ST_LOCAL_SHUTDOWN:
            /* nop */
            break;
        default:
            session_shutdown(session, arg, msg);
            break;
    }
}

static void dispatch_event(h2_proxy_session *session, h2_proxys_event_t ev, 
                           int arg, const char *msg)
{
    switch (ev) {
        case H2_PROXYS_EV_INIT:
            ev_init(session, arg, msg);
            break;            
        case H2_PROXYS_EV_LOCAL_GOAWAY:
            ev_local_goaway(session, arg, msg);
            break;
        case H2_PROXYS_EV_REMOTE_GOAWAY:
            ev_remote_goaway(session, arg, msg);
            break;
        case H2_PROXYS_EV_CONN_ERROR:
            ev_conn_error(session, arg, msg);
            break;
        case H2_PROXYS_EV_PROTO_ERROR:
            ev_proto_error(session, arg, msg);
            break;
        case H2_PROXYS_EV_CONN_TIMEOUT:
            ev_conn_timeout(session, arg, msg);
            break;
        case H2_PROXYS_EV_NO_IO:
            ev_no_io(session, arg, msg);
            break;
        case H2_PROXYS_EV_STREAM_SUBMITTED:
            ev_stream_submitted(session, arg, msg);
            break;
        case H2_PROXYS_EV_STREAM_DONE:
            ev_stream_done(session, arg, msg);
            break;
        case H2_PROXYS_EV_STREAM_RESUMED:
            ev_stream_resumed(session, arg, msg);
            break;
        case H2_PROXYS_EV_DATA_READ:
            ev_data_read(session, arg, msg);
            break;
        case H2_PROXYS_EV_NGH2_DONE:
            ev_ngh2_done(session, arg, msg);
            break;
        case H2_PROXYS_EV_PRE_CLOSE:
            ev_pre_close(session, arg, msg);
            break;
        default:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                          "h2_proxy_session(%s): unknown event %d", 
                          session->id, ev);
            break;
    }
}

static int send_loop(h2_proxy_session *session)
{
    while (nghttp2_session_want_write(session->ngh2)) {
        int rv = nghttp2_session_send(session->ngh2);
        if (rv < 0 && nghttp2_is_fatal(rv)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c, 
                          "h2_proxy_session(%s): write, rv=%d", session->id, rv);
            dispatch_event(session, H2_PROXYS_EV_CONN_ERROR, rv, NULL);
            break;
        }
        return 1;
    }
    return 0;
}

apr_status_t h2_proxy_session_process(h2_proxy_session *session)
{
    apr_status_t status;
    int have_written = 0, have_read = 0;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c, 
                  "h2_proxy_session(%s): process", session->id);
           
run_loop:
    switch (session->state) {
        case H2_PROXYS_ST_INIT:
            status = session_start(session);
            if (status == APR_SUCCESS) {
                dispatch_event(session, H2_PROXYS_EV_INIT, 0, NULL);
                goto run_loop;
            }
            else {
                dispatch_event(session, H2_PROXYS_EV_CONN_ERROR, status, NULL);
            }
            break;
            
        case H2_PROXYS_ST_BUSY:
        case H2_PROXYS_ST_LOCAL_SHUTDOWN:
        case H2_PROXYS_ST_REMOTE_SHUTDOWN:
            have_written = send_loop(session);
            
            if (nghttp2_session_want_read(session->ngh2)) {
                status = h2_proxy_session_read(session, 0, 0);
                if (status == APR_SUCCESS) {
                    have_read = 1;
                }
            }
            
            if (!have_written && !have_read 
                && !nghttp2_session_want_write(session->ngh2)) {
                dispatch_event(session, H2_PROXYS_EV_NO_IO, 0, NULL);
                goto run_loop;
            }
            break;
            
        case H2_PROXYS_ST_WAIT:
            if (check_suspended(session) == APR_EAGAIN) {
                /* no stream has become resumed. Do a blocking read with
                 * ever increasing timeouts... */
                if (session->wait_timeout < 25) {
                    session->wait_timeout = 25;
                }
                else {
                    session->wait_timeout = H2MIN(apr_time_from_msec(100), 
                                                  2*session->wait_timeout);
                }
                
                status = h2_proxy_session_read(session, 1, session->wait_timeout);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, session->c, 
                              APLOGNO(03365)
                              "h2_proxy_session(%s): WAIT read, timeout=%fms", 
                              session->id, (float)session->wait_timeout/1000.0);
                if (status == APR_SUCCESS) {
                    have_read = 1;
                    dispatch_event(session, H2_PROXYS_EV_DATA_READ, 0, NULL);
                }
                else if (APR_STATUS_IS_TIMEUP(status)
                    || APR_STATUS_IS_EAGAIN(status)) {
                    /* go back to checking all inputs again */
                    transit(session, "wait cycle", H2_PROXYS_ST_BUSY);
                }
            }
            break;
            
        case H2_PROXYS_ST_IDLE:
            break;

        case H2_PROXYS_ST_DONE: /* done, session terminated */
            return APR_EOF;
            
        default:
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, session->c,
                          APLOGNO(03346)"h2_proxy_session(%s): unknown state %d", 
                          session->id, session->state);
            dispatch_event(session, H2_PROXYS_EV_PROTO_ERROR, 0, NULL);
            break;
    }


    if (have_read || have_written) {
        session->wait_timeout = 0;
    }
    
    if (!nghttp2_session_want_read(session->ngh2)
        && !nghttp2_session_want_write(session->ngh2)) {
        dispatch_event(session, H2_PROXYS_EV_NGH2_DONE, 0, NULL);
    }
    
    return APR_SUCCESS; /* needs to be called again */
}

typedef struct {
    h2_proxy_session *session;
    h2_proxy_request_done *done;
} cleanup_iter_ctx;

static int cancel_iter(void *udata, void *val)
{
    cleanup_iter_ctx *ctx = udata;
    h2_proxy_stream *stream = val;
    nghttp2_submit_rst_stream(ctx->session->ngh2, NGHTTP2_FLAG_NONE,
                              stream->id, 0);
    return 1;
}

void h2_proxy_session_cancel_all(h2_proxy_session *session)
{
    if (!h2_proxy_ihash_empty(session->streams)) {
        cleanup_iter_ctx ctx;
        ctx.session = session;
        ctx.done = session->done;
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03366)
                      "h2_proxy_session(%s): cancel  %d streams",
                      session->id, (int)h2_proxy_ihash_count(session->streams));
        h2_proxy_ihash_iter(session->streams, cancel_iter, &ctx);
        session_shutdown(session, 0, NULL);
    }
}

static int done_iter(void *udata, void *val)
{
    cleanup_iter_ctx *ctx = udata;
    h2_proxy_stream *stream = val;
    int touched = (stream->data_sent || 
                   stream->id <= ctx->session->last_stream_id);
    ctx->done(ctx->session, stream->r, APR_ECONNABORTED, touched);
    return 1;
}

void h2_proxy_session_cleanup(h2_proxy_session *session, 
                              h2_proxy_request_done *done)
{
    if (!h2_proxy_ihash_empty(session->streams)) {
        cleanup_iter_ctx ctx;
        ctx.session = session;
        ctx.done = done;
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03366)
                      "h2_proxy_session(%s): terminated, %d streams unfinished",
                      session->id, (int)h2_proxy_ihash_count(session->streams));
        h2_proxy_ihash_iter(session->streams, done_iter, &ctx);
        h2_proxy_ihash_clear(session->streams);
    }
}

static int ping_arrived_iter(void *udata, void *val)
{
    h2_proxy_stream *stream = val;
    if (stream->waiting_on_ping) {
        stream->waiting_on_ping = 0;
        stream_resume(stream);
    }
    return 1;
}

static void ping_arrived(h2_proxy_session *session)
{
    if (!h2_proxy_ihash_empty(session->streams)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03470)
                      "h2_proxy_session(%s): ping arrived, unblocking streams",
                      session->id);
        h2_proxy_ihash_iter(session->streams, ping_arrived_iter, &session);
    }
}

typedef struct {
    h2_proxy_session *session;
    conn_rec *c;
    apr_off_t bytes;
    int updated;
} win_update_ctx;

static int win_update_iter(void *udata, void *val)
{
    win_update_ctx *ctx = udata;
    h2_proxy_stream *stream = val;
    
    if (stream->r && stream->r->connection == ctx->c) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, ctx->session->c, 
                      "h2_proxy_session(%s-%d): win_update %ld bytes",
                      ctx->session->id, (int)stream->id, (long)ctx->bytes);
        nghttp2_session_consume(ctx->session->ngh2, stream->id, ctx->bytes);
        ctx->updated = 1;
        return 0;
    }
    return 1;
}


void h2_proxy_session_update_window(h2_proxy_session *session, 
                                    conn_rec *c, apr_off_t bytes)
{
    if (!h2_proxy_ihash_empty(session->streams)) {
        win_update_ctx ctx;
        ctx.session = session;
        ctx.c = c;
        ctx.bytes = bytes;
        ctx.updated = 0;
        h2_proxy_ihash_iter(session->streams, win_update_iter, &ctx);
        
        if (!ctx.updated) {
            /* could not find the stream any more, possibly closed, update
             * the connection window at least */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c, 
                          "h2_proxy_session(%s): win_update conn %ld bytes",
                          session->id, (long)bytes);
            nghttp2_session_consume_connection(session->ngh2, (size_t)bytes);
        }
    }
}

