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
 
#include <assert.h>
#include <stddef.h>
#include <apr_thread_cond.h>
#include <apr_base64.h>
#include <apr_strings.h>

#include <ap_mpm.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <scoreboard.h>

#include <mpm_common.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_bucket_beam.h"
#include "h2_bucket_eos.h"
#include "h2_config.h"
#include "h2_ctx.h"
#include "h2_filter.h"
#include "h2_h2.h"
#include "h2_mplx.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_headers.h"
#include "h2_stream.h"
#include "h2_task.h"
#include "h2_session.h"
#include "h2_util.h"
#include "h2_version.h"
#include "h2_workers.h"


static apr_status_t dispatch_master(h2_session *session);
static apr_status_t h2_session_read(h2_session *session, int block);
static void transit(h2_session *session, const char *action, 
                    h2_session_state nstate);

static void on_stream_state_enter(void *ctx, h2_stream *stream);
static void on_stream_state_event(void *ctx, h2_stream *stream, h2_stream_event_t ev);
static void on_stream_event(void *ctx, h2_stream *stream, h2_stream_event_t ev);

static int h2_session_status_from_apr_status(apr_status_t rv)
{
    if (rv == APR_SUCCESS) {
        return NGHTTP2_NO_ERROR;
    }
    else if (APR_STATUS_IS_EAGAIN(rv)) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    else if (APR_STATUS_IS_EOF(rv)) {
        return NGHTTP2_ERR_EOF;
    }
    return NGHTTP2_ERR_PROTO;
}

static h2_stream *get_stream(h2_session *session, int stream_id)
{
    return nghttp2_session_get_stream_user_data(session->ngh2, stream_id);
}

static void dispatch_event(h2_session *session, h2_session_event_t ev, 
                             int err, const char *msg);

void h2_session_event(h2_session *session, h2_session_event_t ev, 
                             int err, const char *msg)
{
    dispatch_event(session, ev, err, msg);
}

static int rst_unprocessed_stream(h2_stream *stream, void *ctx)
{
    int unprocessed = (!h2_stream_was_closed(stream)
                       && (H2_STREAM_CLIENT_INITIATED(stream->id)? 
                           (!stream->session->local.accepting
                            && stream->id > stream->session->local.accepted_max)
                            : 
                           (!stream->session->remote.accepting
                            && stream->id > stream->session->remote.accepted_max))
                       ); 
    if (unprocessed) {
        h2_stream_rst(stream, H2_ERR_NO_ERROR);
        return 0;
    }
    return 1;
}

static void cleanup_unprocessed_streams(h2_session *session)
{
    h2_mplx_m_stream_do(session->mplx, rst_unprocessed_stream, session);
}

static h2_stream *h2_session_open_stream(h2_session *session, int stream_id,
                                         int initiated_on)
{
    h2_stream * stream;
    apr_pool_t *stream_pool;
    
    apr_pool_create(&stream_pool, session->pool);
    apr_pool_tag(stream_pool, "h2_stream");
    
    stream = h2_stream_create(stream_id, stream_pool, session, 
                              session->monitor, initiated_on);
    if (stream) {
        nghttp2_session_set_stream_user_data(session->ngh2, stream_id, stream);
    }
    return stream;
}

/**
 * Determine the importance of streams when scheduling tasks.
 * - if both stream depend on the same one, compare weights
 * - if one stream is closer to the root, prioritize that one
 * - if both are on the same level, use the weight of their root
 *   level ancestors
 */
static int spri_cmp(int sid1, nghttp2_stream *s1, 
                    int sid2, nghttp2_stream *s2, h2_session *session)
{
    nghttp2_stream *p1, *p2;
    
    p1 = nghttp2_stream_get_parent(s1);
    p2 = nghttp2_stream_get_parent(s2);
    
    if (p1 == p2) {
        int32_t w1, w2;
        
        w1 = nghttp2_stream_get_weight(s1);
        w2 = nghttp2_stream_get_weight(s2);
        return w2 - w1;
    }
    else if (!p1) {
        /* stream 1 closer to root */
        return -1;
    }
    else if (!p2) {
        /* stream 2 closer to root */
        return 1;
    }
    return spri_cmp(sid1, p1, sid2, p2, session);
}

static int stream_pri_cmp(int sid1, int sid2, void *ctx)
{
    h2_session *session = ctx;
    nghttp2_stream *s1, *s2;
    
    s1 = nghttp2_session_find_stream(session->ngh2, sid1);
    s2 = nghttp2_session_find_stream(session->ngh2, sid2);

    if (s1 == s2) {
        return 0;
    }
    else if (!s1) {
        return 1;
    }
    else if (!s2) {
        return -1;
    }
    return spri_cmp(sid1, s1, sid2, s2, session);
}

/*
 * Callback when nghttp2 wants to send bytes back to the client.
 */
static ssize_t send_cb(nghttp2_session *ngh2,
                       const uint8_t *data, size_t length,
                       int flags, void *userp)
{
    h2_session *session = (h2_session *)userp;
    apr_status_t status;
    (void)ngh2;
    (void)flags;
    
    status = h2_conn_io_write(&session->io, (const char *)data, length);
    if (status == APR_SUCCESS) {
        return length;
    }
    if (APR_STATUS_IS_EAGAIN(status)) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, APLOGNO(03062)
                  "h2_session: send error");
    return h2_session_status_from_apr_status(status);
}

static int on_invalid_frame_recv_cb(nghttp2_session *ngh2,
                                    const nghttp2_frame *frame,
                                    int error, void *userp)
{
    h2_session *session = (h2_session *)userp;
    (void)ngh2;
    
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      H2_SSSN_LOG(APLOGNO(03063), session, 
                      "recv invalid FRAME[%s], frames=%ld/%ld (r/s)"),
                      buffer, (long)session->frames_received,
                     (long)session->frames_sent);
    }
    return 0;
}

static int on_data_chunk_recv_cb(nghttp2_session *ngh2, uint8_t flags,
                                 int32_t stream_id,
                                 const uint8_t *data, size_t len, void *userp)
{
    h2_session *session = (h2_session *)userp;
    apr_status_t status = APR_EINVAL;
    h2_stream * stream;
    int rv = 0;
    
    stream = get_stream(session, stream_id);
    if (stream) {
        status = h2_stream_recv_DATA(stream, flags, data, len);
        dispatch_event(session, H2_SESSION_EV_STREAM_CHANGE, 0, "stream data rcvd");
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03064)
                      "h2_stream(%ld-%d): on_data_chunk for unknown stream",
                      session->id, (int)stream_id);
        rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (status != APR_SUCCESS) {
        /* count this as consumed explicitly as no one will read it */
        nghttp2_session_consume(session->ngh2, stream_id, len);
    }
    return rv;
}

static int on_stream_close_cb(nghttp2_session *ngh2, int32_t stream_id,
                              uint32_t error_code, void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream *stream;
    
    (void)ngh2;
    stream = get_stream(session, stream_id);
    if (stream) {
        if (error_code) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                          H2_STRM_LOG(APLOGNO(03065), stream, 
                          "closing with err=%d %s"), 
                          (int)error_code, h2_h2_err_description(error_code));
            h2_stream_rst(stream, error_code);
        }
    }
    return 0;
}

static int on_begin_headers_cb(nghttp2_session *ngh2,
                               const nghttp2_frame *frame, void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream *s;
    
    /* We may see HEADERs at the start of a stream or after all DATA
     * streams to carry trailers. */
    (void)ngh2;
    s = get_stream(session, frame->hd.stream_id);
    if (s) {
        /* nop */
    }
    else {
        s = h2_session_open_stream(userp, frame->hd.stream_id, 0);
    }
    return s? 0 : NGHTTP2_ERR_START_STREAM_NOT_ALLOWED;
}

static int on_header_cb(nghttp2_session *ngh2, const nghttp2_frame *frame,
                        const uint8_t *name, size_t namelen,
                        const uint8_t *value, size_t valuelen,
                        uint8_t flags,
                        void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream * stream;
    apr_status_t status;
    
    (void)flags;
    stream = get_stream(session, frame->hd.stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(02920) 
                      "h2_stream(%ld-%d): on_header unknown stream",
                      session->id, (int)frame->hd.stream_id);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    
    status = h2_stream_add_header(stream, (const char *)name, namelen,
                                  (const char *)value, valuelen);
    if (status != APR_SUCCESS
        && (!stream->rtmp
            || stream->rtmp->http_status == H2_HTTP_STATUS_UNSET)) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    return 0;
}

/**
 * nghttp2 session has received a complete frame. Most are used by nghttp2
 * for processing of internal state. Some, like HEADER and DATA frames,
 * we need to act on.
 */
static int on_frame_recv_cb(nghttp2_session *ng2s,
                            const nghttp2_frame *frame,
                            void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream *stream;
    apr_status_t rv = APR_SUCCESS;
    
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      H2_SSSN_LOG(APLOGNO(03066), session, 
                      "recv FRAME[%s], frames=%ld/%ld (r/s)"),
                      buffer, (long)session->frames_received,
                     (long)session->frames_sent);
    }

    ++session->frames_received;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            /* This can be HEADERS for a new stream, defining the request,
             * or HEADER may come after DATA at the end of a stream as in
             * trailers */
            stream = get_stream(session, frame->hd.stream_id);
            if (stream) {
                rv = h2_stream_recv_frame(stream, NGHTTP2_HEADERS, frame->hd.flags, 
                    frame->hd.length + H2_FRAME_HDR_LEN);
            }
            break;
        case NGHTTP2_DATA:
            stream = get_stream(session, frame->hd.stream_id);
            if (stream) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,  
                              H2_STRM_LOG(APLOGNO(02923), stream, 
                              "DATA, len=%ld, flags=%d"), 
                              (long)frame->hd.length, frame->hd.flags);
                rv = h2_stream_recv_frame(stream, NGHTTP2_DATA, frame->hd.flags, 
                    frame->hd.length + H2_FRAME_HDR_LEN);
            }
            break;
        case NGHTTP2_PRIORITY:
            session->reprioritize = 1;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                          "h2_stream(%ld-%d): PRIORITY frame "
                          " weight=%d, dependsOn=%d, exclusive=%d", 
                          session->id, (int)frame->hd.stream_id,
                          frame->priority.pri_spec.weight,
                          frame->priority.pri_spec.stream_id,
                          frame->priority.pri_spec.exclusive);
            break;
        case NGHTTP2_WINDOW_UPDATE:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                          "h2_stream(%ld-%d): WINDOW_UPDATE incr=%d", 
                          session->id, (int)frame->hd.stream_id,
                          frame->window_update.window_size_increment);
            if (nghttp2_session_want_write(session->ngh2)) {
                dispatch_event(session, H2_SESSION_EV_FRAME_RCVD, 0, "window update");
            }
            break;
        case NGHTTP2_RST_STREAM:
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03067)
                          "h2_stream(%ld-%d): RST_STREAM by client, error=%d",
                          session->id, (int)frame->hd.stream_id,
                          (int)frame->rst_stream.error_code);
            stream = get_stream(session, frame->hd.stream_id);
            if (stream && stream->initiated_on) {
                /* A stream reset on a request we sent it. Normal, when the
                 * client does not want it. */
                ++session->pushes_reset;
            }
            else {
                /* A stream reset on a request it sent us. Could happen in a browser
                 * when the user navigates away or cancels loading - maybe. */
                h2_mplx_m_client_rst(session->mplx, frame->hd.stream_id);
                ++session->streams_reset;
            }
            break;
        case NGHTTP2_GOAWAY:
            if (frame->goaway.error_code == 0 
                && frame->goaway.last_stream_id == ((1u << 31) - 1)) {
                /* shutdown notice. Should not come from a client... */
                session->remote.accepting = 0;
            }
            else {
                session->remote.accepted_max = frame->goaway.last_stream_id;
                dispatch_event(session, H2_SESSION_EV_REMOTE_GOAWAY, 
                               frame->goaway.error_code, NULL);
            }
            break;
        case NGHTTP2_SETTINGS:
            if (APLOGctrace2(session->c)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                              H2_SSSN_MSG(session, "SETTINGS, len=%ld"), (long)frame->hd.length);
            }
            break;
        default:
            if (APLOGctrace2(session->c)) {
                char buffer[256];
                
                h2_util_frame_print(frame, buffer,
                                    sizeof(buffer)/sizeof(buffer[0]));
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                              H2_SSSN_MSG(session, "on_frame_rcv %s"), buffer);
            }
            break;
    }
    
    if (session->state == H2_SESSION_ST_IDLE) {
        /* We received a frame, but session is in state IDLE. That means the frame
         * did not really progress any of the (possibly) open streams. It was a meta
         * frame, e.g. SETTINGS/WINDOW_UPDATE/unknown/etc.
         * Remember: IDLE means we cannot send because either there are no streams open or
         * all open streams are blocked on exhausted WINDOWs for outgoing data.
         * The more frames we receive that do not change this, the less interested we
         * become in serving this connection. This is expressed in increasing "idle_delays".
         * Eventually, the connection will timeout and we'll close it. */
        session->idle_frames = H2MIN(session->idle_frames + 1, session->frames_received);
            ap_log_cerror( APLOG_MARK, APLOG_TRACE2, 0, session->c,
                          H2_SSSN_MSG(session, "session has %ld idle frames"), 
                          (long)session->idle_frames);
        if (session->idle_frames > 10) {
            apr_size_t busy_frames = H2MAX(session->frames_received - session->idle_frames, 1);
            int idle_ratio = (int)(session->idle_frames / busy_frames); 
            if (idle_ratio > 100) {
                session->idle_delay = apr_time_from_msec(H2MIN(1000, idle_ratio));
            }
            else if (idle_ratio > 10) {
                session->idle_delay = apr_time_from_msec(10);
            }
            else if (idle_ratio > 1) {
                session->idle_delay = apr_time_from_msec(1);
            }
            else {
                session->idle_delay = 0;
            }
        }
    }
    
    if (APR_SUCCESS != rv) return NGHTTP2_ERR_PROTO;
    return 0;
}

static int h2_session_continue_data(h2_session *session) {
    if (h2_mplx_m_has_master_events(session->mplx)) {
        return 0;
    }
    if (h2_conn_io_needs_flush(&session->io)) {
        return 0;
    }
    return 1;
}

static char immortal_zeros[H2_MAX_PADLEN];

static int on_send_data_cb(nghttp2_session *ngh2, 
                           nghttp2_frame *frame, 
                           const uint8_t *framehd, 
                           size_t length, 
                           nghttp2_data_source *source, 
                           void *userp)
{
    apr_status_t status = APR_SUCCESS;
    h2_session *session = (h2_session *)userp;
    int stream_id = (int)frame->hd.stream_id;
    unsigned char padlen;
    int eos;
    h2_stream *stream;
    apr_bucket *b;
    apr_off_t len = length;
    
    (void)ngh2;
    (void)source;
    if (!h2_session_continue_data(session)) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }

    ap_assert(frame->data.padlen <= (H2_MAX_PADLEN+1));
    padlen = (unsigned char)frame->data.padlen;
    
    stream = get_stream(session, stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_NOTFOUND, session->c,
                      APLOGNO(02924) 
                      "h2_stream(%ld-%d): send_data, stream not found",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                  H2_STRM_MSG(stream, "send_data_cb for %ld bytes"),
                  (long)length);
                  
    status = h2_conn_io_write(&session->io, (const char *)framehd, H2_FRAME_HDR_LEN);
    if (padlen && status == APR_SUCCESS) {
        --padlen;
        status = h2_conn_io_write(&session->io, (const char *)&padlen, 1);
    }
    
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c,
                      H2_STRM_MSG(stream, "writing frame header"));
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    status = h2_stream_read_to(stream, session->bbtmp, &len, &eos);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c,
                      H2_STRM_MSG(stream, "send_data_cb, reading stream"));
        apr_brigade_cleanup(session->bbtmp);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    else if (len != length) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c,
                      H2_STRM_MSG(stream, "send_data_cb, wanted %ld bytes, "
                      "got %ld from stream"), (long)length, (long)len);
        apr_brigade_cleanup(session->bbtmp);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (padlen) {
        b = apr_bucket_immortal_create(immortal_zeros, padlen, 
                                       session->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(session->bbtmp, b);
    }
    
    status = h2_conn_io_pass(&session->io, session->bbtmp);
    apr_brigade_cleanup(session->bbtmp);
    
    if (status == APR_SUCCESS) {
        stream->out_data_frames++;
        stream->out_data_octets += length;
        return 0;
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c,  
                      H2_STRM_LOG(APLOGNO(02925), stream, "failed send_data_cb"));
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
}

static int on_frame_send_cb(nghttp2_session *ngh2, 
                            const nghttp2_frame *frame,
                            void *user_data)
{
    h2_session *session = user_data;
    h2_stream *stream;
    int stream_id = frame->hd.stream_id;
    
    ++session->frames_sent;
    switch (frame->hd.type) {
        case NGHTTP2_PUSH_PROMISE:
            /* PUSH_PROMISE we report on the promised stream */
            stream_id = frame->push_promise.promised_stream_id;
            break;
        default:    
            break;
    }
    
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      H2_SSSN_LOG(APLOGNO(03068), session, 
                      "sent FRAME[%s], frames=%ld/%ld (r/s)"),
                      buffer, (long)session->frames_received,
                     (long)session->frames_sent);
    }
    
    stream = get_stream(session, stream_id);
    if (stream) {
        h2_stream_send_frame(stream, frame->hd.type, frame->hd.flags, 
            frame->hd.length + H2_FRAME_HDR_LEN);
    }
    return 0;
}

#ifdef H2_NG2_INVALID_HEADER_CB
static int on_invalid_header_cb(nghttp2_session *ngh2, 
                                const nghttp2_frame *frame, 
                                const uint8_t *name, size_t namelen, 
                                const uint8_t *value, size_t valuelen, 
                                uint8_t flags, void *user_data)
{
    h2_session *session = user_data;
    h2_stream *stream;
    
    if (APLOGcdebug(session->c)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03456)
                      "h2_stream(%ld-%d): invalid header '%s: %s'", 
                      session->id, (int)frame->hd.stream_id,
                      apr_pstrndup(session->pool, (const char *)name, namelen),
                      apr_pstrndup(session->pool, (const char *)value, valuelen));
    }
    stream = get_stream(session, frame->hd.stream_id);
    if (stream) {
        h2_stream_rst(stream, NGHTTP2_PROTOCOL_ERROR);
    }
    return 0;
}
#endif

static ssize_t select_padding_cb(nghttp2_session *ngh2, 
                                 const nghttp2_frame *frame, 
                                 size_t max_payloadlen, void *user_data)
{
    h2_session *session = user_data;
    ssize_t frame_len = frame->hd.length + H2_FRAME_HDR_LEN; /* the total length without padding */
    ssize_t padded_len = frame_len;

    /* Determine # of padding bytes to append to frame. Unless session->padding_always
     * the number my be capped by the ui.write_size that currently applies. 
     */
    if (session->padding_max) {
        int n = ap_random_pick(0, session->padding_max);
        padded_len = H2MIN(max_payloadlen + H2_FRAME_HDR_LEN, frame_len + n); 
    }

    if (padded_len != frame_len) {
        if (!session->padding_always && session->io.write_size 
            && (padded_len > session->io.write_size)
            && (frame_len <= session->io.write_size)) {
            padded_len = session->io.write_size;
        }
        if (APLOGctrace2(session->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                          "select padding from [%d, %d]: %d (frame length: 0x%04x, write size: %d)", 
                          (int)frame_len, (int)max_payloadlen+H2_FRAME_HDR_LEN, 
                          (int)(padded_len - frame_len), (int)padded_len, (int)session->io.write_size);
        }
        return padded_len - H2_FRAME_HDR_LEN;
    }
    return frame->hd.length;
}

#define NGH2_SET_CALLBACK(callbacks, name, fn)\
nghttp2_session_callbacks_set_##name##_callback(callbacks, fn)

static apr_status_t init_callbacks(conn_rec *c, nghttp2_session_callbacks **pcb)
{
    int rv = nghttp2_session_callbacks_new(pcb);
    if (rv != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      APLOGNO(02926) "nghttp2_session_callbacks_new: %s",
                      nghttp2_strerror(rv));
        return APR_EGENERAL;
    }
    
    NGH2_SET_CALLBACK(*pcb, send, send_cb);
    NGH2_SET_CALLBACK(*pcb, on_frame_recv, on_frame_recv_cb);
    NGH2_SET_CALLBACK(*pcb, on_invalid_frame_recv, on_invalid_frame_recv_cb);
    NGH2_SET_CALLBACK(*pcb, on_data_chunk_recv, on_data_chunk_recv_cb);
    NGH2_SET_CALLBACK(*pcb, on_stream_close, on_stream_close_cb);
    NGH2_SET_CALLBACK(*pcb, on_begin_headers, on_begin_headers_cb);
    NGH2_SET_CALLBACK(*pcb, on_header, on_header_cb);
    NGH2_SET_CALLBACK(*pcb, send_data, on_send_data_cb);
    NGH2_SET_CALLBACK(*pcb, on_frame_send, on_frame_send_cb);
#ifdef H2_NG2_INVALID_HEADER_CB
    NGH2_SET_CALLBACK(*pcb, on_invalid_header, on_invalid_header_cb);
#endif
    NGH2_SET_CALLBACK(*pcb, select_padding, select_padding_cb);
    return APR_SUCCESS;
}

static apr_status_t h2_session_shutdown_notice(h2_session *session)
{
    apr_status_t status;
    
    ap_assert(session);
    if (!session->local.accepting) {
        return APR_SUCCESS;
    }
    
    nghttp2_submit_shutdown_notice(session->ngh2);
    session->local.accepting = 0;
    status = nghttp2_session_send(session->ngh2);
    if (status == APR_SUCCESS) {
        status = h2_conn_io_flush(&session->io);
    }
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                  H2_SSSN_LOG(APLOGNO(03457), session, "sent shutdown notice"));
    return status;
}

static apr_status_t h2_session_shutdown(h2_session *session, int error, 
                                        const char *msg, int force_close)
{
    apr_status_t status = APR_SUCCESS;
    
    ap_assert(session);
    if (session->local.shutdown) {
        return APR_SUCCESS;
    }
    if (!msg && error) {
        msg = nghttp2_strerror(error);
    }
    
    if (error || force_close) {
        /* not a graceful shutdown, we want to leave... 
         * Do not start further streams that are waiting to be scheduled. 
         * Find out the max stream id that we habe been processed or
         * are still actively working on.
         * Remove all streams greater than this number without submitting
         * a RST_STREAM frame, since that should be clear from the GOAWAY
         * we send. */
        session->local.accepted_max = h2_mplx_m_shutdown(session->mplx);
        session->local.error = error;
    }
    else {
        /* graceful shutdown. we will continue processing all streams
         * we have, but no longer accept new ones. Report the max stream
         * we have received and discard all new ones. */
    }
    
    session->local.accepting = 0;
    session->local.shutdown = 1;
    if (!session->c->aborted) {
        nghttp2_submit_goaway(session->ngh2, NGHTTP2_FLAG_NONE, 
                              session->local.accepted_max, 
                              error, (uint8_t*)msg, msg? strlen(msg):0);
        status = nghttp2_session_send(session->ngh2);
        if (status == APR_SUCCESS) {
            status = h2_conn_io_flush(&session->io);
        }
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      H2_SSSN_LOG(APLOGNO(03069), session, 
                                  "sent GOAWAY, err=%d, msg=%s"), error, msg? msg : "");
    }
    dispatch_event(session, H2_SESSION_EV_LOCAL_GOAWAY, error, msg);
    return status;
}

static apr_status_t session_cleanup(h2_session *session, const char *trigger)
{
    conn_rec *c = session->c;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                  H2_SSSN_MSG(session, "pool_cleanup"));
    
    if (session->state != H2_SESSION_ST_DONE
        && session->state != H2_SESSION_ST_INIT) {
        /* Not good. The connection is being torn down and we have
         * not sent a goaway. This is considered a protocol error and
         * the client has to assume that any streams "in flight" may have
         * been processed and are not safe to retry.
         * As clients with idle connection may only learn about a closed
         * connection when sending the next request, this has the effect
         * that at least this one request will fail.
         */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                      H2_SSSN_LOG(APLOGNO(03199), session, 
                      "connection disappeared without proper "
                      "goodbye, clients will be confused, should not happen"));
    }

    transit(session, trigger, H2_SESSION_ST_CLEANUP);
    h2_mplx_m_release_and_join(session->mplx, session->iowait);
    session->mplx = NULL;

    ap_assert(session->ngh2);
    nghttp2_session_del(session->ngh2);
    session->ngh2 = NULL;
    h2_ctx_clear(c);
    
    
    return APR_SUCCESS;
}

static apr_status_t session_pool_cleanup(void *data)
{
    conn_rec *c = data;
    h2_session *session;
    
    if ((session = h2_ctx_get_session(c))) {
        int mpm_state = 0;
        int level;

        ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state);
        level = (AP_MPMQ_STOPPING == mpm_state)? APLOG_DEBUG : APLOG_WARNING;
        /* if the session is still there, now is the last chance
         * to perform cleanup. Normally, cleanup should have happened
         * earlier in the connection pre_close.
         * However, when the server is stopping, it may shutdown connections
         * without running the pre_close hooks. Do not want about that. */
        ap_log_cerror(APLOG_MARK, level, 0, c,
                      H2_SSSN_LOG(APLOGNO(10020), session, 
                      "session cleanup triggered by pool cleanup. "
                      "this should have happened earlier already."));
        return session_cleanup(session, "pool cleanup");
    }
    return APR_SUCCESS;
}

apr_status_t h2_session_create(h2_session **psession, conn_rec *c, request_rec *r,
                               server_rec *s, h2_workers *workers)
{
    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_option *options = NULL;
    apr_allocator_t *allocator;
    apr_thread_mutex_t *mutex;
    uint32_t n;
    apr_pool_t *pool = NULL;
    h2_session *session;
    apr_status_t status;
    int rv;

    *psession = NULL;
    status = apr_allocator_create(&allocator);
    if (status != APR_SUCCESS) {
        return status;
    }
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    apr_pool_create_ex(&pool, c->pool, NULL, allocator);
    if (!pool) {
        apr_allocator_destroy(allocator);
        return APR_ENOMEM;
    }
    apr_pool_tag(pool, "h2_session");
    apr_allocator_owner_set(allocator, pool);
    status = apr_thread_mutex_create(&mutex, APR_THREAD_MUTEX_DEFAULT, pool);
    if (status != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }
    apr_allocator_mutex_set(allocator, mutex);
    
    session = apr_pcalloc(pool, sizeof(h2_session));
    if (!session) {
        return APR_ENOMEM;
    }
    
    *psession = session;
    session->id = c->id;
    session->c = c;
    session->r = r;
    session->s = s;
    session->pool = pool;
    session->workers = workers;
    
    session->state = H2_SESSION_ST_INIT;
    session->local.accepting = 1;
    session->remote.accepting = 1;
    
    session->max_stream_count = h2_config_sgeti(s, H2_CONF_MAX_STREAMS);
    session->max_stream_mem = h2_config_sgeti(s, H2_CONF_STREAM_MAX_MEM);
    
    status = apr_thread_cond_create(&session->iowait, session->pool);
    if (status != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return status;
    }
    
    session->in_pending = h2_iq_create(session->pool, (int)session->max_stream_count);
    if (session->in_pending == NULL) {
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }

    session->in_process = h2_iq_create(session->pool, (int)session->max_stream_count);
    if (session->in_process == NULL) {
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }
    
    session->monitor = apr_pcalloc(pool, sizeof(h2_stream_monitor));
    if (session->monitor == NULL) {
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }
    session->monitor->ctx = session;
    session->monitor->on_state_enter = on_stream_state_enter;
    session->monitor->on_state_event = on_stream_state_event;
    session->monitor->on_event = on_stream_event;
    
    session->mplx = h2_mplx_m_create(c, s, session->pool, workers);
    
    /* connection input filter that feeds the session */
    session->cin = h2_filter_cin_create(session);
    ap_add_input_filter("H2_IN", session->cin, r, c);
    
    h2_conn_io_init(&session->io, c, s);
    session->padding_max = h2_config_sgeti(s, H2_CONF_PADDING_BITS);
    if (session->padding_max) {
        session->padding_max = (0x01 << session->padding_max) - 1; 
    }
    session->padding_always = h2_config_sgeti(s, H2_CONF_PADDING_ALWAYS);
    session->bbtmp = apr_brigade_create(session->pool, c->bucket_alloc);
    
    status = init_callbacks(c, &callbacks);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c, APLOGNO(02927) 
                      "nghttp2: error in init_callbacks");
        apr_pool_destroy(pool);
        return status;
    }
    
    rv = nghttp2_option_new(&options);
    if (rv != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                      APLOGNO(02928) "nghttp2_option_new: %s", 
                      nghttp2_strerror(rv));
        apr_pool_destroy(pool);
        return status;
    }
    nghttp2_option_set_peer_max_concurrent_streams(options, (uint32_t)session->max_stream_count);
    /* We need to handle window updates ourself, otherwise we
     * get flooded by nghttp2. */
    nghttp2_option_set_no_auto_window_update(options, 1);
    
    rv = nghttp2_session_server_new2(&session->ngh2, callbacks,
                                     session, options);
    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(options);
    
    if (rv != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                      APLOGNO(02929) "nghttp2_session_server_new: %s",
                      nghttp2_strerror(rv));
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }
    
    n = h2_config_sgeti(s, H2_CONF_PUSH_DIARY_SIZE);
    session->push_diary = h2_push_diary_create(session->pool, n);
    
    if (APLOGcdebug(c)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, 
                      H2_SSSN_LOG(APLOGNO(03200), session, 
                                  "created, max_streams=%d, stream_mem=%d, "
                                  "workers_limit=%d, workers_max=%d, "
                                  "push_diary(type=%d,N=%d)"),
                      (int)session->max_stream_count, 
                      (int)session->max_stream_mem,
                      session->mplx->limit_active, 
                      session->mplx->max_active, 
                      session->push_diary->dtype, 
                      (int)session->push_diary->N);
    }
    
    apr_pool_pre_cleanup_register(pool, c, session_pool_cleanup);
        
    return APR_SUCCESS;
}

static apr_status_t h2_session_start(h2_session *session, int *rv)
{
    apr_status_t status = APR_SUCCESS;
    nghttp2_settings_entry settings[3];
    size_t slen;
    int win_size;
    
    ap_assert(session);
    /* Start the conversation by submitting our SETTINGS frame */
    *rv = 0;
    if (session->r) {
        const char *s, *cs;
        apr_size_t dlen; 
        h2_stream * stream;

        /* 'h2c' mode: we should have a 'HTTP2-Settings' header with
         * base64 encoded client settings. */
        s = apr_table_get(session->r->headers_in, "HTTP2-Settings");
        if (!s) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EINVAL, session->r,
                          APLOGNO(02931) 
                          "HTTP2-Settings header missing in request");
            return APR_EINVAL;
        }
        cs = NULL;
        dlen = h2_util_base64url_decode(&cs, s, session->pool);
        
        if (APLOGrdebug(session->r)) {
            char buffer[128];
            h2_util_hex_dump(buffer, 128, (char*)cs, dlen);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, session->r, APLOGNO(03070)
                          "upgrading h2c session with HTTP2-Settings: %s -> %s (%d)",
                          s, buffer, (int)dlen);
        }
        
        *rv = nghttp2_session_upgrade(session->ngh2, (uint8_t*)cs, dlen, NULL);
        if (*rv != 0) {
            status = APR_EINVAL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, session->r,
                          APLOGNO(02932) "nghttp2_session_upgrade: %s", 
                          nghttp2_strerror(*rv));
            return status;
        }
        
        /* Now we need to auto-open stream 1 for the request we got. */
        stream = h2_session_open_stream(session, 1, 0);
        if (!stream) {
            status = APR_EGENERAL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, session->r,
                          APLOGNO(02933) "open stream 1: %s", 
                          nghttp2_strerror(*rv));
            return status;
        }
        
        status = h2_stream_set_request_rec(stream, session->r, 1);
        if (status != APR_SUCCESS) {
            return status;
        }
    }

    slen = 0;
    settings[slen].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    settings[slen].value = (uint32_t)session->max_stream_count;
    ++slen;
    win_size = h2_config_sgeti(session->s, H2_CONF_WIN_SIZE);
    if (win_size != H2_INITIAL_WINDOW_SIZE) {
        settings[slen].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
        settings[slen].value = win_size;
        ++slen;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, 
                  H2_SSSN_LOG(APLOGNO(03201), session, 
                  "start, INITIAL_WINDOW_SIZE=%ld, MAX_CONCURRENT_STREAMS=%d"), 
                  (long)win_size, (int)session->max_stream_count);
    *rv = nghttp2_submit_settings(session->ngh2, NGHTTP2_FLAG_NONE,
                                  settings, slen);
    if (*rv != 0) {
        status = APR_EGENERAL;
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c,
                      H2_SSSN_LOG(APLOGNO(02935), session, 
                      "nghttp2_submit_settings: %s"), nghttp2_strerror(*rv));
    }
    else {
        /* use maximum possible value for connection window size. We are only
         * interested in per stream flow control. which have the initial window
         * size configured above.
         * Therefore, for our use, the connection window can only get in the
         * way. Example: if we allow 100 streams with a 32KB window each, we
         * buffer up to 3.2 MB of data. Unless we do separate connection window
         * interim updates, any smaller connection window will lead to blocking
         * in DATA flow.
         */
        *rv = nghttp2_submit_window_update(session->ngh2, NGHTTP2_FLAG_NONE,
                                           0, NGHTTP2_MAX_WINDOW_SIZE - win_size);
        if (*rv != 0) {
            status = APR_EGENERAL;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c,
                          H2_SSSN_LOG(APLOGNO(02970), session,
                          "nghttp2_submit_window_update: %s"), 
                          nghttp2_strerror(*rv));        
        }
    }
    
    return status;
}

static apr_status_t on_stream_headers(h2_session *session, h2_stream *stream,  
                                      h2_headers *headers, apr_off_t len,
                                      int eos);

static ssize_t stream_data_cb(nghttp2_session *ng2s,
                              int32_t stream_id,
                              uint8_t *buf,
                              size_t length,
                              uint32_t *data_flags,
                              nghttp2_data_source *source,
                              void *puser)
{
    h2_session *session = (h2_session *)puser;
    apr_off_t nread = length;
    int eos = 0;
    apr_status_t status;
    h2_stream *stream;
    ap_assert(session);
    
    /* The session wants to send more DATA for the stream. We need
     * to find out how much of the requested length we can send without
     * blocking.
     * Indicate EOS when we encounter it or DEFERRED if the stream
     * should be suspended. Beware of trailers.
     */
 
    (void)ng2s;
    (void)buf;
    (void)source;
    stream = get_stream(session, stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, session->c,
                      APLOGNO(02937) 
                      "h2_stream(%ld-%d): data_cb, stream not found",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    status = h2_stream_out_prepare(stream, &nread, &eos, NULL);
    if (nread) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c, 
                      H2_STRM_MSG(stream, "prepared no_copy, len=%ld, eos=%d"),
                      (long)nread, eos);
        *data_flags |=  NGHTTP2_DATA_FLAG_NO_COPY;
    }
    
    switch (status) {
        case APR_SUCCESS:
            break;
            
        case APR_EOF:
            eos = 1;
            break;
            
        case APR_ECONNRESET:
        case APR_ECONNABORTED:
            return NGHTTP2_ERR_CALLBACK_FAILURE;
            
        case APR_EAGAIN:
            /* If there is no data available, our session will automatically
             * suspend this stream and not ask for more data until we resume
             * it. Remember at our h2_stream that we need to do this.
             */
            nread = 0;
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                          H2_STRM_LOG(APLOGNO(03071), stream, "suspending"));
            return NGHTTP2_ERR_DEFERRED;
            
        default:
            nread = 0;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c, 
                          H2_STRM_LOG(APLOGNO(02938), stream, "reading data"));
            return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (eos) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return (ssize_t)nread;
}

struct h2_stream *h2_session_push(h2_session *session, h2_stream *is,
                                  h2_push *push)
{
    h2_stream *stream;
    h2_ngheader *ngh;
    apr_status_t status;
    int nid = 0;
    
    status = h2_req_create_ngheader(&ngh, is->pool, push->req);
    if (status == APR_SUCCESS) {
        nid = nghttp2_submit_push_promise(session->ngh2, 0, is->id, 
                                          ngh->nv, ngh->nvlen, NULL);
    }
    if (status != APR_SUCCESS || nid <= 0) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, 
                      H2_STRM_LOG(APLOGNO(03075), is, 
                      "submitting push promise fail: %s"), nghttp2_strerror(nid));
        return NULL;
    }
    ++session->pushes_promised;
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                  H2_STRM_LOG(APLOGNO(03076), is, "SERVER_PUSH %d for %s %s on %d"),
                  nid, push->req->method, push->req->path, is->id);
                  
    stream = h2_session_open_stream(session, nid, is->id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      H2_STRM_LOG(APLOGNO(03077), is,
                      "failed to create stream obj %d"), nid);
        /* kill the push_promise */
        nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE, nid,
                                  NGHTTP2_INTERNAL_ERROR);
        return NULL;
    }
    
    h2_session_set_prio(session, stream, push->priority);
    h2_stream_set_request(stream, push->req);
    ++session->unsent_promises;
    return stream;
}

static int valid_weight(float f) 
{
    int w = (int)f;
    return (w < NGHTTP2_MIN_WEIGHT? NGHTTP2_MIN_WEIGHT : 
            (w > NGHTTP2_MAX_WEIGHT)? NGHTTP2_MAX_WEIGHT : w);
}

apr_status_t h2_session_set_prio(h2_session *session, h2_stream *stream, 
                                 const h2_priority *prio)
{
    apr_status_t status = APR_SUCCESS;
#ifdef H2_NG2_CHANGE_PRIO
    nghttp2_stream *s_grandpa, *s_parent, *s;
    
    if (prio == NULL) {
        /* we treat this as a NOP */
        return APR_SUCCESS;
    }
    s = nghttp2_session_find_stream(session->ngh2, stream->id);
    if (!s) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                      H2_STRM_MSG(stream, "lookup of nghttp2_stream failed"));
        return APR_EINVAL;
    }
    
    s_parent = nghttp2_stream_get_parent(s);
    if (s_parent) {
        nghttp2_priority_spec ps;
        int id_parent, id_grandpa, w_parent, w;
        int rv = 0;
        const char *ptype = "AFTER";
        h2_dependency dep = prio->dependency;
        
        id_parent = nghttp2_stream_get_stream_id(s_parent);
        s_grandpa = nghttp2_stream_get_parent(s_parent);
        if (s_grandpa) {
            id_grandpa = nghttp2_stream_get_stream_id(s_grandpa);
        }
        else {
            /* parent of parent does not exist, 
             * only possible if parent == root */
            dep = H2_DEPENDANT_AFTER;
        }
        
        switch (dep) {
            case H2_DEPENDANT_INTERLEAVED:
                /* PUSHed stream is to be interleaved with initiating stream.
                 * It is made a sibling of the initiating stream and gets a
                 * proportional weight [1, MAX_WEIGHT] of the initiaing
                 * stream weight.
                 */
                ptype = "INTERLEAVED";
                w_parent = nghttp2_stream_get_weight(s_parent);
                w = valid_weight(w_parent * ((float)prio->weight / NGHTTP2_MAX_WEIGHT));
                nghttp2_priority_spec_init(&ps, id_grandpa, w, 0);
                break;
                
            case H2_DEPENDANT_BEFORE:
                /* PUSHed stream os to be sent BEFORE the initiating stream.
                 * It gets the same weight as the initiating stream, replaces
                 * that stream in the dependency tree and has the initiating
                 * stream as child.
                 */
                ptype = "BEFORE";
                w = w_parent = nghttp2_stream_get_weight(s_parent);
                nghttp2_priority_spec_init(&ps, stream->id, w_parent, 0);
                id_grandpa = nghttp2_stream_get_stream_id(s_grandpa);
                rv = nghttp2_session_change_stream_priority(session->ngh2, id_parent, &ps);
                if (rv < 0) {
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03202)
                                  "h2_stream(%ld-%d): PUSH BEFORE, weight=%d, "
                                  "depends=%d, returned=%d",
                                  session->id, id_parent, ps.weight, ps.stream_id, rv);
                    return APR_EGENERAL;
                }
                nghttp2_priority_spec_init(&ps, id_grandpa, w, 0);
                break;
                
            case H2_DEPENDANT_AFTER:
                /* The PUSHed stream is to be sent after the initiating stream.
                 * Give if the specified weight and let it depend on the intiating
                 * stream.
                 */
                /* fall through, it's the default */
            default:
                nghttp2_priority_spec_init(&ps, id_parent, valid_weight(prio->weight), 0);
                break;
        }


        rv = nghttp2_session_change_stream_priority(session->ngh2, stream->id, &ps);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      H2_STRM_LOG(APLOGNO(03203), stream, 
                      "PUSH %s, weight=%d, depends=%d, returned=%d"),
                      ptype, ps.weight, ps.stream_id, rv);
        status = (rv < 0)? APR_EGENERAL : APR_SUCCESS;
    }
#else
    (void)session;
    (void)stream;
    (void)prio;
    (void)valid_weight;
#endif
    return status;
}

int h2_session_push_enabled(h2_session *session)
{
    /* iff we can and they can and want */
    return (session->remote.accepting /* remote GOAWAY received */
            && h2_config_sgeti(session->s, H2_CONF_PUSH)
            && nghttp2_session_get_remote_settings(session->ngh2, 
                   NGHTTP2_SETTINGS_ENABLE_PUSH));
}

static apr_status_t h2_session_send(h2_session *session)
{
    apr_interval_time_t saved_timeout;
    int rv;
    apr_socket_t *socket;
    
    socket = ap_get_conn_socket(session->c);
    if (socket) {
        apr_socket_timeout_get(socket, &saved_timeout);
        apr_socket_timeout_set(socket, session->s->timeout);
    }
    
    rv = nghttp2_session_send(session->ngh2);
    
    if (socket) {
        apr_socket_timeout_set(socket, saved_timeout);
    }
    session->have_written = 1;
    if (rv != 0 && rv != NGHTTP2_ERR_WOULDBLOCK) {
        if (nghttp2_is_fatal(rv)) {
            dispatch_event(session, H2_SESSION_EV_PROTO_ERROR, rv, nghttp2_strerror(rv));
            return APR_EGENERAL;
        }
    }
    
    session->unsent_promises = 0;
    session->unsent_submits = 0;
    
    return APR_SUCCESS;
}

/**
 * headers for the stream are ready.
 */
static apr_status_t on_stream_headers(h2_session *session, h2_stream *stream,  
                                      h2_headers *headers, apr_off_t len,
                                      int eos)
{
    apr_status_t status = APR_SUCCESS;
    const char *s;
    int rv = 0;

    ap_assert(session);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c, 
                  H2_STRM_MSG(stream, "on_headers"));
    if (headers->status < 100) {
        h2_stream_rst(stream, headers->status);
        goto leave;
    }
    else if (stream->has_response) {
        h2_ngheader *nh;
        
        status = h2_res_create_ngtrailer(&nh, stream->pool, headers);
        
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, 
                      H2_STRM_LOG(APLOGNO(03072), stream, "submit %d trailers"), 
                      (int)nh->nvlen);
        if (status == APR_SUCCESS) {
            rv = nghttp2_submit_trailer(session->ngh2, stream->id, 
                                        nh->nv, nh->nvlen);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c,
                          H2_STRM_LOG(APLOGNO(10024), stream, "invalid trailers"));
            h2_stream_rst(stream, NGHTTP2_PROTOCOL_ERROR);
        }
        goto leave;
    }
    else {
        nghttp2_data_provider provider, *pprovider = NULL;
        h2_ngheader *ngh;
        const char *note;
        
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      H2_STRM_LOG(APLOGNO(03073), stream, "submit response %d, REMOTE_WINDOW_SIZE=%u"),
                      headers->status,
                      (unsigned int)nghttp2_session_get_stream_remote_window_size(session->ngh2, stream->id));
        
        if (!eos || len > 0) {
            memset(&provider, 0, sizeof(provider));
            provider.source.fd = stream->id;
            provider.read_callback = stream_data_cb;
            pprovider = &provider;
        }
        
        /* If this stream is not a pushed one itself,
         * and HTTP/2 server push is enabled here,
         * and the response HTTP status is not sth >= 400,
         * and the remote side has pushing enabled,
         * -> find and perform any pushes on this stream
         *    *before* we submit the stream response itself.
         *    This helps clients avoid opening new streams on Link
         *    headers that get pushed right afterwards.
         * 
         * *) the response code is relevant, as we do not want to 
         *    make pushes on 401 or 403 codes and friends. 
         *    And if we see a 304, we do not push either
         *    as the client, having this resource in its cache, might
         *    also have the pushed ones as well.
         */
        if (!stream->initiated_on
            && !stream->has_response
            && stream->request && stream->request->method
            && !strcmp("GET", stream->request->method)
            && (headers->status < 400)
            && (headers->status != 304)
            && h2_session_push_enabled(session)) {
            /* PUSH is possible and enabled on server, unless the request
             * denies it, submit resources to push */
            s = apr_table_get(headers->notes, H2_PUSH_MODE_NOTE);
            if (!s || strcmp(s, "0")) {
                h2_stream_submit_pushes(stream, headers);
            }
        }
        
        if (!stream->pref_priority) {
            stream->pref_priority = h2_stream_get_priority(stream, headers);
        }
        h2_session_set_prio(session, stream, stream->pref_priority);
        
        note = apr_table_get(headers->notes, H2_FILTER_DEBUG_NOTE);
        if (note && !strcmp("on", note)) {
            int32_t connFlowIn, connFlowOut;

            connFlowIn = nghttp2_session_get_effective_local_window_size(session->ngh2); 
            connFlowOut = nghttp2_session_get_remote_window_size(session->ngh2);
            headers = h2_headers_copy(stream->pool, headers);
            apr_table_setn(headers->headers, "conn-flow-in", 
                           apr_itoa(stream->pool, connFlowIn));
            apr_table_setn(headers->headers, "conn-flow-out", 
                           apr_itoa(stream->pool, connFlowOut));
        }
        
        if (headers->status == 103 
            && !h2_config_sgeti(session->s, H2_CONF_EARLY_HINTS)) {
            /* suppress sending this to the client, it might have triggered 
             * pushes and served its purpose nevertheless */
            rv = 0;
            goto leave;
        }
        
        status = h2_res_create_ngheader(&ngh, stream->pool, headers);
        if (status == APR_SUCCESS) {
            rv = nghttp2_submit_response(session->ngh2, stream->id,
                                         ngh->nv, ngh->nvlen, pprovider);
            stream->has_response = h2_headers_are_response(headers);
            session->have_written = 1;
            
            if (stream->initiated_on) {
                ++session->pushes_submitted;
            }
            else {
                ++session->responses_submitted;
            }
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c,
                          H2_STRM_LOG(APLOGNO(10025), stream, "invalid response"));
            h2_stream_rst(stream, NGHTTP2_PROTOCOL_ERROR);
        }
    }
    
leave:
    if (nghttp2_is_fatal(rv)) {
        status = APR_EGENERAL;
        dispatch_event(session, H2_SESSION_EV_PROTO_ERROR, rv, nghttp2_strerror(rv));
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c,
                      APLOGNO(02940) "submit_response: %s", 
                      nghttp2_strerror(rv));
    }
    
    ++session->unsent_submits;
    
    /* Unsent push promises are written immediately, as nghttp2
     * 1.5.0 realizes internal stream data structures only on 
     * send and we might need them for other submits. 
     * Also, to conserve memory, we send at least every 10 submits
     * so that nghttp2 does not buffer all outbound items too 
     * long.
     */
    if (status == APR_SUCCESS 
        && (session->unsent_promises || session->unsent_submits > 10)) {
        status = h2_session_send(session);
    }
    return status;
}

/**
 * A stream was resumed as new response/output data arrived.
 */
static apr_status_t on_stream_resume(void *ctx, h2_stream *stream)
{
    h2_session *session = ctx;
    apr_status_t status = APR_EAGAIN;
    int rv;
    apr_off_t len = 0;
    int eos = 0;
    h2_headers *headers;
    
    ap_assert(stream);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c, 
                  H2_STRM_MSG(stream, "on_resume"));
    
send_headers:
    headers = NULL;
    status = h2_stream_out_prepare(stream, &len, &eos, &headers);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c, 
                  H2_STRM_MSG(stream, "prepared len=%ld, eos=%d"), 
                  (long)len, eos);
    if (headers) {
        status = on_stream_headers(session, stream, headers, len, eos);
        if (status != APR_SUCCESS || stream->rst_error) {
            return status;
        }
        goto send_headers;
    }
    else if (status != APR_EAGAIN) {
        /* we have DATA to send */
        if (!stream->has_response) {
            /* but no response */
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                          H2_STRM_LOG(APLOGNO(03466), stream, 
                          "no response, RST_STREAM"));
            h2_stream_rst(stream, H2_ERR_PROTOCOL_ERROR);
            return APR_SUCCESS;
        } 
        rv = nghttp2_session_resume_data(session->ngh2, stream->id);
        session->have_written = 1;
        ap_log_cerror(APLOG_MARK, nghttp2_is_fatal(rv)?
                      APLOG_ERR : APLOG_DEBUG, 0, session->c,  
                      H2_STRM_LOG(APLOGNO(02936), stream, "resumed"));
    }
    return status;
}

static void h2_session_in_flush(h2_session *session)
{
    int id;
    
    while ((id = h2_iq_shift(session->in_process)) > 0) {
        h2_stream *stream = get_stream(session, id);
        if (stream) {
            ap_assert(!stream->scheduled);
            if (h2_stream_prep_processing(stream) == APR_SUCCESS) {
                h2_mplx_m_process(session->mplx, stream, stream_pri_cmp, session);
            }
            else {
                h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
            }
        }
    }

    while ((id = h2_iq_shift(session->in_pending)) > 0) {
        h2_stream *stream = get_stream(session, id);
        if (stream) {
            h2_stream_flush_input(stream);
        }
    }
}

static apr_status_t session_read(h2_session *session, apr_size_t readlen, int block)
{
    apr_status_t status, rstatus = APR_EAGAIN;
    conn_rec *c = session->c;
    apr_off_t read_start = session->io.bytes_read;
    
    while (1) {
        /* H2_IN filter handles all incoming data against the session.
         * We just pull at the filter chain to make it happen */
        status = ap_get_brigade(c->input_filters,
                                session->bbtmp, AP_MODE_READBYTES,
                                block? APR_BLOCK_READ : APR_NONBLOCK_READ,
                                H2MAX(APR_BUCKET_BUFF_SIZE, readlen));
        /* get rid of any possible data we do not expect to get */
        apr_brigade_cleanup(session->bbtmp); 

        switch (status) {
            case APR_SUCCESS:
                /* successful read, reset our idle timers */
                rstatus = APR_SUCCESS;
                if (block) {
                    /* successful blocked read, try unblocked to
                     * get more. */
                    block = 0;
                }
                break;
            case APR_EAGAIN:
                return rstatus;
            case APR_TIMEUP:
                return status;
            default:
                if (session->io.bytes_read == read_start) {
                    /* first attempt failed */
                    if (APR_STATUS_IS_ETIMEDOUT(status)
                        || APR_STATUS_IS_ECONNABORTED(status)
                        || APR_STATUS_IS_ECONNRESET(status)
                        || APR_STATUS_IS_EOF(status)
                        || APR_STATUS_IS_EBADF(status)) {
                        /* common status for a client that has left */
                        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                      H2_SSSN_MSG(session, "input gone"));
                    }
                    else {
                        /* uncommon status, log on INFO so that we see this */
                        ap_log_cerror( APLOG_MARK, APLOG_DEBUG, status, c,
                                      H2_SSSN_LOG(APLOGNO(02950), session, 
                                      "error reading, terminating"));
                    }
                    return status;
                }
                /* subsequent failure after success(es), return initial
                 * status. */
                return rstatus;
        }
        if ((session->io.bytes_read - read_start) > readlen) {
            /* read enough in one go, give write a chance */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, c,
                          H2_SSSN_MSG(session, "read enough, returning"));
            break;
        }
    }
    return rstatus;
}

static apr_status_t h2_session_read(h2_session *session, int block)
{
    apr_status_t status = session_read(session, session->max_stream_mem
                                       * H2MAX(2, session->open_streams), 
                                       block);
    h2_session_in_flush(session);
    return status;
}

static const char *StateNames[] = {
    "INIT",      /* H2_SESSION_ST_INIT */
    "DONE",      /* H2_SESSION_ST_DONE */
    "IDLE",      /* H2_SESSION_ST_IDLE */
    "BUSY",      /* H2_SESSION_ST_BUSY */
    "WAIT",      /* H2_SESSION_ST_WAIT */
    "CLEANUP",   /* H2_SESSION_ST_CLEANUP */
};

const char *h2_session_state_str(h2_session_state state)
{
    if (state >= (sizeof(StateNames)/sizeof(StateNames[0]))) {
        return "unknown";
    }
    return StateNames[state];
}

static void update_child_status(h2_session *session, int status, const char *msg)
{
    /* Assume that we also change code/msg when something really happened and
     * avoid updating the scoreboard in between */
    if (session->last_status_code != status 
        || session->last_status_msg != msg) {
        apr_snprintf(session->status, sizeof(session->status),
                     "%s, streams: %d/%d/%d/%d/%d (open/recv/resp/push/rst)", 
                     msg? msg : "-",
                     (int)session->open_streams, 
                     (int)session->remote.emitted_count,
                     (int)session->responses_submitted,
                     (int)session->pushes_submitted,
                     (int)session->pushes_reset + session->streams_reset);
        ap_update_child_status_descr(session->c->sbh, status, session->status);
    }
}

static void transit(h2_session *session, const char *action, h2_session_state nstate)
{
    apr_time_t timeout;
    int ostate, loglvl;
    const char *s;
    
    if (session->state != nstate) {
        ostate = session->state;
        session->state = nstate;
        
        loglvl = APLOG_DEBUG;
        if ((ostate == H2_SESSION_ST_BUSY && nstate == H2_SESSION_ST_WAIT)
            || (ostate == H2_SESSION_ST_WAIT && nstate == H2_SESSION_ST_BUSY)){
            loglvl = APLOG_TRACE1;
        }
        ap_log_cerror(APLOG_MARK, loglvl, 0, session->c, 
                      H2_SSSN_LOG(APLOGNO(03078), session, 
                      "transit [%s] -- %s --> [%s]"), 
                      h2_session_state_str(ostate), action, 
                      h2_session_state_str(nstate));
        
        switch (session->state) {
            case H2_SESSION_ST_IDLE:
                if (!session->remote.emitted_count) {
                    /* on fresh connections, with async mpm, do not return
                     * to mpm for a second. This gives the first request a better
                     * chance to arrive (und connection leaving IDLE state).
                     * If we return to mpm right away, this connection has the
                     * same chance of being cleaned up by the mpm as connections
                     * that already served requests - not fair. */
                    session->idle_sync_until = apr_time_now() + apr_time_from_sec(1);
                    s = "timeout";
                    timeout = session->s->timeout;
                    update_child_status(session, SERVER_BUSY_READ, "idle");
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c, 
                                  H2_SSSN_LOG("", session, "enter idle, timeout = %d sec"), 
                                  (int)apr_time_sec(H2MAX(session->s->timeout, session->s->keep_alive_timeout)));
                }
                else if (session->open_streams) {
                    s = "timeout";
                    timeout = session->s->timeout;
                    update_child_status(session, SERVER_BUSY_READ, "idle");
                }
                else {
                    /* normal keepalive setup */
                    s = "keepalive";
                    timeout = session->s->keep_alive_timeout;
                    update_child_status(session, SERVER_BUSY_KEEPALIVE, "idle");
                }
                session->idle_until = apr_time_now() + timeout; 
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c, 
                              H2_SSSN_LOG("", session, "enter idle, %s = %d sec"), 
                              s, (int)apr_time_sec(timeout));
                break;
            case H2_SESSION_ST_DONE:
                update_child_status(session, SERVER_CLOSING, "done");
                break;
            default:
                /* nop */
                break;
        }
    }
}

static void h2_session_ev_init(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_INIT:
            transit(session, "init", H2_SESSION_ST_BUSY);
            break;
        default:
            /* nop */
            break;
    }
}

static void h2_session_ev_local_goaway(h2_session *session, int arg, const char *msg)
{
    cleanup_unprocessed_streams(session);
    if (!session->remote.shutdown) {
        update_child_status(session, SERVER_CLOSING, "local goaway");
    }
    transit(session, "local goaway", H2_SESSION_ST_DONE);
}

static void h2_session_ev_remote_goaway(h2_session *session, int arg, const char *msg)
{
    if (!session->remote.shutdown) {
        session->remote.error = arg;
        session->remote.accepting = 0;
        session->remote.shutdown = 1;
        cleanup_unprocessed_streams(session);
        update_child_status(session, SERVER_CLOSING, "remote goaway");
        transit(session, "remote goaway", H2_SESSION_ST_DONE);
    }
}

static void h2_session_ev_conn_error(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_INIT:
        case H2_SESSION_ST_DONE:
            /* just leave */
            transit(session, "conn error", H2_SESSION_ST_DONE);
            break;
        
        default:
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                          H2_SSSN_LOG(APLOGNO(03401), session, 
                          "conn error -> shutdown"));
            h2_session_shutdown(session, arg, msg, 0);
            break;
    }
}

static void h2_session_ev_proto_error(h2_session *session, int arg, const char *msg)
{
    if (!session->local.shutdown) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      H2_SSSN_LOG(APLOGNO(03402), session, 
                      "proto error -> shutdown"));
        h2_session_shutdown(session, arg, msg, 0);
    }
}

static void h2_session_ev_conn_timeout(h2_session *session, int arg, const char *msg)
{
    transit(session, msg, H2_SESSION_ST_DONE);
    if (!session->local.shutdown) {
        h2_session_shutdown(session, arg, msg, 1);
    }
}

static void h2_session_ev_no_io(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_BUSY:
            /* Nothing to READ, nothing to WRITE on the master connection.
             * Possible causes:
             * - we wait for the client to send us sth
             * - we wait for started tasks to produce output
             * - we have finished all streams and the client has sent GO_AWAY
             */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                          H2_SSSN_MSG(session, "NO_IO event, %d streams open"), 
                          session->open_streams);
            h2_conn_io_flush(&session->io);
            if (session->open_streams > 0) {
                if (h2_mplx_m_awaits_data(session->mplx)) {
                    /* waiting for at least one stream to produce data */
                    transit(session, "no io", H2_SESSION_ST_WAIT);
                }
                else {
                    /* we have streams open, and all are submitted and none
                     * is suspended. The only thing keeping us from WRITEing
                     * more must be the flow control.
                     * This means we only wait for WINDOW_UPDATE from the 
                     * client and can block on READ. */
                    transit(session, "no io (flow wait)", H2_SESSION_ST_IDLE);
                    /* Make sure we have flushed all previously written output
                     * so that the client will react. */
                    if (h2_conn_io_flush(&session->io) != APR_SUCCESS) {
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
                        return;
                    }
                }
            }
            else if (session->local.accepting) {
                /* When we have no streams, but accept new, switch to idle */
                transit(session, "no io (keepalive)", H2_SESSION_ST_IDLE);
            }
            else {
                /* We are no longer accepting new streams and there are
                 * none left. Time to leave. */
                h2_session_shutdown(session, arg, msg, 0);
                transit(session, "no io", H2_SESSION_ST_DONE);
            }
            break;
        default:
            /* nop */
            break;
    }
}

static void h2_session_ev_frame_rcvd(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_IDLE:
        case H2_SESSION_ST_WAIT:
            transit(session, "frame received", H2_SESSION_ST_BUSY);
            break;
        default:
            /* nop */
            break;
    }
}

static void h2_session_ev_stream_change(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_IDLE:
        case H2_SESSION_ST_WAIT:
            transit(session, "stream change", H2_SESSION_ST_BUSY);
            break;
        default:
            /* nop */
            break;
    }
}

static void h2_session_ev_ngh2_done(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_DONE:
            /* nop */
            break;
        default:
            transit(session, "nghttp2 done", H2_SESSION_ST_DONE);
            break;
    }
}

static void h2_session_ev_mpm_stopping(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_DONE:
            /* nop */
            break;
        default:
            h2_session_shutdown_notice(session);
            h2_workers_graceful_shutdown(session->workers);
            break;
    }
}

static void h2_session_ev_pre_close(h2_session *session, int arg, const char *msg)
{
    h2_session_shutdown(session, arg, msg, 1);
}

static void ev_stream_open(h2_session *session, h2_stream *stream)
{
    h2_iq_append(session->in_process, stream->id);
}

static void ev_stream_closed(h2_session *session, h2_stream *stream)
{
    apr_bucket *b;
    
    if (H2_STREAM_CLIENT_INITIATED(stream->id)
        && (stream->id > session->local.completed_max)) {
        session->local.completed_max = stream->id;
    }
    switch (session->state) {
        case H2_SESSION_ST_IDLE:
            break;
        default:
            break;
    }
    
    /* The stream might have data in the buffers of the main connection.
     * We can only free the allocated resources once all had been written.
     * Send a special buckets on the connection that gets destroyed when
     * all preceding data has been handled. On its destruction, it is safe
     * to purge all resources of the stream. */
    b = h2_bucket_eos_create(session->c->bucket_alloc, stream);
    APR_BRIGADE_INSERT_TAIL(session->bbtmp, b);
    h2_conn_io_pass(&session->io, session->bbtmp);
    apr_brigade_cleanup(session->bbtmp);
}

static void on_stream_state_enter(void *ctx, h2_stream *stream)
{
    h2_session *session = ctx;
    /* stream entered a new state */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                  H2_STRM_MSG(stream, "entered state"));
    switch (stream->state) {
        case H2_SS_IDLE: /* stream was created */
            ++session->open_streams;
            if (H2_STREAM_CLIENT_INITIATED(stream->id)) {
                ++session->remote.emitted_count;
                if (stream->id > session->remote.emitted_max) {
                    session->remote.emitted_max = stream->id;
                    session->local.accepted_max = stream->id;
                }
            }
            else {
                if (stream->id > session->local.emitted_max) {
                    ++session->local.emitted_count;
                    session->remote.emitted_max = stream->id;
                }
            }
            break;
        case H2_SS_OPEN: /* stream has request headers */
        case H2_SS_RSVD_L: /* stream has request headers */
            ev_stream_open(session, stream);
            break;
        case H2_SS_CLOSED_L: /* stream output was closed */
            break;
        case H2_SS_CLOSED_R: /* stream input was closed */
            break;
        case H2_SS_CLOSED: /* stream in+out were closed */
            --session->open_streams;
            ev_stream_closed(session, stream);
            break;
        case H2_SS_CLEANUP:
            nghttp2_session_set_stream_user_data(session->ngh2, stream->id, NULL);
            h2_mplx_m_stream_cleanup(session->mplx, stream);
            break;
        default:
            break;
    }
    dispatch_event(session, H2_SESSION_EV_STREAM_CHANGE, 0, "stream state change");
}

static void on_stream_event(void *ctx, h2_stream *stream, 
                                  h2_stream_event_t ev)
{
    h2_session *session = ctx;
    switch (ev) {
        case H2_SEV_IN_DATA_PENDING:
            h2_iq_append(session->in_pending, stream->id);
            break;
        default:
            /* NOP */
            break;
    }
}

static void on_stream_state_event(void *ctx, h2_stream *stream, 
                                  h2_stream_event_t ev)
{
    h2_session *session = ctx;
    switch (ev) {
        case H2_SEV_CANCELLED:
            if (session->state != H2_SESSION_ST_DONE) {
                nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE, 
                                          stream->id, stream->rst_error);
            }
            break;
        default:
            /* NOP */
            break;
    }
}

static void dispatch_event(h2_session *session, h2_session_event_t ev, 
                      int arg, const char *msg)
{
    switch (ev) {
        case H2_SESSION_EV_INIT:
            h2_session_ev_init(session, arg, msg);
            break;            
        case H2_SESSION_EV_LOCAL_GOAWAY:
            h2_session_ev_local_goaway(session, arg, msg);
            break;
        case H2_SESSION_EV_REMOTE_GOAWAY:
            h2_session_ev_remote_goaway(session, arg, msg);
            break;
        case H2_SESSION_EV_CONN_ERROR:
            h2_session_ev_conn_error(session, arg, msg);
            break;
        case H2_SESSION_EV_PROTO_ERROR:
            h2_session_ev_proto_error(session, arg, msg);
            break;
        case H2_SESSION_EV_CONN_TIMEOUT:
            h2_session_ev_conn_timeout(session, arg, msg);
            break;
        case H2_SESSION_EV_NO_IO:
            h2_session_ev_no_io(session, arg, msg);
            break;
        case H2_SESSION_EV_FRAME_RCVD:
            h2_session_ev_frame_rcvd(session, arg, msg);
            break;
        case H2_SESSION_EV_NGH2_DONE:
            h2_session_ev_ngh2_done(session, arg, msg);
            break;
        case H2_SESSION_EV_MPM_STOPPING:
            h2_session_ev_mpm_stopping(session, arg, msg);
            break;
        case H2_SESSION_EV_PRE_CLOSE:
            h2_session_ev_pre_close(session, arg, msg);
            break;
        case H2_SESSION_EV_STREAM_CHANGE:
            h2_session_ev_stream_change(session, arg, msg);
            break;
        default:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                          H2_SSSN_MSG(session, "unknown event %d"), ev);
            break;
    }
}

/* trigger window updates, stream resumes and submits */
static apr_status_t dispatch_master(h2_session *session) {
    apr_status_t status;
    
    status = h2_mplx_m_dispatch_master_events(session->mplx, 
                                            on_stream_resume, session);
    if (status == APR_EAGAIN) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, session->c,
                      H2_SSSN_MSG(session, "no master event available"));
    }
    else if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, session->c,
                      H2_SSSN_MSG(session, "dispatch error"));
        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 
                       H2_ERR_INTERNAL_ERROR, "dispatch error");
    }
    return status;
}

static const int MAX_WAIT_MICROS = 200 * 1000;

apr_status_t h2_session_process(h2_session *session, int async)
{
    apr_status_t status = APR_SUCCESS;
    conn_rec *c = session->c;
    int rv, mpm_state, trace = APLOGctrace3(c);
    apr_time_t now;
    
    if (trace) {
        ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                      H2_SSSN_MSG(session, "process start, async=%d"), async);
    }
                  
    while (session->state != H2_SESSION_ST_DONE) {
        now = apr_time_now();
        session->have_read = session->have_written = 0;

        if (session->local.accepting 
            && !ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state)) {
            if (mpm_state == AP_MPMQ_STOPPING) {
                dispatch_event(session, H2_SESSION_EV_MPM_STOPPING, 0, NULL);
            }
        }
        
        session->status[0] = '\0';
        
        switch (session->state) {
            case H2_SESSION_ST_INIT:
                ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_READ, c);
                if (!h2_is_acceptable_connection(c, session->r, 1)) {
                    update_child_status(session, SERVER_BUSY_READ, 
                                        "inadequate security");
                    h2_session_shutdown(session, 
                                        NGHTTP2_INADEQUATE_SECURITY, NULL, 1);
                } 
                else {
                    update_child_status(session, SERVER_BUSY_READ, "init");
                    status = h2_session_start(session, &rv);
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c, 
                                  H2_SSSN_LOG(APLOGNO(03079), session, 
                                  "started on %s:%d"), 
                                  session->s->server_hostname,
                                  c->local_addr->port);
                    if (status != APR_SUCCESS) {
                        dispatch_event(session, 
                                       H2_SESSION_EV_CONN_ERROR, 0, NULL);
                    }
                    dispatch_event(session, H2_SESSION_EV_INIT, 0, NULL);
                }
                break;
                
            case H2_SESSION_ST_IDLE:
                if (session->idle_until && (now + session->idle_delay) > session->idle_until) {
                    ap_log_cerror( APLOG_MARK, APLOG_TRACE1, status, c,
                                  H2_SSSN_MSG(session, "idle, timeout reached, closing"));
                    if (session->idle_delay) {
                        apr_table_setn(session->c->notes, "short-lingering-close", "1"); 
                    }
                    dispatch_event(session, H2_SESSION_EV_CONN_TIMEOUT, 0, "timeout");
                    goto out;
                }
                
                if (session->idle_delay) {
                    /* we are less interested in spending time on this connection */
                    ap_log_cerror( APLOG_MARK, APLOG_TRACE2, status, c,
                                  H2_SSSN_MSG(session, "session is idle (%ld ms), idle wait %ld sec left"), 
                                  (long)apr_time_as_msec(session->idle_delay),
                                  (long)apr_time_sec(session->idle_until - now));
                    apr_sleep(session->idle_delay);
                    session->idle_delay = 0;
                }

                h2_conn_io_flush(&session->io);
                if (async && !session->r && (now > session->idle_sync_until)) {
                    if (trace) {
                        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, c,
                                      H2_SSSN_MSG(session, 
                                      "nonblock read, %d streams open"), 
                                      session->open_streams);
                    }
                    status = h2_session_read(session, 0);
                    
                    if (status == APR_SUCCESS) {
                        session->have_read = 1;
                    }
                    else if (APR_STATUS_IS_EAGAIN(status) || APR_STATUS_IS_TIMEUP(status)) {
                        status = h2_mplx_m_idle(session->mplx);
                        if (status == APR_EAGAIN) {
                            break;
                        }
                        else if (status != APR_SUCCESS) {
                            dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 
                                           H2_ERR_ENHANCE_YOUR_CALM, "less is more");
                        }
                        status = APR_EAGAIN;
                        goto out;
                    }
                    else {
                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c,
                                      H2_SSSN_LOG(APLOGNO(03403), session, 
                                      "no data, error"));
                        dispatch_event(session, 
                                       H2_SESSION_EV_CONN_ERROR, 0, "timeout");
                    }
                }
                else {
                    /* make certain, we send everything before we idle */
                    if (trace) {
                        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, c,
                                      H2_SSSN_MSG(session, 
                                      "sync, stutter 1-sec, %d streams open"), 
                                      session->open_streams);
                    }
                    /* We wait in smaller increments, using a 1 second timeout.
                     * That gives us the chance to check for MPMQ_STOPPING often. 
                     */
                    status = h2_mplx_m_idle(session->mplx);
                    if (status == APR_EAGAIN) {
                        break;
                    }
                    else if (status != APR_SUCCESS) {
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 
                                       H2_ERR_ENHANCE_YOUR_CALM, "less is more");
                    }
                    h2_filter_cin_timeout_set(session->cin, apr_time_from_sec(1));
                    status = h2_session_read(session, 1);
                    if (status == APR_SUCCESS) {
                        session->have_read = 1;
                    }
                    else if (status == APR_EAGAIN) {
                        /* nothing to read */
                    }
                    else if (APR_STATUS_IS_TIMEUP(status)) {
                        /* continue reading handling */
                    }
                    else if (APR_STATUS_IS_ECONNABORTED(status)
                             || APR_STATUS_IS_ECONNRESET(status)
                             || APR_STATUS_IS_EOF(status)
                             || APR_STATUS_IS_EBADF(status)) {
                        ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                                      H2_SSSN_MSG(session, "input gone"));
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
                    }
                    else {
                        ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                                      H2_SSSN_MSG(session, 
                                      "(1 sec timeout) read failed"));
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, "error");
                    }
                }
                if (nghttp2_session_want_write(session->ngh2)) {
                    ap_update_child_status(session->c->sbh, SERVER_BUSY_WRITE, NULL);
                    status = h2_session_send(session);
                    if (status == APR_SUCCESS) {
                        status = h2_conn_io_flush(&session->io);
                    }
                    if (status != APR_SUCCESS) {
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 
                                       H2_ERR_INTERNAL_ERROR, "writing");
                        break;
                    }
                }
                break;
                
            case H2_SESSION_ST_BUSY:
                if (nghttp2_session_want_read(session->ngh2)) {
                    ap_update_child_status(session->c->sbh, SERVER_BUSY_READ, NULL);
                    h2_filter_cin_timeout_set(session->cin, session->s->timeout);
                    status = h2_session_read(session, 0);
                    if (status == APR_SUCCESS) {
                        session->have_read = 1;
                    }
                    else if (status == APR_EAGAIN) {
                        /* nothing to read */
                    }
                    else if (APR_STATUS_IS_TIMEUP(status)) {
                        dispatch_event(session, H2_SESSION_EV_CONN_TIMEOUT, 0, NULL);
                        break;
                    }
                    else {
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
                    }
                }

                status = dispatch_master(session);
                if (status != APR_SUCCESS && status != APR_EAGAIN) {
                    break;
                }
                
                if (nghttp2_session_want_write(session->ngh2)) {
                    ap_update_child_status(session->c->sbh, SERVER_BUSY_WRITE, NULL);
                    status = h2_session_send(session);
                    if (status == APR_SUCCESS) {
                        status = h2_conn_io_flush(&session->io);
                    }
                    if (status != APR_SUCCESS) {
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 
                                       H2_ERR_INTERNAL_ERROR, "writing");
                        break;
                    }
                }
                
                if (session->have_read || session->have_written) {
                    if (session->wait_us) {
                        session->wait_us = 0;
                    }
                }
                else if (!nghttp2_session_want_write(session->ngh2)) {
                    dispatch_event(session, H2_SESSION_EV_NO_IO, 0, NULL);
                }
                break;
                
            case H2_SESSION_ST_WAIT:
                if (session->wait_us <= 0) {
                    session->wait_us = 10;
                    if (h2_conn_io_flush(&session->io) != APR_SUCCESS) {
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
                        break;
                    }
                }
                else {
                    /* repeating, increase timer for graceful backoff */
                    session->wait_us = H2MIN(session->wait_us*2, MAX_WAIT_MICROS);
                }

                if (trace) {
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                                  "h2_session: wait for data, %ld micros", 
                                  (long)session->wait_us);
                }
                status = h2_mplx_m_out_trywait(session->mplx, session->wait_us, 
                                             session->iowait);
                if (status == APR_SUCCESS) {
                    session->wait_us = 0;
                        dispatch_event(session, H2_SESSION_EV_STREAM_CHANGE, 0, NULL);
                }
                else if (APR_STATUS_IS_TIMEUP(status)) {
                    /* go back to checking all inputs again */
                    transit(session, "wait cycle", session->local.shutdown? 
                            H2_SESSION_ST_DONE : H2_SESSION_ST_BUSY);
                }
                else if (APR_STATUS_IS_ECONNRESET(status) 
                         || APR_STATUS_IS_ECONNABORTED(status)) {
                    dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
                }
                else {
                    ap_log_cerror(APLOG_MARK, APLOG_WARNING, status, c,
                                  H2_SSSN_LOG(APLOGNO(03404), session, 
                                  "waiting on conditional"));
                    h2_session_shutdown(session, H2_ERR_INTERNAL_ERROR, 
                                        "cond wait error", 0);
                }
                break;
                
            default:
                ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                              H2_SSSN_LOG(APLOGNO(03080), session, 
                              "unknown state"));
                dispatch_event(session, H2_SESSION_EV_PROTO_ERROR, 0, NULL);
                break;
        }

        if (!nghttp2_session_want_read(session->ngh2) 
                 && !nghttp2_session_want_write(session->ngh2)) {
            dispatch_event(session, H2_SESSION_EV_NGH2_DONE, 0, NULL); 
        }
        if (session->reprioritize) {
            h2_mplx_m_reprioritize(session->mplx, stream_pri_cmp, session);
            session->reprioritize = 0;
        }
    }
    
out:
    if (trace) {
        ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                      H2_SSSN_MSG(session, "process returns")); 
    }
    
    if ((session->state != H2_SESSION_ST_DONE)
        && (APR_STATUS_IS_EOF(status)
            || APR_STATUS_IS_ECONNRESET(status) 
            || APR_STATUS_IS_ECONNABORTED(status))) {
        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
    }

    return (session->state == H2_SESSION_ST_DONE)? APR_EOF : APR_SUCCESS;
}

apr_status_t h2_session_pre_close(h2_session *session, int async)
{
    apr_status_t status;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c, 
                  H2_SSSN_MSG(session, "pre_close"));
    dispatch_event(session, H2_SESSION_EV_PRE_CLOSE, 0, 
        (session->state == H2_SESSION_ST_IDLE)? "timeout" : NULL);
    status = session_cleanup(session, "pre_close");
    if (status == APR_SUCCESS) {
        /* no one should hold a reference to this session any longer and
         * the h2_ctx was removed from the connection.
         * Take the pool (and thus all subpools etc. down now, instead of
         * during cleanup of main connection pool. */
        apr_pool_destroy(session->pool);
    }
    return status;
}
