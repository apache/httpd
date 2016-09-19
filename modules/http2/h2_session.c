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

#include "h2_private.h"
#include "h2.h"
#include "h2_bucket_eoc.h"
#include "h2_bucket_eos.h"
#include "h2_config.h"
#include "h2_ctx.h"
#include "h2_filter.h"
#include "h2_h2.h"
#include "h2_mplx.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_response.h"
#include "h2_stream.h"
#include "h2_from_h1.h"
#include "h2_task.h"
#include "h2_session.h"
#include "h2_util.h"
#include "h2_version.h"
#include "h2_workers.h"


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

static void update_window(void *ctx, int stream_id, apr_off_t bytes_read)
{
    h2_session *session = (h2_session*)ctx;
    nghttp2_session_consume(session->ngh2, stream_id, bytes_read);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                  "h2_session(%ld-%d): consumed %ld bytes",
                  session->id, stream_id, (long)bytes_read);
}

static apr_status_t h2_session_receive(void *ctx, 
                                       const char *data, apr_size_t len,
                                       apr_size_t *readlen);

static void dispatch_event(h2_session *session, h2_session_event_t ev, 
                             int err, const char *msg);

apr_status_t h2_session_stream_done(h2_session *session, h2_stream *stream)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                  "h2_stream(%ld-%d): EOS bucket cleanup -> done", 
                  session->id, stream->id);
    h2_ihash_remove(session->streams, stream->id);
    h2_mplx_stream_done(session->mplx, stream);
    
    dispatch_event(session, H2_SESSION_EV_STREAM_DONE, 0, NULL);
    return APR_SUCCESS;
}

typedef struct stream_sel_ctx {
    h2_session *session;
    h2_stream *candidate;
} stream_sel_ctx;

static int find_cleanup_stream(void *udata, void *sdata)
{
    stream_sel_ctx *ctx = udata;
    h2_stream *stream = sdata;
    if (H2_STREAM_CLIENT_INITIATED(stream->id)) {
        if (!ctx->session->local.accepting
            && stream->id > ctx->session->local.accepted_max) {
            ctx->candidate = stream;
            return 0;
        }
    }
    else {
        if (!ctx->session->remote.accepting
            && stream->id > ctx->session->remote.accepted_max) {
            ctx->candidate = stream;
            return 0;
        }
    }
    return 1;
}

static void cleanup_streams(h2_session *session)
{
    stream_sel_ctx ctx;
    ctx.session = session;
    ctx.candidate = NULL;
    while (1) {
        h2_ihash_iter(session->streams, find_cleanup_stream, &ctx);
        if (ctx.candidate) {
            h2_session_stream_done(session, ctx.candidate);
            ctx.candidate = NULL;
        }
        else {
            break;
        }
    }
}

h2_stream *h2_session_open_stream(h2_session *session, int stream_id,
                                  int initiated_on, const h2_request *req)
{
    h2_stream * stream;
    apr_pool_t *stream_pool;
    
    apr_pool_create(&stream_pool, session->pool);
    apr_pool_tag(stream_pool, "h2_stream");
    
    stream = h2_stream_open(stream_id, stream_pool, session, 
                            initiated_on, req);
    nghttp2_session_set_stream_user_data(session->ngh2, stream_id, stream);
    h2_ihash_add(session->streams, stream);
    
    if (H2_STREAM_CLIENT_INITIATED(stream_id)) {
        if (stream_id > session->remote.emitted_max) {
            ++session->remote.emitted_count;
            session->remote.emitted_max = stream->id;
            session->local.accepted_max = stream->id;
        }
    }
    else {
        if (stream_id > session->local.emitted_max) {
            ++session->local.emitted_count;
            session->remote.emitted_max = stream->id;
        }
    }
    dispatch_event(session, H2_SESSION_EV_STREAM_OPEN, 0, NULL);
    
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

static apr_status_t stream_schedule(h2_session *session,
                                    h2_stream *stream, int eos)
{
    (void)session;
    return h2_stream_schedule(stream, eos, h2_session_push_enabled(session), 
                              stream_pri_cmp, session);
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
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03063)
                      "h2_session(%ld): recv invalid FRAME[%s], frames=%ld/%ld (r/s)",
                      session->id, buffer, (long)session->frames_received,
                     (long)session->frames_sent);
    }
    return 0;
}

static h2_stream *get_stream(h2_session *session, int stream_id)
{
    return nghttp2_session_get_stream_user_data(session->ngh2, stream_id);
}

static int on_data_chunk_recv_cb(nghttp2_session *ngh2, uint8_t flags,
                                 int32_t stream_id,
                                 const uint8_t *data, size_t len, void *userp)
{
    h2_session *session = (h2_session *)userp;
    apr_status_t status = APR_SUCCESS;
    h2_stream * stream;
    int rv;
    
    (void)flags;
    stream = get_stream(session, stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03064)
                      "h2_stream(%ld-%d): on_data_chunk for unknown stream",
                      session->id, (int)stream_id);
        rv = nghttp2_submit_rst_stream(ngh2, NGHTTP2_FLAG_NONE, stream_id,
                                       NGHTTP2_INTERNAL_ERROR);
        if (nghttp2_is_fatal(rv)) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    /* FIXME: enabling setting EOS this way seems to break input handling
     * in mod_proxy_http2. why? */
    status = h2_stream_write_data(stream, (const char *)data, len,
                                  0 /*flags & NGHTTP2_FLAG_END_STREAM*/);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c,
                  "h2_stream(%ld-%d): data_chunk_recv, written %ld bytes",
                  session->id, stream_id, (long)len);
    if (status != APR_SUCCESS) {
        update_window(session, stream_id, len);
        rv = nghttp2_submit_rst_stream(ngh2, NGHTTP2_FLAG_NONE, stream_id,
                                       H2_STREAM_RST(stream, H2_ERR_INTERNAL_ERROR));
        if (nghttp2_is_fatal(rv)) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return 0;
}

static apr_status_t stream_release(h2_session *session, 
                                   h2_stream *stream,
                                   uint32_t error_code) 
{
    conn_rec *c = session->c;
    apr_bucket *b;
    apr_status_t status;
    
    if (!error_code) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_stream(%ld-%d): handled, closing", 
                      session->id, (int)stream->id);
        if (H2_STREAM_CLIENT_INITIATED(stream->id)) {
            if (stream->id > session->local.completed_max) {
                session->local.completed_max = stream->id;
            }
        }
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03065)
                      "h2_stream(%ld-%d): closing with err=%d %s", 
                      session->id, (int)stream->id, (int)error_code,
                      h2_h2_err_description(error_code));
        h2_stream_rst(stream, error_code);
    }
    
    b = h2_bucket_eos_create(c->bucket_alloc, stream);
    APR_BRIGADE_INSERT_TAIL(session->bbtmp, b);
    status = h2_conn_io_pass(&session->io, session->bbtmp);
    apr_brigade_cleanup(session->bbtmp);
    return status;
}

static int on_stream_close_cb(nghttp2_session *ngh2, int32_t stream_id,
                              uint32_t error_code, void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream *stream;
    
    (void)ngh2;
    stream = get_stream(session, stream_id);
    if (stream) {
        stream_release(session, stream, error_code);
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
        s = h2_session_open_stream(userp, frame->hd.stream_id, 0, NULL);
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
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, session->c,
                      APLOGNO(02920) 
                      "h2_session:  stream(%ld-%d): on_header unknown stream",
                      session->id, (int)frame->hd.stream_id);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    
    status = h2_stream_add_header(stream, (const char *)name, namelen,
                                  (const char *)value, valuelen);
    if (status != APR_SUCCESS && !stream->response) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    return 0;
}

/**
 * nghttp2 session has received a complete frame. Most, it uses
 * for processing of internal state. HEADER and DATA frames however
 * we need to handle ourself.
 */
static int on_frame_recv_cb(nghttp2_session *ng2s,
                            const nghttp2_frame *frame,
                            void *userp)
{
    h2_session *session = (h2_session *)userp;
    apr_status_t status = APR_SUCCESS;
    h2_stream *stream;
    
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03066)
                      "h2_session(%ld): recv FRAME[%s], frames=%ld/%ld (r/s)",
                      session->id, buffer, (long)session->frames_received,
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
                int eos = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM);
                
                if (h2_stream_is_scheduled(stream)) {
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                                  "h2_stream(%ld-%d): TRAILER, eos=%d", 
                                  session->id, frame->hd.stream_id, eos);
                    if (eos) {
                        status = h2_stream_close_input(stream);
                    }
                }
                else {
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                                  "h2_stream(%ld-%d): HEADER, eos=%d", 
                                  session->id, frame->hd.stream_id, eos);
                    status = stream_schedule(session, stream, eos);
                }
            }
            else {
                status = APR_EINVAL;
            }
            break;
        case NGHTTP2_DATA:
            stream = get_stream(session, frame->hd.stream_id);
            if (stream) {
                int eos = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                              "h2_stream(%ld-%d): DATA, len=%ld, eos=%d", 
                              session->id, frame->hd.stream_id, 
                              (long)frame->hd.length, eos);
                if (eos) {
                    status = h2_stream_close_input(stream);
                }
            }
            else {
                status = APR_EINVAL;
            }
            break;
        case NGHTTP2_PRIORITY:
            session->reprioritize = 1;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                          "h2_session:  stream(%ld-%d): PRIORITY frame "
                          " weight=%d, dependsOn=%d, exclusive=%d", 
                          session->id, (int)frame->hd.stream_id,
                          frame->priority.pri_spec.weight,
                          frame->priority.pri_spec.stream_id,
                          frame->priority.pri_spec.exclusive);
            break;
        case NGHTTP2_WINDOW_UPDATE:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                          "h2_session:  stream(%ld-%d): WINDOW_UPDATE "
                          "incr=%d", 
                          session->id, (int)frame->hd.stream_id,
                          frame->window_update.window_size_increment);
            break;
        case NGHTTP2_RST_STREAM:
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03067)
                          "h2_session(%ld-%d): RST_STREAM by client, errror=%d",
                          session->id, (int)frame->hd.stream_id,
                          (int)frame->rst_stream.error_code);
            stream = get_stream(session, frame->hd.stream_id);
            if (stream && stream->request && stream->request->initiated_on) {
                ++session->pushes_reset;
            }
            else {
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
        default:
            if (APLOGctrace2(session->c)) {
                char buffer[256];
                
                h2_util_frame_print(frame, buffer,
                                    sizeof(buffer)/sizeof(buffer[0]));
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                              "h2_session: on_frame_rcv %s", buffer);
            }
            break;
    }

    if (status != APR_SUCCESS) {
        int rv;
        
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c,
                      APLOGNO(02923) 
                      "h2_session: stream(%ld-%d): error handling frame",
                      session->id, (int)frame->hd.stream_id);
        rv = nghttp2_submit_rst_stream(ng2s, NGHTTP2_FLAG_NONE,
                                       frame->hd.stream_id,
                                       NGHTTP2_INTERNAL_ERROR);
        if (nghttp2_is_fatal(rv)) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    
    return 0;
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
    if (frame->data.padlen > H2_MAX_PADLEN) {
        return NGHTTP2_ERR_PROTO;
    }
    padlen = (unsigned char)frame->data.padlen;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                  "h2_stream(%ld-%d): send_data_cb for %ld bytes",
                  session->id, (int)stream_id, (long)length);
                  
    stream = get_stream(session, stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_NOTFOUND, session->c,
                      APLOGNO(02924) 
                      "h2_stream(%ld-%d): send_data, lookup stream",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    status = h2_conn_io_write(&session->io, (const char *)framehd, 9);
    if (padlen && status == APR_SUCCESS) {
        status = h2_conn_io_write(&session->io, (const char *)&padlen, 1);
    }
    
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c,
                      "h2_stream(%ld-%d): writing frame header",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    status = h2_stream_read_to(stream, session->bbtmp, &len, &eos);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c,
                      "h2_stream(%ld-%d): send_data_cb, reading stream",
                      session->id, (int)stream_id);
        apr_brigade_cleanup(session->bbtmp);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    else if (len != length) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c,
                      "h2_stream(%ld-%d): send_data_cb, wanted %ld bytes, "
                      "got %ld from stream",
                      session->id, (int)stream_id, (long)length, (long)len);
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
                      APLOGNO(02925) 
                      "h2_stream(%ld-%d): failed send_data_cb",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
}

static int on_frame_send_cb(nghttp2_session *ngh2, 
                            const nghttp2_frame *frame,
                            void *user_data)
{
    h2_session *session = user_data;
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03068)
                      "h2_session(%ld): sent FRAME[%s], frames=%ld/%ld (r/s)",
                      session->id, buffer, (long)session->frames_received,
                     (long)session->frames_sent);
    }
    ++session->frames_sent;
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
    if (APLOGcdebug(session->c)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03456)
                      "h2_session(%ld-%d): denying stream with invalid header "
                      "'%s: %s'", session->id, (int)frame->hd.stream_id,
                      apr_pstrndup(session->pool, (const char *)name, namelen),
                      apr_pstrndup(session->pool, (const char *)value, valuelen));
    }
    return nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE,
                                     frame->hd.stream_id, 
                                     NGHTTP2_PROTOCOL_ERROR);
}
#endif

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
    return APR_SUCCESS;
}

static void h2_session_destroy(h2_session *session)
{
    AP_DEBUG_ASSERT(session);    

    h2_ihash_clear(session->streams);
    if (session->mplx) {
        h2_mplx_set_consumed_cb(session->mplx, NULL, NULL);
        h2_mplx_release_and_join(session->mplx, session->iowait);
        session->mplx = NULL;
    }

    ap_remove_input_filter_byhandle((session->r? session->r->input_filters :
                                     session->c->input_filters), "H2_IN");
    if (session->ngh2) {
        nghttp2_session_del(session->ngh2);
        session->ngh2 = NULL;
    }
    if (session->c) {
        h2_ctx_clear(session->c);
    }

    if (APLOGctrace1(session->c)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                      "h2_session(%ld): destroy", session->id);
    }
    if (session->pool) {
        apr_pool_destroy(session->pool);
    }
}

static apr_status_t h2_session_shutdown_notice(h2_session *session)
{
    apr_status_t status;
    
    AP_DEBUG_ASSERT(session);
    if (!session->local.accepting) {
        return APR_SUCCESS;
    }
    
    nghttp2_submit_shutdown_notice(session->ngh2);
    session->local.accepting = 0;
    status = nghttp2_session_send(session->ngh2);
    if (status == APR_SUCCESS) {
        status = h2_conn_io_flush(&session->io);
    }
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03457)
                  "session(%ld): sent shutdown notice", session->id);
    return status;
}

static apr_status_t h2_session_shutdown(h2_session *session, int error, 
                                        const char *msg, int force_close)
{
    apr_status_t status = APR_SUCCESS;
    
    AP_DEBUG_ASSERT(session);
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
        session->local.accepted_max = h2_mplx_shutdown(session->mplx);
        session->local.error = error;
    }
    else {
        /* graceful shutdown. we will continue processing all streams
         * we have, but no longer accept new ones. Report the max stream
         * we have received and discard all new ones. */
    }
    nghttp2_submit_goaway(session->ngh2, NGHTTP2_FLAG_NONE, 
                          session->local.accepted_max, 
                          error, (uint8_t*)msg, msg? strlen(msg):0);
    session->local.accepting = 0;
    session->local.shutdown = 1;
    status = nghttp2_session_send(session->ngh2);
    if (status == APR_SUCCESS) {
        status = h2_conn_io_flush(&session->io);
    }
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03069)
                  "session(%ld): sent GOAWAY, err=%d, msg=%s", 
                  session->id, error, msg? msg : "");
    dispatch_event(session, H2_SESSION_EV_LOCAL_GOAWAY, error, msg);
    
    if (force_close) {
        apr_brigade_cleanup(session->bbtmp);
        h2_mplx_abort(session->mplx);
    }
    
    return status;
}

static apr_status_t session_pool_cleanup(void *data)
{
    h2_session *session = data;
    /* On a controlled connection shutdown, this gets never
     * called as we deregister and destroy our pool manually.
     * However when we have an async mpm, and handed it our idle
     * connection, it will just cleanup once the connection is closed
     * from the other side (and sometimes even from out side) and
     * here we arrive then.
     */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                  "session(%ld): pool_cleanup", session->id);
    
    if (session->state != H2_SESSION_ST_DONE) {
        /* Not good. The connection is being torn down and we have
         * not sent a goaway. This is considered a protocol error and
         * the client has to assume that any streams "in flight" may have
         * been processed and are not safe to retry.
         * As clients with idle connection may only learn about a closed
         * connection when sending the next request, this has the effect
         * that at least this one request will fail.
         */
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, session->c, APLOGNO(03199)
                      "session(%ld): connection disappeared without proper "
                      "goodbye, clients will be confused, should not happen", 
                      session->id);
    }
    /* keep us from destroying the pool, since that is already ongoing. */
    session->pool = NULL;
    h2_session_destroy(session);
    return APR_SUCCESS;
}

static void *session_malloc(size_t size, void *ctx)
{
    h2_session *session = ctx;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, session->c,
                  "h2_session(%ld): malloc(%ld)",
                  session->id, (long)size);
    return malloc(size);
}

static void session_free(void *p, void *ctx)
{
    h2_session *session = ctx;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, session->c,
                  "h2_session(%ld): free()",
                  session->id);
    free(p);
}

static void *session_calloc(size_t n, size_t size, void *ctx)
{
    h2_session *session = ctx;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, session->c,
                  "h2_session(%ld): calloc(%ld, %ld)",
                  session->id, (long)n, (long)size);
    return calloc(n, size);
}

static void *session_realloc(void *p, size_t size, void *ctx)
{
    h2_session *session = ctx;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, session->c,
                  "h2_session(%ld): realloc(%ld)",
                  session->id, (long)size);
    return realloc(p, size);
}

static h2_session *h2_session_create_int(conn_rec *c,
                                         request_rec *r,
                                         h2_ctx *ctx, 
                                         h2_workers *workers)
{
    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_option *options = NULL;
    uint32_t n;

    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, c->pool);
    h2_session *session;
    if (status != APR_SUCCESS) {
        return NULL;
    }
    apr_pool_tag(pool, "h2_session");

    session = apr_pcalloc(pool, sizeof(h2_session));
    if (session) {
        int rv;
        nghttp2_mem *mem;
        
        session->id = c->id;
        session->c = c;
        session->r = r;
        session->s = h2_ctx_server_get(ctx);
        session->pool = pool;
        session->config = h2_config_sget(session->s);
        session->workers = workers;
        
        session->state = H2_SESSION_ST_INIT;
        session->local.accepting = 1;
        session->remote.accepting = 1;
        
        apr_pool_pre_cleanup_register(pool, session, session_pool_cleanup);
        
        session->max_stream_count = h2_config_geti(session->config, 
                                                   H2_CONF_MAX_STREAMS);
        session->max_stream_mem = h2_config_geti(session->config, 
                                                 H2_CONF_STREAM_MAX_MEM);

        status = apr_thread_cond_create(&session->iowait, session->pool);
        if (status != APR_SUCCESS) {
            return NULL;
        }
        
        session->streams = h2_ihash_create(session->pool,
                                           offsetof(h2_stream, id));
        session->mplx = h2_mplx_create(c, session->pool, session->config, 
                                       session->s->timeout, workers);
        
        h2_mplx_set_consumed_cb(session->mplx, update_window, session);
        
        /* Install the connection input filter that feeds the session */
        session->cin = h2_filter_cin_create(session->pool, 
                                            h2_session_receive, session);
        ap_add_input_filter("H2_IN", session->cin, r, c);

        h2_conn_io_init(&session->io, c, session->config);
        session->bbtmp = apr_brigade_create(session->pool, c->bucket_alloc);
        
        status = init_callbacks(c, &callbacks);
        if (status != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c, APLOGNO(02927) 
                          "nghttp2: error in init_callbacks");
            h2_session_destroy(session);
            return NULL;
        }
        
        rv = nghttp2_option_new(&options);
        if (rv != 0) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                          APLOGNO(02928) "nghttp2_option_new: %s", 
                          nghttp2_strerror(rv));
            h2_session_destroy(session);
            return NULL;
        }
        nghttp2_option_set_peer_max_concurrent_streams(
            options, (uint32_t)session->max_stream_count);
        /* We need to handle window updates ourself, otherwise we
         * get flooded by nghttp2. */
        nghttp2_option_set_no_auto_window_update(options, 1);
        
        if (APLOGctrace6(c)) {
            mem = apr_pcalloc(session->pool, sizeof(nghttp2_mem));
            mem->mem_user_data = session;
            mem->malloc    = session_malloc;
            mem->free      = session_free;
            mem->calloc    = session_calloc;
            mem->realloc   = session_realloc;
            
            rv = nghttp2_session_server_new3(&session->ngh2, callbacks,
                                             session, options, mem);
        }
        else {
            rv = nghttp2_session_server_new2(&session->ngh2, callbacks,
                                             session, options);
        }
        nghttp2_session_callbacks_del(callbacks);
        nghttp2_option_del(options);
        
        if (rv != 0) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                          APLOGNO(02929) "nghttp2_session_server_new: %s",
                          nghttp2_strerror(rv));
            h2_session_destroy(session);
            return NULL;
        }
         
        n = h2_config_geti(session->config, H2_CONF_PUSH_DIARY_SIZE);
        session->push_diary = h2_push_diary_create(session->pool, n);
        
        if (APLOGcdebug(c)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03200)
                          "h2_session(%ld) created, max_streams=%d, "
                          "stream_mem=%d, workers_limit=%d, workers_max=%d, "
                          "push_diary(type=%d,N=%d)",
                          session->id, (int)session->max_stream_count, 
                          (int)session->max_stream_mem,
                          session->mplx->workers_limit, 
                          session->mplx->workers_max, 
                          session->push_diary->dtype, 
                          (int)session->push_diary->N);
        }
    }
    return session;
}

h2_session *h2_session_create(conn_rec *c, h2_ctx *ctx, h2_workers *workers)
{
    return h2_session_create_int(c, NULL, ctx, workers);
}

h2_session *h2_session_rcreate(request_rec *r, h2_ctx *ctx, h2_workers *workers)
{
    return h2_session_create_int(r->connection, r, ctx, workers);
}

void h2_session_eoc_callback(h2_session *session)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                  "session(%ld): cleanup and destroy", session->id);
    apr_pool_cleanup_kill(session->pool, session, session_pool_cleanup);
    h2_session_destroy(session);
}

static apr_status_t h2_session_start(h2_session *session, int *rv)
{
    apr_status_t status = APR_SUCCESS;
    nghttp2_settings_entry settings[3];
    size_t slen;
    int win_size;
    
    AP_DEBUG_ASSERT(session);
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
        stream = h2_session_open_stream(session, 1, 0, NULL);
        if (!stream) {
            status = APR_EGENERAL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, session->r,
                          APLOGNO(02933) "open stream 1: %s", 
                          nghttp2_strerror(*rv));
            return status;
        }
        
        status = h2_stream_set_request(stream, session->r);
        if (status != APR_SUCCESS) {
            return status;
        }
        status = stream_schedule(session, stream, 1);
        if (status != APR_SUCCESS) {
            return status;
        }
    }

    slen = 0;
    settings[slen].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    settings[slen].value = (uint32_t)session->max_stream_count;
    ++slen;
    win_size = h2_config_geti(session->config, H2_CONF_WIN_SIZE);
    if (win_size != H2_INITIAL_WINDOW_SIZE) {
        settings[slen].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
        settings[slen].value = win_size;
        ++slen;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, APLOGNO(03201)
                  "h2_session(%ld): start, INITIAL_WINDOW_SIZE=%ld, "
                  "MAX_CONCURRENT_STREAMS=%d", 
                  session->id, (long)win_size, (int)session->max_stream_count);
    *rv = nghttp2_submit_settings(session->ngh2, NGHTTP2_FLAG_NONE,
                                  settings, slen);
    if (*rv != 0) {
        status = APR_EGENERAL;
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c,
                      APLOGNO(02935) "nghttp2_submit_settings: %s", 
                      nghttp2_strerror(*rv));
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
                          APLOGNO(02970) "nghttp2_submit_window_update: %s", 
                          nghttp2_strerror(*rv));        
        }
    }
    
    return status;
}

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
    AP_DEBUG_ASSERT(session);
    
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
                      "h2_stream(%ld-%d): data requested but stream not found",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    status = h2_stream_out_prepare(stream, &nread, &eos);
    if (nread) {
        *data_flags |=  NGHTTP2_DATA_FLAG_NO_COPY;
    }
    
    switch (status) {
        case APR_SUCCESS:
            break;
            
        case APR_ECONNABORTED:
        case APR_ECONNRESET:
            return nghttp2_submit_rst_stream(ng2s, NGHTTP2_FLAG_NONE,
                stream->id, H2_STREAM_RST(stream, H2_ERR_INTERNAL_ERROR));
            
        case APR_EAGAIN:
            /* If there is no data available, our session will automatically
             * suspend this stream and not ask for more data until we resume
             * it. Remember at our h2_stream that we need to do this.
             */
            nread = 0;
            h2_mplx_suspend_stream(session->mplx, stream->id);
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03071)
                          "h2_stream(%ld-%d): suspending",
                          session->id, (int)stream_id);
            return NGHTTP2_ERR_DEFERRED;
            
        default:
            nread = 0;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c,
                          APLOGNO(02938) "h2_stream(%ld-%d): reading data",
                          session->id, (int)stream_id);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (eos) {
        apr_table_t *trailers = h2_stream_get_trailers(stream);
        if (trailers && !apr_is_empty_table(trailers)) {
            h2_ngheader *nh;
            int rv;
            
            nh = h2_util_ngheader_make(stream->pool, trailers);
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03072)
                          "h2_stream(%ld-%d): submit %d trailers",
                          session->id, (int)stream_id,(int) nh->nvlen);
            rv = nghttp2_submit_trailer(ng2s, stream->id, nh->nv, nh->nvlen);
            if (rv < 0) {
                nread = rv;
            }
            *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        }
        
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    
    return (ssize_t)nread;
}

struct h2_stream *h2_session_push(h2_session *session, h2_stream *is,
                                  h2_push *push)
{
    apr_status_t status;
    h2_stream *stream;
    h2_ngheader *ngh;
    int nid;
    
    ngh = h2_util_ngheader_make_req(is->pool, push->req);
    nid = nghttp2_submit_push_promise(session->ngh2, 0, is->id, 
                                      ngh->nv, ngh->nvlen, NULL);
    if (nid <= 0) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03075)
                      "h2_stream(%ld-%d): submitting push promise fail: %s",
                      session->id, is->id, nghttp2_strerror(nid));
        return NULL;
    }
    ++session->pushes_promised;
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03076)
                  "h2_stream(%ld-%d): SERVER_PUSH %d for %s %s on %d",
                  session->id, is->id, nid,
                  push->req->method, push->req->path, is->id);
                  
    stream = h2_session_open_stream(session, nid, is->id, push->req);
    if (stream) {
        status = stream_schedule(session, stream, 1);
        if (status != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c,
                          "h2_stream(%ld-%d): scheduling push stream",
                          session->id, stream->id);
            stream = NULL;
        }
        ++session->unsent_promises;
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03077)
                      "h2_stream(%ld-%d): failed to create stream obj %d",
                      session->id, is->id, nid);
    }

    if (!stream) {
        /* try to tell the client that it should not wait. */
        nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE, nid,
                                  NGHTTP2_INTERNAL_ERROR);
    }
    
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
    
    s = nghttp2_session_find_stream(session->ngh2, stream->id);
    if (!s) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                      "h2_stream(%ld-%d): lookup of nghttp2_stream failed",
                      session->id, stream->id);
        return APR_EINVAL;
    }
    
    s_parent = nghttp2_stream_get_parent(s);
    if (s_parent) {
        nghttp2_priority_spec ps;
        int id_parent, id_grandpa, w_parent, w, rv = 0;
        char *ptype = "AFTER";
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
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03203)
                      "h2_stream(%ld-%d): PUSH %s, weight=%d, "
                      "depends=%d, returned=%d",
                      session->id, stream->id, ptype, 
                      ps.weight, ps.stream_id, rv);
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
            && h2_config_geti(session->config, H2_CONF_PUSH)
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
    if (rv != 0) {
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
 * A stream was resumed as new output data arrived.
 */
static apr_status_t on_stream_resume(void *ctx, int stream_id)
{
    h2_session *session = ctx;
    h2_stream *stream = get_stream(session, stream_id);
    apr_status_t status = APR_SUCCESS;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c, 
                  "h2_stream(%ld-%d): on_resume", session->id, stream_id);
    if (stream) {
        int rv;
        if (stream->rst_error) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO()
                          "h2_stream(%ld-%d): RST_STREAM, err=%d",
                          session->id, stream->id, stream->rst_error);
            rv = nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE,
                                           stream->id, stream->rst_error);
        }
        else {
            rv = nghttp2_session_resume_data(session->ngh2, stream_id);
        }
        session->have_written = 1;
        ap_log_cerror(APLOG_MARK, nghttp2_is_fatal(rv)?
                      APLOG_ERR : APLOG_DEBUG, 0, session->c,
                      APLOGNO(02936) 
                      "h2_stream(%ld-%d): resuming %s",
                      session->id, stream->id, rv? nghttp2_strerror(rv) : "");
    }
    return status;
}

/**
 * A response for the stream is ready.
 */
static apr_status_t on_stream_response(void *ctx, int stream_id)
{
    h2_session *session = ctx;
    h2_stream *stream = get_stream(session, stream_id);
    apr_status_t status = APR_SUCCESS;
    h2_response *response;
    int rv = 0;

    AP_DEBUG_ASSERT(session);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c, 
                  "h2_stream(%ld-%d): on_response", session->id, stream_id);
    if (!stream) {
        return APR_NOTFOUND;
    }
    else if (stream->rst_error || !stream->response) {
        int err = H2_STREAM_RST(stream, H2_ERR_PROTOCOL_ERROR);
        
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03074)
                      "h2_stream(%ld-%d): RST_STREAM, err=%d",
                      session->id, stream->id, err);

        rv = nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE,
                                       stream->id, err);
        goto leave;
    }
    
    while ((response = h2_stream_get_unsent_response(stream)) != NULL) {
        nghttp2_data_provider provider, *pprovider = NULL;
        h2_ngheader *ngh;
        const h2_priority *prio;
        
        if (stream->submitted) {
            rv = NGHTTP2_PROTOCOL_ERROR;
            goto leave;
        }
        
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03073)
                      "h2_stream(%ld-%d): submit response %d, REMOTE_WINDOW_SIZE=%u",
                      session->id, stream->id, response->http_status,
                      (unsigned int)nghttp2_session_get_stream_remote_window_size(session->ngh2, stream->id));
        
        if (response->content_length != 0) {
            memset(&provider, 0, sizeof(provider));
            provider.source.fd = stream->id;
            provider.read_callback = stream_data_cb;
            pprovider = &provider;
        }
        
        /* If this stream is not a pushed one itself,
         * and HTTP/2 server push is enabled here,
         * and the response is in the range 200-299 *),
         * and the remote side has pushing enabled,
         * -> find and perform any pushes on this stream
         *    *before* we submit the stream response itself.
         *    This helps clients avoid opening new streams on Link
         *    headers that get pushed right afterwards.
         * 
         * *) the response code is relevant, as we do not want to 
         *    make pushes on 401 or 403 codes, neiterh on 301/302
         *    and friends. And if we see a 304, we do not push either
         *    as the client, having this resource in its cache, might
         *    also have the pushed ones as well.
         */
        if (stream->request 
            && !stream->request->initiated_on
            && h2_response_is_final(response)
            && H2_HTTP_2XX(response->http_status)
            && h2_session_push_enabled(session)) {
            
            h2_stream_submit_pushes(stream);
        }
        
        prio = h2_stream_get_priority(stream);
        if (prio) {
            h2_session_set_prio(session, stream, prio);
        }
        
        ngh = h2_util_ngheader_make_res(stream->pool, response->http_status, 
                                        response->headers);
        rv = nghttp2_submit_response(session->ngh2, response->stream_id,
                                     ngh->nv, ngh->nvlen, pprovider);
        stream->submitted = h2_response_is_final(response);
        session->have_written = 1;
        
        if (stream->request && stream->request->initiated_on) {
            ++session->pushes_submitted;
        }
        else {
            ++session->responses_submitted;
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

static apr_status_t h2_session_receive(void *ctx, const char *data, 
                                       apr_size_t len, apr_size_t *readlen)
{
    h2_session *session = ctx;
    ssize_t n;
    
    if (len > 0) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                      "h2_session(%ld): feeding %ld bytes to nghttp2",
                      session->id, (long)len);
        n = nghttp2_session_mem_recv(session->ngh2, (const uint8_t *)data, len);
        if (n < 0) {
            if (nghttp2_is_fatal((int)n)) {
                dispatch_event(session, H2_SESSION_EV_PROTO_ERROR, (int)n, nghttp2_strerror(n));
                return APR_EGENERAL;
            }
        }
        else {
            *readlen = n;
            session->io.bytes_read += n;
        }
    }
    return APR_SUCCESS;
}

static apr_status_t h2_session_read(h2_session *session, int block)
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
                                APR_BUCKET_BUFF_SIZE);
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
                        ap_log_cerror( APLOG_MARK, APLOG_TRACE1, status, c,
                                      "h2_session(%ld): input gone", session->id);
                    }
                    else {
                        /* uncommon status, log on INFO so that we see this */
                        ap_log_cerror( APLOG_MARK, APLOG_DEBUG, status, c,
                                      APLOGNO(02950) 
                                      "h2_session(%ld): error reading, terminating",
                                      session->id);
                    }
                    return status;
                }
                /* subsequent failure after success(es), return initial
                 * status. */
                return rstatus;
        }
        if ((session->io.bytes_read - read_start) > (64*1024)) {
            /* read enough in one go, give write a chance */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, c,
                          "h2_session(%ld): read 64k, returning", session->id);
            break;
        }
    }
    return rstatus;
}

static const char *StateNames[] = {
    "INIT",      /* H2_SESSION_ST_INIT */
    "DONE",      /* H2_SESSION_ST_DONE */
    "IDLE",      /* H2_SESSION_ST_IDLE */
    "BUSY",      /* H2_SESSION_ST_BUSY */
    "WAIT",      /* H2_SESSION_ST_WAIT */
};

static const char *state_name(h2_session_state state)
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
    if (session->state != nstate) {
        int loglvl = APLOG_DEBUG;
        if ((session->state == H2_SESSION_ST_BUSY && nstate == H2_SESSION_ST_WAIT)
            || (session->state == H2_SESSION_ST_WAIT && nstate == H2_SESSION_ST_BUSY)){
            loglvl = APLOG_TRACE1;
        }
        ap_log_cerror(APLOG_MARK, loglvl, 0, session->c, APLOGNO(03078)
                      "h2_session(%ld): transit [%s] -- %s --> [%s]", session->id,
                      state_name(session->state), action, state_name(nstate));
        session->state = nstate;
        switch (session->state) {
            case H2_SESSION_ST_IDLE:
                update_child_status(session, (session->open_streams == 0? 
                                              SERVER_BUSY_KEEPALIVE
                                              : SERVER_BUSY_READ), "idle");
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
    cleanup_streams(session);
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
        cleanup_streams(session);
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
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03401)
                          "h2_session(%ld): conn error -> shutdown", session->id);
            h2_session_shutdown(session, arg, msg, 0);
            break;
    }
}

static void h2_session_ev_proto_error(h2_session *session, int arg, const char *msg)
{
    if (!session->local.shutdown) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03402)
                      "h2_session(%ld): proto error -> shutdown", session->id);
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
                          "h2_session(%ld): NO_IO event, %d streams open", 
                          session->id, session->open_streams);
            h2_conn_io_flush(&session->io);
            if (session->open_streams > 0) {
                if (h2_mplx_is_busy(session->mplx)) {
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
                    session->idle_until = apr_time_now() + session->s->timeout;
                    session->keep_sync_until = session->idle_until;
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
                apr_time_t now = apr_time_now();
                transit(session, "no io (keepalive)", H2_SESSION_ST_IDLE);
                session->idle_until = (session->remote.emitted_count? 
                                       session->s->keep_alive_timeout : 
                                       session->s->timeout) + now;
                session->keep_sync_until = now + apr_time_from_sec(1);
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

static void h2_session_ev_stream_ready(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_WAIT:
            transit(session, "stream ready", H2_SESSION_ST_BUSY);
            break;
        default:
            /* nop */
            break;
    }
}

static void h2_session_ev_data_read(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_IDLE:
        case H2_SESSION_ST_WAIT:
            transit(session, "data read", H2_SESSION_ST_BUSY);
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
            break;
    }
}

static void h2_session_ev_pre_close(h2_session *session, int arg, const char *msg)
{
    h2_session_shutdown(session, arg, msg, 1);
}

static void h2_session_ev_stream_open(h2_session *session, int arg, const char *msg)
{
    ++session->open_streams;
    switch (session->state) {
        case H2_SESSION_ST_IDLE:
            if (session->open_streams == 1) {
                /* enter tiomeout, since we have a stream again */
                session->idle_until = (session->s->timeout + apr_time_now());
            }
            break;
        default:
            break;
    }
}

static void h2_session_ev_stream_done(h2_session *session, int arg, const char *msg)
{
    --session->open_streams;
    switch (session->state) {
        case H2_SESSION_ST_IDLE:
            if (session->open_streams == 0) {
                /* enter keepalive timeout, since we no longer have streams */
                session->idle_until = (session->s->keep_alive_timeout
                                       + apr_time_now());
            }
            break;
        default:
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
        case H2_SESSION_EV_STREAM_READY:
            h2_session_ev_stream_ready(session, arg, msg);
            break;
        case H2_SESSION_EV_DATA_READ:
            h2_session_ev_data_read(session, arg, msg);
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
        case H2_SESSION_EV_STREAM_OPEN:
            h2_session_ev_stream_open(session, arg, msg);
            break;
        case H2_SESSION_EV_STREAM_DONE:
            h2_session_ev_stream_done(session, arg, msg);
            break;
        default:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                          "h2_session(%ld): unknown event %d", 
                          session->id, ev);
            break;
    }
    
    if (session->state == H2_SESSION_ST_DONE) {
        apr_brigade_cleanup(session->bbtmp);
        h2_mplx_abort(session->mplx);
    }
}

static const int MAX_WAIT_MICROS = 200 * 1000;

apr_status_t h2_session_process(h2_session *session, int async)
{
    apr_status_t status = APR_SUCCESS;
    conn_rec *c = session->c;
    int rv, mpm_state, trace = APLOGctrace3(c);

    if (trace) {
        ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                      "h2_session(%ld): process start, async=%d", 
                      session->id, async);
    }
                  
    if (c->cs) {
        c->cs->state = CONN_STATE_WRITE_COMPLETION;
    }
    
    while (session->state != H2_SESSION_ST_DONE) {
        trace = APLOGctrace3(c);
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
                if (!h2_is_acceptable_connection(c, 1)) {
                    update_child_status(session, SERVER_BUSY_READ, "inadequate security");
                    h2_session_shutdown(session, NGHTTP2_INADEQUATE_SECURITY, NULL, 1);
                } 
                else {
                    update_child_status(session, SERVER_BUSY_READ, "init");
                    status = h2_session_start(session, &rv);
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c, APLOGNO(03079)
                                  "h2_session(%ld): started on %s:%d", session->id,
                                  session->s->server_hostname,
                                  c->local_addr->port);
                    if (status != APR_SUCCESS) {
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
                    }
                    dispatch_event(session, H2_SESSION_EV_INIT, 0, NULL);
                }
                break;
                
            case H2_SESSION_ST_IDLE:
                /* make certain, we send everything before we idle */
                h2_conn_io_flush(&session->io);
                if (!session->keep_sync_until && async && !session->open_streams
                    && !session->r && session->remote.emitted_count) {
                    if (trace) {
                        ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                                      "h2_session(%ld): async idle, nonblock read, "
                                      "%d streams open", session->id, 
                                      session->open_streams);
                    }
                    /* We do not return to the async mpm immediately, since under
                     * load, mpms show the tendency to throw keep_alive connections
                     * away very rapidly.
                     * So, if we are still processing streams, we wait for the
                     * normal timeout first and, on timeout, close.
                     * If we have no streams, we still wait a short amount of
                     * time here for the next frame to arrive, before handing
                     * it to keep_alive processing of the mpm.
                     */
                    status = h2_session_read(session, 0);
                    
                    if (status == APR_SUCCESS) {
                        session->have_read = 1;
                        dispatch_event(session, H2_SESSION_EV_DATA_READ, 0, NULL);
                    }
                    else if (APR_STATUS_IS_EAGAIN(status) || APR_STATUS_IS_TIMEUP(status)) {
                        if (apr_time_now() > session->idle_until) {
                            dispatch_event(session, H2_SESSION_EV_CONN_TIMEOUT, 0, NULL);
                        }
                        else {
                            status = APR_EAGAIN;
                            goto out;
                        }
                    }
                    else {
                        ap_log_cerror( APLOG_MARK, APLOG_DEBUG, status, c,
				      APLOGNO(03403)
                                      "h2_session(%ld): idle, no data, error", 
                                      session->id);
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, "timeout");
                    }
                }
                else {
                    if (trace) {
                        ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                                      "h2_session(%ld): sync idle, stutter 1-sec, "
                                      "%d streams open", session->id,
                                      session->open_streams);
                    }
                    /* We wait in smaller increments, using a 1 second timeout.
                     * That gives us the chance to check for MPMQ_STOPPING often. 
                     */
                    status = h2_mplx_idle(session->mplx);
                    if (status != APR_SUCCESS) {
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 
                                       H2_ERR_ENHANCE_YOUR_CALM, "less is more");
                    }
                    h2_filter_cin_timeout_set(session->cin, apr_time_from_sec(1));
                    status = h2_session_read(session, 1);
                    if (status == APR_SUCCESS) {
                        session->have_read = 1;
                        dispatch_event(session, H2_SESSION_EV_DATA_READ, 0, NULL);
                    }
                    else if (status == APR_EAGAIN) {
                        /* nothing to read */
                    }
                    else if (APR_STATUS_IS_TIMEUP(status)) {
                        apr_time_t now = apr_time_now();
                        if (now > session->keep_sync_until) {
                            /* if we are on an async mpm, now is the time that
                             * we may dare to pass control to it. */
                            session->keep_sync_until = 0;
                        }
                        if (now > session->idle_until) {
                            if (trace) {
                                ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                                              "h2_session(%ld): keepalive timeout",
                                              session->id);
                            }
                            dispatch_event(session, H2_SESSION_EV_CONN_TIMEOUT, 0, "timeout");
                        }
                        else if (trace) {                        
                            ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                                          "h2_session(%ld): keepalive, %f sec left",
                                          session->id, (session->idle_until - now) / 1000000.0f);
                        }
                        /* continue reading handling */
                    }
                    else {
                        if (trace) {
                            ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                                          "h2_session(%ld): idle(1 sec timeout) "
                                          "read failed", session->id);
                        }
                        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, "error");
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
                        dispatch_event(session, H2_SESSION_EV_DATA_READ, 0, NULL);
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
                
                /* trigger window updates, stream resumes and submits */
                status = h2_mplx_dispatch_master_events(session->mplx, 
                                                        on_stream_resume,
                                                        on_stream_response, 
                                                        session);
                if (status != APR_SUCCESS) {
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, c,
                                  "h2_session(%ld): dispatch error", 
                                  session->id);
                    dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 
                                   H2_ERR_INTERNAL_ERROR, 
                                   "dispatch error");
                    break;
                }
                
                if (nghttp2_session_want_write(session->ngh2)) {
                    ap_update_child_status(session->c->sbh, SERVER_BUSY_WRITE, NULL);
                    status = h2_session_send(session);
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
                status = h2_mplx_out_trywait(session->mplx, session->wait_us, 
                                             session->iowait);
                if (status == APR_SUCCESS) {
                    session->wait_us = 0;
                    dispatch_event(session, H2_SESSION_EV_DATA_READ, 0, NULL);
                }
                else if (APR_STATUS_IS_TIMEUP(status)) {
                    /* go back to checking all inputs again */
                    transit(session, "wait cycle", session->local.accepting? 
                            H2_SESSION_ST_BUSY : H2_SESSION_ST_DONE);
                }
                else if (APR_STATUS_IS_ECONNRESET(status) 
                         || APR_STATUS_IS_ECONNABORTED(status)) {
                    dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
                }
                else {
                    ap_log_cerror(APLOG_MARK, APLOG_WARNING, status, c,
				  APLOGNO(03404)
                                  "h2_session(%ld): waiting on conditional",
                                  session->id);
                    h2_session_shutdown(session, H2_ERR_INTERNAL_ERROR, 
                                        "cond wait error", 0);
                }
                break;
                
            default:
                ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                              APLOGNO(03080)
                              "h2_session(%ld): unknown state %d", session->id, session->state);
                dispatch_event(session, H2_SESSION_EV_PROTO_ERROR, 0, NULL);
                break;
        }

        if (!nghttp2_session_want_read(session->ngh2) 
                 && !nghttp2_session_want_write(session->ngh2)) {
            dispatch_event(session, H2_SESSION_EV_NGH2_DONE, 0, NULL); 
        }
        if (session->reprioritize) {
            h2_mplx_reprioritize(session->mplx, stream_pri_cmp, session);
            session->reprioritize = 0;
        }
    }
    
out:
    if (trace) {
        ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                      "h2_session(%ld): [%s] process returns", 
                      session->id, state_name(session->state));
    }
    
    if ((session->state != H2_SESSION_ST_DONE)
        && (APR_STATUS_IS_EOF(status)
            || APR_STATUS_IS_ECONNRESET(status) 
            || APR_STATUS_IS_ECONNABORTED(status))) {
        dispatch_event(session, H2_SESSION_EV_CONN_ERROR, 0, NULL);
    }

    status = APR_SUCCESS;
    if (session->state == H2_SESSION_ST_DONE) {
        status = APR_EOF;
        if (!session->eoc_written) {
            session->eoc_written = 1;
            h2_conn_io_write_eoc(&session->io, session);
        }
    }
    
    return status;
}

apr_status_t h2_session_pre_close(h2_session *session, int async)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c, 
                  "h2_session(%ld): pre_close", session->id);
    dispatch_event(session, H2_SESSION_EV_PRE_CLOSE, 0, 
        (session->state == H2_SESSION_ST_IDLE)? "timeout" : NULL);
    return APR_SUCCESS;
}
