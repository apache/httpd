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
#include <apr_thread_cond.h>
#include <apr_base64.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <scoreboard.h>

#include "h2_private.h"
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
#include "h2_stream_set.h"
#include "h2_from_h1.h"
#include "h2_task.h"
#include "h2_session.h"
#include "h2_util.h"
#include "h2_version.h"
#include "h2_workers.h"

#define H2MAX(x,y) ((x) > (y) ? (x) : (y))
#define H2MIN(x,y) ((x) < (y) ? (x) : (y))

static int frame_print(const nghttp2_frame *frame, char *buffer, size_t maxlen);

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

h2_stream *h2_session_open_stream(h2_session *session, int stream_id)
{
    h2_stream * stream;
    apr_pool_t *stream_pool;
    if (session->aborted) {
        return NULL;
    }
    
    if (session->spare) {
        stream_pool = session->spare;
        session->spare = NULL;
    }
    else {
        apr_pool_create(&stream_pool, session->pool);
    }
    
    stream = h2_stream_open(stream_id, stream_pool, session);
    
    h2_stream_set_add(session->streams, stream);
    if (H2_STREAM_CLIENT_INITIATED(stream_id)
        && stream_id > session->max_stream_received) {
        session->max_stream_received = stream->id;
    }
    
    return stream;
}

#ifdef H2_NG2_STREAM_API

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

#else /* ifdef H2_NG2_STREAM_API */

/* In absence of nghttp2_stream API, which gives information about
 * priorities since nghttp2 1.3.x, we just sort the streams by
 * their identifier, aka. order of arrival.
 */
static int stream_pri_cmp(int sid1, int sid2, void *ctx)
{
    (void)ctx;
    return sid1 - sid2;
}

#endif /* (ifdef else) H2_NG2_STREAM_API */

static apr_status_t stream_schedule(h2_session *session,
                                    h2_stream *stream, int eos)
{
    (void)session;
    ++session->requests_received;
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
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c,
                  "h2_session: send error");
    return h2_session_status_from_apr_status(status);
}

static int on_invalid_frame_recv_cb(nghttp2_session *ngh2,
                                    const nghttp2_frame *frame,
                                    int error, void *userp)
{
    h2_session *session = (h2_session *)userp;
    (void)ngh2;
    
    if (session->aborted) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if (APLOGctrace2(session->c)) {
        char buffer[256];
        
        frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                      "h2_session: callback on_invalid_frame_recv error=%d %s",
                      error, buffer);
    }
    return 0;
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
    if (session->aborted) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    stream = h2_session_get_stream(session, stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                      "h2_stream(%ld-%d): on_data_chunk for unknown stream",
                      session->id, (int)stream_id);
        rv = nghttp2_submit_rst_stream(ngh2, NGHTTP2_FLAG_NONE, stream_id,
                                       NGHTTP2_INTERNAL_ERROR);
        if (nghttp2_is_fatal(rv)) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }
    
    status = h2_stream_write_data(stream, (const char *)data, len);
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
    if (!error_code) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                      "h2_stream(%ld-%d): handled, closing", 
                      session->id, (int)stream->id);
        if (stream->id > session->max_stream_handled) {
            session->max_stream_handled = stream->id;
        }
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                      "h2_stream(%ld-%d): closing with err=%d %s", 
                      session->id, (int)stream->id, (int)error_code,
                      h2_h2_err_description(error_code));
        h2_stream_rst(stream, error_code);
    }
    
    return h2_conn_io_writeb(&session->io,
                             h2_bucket_eos_create(session->c->bucket_alloc, 
                                                  stream));
}

static int on_stream_close_cb(nghttp2_session *ngh2, int32_t stream_id,
                              uint32_t error_code, void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream *stream;
    
    (void)ngh2;
    if (session->aborted) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    stream = h2_session_get_stream(session, stream_id);
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
    s = h2_session_get_stream(session, frame->hd.stream_id);
    if (s) {
        /* nop */
    }
    else {
        s = h2_session_open_stream((h2_session *)userp, frame->hd.stream_id);
    }
    return s? 0 : NGHTTP2_ERR_CALLBACK_FAILURE;
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
    
    (void)ngh2;
    (void)flags;
    if (session->aborted) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    stream = h2_session_get_stream(session, frame->hd.stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, session->c,
                      APLOGNO(02920) 
                      "h2_session:  stream(%ld-%d): on_header for unknown stream",
                      session->id, (int)frame->hd.stream_id);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    
    status = h2_stream_add_header(stream, (const char *)name, namelen,
                                  (const char *)value, valuelen);
                                    
    if (status != APR_SUCCESS) {
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
    
    if (session->aborted) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
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
            stream = h2_session_get_stream(session, frame->hd.stream_id);
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
            stream = h2_session_get_stream(session, frame->hd.stream_id);
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
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                          "h2_session(%ld-%d): RST_STREAM by client, errror=%d",
                          session->id, (int)frame->hd.stream_id,
                          (int)frame->rst_stream.error_code);
            ++session->streams_reset;
            break;
        case NGHTTP2_GOAWAY:
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                          "h2_session(%ld): GOAWAY errror=%d",
                          session->id, (int)frame->goaway.error_code);
            session->client_goaway = 1;
            break;
        default:
            if (APLOGctrace2(session->c)) {
                char buffer[256];
                
                frame_print(frame, buffer,
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

static apr_status_t pass_data(void *ctx, 
                              const char *data, apr_off_t length)
{
    return h2_conn_io_write(&((h2_session*)ctx)->io, data, length);
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
    
    (void)ngh2;
    (void)source;
    if (session->aborted) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (frame->data.padlen > H2_MAX_PADLEN) {
        return NGHTTP2_ERR_PROTO;
    }
    padlen = (unsigned char)frame->data.padlen;
    
    stream = h2_session_get_stream(session, stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_NOTFOUND, session->c,
                      APLOGNO(02924) 
                      "h2_stream(%ld-%d): send_data",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                  "h2_stream(%ld-%d): send_data_cb for %ld bytes",
                  session->id, (int)stream_id, (long)length);
                  
    if (h2_conn_io_is_buffered(&session->io)) {
        status = h2_conn_io_write(&session->io, (const char *)framehd, 9);
        if (status == APR_SUCCESS) {
            if (padlen) {
                status = h2_conn_io_write(&session->io, (const char *)&padlen, 1);
            }
            
            if (status == APR_SUCCESS) {
                apr_off_t len = length;
                status = h2_stream_readx(stream, pass_data, session, &len, &eos);
                if (status == APR_SUCCESS && len != length) {
                    status = APR_EINVAL;
                }
            }
            
            if (status == APR_SUCCESS && padlen) {
                if (padlen) {
                    status = h2_conn_io_write(&session->io, immortal_zeros, padlen);
                }
            }
        }
    }
    else {
        apr_bucket *b;
        char *header = apr_pcalloc(stream->pool, 10);
        memcpy(header, (const char *)framehd, 9);
        if (padlen) {
            header[9] = (char)padlen;
        }
        b = apr_bucket_pool_create(header, padlen? 10 : 9, 
                                   stream->pool, session->c->bucket_alloc);
        status = h2_conn_io_writeb(&session->io, b);
        
        if (status == APR_SUCCESS) {
            apr_off_t len = length;
            status = h2_stream_read_to(stream, session->io.output, &len, &eos);
            if (status == APR_SUCCESS && len != length) {
                status = APR_EINVAL;
            }
        }
            
        if (status == APR_SUCCESS && padlen) {
            b = apr_bucket_immortal_create(immortal_zeros, padlen, 
                                           session->c->bucket_alloc);
            status = h2_conn_io_writeb(&session->io, b);
        }
    }
    
    
    if (status == APR_SUCCESS) {
        stream->data_frames_sent++;
        h2_conn_io_consider_flush(&session->io);
        return 0;
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c,
                      APLOGNO(02925) 
                      "h2_stream(%ld-%d): failed send_data_cb",
                      session->id, (int)stream_id);
    }
    
    return h2_session_status_from_apr_status(status);
}

static int on_frame_send_cb(nghttp2_session *ngh2, 
                            const nghttp2_frame *frame,
                            void *user_data)
{
    h2_session *session = user_data;
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                      "h2_session(%ld): sent FRAME[%s], frames=%ld/%ld (r/s)",
                      session->id, buffer, (long)session->frames_received,
                     (long)session->frames_sent);
    }
    ++session->frames_sent;
    return 0;
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

    return APR_SUCCESS;
}

static void h2_session_cleanup(h2_session *session)
{
    AP_DEBUG_ASSERT(session);
    /* This is an early cleanup of the session that may
     * discard what is no longer necessary for *new* streams
     * and general HTTP/2 processing.
     * At this point, all frames are in transit or somehwere in
     * our buffers or passed down output filters.
     * h2 streams might still being written out.
     */
    if (session->c) {
        h2_ctx_clear(session->c);
    }
    if (session->ngh2) {
        nghttp2_session_del(session->ngh2);
        session->ngh2 = NULL;
    }
    if (session->spare) {
        apr_pool_destroy(session->spare);
        session->spare = NULL;
    }
}

static void h2_session_destroy(h2_session *session)
{
    AP_DEBUG_ASSERT(session);
    h2_session_cleanup(session);

    if (APLOGctrace1(session->c)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                      "h2_session(%ld): destroy, %d streams open",
                      session->id, (int)h2_stream_set_size(session->streams));
    }
    if (session->mplx) {
        h2_mplx_set_consumed_cb(session->mplx, NULL, NULL);
        h2_mplx_release_and_join(session->mplx, session->iowait);
        session->mplx = NULL;
    }
    if (session->streams) {
        h2_stream_set_destroy(session->streams);
        session->streams = NULL;
    }
    if (session->pool) {
        apr_pool_destroy(session->pool);
    }
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

    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, c->pool);
    h2_session *session;
    if (status != APR_SUCCESS) {
        return NULL;
    }

    session = apr_pcalloc(pool, sizeof(h2_session));
    if (session) {
        int rv;
        nghttp2_mem *mem;
        
        session->id = c->id;
        session->c = c;
        session->r = r;
        session->s = h2_ctx_server_get(ctx);
        session->config = h2_config_sget(session->s);
        
        session->state = H2_SESSION_ST_INIT;
        
        session->pool = pool;
        apr_pool_pre_cleanup_register(pool, session, session_pool_cleanup);
        
        session->max_stream_count = h2_config_geti(session->config, H2_CONF_MAX_STREAMS);
        session->max_stream_mem = h2_config_geti(session->config, H2_CONF_STREAM_MAX_MEM);
        session->timeout_secs = h2_config_geti(session->config, H2_CONF_TIMEOUT_SECS);
        if (session->timeout_secs <= 0) {
            session->timeout_secs = apr_time_sec(session->s->timeout);
        }
        session->keepalive_secs = h2_config_geti(session->config, H2_CONF_KEEPALIVE_SECS);
        if (session->keepalive_secs <= 0) {
            session->keepalive_secs = apr_time_sec(session->s->keep_alive_timeout);
        }
        
        status = apr_thread_cond_create(&session->iowait, session->pool);
        if (status != APR_SUCCESS) {
            return NULL;
        }
        
        session->streams = h2_stream_set_create(session->pool, session->max_stream_count);
        
        session->workers = workers;
        session->mplx = h2_mplx_create(c, session->pool, session->config, workers);
        
        h2_mplx_set_consumed_cb(session->mplx, update_window, session);
        
        /* Install the connection input filter that feeds the session */
        session->cin = h2_filter_cin_create(session->pool, h2_session_receive, session);
        ap_add_input_filter("H2_IN", session->cin, r, c);

        h2_conn_io_init(&session->io, c, session->config, session->pool);
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
        nghttp2_option_set_peer_max_concurrent_streams(options, 
                                                       (uint32_t)session->max_stream_count);
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
            
        if (APLOGcdebug(c)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                          "session(%ld) created, timeout=%d, keepalive_timeout=%d, "
                          "max_streams=%d, stream_mem=%d",
                          session->id, session->timeout_secs, session->keepalive_secs,
                          (int)session->max_stream_count, (int)session->max_stream_mem);
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

static apr_status_t h2_session_shutdown(h2_session *session, int reason)
{
    AP_DEBUG_ASSERT(session);
    session->aborted = 1;
    if (session->state != H2_SESSION_ST_CLOSING
        && session->state != H2_SESSION_ST_ABORTED) {
        if (session->client_goaway) {
            /* client sent us a GOAWAY, just terminate */
            nghttp2_session_terminate_session(session->ngh2, NGHTTP2_ERR_EOF);
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                          "session(%ld): shutdown, GOAWAY from client", session->id);
        }
        else if (!reason) {
            nghttp2_submit_goaway(session->ngh2, NGHTTP2_FLAG_NONE, 
                                  session->max_stream_received, 
                                  reason, NULL, 0);
            nghttp2_session_send(session->ngh2);
            session->server_goaway = 1;
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                          "session(%ld): shutdown, no err", session->id);
        }
        else {
            const char *err = nghttp2_strerror(reason);
            nghttp2_submit_goaway(session->ngh2, NGHTTP2_FLAG_NONE, 
                                  session->max_stream_received, 
                                  reason, (const uint8_t *)err, 
                                  strlen(err));
            nghttp2_session_send(session->ngh2);
            session->server_goaway = 1;
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                          "session(%ld): shutdown, err=%d '%s'",
                          session->id, reason, err);
        }
        session->state = H2_SESSION_ST_CLOSING;
        h2_mplx_abort(session->mplx);
    }
    return APR_SUCCESS;
}

void h2_session_abort(h2_session *session, apr_status_t status)
{
    AP_DEBUG_ASSERT(session);
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c,
                  "h2_session(%ld): aborting", session->id);
    session->state = H2_SESSION_ST_ABORTED;
    session->aborted = 1;
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
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, session->r,
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
        stream = h2_session_open_stream(session, 1);
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

typedef struct {
    h2_session *session;
    int resume_count;
} resume_ctx;

static int resume_on_data(void *ctx, h2_stream *stream)
{
    resume_ctx *rctx = (resume_ctx*)ctx;
    h2_session *session = rctx->session;
    AP_DEBUG_ASSERT(session);
    AP_DEBUG_ASSERT(stream);
    
    if (h2_stream_is_suspended(stream)) {
        if (h2_mplx_out_has_data_for(stream->session->mplx, stream->id)) {
            int rv;
            h2_stream_set_suspended(stream, 0);
            ++rctx->resume_count;
            
            rv = nghttp2_session_resume_data(session->ngh2, stream->id);
            ap_log_cerror(APLOG_MARK, nghttp2_is_fatal(rv)?
                          APLOG_ERR : APLOG_DEBUG, 0, session->c,
                          APLOGNO(02936) 
                          "h2_stream(%ld-%d): resuming %s",
                          session->id, stream->id, rv? nghttp2_strerror(rv) : "");
        }
    }
    return 1;
}

static int h2_session_resume_streams_with_data(h2_session *session)
{
    AP_DEBUG_ASSERT(session);
    if (!h2_stream_set_is_empty(session->streams)
        && session->mplx && !session->aborted) {
        resume_ctx ctx;
        
        ctx.session      = session;
        ctx.resume_count = 0;

        /* Resume all streams where we have data in the out queue and
         * which had been suspended before. */
        h2_stream_set_iter(session->streams, resume_on_data, &ctx);
        return ctx.resume_count;
    }
    return 0;
}

h2_stream *h2_session_get_stream(h2_session *session, int stream_id)
{
    if (!session->last_stream || stream_id != session->last_stream->id) {
        session->last_stream = h2_stream_set_get(session->streams, stream_id);
    }
    return session->last_stream;
}

void h2_session_close(h2_session *session)
{
    apr_bucket *b;
    conn_rec *c = session->c;
    apr_status_t status;
    
    AP_DEBUG_ASSERT(session);
    if (!session->aborted) {
        h2_session_shutdown(session, 0);
    }
    h2_session_cleanup(session);

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "h2_session(%ld): writing eoc", c->id);
    b = h2_bucket_eoc_create(c->bucket_alloc, session);
    status = h2_conn_io_write_eoc(&session->io, b);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
                      "h2_session(%ld): flushed eoc bucket", c->id);
    } 
    /* and all is or will be destroyed */
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
    stream = h2_session_get_stream(session, stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, session->c,
                      APLOGNO(02937) 
                      "h2_stream(%ld-%d): data requested but stream not found",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    AP_DEBUG_ASSERT(!h2_stream_is_suspended(stream));
    
    status = h2_stream_prep_read(stream, &nread, &eos);
    if (nread) {
        *data_flags |=  NGHTTP2_DATA_FLAG_NO_COPY;
    }
    
    switch (status) {
        case APR_SUCCESS:
            break;
            
        case APR_ECONNRESET:
            return nghttp2_submit_rst_stream(ng2s, NGHTTP2_FLAG_NONE,
                stream->id, stream->rst_error);
            
        case APR_EAGAIN:
            /* If there is no data available, our session will automatically
             * suspend this stream and not ask for more data until we resume
             * it. Remember at our h2_stream that we need to do this.
             */
            nread = 0;
            h2_stream_set_suspended(stream, 1);
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                          "h2_stream(%ld-%d): suspending",
                          session->id, (int)stream_id);
            return NGHTTP2_ERR_DEFERRED;
            
        case APR_EOF:
            nread = 0;
            eos = 1;
            break;
            
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
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
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

typedef struct {
    nghttp2_nv *nv;
    size_t nvlen;
    size_t offset;
} nvctx_t;

/**
 * Start submitting the response to a stream request. This is possible
 * once we have all the response headers. The response body will be
 * read by the session using the callback we supply.
 */
static apr_status_t submit_response(h2_session *session, h2_stream *stream)
{
    apr_status_t status = APR_SUCCESS;
    int rv = 0;
    AP_DEBUG_ASSERT(session);
    AP_DEBUG_ASSERT(stream);
    AP_DEBUG_ASSERT(stream->response || stream->rst_error);
    
    if (stream->submitted) {
        rv = NGHTTP2_PROTOCOL_ERROR;
    }
    else if (stream->response && stream->response->headers) {
        nghttp2_data_provider provider;
        h2_response *response = stream->response;
        h2_ngheader *ngh;
        const h2_priority *prio;
        
        memset(&provider, 0, sizeof(provider));
        provider.source.fd = stream->id;
        provider.read_callback = stream_data_cb;
        
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                      "h2_stream(%ld-%d): submit response %d",
                      session->id, stream->id, response->http_status);
        
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
        if (!stream->initiated_on
            && H2_HTTP_2XX(response->http_status)
            && h2_session_push_enabled(session)) {
            
            h2_stream_submit_pushes(stream);
        }
        
        prio = h2_stream_get_priority(stream);
        if (prio) {
            h2_session_set_prio(session, stream, prio);
            /* no showstopper if that fails for some reason */
        }
        
        ngh = h2_util_ngheader_make_res(stream->pool, response->http_status, 
                                        response->headers);
        rv = nghttp2_submit_response(session->ngh2, response->stream_id,
                                     ngh->nv, ngh->nvlen, &provider);
        ++session->responses_sent;
    }
    else {
        int err = H2_STREAM_RST(stream, H2_ERR_PROTOCOL_ERROR);
        
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                      "h2_stream(%ld-%d): RST_STREAM, err=%d",
                      session->id, stream->id, err);

        rv = nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE,
                                       stream->id, err);
        ++session->responses_sent;
    }
    
    stream->submitted = 1;

    if (nghttp2_is_fatal(rv)) {
        status = APR_EGENERAL;
        h2_session_shutdown(session, rv);
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c,
                      APLOGNO(02940) "submit_response: %s", 
                      nghttp2_strerror(rv));
    }
    
    return status;
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
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                      "h2_stream(%ld-%d): submitting push promise fail: %s",
                      session->id, is->id, nghttp2_strerror(nid));
        return NULL;
    }
    ++session->streams_pushed;
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                  "h2_stream(%ld-%d): SERVER_PUSH %d for %s %s on %d",
                  session->id, is->id, nid,
                  push->req->method, push->req->path, is->id);
                  
    stream = h2_session_open_stream(session, nid);
    if (stream) {
        h2_stream_set_h2_request(stream, is->id, push->req);
        status = stream_schedule(session, stream, 1);
        if (status != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c,
                          "h2_stream(%ld-%d): scheduling push stream",
                          session->id, stream->id);
            h2_stream_cleanup(stream);
            stream = NULL;
        }
        ++session->unsent_promises;
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
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
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
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

apr_status_t h2_session_stream_destroy(h2_session *session, h2_stream *stream)
{
    apr_pool_t *pool = h2_stream_detach_pool(stream);

    /* this may be called while the session has already freed
     * some internal structures. */
    if (session->mplx) {
        h2_mplx_stream_done(session->mplx, stream->id, stream->rst_error);
        if (session->last_stream == stream) {
            session->last_stream = NULL;
        }
    }
    
    if (session->streams) {
        h2_stream_set_remove(session->streams, stream->id);
    }
    h2_stream_destroy(stream);
    
    if (pool) {
        apr_pool_clear(pool);
        if (session->spare) {
            apr_pool_destroy(session->spare);
        }
        session->spare = pool;
    }
    return APR_SUCCESS;
}

static int frame_print(const nghttp2_frame *frame, char *buffer, size_t maxlen)
{
    char scratch[128];
    size_t s_len = sizeof(scratch)/sizeof(scratch[0]);
    
    switch (frame->hd.type) {
        case NGHTTP2_DATA: {
            return apr_snprintf(buffer, maxlen,
                                "DATA[length=%d, flags=%d, stream=%d, padlen=%d]",
                                (int)frame->hd.length, frame->hd.flags,
                                frame->hd.stream_id, (int)frame->data.padlen);
        }
        case NGHTTP2_HEADERS: {
            return apr_snprintf(buffer, maxlen,
                                "HEADERS[length=%d, hend=%d, stream=%d, eos=%d]",
                                (int)frame->hd.length,
                                !!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS),
                                frame->hd.stream_id,
                                !!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM));
        }
        case NGHTTP2_PRIORITY: {
            return apr_snprintf(buffer, maxlen,
                                "PRIORITY[length=%d, flags=%d, stream=%d]",
                                (int)frame->hd.length,
                                frame->hd.flags, frame->hd.stream_id);
        }
        case NGHTTP2_RST_STREAM: {
            return apr_snprintf(buffer, maxlen,
                                "RST_STREAM[length=%d, flags=%d, stream=%d]",
                                (int)frame->hd.length,
                                frame->hd.flags, frame->hd.stream_id);
        }
        case NGHTTP2_SETTINGS: {
            if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
                return apr_snprintf(buffer, maxlen,
                                    "SETTINGS[ack=1, stream=%d]",
                                    frame->hd.stream_id);
            }
            return apr_snprintf(buffer, maxlen,
                                "SETTINGS[length=%d, stream=%d]",
                                (int)frame->hd.length, frame->hd.stream_id);
        }
        case NGHTTP2_PUSH_PROMISE: {
            return apr_snprintf(buffer, maxlen,
                                "PUSH_PROMISE[length=%d, hend=%d, stream=%d]",
                                (int)frame->hd.length,
                                !!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS),
                                frame->hd.stream_id);
        }
        case NGHTTP2_PING: {
            return apr_snprintf(buffer, maxlen,
                                "PING[length=%d, ack=%d, stream=%d]",
                                (int)frame->hd.length,
                                frame->hd.flags&NGHTTP2_FLAG_ACK,
                                frame->hd.stream_id);
        }
        case NGHTTP2_GOAWAY: {
            size_t len = (frame->goaway.opaque_data_len < s_len)?
            frame->goaway.opaque_data_len : s_len-1;
            memcpy(scratch, frame->goaway.opaque_data, len);
            scratch[len+1] = '\0';
            return apr_snprintf(buffer, maxlen, "GOAWAY[error=%d, reason='%s']",
                                frame->goaway.error_code, scratch);
        }
        case NGHTTP2_WINDOW_UPDATE: {
            return apr_snprintf(buffer, maxlen,
                                "WINDOW_UPDATE[length=%d, stream=%d]",
                                (int)frame->hd.length, frame->hd.stream_id);
        }
        default:
            return apr_snprintf(buffer, maxlen,
                                "type=%d[length=%d, flags=%d, stream=%d]",
                                frame->hd.type, (int)frame->hd.length,
                                frame->hd.flags, frame->hd.stream_id);
    }
}

int h2_session_push_enabled(h2_session *session)
{
    /* iff we can and they can */
    return (h2_config_geti(session->config, H2_CONF_PUSH)
            && nghttp2_session_get_remote_settings(session->ngh2, 
                                                   NGHTTP2_SETTINGS_ENABLE_PUSH));
}

static apr_status_t h2_session_send(h2_session *session)
{
    int rv = nghttp2_session_send(session->ngh2);
    if (rv != 0) {
        if (nghttp2_is_fatal(rv)) {
            ap_log_cerror( APLOG_MARK, APLOG_DEBUG, 0, session->c,
                          "h2_session: send gave error=%s", nghttp2_strerror(rv));
            h2_session_shutdown(session, rv);
            return APR_EGENERAL;
        }
    }
    
    session->unsent_promises = 0;
    session->unsent_submits = 0;
    
    return APR_SUCCESS;
}

static apr_status_t h2_session_receive(void *ctx, const char *data, 
                                       apr_size_t len, apr_size_t *readlen)
{
    h2_session *session = ctx;
    if (len > 0) {
        ssize_t n = nghttp2_session_mem_recv(session->ngh2,
                                             (const uint8_t *)data, len);
        if (n < 0) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL,
                          session->c,
                          "h2_session: nghttp2_session_mem_recv error=%d",
                          (int)n);
            if (nghttp2_is_fatal((int)n)) {
                h2_session_shutdown(session, (int)n);
                return APR_EGENERAL;
            }
        }
        else {
            *readlen = n;
        }
    }
    return APR_SUCCESS;
}

static apr_status_t h2_session_read(h2_session *session, int block, int loops)
{
    apr_status_t status, rstatus = APR_EAGAIN;
    conn_rec *c = session->c;
    int i;
    
    for (i = 0; i < loops; ++i) {
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
                    /* successfull blocked read, try unblocked to
                     * get more. */
                    block = 0;
                }
                break;
            case APR_EAGAIN:
                return rstatus;
            case APR_TIMEUP:
                return status;
            default:
                if (!i) {
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
                        ap_log_cerror( APLOG_MARK, APLOG_INFO, status, c,
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
    }
    return rstatus;
}

static apr_status_t h2_session_submit(h2_session *session)
{
    apr_status_t status = APR_EAGAIN;
    h2_stream *stream;
    
    if (h2_stream_set_has_unsubmitted(session->streams)) {
        /* If we have responses ready, submit them now. */
        while ((stream = h2_mplx_next_submit(session->mplx, session->streams))) {
            status = submit_response(session, stream);
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
                if (status != APR_SUCCESS) {
                    break;
                }
            }
        }
    }
    return status;
}

static const int MAX_WAIT_MICROS = 200 * 1000;

apr_status_t h2_session_process(h2_session *session, int async)
{
    apr_status_t status = APR_SUCCESS;
    conn_rec *c = session->c;
    int rv, have_written, have_read, remain_secs;
    const char *reason = "";

    ap_log_cerror( APLOG_MARK, APLOG_TRACE1, status, c,
                  "h2_session(%ld): process start, async=%d", session->id, async);
                  
    while (1) {
        have_read = have_written = 0;

        if (session->aborted) {
            reason = "aborted";
            status = APR_ECONNABORTED;
            goto out;
        }
        
        switch (session->state) {
            case H2_SESSION_ST_INIT:
                if (!h2_is_acceptable_connection(c, 1)) {
                    nghttp2_submit_goaway(session->ngh2, NGHTTP2_FLAG_NONE, 0,
                                          NGHTTP2_INADEQUATE_SECURITY, NULL, 0);
                    nghttp2_session_send(session->ngh2);
                    session->server_goaway = 1;
                } 
                
                status = h2_session_start(session, &rv);
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c,
                              "h2_session(%ld): started on %s:%d", session->id,
                              session->s->server_hostname,
                              c->local_addr->port);
                if (status != APR_SUCCESS) {
                    reason = "start failed";
                    goto out;
                }
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                  "h2_session(%ld): INIT -> BUSY", session->id);
                session->state = H2_SESSION_ST_BUSY;
                break;
                
            case H2_SESSION_ST_IDLE_READ:
                h2_filter_cin_timeout_set(session->cin, session->timeout_secs);
                ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);
                status = h2_session_read(session, 1, 10);
                if (APR_STATUS_IS_TIMEUP(status)) {
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                  "h2_session(%ld): IDLE -> KEEPALIVE", session->id);
                    session->state = H2_SESSION_ST_KEEPALIVE;
                }
                else if (status == APR_SUCCESS) {
                    /* got something, go busy again */
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                  "h2_session(%ld): IDLE -> BUSY", session->id);
                    session->state = H2_SESSION_ST_BUSY;
                }
                else {
                    reason = "keepalive error";
                    goto out;
                }
                break;
                
            case H2_SESSION_ST_BUSY:
                if (nghttp2_session_want_read(session->ngh2)) {
                    h2_filter_cin_timeout_set(session->cin, session->timeout_secs);
                    status = h2_session_read(session, 0, 10);
                    if (status == APR_SUCCESS) {
                        /* got something, continue processing */
                        have_read = 1;
                    }
                    else if (status == APR_EAGAIN) {
                        /* nothing to read */
                    }
                    else {
                        reason = "busy read error";
                        goto out;
                    }
                }
                
                if (!h2_stream_set_is_empty(session->streams)) {
                    /* resume any streams for which data is available again */
                    h2_session_resume_streams_with_data(session);
                    /* Submit any responses/push_promises that are ready */
                    status = h2_session_submit(session);
                    if (status == APR_SUCCESS) {
                        have_written = 1;
                    }
                    else if (status != APR_EAGAIN) {
                        reason = "submit error";
                        goto out;
                    }
                    /* send out window updates for our inputs */
                    status = h2_mplx_in_update_windows(session->mplx);
                    if (status != APR_SUCCESS && status != APR_EAGAIN) {
                        reason = "window update error";
                        goto out;
                    }
                }
                
                if (nghttp2_session_want_write(session->ngh2)) {
                    status = h2_session_send(session);
                    if (status != APR_SUCCESS) {
                        reason = "send error";
                        goto out;
                    }
                    have_written = 1;
                }
                
                if (have_read || have_written) {
                    session->wait_us = 0;
                }
                else {
                    /* nothing for input and output to do. If we remain
                     * in this state, we go into a tight loop and suck up
                     * CPU cycles. 
                     * Ideally, we'd like to do a blocking read, but that
                     * is not possible if we have scheduled tasks and wait
                     * for them to produce something. */
                    if (h2_stream_set_is_empty(session->streams)) {
                        /* When we have no streams, no task event are possible,
                         * switch to blocking reads */
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                  "h2_session(%ld): BUSY -> IDLE", session->id);
                        session->state = H2_SESSION_ST_IDLE_READ;
                    }
                    else if (!h2_stream_set_has_unsubmitted(session->streams)
                             && !h2_stream_set_has_suspended(session->streams)) {
                        /* none of our streams is waiting for a response or
                         * new output data from task processing, 
                         * switch to blocking reads. */
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                  "h2_session(%ld): BUSY -> IDLE", session->id);
                        session->state = H2_SESSION_ST_IDLE_READ;
                    }
                    else {
                        /* Unable to do blocking reads, as we wait on events from
                         * task processing in other threads. Do a busy wait with
                         * backoff timer. */
                        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                      "h2_session(%ld): BUSY -> WAIT", session->id);
                        session->state = H2_SESSION_ST_BUSY_WAIT;
                    }
                }
                break;
                
            case H2_SESSION_ST_BUSY_WAIT:
                session->wait_us = H2MAX(session->wait_us, 10);
                if (APLOGctrace1(c)) {
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                                  "h2_session: wait for data, %ld micros", 
                                  (long)session->wait_us);
                }
                
                h2_conn_io_flush(&session->io);
                ap_log_cerror( APLOG_MARK, APLOG_TRACE2, status, c,
                              "h2_session(%ld): process -> trywait", session->id);
                status = h2_mplx_out_trywait(session->mplx, session->wait_us, 
                                             session->iowait);
                if (status == APR_SUCCESS) {
                    /* got something, go busy again */
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                  "h2_session(%ld): WAIT -> BUSY", session->id);
                    session->state = H2_SESSION_ST_BUSY;
                }
                else if (status == APR_TIMEUP) {
                    if (nghttp2_session_want_read(session->ngh2)) {
                        status = h2_session_read(session, 0, 1);
                        if (status == APR_SUCCESS) {
                            /* got something, go busy again */
                            session->wait_us = 0;
                            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                          "h2_session(%ld): WAIT -> BUSY", session->id);
                            session->state = H2_SESSION_ST_BUSY;
                        }
                        else if (status != APR_EAGAIN) {
                            reason = "busy read error";
                            goto out;
                        }
                    }
                    /* nothing, increase timer for graceful backup */
                    session->wait_us = H2MIN(session->wait_us*2, MAX_WAIT_MICROS);
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                  "h2_session(%ld): WAIT -> BUSY", session->id);
                    session->state = H2_SESSION_ST_BUSY;
                }
                else {
                    reason = "busy wait error";
                    goto out;
                }
                break;
                
            case H2_SESSION_ST_KEEPALIVE:
                /* Our normal H2Timeout has passed and we are considering to
                 * extend that with the H2KeepAliveTimeout. */
                remain_secs = session->keepalive_secs - session->timeout_secs;
                if (remain_secs <= 0) {
                    /* keepalive is <= normal timeout, close the session */
                    reason = "keepalive expired";
                    h2_session_shutdown(session, 0);
                    goto out;
                }
                session->c->keepalive = AP_CONN_KEEPALIVE;
                ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_KEEPALIVE, c);
                
                if ((apr_time_sec(session->s->keep_alive_timeout) >= remain_secs)
                    && async && session->c->cs
                    && !session->r) {
                    /* Async MPMs are able to handle keep-alive connections without
                     * blocking a thread. For this to happen, we need to return from
                     * processing, indicating the IO event we are waiting for, and
                     * may be called again if the event happens.
                     * TODO: this does not properly GOAWAY connections...
                     * TODO: This currently does not work on upgraded requests...
                     */
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                                  "h2_session(%ld): async KEEPALIVE -> IDLE_READ", session->id);
                    session->state = H2_SESSION_ST_IDLE_READ;
                    session->c->cs->state = CONN_STATE_WRITE_COMPLETION;
                    reason = "async keepalive";
                    status = APR_SUCCESS;
                    goto out;
                }
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                              "h2_session(%ld): KEEPALIVE read", session->id);
                h2_filter_cin_timeout_set(session->cin, remain_secs);
                status = h2_session_read(session, 1, 1);
                if (APR_STATUS_IS_TIMEUP(status)) {
                    reason = "keepalive expired";
                    h2_session_shutdown(session, 0);
                    goto out;
                }
                else if (status != APR_SUCCESS) {
                    reason = "keepalive error";
                    goto out;
                }
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                              "h2_session(%ld): KEEPALIVE -> BUSY", session->id);
                session->state = H2_SESSION_ST_BUSY;
                break;
                
            case H2_SESSION_ST_CLOSING:
                if (nghttp2_session_want_write(session->ngh2)) {
                    status = h2_session_send(session);
                    if (status != APR_SUCCESS) {
                        reason = "send error";
                        goto out;
                    }
                    have_written = 1;
                }
                reason = "closing";
                goto out;
                
            case H2_SESSION_ST_ABORTED:
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c,
                              "h2_session(%ld): processing ABORTED", session->id);
                return APR_ECONNABORTED;
                
            default:
                ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                              "h2_session(%ld): state %d", session->id, session->state);
                return APR_EGENERAL;
        }

        if (!nghttp2_session_want_read(session->ngh2)
            && !nghttp2_session_want_write(session->ngh2)) {
            session->state = H2_SESSION_ST_CLOSING;
        }        

        if (have_written) {
            h2_conn_io_flush(&session->io);
        }
    }
out:
    if (have_written) {
        h2_conn_io_flush(&session->io);
    }
    ap_log_cerror( APLOG_MARK, APLOG_TRACE1, status, c,
                  "h2_session(%ld): process return, state %d, reason '%s'", 
                  session->id, session->state, reason);
    return status;
}
