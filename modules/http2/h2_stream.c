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

#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_log.h>
#include <http_ssl.h>

#include <nghttp2/nghttp2.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_bucket_beam.h"
#include "h2_c1.h"
#include "h2_config.h"
#include "h2_protocol.h"
#include "h2_mplx.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_headers.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_c2.h"
#include "h2_conn_ctx.h"
#include "h2_c2.h"
#include "h2_util.h"


static const char *h2_ss_str(const h2_stream_state_t state)
{
    switch (state) {
        case H2_SS_IDLE:
            return "IDLE";
        case H2_SS_RSVD_L:
            return "RESERVED_LOCAL";
        case H2_SS_RSVD_R:
            return "RESERVED_REMOTE";
        case H2_SS_OPEN:
            return "OPEN";
        case H2_SS_CLOSED_L:
            return "HALF_CLOSED_LOCAL";
        case H2_SS_CLOSED_R:
            return "HALF_CLOSED_REMOTE";
        case H2_SS_CLOSED:
            return "CLOSED";
        case H2_SS_CLEANUP:
            return "CLEANUP";
        default:
            return "UNKNOWN";
    }
}

const char *h2_stream_state_str(const h2_stream *stream)
{
    return h2_ss_str(stream->state);
}

/* Abbreviations for stream transit tables */
#define S_XXX     (-2)                      /* Programming Error */
#define S_ERR     (-1)                      /* Protocol Error */
#define S_NOP     (0)                       /* No Change */
#define S_IDL     (H2_SS_IDL + 1)
#define S_RS_L    (H2_SS_RSVD_L + 1)
#define S_RS_R    (H2_SS_RSVD_R + 1)
#define S_OPEN    (H2_SS_OPEN + 1)
#define S_CL_L    (H2_SS_CLOSED_L + 1)
#define S_CL_R    (H2_SS_CLOSED_R + 1)
#define S_CLS     (H2_SS_CLOSED + 1)
#define S_CLN     (H2_SS_CLEANUP + 1)

/* state transisitions when certain frame types are sent */
static int trans_on_send[][H2_SS_MAX] = {
/*S_IDLE,S_RS_R, S_RS_L, S_OPEN, S_CL_R, S_CL_L, S_CLS,  S_CLN, */        
{ S_ERR, S_ERR,  S_ERR,  S_NOP,  S_NOP,  S_ERR,  S_NOP,  S_NOP, },/* DATA */ 
{ S_ERR, S_ERR,  S_CL_R, S_NOP,  S_NOP,  S_ERR,  S_NOP,  S_NOP, },/* HEADERS */ 
{ S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },/* PRIORITY */    
{ S_CLS, S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_NOP,  S_NOP, },/* RST_STREAM */ 
{ S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },/* SETTINGS */ 
{ S_RS_L,S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },/* PUSH_PROMISE */  
{ S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },/* PING */ 
{ S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },/* GOAWAY */ 
{ S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },/* WINDOW_UPDATE */ 
{ S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },/* CONT */ 
};
/* state transisitions when certain frame types are received */
static int trans_on_recv[][H2_SS_MAX] = {
/*S_IDLE,S_RS_R, S_RS_L, S_OPEN, S_CL_R, S_CL_L, S_CLS,  S_CLN, */        
{ S_ERR, S_ERR,  S_ERR,  S_NOP,  S_ERR,  S_NOP,  S_NOP,  S_NOP, },/* DATA */ 
{ S_OPEN,S_CL_L, S_ERR,  S_NOP,  S_ERR,  S_NOP,  S_NOP,  S_NOP, },/* HEADERS */ 
{ S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },/* PRIORITY */    
{ S_ERR, S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_NOP,  S_NOP, },/* RST_STREAM */ 
{ S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },/* SETTINGS */ 
{ S_RS_R,S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },/* PUSH_PROMISE */  
{ S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },/* PING */ 
{ S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },/* GOAWAY */ 
{ S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },/* WINDOW_UPDATE */ 
{ S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },/* CONT */ 
};
/* state transisitions when certain events happen */
static int trans_on_event[][H2_SS_MAX] = {
/*S_IDLE,S_RS_R, S_RS_L, S_OPEN, S_CL_R, S_CL_L, S_CLS,  S_CLN, */        
{ S_XXX, S_ERR,  S_ERR,  S_CL_L, S_CLS,  S_XXX,  S_XXX,  S_XXX, },/* EV_CLOSED_L*/
{ S_ERR, S_ERR,  S_ERR,  S_CL_R, S_ERR,  S_CLS,  S_NOP,  S_NOP, },/* EV_CLOSED_R*/
{ S_CLS, S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_NOP,  S_NOP, },/* EV_CANCELLED*/
{ S_NOP, S_XXX,  S_XXX,  S_XXX,  S_XXX,  S_CLS,  S_CLN,  S_XXX, },/* EV_EOS_SENT*/
{ S_NOP, S_XXX,  S_CLS,  S_XXX,  S_XXX,  S_CLS,  S_XXX,  S_XXX, },/* EV_IN_ERROR*/
};

static int on_map(h2_stream_state_t state, int map[H2_SS_MAX])
{
    int op = map[state];
    switch (op) {
        case S_XXX:
        case S_ERR:
            return op;
        case S_NOP:
            return state;
        default:
            return op-1;
    }
}

static int on_frame(h2_stream_state_t state, int frame_type, 
                    int frame_map[][H2_SS_MAX], apr_size_t maxlen)
{
    ap_assert(frame_type >= 0);
    ap_assert(state >= 0);
    if (frame_type >= maxlen) {
        return state; /* NOP, ignore unknown frame types */
    }
    return on_map(state, frame_map[frame_type]);
}

static int on_frame_send(h2_stream_state_t state, int frame_type)
{
    return on_frame(state, frame_type, trans_on_send, H2_ALEN(trans_on_send));
}

static int on_frame_recv(h2_stream_state_t state, int frame_type)
{
    return on_frame(state, frame_type, trans_on_recv, H2_ALEN(trans_on_recv));
}

static int on_event(h2_stream* stream, h2_stream_event_t ev)
{
    if (stream->monitor && stream->monitor->on_event) {
        stream->monitor->on_event(stream->monitor->ctx, stream, ev);
    }
    if (ev < H2_ALEN(trans_on_event)) {
        return on_map(stream->state, trans_on_event[ev]);
    }
    return stream->state;
}

static ssize_t stream_data_cb(nghttp2_session *ng2s,
                              int32_t stream_id,
                              uint8_t *buf,
                              size_t length,
                              uint32_t *data_flags,
                              nghttp2_data_source *source,
                              void *puser);

static void H2_STREAM_OUT_LOG(int lvl, h2_stream *s, const char *tag)
{
    if (APLOG_C_IS_LEVEL(s->session->c1, lvl)) {
        conn_rec *c = s->session->c1;
        char buffer[4 * 1024];
        apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]);
        
        len = h2_util_bb_print(buffer, bmax, tag, "", s->out_buffer);
        ap_log_cerror(APLOG_MARK, lvl, 0, c, 
                      H2_STRM_MSG(s, "out-buffer(%s)"), len? buffer : "empty");
    }
}

apr_status_t h2_stream_setup_input(h2_stream *stream)
{
    if (stream->input == NULL) {
        int empty = (stream->input_closed
                     && (!stream->in_buffer 
                         || APR_BRIGADE_EMPTY(stream->in_buffer)));
        if (!empty) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c1,
                          H2_STRM_MSG(stream, "setup input beam"));
            h2_beam_create(&stream->input, stream->session->c1,
                           stream->pool, stream->id,
                           "input", 0, stream->session->s->timeout);
        }
    }
    return APR_SUCCESS;
}

static void input_append_bucket(h2_stream *stream, apr_bucket *b)
{
    if (!stream->in_buffer) {
        stream->in_buffer = apr_brigade_create(
            stream->pool, stream->session->c1->bucket_alloc);
    }
    APR_BRIGADE_INSERT_TAIL(stream->in_buffer, b);
}

static void input_append_data(h2_stream *stream, const char *data, apr_size_t len)
{
    if (!stream->in_buffer) {
        stream->in_buffer = apr_brigade_create(
            stream->pool, stream->session->c1->bucket_alloc);
    }
    apr_brigade_write(stream->in_buffer, NULL, NULL, data, len);
}


static apr_status_t close_input(h2_stream *stream)
{
    conn_rec *c = stream->session->c1;
    apr_status_t rv = APR_SUCCESS;
    apr_bucket *b;

    if (stream->input_closed) goto cleanup;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "closing input"));
    if (!stream->rst_error
        && stream->trailers_in
        && !apr_is_empty_table(stream->trailers_in)) {
        h2_headers *r;
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "adding trailers"));
        r = h2_headers_create(HTTP_OK, stream->trailers_in, NULL,
            stream->in_trailer_octets, stream->pool);
        stream->trailers_in = NULL;
        b = h2_bucket_headers_create(c->bucket_alloc, r);
        input_append_bucket(stream, b);
    }

    stream->input_closed = 1;
    if (stream->in_buffer || stream->input) {
        b = apr_bucket_eos_create(c->bucket_alloc);
        input_append_bucket(stream, b);
        h2_stream_dispatch(stream, H2_SEV_IN_DATA_PENDING);
    }
cleanup:
    return rv;
}

static void on_state_enter(h2_stream *stream)
{
    if (stream->monitor && stream->monitor->on_state_enter) {
        stream->monitor->on_state_enter(stream->monitor->ctx, stream);
    }
}

static void on_state_event(h2_stream *stream, h2_stream_event_t ev) 
{
    if (stream->monitor && stream->monitor->on_state_event) {
        stream->monitor->on_state_event(stream->monitor->ctx, stream, ev);
    }
}

static void on_state_invalid(h2_stream *stream) 
{
    if (stream->monitor && stream->monitor->on_state_invalid) {
        stream->monitor->on_state_invalid(stream->monitor->ctx, stream);
    }
    /* stream got an event/frame invalid in its state */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "invalid state event")); 
    switch (stream->state) {
        case H2_SS_OPEN:
        case H2_SS_RSVD_L:
        case H2_SS_RSVD_R:
        case H2_SS_CLOSED_L:
        case H2_SS_CLOSED_R:
            h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
            break;
        default:
            break;
    }
}

static apr_status_t transit(h2_stream *stream, int new_state)
{
    if (new_state == stream->state) {
        return APR_SUCCESS;
    }
    else if (new_state < 0) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, stream->session->c1,
                      H2_STRM_LOG(APLOGNO(03081), stream, "invalid transition"));
        on_state_invalid(stream);
        return APR_EINVAL;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "transit to [%s]"), h2_ss_str(new_state));
    stream->state = new_state;
    switch (new_state) {
        case H2_SS_IDLE:
            break;
        case H2_SS_RSVD_L:
            close_input(stream);
            break;
        case H2_SS_RSVD_R:
            break;
        case H2_SS_OPEN:
            break;
        case H2_SS_CLOSED_L:
            break;
        case H2_SS_CLOSED_R:
            close_input(stream);
            break;
        case H2_SS_CLOSED:
            close_input(stream);
            if (stream->out_buffer) {
                apr_brigade_cleanup(stream->out_buffer);
            }
            break;
        case H2_SS_CLEANUP:
            break;
    }
    on_state_enter(stream);
    return APR_SUCCESS;
}

void h2_stream_set_monitor(h2_stream *stream, h2_stream_monitor *monitor)
{
    stream->monitor = monitor;
}

void h2_stream_dispatch(h2_stream *stream, h2_stream_event_t ev)
{
    int new_state;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "dispatch event %d"), ev);
    new_state = on_event(stream, ev);
    if (new_state < 0) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, stream->session->c1,
                      H2_STRM_LOG(APLOGNO(10002), stream, "invalid event %d"), ev);
        on_state_invalid(stream);
        AP_DEBUG_ASSERT(new_state > S_XXX);
        return;
    }
    else if (new_state == stream->state) {
        /* nop */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "non-state event %d"), ev);
        return;
    }
    else {
        on_state_event(stream, ev);
        transit(stream, new_state);
    }
}

static void set_policy_for(h2_stream *stream, h2_request *r) 
{
    int enabled = h2_session_push_enabled(stream->session);
    stream->push_policy = h2_push_policy_determine(r->headers, stream->pool, enabled);
}

apr_status_t h2_stream_send_frame(h2_stream *stream, int ftype, int flags, size_t frame_len)
{
    apr_status_t status = APR_SUCCESS;
    int new_state, eos = 0;

    new_state = on_frame_send(stream->state, ftype);
    if (new_state < 0) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "invalid frame %d send"), ftype);
        AP_DEBUG_ASSERT(new_state > S_XXX);
        return transit(stream, new_state);
    }

    ++stream->out_frames;
    stream->out_frame_octets += frame_len;
    switch (ftype) {
        case NGHTTP2_DATA:
            eos = (flags & NGHTTP2_FLAG_END_STREAM);
            break;
            
        case NGHTTP2_HEADERS:
            eos = (flags & NGHTTP2_FLAG_END_STREAM);
            break;
            
        case NGHTTP2_PUSH_PROMISE:
                /* start pushed stream */
                ap_assert(stream->request == NULL);
                ap_assert(stream->rtmp != NULL);
                status = h2_stream_end_headers(stream, 1, 0);
                if (status != APR_SUCCESS) goto leave;
            break;
            
        default:
            break;
    }
    status = transit(stream, new_state);
    if (status == APR_SUCCESS && eos) {
        status = transit(stream, on_event(stream, H2_SEV_CLOSED_L));
    }
leave:
    return status;
}

apr_status_t h2_stream_recv_frame(h2_stream *stream, int ftype, int flags, size_t frame_len)
{
    apr_status_t status = APR_SUCCESS;
    int new_state, eos = 0;

    new_state = on_frame_recv(stream->state, ftype);
    if (new_state < 0) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "invalid frame %d recv"), ftype);
        AP_DEBUG_ASSERT(new_state > S_XXX);
        return transit(stream, new_state);
    }
    
    switch (ftype) {
        case NGHTTP2_DATA:
            eos = (flags & NGHTTP2_FLAG_END_STREAM);
            break;
            
        case NGHTTP2_HEADERS:
            eos = (flags & NGHTTP2_FLAG_END_STREAM);
            if (stream->state == H2_SS_OPEN) {
                /* trailer HEADER */
                if (!eos) {
                    h2_stream_rst(stream, H2_ERR_PROTOCOL_ERROR);
                }
                stream->in_trailer_octets += frame_len;
            }
            else {
                /* request HEADER */
                ap_assert(stream->request == NULL);
                if (stream->rtmp == NULL) {
                    /* This can only happen, if the stream has received no header
                     * name/value pairs at all. The latest nghttp2 version have become
                     * pretty good at detecting this early. In any case, we have
                     * to abort the connection here, since this is clearly a protocol error */
                    return APR_EINVAL;
                }
                status = h2_stream_end_headers(stream, eos, frame_len);
                if (status != APR_SUCCESS) goto leave;
            }
            break;
            
        default:
            break;
    }
    status = transit(stream, new_state);
    if (status == APR_SUCCESS && eos) {
        status = transit(stream, on_event(stream, H2_SEV_CLOSED_R));
    }
leave:
    return status;
}

apr_status_t h2_stream_flush_input(h2_stream *stream)
{
    apr_status_t status = APR_SUCCESS;
    apr_off_t written;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "flush input"));
    if (stream->in_buffer && !APR_BRIGADE_EMPTY(stream->in_buffer)) {
        if (!stream->input) {
            h2_stream_setup_input(stream);
        }
        status = h2_beam_send(stream->input, stream->session->c1,
                              stream->in_buffer, APR_BLOCK_READ, &written);
        stream->in_last_write = apr_time_now();
        if (APR_SUCCESS != status && stream->state == H2_SS_CLOSED_L) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, stream->session->c1,
                          H2_STRM_MSG(stream, "send input error"));
            h2_stream_dispatch(stream, H2_SEV_IN_ERROR);
        }
    }
    return status;
}

apr_status_t h2_stream_recv_DATA(h2_stream *stream, uint8_t flags,
                                    const uint8_t *data, size_t len)
{
    h2_session *session = stream->session;
    apr_status_t status = APR_SUCCESS;
    
    stream->in_data_frames++;
    if (len > 0) {
        if (APLOGctrace3(session->c1)) {
            const char *load = apr_pstrndup(stream->pool, (const char *)data, len);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, session->c1,
                          H2_STRM_MSG(stream, "recv DATA, len=%d: -->%s<--"), 
                          (int)len, load);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c1,
                          H2_STRM_MSG(stream, "recv DATA, len=%d"), (int)len);
        }
        stream->in_data_octets += len;
        input_append_data(stream, (const char*)data, len);
        h2_stream_dispatch(stream, H2_SEV_IN_DATA_PENDING);
    }
    return status;
}

h2_stream *h2_stream_create(int id, apr_pool_t *pool, h2_session *session,
                            h2_stream_monitor *monitor, int initiated_on)
{
    h2_stream *stream = apr_pcalloc(pool, sizeof(h2_stream));
    
    stream->id           = id;
    stream->initiated_on = initiated_on;
    stream->created      = apr_time_now();
    stream->state        = H2_SS_IDLE;
    stream->pool         = pool;
    stream->session      = session;
    stream->monitor      = monitor;

#ifdef H2_NG2_LOCAL_WIN_SIZE
    if (id) {
        stream->in_window_size =
            nghttp2_session_get_stream_local_window_size(
                stream->session->ngh2, stream->id);
    }
#endif
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                  H2_STRM_LOG(APLOGNO(03082), stream, "created"));
    on_state_enter(stream);
    return stream;
}

void h2_stream_cleanup(h2_stream *stream)
{
    /* Stream is done on c1. There might still be processing on a c2
     * going on. The input/output beams get aborted and the stream's
     * end of the in/out notifications get closed.
     */
    ap_assert(stream);
    if (stream->out_buffer) {
        apr_brigade_cleanup(stream->out_buffer);
    }
}

void h2_stream_destroy(h2_stream *stream)
{
    ap_assert(stream);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "destroy"));
    apr_pool_destroy(stream->pool);
}

void h2_stream_rst(h2_stream *stream, int error_code)
{
    stream->rst_error = error_code;
    if (stream->input) {
        h2_beam_abort(stream->input, stream->session->c1);
    }
    if (stream->output) {
        h2_beam_abort(stream->output, stream->session->c1);
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "reset, error=%d"), error_code);
    h2_stream_dispatch(stream, H2_SEV_CANCELLED);
}

apr_status_t h2_stream_set_request_rec(h2_stream *stream, 
                                       request_rec *r, int eos)
{
    h2_request *req;
    apr_status_t status;

    ap_assert(stream->request == NULL);
    ap_assert(stream->rtmp == NULL);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    status = h2_request_rcreate(&req, stream->pool, r);
    if (status == APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, 
                      H2_STRM_LOG(APLOGNO(03058), stream, 
                      "set_request_rec %s host=%s://%s%s"),
                      req->method, req->scheme, req->authority, req->path);
        stream->rtmp = req;
        /* simulate the frames that led to this */
        return h2_stream_recv_frame(stream, NGHTTP2_HEADERS, 
                                    NGHTTP2_FLAG_END_STREAM, 0);
    }
    return status;
}

void h2_stream_set_request(h2_stream *stream, const h2_request *r)
{
    ap_assert(stream->request == NULL);
    ap_assert(stream->rtmp == NULL);
    stream->rtmp = h2_request_clone(stream->pool, r);
}

static void set_error_response(h2_stream *stream, int http_status)
{
    if (!h2_stream_is_ready(stream) && stream->rtmp) {
        stream->rtmp->http_status = http_status;
    }
}

static apr_status_t add_trailer(h2_stream *stream,
                                const char *name, size_t nlen,
                                const char *value, size_t vlen,
                                size_t max_field_len, int *pwas_added)
{
    conn_rec *c = stream->session->c1;
    char *hname, *hvalue;
    const char *existing;

    *pwas_added = 0;
    if (nlen == 0 || name[0] == ':') {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EINVAL, c, 
                      H2_STRM_LOG(APLOGNO(03060), stream, 
                      "pseudo header in trailer"));
        return APR_EINVAL;
    }
    if (h2_req_ignore_trailer(name, nlen)) {
        return APR_SUCCESS;
    }
    if (!stream->trailers_in) {
        stream->trailers_in = apr_table_make(stream->pool, 5);
    }
    hname = apr_pstrndup(stream->pool, name, nlen);
    h2_util_camel_case_header(hname, nlen);
    existing = apr_table_get(stream->trailers_in, hname);
    if (max_field_len 
        && ((existing? strlen(existing)+2 : 0) + vlen + nlen + 2 > max_field_len)) {
        /* "key: (oldval, )?nval" is too long */
        return APR_EINVAL;
    }
    if (!existing) *pwas_added = 1;
    hvalue = apr_pstrndup(stream->pool, value, vlen);
    apr_table_mergen(stream->trailers_in, hname, hvalue);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, 
                  H2_STRM_MSG(stream, "added trailer '%s: %s'"), hname, hvalue);
    
    return APR_SUCCESS;
}

apr_status_t h2_stream_add_header(h2_stream *stream,
                                  const char *name, size_t nlen,
                                  const char *value, size_t vlen)
{
    h2_session *session = stream->session;
    int error = 0, was_added = 0;
    apr_status_t status = APR_SUCCESS;
    
    if (stream->response) {
        return APR_EINVAL;    
    }

    if (name[0] == ':') {
        if ((vlen) > session->s->limit_req_line) {
            /* pseudo header: approximation of request line size check */
            if (!h2_stream_is_ready(stream)) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, session->c1,
                              H2_STRM_LOG(APLOGNO(10178), stream,
                                          "Request pseudo header exceeds "
                                          "LimitRequestFieldSize: %s"), name);
            }
            error = HTTP_REQUEST_URI_TOO_LARGE;
            goto cleanup;
        }
    }
    
    if (session->s->limit_req_fields > 0 
        && stream->request_headers_added > session->s->limit_req_fields) {
        /* already over limit, count this attempt, but do not take it in */
        ++stream->request_headers_added;
    }
    else if (H2_SS_IDLE == stream->state) {
        if (!stream->rtmp) {
            stream->rtmp = h2_request_create(stream->id, stream->pool,
                                             NULL, NULL, NULL, NULL, NULL);
        }
        status = h2_request_add_header(stream->rtmp, stream->pool,
                                       name, nlen, value, vlen,
                                       session->s->limit_req_fieldsize, &was_added);
        if (was_added) ++stream->request_headers_added;
    }
    else if (H2_SS_OPEN == stream->state) {
        status = add_trailer(stream, name, nlen, value, vlen,
                             session->s->limit_req_fieldsize, &was_added);
        if (was_added) ++stream->request_headers_added;
    }
    else {
        status = APR_EINVAL;
        goto cleanup;
    }
    
    if (APR_EINVAL == status) {
        /* header too long */
        if (!h2_stream_is_ready(stream)) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, session->c1,
                          H2_STRM_LOG(APLOGNO(10180), stream,"Request header exceeds "
                                      "LimitRequestFieldSize: %.*s"),
                          (int)H2MIN(nlen, 80), name);
        }
        error = HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
        goto cleanup;
    }
    
    if (session->s->limit_req_fields > 0 
        && stream->request_headers_added > session->s->limit_req_fields) {
        /* too many header lines */
        if (stream->request_headers_added > session->s->limit_req_fields + 100) {
            /* yeah, right, this request is way over the limit, say goodbye */
            h2_stream_rst(stream, H2_ERR_ENHANCE_YOUR_CALM);
            return APR_ECONNRESET;
        }
        if (!h2_stream_is_ready(stream)) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, session->c1,
                          H2_STRM_LOG(APLOGNO(10181), stream, "Number of request headers "
                                      "exceeds LimitRequestFields"));
        }
        error = HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
        goto cleanup;
    }
    
cleanup:
    if (error) {
        set_error_response(stream, error);
        return APR_EINVAL; 
    }
    else if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c1,
                      H2_STRM_MSG(stream, "header %s not accepted"), name);
        h2_stream_dispatch(stream, H2_SEV_CANCELLED);
    }
    return status;
}

typedef struct {
    apr_size_t maxlen;
    const char *failed_key;
} val_len_check_ctx;

static int table_check_val_len(void *baton, const char *key, const char *value)
{
    val_len_check_ctx *ctx = baton;

    if (strlen(value) <= ctx->maxlen) return 1;
    ctx->failed_key = key;
    return 0;
}

apr_status_t h2_stream_end_headers(h2_stream *stream, int eos, size_t raw_bytes)
{
    apr_status_t status;
    val_len_check_ctx ctx;
    
    status = h2_request_end_headers(stream->rtmp, stream->pool, eos, raw_bytes);
    if (APR_SUCCESS == status) {
        set_policy_for(stream, stream->rtmp);

        ctx.maxlen = stream->session->s->limit_req_fieldsize;
        ctx.failed_key = NULL;
        apr_table_do(table_check_val_len, &ctx, stream->rtmp->headers, NULL);
        if (ctx.failed_key) {
            if (!h2_stream_is_ready(stream)) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, stream->session->c1,
                              H2_STRM_LOG(APLOGNO(10230), stream,"Request header exceeds "
                                          "LimitRequestFieldSize: %.*s"),
                              (int)H2MIN(strlen(ctx.failed_key), 80), ctx.failed_key);
            }
            set_error_response(stream, HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
            /* keep on returning APR_SUCCESS, so that we send a HTTP response and
             * do not RST the stream. */
        }
        if (stream->rtmp->scheme && strcasecmp(stream->rtmp->scheme,
            ap_ssl_conn_is_ssl(stream->session->c1)? "https" : "http")) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, stream->session->c1,
                              H2_STRM_LOG(APLOGNO(), stream,"Request :scheme '%s' and "
                              "connection do not match."), stream->rtmp->scheme);
            set_error_response(stream, HTTP_BAD_REQUEST);
        }
        stream->request = stream->rtmp;
        stream->rtmp = NULL;
    }
    return status;
}

static apr_bucket *get_first_headers_bucket(apr_bucket_brigade *bb)
{
    if (bb) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);
        while (b != APR_BRIGADE_SENTINEL(bb)) {
            if (H2_BUCKET_IS_HEADERS(b)) {
                return b;
            }
            b = APR_BUCKET_NEXT(b);
        }
    }
    return NULL;
}

static apr_status_t buffer_output_receive(h2_stream *stream)
{
    apr_status_t rv = APR_EAGAIN;
    apr_off_t buf_len;
    conn_rec *c1 = stream->session->c1;
    apr_bucket *b, *e;

    if (!stream->output) {
        goto cleanup;
    }

    if (!stream->out_buffer) {
        stream->out_buffer = apr_brigade_create(stream->pool, c1->bucket_alloc);
        buf_len = 0;
    }
    else {
        /* if the brigade contains a file bucket, its normal report length
         * might be megabytes, but the memory used is tiny. For buffering,
         * we are only interested in the memory footprint. */
        buf_len = h2_brigade_mem_size(stream->out_buffer);
    }

    if (buf_len >= stream->session->max_stream_mem) {
        /* we have buffered enough. No need to read more.
         * However, we have now output pending for which we may not
         * receive another poll event. We need to make sure that this
         * stream is not suspended so we keep on processing output.
         */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
                      H2_STRM_MSG(stream, "out_buffer, already has %ld length"),
                      (long)buf_len);
        rv = APR_SUCCESS;
        goto cleanup;
    }

    H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "pre");
    rv = h2_beam_receive(stream->output, stream->session->c1, stream->out_buffer,
                         APR_NONBLOCK_READ, stream->session->max_stream_mem - buf_len);
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
                      H2_STRM_MSG(stream, "out_buffer, receive unsuccessful"));
        goto cleanup;
    }

    /* get rid of buckets we have no need for */
    if (!APR_BRIGADE_EMPTY(stream->out_buffer)) {
        b = APR_BRIGADE_FIRST(stream->out_buffer);
        while (b != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
            e = APR_BUCKET_NEXT(b);
            if (APR_BUCKET_IS_METADATA(b)) {
                if (APR_BUCKET_IS_FLUSH(b)) {  /* we flush any c1 data already */
                    APR_BUCKET_REMOVE(b);
                    apr_bucket_destroy(b);
                }
            }
            else if (b->length == 0) {  /* zero length data */
                APR_BUCKET_REMOVE(b);
                apr_bucket_destroy(b);
            }
            b = e;
        }
    }
    H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "out_buffer, after receive");

cleanup:
    return rv;
}

static int bucket_pass_to_c1(apr_bucket *b)
{
    return !H2_BUCKET_IS_HEADERS(b) && !APR_BUCKET_IS_EOS(b);
}

apr_status_t h2_stream_read_to(h2_stream *stream, apr_bucket_brigade *bb, 
                               apr_off_t *plen, int *peos)
{
    apr_status_t rv = APR_SUCCESS;

    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    rv = h2_append_brigade(bb, stream->out_buffer, plen, peos, bucket_pass_to_c1);
    if (APR_SUCCESS  == rv && !*peos && !*plen) {
        rv = APR_EAGAIN;
    }
    return rv;
}

static apr_status_t buffer_output_process_headers(h2_stream *stream)
{
    conn_rec *c1 = stream->session->c1;
    h2_headers *headers = NULL;
    apr_status_t rv = APR_EAGAIN;
    int ngrv = 0, is_empty;
    h2_ngheader *nh = NULL;
    apr_bucket *b, *e;

    if (!stream->out_buffer) goto cleanup;

    b = APR_BRIGADE_FIRST(stream->out_buffer);
    while (b != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
        e = APR_BUCKET_NEXT(b);
        if (APR_BUCKET_IS_METADATA(b)) {
            if (H2_BUCKET_IS_HEADERS(b)) {
                headers = h2_bucket_headers_get(b);
                APR_BUCKET_REMOVE(b);
                apr_bucket_destroy(b);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c1,
                              H2_STRM_MSG(stream, "process headers, response %d"),
                              headers->status);
                b = e;
                break;
            }
        }
        else {
            if (!stream->response) {
                /* data buckets before response headers, an error */
                rv = APR_EINVAL;
            }
            /* data bucket, need to send those before processing
             * any subsequent headers (trailers) */
            goto cleanup;
        }
        b = e;
    }
    if (!headers) goto cleanup;

    if (stream->response) {
        rv = h2_res_create_ngtrailer(&nh, stream->pool, headers);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c1,
                      H2_STRM_LOG(APLOGNO(03072), stream, "submit %d trailers"),
                      (int)nh->nvlen);
        if (APR_SUCCESS != rv) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c1,
                          H2_STRM_LOG(APLOGNO(10024), stream, "invalid trailers"));
            h2_stream_rst(stream, NGHTTP2_PROTOCOL_ERROR);
            goto cleanup;
        }

        ngrv = nghttp2_submit_trailer(stream->session->ngh2, stream->id, nh->nv, nh->nvlen);
    }
    else if (headers->status < 100) {
        h2_stream_rst(stream, headers->status);
        goto cleanup;
    }
    else {
        nghttp2_data_provider provider, *pprovider = NULL;

        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c1,
                      H2_STRM_LOG(APLOGNO(03073), stream,
                      "submit response %d"), headers->status);

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
            && !stream->response
            && stream->request && stream->request->method
            && !strcmp("GET", stream->request->method)
            && (headers->status < 400)
            && (headers->status != 304)
            && h2_session_push_enabled(stream->session)) {
            /* PUSH is possible and enabled on server, unless the request
             * denies it, submit resources to push */
            const char *s = apr_table_get(headers->notes, H2_PUSH_MODE_NOTE);
            if (!s || strcmp(s, "0")) {
                h2_stream_submit_pushes(stream, headers);
            }
        }

        if (!stream->pref_priority) {
            stream->pref_priority = h2_stream_get_priority(stream, headers);
        }
        h2_session_set_prio(stream->session, stream, stream->pref_priority);

        if (headers->status == 103
            && !h2_config_sgeti(stream->session->s, H2_CONF_EARLY_HINTS)) {
            /* suppress sending this to the client, it might have triggered
             * pushes and served its purpose nevertheless */
            rv = APR_SUCCESS;
            goto cleanup;
        }
        if (h2_headers_are_final_response(headers)) {
            stream->response = headers;
        }

        /* Do we know if this stream has no response body? */
        is_empty = 0;
        while (b != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
            if (APR_BUCKET_IS_METADATA(b)) {
                if (APR_BUCKET_IS_EOS(b)) {
                    is_empty = 1;
                    break;
                }
            }
            else {  /* data, not empty */
                break;
            }
            b = APR_BUCKET_NEXT(b);
        }

        if (!is_empty) {
            memset(&provider, 0, sizeof(provider));
            provider.source.fd = stream->id;
            provider.read_callback = stream_data_cb;
            pprovider = &provider;
        }

        rv = h2_res_create_ngheader(&nh, stream->pool, headers);
        if (APR_SUCCESS != rv) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c1,
                          H2_STRM_LOG(APLOGNO(10025), stream, "invalid response"));
            h2_stream_rst(stream, NGHTTP2_PROTOCOL_ERROR);
            goto cleanup;
        }
        ngrv = nghttp2_submit_response(stream->session->ngh2, stream->id,
                                       nh->nv, nh->nvlen, pprovider);
        if (stream->initiated_on) {
            ++stream->session->pushes_submitted;
        }
        else {
            ++stream->session->responses_submitted;
        }
    }

cleanup:
    if (nghttp2_is_fatal(ngrv)) {
        rv = APR_EGENERAL;
        h2_session_dispatch_event(stream->session,
                                 H2_SESSION_EV_PROTO_ERROR, ngrv, nghttp2_strerror(rv));
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c1,
                      APLOGNO(02940) "submit_response: %s",
                      nghttp2_strerror(rv));
    }
    return rv;
}

apr_status_t h2_stream_submit_pushes(h2_stream *stream, h2_headers *response)
{
    apr_status_t status = APR_SUCCESS;
    apr_array_header_t *pushes;
    int i;
    
    pushes = h2_push_collect_update(stream, stream->request, response);
    if (pushes && !apr_is_empty_array(pushes)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "found %d push candidates"),
                      pushes->nelts);
        for (i = 0; i < pushes->nelts; ++i) {
            h2_push *push = APR_ARRAY_IDX(pushes, i, h2_push*);
            h2_stream *s = h2_session_push(stream->session, stream, push);
            if (!s) {
                status = APR_ECONNRESET;
                break;
            }
        }
    }
    return status;
}

apr_table_t *h2_stream_get_trailers(h2_stream *stream)
{
    return NULL;
}

const h2_priority *h2_stream_get_priority(h2_stream *stream, 
                                          h2_headers *response)
{
    if (response && stream->initiated_on) {
        const char *ctype = apr_table_get(response->headers, "content-type");
        if (ctype) {
            /* FIXME: Not good enough, config needs to come from request->server */
            return h2_cconfig_get_priority(stream->session->c1, ctype);
        }
    }
    return NULL;
}

int h2_stream_is_ready(h2_stream *stream)
{
    if (stream->response) {
        return 1;
    }
    else if (stream->out_buffer && get_first_headers_bucket(stream->out_buffer)) {
        return 1;
    }
    return 0;
}

int h2_stream_was_closed(const h2_stream *stream)
{
    switch (stream->state) {
        case H2_SS_CLOSED:
        case H2_SS_CLEANUP:
            return 1;
        default:
            return 0;
    }
}

apr_status_t h2_stream_in_consumed(h2_stream *stream, apr_off_t amount)
{
    h2_session *session = stream->session;
    
    if (amount > 0) {
        apr_off_t consumed = amount;
        
        while (consumed > 0) {
            int len = (consumed > INT_MAX)? INT_MAX : (int)consumed;
            nghttp2_session_consume(session->ngh2, stream->id, len);
            consumed -= len;
        }

#ifdef H2_NG2_LOCAL_WIN_SIZE
        if (1) {
            int cur_size = nghttp2_session_get_stream_local_window_size(
                session->ngh2, stream->id);
            int win = stream->in_window_size;
            int thigh = win * 8/10;
            int tlow = win * 2/10;
            const int win_max = 2*1024*1024;
            const int win_min = 32*1024;
            
            /* Work in progress, probably should add directives for these
             * values once this stabilizes somewhat. The general idea is
             * to adapt stream window sizes if the input window changes
             * a) very quickly (< good RTT) from full to empty
             * b) only a little bit (> bad RTT)
             * where in a) it grows and in b) it shrinks again.
             */
            if (cur_size > thigh && amount > thigh && win < win_max) {
                /* almost empty again with one reported consumption, how
                 * long did this take? */
                long ms = apr_time_msec(apr_time_now() - stream->in_last_write);
                if (ms < 40) {
                    win = H2MIN(win_max, win + (64*1024));
                }
            }
            else if (cur_size < tlow && amount < tlow && win > win_min) {
                /* staying full, for how long already? */
                long ms = apr_time_msec(apr_time_now() - stream->in_last_write);
                if (ms > 700) {
                    win = H2MAX(win_min, win - (32*1024));
                }
            }
            
            if (win != stream->in_window_size) {
                stream->in_window_size = win;
                nghttp2_session_set_local_window_size(session->ngh2, 
                        NGHTTP2_FLAG_NONE, stream->id, win);
            } 
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                          "h2_stream(%ld-%d): consumed %ld bytes, window now %d/%d",
                          session->id, stream->id, (long)amount, 
                          cur_size, stream->in_window_size);
        }
#endif /* #ifdef H2_NG2_LOCAL_WIN_SIZE */
    }
    return APR_SUCCESS;   
}

static apr_off_t buffer_output_data_to_send(h2_stream *stream, int *peos)
{
    /* How much data do we have in our buffers that we can write? */
    apr_off_t buf_len = 0;
    apr_bucket *b;

    *peos = 0;
    if (stream->out_buffer) {
        b = APR_BRIGADE_FIRST(stream->out_buffer);
        while (b != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
            if (APR_BUCKET_IS_METADATA(b)) {
                if (APR_BUCKET_IS_EOS(b)) {
                    *peos = 1;
                    break;
                }
                else if (H2_BUCKET_IS_HEADERS(b)) {
                    break;
                }
            }
            else {
                buf_len += b->length;
            }
            b = APR_BUCKET_NEXT(b);
        }
    }
    return buf_len;
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
    conn_rec *c1 = session->c1;
    apr_off_t buf_len;
    int eos;
    apr_status_t rv;
    h2_stream *stream;

    /* nghttp2 wants to send more DATA for the stream. We need
     * to find out how much of the requested length we can send without
     * blocking.
     * Indicate EOS when we encounter it or DEFERRED if the stream
     * should be suspended. Beware of trailers.
     */
    ap_assert(session);
    (void)ng2s;
    (void)buf;
    (void)source;
    stream = nghttp2_session_get_stream_user_data(session->ngh2, stream_id);
    if (!stream || !stream->output) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c1,
                      APLOGNO(02937)
                      "h2_stream(%ld-%d): data_cb, stream not found",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if (!stream->response) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c1,
                      APLOGNO(10299)
                      "h2_stream(%ld-%d): data_cb, no response seen yet",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_DEFERRED;
    }
    if (stream->rst_error) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if (!stream->out_buffer) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c1,
                      "h2_stream(%ld-%d): suspending",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_DEFERRED;
    }
    if (h2_c1_io_needs_flush(&session->io)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c1,
                      "h2_stream(%ld-%d): suspending on c1 out needs flush",
                      session->id, (int)stream_id);
        h2_stream_dispatch(stream, H2_SEV_OUT_C1_BLOCK);
        return NGHTTP2_ERR_DEFERRED;
    }

    /* determine how much we'd like to send. We cannot send more than
     * is requested. But we can reduce the size in case the master
     * connection operates in smaller chunks. (TSL warmup) */
    if (stream->session->io.write_size > 0) {
        apr_off_t chunk_len = stream->session->io.write_size - H2_FRAME_HDR_LEN;
        if (length > chunk_len) {
            length = chunk_len;
        }
    }

    /* How much data do we have in our buffers that we can write? */
    buf_len = buffer_output_data_to_send(stream, &eos);
    if (buf_len < length && !eos) {
        /* read more? */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c1,
                      "h2_stream(%ld-%d): need more (read len=%ld, %ld in buffer)",
                      session->id, (int)stream_id, (long)length, (long)buf_len);
        rv = buffer_output_receive(stream);
        /* process all headers sitting at the buffer head. */
        while (APR_SUCCESS == rv) {
            rv = buffer_output_process_headers(stream);
            if (APR_SUCCESS != rv && APR_EAGAIN != rv) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c1,
                              H2_STRM_LOG(APLOGNO(10300), stream,
                              "data_cb, error processing headers"));
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            buf_len = buffer_output_data_to_send(stream, &eos);
        }

        if (APR_EOF == rv) {
            eos = 1;
        }
        else if (APR_SUCCESS != rv && !APR_STATUS_IS_EAGAIN(rv)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c1,
                          H2_STRM_LOG(APLOGNO(02938), stream, "data_cb, reading data"));
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    if (buf_len > (apr_off_t)length) {
        eos = 0;
    }
    else {
        length = (size_t)buf_len;
    }
    if (length) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c1,
                      H2_STRM_MSG(stream, "data_cb, sending len=%ld, eos=%d"),
                      (long)length, eos);
        *data_flags |=  NGHTTP2_DATA_FLAG_NO_COPY;
    }
    else if (!eos) {
        /* no data available and output is not closed, need to suspend */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c1,
                      H2_STRM_LOG(APLOGNO(03071), stream, "data_cb, suspending"));
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c1,
                      "h2_stream(%ld-%d): suspending",
                      session->id, (int)stream_id);
        return NGHTTP2_ERR_DEFERRED;
    }

    if (eos) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return length;
}

apr_status_t h2_stream_read_output(h2_stream *stream)
{
    conn_rec *c1 = stream->session->c1;
    apr_status_t rv = APR_EAGAIN;

    /* stream->pout_recv_write signalled a change. Check what has happend, read
     * from it and act on seeing a response/data. */
    if (!stream->output) {
        /* c2 has not assigned the output beam to the stream (yet). */
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c1,
                      H2_STRM_MSG(stream, "read_output, no output beam registered"));
        rv = APR_EAGAIN;
        goto cleanup;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c1,
                  H2_STRM_MSG(stream, "read_output"));

    if (h2_stream_was_closed(stream)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c1,
                      H2_STRM_LOG(APLOGNO(10301), stream, "already closed"));
        rv = APR_EOF;
        goto cleanup;
    }
    else if (stream->state == H2_SS_CLOSED_L) {
        /* We have delivered a response to a stream that was not closed
         * by the client. This could be a POST with body that we negate
         * and we need to RST_STREAM to end if. */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c1,
                      H2_STRM_LOG(APLOGNO(10313), stream, "remote close missing"));
        nghttp2_submit_rst_stream(stream->session->ngh2, NGHTTP2_FLAG_NONE,
                                  stream->id, NGHTTP2_NO_ERROR);
        rv = APR_EOF;
        goto cleanup;
    }

    rv = buffer_output_receive(stream);
    if (APR_SUCCESS != rv) goto cleanup;

    /* process all headers sitting at the buffer head. */
    while (1) {
        rv = buffer_output_process_headers(stream);
        if (APR_EAGAIN == rv) {
            rv = APR_SUCCESS;
            break;
        }
        if (APR_SUCCESS != rv) goto cleanup;
    }

    nghttp2_session_resume_data(stream->session->ngh2, stream->id);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c1,
                  "h2_stream(%ld-%d): resumed",
                  stream->session->id, (int)stream->id);

cleanup:
    return rv;
}
