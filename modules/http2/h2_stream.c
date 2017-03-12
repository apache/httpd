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

#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_log.h>

#include <nghttp2/nghttp2.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_bucket_beam.h"
#include "h2_conn.h"
#include "h2_config.h"
#include "h2_h2.h"
#include "h2_mplx.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_headers.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_task.h"
#include "h2_ctx.h"
#include "h2_task.h"
#include "h2_util.h"


#define S_XXX (-2)
#define S_ERR (-1)
#define S_NOP (0)
#define S_IDL     (H2_SS_IDL + 1)
#define S_RS_L    (H2_SS_RSVD_L + 1)
#define S_RS_R    (H2_SS_RSVD_R + 1)
#define S_OPEN    (H2_SS_OPEN + 1)
#define S_CL_L    (H2_SS_CLOSED_L + 1)
#define S_CL_R    (H2_SS_CLOSED_R + 1)
#define S_CLS     (H2_SS_CLOSED + 1)
#define S_CLN     (H2_SS_CLEANUP + 1)

static const char *h2_ss_str(h2_stream_state_t state)
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

const char *h2_stream_state_str(h2_stream *stream) 
{
    return h2_ss_str(stream->state);
}

static int trans_on_send[][H2_SS_MAX] = {
/*                    S_IDLE,S_RS_R, S_RS_L, S_OPEN, S_CL_R, S_CL_L, S_CLS,  S_CLN, */        
/* DATA,         */ { S_ERR, S_ERR,  S_ERR,  S_NOP,  S_NOP,  S_ERR,  S_NOP,  S_NOP, },
/* HEADERS,      */ { S_ERR, S_ERR,  S_CL_R, S_NOP,  S_NOP,  S_ERR,  S_NOP,  S_NOP, },
/* PRIORITY,     */ { S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },   
/* RST_STREAM,   */ { S_CLS, S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_NOP,  S_NOP, },
/* SETTINGS,     */ { S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },
/* PUSH_PROMISE, */ { S_RS_L,S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, }, 
/* PING,         */ { S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },
/* GOAWAY,       */ { S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },
/* WINDOW_UPDATE,*/ { S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },
/* CONT          */ { S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },
};
static int trans_on_recv[][H2_SS_MAX] = {
/*                    S_IDLE,S_RS_R, S_RS_L, S_OPEN, S_CL_R, S_CL_L, S_CLS,  S_CLN, */        
/* DATA,         */ { S_ERR, S_ERR,  S_ERR,  S_NOP,  S_ERR,  S_NOP,  S_NOP,  S_NOP, },
/* HEADERS,      */ { S_OPEN,S_CL_L, S_ERR,  S_NOP,  S_ERR,  S_NOP,  S_NOP,  S_NOP, },
/* PRIORITY,     */ { S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },   
/* RST_STREAM,   */ { S_ERR, S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_NOP,  S_NOP, },
/* SETTINGS,     */ { S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },
/* PUSH_PROMISE, */ { S_RS_R,S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, }, 
/* PING,         */ { S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },
/* GOAWAY,       */ { S_ERR, S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR,  S_ERR, },
/* WINDOW_UPDATE,*/ { S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },
/* CONT          */ { S_NOP, S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP,  S_NOP, },
};
static int trans_on_event[][H2_SS_MAX] = {
/* H2_SEV_CLOSED_L*/{ S_XXX, S_ERR,  S_ERR,  S_CL_L, S_CLS,  S_XXX,  S_XXX,  S_XXX, },
/* H2_SEV_CLOSED_R*/{ S_ERR, S_ERR,  S_ERR,  S_CL_R, S_ERR,  S_CLS,  S_NOP,  S_NOP, },
/* H2_SEV_CANCELLED*/{S_CLS, S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_CLS,  S_NOP,  S_NOP, },
/* H2_SEV_EOS_SENT*/{ S_NOP, S_XXX,  S_XXX,  S_XXX,  S_XXX,  S_CLS,  S_CLN,  S_XXX, },
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
        return state; /* NOP */
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

static int on_event(h2_stream_state_t state, h2_stream_event_t ev)
{
    return on_map(state, trans_on_event[ev]);
}

static void H2_STREAM_OUT_LOG(int lvl, h2_stream *s, const char *tag)
{
    if (APLOG_C_IS_LEVEL(s->session->c, lvl)) {
        conn_rec *c = s->session->c;
        char buffer[4 * 1024];
        apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]);
        
        len = h2_util_bb_print(buffer, bmax, tag, "", s->out_buffer);
        ap_log_cerror(APLOG_MARK, lvl, 0, c, 
                      H2_STRM_MSG(s, "out-buffer(%s)"), len? buffer : "empty");
    }
}

static apr_status_t setup_input(h2_stream *stream) {
    if (stream->input == NULL && !stream->input_eof) {
        h2_beam_create(&stream->input, stream->pool, stream->id, 
                       "input", H2_BEAM_OWNER_SEND, 0, 
                       stream->session->s->timeout);
        h2_beam_send_from(stream->input, stream->pool);
    }
    return APR_SUCCESS;
}

static apr_status_t close_input(h2_stream *stream)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;

    stream->input_eof = 1;
    if (stream->input && h2_beam_is_closed(stream->input)) {
        return APR_SUCCESS;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                  H2_STRM_MSG(stream, "closing input"));
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    
    if (stream->trailers && !apr_is_empty_table(stream->trailers)) {
        apr_bucket_brigade *tmp;
        apr_bucket *b;
        h2_headers *r;
        
        tmp = apr_brigade_create(stream->pool, c->bucket_alloc);
        
        r = h2_headers_create(HTTP_OK, stream->trailers, NULL, stream->pool);
        stream->trailers = NULL;        
        b = h2_bucket_headers_create(c->bucket_alloc, r);
        APR_BRIGADE_INSERT_TAIL(tmp, b);
        
        b = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(tmp, b);
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c,
                      H2_STRM_MSG(stream, "added trailers"));
        setup_input(stream);
        status = h2_beam_send(stream->input, tmp, APR_BLOCK_READ);
        apr_brigade_destroy(tmp);
    }
    if (stream->input) {
        return h2_beam_close(stream->input);
    }
    return status;
}

static apr_status_t close_output(h2_stream *stream)
{
    if (h2_beam_is_closed(stream->output)) {
        return APR_SUCCESS;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                  H2_STRM_MSG(stream, "closing output"));
    return h2_beam_leave(stream->output);
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
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
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
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, stream->session->c, 
                      H2_STRM_LOG(APLOGNO(03081), stream, "invalid transition"));
        on_state_invalid(stream);
        return APR_EINVAL;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, 
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
            close_output(stream);
            break;
        case H2_SS_CLOSED_R:
            close_input(stream);
            break;
        case H2_SS_CLOSED:
            close_input(stream);
            close_output(stream);
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
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c,
                  H2_STRM_MSG(stream, "dispatch event %d"), ev);
    new_state = on_event(stream->state, ev);
    if (new_state < 0) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, stream->session->c, 
                      H2_STRM_LOG(APLOGNO(10002), stream, "invalid event %d"), ev);
        on_state_invalid(stream);
        AP_DEBUG_ASSERT(new_state > S_XXX);
        return;
    }
    else if (new_state == stream->state) {
        /* nop */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c,
                      H2_STRM_MSG(stream, "ignored event %d"), ev);
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
    stream->push_policy = h2_push_policy_determine(r->headers, stream->pool, 
                                                   enabled);
    r->serialize = h2_config_geti(stream->session->config, H2_CONF_SER_HEADERS);
}

apr_status_t h2_stream_send_frame(h2_stream *stream, int ftype, int flags)
{
    apr_status_t status = APR_SUCCESS;
    int new_state, eos = 0;

    new_state = on_frame_send(stream->state, ftype);
    if (new_state < 0) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, 
                      H2_STRM_MSG(stream, "invalid frame %d send"), ftype);
        AP_DEBUG_ASSERT(new_state > S_XXX);
        return transit(stream, new_state);
    }
    
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
                status = h2_request_end_headers(stream->rtmp, stream->pool, 1);
                if (status != APR_SUCCESS) {
                    return status;
                }
                set_policy_for(stream, stream->rtmp);
                stream->request = stream->rtmp;
                stream->rtmp = NULL;
            break;
            
        default:
            break;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, 
                  H2_STRM_MSG(stream, "send frame %d, eos=%d"), ftype, eos);
    status = transit(stream, new_state);
    if (status == APR_SUCCESS && eos) {
        status = transit(stream, on_event(stream->state, H2_SEV_CLOSED_L));
    }
    return status;
}

apr_status_t h2_stream_recv_frame(h2_stream *stream, int ftype, int flags)
{
    apr_status_t status = APR_SUCCESS;
    int new_state, eos = 0;

    new_state = on_frame_recv(stream->state, ftype);
    if (new_state < 0) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, 
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
            }
            else {
                /* request HEADER */
                ap_assert(stream->request == NULL);
                ap_assert(stream->rtmp != NULL);
                status = h2_request_end_headers(stream->rtmp, stream->pool, eos);
                if (status != APR_SUCCESS) {
                    return status;
                }
                set_policy_for(stream, stream->rtmp);
                stream->request = stream->rtmp;
                stream->rtmp = NULL;
            }
            break;
            
        default:
            break;
    }
    status = transit(stream, new_state);
    if (status == APR_SUCCESS && eos) {
        status = transit(stream, on_event(stream->state, H2_SEV_CLOSED_R));
    }
    return status;
}

apr_status_t h2_stream_recv_DATA(h2_stream *stream, uint8_t flags,
                                    const uint8_t *data, size_t len)
{
    h2_session *session = stream->session;
    apr_status_t status = APR_SUCCESS;
    apr_bucket_brigade *tmp;
    
    ap_assert(stream);
    if (len > 0) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c,
                      H2_STRM_MSG(stream, "recv DATA, len=%d"), (int)len);
        
        tmp = apr_brigade_create(stream->pool, session->c->bucket_alloc);
        apr_brigade_write(tmp, NULL, NULL, (const char *)data, len);
        setup_input(stream);
        status = h2_beam_send(stream->input, tmp, APR_BLOCK_READ);
        apr_brigade_destroy(tmp);
    }
    stream->in_data_frames++;
    stream->in_data_octets += len;
    return status;
}

static void prep_output(h2_stream *stream) {
    conn_rec *c = stream->session->c;
    if (!stream->out_buffer) {
        stream->out_buffer = apr_brigade_create(stream->pool, c->bucket_alloc);
    }
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
    stream->max_mem      = session->max_stream_mem;
    
    h2_beam_create(&stream->output, pool, id, "output", H2_BEAM_OWNER_RECV, 0,
                   session->s->timeout);
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                  H2_STRM_LOG(APLOGNO(03082), stream, "created"));
    on_state_enter(stream);
    return stream;
}

void h2_stream_cleanup(h2_stream *stream)
{
    apr_status_t status;
    
    ap_assert(stream);
    if (stream->out_buffer) {
        /* remove any left over output buckets that may still have
         * references into request pools */
        apr_brigade_cleanup(stream->out_buffer);
    }
    if (stream->input) {
        h2_beam_abort(stream->input);
        status = h2_beam_wait_empty(stream->input, APR_NONBLOCK_READ);
        if (status == APR_EAGAIN) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c, 
                          H2_STRM_MSG(stream, "wait on input drain"));
            status = h2_beam_wait_empty(stream->input, APR_BLOCK_READ);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, stream->session->c, 
                          H2_STRM_MSG(stream, "input drain returned"));
        }
    }
}

void h2_stream_destroy(h2_stream *stream)
{
    ap_assert(stream);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, stream->session->c, 
                  H2_STRM_MSG(stream, "destroy"));
    if (stream->pool) {
        apr_pool_destroy(stream->pool);
        stream->pool = NULL;
    }
}

apr_pool_t *h2_stream_detach_pool(h2_stream *stream)
{
    apr_pool_t *pool = stream->pool;
    stream->pool = NULL;
    return pool;
}

apr_status_t h2_stream_prep_processing(h2_stream *stream)
{
    if (stream->request) {
        const h2_request *r = stream->request;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                      H2_STRM_MSG(stream, "schedule %s %s://%s%s chunked=%d"),
                      r->method, r->scheme, r->authority, r->path, r->chunked);
        setup_input(stream);
        stream->scheduled = 1;
        return APR_SUCCESS;
    }
    return APR_EINVAL;
}

void h2_stream_rst(h2_stream *stream, int error_code)
{
    stream->rst_error = error_code;
    if (stream->input) {
        h2_beam_abort(stream->input);
    }
    h2_beam_leave(stream->output);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
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
                                    NGHTTP2_FLAG_END_STREAM);
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
    if (!h2_stream_is_ready(stream)) {
        conn_rec *c = stream->session->c;
        apr_bucket *b;
        h2_headers *response;
        
        response = h2_headers_die(http_status, stream->request, stream->pool);
        prep_output(stream);
        b = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_HEAD(stream->out_buffer, b);
        b = h2_bucket_headers_create(c->bucket_alloc, response);
        APR_BRIGADE_INSERT_HEAD(stream->out_buffer, b);
    }
}

static apr_status_t add_trailer(h2_stream *stream,
                                const char *name, size_t nlen,
                                const char *value, size_t vlen)
{
    conn_rec *c = stream->session->c;
    char *hname, *hvalue;

    if (nlen == 0 || name[0] == ':') {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EINVAL, c, 
                      H2_STRM_LOG(APLOGNO(03060), stream, 
                      "pseudo header in trailer"));
        return APR_EINVAL;
    }
    if (h2_req_ignore_trailer(name, nlen)) {
        return APR_SUCCESS;
    }
    if (!stream->trailers) {
        stream->trailers = apr_table_make(stream->pool, 5);
    }
    hname = apr_pstrndup(stream->pool, name, nlen);
    hvalue = apr_pstrndup(stream->pool, value, vlen);
    h2_util_camel_case_header(hname, nlen);
    apr_table_mergen(stream->trailers, hname, hvalue);
    
    return APR_SUCCESS;
}

apr_status_t h2_stream_add_header(h2_stream *stream,
                                  const char *name, size_t nlen,
                                  const char *value, size_t vlen)
{
    h2_session *session = stream->session;
    int error = 0;
    apr_status_t status;
    
    if (stream->has_response) {
        return APR_EINVAL;    
    }
    ++stream->request_headers_added;
    if (name[0] == ':') {
        if ((vlen) > session->s->limit_req_line) {
            /* pseudo header: approximation of request line size check */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                          H2_STRM_MSG(stream, "pseudo %s too long"), name);
            error = HTTP_REQUEST_URI_TOO_LARGE;
        }
    }
    else if ((nlen + 2 + vlen) > session->s->limit_req_fieldsize) {
        /* header too long */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                      H2_STRM_MSG(stream, "header %s too long"), name);
        error = HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
    }
    
    if (stream->request_headers_added > session->s->limit_req_fields + 4) {
        /* too many header lines, include 4 pseudo headers */
        if (stream->request_headers_added 
            > session->s->limit_req_fields + 4 + 100) {
            /* yeah, right */
            h2_stream_rst(stream, H2_ERR_ENHANCE_YOUR_CALM);
            return APR_ECONNRESET;
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                      H2_STRM_MSG(stream, "too many header lines")); 
        error = HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
    }
    
    if (error) {
        set_error_response(stream, error);
        return APR_EINVAL; 
    }
    else if (H2_SS_IDLE == stream->state) {
        if (!stream->rtmp) {
            stream->rtmp = h2_req_create(stream->id, stream->pool, 
                                         NULL, NULL, NULL, NULL, NULL, 0);
        }
        status = h2_request_add_header(stream->rtmp, stream->pool,
                                       name, nlen, value, vlen);
    }
    else  {
        status = add_trailer(stream, name, nlen, value, vlen);
    }
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c,
                      H2_STRM_MSG(stream, "header %s not accepted"), name);
        h2_stream_dispatch(stream, H2_SEV_CANCELLED);
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

apr_status_t h2_stream_out_prepare(h2_stream *stream, apr_off_t *plen, 
                                   int *peos, h2_headers **presponse)
{
    apr_status_t status = APR_SUCCESS;
    apr_off_t requested, max_chunk = H2_DATA_CHUNK_SIZE;
    apr_bucket *b, *e;
    conn_rec *c;

    if (presponse) {
        *presponse = NULL;
    }
    
    if (stream->rst_error) {
        *plen = 0;
        *peos = 1;
        return APR_ECONNRESET;
    }
    
    c = stream->session->c;
    prep_output(stream);
    
    /* determine how much we'd like to send. We cannot send more than
     * is requested. But we can reduce the size in case the master
     * connection operates in smaller chunks. (TSL warmup) */
    if (stream->session->io.write_size > 0) {
        max_chunk = stream->session->io.write_size - 9; /* header bits */ 
    }
    *plen = requested = (*plen > 0)? H2MIN(*plen, max_chunk) : max_chunk;
    
    h2_util_bb_avail(stream->out_buffer, plen, peos);
    if (!*peos && *plen < requested && *plen < stream->max_mem) {
        H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "pre");
        status = h2_beam_receive(stream->output, stream->out_buffer, 
                                 APR_NONBLOCK_READ, stream->max_mem - *plen);
        if (APR_STATUS_IS_EOF(status)) {
            apr_bucket *eos = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(stream->out_buffer, eos);
            status = APR_SUCCESS;
        }
        else if (status == APR_EAGAIN) {
            status = APR_SUCCESS;
        }
        *plen = requested;
        h2_util_bb_avail(stream->out_buffer, plen, peos);
        H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "post");
    }
    else {
        H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "ok");
    }

    b = APR_BRIGADE_FIRST(stream->out_buffer);
    while (b != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
        e = APR_BUCKET_NEXT(b);
        if (APR_BUCKET_IS_FLUSH(b)
            || (!APR_BUCKET_IS_METADATA(b) && b->length == 0)) {
            APR_BUCKET_REMOVE(b);
            apr_bucket_destroy(b);
        }
        else {
            break;
        }
        b = e;
    }

    b = get_first_headers_bucket(stream->out_buffer);
    if (b) {
        /* there are HEADERS to submit */
        *peos = 0;
        *plen = 0;
        if (b == APR_BRIGADE_FIRST(stream->out_buffer)) {
            if (presponse) {
                *presponse = h2_bucket_headers_get(b);
                APR_BUCKET_REMOVE(b);
                apr_bucket_destroy(b);
                status = APR_SUCCESS;
            }
            else {
                /* someone needs to retrieve the response first */
                h2_mplx_keep_active(stream->session->mplx, stream->id);
                status = APR_EAGAIN;
            }
        }
        else {
            apr_bucket *e = APR_BRIGADE_FIRST(stream->out_buffer);
            while (e != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
                if (e == b) {
                    break;
                }
                else if (e->length != (apr_size_t)-1) {
                    *plen += e->length;
                }
                e = APR_BUCKET_NEXT(e);
            }
        }
    }

    if (status == APR_SUCCESS) {
        if (presponse && *presponse) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                          H2_STRM_MSG(stream, "prepare, response %d"), 
                          (*presponse)->status);
        }
        else if (*peos || *plen) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                          H2_STRM_MSG(stream, "prepare, len=%ld eos=%d"),
                          (long)*plen, *peos);
        }
        else {
            status = APR_EAGAIN;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                          H2_STRM_MSG(stream, "prepare, no data"));
        }
    }
    return status;
}

static int is_not_headers(apr_bucket *b)
{
    return !H2_BUCKET_IS_HEADERS(b);
}

apr_status_t h2_stream_read_to(h2_stream *stream, apr_bucket_brigade *bb, 
                               apr_off_t *plen, int *peos)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;

    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    status = h2_append_brigade(bb, stream->out_buffer, plen, peos, is_not_headers);
    if (status == APR_SUCCESS && !*peos && !*plen) {
        status = APR_EAGAIN;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, c,
                  H2_STRM_MSG(stream, "read_to, len=%ld eos=%d"),
                  (long)*plen, *peos);
    return status;
}


apr_status_t h2_stream_submit_pushes(h2_stream *stream, h2_headers *response)
{
    apr_status_t status = APR_SUCCESS;
    apr_array_header_t *pushes;
    int i;
    
    pushes = h2_push_collect_update(stream, stream->request, response);
    if (pushes && !apr_is_empty_array(pushes)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
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
            return h2_config_get_priority(stream->session->config, ctype);
        }
    }
    return NULL;
}

int h2_stream_is_ready(h2_stream *stream)
{
    if (stream->has_response) {
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


