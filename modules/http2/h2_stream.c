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

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_strmatch.h"

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_log.h>
#include <http_protocol.h>
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
{ S_NOP, S_XXX,  S_XXX,  S_XXX,  S_XXX,  S_CLS,  S_CLN,  S_NOP, },/* EV_EOS_SENT*/
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
    if ((apr_size_t)frame_type >= maxlen) {
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
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
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

static void stream_setup_input(h2_stream *stream)
{
    if (stream->input != NULL) return;
    ap_assert(!stream->input_closed);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "setup input beam"));
    h2_beam_create(&stream->input, stream->session->c1,
                   stream->pool, stream->id,
                   "input", 0, stream->session->s->timeout);
}

apr_status_t h2_stream_prepare_processing(h2_stream *stream)
{
    /* Right before processing starts, last chance to decide if
     * there is need to an input beam. */
    if (!stream->input_closed) {
        stream_setup_input(stream);
    }
    return APR_SUCCESS;
}

static int input_buffer_is_empty(h2_stream *stream)
{
    return !stream->in_buffer || APR_BRIGADE_EMPTY(stream->in_buffer);
}

static apr_status_t input_flush(h2_stream *stream)
{
    apr_status_t status = APR_SUCCESS;
    apr_off_t written;

    if (input_buffer_is_empty(stream)) goto cleanup;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "flush input"));
    status = h2_beam_send(stream->input, stream->session->c1,
                          stream->in_buffer, APR_BLOCK_READ, &written);
    stream->in_last_write = apr_time_now();
    if (APR_SUCCESS != status && h2_stream_is_at(stream, H2_SS_CLOSED_L)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, stream->session->c1,
                      H2_STRM_MSG(stream, "send input error"));
        h2_stream_dispatch(stream, H2_SEV_IN_ERROR);
    }
cleanup:
    return status;
}

static void input_append_bucket(h2_stream *stream, apr_bucket *b)
{
    if (!stream->in_buffer) {
        stream_setup_input(stream);
        stream->in_buffer = apr_brigade_create(
            stream->pool, stream->session->c1->bucket_alloc);
    }
    APR_BRIGADE_INSERT_TAIL(stream->in_buffer, b);
}

static void input_append_data(h2_stream *stream, const char *data, apr_size_t len)
{
    if (!stream->in_buffer) {
        stream_setup_input(stream);
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
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "adding trailers"));
#if AP_HAS_RESPONSE_BUCKETS
        b = ap_bucket_headers_create(stream->trailers_in,
                                     stream->pool, c->bucket_alloc);
#else
        b = h2_bucket_headers_create(c->bucket_alloc,
            h2_headers_create(HTTP_OK, stream->trailers_in, NULL,
                              stream->in_trailer_octets, stream->pool));
#endif
        input_append_bucket(stream, b);
        stream->trailers_in = NULL;
    }

    stream->input_closed = 1;
    if (stream->input) {
        b = apr_bucket_eos_create(c->bucket_alloc);
        input_append_bucket(stream, b);
        input_flush(stream);
        h2_stream_dispatch(stream, H2_SEV_IN_DATA_PENDING);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "input flush + EOS"));
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
    if ((h2_stream_state_t)new_state == stream->state) {
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
    
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
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
    else if ((h2_stream_state_t)new_state == stream->state) {
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

    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    new_state = on_frame_send(stream->state, ftype);
    if (new_state < 0) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "invalid frame %d send"), ftype);
        AP_DEBUG_ASSERT(new_state > S_XXX);
        return transit(stream, new_state);
    }

    ++stream->out_frames;
    stream->out_frame_octets += frame_len;
    if(stream->c2) {
      h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(stream->c2);
      if(conn_ctx)
        conn_ctx->bytes_sent = stream->out_frame_octets;
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

    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
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
            if (h2_stream_is_at_or_past(stream, H2_SS_OPEN)) {
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

apr_status_t h2_stream_recv_DATA(h2_stream *stream, uint8_t flags,
                                    const uint8_t *data, size_t len)
{
    h2_session *session = stream->session;
    apr_status_t status = APR_SUCCESS;
    
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
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
        input_flush(stream);
        h2_stream_dispatch(stream, H2_SEV_IN_DATA_PENDING);
    }
    return status;
}

#ifdef AP_DEBUG
static apr_status_t stream_pool_destroy(void *data)
{
    h2_stream *stream = data;
    switch (stream->magic) {
    case H2_STRM_MAGIC_OK:
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "was not destroyed explicitly"));
        AP_DEBUG_ASSERT(0);
        break;
    case H2_STRM_MAGIC_SDEL:
        /* stream has been explicitly destroyed, as it should */
        H2_STRM_ASSIGN_MAGIC(stream, H2_STRM_MAGIC_PDEL);
        break;
    case H2_STRM_MAGIC_PDEL:
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, stream->session->c1,
                      H2_STRM_MSG(stream, "already pool destroyed"));
        AP_DEBUG_ASSERT(0);
        break;
    default:
        AP_DEBUG_ASSERT(0);
    }
    return APR_SUCCESS;
}
#endif

h2_stream *h2_stream_create(int id, apr_pool_t *pool, h2_session *session,
                            h2_stream_monitor *monitor, int initiated_on)
{
    h2_stream *stream = apr_pcalloc(pool, sizeof(h2_stream));

    H2_STRM_ASSIGN_MAGIC(stream, H2_STRM_MAGIC_OK);
    stream->id           = id;
    stream->initiated_on = initiated_on;
    stream->created      = apr_time_now();
    stream->state        = H2_SS_IDLE;
    stream->pool         = pool;
    stream->session      = session;
    stream->monitor      = monitor;
#ifdef AP_DEBUG
    if (id) { /* stream 0 has special lifetime */
        apr_pool_cleanup_register(pool, stream, stream_pool_destroy,
                                  apr_pool_cleanup_null);
    }
#endif

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
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    if (stream->out_buffer) {
        apr_brigade_cleanup(stream->out_buffer);
    }
}

void h2_stream_destroy(h2_stream *stream)
{
    ap_assert(stream);
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "destroy"));
    H2_STRM_ASSIGN_MAGIC(stream, H2_STRM_MAGIC_SDEL);
    apr_pool_destroy(stream->pool);
}

void h2_stream_rst(h2_stream *stream, int error_code)
{
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    stream->rst_error = error_code;
    if (stream->c2) {
        h2_c2_abort(stream->c2, stream->session->c1);
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

    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
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
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
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
    if (h2_ignore_req_trailer(name, nlen)) {
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
    
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    if (stream->response) {
        return APR_EINVAL;    
    }

    if (name[0] == ':') {
        if (vlen > APR_INT32_MAX || (int)vlen > session->s->limit_req_line) {
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
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c1,
                      H2_STRM_MSG(stream, "add_header: '%.*s: %.*s"),
                      (int)nlen, name, (int)vlen, value);
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
        ++stream->request_headers_failed;
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
    int is_http_or_https;
    h2_request *req = stream->rtmp;

    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    status = h2_request_end_headers(req, stream->pool, raw_bytes);
    if (APR_SUCCESS != status || req->http_status != H2_HTTP_STATUS_UNSET) {
        goto cleanup;
    }

    /* keep on returning APR_SUCCESS for error responses, so that we
     * send it and do not RST the stream.
     */
    set_policy_for(stream, req);

    ctx.maxlen = stream->session->s->limit_req_fieldsize;
    ctx.failed_key = NULL;
    apr_table_do(table_check_val_len, &ctx, req->headers, NULL);
    if (ctx.failed_key) {
        if (!h2_stream_is_ready(stream)) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, stream->session->c1,
                          H2_STRM_LOG(APLOGNO(10230), stream,"Request header exceeds "
                                      "LimitRequestFieldSize: %.*s"),
                          (int)H2MIN(strlen(ctx.failed_key), 80), ctx.failed_key);
        }
        set_error_response(stream, HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
        goto cleanup;
    }

    /* http(s) scheme. rfc7540, ch. 8.1.2.3:
     * This [:path] pseudo-header field MUST NOT be empty for "http" or "https"
     * URIs; "http" or "https" URIs that do not contain a path component
     * MUST include a value of '/'.  The exception to this rule is an
     * OPTIONS request for an "http" or "https" URI that does not include
     * a path component; these MUST include a ":path" pseudo-header field
     * with a value of '*'
     *
     * All HTTP/2 requests MUST include exactly one valid value for the
     * ":method", ":scheme", and ":path" pseudo-header fields, unless it is
     * a CONNECT request.
     */
    is_http_or_https = (!req->scheme
            || !(ap_cstr_casecmpn(req->scheme, "http", 4) != 0
                 || (req->scheme[4] != '\0'
                     && (apr_tolower(req->scheme[4]) != 's'
                         || req->scheme[5] != '\0'))));

    /* CONNECT. rfc7540, ch. 8.3:
     * In HTTP/2, the CONNECT method is used to establish a tunnel over a
     * single HTTP/2 stream to a remote host for similar purposes.  The HTTP
     * header field mapping works as defined in Section 8.1.2.3 ("Request
     * Pseudo-Header Fields"), with a few differences.  Specifically:
     *   o  The ":method" pseudo-header field is set to "CONNECT".
     *   o  The ":scheme" and ":path" pseudo-header fields MUST be omitted.
     *   o  The ":authority" pseudo-header field contains the host and port to
     *      connect to (equivalent to the authority-form of the request-target
     *      of CONNECT requests (see [RFC7230], Section 5.3)).
     */
    if (!ap_cstr_casecmp(req->method, "CONNECT")) {
        if (req->protocol) {
            if (!strcmp("websocket", req->protocol)) {
                if (!req->scheme || !req->path) {
                    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, stream->session->c1,
                                  H2_STRM_LOG(APLOGNO(10457), stream, "Request to websocket CONNECT "
                                  "without :scheme or :path, sending 400 answer"));
                    set_error_response(stream, HTTP_BAD_REQUEST);
                    goto cleanup;
                }
            }
            else {
                /* do not know that protocol */
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, stream->session->c1, APLOGNO(10460)
                              "':protocol: %s' header present in %s request",
                              req->protocol, req->method);
                set_error_response(stream, HTTP_NOT_IMPLEMENTED);
                goto cleanup;
            }
        }
        else if (req->scheme || req->path) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, stream->session->c1,
                          H2_STRM_LOG(APLOGNO(10384), stream, "Request to CONNECT "
                          "with :scheme or :path specified, sending 400 answer"));
            set_error_response(stream, HTTP_BAD_REQUEST);
            goto cleanup;
        }
    }
    else if (is_http_or_https) {
        if (!req->path) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, stream->session->c1,
                          H2_STRM_LOG(APLOGNO(10385), stream, "Request for http(s) "
                          "resource without :path, sending 400 answer"));
            set_error_response(stream, HTTP_BAD_REQUEST);
            goto cleanup;
        }
        if (!req->scheme) {
            req->scheme = ap_ssl_conn_is_ssl(stream->session->c1)? "https" : "http";
        }
    }

    if (req->scheme && (req->path && req->path[0] != '/')) {
        /* We still have a scheme, which means we need to pass an absolute URI into
         * our HTTP protocol handling and the missing '/' at the start will prevent
         * us from doing so (as it then confuses path and authority). */
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, stream->session->c1,
                      H2_STRM_LOG(APLOGNO(10379), stream, "Request :scheme '%s' and "
                      "path '%s' do not allow creating an absolute URL. Failing "
                      "request with 400."), req->scheme, req->path);
        set_error_response(stream, HTTP_BAD_REQUEST);
        goto cleanup;
    }

cleanup:
    if (APR_SUCCESS == status) {
        stream->request = req;
        stream->rtmp = NULL;

        if (APLOGctrace4(stream->session->c1)) {
            int i;
            const apr_array_header_t *t_h = apr_table_elts(req->headers);
            const apr_table_entry_t *t_elt = (apr_table_entry_t *)t_h->elts;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, stream->session->c1,
                          H2_STRM_MSG(stream,"headers received from client:"));
            for (i = 0; i < t_h->nelts; i++, t_elt++) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, stream->session->c1,
                              H2_STRM_MSG(stream, "  %s: %s"),
                              ap_escape_logitem(stream->pool, t_elt->key),
                              ap_escape_logitem(stream->pool, t_elt->val));
            }
        }
    }
    return status;
}

static apr_bucket *get_first_response_bucket(apr_bucket_brigade *bb)
{
    if (bb) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);
        while (b != APR_BRIGADE_SENTINEL(bb)) {
#if AP_HAS_RESPONSE_BUCKETS
            if (AP_BUCKET_IS_RESPONSE(b)) {
                return b;
            }
#else
            if (H2_BUCKET_IS_HEADERS(b)) {
                return b;
            }
#endif
            b = APR_BUCKET_NEXT(b);
        }
    }
    return NULL;
}

static void stream_do_error_bucket(h2_stream *stream, apr_bucket *b)
{
    int err = ((ap_bucket_error *)(b->data))->status;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c1,
                  H2_STRM_MSG(stream, "error bucket received, err=%d"), err);
    if (err >= 500) {
        err = NGHTTP2_INTERNAL_ERROR;
    }
    else if (err >= 400) {
        err = NGHTTP2_STREAM_CLOSED;
    }
    else {
        err = NGHTTP2_PROTOCOL_ERROR;
    }
    h2_stream_rst(stream, err);
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
    if (stream->rst_error) {
        rv = APR_ECONNRESET;
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

    if (buf_len > APR_INT32_MAX
        || (apr_size_t)buf_len >= stream->session->max_stream_mem) {
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

    if (stream->output_eos) {
        rv = APR_BRIGADE_EMPTY(stream->out_buffer)? APR_EOF : APR_SUCCESS;
    }
    else {
        H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "pre");
        rv = h2_beam_receive(stream->output, stream->session->c1, stream->out_buffer,
                             APR_NONBLOCK_READ, stream->session->max_stream_mem - buf_len);
        if (APR_SUCCESS != rv) {
            if (APR_EAGAIN != rv) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
                              H2_STRM_MSG(stream, "out_buffer, receive unsuccessful"));
            }
        }
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
                else if (APR_BUCKET_IS_EOS(b)) {
                    stream->output_eos = 1;
                }
                else if (AP_BUCKET_IS_ERROR(b)) {
                    stream_do_error_bucket(stream, b);
                    break;
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
#if AP_HAS_RESPONSE_BUCKETS
    return !AP_BUCKET_IS_RESPONSE(b)
           && !AP_BUCKET_IS_HEADERS(b)
           && !APR_BUCKET_IS_EOS(b);
#else
    return !H2_BUCKET_IS_HEADERS(b) && !APR_BUCKET_IS_EOS(b);
#endif
}

apr_status_t h2_stream_read_to(h2_stream *stream, apr_bucket_brigade *bb, 
                               apr_off_t *plen, int *peos)
{
    apr_status_t rv = APR_SUCCESS;

    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    rv = h2_append_brigade(bb, stream->out_buffer, plen, peos, bucket_pass_to_c1);
    if (APR_SUCCESS  == rv && !*peos && !*plen) {
        rv = APR_EAGAIN;
    }
    return rv;
}

static apr_status_t stream_do_trailers(h2_stream *stream)
{
    conn_rec *c1 = stream->session->c1;
    int ngrv;
    h2_ngheader *nh = NULL;
    apr_bucket *b, *e;
#if AP_HAS_RESPONSE_BUCKETS
    ap_bucket_headers *headers = NULL;
#else
    h2_headers *headers = NULL;
#endif
    apr_status_t rv;

    ap_assert(stream->response);
    ap_assert(stream->out_buffer);

    b = APR_BRIGADE_FIRST(stream->out_buffer);
    while (b != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
        e = APR_BUCKET_NEXT(b);
        if (APR_BUCKET_IS_METADATA(b)) {
#if AP_HAS_RESPONSE_BUCKETS
            if (AP_BUCKET_IS_HEADERS(b)) {
                headers = b->data;
#else /* AP_HAS_RESPONSE_BUCKETS */
            if (H2_BUCKET_IS_HEADERS(b)) {
                headers = h2_bucket_headers_get(b);
#endif /* else AP_HAS_RESPONSE_BUCKETS */
                APR_BUCKET_REMOVE(b);
                apr_bucket_destroy(b);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c1,
                              H2_STRM_MSG(stream, "process trailers"));
                break;
            }
            else if (APR_BUCKET_IS_EOS(b)) {
                break;
            }
        }
        else {
            break;
        }
        b = e;
    }

    if (!headers) {
        rv = APR_EAGAIN;
        goto cleanup;
    }

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
    if (nghttp2_is_fatal(ngrv)) {
        rv = APR_EGENERAL;
        h2_session_dispatch_event(stream->session,
                                 H2_SESSION_EV_PROTO_ERROR, ngrv, nghttp2_strerror(rv));
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c1,
                      APLOGNO(02940) "submit_response: %s",
                      nghttp2_strerror(rv));
    }
    stream->sent_trailers = 1;

cleanup:
    return rv;
}

#if AP_HAS_RESPONSE_BUCKETS
apr_status_t h2_stream_submit_pushes(h2_stream *stream, ap_bucket_response *response)
#else
apr_status_t h2_stream_submit_pushes(h2_stream *stream, h2_headers *response)
#endif
{
    apr_status_t status = APR_SUCCESS;
    apr_array_header_t *pushes;
    int i;
    
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
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
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    return NULL;
}

#if AP_HAS_RESPONSE_BUCKETS
const h2_priority *h2_stream_get_priority(h2_stream *stream,
                                          ap_bucket_response *response)
#else
const h2_priority *h2_stream_get_priority(h2_stream *stream,
                                          h2_headers *response)
#endif
{
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
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
    /* Have we sent a response or do we have the response in our buffer? */
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    if (stream->response) {
        return 1;
    }
    else if (stream->out_buffer && get_first_response_bucket(stream->out_buffer)) {
        return 1;
    }
    return 0;
}

int h2_stream_wants_send_data(h2_stream *stream)
{
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    return h2_stream_is_ready(stream) &&
           ((stream->out_buffer && !APR_BRIGADE_EMPTY(stream->out_buffer)) ||
            (stream->output && !h2_beam_empty(stream->output)));
}

int h2_stream_is_at(const h2_stream *stream, h2_stream_state_t state)
{
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    return stream->state == state;
}

int h2_stream_is_at_or_past(const h2_stream *stream, h2_stream_state_t state)
{
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    switch (state) {
        case H2_SS_IDLE:
            return 1; /* by definition */
        case H2_SS_RSVD_R: /*fall through*/
        case H2_SS_RSVD_L: /*fall through*/
        case H2_SS_OPEN:
            return stream->state == state || stream->state >= H2_SS_OPEN;
        case H2_SS_CLOSED_R: /*fall through*/
        case H2_SS_CLOSED_L: /*fall through*/
        case H2_SS_CLOSED:
            return stream->state == state || stream->state >= H2_SS_CLOSED;
        case H2_SS_CLEANUP:
            return stream->state == state;
        default:
            return 0;
    }
}

apr_status_t h2_stream_in_consumed(h2_stream *stream, apr_off_t amount)
{
    h2_session *session = stream->session;
    
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
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
                          H2_STRM_MSG(stream, "consumed %ld bytes, window now %d/%d"),
                          (long)amount, cur_size, stream->in_window_size);
        }
#endif /* #ifdef H2_NG2_LOCAL_WIN_SIZE */
    }
    return APR_SUCCESS;   
}

static apr_off_t output_data_buffered(h2_stream *stream, int *peos, int *pheader_blocked)
{
    /* How much data do we have in our buffers that we can write? */
    apr_off_t buf_len = 0;
    apr_bucket *b;

    *peos = *pheader_blocked = 0;
    if (stream->out_buffer) {
        b = APR_BRIGADE_FIRST(stream->out_buffer);
        while (b != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
            if (APR_BUCKET_IS_METADATA(b)) {
                if (APR_BUCKET_IS_EOS(b)) {
                    *peos = 1;
                    break;
                }
#if AP_HAS_RESPONSE_BUCKETS
                else if (AP_BUCKET_IS_RESPONSE(b)) {
                    break;
                }
                else if (AP_BUCKET_IS_HEADERS(b)) {
                    *pheader_blocked = 1;
                    break;
                }
#else
                else if (H2_BUCKET_IS_HEADERS(b)) {
                    *pheader_blocked = 1;
                    break;
                }
#endif
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
    int eos, header_blocked;
    apr_status_t rv;
    h2_stream *stream;

    /* nghttp2 wants to send more DATA for the stream.
     * we should have submitted the final response at this time
     * after receiving output via stream_do_responses() */
    ap_assert(session);
    (void)ng2s;
    (void)buf;
    (void)source;
    stream = nghttp2_session_get_stream_user_data(session->ngh2, stream_id);

    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c1,
                      APLOGNO(02937)
                      H2_SSSN_STRM_MSG(session, stream_id, "data_cb, stream not found"));
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    if (!stream->output || !stream->response || !stream->out_buffer) {
        return NGHTTP2_ERR_DEFERRED;
    }
    if (stream->rst_error) {
        return NGHTTP2_ERR_DEFERRED;
    }
    if (h2_c1_io_needs_flush(&session->io)) {
        rv = h2_c1_io_pass(&session->io);
        if (APR_STATUS_IS_EAGAIN(rv)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c1,
                          H2_SSSN_STRM_MSG(session, stream_id, "suspending on c1 out needs flush"));
            h2_stream_dispatch(stream, H2_SEV_OUT_C1_BLOCK);
            return NGHTTP2_ERR_DEFERRED;
        }
        else if (rv) {
            h2_session_dispatch_event(session, H2_SESSION_EV_CONN_ERROR, rv, NULL);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    /* determine how much we'd like to send. We cannot send more than
     * is requested. But we can reduce the size in case the master
     * connection operates in smaller chunks. (TSL warmup) */
    if (stream->session->io.write_size > 0) {
        apr_size_t chunk_len = stream->session->io.write_size - H2_FRAME_HDR_LEN;
        if (length > chunk_len) {
            length = chunk_len;
        }
    }
    /* We allow configurable max DATA frame length. */
    if (stream->session->max_data_frame_len > 0
        && length > stream->session->max_data_frame_len) {
      length = stream->session->max_data_frame_len;
    }

    /* How much data do we have in our buffers that we can write?
     * if not enough, receive more. */
    buf_len = output_data_buffered(stream, &eos, &header_blocked);
    if (buf_len < (apr_off_t)length && !eos
           && !header_blocked && !stream->rst_error) {
        /* read more? */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c1,
                      H2_SSSN_STRM_MSG(session, stream_id,
                      "need more (read len=%ld, %ld in buffer)"),
                      (long)length, (long)buf_len);
        rv = buffer_output_receive(stream);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
                      H2_SSSN_STRM_MSG(session, stream_id,
                      "buffer_output_received"));
        if (APR_STATUS_IS_EAGAIN(rv)) {
            /* currently, no more is available */
        }
        else if (APR_SUCCESS == rv) {
            /* got some, re-assess */
            buf_len = output_data_buffered(stream, &eos, &header_blocked);
        }
        else if (APR_EOF == rv) {
            if (!stream->output_eos) {
                /* Seeing APR_EOF without an EOS bucket received before indicates
                 * that stream output is incomplete. Commonly, we expect to see
                 * an ERROR bucket to have been generated. But faulty handlers
                 * may not have generated one.
                 * We need to RST the stream bc otherwise the client thinks
                 * it is all fine. */
                 ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
                               H2_SSSN_STRM_MSG(session, stream_id, "rst stream"));
                 h2_stream_rst(stream, H2_ERR_STREAM_CLOSED);
                 return NGHTTP2_ERR_DEFERRED;
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
                          H2_SSSN_STRM_MSG(session, stream_id,
                          "eof on receive (read len=%ld, %ld in buffer)"),
                          (long)length, (long)buf_len);
            eos = 1;
            rv = APR_SUCCESS;
        }
        else if (APR_ECONNRESET == rv || APR_ECONNABORTED == rv) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c1,
                          H2_STRM_LOG(APLOGNO(10471), stream, "data_cb, reading data"));
            h2_stream_rst(stream, H2_ERR_STREAM_CLOSED);
            return NGHTTP2_ERR_DEFERRED;
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c1,
                          H2_STRM_LOG(APLOGNO(02938), stream, "data_cb, reading data"));
            h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
            return NGHTTP2_ERR_DEFERRED;
        }
    }

    if (stream->rst_error) {
        return NGHTTP2_ERR_DEFERRED;
    }

    if (buf_len == 0 && header_blocked) {
        rv = stream_do_trailers(stream);
        if (APR_SUCCESS != rv && !APR_STATUS_IS_EAGAIN(rv)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c1,
                          H2_STRM_LOG(APLOGNO(10300), stream,
                          "data_cb, error processing trailers"));
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        length = 0;
        eos = 0;
    }
    else if (buf_len > (apr_off_t)length) {
        eos = 0;  /* Any EOS we have in the buffer does not apply yet */
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
    else if (!eos && !stream->sent_trailers) {
        /* We have not reached the end of DATA yet, DEFER sending */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c1,
                      H2_STRM_LOG(APLOGNO(03071), stream, "data_cb, suspending"));
        return NGHTTP2_ERR_DEFERRED;
    }

    if (eos) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return length;
}

static apr_status_t stream_do_response(h2_stream *stream)
{
    conn_rec *c1 = stream->session->c1;
    apr_status_t rv = APR_EAGAIN;
    int ngrv, is_empty = 0;
    h2_ngheader *nh = NULL;
    apr_bucket *b, *e;
#if AP_HAS_RESPONSE_BUCKETS
    ap_bucket_response *resp = NULL;
#else
    h2_headers *resp = NULL;
#endif
    nghttp2_data_provider provider, *pprovider = NULL;

    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    ap_assert(!stream->response);
    ap_assert(stream->out_buffer);

    b = APR_BRIGADE_FIRST(stream->out_buffer);
    while (b != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
        e = APR_BUCKET_NEXT(b);
        if (APR_BUCKET_IS_METADATA(b)) {
#if AP_HAS_RESPONSE_BUCKETS
            if (AP_BUCKET_IS_RESPONSE(b)) {
                resp = b->data;
#else /* AP_HAS_RESPONSE_BUCKETS */
            if (H2_BUCKET_IS_HEADERS(b)) {
                resp = h2_bucket_headers_get(b);
#endif /* else AP_HAS_RESPONSE_BUCKETS */
                APR_BUCKET_REMOVE(b);
                apr_bucket_destroy(b);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c1,
                              H2_STRM_MSG(stream, "process response %d"),
                              resp->status);
                is_empty = (e != APR_BRIGADE_SENTINEL(stream->out_buffer)
                            && APR_BUCKET_IS_EOS(e));
                break;
            }
            else if (APR_BUCKET_IS_EOS(b)) {
                h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
                rv = APR_EINVAL;
                goto cleanup;
            }
            else if (AP_BUCKET_IS_ERROR(b)) {
                stream_do_error_bucket(stream, b);
                rv = APR_EINVAL;
                goto cleanup;
            }
        }
        else {
            /* data buckets before response headers, an error */
            h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
            rv = APR_EINVAL;
            goto cleanup;
        }
        b = e;
    }

    if (!resp) {
        rv = APR_EAGAIN;
        goto cleanup;
    }

    if (resp->status < 100) {
        h2_stream_rst(stream, resp->status);
        goto cleanup;
    }

    if (resp->status == HTTP_FORBIDDEN && resp->notes) {
        const char *cause = apr_table_get(resp->notes, "ssl-renegotiate-forbidden");
        if (cause) {
            /* This request triggered a TLS renegotiation that is not allowed
             * in HTTP/2. Tell the client that it should use HTTP/1.1 for this.
             */
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, resp->status, c1,
                          H2_STRM_LOG(APLOGNO(03061), stream,
                          "renegotiate forbidden, cause: %s"), cause);
            h2_stream_rst(stream, H2_ERR_HTTP_1_1_REQUIRED);
            goto cleanup;
        }
    }

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c1,
                  H2_STRM_LOG(APLOGNO(03073), stream,
                  "submit response %d"), resp->status);

    /* If this stream is not a pushed one itself,
     * and HTTP/2 server push is enabled here,
     * and the response HTTP status is not sth >= 400,
     * and the remote side has pushing enabled,
     * -> find and perform any pushes on this stream
     *    *before* we submit the stream response itself.
     *    This helps clients avoid opening new streams on Link
     *    resp that get pushed right afterwards.
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
        && (resp->status < 400)
        && (resp->status != 304)
        && h2_session_push_enabled(stream->session)) {
        /* PUSH is possible and enabled on server, unless the request
         * denies it, submit resources to push */
        const char *s = apr_table_get(resp->notes, H2_PUSH_MODE_NOTE);
        if (!s || strcmp(s, "0")) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c1,
                          H2_STRM_MSG(stream, "submit pushes, note=%s"), s);
            h2_stream_submit_pushes(stream, resp);
        }
    }

    if (!stream->pref_priority) {
        stream->pref_priority = h2_stream_get_priority(stream, resp);
    }
    h2_session_set_prio(stream->session, stream, stream->pref_priority);

    if (resp->status == 103
        && !h2_config_sgeti(stream->session->s, H2_CONF_EARLY_HINTS)) {
        /* suppress sending this to the client, it might have triggered
         * pushes and served its purpose nevertheless */
        rv = APR_SUCCESS;
        goto cleanup;
    }
    if (resp->status >= 200) {
        stream->response = resp;
    }

    if (!is_empty) {
        memset(&provider, 0, sizeof(provider));
        provider.source.fd = stream->id;
        provider.read_callback = stream_data_cb;
        pprovider = &provider;
    }

    rv = h2_res_create_ngheader(&nh, stream->pool, resp);
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c1,
                      H2_STRM_LOG(APLOGNO(10025), stream, "invalid response"));
        h2_stream_rst(stream, NGHTTP2_PROTOCOL_ERROR);
        goto cleanup;
    }

    ngrv = nghttp2_submit_response(stream->session->ngh2, stream->id,
                                   nh->nv, nh->nvlen, pprovider);
    if (nghttp2_is_fatal(ngrv)) {
        rv = APR_EGENERAL;
        h2_session_dispatch_event(stream->session,
                                 H2_SESSION_EV_PROTO_ERROR, ngrv, nghttp2_strerror(rv));
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c1,
                      APLOGNO(10402) "submit_response: %s",
                      nghttp2_strerror(rv));
        goto cleanup;
    }

    if (stream->initiated_on) {
        ++stream->session->pushes_submitted;
    }
    else {
        ++stream->session->responses_submitted;
    }

cleanup:
    return rv;
}

static void stream_do_responses(h2_stream *stream)
{
    h2_session *session = stream->session;
    conn_rec *c1 = session->c1;
    apr_status_t rv;

    ap_assert(!stream->response);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c1,
                  H2_STRM_MSG(stream, "do_response"));
    rv = buffer_output_receive(stream);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c1,
                  H2_SSSN_STRM_MSG(session, stream->id,
                  "buffer_output_received2"));
    if (APR_SUCCESS != rv && APR_EAGAIN != rv) {
        h2_stream_rst(stream, NGHTTP2_PROTOCOL_ERROR);
    }
    else {
        /* process all headers sitting at the buffer head. */
        do {
            rv = stream_do_response(stream);
        } while (APR_SUCCESS == rv
                 && !stream->rst_error
                 && !stream->response);
    }
}

void h2_stream_on_output_change(h2_stream *stream)
{
    conn_rec *c1 = stream->session->c1;
    apr_status_t rv = APR_EAGAIN;

    /* stream->pout_recv_write signalled a change. Check what has happend, read
     * from it and act on seeing a response/data. */
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    if (!stream->output) {
        /* c2 has not assigned the output beam to the stream (yet). */
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c1,
                      H2_STRM_MSG(stream, "read_output, no output beam registered"));
    }
    else if (h2_stream_is_at_or_past(stream, H2_SS_CLOSED)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c1,
                      H2_STRM_LOG(APLOGNO(10301), stream, "already closed"));
    }
    else if (h2_stream_is_at(stream, H2_SS_CLOSED_L)) {
        /* We have delivered a response to a stream that was not closed
         * by the client. This could be a POST with body that we negate
         * and we need to RST_STREAM to end if. */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c1,
                      H2_STRM_LOG(APLOGNO(10313), stream, "remote close missing"));
        h2_stream_rst(stream, H2_ERR_NO_ERROR);
    }
    else {
        /* stream is not closed, a change in output happened. There are
         * two modes of operation here:
         * 1) the final response has been submitted. nghttp2 is invoking
         *    stream_data_cb() to progress the stream. This handles DATA,
         *    trailers, EOS and ERRORs.
         *    When stream_data_cb() runs out of things to send, it returns
         *    NGHTTP2_ERR_DEFERRED and nghttp2 *suspends* further processing
         *    until we tell it to resume.
         * 2) We have not seen the *final* response yet. The stream can not
         *    send any response DATA. The nghttp2 stream_data_cb() is not
         *    invoked. We need to receive output, expecting not DATA but
         *    RESPONSEs (intermediate may arrive) and submit those. On
         *    the final response, nghttp2 will start calling stream_data_cb().
         */
        if (stream->response) {
            nghttp2_session_resume_data(stream->session->ngh2, stream->id);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c1,
                          H2_STRM_MSG(stream, "resumed"));
        }
        else {
            stream_do_responses(stream);
            if (!stream->rst_error) {
                nghttp2_session_resume_data(stream->session->ngh2, stream->id);
            }
        }
    }
}

void h2_stream_on_input_change(h2_stream *stream)
{
    H2_STRM_ASSERT_MAGIC(stream, H2_STRM_MAGIC_OK);
    ap_assert(stream->input);
    h2_beam_report_consumption(stream->input);
    if (h2_stream_is_at(stream, H2_SS_CLOSED_L)
        && !h2_mplx_c1_stream_is_running(stream->session->mplx, stream)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, stream->session->c1,
                      H2_STRM_LOG(APLOGNO(10026), stream, "remote close missing"));
        h2_stream_rst(stream, H2_ERR_NO_ERROR);
    }
}
