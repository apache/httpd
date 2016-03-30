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

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_log.h>

#include <nghttp2/nghttp2.h>

#include "h2_private.h"
#include "h2_conn.h"
#include "h2_config.h"
#include "h2_h2.h"
#include "h2_filter.h"
#include "h2_mplx.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_response.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_task.h"
#include "h2_ctx.h"
#include "h2_task_input.h"
#include "h2_task.h"
#include "h2_util.h"


static int state_transition[][7] = {
    /*  ID OP RL RR CI CO CL */
/*ID*/{  1, 0, 0, 0, 0, 0, 0 },
/*OP*/{  1, 1, 0, 0, 0, 0, 0 },
/*RL*/{  0, 0, 1, 0, 0, 0, 0 },
/*RR*/{  0, 0, 0, 1, 0, 0, 0 },
/*CI*/{  1, 1, 0, 0, 1, 0, 0 },
/*CO*/{  1, 1, 0, 0, 0, 1, 0 },
/*CL*/{  1, 1, 0, 0, 1, 1, 1 },
};

static int set_state(h2_stream *stream, h2_stream_state_t state)
{
    int allowed = state_transition[state][stream->state];
    if (allowed) {
        stream->state = state;
        return 1;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, stream->session->c, APLOGNO(03081)
                  "h2_stream(%ld-%d): invalid state transition from %d to %d", 
                  stream->session->id, stream->id, stream->state, state);
    return 0;
}

static int close_input(h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_CLOSED_INPUT:
        case H2_STREAM_ST_CLOSED:
            return 0; /* ignore, idempotent */
        case H2_STREAM_ST_CLOSED_OUTPUT:
            /* both closed now */
            set_state(stream, H2_STREAM_ST_CLOSED);
            break;
        default:
            /* everything else we jump to here */
            set_state(stream, H2_STREAM_ST_CLOSED_INPUT);
            break;
    }
    return 1;
}

static int input_closed(h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_OPEN:
        case H2_STREAM_ST_CLOSED_OUTPUT:
            return 0;
        default:
            return 1;
    }
}

static int close_output(h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_CLOSED_OUTPUT:
        case H2_STREAM_ST_CLOSED:
            return 0; /* ignore, idempotent */
        case H2_STREAM_ST_CLOSED_INPUT:
            /* both closed now */
            set_state(stream, H2_STREAM_ST_CLOSED);
            break;
        default:
            /* everything else we jump to here */
            set_state(stream, H2_STREAM_ST_CLOSED_OUTPUT);
            break;
    }
    return 1;
}

static int input_open(const h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_OPEN:
        case H2_STREAM_ST_CLOSED_OUTPUT:
            return 1;
        default:
            return 0;
    }
}

static int output_open(h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_OPEN:
        case H2_STREAM_ST_CLOSED_INPUT:
            return 1;
        default:
            return 0;
    }
}

static h2_sos *h2_sos_mplx_create(h2_stream *stream, h2_response *response);

h2_stream *h2_stream_open(int id, apr_pool_t *pool, h2_session *session)
{
    h2_stream *stream = apr_pcalloc(pool, sizeof(h2_stream));
    stream->id        = id;
    stream->state     = H2_STREAM_ST_IDLE;
    stream->pool      = pool;
    stream->session   = session;
    set_state(stream, H2_STREAM_ST_OPEN);
    stream->request   = h2_request_create(id, pool, 
        h2_config_geti(session->config, H2_CONF_SER_HEADERS));
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03082)
                  "h2_stream(%ld-%d): opened", session->id, stream->id);
    return stream;
}

apr_status_t h2_stream_destroy(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    if (stream->pool) {
        apr_pool_destroy(stream->pool);
    }
    return APR_SUCCESS;
}

void h2_stream_cleanup(h2_stream *stream)
{
    h2_session_stream_destroy(stream->session, stream);
    /* stream is gone */
}

apr_pool_t *h2_stream_detach_pool(h2_stream *stream)
{
    apr_pool_t *pool = stream->pool;
    stream->pool = NULL;
    return pool;
}

void h2_stream_rst(h2_stream *stream, int error_code)
{
    stream->rst_error = error_code;
    close_input(stream);
    close_output(stream);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                  "h2_stream(%ld-%d): reset, error=%d", 
                  stream->session->id, stream->id, error_code);
}

struct h2_response *h2_stream_get_response(h2_stream *stream)
{
    return stream->sos? stream->sos->response : NULL;
}

apr_status_t h2_stream_set_response(h2_stream *stream, h2_response *response,
                                    apr_bucket_brigade *bb)
{
    apr_status_t status = APR_SUCCESS;
    h2_sos *sos;
    
    if (!output_open(stream)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                      "h2_stream(%ld-%d): output closed", 
                      stream->session->id, stream->id);
        return APR_ECONNRESET;
    }
    
    sos = h2_sos_mplx_create(stream, response);
    if (sos->response->sos_filter) {
        sos = h2_filter_sos_create(sos->response->sos_filter, sos); 
    }
    stream->sos = sos;
    
    status = stream->sos->buffer(stream->sos, bb);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, stream->session->c,
                  "h2_stream(%ld-%d): set_response(%d)", 
                  stream->session->id, stream->id, stream->sos->response->http_status);
    return status;
}

apr_status_t h2_stream_set_request(h2_stream *stream, request_rec *r)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(stream);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    set_state(stream, H2_STREAM_ST_OPEN);
    status = h2_request_rwrite(stream->request, r);
    stream->request->serialize = h2_config_geti(h2_config_rget(r), 
                                                H2_CONF_SER_HEADERS);

    return status;
}

void h2_stream_set_h2_request(h2_stream *stream, int initiated_on,
                              const h2_request *req)
{
    h2_request_copy(stream->pool, stream->request, req);
    stream->request->initiated_on = initiated_on;
    stream->request->eoh = 0;
}

apr_status_t h2_stream_add_header(h2_stream *stream,
                                  const char *name, size_t nlen,
                                  const char *value, size_t vlen)
{
    AP_DEBUG_ASSERT(stream);
    if (h2_stream_is_scheduled(stream)) {
        return h2_request_add_trailer(stream->request, stream->pool,
                                      name, nlen, value, vlen);
    }
    else {
        if (!input_open(stream)) {
            return APR_ECONNRESET;
        }
        return h2_request_add_header(stream->request, stream->pool,
                                     name, nlen, value, vlen);
    }
}

apr_status_t h2_stream_schedule(h2_stream *stream, int eos, int push_enabled, 
                                h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(stream);
    AP_DEBUG_ASSERT(stream->session);
    AP_DEBUG_ASSERT(stream->session->mplx);
    
    if (!output_open(stream)) {
        return APR_ECONNRESET;
    }
    if (stream->scheduled) {
        return APR_EINVAL;
    }
    if (eos) {
        close_input(stream);
    }
    
    /* Seeing the end-of-headers, we have everything we need to 
     * start processing it.
     */
    status = h2_request_end_headers(stream->request, stream->pool, 
                                    eos, push_enabled);
    if (status == APR_SUCCESS) {
        if (!eos) {
            stream->request->body = 1;
        }
        stream->input_remaining = stream->request->content_length;
        
        status = h2_mplx_process(stream->session->mplx, stream->id, 
                                 stream->request, cmp, ctx);
        stream->scheduled = 1;
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                      "h2_stream(%ld-%d): scheduled %s %s://%s%s",
                      stream->session->id, stream->id,
                      stream->request->method, stream->request->scheme,
                      stream->request->authority, stream->request->path);
    }
    else {
        h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                      "h2_stream(%ld-%d): RST=2 (internal err) %s %s://%s%s",
                      stream->session->id, stream->id,
                      stream->request->method, stream->request->scheme,
                      stream->request->authority, stream->request->path);
    }
    
    return status;
}

int h2_stream_is_scheduled(const h2_stream *stream)
{
    return stream->scheduled;
}

apr_status_t h2_stream_close_input(h2_stream *stream)
{
    apr_status_t status = APR_SUCCESS;
    
    AP_DEBUG_ASSERT(stream);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                  "h2_stream(%ld-%d): closing input",
                  stream->session->id, stream->id);
                  
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    
    if (close_input(stream)) {
        status = h2_mplx_in_close(stream->session->mplx, stream->id);
    }
    return status;
}

apr_status_t h2_stream_write_data(h2_stream *stream,
                                  const char *data, size_t len, int eos)
{
    apr_status_t status = APR_SUCCESS;
    
    AP_DEBUG_ASSERT(stream);
    if (input_closed(stream) || !stream->request->eoh) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                      "h2_stream(%ld-%d): writing denied, closed=%d, eoh=%d", 
                      stream->session->id, stream->id, input_closed(stream),
                      stream->request->eoh);
        return APR_EINVAL;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                  "h2_stream(%ld-%d): add %ld input bytes", 
                  stream->session->id, stream->id, (long)len);

    if (!stream->request->chunked) {
        stream->input_remaining -= len;
        if (stream->input_remaining < 0) {
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, stream->session->c,
                          APLOGNO(02961) 
                          "h2_stream(%ld-%d): got %ld more content bytes than announced "
                          "in content-length header: %ld", 
                          stream->session->id, stream->id,
                          (long)stream->request->content_length, 
                          -(long)stream->input_remaining);
            h2_stream_rst(stream, H2_ERR_PROTOCOL_ERROR);
            return APR_ECONNABORTED;
        }
    }
    
    status = h2_mplx_in_write(stream->session->mplx, stream->id, data, len, eos);
    if (eos) {
        close_input(stream);
    }
    return status;
}

void h2_stream_set_suspended(h2_stream *stream, int suspended)
{
    AP_DEBUG_ASSERT(stream);
    stream->suspended = !!suspended;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c,
                  "h2_stream(%ld-%d): suspended=%d",
                  stream->session->id, stream->id, stream->suspended);
}

int h2_stream_is_suspended(const h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    return stream->suspended;
}

apr_status_t h2_stream_out_prepare(h2_stream *stream, 
                                   apr_off_t *plen, int *peos)
{
    if (stream->rst_error) {
        *plen = 0;
        *peos = 1;
        return APR_ECONNRESET;
    }

    AP_DEBUG_ASSERT(stream->sos);
    return stream->sos->prepare(stream->sos, plen, peos);
}

apr_status_t h2_stream_readx(h2_stream *stream, 
                             h2_io_data_cb *cb, void *ctx,
                             apr_off_t *plen, int *peos)
{
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    if (!stream->sos) {
        return APR_EGENERAL;
    }
    return stream->sos->readx(stream->sos, cb, ctx, plen, peos);
}

apr_status_t h2_stream_read_to(h2_stream *stream, apr_bucket_brigade *bb, 
                               apr_off_t *plen, int *peos)
{
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    if (!stream->sos) {
        return APR_EGENERAL;
    }
    return stream->sos->read_to(stream->sos, bb, plen, peos);
}

int h2_stream_input_is_open(const h2_stream *stream) 
{
    return input_open(stream);
}

int h2_stream_needs_submit(const h2_stream *stream)
{
    switch (stream->state) {
        case H2_STREAM_ST_OPEN:
        case H2_STREAM_ST_CLOSED_INPUT:
        case H2_STREAM_ST_CLOSED_OUTPUT:
        case H2_STREAM_ST_CLOSED:
            return !stream->submitted;
        default:
            return 0;
    }
}

apr_status_t h2_stream_submit_pushes(h2_stream *stream)
{
    apr_status_t status = APR_SUCCESS;
    apr_array_header_t *pushes;
    int i;
    
    pushes = h2_push_collect_update(stream, stream->request, 
                                    h2_stream_get_response(stream));
    if (pushes && !apr_is_empty_array(pushes)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                      "h2_stream(%ld-%d): found %d push candidates",
                      stream->session->id, stream->id, pushes->nelts);
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
    return stream->sos? stream->sos->get_trailers(stream->sos) : NULL;
}

const h2_priority *h2_stream_get_priority(h2_stream *stream)
{
    h2_response *response = h2_stream_get_response(stream);
    
    if (response && stream->request && stream->request->initiated_on) {
        const char *ctype = apr_table_get(response->headers, "content-type");
        if (ctype) {
            /* FIXME: Not good enough, config needs to come from request->server */
            return h2_config_get_priority(stream->session->config, ctype);
        }
    }
    return NULL;
}

/*******************************************************************************
 * h2_sos_mplx
 ******************************************************************************/

typedef struct h2_sos_mplx {
    h2_mplx *m;
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tmp;
    apr_table_t *trailers;
    apr_off_t  buffer_size;
} h2_sos_mplx;

#define H2_SOS_MPLX_OUT(lvl,msos,msg) \
    do { \
        if (APLOG_C_IS_LEVEL((msos)->m->c,lvl)) \
        h2_util_bb_log((msos)->m->c,(msos)->m->id,lvl,msg,(msos)->bb); \
    } while(0)
    

static apr_status_t mplx_transfer(h2_sos_mplx *msos, int stream_id, 
                                  apr_pool_t *pool)
{
    apr_status_t status;
    apr_table_t *trailers = NULL;
    
    if (!msos->tmp) {
        msos->tmp = apr_brigade_create(msos->bb->p, msos->bb->bucket_alloc);
    }
    status = h2_mplx_out_get_brigade(msos->m, stream_id, msos->tmp, 
                                     msos->buffer_size-1, &trailers);
    if (!APR_BRIGADE_EMPTY(msos->tmp)) {
        h2_transfer_brigade(msos->bb, msos->tmp, pool);
    }
    if (trailers) {
        msos->trailers = trailers;
    }
    return status;
}
 
static apr_status_t h2_sos_mplx_read_to(h2_sos *sos, apr_bucket_brigade *bb, 
                                        apr_off_t *plen, int *peos)
{
    h2_sos_mplx *msos = sos->ctx;
    apr_status_t status;

    status = h2_append_brigade(bb, msos->bb, plen, peos);
    if (status == APR_SUCCESS && !*peos && !*plen) {
        status = APR_EAGAIN;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, msos->m->c,
                      "h2_stream(%ld-%d): read_to, len=%ld eos=%d",
                      msos->m->id, sos->stream->id, (long)*plen, *peos);
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, msos->m->c,
                  "h2_stream(%ld-%d): read_to, len=%ld eos=%d",
                  msos->m->id, sos->stream->id, (long)*plen, *peos);
    return status;
}

static apr_status_t h2_sos_mplx_readx(h2_sos *sos, h2_io_data_cb *cb, void *ctx,
                                      apr_off_t *plen, int *peos)
{
    h2_sos_mplx *msos = sos->ctx;
    apr_status_t status = APR_SUCCESS;
    
    status = h2_util_bb_readx(msos->bb, cb, ctx, plen, peos);
    if (status == APR_SUCCESS && !*peos && !*plen) {
        status = APR_EAGAIN;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, msos->m->c,
                  "h2_stream(%ld-%d): readx, len=%ld eos=%d",
                  msos->m->id, sos->stream->id, (long)*plen, *peos);
    return status;
}

static apr_status_t h2_sos_mplx_prepare(h2_sos *sos, apr_off_t *plen, int *peos)
{
    h2_sos_mplx *msos = sos->ctx;
    apr_status_t status = APR_SUCCESS;
    
    H2_SOS_MPLX_OUT(APLOG_TRACE2, msos, "h2_sos_mplx prepare_pre");
    
    if (APR_BRIGADE_EMPTY(msos->bb)) {
        status = mplx_transfer(msos, sos->stream->id, sos->stream->pool);
    }
    h2_util_bb_avail(msos->bb, plen, peos);
    
    H2_SOS_MPLX_OUT(APLOG_TRACE2, msos, "h2_sos_mplx prepare_post");
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, msos->m->c,
                  "h2_stream(%ld-%d): prepare, len=%ld eos=%d, trailers=%s",
                  msos->m->id, sos->stream->id, (long)*plen, *peos,
                  msos->trailers? "yes" : "no");
    if (!*peos && !*plen) {
        status = APR_EAGAIN;
    }
    
    return status;
}

static apr_table_t *h2_sos_mplx_get_trailers(h2_sos *sos)
{
    h2_sos_mplx *msos = sos->ctx;

    return msos->trailers;
}

static apr_status_t h2_sos_mplx_buffer(h2_sos *sos, apr_bucket_brigade *bb) 
{
    h2_sos_mplx *msos = sos->ctx;
    apr_status_t status = APR_SUCCESS;

    if (bb && !APR_BRIGADE_EMPTY(bb)) {
        H2_SOS_MPLX_OUT(APLOG_TRACE2, msos, "h2_sos_mplx set_response_pre");
        status = mplx_transfer(msos, sos->stream->id, sos->stream->pool);
        H2_SOS_MPLX_OUT(APLOG_TRACE2, msos, "h2_sos_mplx set_response_post");
    }
    return status;
}

static h2_sos *h2_sos_mplx_create(h2_stream *stream, h2_response *response)
{
    h2_sos *sos;
    h2_sos_mplx *msos;
    
    msos = apr_pcalloc(stream->pool, sizeof(*msos));
    msos->m = stream->session->mplx;
    msos->bb = apr_brigade_create(stream->pool, msos->m->c->bucket_alloc);
    msos->buffer_size = 32 * 1024;
    
    sos = apr_pcalloc(stream->pool, sizeof(*sos));
    sos->stream = stream;
    sos->response = response;
    
    sos->ctx = msos;
    sos->buffer = h2_sos_mplx_buffer;
    sos->prepare = h2_sos_mplx_prepare;
    sos->readx = h2_sos_mplx_readx;
    sos->read_to = h2_sos_mplx_read_to;
    sos->get_trailers = h2_sos_mplx_get_trailers;
    
    sos->response = response;

    return sos;
}

