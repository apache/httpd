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
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_response.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_task.h"
#include "h2_ctx.h"
#include "h2_task_input.h"
#include "h2_task.h"
#include "h2_util.h"


static void set_state(h2_stream *stream, h2_stream_state_t state)
{
    AP_DEBUG_ASSERT(stream);
    if (stream->state != state) {
        stream->state = state;
    }
}

h2_stream *h2_stream_create(int id, apr_pool_t *pool, h2_session *session)
{
    h2_stream *stream = apr_pcalloc(pool, sizeof(h2_stream));
    if (stream != NULL) {
        stream->id = id;
        stream->state = H2_STREAM_ST_IDLE;
        stream->pool = pool;
        stream->session = session;
        stream->bbout = apr_brigade_create(stream->pool, 
                                           stream->session->c->bucket_alloc);
        stream->request = h2_request_create(id, pool, session->c->bucket_alloc);
        
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c,
                      "h2_stream(%ld-%d): created", session->id, stream->id);
    }
    return stream;
}

apr_status_t h2_stream_destroy(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, stream->session->c,
                  "h2_stream(%ld-%d): destroy", stream->session->id, stream->id);
    if (stream->request) {
        h2_request_destroy(stream->request);
        stream->request = NULL;
    }
    
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
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, stream->session->c,
                  "h2_stream(%ld-%d): reset, error=%d", 
                  stream->session->id, stream->id, error_code);
}

apr_status_t h2_stream_set_response(h2_stream *stream, h2_response *response,
                                    apr_bucket_brigade *bb)
{
    apr_status_t status = APR_SUCCESS;
    
    stream->response = response;
    if (bb && !APR_BRIGADE_EMPTY(bb)) {
        int move_all = INT_MAX;
        /* we can move file handles from h2_mplx into this h2_stream as many
         * as we want, since the lifetimes are the same and we are not freeing
         * the ones in h2_mplx->io before this stream is done. */
        status = h2_util_move(stream->bbout, bb, 16 * 1024, &move_all,  
                              "h2_stream_set_response");
    }
    if (APLOGctrace1(stream->session->c)) {
        apr_size_t len = 0;
        int eos = 0;
        h2_util_bb_avail(stream->bbout, &len, &eos);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, stream->session->c,
                      "h2_stream(%ld-%d): set_response(%s), len=%ld, eos=%d", 
                      stream->session->id, stream->id, response->status,
                      (long)len, (int)eos);
    }
    return status;
}

static int set_closed(h2_stream *stream) 
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

apr_status_t h2_stream_rwrite(h2_stream *stream, request_rec *r)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(stream);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    set_state(stream, H2_STREAM_ST_OPEN);
    status = h2_request_rwrite(stream->request, r, stream->session->mplx);
    return status;
}

apr_status_t h2_stream_schedule(h2_stream *stream, int eos,
                                h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(stream);
    
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    /* Seeing the end-of-headers, we have everything we need to 
     * start processing it.
     */
    status = h2_mplx_process(stream->session->mplx, stream->id, 
                             stream->request, eos, cmp, ctx);
    if (eos) {
        set_closed(stream);
    }
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, stream->session->c,
                  "h2_mplx(%ld-%d): start stream, task %s %s (%s)",
                  stream->session->id, stream->id,
                  stream->request->method, stream->request->path,
                  stream->request->authority);
    
    return status;
}

apr_status_t h2_stream_write_eos(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, stream->session->c,
                  "h2_stream(%ld-%d): closing input",
                  stream->session->id, stream->id);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    if (set_closed(stream)) {
        return h2_request_close(stream->request);
    }
    return APR_SUCCESS;
}

apr_status_t h2_stream_write_header(h2_stream *stream,
                                    const char *name, size_t nlen,
                                    const char *value, size_t vlen)
{
    AP_DEBUG_ASSERT(stream);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    switch (stream->state) {
        case H2_STREAM_ST_IDLE:
            set_state(stream, H2_STREAM_ST_OPEN);
            break;
        case H2_STREAM_ST_OPEN:
            break;
        default:
            return APR_EINVAL;
    }
    return h2_request_write_header(stream->request, name, nlen,
                                   value, vlen, stream->session->mplx);
}

apr_status_t h2_stream_write_data(h2_stream *stream,
                                  const char *data, size_t len)
{
    AP_DEBUG_ASSERT(stream);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    switch (stream->state) {
        case H2_STREAM_ST_OPEN:
            break;
        default:
            return APR_EINVAL;
    }
    return h2_request_write_data(stream->request, data, len);
}

apr_status_t h2_stream_prep_read(h2_stream *stream, 
                                 apr_size_t *plen, int *peos)
{
    apr_status_t status = APR_SUCCESS;
    const char *src;
    
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }

    if (!APR_BRIGADE_EMPTY(stream->bbout)) {
        src = "stream";
        status = h2_util_bb_avail(stream->bbout, plen, peos);
        if (status == APR_SUCCESS && !*peos && !*plen) {
            apr_brigade_cleanup(stream->bbout);
            return h2_stream_prep_read(stream, plen, peos);
        }
    }
    else {
        src = "mplx";
        status = h2_mplx_out_readx(stream->session->mplx, stream->id, 
                                   NULL, NULL, plen, peos);
    }
    if (status == APR_SUCCESS && !*peos && !*plen) {
        status = APR_EAGAIN;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, stream->session->c,
                  "h2_stream(%ld-%d): prep_read %s, len=%ld eos=%d",
                  stream->session->id, stream->id, src, (long)*plen, *peos);
    return status;
}

apr_status_t h2_stream_readx(h2_stream *stream, 
                             h2_io_data_cb *cb, void *ctx,
                             apr_size_t *plen, int *peos)
{
    apr_status_t status = APR_SUCCESS;
    const char *src;
    
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    *peos = 0;
    if (!APR_BRIGADE_EMPTY(stream->bbout)) {
        apr_size_t origlen = *plen;
        
        src = "stream";
        status = h2_util_bb_readx(stream->bbout, cb, ctx, plen, peos);
        if (status == APR_SUCCESS && !*peos && !*plen) {
            apr_brigade_cleanup(stream->bbout);
            *plen = origlen;
            return h2_stream_readx(stream, cb, ctx, plen, peos);
        }
    }
    else {
        src = "mplx";
        status = h2_mplx_out_readx(stream->session->mplx, stream->id, 
                                   cb, ctx, plen, peos);
    }
    
    if (status == APR_SUCCESS && !*peos && !*plen) {
        status = APR_EAGAIN;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, stream->session->c,
                  "h2_stream(%ld-%d): readx %s, len=%ld eos=%d",
                  stream->session->id, stream->id, src, (long)*plen, *peos);
    return status;
}

apr_status_t h2_stream_read_to(h2_stream *stream, apr_bucket_brigade *bb, 
                               apr_size_t *plen, int *peos)
{
    apr_status_t status = APR_SUCCESS;

    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    
    if (APR_BRIGADE_EMPTY(stream->bbout)) {
        apr_size_t tlen = *plen;
        int eos;
        status = h2_mplx_out_read_to(stream->session->mplx, stream->id, 
                                     stream->bbout, &tlen, &eos);
    }
    
    if (status == APR_SUCCESS && !APR_BRIGADE_EMPTY(stream->bbout)) {
        status = h2_transfer_brigade(bb, stream->bbout, stream->pool, 
                                     plen, peos);
    }
    else {
        *plen = 0;
        *peos = 0;
    }

    if (status == APR_SUCCESS && !*peos && !*plen) {
        status = APR_EAGAIN;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, stream->session->c,
                  "h2_stream(%ld-%d): read_to, len=%ld eos=%d",
                  stream->session->id, stream->id, (long)*plen, *peos);
    return status;
}

void h2_stream_set_suspended(h2_stream *stream, int suspended)
{
    AP_DEBUG_ASSERT(stream);
    stream->suspended = !!suspended;
}

int h2_stream_is_suspended(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    return stream->suspended;
}

