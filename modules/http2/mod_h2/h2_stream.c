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

#define APR_POOL_DEBUG  7

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

h2_stream *h2_stream_create(int id, apr_pool_t *pool, struct h2_mplx *m)
{
    h2_stream *stream = apr_pcalloc(pool, sizeof(h2_stream));
    if (stream != NULL) {
        stream->id = id;
        stream->state = H2_STREAM_ST_IDLE;
        stream->pool = pool;
        stream->m = m;
        stream->request = h2_request_create(id, pool, m->c->bucket_alloc);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c,
                      "h2_stream(%ld-%d): created", m->id, stream->id);
    }
    return stream;
}

void h2_stream_cleanup(h2_stream *stream)
{
    if (stream->request) {
        h2_request_destroy(stream->request);
        stream->request = NULL;
    }
}

apr_status_t h2_stream_destroy(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, stream->m->c,
                  "h2_stream(%ld-%d): destroy", stream->m->id, stream->id);
    h2_stream_cleanup(stream);
    
    if (stream->task) {
        h2_task_destroy(stream->task);
        stream->task = NULL;
    }
    if (stream->pool) {
        apr_pool_destroy(stream->pool);
    }
    return APR_SUCCESS;
}

void h2_stream_attach_pool(h2_stream *stream, apr_pool_t *pool)
{
    stream->pool = pool;
}

apr_pool_t *h2_stream_detach_pool(h2_stream *stream)
{
    apr_pool_t *pool = stream->pool;
    stream->pool = NULL;
    return pool;
}

void h2_stream_abort(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    stream->aborted = 1;
}

apr_status_t h2_stream_set_response(h2_stream *stream, h2_response *response,
                                    apr_bucket_brigade *bb)
{
    stream->response = response;
    if (bb && !APR_BRIGADE_EMPTY(bb)) {
        if (!stream->bbout) {
            stream->bbout = apr_brigade_create(stream->pool, 
                                               stream->m->c->bucket_alloc);
        }
        return h2_util_move(stream->bbout, bb, 16 * 1024, NULL,  
                            "h2_stream_set_response");
    }
    return APR_SUCCESS;
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
    AP_DEBUG_ASSERT(stream);
    set_state(stream, H2_STREAM_ST_OPEN);
    apr_status_t status = h2_request_rwrite(stream->request, r, stream->m);
    return status;
}

apr_status_t h2_stream_write_eoh(h2_stream *stream, int eos)
{
    AP_DEBUG_ASSERT(stream);
    /* Seeing the end-of-headers, we have everything we need to 
     * start processing it.
     */
    conn_rec *c = h2_conn_create(stream->m->c, stream->pool);
    if (c == NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, stream->m->c,
                      "h2_stream(%ld-%d): create connection",
                      stream->m->id, stream->id);
        return APR_ENOMEM;
    }
    stream->task = h2_task_create(stream->m->id, stream->id, 
                                  stream->pool, stream->m, c);
    
    apr_status_t status = h2_request_end_headers(stream->request, 
                                                 stream->m, stream->task, eos);
    if (status == APR_SUCCESS) {
        status = h2_mplx_do_task(stream->m, stream->task);
    }
    if (eos) {
        status = h2_stream_write_eos(stream);
    }
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, stream->m->c,
                  "h2_stream(%ld-%d): end header, task %s %s (%s)",
                  stream->m->id, stream->id,
                  stream->request->method, stream->request->path,
                  stream->request->authority);
    
    return status;
}

apr_status_t h2_stream_write_eos(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, stream->m->c,
                  "h2_stream(%ld-%d): closing input",
                  stream->m->id, stream->id);
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
                                   value, vlen, stream->m);
}

apr_status_t h2_stream_write_data(h2_stream *stream,
                                  const char *data, size_t len)
{
    AP_DEBUG_ASSERT(stream);
    AP_DEBUG_ASSERT(stream);
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
    
    if (stream->bbout && !APR_BRIGADE_EMPTY(stream->bbout)) {
        src = "stream";
        status = h2_util_bb_avail(stream->bbout, plen, peos);
        if (status == APR_SUCCESS && !*peos && !*plen) {
            apr_brigade_cleanup(stream->bbout);
            return h2_stream_prep_read(stream, plen, peos);
        }
    }
    else {
        src = "mplx";
        status = h2_mplx_out_readx(stream->m, stream->id, 
                                   NULL, NULL, plen, peos);
    }
    if (status == APR_SUCCESS && !*peos && !*plen) {
        status = APR_EAGAIN;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, stream->m->c,
                  "h2_stream(%ld-%d): prep_read %s, len=%ld eos=%d",
                  stream->m->id, stream->id, 
                  src, (long)*plen, *peos);
    return status;
}

apr_status_t h2_stream_readx(h2_stream *stream, 
                             h2_io_data_cb *cb, void *ctx,
                             apr_size_t *plen, int *peos)
{
    if (stream->bbout && !APR_BRIGADE_EMPTY(stream->bbout)) {
        return h2_util_bb_readx(stream->bbout, cb, ctx, plen, peos);
    }
    return h2_mplx_out_readx(stream->m, stream->id, 
                             cb, ctx, plen, peos);
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

