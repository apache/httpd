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
#include "h2.h"
#include "h2_bucket_beam.h"
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

static void H2_STREAM_OUT_LOG(int lvl, h2_stream *s, char *tag)
{
    if (APLOG_C_IS_LEVEL(s->session->c, lvl)) {
        conn_rec *c = s->session->c;
        char buffer[4 * 1024];
        const char *line = "(null)";
        apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]);
        
        len = h2_util_bb_print(buffer, bmax, tag, "", s->buffer);
        ap_log_cerror(APLOG_MARK, lvl, 0, c, "bb_dump(%ld-%d): %s", 
                      c->id, s->id, len? buffer : line);
    }
}

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

static apr_status_t stream_pool_cleanup(void *ctx)
{
    h2_stream *stream = ctx;
    apr_status_t status;
    
    if (stream->input) {
        h2_beam_destroy(stream->input);
        stream->input = NULL;
    }
    if (stream->files) {
        apr_file_t *file;
        int i;
        for (i = 0; i < stream->files->nelts; ++i) {
            file = APR_ARRAY_IDX(stream->files, i, apr_file_t*);
            status = apr_file_close(file);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, stream->session->c, 
                          "h2_stream(%ld-%d): destroy, closed file %d", 
                          stream->session->id, stream->id, i);
        }
        stream->files = NULL;
    }
    return APR_SUCCESS;
}

h2_stream *h2_stream_open(int id, apr_pool_t *pool, h2_session *session,
                          int initiated_on, const h2_request *creq)
{
    h2_request *req;
    h2_stream *stream = apr_pcalloc(pool, sizeof(h2_stream));
    
    stream->id        = id;
    stream->state     = H2_STREAM_ST_IDLE;
    stream->pool      = pool;
    stream->session   = session;
    set_state(stream, H2_STREAM_ST_OPEN);
    
    if (creq) {
        /* take it into out pool and assure correct id's */
        req = h2_request_clone(pool, creq);
        req->id = id;
        req->initiated_on = initiated_on;
    }
    else {
        req = h2_req_create(id, pool, 
                h2_config_geti(session->config, H2_CONF_SER_HEADERS));
    }
    stream->request = req; 
    
    apr_pool_cleanup_register(pool, stream, stream_pool_cleanup, 
                              apr_pool_cleanup_null);
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03082)
                  "h2_stream(%ld-%d): opened", session->id, stream->id);
    return stream;
}

void h2_stream_cleanup(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    if (stream->buffer) {
        apr_brigade_cleanup(stream->buffer);
    }
    if (stream->input) {
        apr_status_t status;
        status = h2_beam_shutdown(stream->input, APR_NONBLOCK_READ);
        if (status == APR_EAGAIN) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c, 
                          "h2_stream(%ld-%d): wait on input shutdown", 
                          stream->session->id, stream->id);
            status = h2_beam_shutdown(stream->input, APR_BLOCK_READ);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, stream->session->c, 
                          "h2_stream(%ld-%d): input shutdown returned", 
                          stream->session->id, stream->id);
        }
    }
}

void h2_stream_destroy(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, stream->session->c, 
                  "h2_stream(%ld-%d): destroy", 
                  stream->session->id, stream->id);
    if (stream->pool) {
        apr_pool_destroy(stream->pool);
    }
}

void h2_stream_eos_destroy(h2_stream *stream)
{
    h2_session_stream_done(stream->session, stream);
    /* stream possibly destroyed */
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
    return stream->response;
}

apr_status_t h2_stream_set_request(h2_stream *stream, request_rec *r)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(stream);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    set_state(stream, H2_STREAM_ST_OPEN);
    status = h2_request_rwrite(stream->request, stream->pool, r);
    stream->request->serialize = h2_config_geti(h2_config_rget(r), 
                                                H2_CONF_SER_HEADERS);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, APLOGNO(03058)
                  "h2_request(%d): rwrite %s host=%s://%s%s",
                  stream->request->id, stream->request->method, 
                  stream->request->scheme, stream->request->authority, 
                  stream->request->path);

    return status;
}

apr_status_t h2_stream_add_header(h2_stream *stream,
                                  const char *name, size_t nlen,
                                  const char *value, size_t vlen)
{
    AP_DEBUG_ASSERT(stream);
    if (!stream->response) {
        if (name[0] == ':') {
            if ((vlen) > stream->session->s->limit_req_line) {
                /* pseudo header: approximation of request line size check */
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                              "h2_stream(%ld-%d): pseudo header %s too long", 
                              stream->session->id, stream->id, name);
                return h2_stream_set_error(stream, 
                                           HTTP_REQUEST_URI_TOO_LARGE);
            }
        }
        else if ((nlen + 2 + vlen) > stream->session->s->limit_req_fieldsize) {
            /* header too long */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                          "h2_stream(%ld-%d): header %s too long", 
                          stream->session->id, stream->id, name);
            return h2_stream_set_error(stream, 
                                       HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        
        if (name[0] != ':') {
            ++stream->request_headers_added;
            if (stream->request_headers_added 
                > stream->session->s->limit_req_fields) {
                /* too many header lines */
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                              "h2_stream(%ld-%d): too many header lines", 
                              stream->session->id, stream->id);
                return h2_stream_set_error(stream, 
                                           HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
            }
        }
    }
    
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
    
    if (stream->response) {
        /* already have a resonse, probably a HTTP error code */
        return h2_mplx_process(stream->session->mplx, stream, cmp, ctx);
    }
    
    /* Seeing the end-of-headers, we have everything we need to 
     * start processing it.
     */
    status = h2_request_end_headers(stream->request, stream->pool, 
                                    eos, push_enabled);
    if (status == APR_SUCCESS) {
        stream->request->body = !eos;
        stream->scheduled = 1;
        stream->input_remaining = stream->request->content_length;
        
        status = h2_mplx_process(stream->session->mplx, stream, cmp, ctx);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                      "h2_stream(%ld-%d): scheduled %s %s://%s%s",
                      stream->session->id, stream->id,
                      stream->request->method, stream->request->scheme,
                      stream->request->authority, stream->request->path);
    }
    else {
        h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, stream->session->c,
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
    
    if (close_input(stream) && stream->input) {
        status = h2_beam_close(stream->input);
    }
    return status;
}

apr_status_t h2_stream_write_data(h2_stream *stream,
                                  const char *data, size_t len, int eos)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;
    
    AP_DEBUG_ASSERT(stream);
    if (!stream->input) {
        return APR_EOF;
    }
    if (input_closed(stream) || !stream->request->eoh) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_stream(%ld-%d): writing denied, closed=%d, eoh=%d", 
                      stream->session->id, stream->id, input_closed(stream),
                      stream->request->eoh);
        return APR_EINVAL;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                  "h2_stream(%ld-%d): add %ld input bytes", 
                  stream->session->id, stream->id, (long)len);

    if (!stream->request->chunked) {
        stream->input_remaining -= len;
        if (stream->input_remaining < 0) {
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c,
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
    
    if (!stream->tmp) {
        stream->tmp = apr_brigade_create(stream->pool, c->bucket_alloc);
    }
    apr_brigade_write(stream->tmp, NULL, NULL, data, len);
    if (eos) {
        APR_BRIGADE_INSERT_TAIL(stream->tmp, 
                                apr_bucket_eos_create(c->bucket_alloc)); 
        close_input(stream);
    }
    
    status = h2_beam_send(stream->input, stream->tmp, APR_BLOCK_READ);
    apr_brigade_cleanup(stream->tmp);
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

static apr_status_t fill_buffer(h2_stream *stream, apr_size_t amount)
{
    conn_rec *c = stream->session->c;
    apr_bucket *b;
    apr_status_t status;
    
    if (!stream->output) {
        return APR_EOF;
    }
    status = h2_beam_receive(stream->output, stream->buffer, 
                             APR_NONBLOCK_READ, amount);
    /* The buckets we reveive are using the stream->buffer pool as
     * lifetime which is exactly what we want since this is stream->pool.
     *
     * However: when we send these buckets down the core output filters, the
     * filter might decide to setaside them into a pool of its own. And it
     * might decide, after having sent the buckets, to clear its pool.
     *
     * This is problematic for file buckets because it then closed the contained
     * file. Any split off buckets we sent afterwards will result in a 
     * APR_EBADF.
     */
    for (b = APR_BRIGADE_FIRST(stream->buffer);
         b != APR_BRIGADE_SENTINEL(stream->buffer);
         b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_FILE(b)) {
            apr_bucket_file *f = (apr_bucket_file *)b->data;
            apr_pool_t *fpool = apr_file_pool_get(f->fd);
            if (fpool != c->pool) {
                apr_bucket_setaside(b, c->pool);
                if (!stream->files) {
                    stream->files = apr_array_make(stream->pool, 
                                                   5, sizeof(apr_file_t*));
                }
                APR_ARRAY_PUSH(stream->files, apr_file_t*) = f->fd;
            }
        }
    }
    return status;
}

apr_status_t h2_stream_set_response(h2_stream *stream, h2_response *response,
                                    h2_bucket_beam *output)
{
    apr_status_t status = APR_SUCCESS;
    conn_rec *c = stream->session->c;
    
    if (!output_open(stream)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_stream(%ld-%d): output closed", 
                      stream->session->id, stream->id);
        return APR_ECONNRESET;
    }
    
    stream->response = response;
    stream->output = output;
    stream->buffer = apr_brigade_create(stream->pool, c->bucket_alloc);
    
    h2_stream_filter(stream);
    if (stream->output) {
        status = fill_buffer(stream, 0);
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                  "h2_stream(%ld-%d): set_response(%d)", 
                  stream->session->id, stream->id, 
                  stream->response->http_status);
    return status;
}

apr_status_t h2_stream_set_error(h2_stream *stream, int http_status)
{
    h2_response *response;
    
    if (stream->submitted) {
        return APR_EINVAL;
    }
    response = h2_response_die(stream->id, http_status, stream->request, 
                               stream->pool);
    return h2_stream_set_response(stream, response, NULL);
}

static const apr_size_t DATA_CHUNK_SIZE = ((16*1024) - 100 - 9); 

apr_status_t h2_stream_out_prepare(h2_stream *stream,
                                   apr_off_t *plen, int *peos)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;
    apr_off_t requested;

    if (stream->rst_error) {
        *plen = 0;
        *peos = 1;
        return APR_ECONNRESET;
    }

    if (*plen > 0) {
        requested = H2MIN(*plen, DATA_CHUNK_SIZE);
    }
    else {
        requested = DATA_CHUNK_SIZE;
    }
    *plen = requested;
    
    H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "h2_stream_out_prepare_pre");
    h2_util_bb_avail(stream->buffer, plen, peos);
    if (!*peos && *plen < requested) {
        /* try to get more data */
        status = fill_buffer(stream, (requested - *plen) + DATA_CHUNK_SIZE);
        if (APR_STATUS_IS_EOF(status)) {
            apr_bucket *eos = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(stream->buffer, eos);
            status = APR_SUCCESS;
        }
        else if (status == APR_EAGAIN) {
            /* did not receive more, it's ok */
            status = APR_SUCCESS;
        }
        *plen = requested;
        h2_util_bb_avail(stream->buffer, plen, peos);
    }
    H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "h2_stream_out_prepare_post");
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                  "h2_stream(%ld-%d): prepare, len=%ld eos=%d, trailers=%s",
                  c->id, stream->id, (long)*plen, *peos,
                  (stream->response && stream->response->trailers)? 
                  "yes" : "no");
    if (!*peos && !*plen && status == APR_SUCCESS) {
        return APR_EAGAIN;
    }
    return status;
}


apr_status_t h2_stream_read_to(h2_stream *stream, apr_bucket_brigade *bb, 
                               apr_off_t *plen, int *peos)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;

    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    status = h2_append_brigade(bb, stream->buffer, plen, peos);
    if (status == APR_SUCCESS && !*peos && !*plen) {
        status = APR_EAGAIN;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, c,
                  "h2_stream(%ld-%d): read_to, len=%ld eos=%d",
                  c->id, stream->id, (long)*plen, *peos);
    return status;
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
    return stream->response? stream->response->trailers : NULL;
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

