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

static void H2_STREAM_OUT_LOG(int lvl, h2_stream *s, const char *tag)
{
    if (APLOG_C_IS_LEVEL(s->session->c, lvl)) {
        conn_rec *c = s->session->c;
        char buffer[4 * 1024];
        const char *line = "(null)";
        apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]);
        
        len = h2_util_bb_print(buffer, bmax, tag, "", s->out_buffer);
        ap_log_cerror(APLOG_MARK, lvl, 0, c, "bb_dump(%s): %s", 
                      c->log_id, len? buffer : line);
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

static void prep_output(h2_stream *stream) {
    conn_rec *c = stream->session->c;
    if (!stream->out_buffer) {
        stream->out_buffer = apr_brigade_create(stream->pool, c->bucket_alloc);
    }
}

static void prepend_response(h2_stream *stream, h2_headers *response)
{
    conn_rec *c = stream->session->c;
    apr_bucket *b;
    
    prep_output(stream);
    b = h2_bucket_headers_create(c->bucket_alloc, response);
    APR_BRIGADE_INSERT_HEAD(stream->out_buffer, b);
}

static apr_status_t stream_pool_cleanup(void *ctx)
{
    h2_stream *stream = ctx;
    apr_status_t status;
    
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
                          int initiated_on)
{
    h2_stream *stream = apr_pcalloc(pool, sizeof(h2_stream));
    
    stream->id           = id;
    stream->initiated_on = initiated_on;
    stream->created      = apr_time_now();
    stream->state        = H2_STREAM_ST_IDLE;
    stream->pool         = pool;
    stream->session      = session;

    h2_beam_create(&stream->input, pool, id, "input", 0);
    h2_beam_create(&stream->output, pool, id, "output", 0);
    
    set_state(stream, H2_STREAM_ST_OPEN);
    apr_pool_cleanup_register(pool, stream, stream_pool_cleanup, 
                              apr_pool_cleanup_null);
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03082)
                  "h2_stream(%ld-%d): opened", session->id, stream->id);
    return stream;
}

void h2_stream_cleanup(h2_stream *stream)
{
    AP_DEBUG_ASSERT(stream);
    if (stream->out_buffer) {
        apr_brigade_cleanup(stream->out_buffer);
    }
    if (stream->input) {
        apr_status_t status;
        status = h2_beam_shutdown(stream->input, APR_NONBLOCK_READ, 1);
        if (status == APR_EAGAIN) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c, 
                          "h2_stream(%ld-%d): wait on input shutdown", 
                          stream->session->id, stream->id);
            status = h2_beam_shutdown(stream->input, APR_BLOCK_READ, 1);
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
    if (stream->out_buffer) {
        apr_brigade_cleanup(stream->out_buffer);
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                  "h2_stream(%ld-%d): reset, error=%d", 
                  stream->session->id, stream->id, error_code);
}

apr_status_t h2_stream_set_request_rec(h2_stream *stream, request_rec *r)
{
    h2_request *req;
    apr_status_t status;

    ap_assert(stream->request == NULL);
    ap_assert(stream->rtmp == NULL);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    status = h2_request_rcreate(&req, stream->pool, r);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, APLOGNO(03058)
                  "h2_request(%d): set_request_rec %s host=%s://%s%s",
                  stream->id, req->method, req->scheme, req->authority, 
                  req->path);
    stream->rtmp = req;
    return status;
}

apr_status_t h2_stream_set_request(h2_stream *stream, const h2_request *r)
{
    ap_assert(stream->request == NULL);
    ap_assert(stream->rtmp == NULL);
    stream->rtmp = h2_request_clone(stream->pool, r);
    return APR_SUCCESS;
}

static apr_status_t add_trailer(h2_stream *stream,
                                const char *name, size_t nlen,
                                const char *value, size_t vlen)
{
    conn_rec *c = stream->session->c;
    char *hname, *hvalue;

    if (nlen == 0 || name[0] == ':') {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EINVAL, c, APLOGNO(03060)
                      "h2_request(%ld-%d): pseudo header in trailer",
                      c->id, stream->id);
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
    AP_DEBUG_ASSERT(stream);
    
    if (!stream->has_response) {
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
        return add_trailer(stream, name, nlen, value, vlen);
    }
    else {
        if (!stream->rtmp) {
            stream->rtmp = h2_req_create(stream->id, stream->pool, 
                                         NULL, NULL, NULL, NULL, NULL, 0);
        }
        if (stream->state != H2_STREAM_ST_OPEN) {
            return APR_ECONNRESET;
        }
        return h2_request_add_header(stream->rtmp, stream->pool,
                                     name, nlen, value, vlen);
    }
}

apr_status_t h2_stream_schedule(h2_stream *stream, int eos, int push_enabled, 
                                h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status = APR_EINVAL;
    AP_DEBUG_ASSERT(stream);
    AP_DEBUG_ASSERT(stream->session);
    AP_DEBUG_ASSERT(stream->session->mplx);
    
    if (!stream->scheduled) {
        if (eos) {
            close_input(stream);
        }

        if (h2_stream_is_ready(stream)) {
            /* already have a resonse, probably a HTTP error code */
            return h2_mplx_process(stream->session->mplx, stream, cmp, ctx);
        }
        else if (!stream->request && stream->rtmp) {
            /* This is the common case: a h2_request was being assembled, now
             * it gets finalized and checked for completness */
            status = h2_request_end_headers(stream->rtmp, stream->pool, eos);
            if (status == APR_SUCCESS) {
                stream->rtmp->serialize = h2_config_geti(stream->session->config,
                                                         H2_CONF_SER_HEADERS); 

                stream->request = stream->rtmp;
                stream->rtmp = NULL;
                stream->scheduled = 1;
                stream->push_policy = h2_push_policy_determine(stream->request->headers, 
                                                               stream->pool, push_enabled);
            
                
                status = h2_mplx_process(stream->session->mplx, stream, cmp, ctx);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                              "h2_stream(%ld-%d): scheduled %s %s://%s%s "
                              "chunked=%d",
                              stream->session->id, stream->id,
                              stream->request->method, stream->request->scheme,
                              stream->request->authority, stream->request->path,
                              stream->request->chunked);
                return status;
            }
        }
        else {
            status = APR_ECONNRESET;
        }
    }
    
    h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, stream->session->c,
                  "h2_stream(%ld-%d): RST=2 (internal err) %s %s://%s%s",
                  stream->session->id, stream->id,
                  stream->request->method, stream->request->scheme,
                  stream->request->authority, stream->request->path);
    return status;
}

int h2_stream_is_scheduled(const h2_stream *stream)
{
    return stream->scheduled;
}

apr_status_t h2_stream_close_input(h2_stream *stream)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS, rv;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                  "h2_stream(%ld-%d): closing input",
                  stream->session->id, stream->id);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    
    if (!stream->input) {
        h2_beam_create(&stream->input, stream->pool, stream->id, "input", 0);
    }
    
    if (stream->trailers && !apr_is_empty_table(stream->trailers)) {
        h2_headers *r = h2_headers_create(HTTP_OK, stream->trailers, 
                                          NULL, stream->pool);
        apr_bucket *b = h2_bucket_headers_create(c->bucket_alloc, r);
        apr_bucket_brigade *tmp;
        
        tmp = apr_brigade_create(stream->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(tmp, b);
        status = h2_beam_send(stream->input, tmp, APR_BLOCK_READ);
        apr_brigade_destroy(tmp);
        
        stream->trailers = NULL;
    }
    
    close_input(stream);
    rv = h2_beam_close(stream->input);
    return status ? status : rv;
}

apr_status_t h2_stream_write_data(h2_stream *stream,
                                  const char *data, size_t len, int eos)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;
    apr_bucket_brigade *tmp;
    
    AP_DEBUG_ASSERT(stream);
    if (!stream->input) {
        return APR_EOF;
    }
    if (input_closed(stream) || !stream->request) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_stream(%ld-%d): writing denied, closed=%d, eoh=%d", 
                      stream->session->id, stream->id, input_closed(stream),
                      stream->request != NULL);
        return APR_EINVAL;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                  "h2_stream(%ld-%d): add %ld input bytes", 
                  stream->session->id, stream->id, (long)len);
    
    tmp = apr_brigade_create(stream->pool, c->bucket_alloc);
    apr_brigade_write(tmp, NULL, NULL, data, len);
    status = h2_beam_send(stream->input, tmp, APR_BLOCK_READ);
    apr_brigade_destroy(tmp);
    
    stream->in_data_frames++;
    stream->in_data_octets += len;
    
    if (eos) {
        return h2_stream_close_input(stream);
    }
    
    return status;
}

static apr_status_t fill_buffer(h2_stream *stream, apr_size_t amount)
{
    conn_rec *c = stream->session->c;
    apr_bucket *b;
    apr_status_t status;
    
    if (!stream->output) {
        return APR_EOF;
    }
    status = h2_beam_receive(stream->output, stream->out_buffer, 
                             APR_NONBLOCK_READ, amount);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, stream->session->c,
                  "h2_stream(%ld-%d): beam_received",
                  stream->session->id, stream->id);
    /* The buckets we reveive are using the stream->out_buffer pool as
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
    for (b = APR_BRIGADE_FIRST(stream->out_buffer);
         b != APR_BRIGADE_SENTINEL(stream->out_buffer);
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

apr_status_t h2_stream_set_error(h2_stream *stream, int http_status)
{
    h2_headers *response;
    
    if (h2_stream_is_ready(stream)) {
        return APR_EINVAL;
    }
    if (stream->rtmp) {
        stream->request = stream->rtmp;
        stream->rtmp = NULL;
    }
    response = h2_headers_die(http_status, stream->request, stream->pool);
    prepend_response(stream, response);
    h2_beam_close(stream->output);
    return APR_SUCCESS;
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
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;
    apr_off_t requested;
    apr_bucket *b, *e;

    if (presponse) {
        *presponse = NULL;
    }
    
    if (stream->rst_error) {
        *plen = 0;
        *peos = 1;
        return APR_ECONNRESET;
    }
    
    if (!output_open(stream)) {
        return APR_ECONNRESET;
    }
    prep_output(stream);

    if (*plen > 0) {
        requested = H2MIN(*plen, H2_DATA_CHUNK_SIZE);
    }
    else {
        requested = H2_DATA_CHUNK_SIZE;
    }
    *plen = requested;
    
    H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "h2_stream_out_prepare_pre");
    h2_util_bb_avail(stream->out_buffer, plen, peos);
    if (!*peos && *plen < requested) {
        /* try to get more data */
        status = fill_buffer(stream, (requested - *plen) + H2_DATA_CHUNK_SIZE);
        if (APR_STATUS_IS_EOF(status)) {
            apr_bucket *eos = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(stream->out_buffer, eos);
            status = APR_SUCCESS;
        }
        else if (status == APR_EAGAIN) {
            /* did not receive more, it's ok */
            status = APR_SUCCESS;
        }
        *plen = requested;
        h2_util_bb_avail(stream->out_buffer, plen, peos);
    }
    H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "h2_stream_out_prepare_post");
    
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
    
    if (!*peos && !*plen && status == APR_SUCCESS 
        && (!presponse || !*presponse)) {
        status = APR_EAGAIN;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c,
                  "h2_stream(%ld-%d): prepare, len=%ld eos=%d",
                  c->id, stream->id, (long)*plen, *peos);
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
                  "h2_stream(%ld-%d): read_to, len=%ld eos=%d",
                  c->id, stream->id, (long)*plen, *peos);
    return status;
}


int h2_stream_input_is_open(const h2_stream *stream) 
{
    return input_open(stream);
}

apr_status_t h2_stream_submit_pushes(h2_stream *stream, h2_headers *response)
{
    apr_status_t status = APR_SUCCESS;
    apr_array_header_t *pushes;
    int i;
    
    pushes = h2_push_collect_update(stream, stream->request, response);
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

const char *h2_stream_state_str(h2_stream *stream)
{
    switch (stream->state) {
        case H2_STREAM_ST_IDLE:
            return "IDLE";
        case H2_STREAM_ST_OPEN:
            return "OPEN";
        case H2_STREAM_ST_RESV_LOCAL:
            return "RESERVED_LOCAL";
        case H2_STREAM_ST_RESV_REMOTE:
            return "RESERVED_REMOTE";
        case H2_STREAM_ST_CLOSED_INPUT:
            return "HALF_CLOSED_REMOTE";
        case H2_STREAM_ST_CLOSED_OUTPUT:
            return "HALF_CLOSED_LOCAL";
        case H2_STREAM_ST_CLOSED:
            return "CLOSED";
        default:
            return "UNKNOWN";
            
    }
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


