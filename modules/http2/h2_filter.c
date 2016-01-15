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

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>
#include <scoreboard.h>

#include "h2_private.h"
#include "h2_conn_io.h"
#include "h2_ctx.h"
#include "h2_mplx.h"
#include "h2_push.h"
#include "h2_task.h"
#include "h2_stream.h"
#include "h2_stream_set.h"
#include "h2_response.h"
#include "h2_session.h"
#include "h2_util.h"
#include "h2_version.h"

#include "h2_filter.h"

#define UNSET       -1
#define H2MIN(x,y) ((x) < (y) ? (x) : (y))

static apr_status_t consume_brigade(h2_filter_cin *cin, 
                                    apr_bucket_brigade *bb, 
                                    apr_read_type_e block)
{
    apr_status_t status = APR_SUCCESS;
    apr_size_t readlen = 0;
    
    while (status == APR_SUCCESS && !APR_BRIGADE_EMPTY(bb)) {
        
        apr_bucket* bucket = APR_BRIGADE_FIRST(bb);
        if (APR_BUCKET_IS_METADATA(bucket)) {
            /* we do nothing regarding any meta here */
        }
        else {
            const char *bucket_data = NULL;
            apr_size_t bucket_length = 0;
            status = apr_bucket_read(bucket, &bucket_data,
                                     &bucket_length, block);
            
            if (status == APR_SUCCESS && bucket_length > 0) {
                apr_size_t consumed = 0;

                status = cin->cb(cin->cb_ctx, bucket_data, bucket_length, &consumed);
                if (status == APR_SUCCESS && bucket_length > consumed) {
                    /* We have data left in the bucket. Split it. */
                    status = apr_bucket_split(bucket, consumed);
                }
                readlen += consumed;
                cin->start_read = apr_time_now();
            }
        }
        apr_bucket_delete(bucket);
    }
    
    if (readlen == 0 && status == APR_SUCCESS && block == APR_NONBLOCK_READ) {
        return APR_EAGAIN;
    }
    return status;
}

h2_filter_cin *h2_filter_cin_create(apr_pool_t *p, h2_filter_cin_cb *cb, void *ctx)
{
    h2_filter_cin *cin;
    
    cin = apr_pcalloc(p, sizeof(*cin));
    cin->pool      = p;
    cin->cb        = cb;
    cin->cb_ctx    = ctx;
    cin->start_read = UNSET;
    return cin;
}

void h2_filter_cin_timeout_set(h2_filter_cin *cin, int timeout_secs)
{
    cin->timeout_secs = timeout_secs;
}

apr_status_t h2_filter_core_input(ap_filter_t* f,
                                  apr_bucket_brigade* brigade,
                                  ap_input_mode_t mode,
                                  apr_read_type_e block,
                                  apr_off_t readbytes) 
{
    h2_filter_cin *cin = f->ctx;
    apr_status_t status = APR_SUCCESS;
    apr_time_t saved_timeout = UNSET;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                  "core_input(%ld): read, %s, mode=%d, readbytes=%ld, timeout=%d", 
                  (long)f->c->id, (block == APR_BLOCK_READ)? "BLOCK_READ" : "NONBLOCK_READ", 
                  mode, (long)readbytes, cin->timeout_secs);
    
    if (mode == AP_MODE_INIT || mode == AP_MODE_SPECULATIVE) {
        return ap_get_brigade(f->next, brigade, mode, block, readbytes);
    }
    
    if (mode != AP_MODE_READBYTES) {
        return (block == APR_BLOCK_READ)? APR_SUCCESS : APR_EAGAIN;
    }
    
    if (!cin->bb) {
        cin->bb = apr_brigade_create(cin->pool, f->c->bucket_alloc);
    }

    if (!cin->socket) {
        cin->socket = ap_get_conn_socket(f->c);
    }
    
    cin->start_read = apr_time_now();
    if (APR_BRIGADE_EMPTY(cin->bb)) {
        /* We only do a blocking read when we have no streams to process. So,
         * in httpd scoreboard lingo, we are in a KEEPALIVE connection state.
         * When reading non-blocking, we do have streams to process and update
         * child with NULL request. That way, any current request information
         * in the scoreboard is preserved.
         */
        if (block == APR_BLOCK_READ) {
            if (cin->timeout_secs > 0) {
                apr_time_t t = apr_time_from_sec(cin->timeout_secs);
                apr_socket_timeout_get(cin->socket, &saved_timeout);
                apr_socket_timeout_set(cin->socket, t);
            }
        }
        status = ap_get_brigade(f->next, cin->bb, AP_MODE_READBYTES,
                                block, readbytes);
        if (saved_timeout != UNSET) {
            apr_socket_timeout_set(cin->socket, saved_timeout);
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "core_input(%ld): got_brigade", (long)f->c->id);
    }
    
    switch (status) {
        case APR_SUCCESS:
            status = consume_brigade(cin, cin->bb, block);
            break;
        case APR_EOF:
        case APR_EAGAIN:
        case APR_TIMEUP:
            break;
        default:
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, f->c,
                          "h2_conn_io: error reading");
            break;
    }
    return status;
}

/*******************************************************************************
 * http2 connection status handler + stream out source
 ******************************************************************************/

static const char *H2_SOS_H2_STATUS = "http2-status";

int h2_filter_h2_status_handler(request_rec *r)
{
    h2_ctx *ctx = h2_ctx_rget(r);
    h2_task *task;
    
    if (strcmp(r->handler, "http2-status")) {
        return DECLINED;
    }
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    task = ctx? h2_ctx_get_task(ctx) : NULL;
    if (task) {
        /* We need to handle the actual output on the main thread, as
         * we need to access h2_session information. */
        apr_table_setn(r->notes, H2_RESP_SOS_NOTE, H2_SOS_H2_STATUS);
        apr_table_setn(r->headers_out, "Content-Type", "application/json");
        r->status = 200;
        return DONE;
    }
    return DECLINED;
}

#define bbout(...)   apr_brigade_printf(bb, NULL, NULL, __VA_ARGS__)
static apr_status_t h2_sos_h2_status_buffer(h2_sos *sos, apr_bucket_brigade *bb)
{
    h2_stream *stream = sos->stream;
    h2_session *session = stream->session;
    h2_mplx *mplx = session->mplx;
    apr_status_t status;
    
    if (!bb) {
        bb = apr_brigade_create(stream->pool, session->c->bucket_alloc);
    }
    
    bbout("{\n");
    bbout("  \"HTTP2\": \"on\",\n");
    bbout("  \"H2PUSH\": \"%s\",\n", h2_session_push_enabled(session)? "on" : "off");
    bbout("  \"mod_http2_version\": \"%s\",\n", MOD_HTTP2_VERSION);
    bbout("  \"session_id\": %ld,\n", (long)session->id);
    bbout("  \"streams_max\": %d,\n", (int)session->max_stream_count);
    bbout("  \"this_stream\": %d,\n", stream->id);
    bbout("  \"streams_open\": %d,\n", (int)h2_stream_set_size(session->streams));
    bbout("  \"max_stream_started\": %d,\n", mplx->max_stream_started);
    bbout("  \"requests_received\": %d,\n", session->requests_received);
    bbout("  \"responses_submitted\": %d,\n", session->responses_submitted);
    bbout("  \"streams_reset\": %d, \n", session->streams_reset);
    bbout("  \"pushes_promised\": %d,\n", session->pushes_promised);
    bbout("  \"pushes_submitted\": %d,\n", session->pushes_submitted);
    bbout("  \"pushes_reset\": %d,\n", session->pushes_reset);
    
    if (session->push_diary) {
        const char *data;
        const char *base64_digest;
        apr_size_t len;
        
        status = h2_push_diary_digest_get(session->push_diary, stream->pool, 1024, &data, &len);
        if (status == APR_SUCCESS) {
            base64_digest = h2_util_base64url_encode(data, len, stream->pool);
            bbout("  \"cache_digest\": \"%s\",\n", base64_digest);
        }
        
        /* try the reverse for testing purposes */
        status = h2_push_diary_digest_set(session->push_diary, data, len);
        if (status == APR_SUCCESS) {
            status = h2_push_diary_digest_get(session->push_diary, stream->pool, 1024, &data, &len);
            if (status == APR_SUCCESS) {
                base64_digest = h2_util_base64url_encode(data, len, stream->pool);
                bbout("  \"cache_digest^2\": \"%s\",\n", base64_digest);
            }
        }
    }
    bbout("  \"frames_received\": %ld,\n", (long)session->frames_received);
    bbout("  \"frames_sent\": %ld,\n", (long)session->frames_sent);
    bbout("  \"bytes_received\": %"APR_UINT64_T_FMT",\n", session->io.bytes_read);
    bbout("  \"bytes_sent\": %"APR_UINT64_T_FMT"\n", session->io.bytes_written);
    bbout("}\n");
    
    return sos->prev->buffer(sos->prev, bb);
}

static apr_status_t h2_sos_h2_status_read_to(h2_sos *sos, apr_bucket_brigade *bb, 
                                             apr_off_t *plen, int *peos)
{
    return sos->prev->read_to(sos->prev, bb, plen, peos);
}

static apr_status_t h2_sos_h2_status_prep_read(h2_sos *sos, apr_off_t *plen, int *peos)
{
    return sos->prev->prep_read(sos->prev, plen, peos);
}

static apr_status_t h2_sos_h2_status_readx(h2_sos *sos, h2_io_data_cb *cb, void *ctx,
                                           apr_off_t *plen, int *peos)
{
    return sos->prev->readx(sos->prev, cb, ctx, plen, peos);
}

static apr_table_t *h2_sos_h2_status_get_trailers(h2_sos *sos)
{
    return sos->prev->get_trailers(sos->prev);
}

static h2_sos *h2_sos_h2_status_create(h2_sos *prev) 
{
    h2_sos *sos;
    h2_response *response = prev->response;
    
    apr_table_unset(response->headers, "Content-Length");
    response->content_length = -1;

    sos = apr_pcalloc(prev->stream->pool, sizeof(*sos));
    sos->prev         = prev;
    sos->response     = response;
    sos->stream       = prev->stream;
    sos->buffer       = h2_sos_h2_status_buffer;
    sos->prep_read    = h2_sos_h2_status_prep_read;
    sos->readx        = h2_sos_h2_status_readx;
    sos->read_to      = h2_sos_h2_status_read_to;
    sos->get_trailers = h2_sos_h2_status_get_trailers;
    
    return sos;
}

h2_sos *h2_filter_sos_create(const char *name, struct h2_sos *prev)
{
    if (!strcmp(H2_SOS_H2_STATUS, name)) {
        return h2_sos_h2_status_create(prev);
    }
    return prev;
}

