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

#include <apr_strings.h>
#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>
#include <scoreboard.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_config.h"
#include "h2_conn_io.h"
#include "h2_ctx.h"
#include "h2_mplx.h"
#include "h2_push.h"
#include "h2_task.h"
#include "h2_stream.h"
#include "h2_request.h"
#include "h2_response.h"
#include "h2_stream.h"
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

void h2_filter_cin_timeout_set(h2_filter_cin *cin, apr_interval_time_t timeout)
{
    cin->timeout = timeout;
}

apr_status_t h2_filter_core_input(ap_filter_t* f,
                                  apr_bucket_brigade* brigade,
                                  ap_input_mode_t mode,
                                  apr_read_type_e block,
                                  apr_off_t readbytes) 
{
    h2_filter_cin *cin = f->ctx;
    apr_status_t status = APR_SUCCESS;
    apr_interval_time_t saved_timeout = UNSET;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                  "core_input(%ld): read, %s, mode=%d, readbytes=%ld", 
                  (long)f->c->id, (block == APR_BLOCK_READ)? "BLOCK_READ" : "NONBLOCK_READ", 
                  mode, (long)readbytes);
    
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
            if (cin->timeout > 0) {
                apr_socket_timeout_get(cin->socket, &saved_timeout);
                apr_socket_timeout_set(cin->socket, cin->timeout);
            }
        }
        status = ap_get_brigade(f->next, cin->bb, AP_MODE_READBYTES,
                                block, readbytes);
        if (saved_timeout != UNSET) {
            apr_socket_timeout_set(cin->socket, saved_timeout);
        }
    }
    
    switch (status) {
        case APR_SUCCESS:
            status = consume_brigade(cin, cin->bb, block);
            break;
        case APR_EOF:
        case APR_EAGAIN:
        case APR_TIMEUP:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                          "core_input(%ld): read", (long)f->c->id);
            break;
        default:
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, f->c, APLOGNO(03046)
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

static apr_status_t bbout(apr_bucket_brigade *bb, const char *fmt, ...)
{
    va_list args;
    apr_status_t rv;

    va_start(args, fmt);
    rv = apr_brigade_vprintf(bb, NULL, NULL, fmt, args);
    va_end(args);

    return rv;
}

static void add_settings(apr_bucket_brigade *bb, h2_session *s, int last) 
{
    h2_mplx *m = s->mplx;
    
    bbout(bb, "  \"settings\": {\n");
    bbout(bb, "    \"SETTINGS_MAX_CONCURRENT_STREAMS\": %d,\n", m->max_streams); 
    bbout(bb, "    \"SETTINGS_MAX_FRAME_SIZE\": %d,\n", 16*1024); 
    bbout(bb, "    \"SETTINGS_INITIAL_WINDOW_SIZE\": %d,\n",
          h2_config_geti(s->config, H2_CONF_WIN_SIZE));
    bbout(bb, "    \"SETTINGS_ENABLE_PUSH\": %d\n", h2_session_push_enabled(s)); 
    bbout(bb, "  }%s\n", last? "" : ",");
}

static void add_peer_settings(apr_bucket_brigade *bb, h2_session *s, int last) 
{
    bbout(bb, "  \"peerSettings\": {\n");
    bbout(bb, "    \"SETTINGS_MAX_CONCURRENT_STREAMS\": %d,\n", 
        nghttp2_session_get_remote_settings(s->ngh2, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)); 
    bbout(bb, "    \"SETTINGS_MAX_FRAME_SIZE\": %d,\n", 
        nghttp2_session_get_remote_settings(s->ngh2, NGHTTP2_SETTINGS_MAX_FRAME_SIZE)); 
    bbout(bb, "    \"SETTINGS_INITIAL_WINDOW_SIZE\": %d,\n", 
        nghttp2_session_get_remote_settings(s->ngh2, NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE)); 
    bbout(bb, "    \"SETTINGS_ENABLE_PUSH\": %d,\n", 
        nghttp2_session_get_remote_settings(s->ngh2, NGHTTP2_SETTINGS_ENABLE_PUSH)); 
    bbout(bb, "    \"SETTINGS_HEADER_TABLE_SIZE\": %d,\n", 
        nghttp2_session_get_remote_settings(s->ngh2, NGHTTP2_SETTINGS_HEADER_TABLE_SIZE)); 
    bbout(bb, "    \"SETTINGS_MAX_HEADER_LIST_SIZE\": %d\n", 
        nghttp2_session_get_remote_settings(s->ngh2, NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE)); 
    bbout(bb, "  }%s\n", last? "" : ",");
}

typedef struct {
    apr_bucket_brigade *bb;
    h2_session *s;
    int idx;
} stream_ctx_t;

static int add_stream(h2_stream *stream, void *ctx)
{
    stream_ctx_t *x = ctx;
    int32_t flowIn, flowOut;
    
    flowIn = nghttp2_session_get_stream_effective_local_window_size(x->s->ngh2, stream->id); 
    flowOut = nghttp2_session_get_stream_remote_window_size(x->s->ngh2, stream->id);
    bbout(x->bb, "%s\n    \"%d\": {\n", (x->idx? "," : ""), stream->id);
    bbout(x->bb, "    \"state\": \"%s\",\n", h2_stream_state_str(stream));
    bbout(x->bb, "    \"created\": %f,\n", ((double)stream->created)/APR_USEC_PER_SEC);
    bbout(x->bb, "    \"flowIn\": %d,\n", flowIn);
    bbout(x->bb, "    \"flowOut\": %d,\n", flowOut);
    bbout(x->bb, "    \"dataIn\": %"APR_UINT64_T_FMT",\n", stream->in_data_octets);  
    bbout(x->bb, "    \"dataOut\": %"APR_UINT64_T_FMT"\n", stream->out_data_octets);  
    bbout(x->bb, "    }");
    
    ++x->idx;
    return 1;
} 

static void add_streams(apr_bucket_brigade *bb, h2_session *s, int last) 
{
    stream_ctx_t x;
    
    x.bb = bb;
    x.s = s;
    x.idx = 0;
    bbout(bb, "  \"streams\": {");
    h2_mplx_stream_do(s->mplx, add_stream, &x);
    bbout(bb, "\n  }%s\n", last? "" : ",");
}

static void add_push(apr_bucket_brigade *bb, h2_session *s, 
                     h2_stream *stream, int last) 
{
    h2_push_diary *diary;
    apr_status_t status;
    
    bbout(bb, "    \"push\": {\n");
    diary = s->push_diary;
    if (diary) {
        const char *data;
        const char *base64_digest;
        apr_size_t len;
        
        status = h2_push_diary_digest_get(diary, bb->p, 256, 
                                          stream->request->authority, 
                                          &data, &len);
        if (status == APR_SUCCESS) {
            base64_digest = h2_util_base64url_encode(data, len, bb->p);
            bbout(bb, "      \"cacheDigest\": \"%s\",\n", base64_digest);
        }
    }
    bbout(bb, "      \"promises\": %d,\n", s->pushes_promised);
    bbout(bb, "      \"submits\": %d,\n", s->pushes_submitted);
    bbout(bb, "      \"resets\": %d\n", s->pushes_reset);
    bbout(bb, "    }%s\n", last? "" : ",");
}

static void add_in(apr_bucket_brigade *bb, h2_session *s, int last) 
{
    bbout(bb, "    \"in\": {\n");
    bbout(bb, "      \"requests\": %d,\n", s->remote.emitted_count);
    bbout(bb, "      \"resets\": %d, \n", s->streams_reset);
    bbout(bb, "      \"frames\": %ld,\n", (long)s->frames_received);
    bbout(bb, "      \"octets\": %"APR_UINT64_T_FMT"\n", s->io.bytes_read);
    bbout(bb, "    }%s\n", last? "" : ",");
}

static void add_out(apr_bucket_brigade *bb, h2_session *s, int last) 
{
    bbout(bb, "    \"out\": {\n");
    bbout(bb, "      \"responses\": %d,\n", s->responses_submitted);
    bbout(bb, "      \"frames\": %ld,\n", (long)s->frames_sent);
    bbout(bb, "      \"octets\": %"APR_UINT64_T_FMT"\n", s->io.bytes_written);
    bbout(bb, "    }%s\n", last? "" : ",");
}

static void add_stats(apr_bucket_brigade *bb, h2_session *s, 
                     h2_stream *stream, int last) 
{
    bbout(bb, "  \"stats\": {\n");
    add_in(bb, s, 0);
    add_out(bb, s, 0);
    add_push(bb, s, stream, 1);
    bbout(bb, "  }%s\n", last? "" : ",");
}

static apr_status_t h2_status_stream_filter(h2_stream *stream)
{
    h2_session *s = stream->session;
    conn_rec *c = s->c;
    apr_bucket_brigade *bb;
    int32_t connFlowIn, connFlowOut;
    
    if (!stream->response) {
        return APR_EINVAL;
    }
    
    if (!stream->buffer) {
        stream->buffer = apr_brigade_create(stream->pool, c->bucket_alloc);
    }
    bb = stream->buffer;
    
    apr_table_unset(stream->response->headers, "Content-Length");
    stream->response->content_length = -1;
    
    connFlowIn = nghttp2_session_get_effective_local_window_size(s->ngh2); 
    connFlowOut = nghttp2_session_get_remote_window_size(s->ngh2);
    apr_table_setn(stream->response->headers, "conn-flow-in", 
                   apr_itoa(stream->pool, connFlowIn));
    apr_table_setn(stream->response->headers, "conn-flow-out", 
                   apr_itoa(stream->pool, connFlowOut));
     
    bbout(bb, "{\n");
    bbout(bb, "  \"version\": \"draft-01\",\n");
    add_settings(bb, s, 0);
    add_peer_settings(bb, s, 0);
    bbout(bb, "  \"connFlowIn\": %d,\n", connFlowIn);
    bbout(bb, "  \"connFlowOut\": %d,\n", connFlowOut);
    bbout(bb, "  \"sentGoAway\": %d,\n", s->local.shutdown);

    add_streams(bb, s, 0);
    
    add_stats(bb, s, stream, 1);
    bbout(bb, "}\n");
    
    return APR_SUCCESS;
}

apr_status_t h2_stream_filter(h2_stream *stream)
{
    const char *fname = stream->response? stream->response->sos_filter : NULL; 
    if (fname && !strcmp(H2_SOS_H2_STATUS, fname)) {
        return h2_status_stream_filter(stream);
    }
    return APR_SUCCESS;
}

