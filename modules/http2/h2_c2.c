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

#include <apr_atomic.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_vhost.h>
#include <util_filter.h>
#include <ap_mmn.h>
#include <ap_mpm.h>
#include <mpm_common.h>
#include <mod_core.h>
#include <scoreboard.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_bucket_beam.h"
#include "h2_c1.h"
#include "h2_config.h"
#include "h2_conn_ctx.h"
#include "h2_c2_filter.h"
#include "h2_protocol.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_c2.h"
#include "h2_util.h"


static module *mpm_module;
static int mpm_supported = 1;
static apr_socket_t *dummy_socket;

static ap_filter_rec_t *c2_net_in_filter_handle;
static ap_filter_rec_t *c2_net_out_filter_handle;
static ap_filter_rec_t *c2_request_in_filter_handle;
static ap_filter_rec_t *c2_notes_out_filter_handle;


static void check_modules(int force)
{
    static int checked = 0;
    int i;

    if (force || !checked) {
        for (i = 0; ap_loaded_modules[i]; ++i) {
            module *m = ap_loaded_modules[i];

            if (!strcmp("event.c", m->name)) {
                mpm_module = m;
                break;
            }
            else if (!strcmp("motorz.c", m->name)) {
                mpm_module = m;
                break;
            }
            else if (!strcmp("mpm_netware.c", m->name)) {
                mpm_module = m;
                break;
            }
            else if (!strcmp("prefork.c", m->name)) {
                mpm_module = m;
                /* While http2 can work really well on prefork, it collides
                 * today's use case for prefork: running single-thread app engines
                 * like php. If we restrict h2_workers to 1 per process, php will
                 * work fine, but browser will be limited to 1 active request at a
                 * time. */
                mpm_supported = 0;
                break;
            }
            else if (!strcmp("simple_api.c", m->name)) {
                mpm_module = m;
                mpm_supported = 0;
                break;
            }
            else if (!strcmp("mpm_winnt.c", m->name)) {
                mpm_module = m;
                break;
            }
            else if (!strcmp("worker.c", m->name)) {
                mpm_module = m;
                break;
            }
        }
        checked = 1;
    }
}

const char *h2_conn_mpm_name(void)
{
    check_modules(0);
    return mpm_module? mpm_module->name : "unknown";
}

int h2_mpm_supported(void)
{
    check_modules(0);
    return mpm_supported;
}

apr_status_t h2_c2_child_init(apr_pool_t *pool, server_rec *s)
{
    check_modules(1);
    return apr_socket_create(&dummy_socket, APR_INET, SOCK_STREAM,
                             APR_PROTO_TCP, pool);
}

void h2_c2_destroy(conn_rec *c2)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c2,
                  "h2_c2(%s): destroy", c2->log_id);
    apr_pool_destroy(c2->pool);
}

void h2_c2_abort(conn_rec *c2, conn_rec *from)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c2);

    AP_DEBUG_ASSERT(conn_ctx);
    AP_DEBUG_ASSERT(conn_ctx->stream_id);
    if (conn_ctx->beam_in) {
        h2_beam_abort(conn_ctx->beam_in, from);
    }
    if (conn_ctx->beam_out) {
        h2_beam_abort(conn_ctx->beam_out, from);
    }
    c2->aborted = 1;
}

typedef struct {
    apr_bucket_brigade *bb;       /* c2: data in holding area */
} h2_c2_fctx_in_t;

static apr_status_t h2_c2_filter_in(ap_filter_t* f,
                                           apr_bucket_brigade* bb,
                                           ap_input_mode_t mode,
                                           apr_read_type_e block,
                                           apr_off_t readbytes)
{
    h2_conn_ctx_t *conn_ctx;
    h2_c2_fctx_in_t *fctx = f->ctx;
    apr_status_t status = APR_SUCCESS;
    apr_bucket *b;
    apr_off_t bblen;
    apr_size_t rmax = ((readbytes <= APR_SIZE_MAX)?
                       (apr_size_t)readbytes : APR_SIZE_MAX);
    
    conn_ctx = h2_conn_ctx_get(f->c);
    AP_DEBUG_ASSERT(conn_ctx);

    if (mode == AP_MODE_INIT) {
        return ap_get_brigade(f->c->input_filters, bb, mode, block, readbytes);
    }
    
    if (f->c->aborted) {
        return APR_ECONNABORTED;
    }
    
    if (APLOGctrace3(f->c)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, f->c,
                      "h2_c2_in(%s-%d): read, mode=%d, block=%d, readbytes=%ld",
                      conn_ctx->id, conn_ctx->stream_id, mode, block,
                      (long)readbytes);
    }

    if (!fctx) {
        fctx = apr_pcalloc(f->c->pool, sizeof(*fctx));
        f->ctx = fctx;
        fctx->bb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
        if (!conn_ctx->beam_in) {
            b = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(fctx->bb, b);
        }
    }
    
    while (APR_BRIGADE_EMPTY(fctx->bb)) {
        /* Get more input data for our request. */
        if (APLOGctrace2(f->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, f->c,
                          "h2_c2_in(%s-%d): get more data from mplx, block=%d, "
                          "readbytes=%ld",
                          conn_ctx->id, conn_ctx->stream_id, block, (long)readbytes);
        }
        if (conn_ctx->beam_in) {
            if (conn_ctx->pipe_in[H2_PIPE_OUT]) {
receive:
                status = h2_beam_receive(conn_ctx->beam_in, f->c, fctx->bb, APR_NONBLOCK_READ,
                                         conn_ctx->mplx->stream_max_mem);
                if (APR_STATUS_IS_EAGAIN(status) && APR_BLOCK_READ == block) {
                    status = h2_util_wait_on_pipe(conn_ctx->pipe_in[H2_PIPE_OUT]);
                    if (APR_SUCCESS == status) {
                        goto receive;
                    }
                }
            }
            else {
                status = h2_beam_receive(conn_ctx->beam_in, f->c, fctx->bb, block,
                                         conn_ctx->mplx->stream_max_mem);
            }
        }
        else {
            status = APR_EOF;
        }
        
        if (APLOGctrace3(f->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, f->c,
                          "h2_c2_in(%s-%d): read returned",
                          conn_ctx->id, conn_ctx->stream_id);
        }
        if (APR_STATUS_IS_EAGAIN(status) 
            && (mode == AP_MODE_GETLINE || block == APR_BLOCK_READ)) {
            /* chunked input handling does not seem to like it if we
             * return with APR_EAGAIN from a GETLINE read... 
             * upload 100k test on test-ser.example.org hangs */
            status = APR_SUCCESS;
        }
        else if (APR_STATUS_IS_EOF(status)) {
            break;
        }
        else if (status != APR_SUCCESS) {
            conn_ctx->last_err = status;
            return status;
        }

        if (APLOGctrace3(f->c)) {
            h2_util_bb_log(f->c, conn_ctx->stream_id, APLOG_TRACE3,
                        "c2 input recv raw", fctx->bb);
        }
        if (h2_c_logio_add_bytes_in) {
            apr_brigade_length(bb, 0, &bblen);
            h2_c_logio_add_bytes_in(f->c, bblen);
        }
    }
    
    /* Nothing there, no more data to get. Return. */
    if (status == APR_EOF && APR_BRIGADE_EMPTY(fctx->bb)) {
        return status;
    }

    if (APLOGctrace3(f->c)) {
        h2_util_bb_log(f->c, conn_ctx->stream_id, APLOG_TRACE3,
                    "c2 input.bb", fctx->bb);
    }
           
    if (APR_BRIGADE_EMPTY(fctx->bb)) {
        if (APLOGctrace3(f->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, f->c,
                          "h2_c2_in(%s-%d): no data",
                          conn_ctx->id, conn_ctx->stream_id);
        }
        return (block == APR_NONBLOCK_READ)? APR_EAGAIN : APR_EOF;
    }
    
    if (mode == AP_MODE_EXHAUSTIVE) {
        /* return all we have */
        APR_BRIGADE_CONCAT(bb, fctx->bb);
    }
    else if (mode == AP_MODE_READBYTES) {
        status = h2_brigade_concat_length(bb, fctx->bb, rmax);
    }
    else if (mode == AP_MODE_SPECULATIVE) {
        status = h2_brigade_copy_length(bb, fctx->bb, rmax);
    }
    else if (mode == AP_MODE_GETLINE) {
        /* we are reading a single LF line, e.g. the HTTP headers. 
         * this has the nasty side effect to split the bucket, even
         * though it ends with CRLF and creates a 0 length bucket */
        status = apr_brigade_split_line(bb, fctx->bb, block,
                                        HUGE_STRING_LEN);
        if (APLOGctrace3(f->c)) {
            char buffer[1024];
            apr_size_t len = sizeof(buffer)-1;
            apr_brigade_flatten(bb, buffer, &len);
            buffer[len] = 0;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, f->c,
                          "h2_c2_in(%s-%d): getline: %s",
                          conn_ctx->id, conn_ctx->stream_id, buffer);
        }
    }
    else {
        /* Hmm, well. There is mode AP_MODE_EATCRLF, but we chose not
         * to support it. Seems to work. */
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, f->c,
                      APLOGNO(03472) 
                      "h2_c2_in(%s-%d), unsupported READ mode %d",
                      conn_ctx->id, conn_ctx->stream_id, mode);
        status = APR_ENOTIMPL;
    }
    
    if (APLOGctrace3(f->c)) {
        apr_brigade_length(bb, 0, &bblen);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, f->c,
                      "h2_c2_in(%s-%d): %ld data bytes",
                      conn_ctx->id, conn_ctx->stream_id, (long)bblen);
    }
    return status;
}

static apr_status_t beam_out(conn_rec *c2, h2_conn_ctx_t *conn_ctx, apr_bucket_brigade* bb)
{
    apr_off_t written, header_len = 0;
    apr_status_t rv;

    if (h2_c_logio_add_bytes_out) {
        /* mod_logio wants to report the number of bytes  written in a
         * response, including header and footer fields. Since h2 converts
         * those during c1 processing into the HPACKed h2 HEADER frames,
         * we need to give mod_logio something here and count just the
         * raw lengths of all headers in the buckets. */
        apr_bucket *b;
        for (b = APR_BRIGADE_FIRST(bb);
             b != APR_BRIGADE_SENTINEL(bb);
             b = APR_BUCKET_NEXT(b)) {
            if (AP_BUCKET_IS_RESPONSE(b)) {
                header_len += (apr_off_t)response_length_estimate(b->data);
            }
            if (AP_BUCKET_IS_HEADERS(b)) {
                header_len += (apr_off_t)headers_length_estimate(b->data);
            }
        }
    }

    rv = h2_beam_send(conn_ctx->beam_out, c2, bb, APR_BLOCK_READ, &written);

    if (APR_STATUS_IS_EAGAIN(rv)) {
        rv = APR_SUCCESS;
    }
    if (written && h2_c_logio_add_bytes_out) {
        h2_c_logio_add_bytes_out(c2, written + header_len);
    }
    return rv;
}

static apr_status_t h2_c2_filter_out(ap_filter_t* f, apr_bucket_brigade* bb)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(f->c);
    apr_bucket *e;
    apr_status_t rv;

    ap_assert(conn_ctx);
    if (!conn_ctx->has_final_response) {
        for (e = APR_BRIGADE_FIRST(bb);
             e != APR_BRIGADE_SENTINEL(bb);
             e = APR_BUCKET_NEXT(e))
        {
            if (AP_BUCKET_IS_RESPONSE(e)) {
                ap_bucket_response *resp = e->data;
                if (resp->status >= 200) {
                    conn_ctx->has_final_response = 1;
                    break;
                }
            }
            if (APR_BUCKET_IS_EOS(e)) {
                break;
            }
        }
    }
    rv = beam_out(f->c, conn_ctx, bb);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, f->c,
                  "h2_c2(%s-%d): output leave",
                  conn_ctx->id, conn_ctx->stream_id);
    if (APR_SUCCESS != rv) {
        h2_c2_abort(f->c, f->c);
    }
    return rv;
}

static int c2_hook_pre_connection(conn_rec *c2, void *csd)
{
    h2_conn_ctx_t *conn_ctx;

    if (!c2->master || !(conn_ctx = h2_conn_ctx_get(c2)) || !conn_ctx->stream_id) {
        return DECLINED;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c2,
                  "h2_c2(%s-%d), adding filters",
                  conn_ctx->id, conn_ctx->stream_id);
    ap_add_input_filter_handle(c2_net_in_filter_handle, NULL, NULL, c2);
    ap_add_output_filter_handle(c2_net_out_filter_handle, NULL, NULL, c2);
    if (c2->keepalives == 0) {
        /* Simulate that we had already a request on this connection. Some
         * hooks trigger special behaviour when keepalives is 0.
         * (Not necessarily in pre_connection, but later. Set it here, so it
         * is in place.) */
        c2->keepalives = 1;
        /* We signal that this connection will be closed after the request.
         * Which is true in that sense that we throw away all traffic data
         * on this c2 connection after each requests. Although we might
         * reuse internal structures like memory pools.
         * The wanted effect of this is that httpd does not try to clean up
         * any dangling data on this connection when a request is done. Which
         * is unnecessary on a h2 stream.
         */
        c2->keepalive = AP_CONN_CLOSE;
    }
    return OK;
}

static void check_push(request_rec *r, const char *tag)
{
    apr_array_header_t *push_list = h2_config_push_list(r);

    if (!r->expecting_100 && push_list && push_list->nelts > 0) {
        int i, old_status;
        const char *old_line;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "%s, early announcing %d resources for push",
                      tag, push_list->nelts);
        for (i = 0; i < push_list->nelts; ++i) {
            h2_push_res *push = &APR_ARRAY_IDX(push_list, i, h2_push_res);
            apr_table_add(r->headers_out, "Link",
                           apr_psprintf(r->pool, "<%s>; rel=preload%s",
                                        push->uri_ref, push->critical? "; critical" : ""));
        }
        old_status = r->status;
        old_line = r->status_line;
        r->status = 103;
        r->status_line = "103 Early Hints";
        ap_send_interim_response(r, 1);
        r->status = old_status;
        r->status_line = old_line;
    }
}

static void c2_pre_read_request(request_rec *r, conn_rec *c2)
{
    h2_conn_ctx_t *conn_ctx;

    if (!c2->master || !(conn_ctx = h2_conn_ctx_get(c2)) || !conn_ctx->stream_id) {
        return;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                  "h2_c2(%s-%d): adding request filters",
                  conn_ctx->id, conn_ctx->stream_id);
    ap_add_input_filter_handle(c2_request_in_filter_handle, NULL, r, r->connection);
    ap_add_output_filter_handle(c2_notes_out_filter_handle, NULL, r, r->connection);
}

static int c2_post_read_request(request_rec *r)
{
    h2_conn_ctx_t *conn_ctx;
    conn_rec *c2 = r->connection;

    if (!c2->master || !(conn_ctx = h2_conn_ctx_get(c2)) || !conn_ctx->stream_id) {
        return DECLINED;
    }
    /* Now that the request_rec is fully initialized, set relevant params */
    conn_ctx->server = r->server;
    h2_conn_ctx_set_timeout(conn_ctx, r->server->timeout);
    /* We only handle this one request on the connection and tell everyone
     * that there is no need to keep it "clean" if something fails. Also,
     * this prevents mod_reqtimeout from doing funny business with monitoring
     * keepalive timeouts.
     */
    r->connection->keepalive = AP_CONN_CLOSE;

    if (conn_ctx->beam_in && !apr_table_get(r->headers_in, "Content-Length")) {
        r->body_indeterminate = 1;
    }

    if (h2_config_sgeti(conn_ctx->server, H2_CONF_COPY_FILES)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "h2_mplx(%s-%d): copy_files in output",
                      conn_ctx->id, conn_ctx->stream_id);
        h2_beam_set_copy_files(conn_ctx->beam_out, 1);
    }

    /* Add the raw bytes of the request (e.g. header frame lengths to
     * the logio for this request. */
    if (conn_ctx->request->raw_bytes && h2_c_logio_add_bytes_in) {
        h2_c_logio_add_bytes_in(c2, conn_ctx->request->raw_bytes);
    }
    return OK;
}

static int c2_hook_fixups(request_rec *r)
{
    conn_rec *c2 = r->connection;
    h2_conn_ctx_t *conn_ctx;

    if (!c2->master || !(conn_ctx = h2_conn_ctx_get(c2)) || !conn_ctx->stream_id) {
        return DECLINED;
    }

    check_push(r, "late_fixup");

    return DECLINED;
}

void h2_c2_register_hooks(void)
{
    /* When the connection processing actually starts, we might
     * take over, if the connection is for a h2 stream.
     */
    ap_hook_pre_connection(c2_hook_pre_connection,
                           NULL, NULL, APR_HOOK_MIDDLE);

    /* We need to manipulate the standard HTTP/1.1 protocol filters and
     * install our own. This needs to be done very early. */
    ap_hook_pre_read_request(c2_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(c2_post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_fixups(c2_hook_fixups, NULL, NULL, APR_HOOK_LAST);

    c2_net_in_filter_handle =
        ap_register_input_filter("H2_C2_NET_IN", h2_c2_filter_in,
                                 NULL, AP_FTYPE_NETWORK);
    c2_net_out_filter_handle =
        ap_register_output_filter("H2_C2_NET_OUT", h2_c2_filter_out,
                                  NULL, AP_FTYPE_NETWORK);
    c2_request_in_filter_handle =
        ap_register_input_filter("H2_C2_REQUEST_IN", h2_c2_filter_request_in,
                                 NULL, AP_FTYPE_PROTOCOL);
    c2_notes_out_filter_handle =
        ap_register_output_filter("H2_C2_NOTES_OUT", h2_c2_filter_notes_out,
                                  NULL, AP_FTYPE_PROTOCOL);
}

