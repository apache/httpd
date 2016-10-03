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

#include <apr_atomic.h>
#include <apr_thread_cond.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_vhost.h>
#include <util_filter.h>
#include <ap_mpm.h>
#include <mod_core.h>
#include <scoreboard.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_bucket_beam.h"
#include "h2_conn.h"
#include "h2_config.h"
#include "h2_ctx.h"
#include "h2_from_h1.h"
#include "h2_h2.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_headers.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_task.h"
#include "h2_worker.h"
#include "h2_util.h"

static void H2_TASK_OUT_LOG(int lvl, h2_task *task, apr_bucket_brigade *bb, char *tag)
{
    if (APLOG_C_IS_LEVEL(task->c, lvl)) {
        conn_rec *c = task->c;
        char buffer[4 * 1024];
        const char *line = "(null)";
        apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]);
        
        len = h2_util_bb_print(buffer, bmax, tag, "", bb);
        ap_log_cerror(APLOG_MARK, lvl, 0, c, "bb_dump(%s): %s", 
                      task->id, len? buffer : line);
    }
}

/*******************************************************************************
 * task input handling
 ******************************************************************************/

static int input_ser_header(void *ctx, const char *name, const char *value) 
{
    h2_task *task = ctx;
    apr_brigade_printf(task->input.bb, NULL, NULL, "%s: %s\r\n", name, value);
    return 1;
}

static apr_status_t input_read(h2_task *task, ap_filter_t* f,
                               apr_bucket_brigade* bb, ap_input_mode_t mode,
                               apr_read_type_e block, apr_off_t readbytes)
{
    apr_status_t status = APR_SUCCESS;
    apr_bucket *b, *next;
    apr_off_t bblen;
    apr_size_t rmax = ((readbytes <= APR_SIZE_MAX)? 
                       (apr_size_t)readbytes : APR_SIZE_MAX);
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                  "h2_task(%s): read, mode=%d, block=%d, readbytes=%ld", 
                  task->id, mode, block, (long)readbytes);
    
    if (mode == AP_MODE_INIT) {
        return ap_get_brigade(f->c->input_filters, bb, mode, block, readbytes);
    }
    
    if (f->c->aborted) {
        return APR_ECONNABORTED;
    }
    
    if (!task->input.bb) {
        return APR_EOF;
    }
    
    /* Cleanup brigades from those nasty 0 length non-meta buckets
     * that apr_brigade_split_line() sometimes produces. */
    for (b = APR_BRIGADE_FIRST(task->input.bb);
         b != APR_BRIGADE_SENTINEL(task->input.bb); b = next) {
        next = APR_BUCKET_NEXT(b);
        if (b->length == 0 && !APR_BUCKET_IS_METADATA(b)) {
            apr_bucket_delete(b);
        } 
    }
    
    while (APR_BRIGADE_EMPTY(task->input.bb)) {
        /* Get more input data for our request. */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_task(%s): get more data from mplx, block=%d, "
                      "readbytes=%ld", task->id, block, (long)readbytes);
        
        /* Override the block mode we get called with depending on the input's
         * setting. */
        if (task->input.beam) {
            status = h2_beam_receive(task->input.beam, task->input.bb, block, 
                                     H2MIN(readbytes, 32*1024));
        }
        else {
            status = APR_EOF;
        }
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, f->c,
                      "h2_task(%s): read returned", task->id);
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
            return status;
        }
        
        /* Inspect the buckets received, detect EOS and apply
         * chunked encoding if necessary */
        h2_util_bb_log(f->c, task->stream_id, APLOG_TRACE2, 
                       "input.beam recv raw", task->input.bb);
        if (h2_task_logio_add_bytes_in) {
            apr_brigade_length(bb, 0, &bblen);
            h2_task_logio_add_bytes_in(f->c, bblen);
        }
    }
    
    if (status == APR_EOF && APR_BRIGADE_EMPTY(task->input.bb)) {
        return APR_EOF;
    }

    h2_util_bb_log(f->c, task->stream_id, APLOG_TRACE2, 
                   "task_input.bb", task->input.bb);
           
    if (APR_BRIGADE_EMPTY(task->input.bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                      "h2_task(%s): no data", task->id);
        return (block == APR_NONBLOCK_READ)? APR_EAGAIN : APR_EOF;
    }
    
    if (mode == AP_MODE_EXHAUSTIVE) {
        /* return all we have */
        APR_BRIGADE_CONCAT(bb, task->input.bb);
    }
    else if (mode == AP_MODE_READBYTES) {
        status = h2_brigade_concat_length(bb, task->input.bb, rmax);
    }
    else if (mode == AP_MODE_SPECULATIVE) {
        status = h2_brigade_copy_length(bb, task->input.bb, rmax);
    }
    else if (mode == AP_MODE_GETLINE) {
        /* we are reading a single LF line, e.g. the HTTP headers. 
         * this has the nasty side effect to split the bucket, even
         * though it ends with CRLF and creates a 0 length bucket */
        status = apr_brigade_split_line(bb, task->input.bb, block, 
                                        HUGE_STRING_LEN);
        if (APLOGctrace1(f->c)) {
            char buffer[1024];
            apr_size_t len = sizeof(buffer)-1;
            apr_brigade_flatten(bb, buffer, &len);
            buffer[len] = 0;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                          "h2_task(%s): getline: %s",
                          task->id, buffer);
        }
    }
    else {
        /* Hmm, well. There is mode AP_MODE_EATCRLF, but we chose not
         * to support it. Seems to work. */
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, f->c,
                      APLOGNO(02942) 
                      "h2_task, unsupported READ mode %d", mode);
        status = APR_ENOTIMPL;
    }
    
    if (APLOGctrace1(f->c)) {
        apr_brigade_length(bb, 0, &bblen);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_task(%s): return %ld data bytes",
                      task->id, (long)bblen);
    }
    return status;
}

/*******************************************************************************
 * task output handling
 ******************************************************************************/

static apr_status_t open_output(h2_task *task)
{
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, task->c, APLOGNO(03348)
                  "h2_task(%s): open output to %s %s %s",
                  task->id, task->request->method, 
                  task->request->authority, 
                  task->request->path);
    task->output.opened = 1;
    return h2_mplx_out_open(task->mplx, task->stream_id, task->output.beam);
}

static apr_status_t send_out(h2_task *task, apr_bucket_brigade* bb)
{
    apr_off_t written, left;
    apr_status_t status;

    apr_brigade_length(bb, 0, &written);
    H2_TASK_OUT_LOG(APLOG_TRACE2, task, bb, "h2_task send_out");
    /* engines send unblocking */
    status = h2_beam_send(task->output.beam, bb, 
                          task->assigned? APR_NONBLOCK_READ
                          : APR_BLOCK_READ);
    if (APR_STATUS_IS_EAGAIN(status)) {
        apr_brigade_length(bb, 0, &left);
        written -= left;
        status = APR_SUCCESS;
    }
    if (status == APR_SUCCESS) {
        if (h2_task_logio_add_bytes_out) {
            h2_task_logio_add_bytes_out(task->c, written);
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, task->c, 
                      "h2_task(%s): send_out done", task->id);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, task->c,
                      "h2_task(%s): send_out (%ld bytes)", 
                      task->id, (long)written);
    }
    return status;
}

/* Bring the data from the brigade (which represents the result of the
 * request_rec out filter chain) into the h2_mplx for further sending
 * on the master connection. 
 */
static apr_status_t slave_out(h2_task *task, ap_filter_t* f, 
                              apr_bucket_brigade* bb)
{
    apr_bucket *b;
    apr_status_t status = APR_SUCCESS;
    int flush = 0;
    
    if (APR_BRIGADE_EMPTY(bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, task->c,
                      "h2_task(%s): empty write", task->id);
        return APR_SUCCESS;
    }
    
    if (task->frozen) {
        h2_util_bb_log(task->c, task->stream_id, APLOG_TRACE2,
                       "frozen task output write, ignored", bb);
        while (!APR_BRIGADE_EMPTY(bb)) {
            b = APR_BRIGADE_FIRST(bb);
            if (AP_BUCKET_IS_EOR(b)) {
                APR_BUCKET_REMOVE(b);
                task->eor = b;
            }
            else {
                apr_bucket_delete(b);
            }
        }
        return APR_SUCCESS;
    }
    
    if (!task->output.beam) {
        h2_beam_create(&task->output.beam, task->pool, 
                       task->stream_id, "output", 0);
        if (task->output.copy_files) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, task->c,
                          "h2_task(%s): copy_files on", task->id);
            h2_beam_on_file_beam(task->output.beam, h2_beam_no_files, NULL);
        }
    }
    
    /* Attempt to write saved brigade first */
    if (task->output.bb && !APR_BRIGADE_EMPTY(task->output.bb)) {
        status = send_out(task, task->output.bb); 
        if (status != APR_SUCCESS) {
            return status;
        }
    }
    
    /* If there is nothing saved (anymore), try to write the brigade passed */
    if ((!task->output.bb || APR_BRIGADE_EMPTY(task->output.bb)) 
        && !APR_BRIGADE_EMPTY(bb)) {
        /* check if we have a flush before the end-of-request */
        if (!task->output.opened) {
            for (b = APR_BRIGADE_FIRST(bb);
                 b != APR_BRIGADE_SENTINEL(bb);
                 b = APR_BUCKET_NEXT(b)) {
                if (AP_BUCKET_IS_EOR(b)) {
                    break;
                }
                else if (APR_BUCKET_IS_FLUSH(b)) {
                    flush = 1;
                }
            }
        }

        status = send_out(task, bb); 
        if (status != APR_SUCCESS) {
            return status;
        }
    }
    
    /* If the passed brigade is not empty, save it before return */
    if (!APR_BRIGADE_EMPTY(bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, task->c, APLOGNO(03405)
                      "h2_task(%s): could not write all, saving brigade", 
                      task->id);
        if (!task->output.bb) {
            task->output.bb = apr_brigade_create(task->pool, 
                                          task->c->bucket_alloc);
        }
        status = ap_save_brigade(f, &task->output.bb, &bb, task->pool);
        if (status != APR_SUCCESS) {
            return status;
        }
    }
    
    if (!task->output.opened 
        && (flush || h2_beam_get_mem_used(task->output.beam) > (32*1024))) {
        /* if we have enough buffered or we got a flush bucket, open
        * the response now. */
        status = open_output(task);
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, task->c, 
                  "h2_task(%s): slave_out leave", task->id);    
    return status;
}

static apr_status_t output_finish(h2_task *task)
{
    if (!task->output.opened) {
        return open_output(task);
    }
    return APR_SUCCESS;
}

/*******************************************************************************
 * task slave connection filters
 ******************************************************************************/

static apr_status_t h2_filter_slave_input(ap_filter_t* filter,
                                          apr_bucket_brigade* brigade,
                                          ap_input_mode_t mode,
                                          apr_read_type_e block,
                                          apr_off_t readbytes)
{
    h2_task *task = h2_ctx_cget_task(filter->c);
    AP_DEBUG_ASSERT(task);
    return input_read(task, filter, brigade, mode, block, readbytes);
}

static apr_status_t h2_filter_continue(ap_filter_t* f,
                                       apr_bucket_brigade* brigade,
                                       ap_input_mode_t mode,
                                       apr_read_type_e block,
                                       apr_off_t readbytes)
{
    h2_task *task = h2_ctx_cget_task(f->c);
    apr_status_t status;
    
    ap_assert(task);
    if (f->r->expecting_100 && ap_is_HTTP_SUCCESS(f->r->status)) {
        h2_headers *response;
        apr_bucket_brigade *tmp;
        apr_bucket *b;

        response = h2_headers_rcreate(f->r, HTTP_CONTINUE, NULL, f->r->pool);
        tmp = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        b = h2_bucket_headers_create(f->c->bucket_alloc, response);
        APR_BRIGADE_INSERT_TAIL(tmp, b);
        b = apr_bucket_flush_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(tmp, b);                      
        status = ap_pass_brigade(f->r->output_filters, tmp);
        apr_brigade_destroy(tmp);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, status, f->r,
                      "h2_task(%s): sent 100 Continue", task->id);
        if (status != APR_SUCCESS) {
            return status;
        }
        f->r->expecting_100 = 0;
        apr_table_clear(f->r->headers_out);
    }
    return ap_get_brigade(f->next, brigade, mode, block, readbytes);
}

static apr_status_t h2_filter_slave_output(ap_filter_t* filter,
                                           apr_bucket_brigade* brigade)
{
    h2_task *task = h2_ctx_cget_task(filter->c);
    apr_status_t status;
    
    ap_assert(task);
    status = slave_out(task, filter, brigade);
    if (status != APR_SUCCESS) {
        h2_task_rst(task, H2_ERR_INTERNAL_ERROR);
    }
    return status;
}

/*******************************************************************************
 * task things
 ******************************************************************************/
 
int h2_task_can_redo(h2_task *task) {
    if (task->input.beam && h2_beam_was_received(task->input.beam)) {
        /* cannot repeat that. */
        return 0;
    }
    return (!strcmp("GET", task->request->method)
            || !strcmp("HEAD", task->request->method)
            || !strcmp("OPTIONS", task->request->method));
}

void h2_task_redo(h2_task *task)
{
    task->rst_error = 0;
}

void h2_task_rst(h2_task *task, int error)
{
    task->rst_error = error;
    if (task->input.beam) {
        h2_beam_abort(task->input.beam);
    }
    if (!task->worker_done && task->output.beam) {
        h2_beam_abort(task->output.beam);
    }
    if (task->c) {
        task->c->aborted = 1;
    }
}

/*******************************************************************************
 * Register various hooks
 */
static const char *const mod_ssl[]        = { "mod_ssl.c", NULL};
static int h2_task_pre_conn(conn_rec* c, void *arg);
static int h2_task_process_conn(conn_rec* c);

APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_in) *h2_task_logio_add_bytes_in;
APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *h2_task_logio_add_bytes_out;

void h2_task_register_hooks(void)
{
    /* This hook runs on new connections before mod_ssl has a say.
     * Its purpose is to prevent mod_ssl from touching our pseudo-connections
     * for streams.
     */
    ap_hook_pre_connection(h2_task_pre_conn,
                           NULL, mod_ssl, APR_HOOK_FIRST);
    /* When the connection processing actually starts, we might 
     * take over, if the connection is for a task.
     */
    ap_hook_process_connection(h2_task_process_conn, 
                               NULL, NULL, APR_HOOK_FIRST);

    ap_register_input_filter("H2_SLAVE_IN", h2_filter_slave_input,
                             NULL, AP_FTYPE_NETWORK);
    ap_register_output_filter("H2_SLAVE_OUT", h2_filter_slave_output,
                              NULL, AP_FTYPE_NETWORK);

    ap_register_input_filter("H2_CONTINUE", h2_filter_continue,
                             NULL, AP_FTYPE_PROTOCOL);
    ap_register_input_filter("H2_REQUEST", h2_filter_request_in,
                             NULL, AP_FTYPE_PROTOCOL);
    ap_register_output_filter("H2_RESPONSE", h2_headers_output_filter,
                              NULL, AP_FTYPE_PROTOCOL);
    ap_register_output_filter("H2_TRAILERS_OUT", h2_filter_trailers_out,
                              NULL, AP_FTYPE_PROTOCOL);
}

/* post config init */
apr_status_t h2_task_init(apr_pool_t *pool, server_rec *s)
{
    h2_task_logio_add_bytes_in = APR_RETRIEVE_OPTIONAL_FN(ap_logio_add_bytes_in);
    h2_task_logio_add_bytes_out = APR_RETRIEVE_OPTIONAL_FN(ap_logio_add_bytes_out);

    return APR_SUCCESS;
}

static int h2_task_pre_conn(conn_rec* c, void *arg)
{
    h2_ctx *ctx;
    
    if (!c->master) {
        return OK;
    }
    
    ctx = h2_ctx_get(c, 0);
    (void)arg;
    if (h2_ctx_is_task(ctx)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                      "h2_h2, pre_connection, found stream task");
        ap_add_input_filter("H2_SLAVE_IN", NULL, NULL, c);
        ap_add_output_filter("H2_SLAVE_OUT", NULL, NULL, c);
    }
    return OK;
}

h2_task *h2_task_create(conn_rec *c, apr_uint32_t stream_id,
                        const h2_request *req, h2_bucket_beam *input, 
                        h2_mplx *mplx)
{
    apr_pool_t *pool;
    h2_task *task;
    
    ap_assert(mplx);
    ap_assert(c);
    ap_assert(req);

    apr_pool_create(&pool, c->pool);
    task = apr_pcalloc(pool, sizeof(h2_task));
    if (task == NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, c,
                      APLOGNO(02941) "h2_task(%ld-%d): create stream task", 
                      c->id, stream_id);
        return NULL;
    }
    task->id          = apr_psprintf(pool, "%ld-%d", c->master->id, stream_id);
    task->stream_id   = stream_id;
    task->c           = c;
    task->mplx        = mplx;
    task->c->keepalives = mplx->c->keepalives;
    task->pool        = pool;
    task->request     = req;
    task->input.beam  = input;
    
    apr_thread_cond_create(&task->cond, pool);

    h2_ctx_create_for(c, task);
    return task;
}

void h2_task_destroy(h2_task *task)
{
    if (task->output.beam) {
        h2_beam_destroy(task->output.beam);
        task->output.beam = NULL;
    }
    if (task->eor) {
        apr_bucket_destroy(task->eor);
    }
    if (task->pool) {
        apr_pool_destroy(task->pool);
    }
}

apr_status_t h2_task_do(h2_task *task, apr_thread_t *thread)
{
    AP_DEBUG_ASSERT(task);
    
    task->input.chunked = task->request->chunked;
    task->input.bb = apr_brigade_create(task->pool, task->c->bucket_alloc);
    if (task->request->serialize) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, task->c,
                      "h2_task(%s): serialize request %s %s", 
                      task->id, task->request->method, task->request->path);
        apr_brigade_printf(task->input.bb, NULL, 
                           NULL, "%s %s HTTP/1.1\r\n", 
                           task->request->method, task->request->path);
        apr_table_do(input_ser_header, task, task->request->headers, NULL);
        apr_brigade_puts(task->input.bb, NULL, NULL, "\r\n");
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, task->c,
                  "h2_task(%s): process connection", task->id);
    task->c->current_thread = thread; 
    ap_run_process_connection(task->c);
    
    if (task->frozen) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, task->c,
                      "h2_task(%s): process_conn returned frozen task", 
                      task->id);
        /* cleanup delayed */
        return APR_EAGAIN;
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, task->c,
                      "h2_task(%s): processing done", task->id);
        return output_finish(task);
    }
}

static apr_status_t h2_task_process_request(h2_task *task, conn_rec *c)
{
    const h2_request *req = task->request;
    conn_state_t *cs = c->cs;
    request_rec *r;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                  "h2_task(%s): create request_rec", task->id);
    r = h2_request_create_rec(req, c);
    if (r && (r->status == HTTP_OK)) {
        ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
        
        if (cs) {
            cs->state = CONN_STATE_HANDLER;
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_task(%s): start process_request", task->id);
    
        ap_process_request(r);
        if (task->frozen) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                          "h2_task(%s): process_request frozen", task->id);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                          "h2_task(%s): process_request done", task->id);
        }
        
        /* After the call to ap_process_request, the
         * request pool will have been deleted.  We set
         * r=NULL here to ensure that any dereference
         * of r that might be added later in this function
         * will result in a segfault immediately instead
         * of nondeterministic failures later.
         */
        if (cs) 
            cs->state = CONN_STATE_WRITE_COMPLETION;
        r = NULL;
    }
    else if (!r) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_task(%s): create request_rec failed, r=NULL", task->id);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_task(%s): create request_rec failed, r->status=%d", 
                      task->id, r->status);
    }

    return APR_SUCCESS;
}

static int h2_task_process_conn(conn_rec* c)
{
    h2_ctx *ctx;
    
    if (!c->master) {
        return DECLINED;
    }
    
    ctx = h2_ctx_get(c, 0);
    if (h2_ctx_is_task(ctx)) {
        if (!ctx->task->request->serialize) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, 
                          "h2_h2, processing request directly");
            h2_task_process_request(ctx->task, c);
            return DONE;
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, 
                      "h2_task(%s), serialized handling", ctx->task->id);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, 
                      "slave_conn(%ld): has no task", c->id);
    }
    return DECLINED;
}

apr_status_t h2_task_freeze(h2_task *task)
{   
    if (!task->frozen) {
        task->frozen = 1;
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, task->c, APLOGNO(03406) 
                      "h2_task(%s), frozen", task->id);
    }
    return APR_SUCCESS;
}

apr_status_t h2_task_thaw(h2_task *task)
{
    if (task->frozen) {
        task->frozen = 0;
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, task->c, APLOGNO(03407) 
                      "h2_task(%s), thawed", task->id);
    }
    task->detached = 1;
    return APR_SUCCESS;
}

int h2_task_is_detached(h2_task *task)
{
    return task->detached;
}
