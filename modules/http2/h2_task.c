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

static void H2_TASK_OUT_LOG(int lvl, h2_task *task, apr_bucket_brigade *bb, 
                            const char *tag)
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

static void h2_beam_log(h2_bucket_beam *beam, int id, const char *msg, 
                        conn_rec *c, int level)
{
    if (beam && APLOG_C_IS_LEVEL(c,level)) {
        char buffer[2048];
        apr_size_t off = 0;
        
        off += apr_snprintf(buffer+off, H2_ALEN(buffer)-off, "cl=%d, ", beam->closed);
        off += h2_util_bl_print(buffer+off, H2_ALEN(buffer)-off, "red", ", ", &beam->send_list);
        off += h2_util_bb_print(buffer+off, H2_ALEN(buffer)-off, "green", ", ", beam->recv_buffer);
        off += h2_util_bl_print(buffer+off, H2_ALEN(buffer)-off, "hold", ", ", &beam->hold_list);
        off += h2_util_bl_print(buffer+off, H2_ALEN(buffer)-off, "purge", "", &beam->purge_list);

        ap_log_cerror(APLOG_MARK, level, 0, c, "beam(%ld-%d): %s %s", 
                      c->id, id, msg, buffer);
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

static apr_status_t send_out(h2_task *task, apr_bucket_brigade* bb, int block)
{
    apr_off_t written, left;
    apr_status_t status;

    apr_brigade_length(bb, 0, &written);
    H2_TASK_OUT_LOG(APLOG_TRACE2, task, bb, "h2_task send_out");
    h2_beam_log(task->output.beam, task->stream_id, "send_out(before)", task->c, APLOG_TRACE2);
    /* engines send unblocking */
    status = h2_beam_send(task->output.beam, bb, 
                          block? APR_BLOCK_READ : APR_NONBLOCK_READ);
    h2_beam_log(task->output.beam, task->stream_id, "send_out(after)", task->c, APLOG_TRACE2);
    
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
    int flush = 0, blocking;
    
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

    /* we send block once we opened the output, so someone is there
     * reading it *and* the task is not assigned to a h2_req_engine */
    blocking = (!task->assigned && task->output.opened);
    if (!task->output.opened) {
        for (b = APR_BRIGADE_FIRST(bb);
             b != APR_BRIGADE_SENTINEL(bb);
             b = APR_BUCKET_NEXT(b)) {
            if (APR_BUCKET_IS_FLUSH(b)) {
                flush = 1;
                break;
            }
        }
    }
    
    if (task->output.bb && !APR_BRIGADE_EMPTY(task->output.bb)) {
        /* still have data buffered from previous attempt.
         * setaside and append new data and try to pass the complete data */
        if (!APR_BRIGADE_EMPTY(bb)) {
            status = ap_save_brigade(f, &task->output.bb, &bb, task->pool);
        }
        if (status == APR_SUCCESS) {
            status = send_out(task, task->output.bb, blocking);
        } 
    }
    else {
        /* no data buffered here, try to pass the brigade directly */
        status = send_out(task, bb, blocking); 
        if (status == APR_SUCCESS && !APR_BRIGADE_EMPTY(bb)) {
            /* could not write all, buffer the rest */
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, task->c, APLOGNO(03405)
                          "h2_slave_out(%s): saving brigade", 
                          task->id);
            status = ap_save_brigade(f, &task->output.bb, &bb, task->pool);
            flush = 1;
        }
    }
    
    if (status == APR_SUCCESS && !task->output.opened && flush) {
        /* got a flush or could not write all, time to tell someone to read */
        status = open_output(task);
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, task->c, 
                  "h2_slave_out(%s): slave_out leave", task->id);    
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

static apr_status_t h2_filter_slave_in(ap_filter_t* f,
                                       apr_bucket_brigade* bb,
                                       ap_input_mode_t mode,
                                       apr_read_type_e block,
                                       apr_off_t readbytes)
{
    h2_task *task;
    apr_status_t status = APR_SUCCESS;
    apr_bucket *b, *next;
    apr_off_t bblen;
    apr_size_t rmax;
    
    task = h2_ctx_cget_task(f->c);
    ap_assert(task);
    rmax = ((readbytes <= APR_SIZE_MAX)? (apr_size_t)readbytes : APR_SIZE_MAX);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                  "h2_slave_in(%s): read, mode=%d, block=%d, readbytes=%ld", 
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
                      "h2_slave_in(%s): get more data from mplx, block=%d, "
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
                      "h2_slave_in(%s): read returned", task->id);
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
        
        h2_util_bb_log(f->c, task->stream_id, APLOG_TRACE2, 
                       "input.beam recv raw", task->input.bb);
        if (h2_task_logio_add_bytes_in) {
            apr_brigade_length(bb, 0, &bblen);
            h2_task_logio_add_bytes_in(f->c, bblen);
        }
    }
    
    /* Inspect the buckets received, detect EOS and apply
     * chunked encoding if necessary */
    if (status == APR_EOF && APR_BRIGADE_EMPTY(task->input.bb)) {
        return APR_EOF;
    }

    h2_util_bb_log(f->c, task->stream_id, APLOG_TRACE2, 
                   "task_input.bb", task->input.bb);
           
    if (APR_BRIGADE_EMPTY(task->input.bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                      "h2_slave_in(%s): no data", task->id);
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
                          "h2_slave_in(%s): getline: %s",
                          task->id, buffer);
        }
    }
    else {
        /* Hmm, well. There is mode AP_MODE_EATCRLF, but we chose not
         * to support it. Seems to work. */
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, f->c,
                      APLOGNO(03472) 
                      "h2_slave_in(%s), unsupported READ mode %d", 
                      task->id, mode);
        status = APR_ENOTIMPL;
    }
    
    if (APLOGctrace1(f->c)) {
        apr_brigade_length(bb, 0, &bblen);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_slave_in(%s): %ld data bytes", task->id, (long)bblen);
    }
    return status;
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

static apr_status_t h2_filter_parse_h1(ap_filter_t* f, apr_bucket_brigade* bb)
{
    h2_task *task = h2_ctx_cget_task(f->c);
    apr_status_t status;
    
    ap_assert(task);
    /* There are cases where we need to parse a serialized http/1.1 
     * response. One example is a 100-continue answer in serialized mode
     * or via a mod_proxy setup */
    while (!task->output.sent_response) {
        status = h2_from_h1_parse_response(task, f, bb);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, f->c,
                      "h2_task(%s): parsed response", task->id);
        if (APR_BRIGADE_EMPTY(bb) || status != APR_SUCCESS) {
            return status;
        }
    }
    
    return ap_pass_brigade(f->next, bb);
}

/*******************************************************************************
 * task things
 ******************************************************************************/
 
int h2_task_can_redo(h2_task *task) {
    if (h2_beam_was_received(task->input.beam)) {
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
    h2_beam_abort(task->input.beam);
    if (!task->worker_done) {
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

    ap_register_input_filter("H2_SLAVE_IN", h2_filter_slave_in,
                             NULL, AP_FTYPE_NETWORK);
    ap_register_output_filter("H2_SLAVE_OUT", h2_filter_slave_output,
                              NULL, AP_FTYPE_NETWORK);
    ap_register_output_filter("H2_PARSE_H1", h2_filter_parse_h1,
                              NULL, AP_FTYPE_NETWORK);

    ap_register_input_filter("H2_REQUEST", h2_filter_request_in,
                             NULL, AP_FTYPE_PROTOCOL);
    ap_register_output_filter("H2_RESPONSE", h2_filter_headers_out,
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
        ap_add_output_filter("H2_PARSE_H1", NULL, NULL, c);
        ap_add_output_filter("H2_SLAVE_OUT", NULL, NULL, c);
    }
    return OK;
}

h2_task *h2_task_create(conn_rec *c, int stream_id, const h2_request *req, 
                        h2_bucket_beam *input, h2_bucket_beam *output,  
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
    task->output.beam = output;
    
    h2_beam_send_from(output, task->pool);
    apr_thread_cond_create(&task->cond, pool);
    h2_ctx_create_for(c, task);
    
    return task;
}

void h2_task_destroy(h2_task *task)
{
    if (task->eor) {
        apr_bucket_destroy(task->eor);
    }
    if (task->pool) {
        apr_pool_destroy(task->pool);
    }
}

apr_status_t h2_task_do(h2_task *task, apr_thread_t *thread, int worker_id)
{
    ap_assert(task);

    if (task->c->master) {
        /* Each conn_rec->id is supposed to be unique at a point in time. Since
         * some modules (and maybe external code) uses this id as an identifier
         * for the request_rec they handle, it needs to be unique for slave 
         * connections also.
         * The connection id is generated by the MPM and most MPMs use the formula
         *    id := (child_num * max_threads) + thread_num
         * which means that there is a maximum id of about
         *    idmax := max_child_count * max_threads
         * If we assume 2024 child processes with 2048 threads max, we get
         *    idmax ~= 2024 * 2048 = 2 ** 22
         * On 32 bit systems, we have not much space left, but on 64 bit systems
         * (and higher?) we can use the upper 32 bits without fear of collision.
         * 32 bits is just what we need, since a connection can only handle so
         * many streams. 
         */
        int slave_id, free_bits;
        
        if (sizeof(unsigned long) >= 8) {
            free_bits = 32;
            slave_id = task->stream_id;
        }
        else {
            /* Assume we have a more limited number of threads/processes
             * and h2 workers on a 32-bit system. Use the worker instead
             * of the stream id. */
            free_bits = 8;
            slave_id = worker_id; 
        }
        task->c->id = (task->c->master->id << free_bits)^slave_id;
    }
    
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
    task->thawed = 1;
    return APR_SUCCESS;
}

int h2_task_has_thawed(h2_task *task)
{
    return task->thawed;
}
