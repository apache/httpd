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
#include "h2_conn.h"
#include "h2_config.h"
#include "h2_from_h1.h"
#include "h2_h2.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_task_input.h"
#include "h2_task_output.h"
#include "h2_task.h"
#include "h2_ctx.h"
#include "h2_worker.h"


static apr_status_t h2_filter_stream_input(ap_filter_t* filter,
                                           apr_bucket_brigade* brigade,
                                           ap_input_mode_t mode,
                                           apr_read_type_e block,
                                           apr_off_t readbytes)
{
    h2_task *task = filter->ctx;
    AP_DEBUG_ASSERT(task);
    if (!task->input) {
        return APR_ECONNABORTED;
    }
    return h2_task_input_read(task->input, filter, brigade,
                              mode, block, readbytes);
}

static apr_status_t h2_filter_stream_output(ap_filter_t* filter,
                                            apr_bucket_brigade* brigade)
{
    h2_task *task = filter->ctx;
    AP_DEBUG_ASSERT(task);
    if (!task->output) {
        return APR_ECONNABORTED;
    }
    return h2_task_output_write(task->output, filter, brigade);
}

static apr_status_t h2_filter_read_response(ap_filter_t* f,
                                            apr_bucket_brigade* bb)
{
    h2_task *task = f->ctx;
    AP_DEBUG_ASSERT(task);
    if (!task->output || !task->output->from_h1) {
        return APR_ECONNABORTED;
    }
    return h2_from_h1_read_response(task->output->from_h1, f, bb);
}

/*******************************************************************************
 * Register various hooks
 */
static const char *const mod_ssl[]        = { "mod_ssl.c", NULL};
static int h2_task_pre_conn(conn_rec* c, void *arg);
static int h2_task_process_conn(conn_rec* c);

void h2_task_register_hooks(void)
{
    /* This hook runs on new connections before mod_ssl has a say.
     * Its purpose is to prevent mod_ssl from touching our pseudo-connections
     * for streams.
     */
    ap_hook_pre_connection(h2_task_pre_conn,
                           NULL, mod_ssl, APR_HOOK_FIRST);
    /* When the connection processing actually starts, we might to
     * take over, if the connection is for a task.
     */
    ap_hook_process_connection(h2_task_process_conn, 
                               NULL, NULL, APR_HOOK_FIRST);

    ap_register_output_filter("H2_RESPONSE", h2_response_output_filter,
                              NULL, AP_FTYPE_PROTOCOL);
    ap_register_input_filter("H2_TO_H1", h2_filter_stream_input,
                             NULL, AP_FTYPE_NETWORK);
    ap_register_output_filter("H1_TO_H2", h2_filter_stream_output,
                              NULL, AP_FTYPE_NETWORK);
    ap_register_output_filter("H1_TO_H2_RESP", h2_filter_read_response,
                              NULL, AP_FTYPE_PROTOCOL);
    ap_register_output_filter("H2_TRAILERS", h2_response_trailers_filter,
                              NULL, AP_FTYPE_PROTOCOL);
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
        h2_task *task = h2_ctx_get_task(ctx);
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                      "h2_h2, pre_connection, found stream task");
        
        /* Add our own, network level in- and output filters.
         */
        ap_add_input_filter("H2_TO_H1", task, NULL, c);
        ap_add_output_filter("H1_TO_H2", task, NULL, c);
    }
    return OK;
}

h2_task *h2_task_create(long session_id, const h2_request *req, 
                        apr_pool_t *pool, h2_mplx *mplx, int eos)
{
    h2_task *task = apr_pcalloc(pool, sizeof(h2_task));
    if (task == NULL) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, pool,
                      APLOGNO(02941) "h2_task(%ld-%d): create stream task", 
                      session_id, req->id);
        h2_mplx_out_close(mplx, req->id, NULL);
        return NULL;
    }
    
    task->id        = apr_psprintf(pool, "%ld-%d", session_id, req->id);
    task->stream_id = req->id;
    task->pool      = pool;
    task->mplx      = mplx;
    task->c         = h2_conn_create(mplx->c, task->pool);

    task->request   = req;
    task->input_eos = eos;    
    
    return task;
}

apr_status_t h2_task_destroy(h2_task *task)
{
    (void)task;
    return APR_SUCCESS;
}

apr_status_t h2_task_do(h2_task *task, h2_worker *worker)
{
    apr_status_t status = APR_SUCCESS;
    
    AP_DEBUG_ASSERT(task);
    
    task->serialize_headers = h2_config_geti(task->request->config, H2_CONF_SER_HEADERS);

    status = h2_worker_setup_task(worker, task);
    
    /* save in connection that this one is a pseudo connection */
    h2_ctx_create_for(task->c, task);

    if (status == APR_SUCCESS) {
        task->input = h2_task_input_create(task, task->pool, 
                                           task->c->bucket_alloc);
        task->output = h2_task_output_create(task, task->pool);
        
        ap_process_connection(task->c, h2_worker_get_socket(worker));
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, task->c,
                      "h2_task(%s): processing done", task->id);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, status, task->c,
                      APLOGNO(02957) "h2_task(%s): error setting up h2_task", 
                      task->id);
    }
    
    if (task->input) {
        h2_task_input_destroy(task->input);
        task->input = NULL;
    }
    
    if (task->output) {
        h2_task_output_close(task->output);
        h2_task_output_destroy(task->output);
        task->output = NULL;
    }

    if (task->io) {
        apr_thread_cond_signal(task->io);
    }
    
    h2_worker_release_task(worker, task);
    h2_mplx_task_done(task->mplx, task->stream_id);
    
    return status;
}

static apr_status_t h2_task_process_request(const h2_request *req, conn_rec *c)
{
    request_rec *r;
    conn_state_t *cs = c->cs;

    r = h2_request_create_rec(req, c);
    if (r && (r->status == HTTP_OK)) {
        ap_update_child_status(c->sbh, SERVER_BUSY_READ, r);
        
        if (cs)
            cs->state = CONN_STATE_HANDLER;
        ap_process_request(r);
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
    ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, NULL);
    c->sbh = NULL;

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
        if (!ctx->task->serialize_headers) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, 
                          "h2_h2, processing request directly");
            h2_task_process_request(ctx->task->request, c);
            return DONE;
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, 
                      "h2_task(%s), serialized handling", ctx->task->id);
    }
    return DECLINED;
}
