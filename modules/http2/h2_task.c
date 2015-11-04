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
                                           apr_off_t readbytes) {
    h2_task *task = filter->ctx;
    AP_DEBUG_ASSERT(task);
    if (!task->input) {
        return APR_ECONNABORTED;
    }
    return h2_task_input_read(task->input, filter, brigade,
                              mode, block, readbytes);
}

static apr_status_t h2_filter_stream_output(ap_filter_t* filter,
                                            apr_bucket_brigade* brigade) {
    h2_task *task = filter->ctx;
    AP_DEBUG_ASSERT(task);
    if (!task->output) {
        return APR_ECONNABORTED;
    }
    return h2_task_output_write(task->output, filter, brigade);
}

static apr_status_t h2_filter_read_response(ap_filter_t* f,
                                            apr_bucket_brigade* bb) {
    h2_task *task = f->ctx;
    AP_DEBUG_ASSERT(task);
    if (!task->output || !task->output->from_h1) {
        return APR_ECONNABORTED;
    }
    return h2_from_h1_read_response(task->output->from_h1, f, bb);
}

static apr_status_t h2_task_process_request(h2_task *task);

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
}

static int h2_task_pre_conn(conn_rec* c, void *arg)
{
    
    h2_ctx *ctx = h2_ctx_get(c);
    
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

static int h2_task_process_conn(conn_rec* c)
{
    h2_ctx *ctx = h2_ctx_get(c);
    
    if (h2_ctx_is_task(ctx)) {
        if (!ctx->task->serialize_headers) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, 
                          "h2_h2, processing request directly");
            h2_task_process_request(ctx->task);
            return DONE;
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, 
                      "h2_task(%s), serialized handling", ctx->task->id);
    }
    return DECLINED;
}


h2_task *h2_task_create(long session_id,
                        int stream_id,
                        apr_pool_t *stream_pool,
                        h2_mplx *mplx, conn_rec *c)
{
    h2_task *task = apr_pcalloc(stream_pool, sizeof(h2_task));
    if (task == NULL) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, stream_pool,
                      APLOGNO(02941) "h2_task(%ld-%d): create stream task", 
                      session_id, stream_id);
        h2_mplx_out_close(mplx, stream_id);
        return NULL;
    }
    
    task->id = apr_psprintf(stream_pool, "%ld-%d", session_id, stream_id);
    task->stream_id = stream_id;
    task->mplx = mplx;
    
    task->c = c;
    
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, stream_pool,
                  "h2_task(%s): created", task->id);
    return task;
}

void h2_task_set_request(h2_task *task, 
                         const char *method, 
                         const char *scheme, 
                         const char *authority, 
                         const char *path, 
                         apr_table_t *headers, int eos)
{
    task->method = method;
    task->scheme = scheme;
    task->authority = authority;
    task->path = path;
    task->headers = headers;
    task->input_eos = eos;
}

apr_status_t h2_task_destroy(h2_task *task)
{
    (void)task;
    return APR_SUCCESS;
}

apr_status_t h2_task_do(h2_task *task, h2_worker *worker)
{
    apr_status_t status = APR_SUCCESS;
    h2_config *cfg = h2_config_get(task->mplx->c);
    
    AP_DEBUG_ASSERT(task);
    
    task->serialize_headers = h2_config_geti(cfg, H2_CONF_SER_HEADERS);
    
    /* Create a subpool from the worker one to be used for all things
     * with life-time of this task execution.
     */
    apr_pool_create(&task->pool, h2_worker_get_pool(worker));

    /* Link the task to the worker which provides useful things such
     * as mutex, a socket etc. */
    task->io = h2_worker_get_cond(worker);
    
    status = h2_conn_setup(task, worker);
    
    /* save in connection that this one is a pseudo connection, prevents
     * other hooks from messing with it. */
    h2_ctx_create_for(task->c, task);

    if (status == APR_SUCCESS) {
        task->input = h2_task_input_create(task, task->pool, 
                                           task->c->bucket_alloc);
        task->output = h2_task_output_create(task, task->pool,
                                             task->c->bucket_alloc);
        status = h2_conn_process(task->c, h2_worker_get_socket(worker));
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, task->c,
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
    
    if (task->pool) {
        apr_pool_destroy(task->pool);
        task->pool = NULL;
    }
    
    if (task->c->id) {
        h2_conn_post(task->c, worker);
    }
    
    h2_mplx_task_done(task->mplx, task->stream_id);
    
    return status;
}

static request_rec *h2_task_create_request(h2_task *task)
{
    conn_rec *conn = task->c;
    request_rec *r;
    apr_pool_t *p;
    int access_status = HTTP_OK;    
    
    apr_pool_create(&p, conn->pool);
    apr_pool_tag(p, "request");
    r = apr_pcalloc(p, sizeof(request_rec));
    AP_READ_REQUEST_ENTRY((intptr_t)r, (uintptr_t)conn);
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;
    
    r->user            = NULL;
    r->ap_auth_type    = NULL;
    
    r->allowed_methods = ap_make_method_list(p, 2);
    
    r->headers_in = apr_table_copy(r->pool, task->headers);
    r->trailers_in     = apr_table_make(r->pool, 5);
    r->subprocess_env  = apr_table_make(r->pool, 25);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->trailers_out    = apr_table_make(r->pool, 5);
    r->notes           = apr_table_make(r->pool, 5);
    
    r->request_config  = ap_create_request_config(r->pool);
    /* Must be set before we run create request hook */
    
    r->proto_output_filters = conn->output_filters;
    r->output_filters  = r->proto_output_filters;
    r->proto_input_filters = conn->input_filters;
    r->input_filters   = r->proto_input_filters;
    ap_run_create_request(r);
    r->per_dir_config  = r->server->lookup_defaults;
    
    r->sent_bodyct     = 0;                      /* bytect isn't for body */
    
    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;
    
    r->status          = HTTP_OK;  /* Until further notice */
    r->header_only     = 0;
    r->the_request     = NULL;
    
    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;
    
    r->useragent_addr = conn->client_addr;
    r->useragent_ip = conn->client_ip;
    
    ap_run_pre_read_request(r, conn);
    
    /* Time to populate r with the data we have. */
    r->request_time = apr_time_now();
    r->method = task->method;
    /* Provide quick information about the request method as soon as known */
    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_GET && r->method[0] == 'H') {
        r->header_only = 1;
    }

    ap_parse_uri(r, task->path);
    r->protocol = (char*)"HTTP/2";
    r->proto_num = HTTP_VERSION(2, 0);

    r->the_request = apr_psprintf(r->pool, "%s %s %s", 
                                  r->method, task->path, r->protocol);
    
    /* update what we think the virtual host is based on the headers we've
     * now read. may update status.
     * Leave r->hostname empty, vhost will parse if form our Host: header,
     * otherwise we get complains about port numbers.
     */
    r->hostname = NULL;
    ap_update_vhost_from_headers(r);
    
    /* we may have switched to another server */
    r->per_dir_config = r->server->lookup_defaults;
    
    /*
     * Add the HTTP_IN filter here to ensure that ap_discard_request_body
     * called by ap_die and by ap_send_error_response works correctly on
     * status codes that do not cause the connection to be dropped and
     * in situations where the connection should be kept alive.
     */
    ap_add_input_filter_handle(ap_http_input_filter_handle,
                               NULL, r, r->connection);
    
    if (access_status != HTTP_OK
        || (access_status = ap_run_post_read_request(r))) {
        /* Request check post hooks failed. An example of this would be a
         * request for a vhost where h2 is disabled --> 421.
         */
        ap_die(access_status, r);
        ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
        ap_run_log_transaction(r);
        r = NULL;
        goto traceout;
    }
    
    AP_READ_REQUEST_SUCCESS((uintptr_t)r, (char *)r->method, 
                            (char *)r->uri, (char *)r->server->defn_name, 
                            r->status);
    return r;
traceout:
    AP_READ_REQUEST_FAILURE((uintptr_t)r);
    return r;
}


static apr_status_t h2_task_process_request(h2_task *task)
{
    conn_rec *c = task->c;
    request_rec *r;
    conn_state_t *cs = c->cs;

    r = h2_task_create_request(task);
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
        r = NULL;
    }
    ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, NULL);
    c->sbh = NULL;

    return APR_SUCCESS;
}




