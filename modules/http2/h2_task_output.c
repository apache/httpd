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

#include <apr_thread_cond.h>
#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>
#include <http_request.h>

#include "h2_private.h"
#include "h2_conn.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_from_h1.h"
#include "h2_response.h"
#include "h2_task_output.h"
#include "h2_task.h"
#include "h2_util.h"


h2_task_output *h2_task_output_create(h2_task *task, conn_rec *c)
{
    h2_task_output *output = apr_pcalloc(task->pool, sizeof(h2_task_output));
    if (output) {
        output->task = task;
        output->from_h1 = h2_from_h1_create(task->stream_id, task->pool);
    }
    return output;
}

static apr_status_t open_response(h2_task_output *output, ap_filter_t *f,
                                  apr_bucket_brigade *bb, const char *caller)
{
    h2_response *response;
    response = h2_from_h1_get_response(output->from_h1);
    if (!response) {
        if (f) {
            /* This happens currently when ap_die(status, r) is invoked
             * by a read request filter. */
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, output->task->c, APLOGNO(03204)
                          "h2_task_output(%s): write without response by %s "
                          "for %s %s %s",
                          output->task->id, caller, 
                          output->task->request->method, 
                          output->task->request->authority, 
                          output->task->request->path);
            output->task->c->aborted = 1;
        }
        if (output->task->io) {
            apr_thread_cond_broadcast(output->task->io);
        }
        return APR_ECONNABORTED;
    }
    
    if (h2_task_logio_add_bytes_out) {
        /* count headers as if we'd do a HTTP/1.1 serialization */
        output->written = h2_util_table_bytes(response->headers, 3)+1;
        h2_task_logio_add_bytes_out(output->task->c, output->written);
    }
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, output->task->c, APLOGNO(03348)
                  "h2_task(%s): open response to %s %s %s",
                  output->task->id, output->task->request->method, 
                  output->task->request->authority, 
                  output->task->request->path);
    return h2_mplx_out_open(output->task->mplx, output->task->stream_id, 
                            response, f, bb, output->task->io);
}

static apr_status_t write_brigade_raw(h2_task_output *output, 
                                      ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_off_t written, left;
    apr_status_t status;

    apr_brigade_length(bb, 0, &written);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, output->task->c,
                  "h2_task(%s): write response body (%ld bytes)", 
                  output->task->id, (long)written);
    
    status = h2_mplx_out_write(output->task->mplx, output->task->stream_id, 
                               f, output->task->blocking, bb, output->task->io);
    if (status == APR_INCOMPLETE) {
        apr_brigade_length(bb, 0, &left);
        written -= left;
        status = APR_SUCCESS;
    }

    if (status == APR_SUCCESS) {
        output->written += written;
        if (h2_task_logio_add_bytes_out) {
            h2_task_logio_add_bytes_out(output->task->c, written);
        }
    }
    return status;
}

/* Bring the data from the brigade (which represents the result of the
 * request_rec out filter chain) into the h2_mplx for further sending
 * on the master connection. 
 */
apr_status_t h2_task_output_write(h2_task_output *output,
                                  ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_bucket *b;
    apr_status_t status = APR_SUCCESS;
    
    if (APR_BRIGADE_EMPTY(bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, output->task->c,
                      "h2_task(%s): empty write", output->task->id);
        return APR_SUCCESS;
    }
    
    if (output->task->frozen) {
        h2_util_bb_log(output->task->c, output->task->stream_id, APLOG_TRACE2,
                       "frozen task output write, ignored", bb);
        while (!APR_BRIGADE_EMPTY(bb)) {
            b = APR_BRIGADE_FIRST(bb);
            if (AP_BUCKET_IS_EOR(b)) {
                /* TODO: keep it */
                APR_BUCKET_REMOVE(b);
            }
            else {
                apr_bucket_delete(b);
            }
        }
        return APR_SUCCESS;
    }
    
    if (!output->response_open) {
        status = open_response(output, f, bb, "write");
        output->response_open = 1;
    }
    
    /* Attempt to write saved brigade first */
    if (status == APR_SUCCESS && output->bb && !APR_BRIGADE_EMPTY(output->bb)) {
        status = write_brigade_raw(output, f, output->bb);
    }
    
    /* If there is nothing saved (anymore), try to write the brigade passed */
    if (status == APR_SUCCESS
        && (!output->bb || APR_BRIGADE_EMPTY(output->bb))
        && !APR_BRIGADE_EMPTY(bb)) {
        status = write_brigade_raw(output, f, bb);
    }
    
    /* If the passed brigade is not empty, save it before return */
    if (status == APR_SUCCESS && !APR_BRIGADE_EMPTY(bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, output->task->c,
                      "h2_task(%s): could not write all, saving brigade", 
                      output->task->id);
        if (!output->bb) {
            output->bb = apr_brigade_create(output->task->pool, output->task->c->bucket_alloc);
        }
        return ap_save_brigade(f, &output->bb, &bb, output->task->pool);
    }
    
    return status;
}

