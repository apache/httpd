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
    h2_task_output *output = apr_pcalloc(c->pool, sizeof(h2_task_output));
    if (output) {
        output->c = c;
        output->task = task;
        output->state = H2_TASK_OUT_INIT;
        output->from_h1 = h2_from_h1_create(task->stream_id, c->pool);
        if (!output->from_h1) {
            return NULL;
        }
    }
    return output;
}

static apr_table_t *get_trailers(h2_task_output *output)
{
    if (!output->trailers_passed) {
        h2_response *response = h2_from_h1_get_response(output->from_h1);
        if (response && response->trailers) {
            output->trailers_passed = 1;
            if (h2_task_logio_add_bytes_out) {
                /* counter trailers as if we'd do a HTTP/1.1 serialization */
                h2_task_logio_add_bytes_out(output->c, 
                                            h2_util_table_bytes(response->trailers, 3)+1);
            }
            return response->trailers;
        }
    }
    return NULL;
}

static apr_status_t open_if_needed(h2_task_output *output, ap_filter_t *f,
                                   apr_bucket_brigade *bb, const char *caller)
{
    if (output->state == H2_TASK_OUT_INIT) {
        h2_response *response;
        output->state = H2_TASK_OUT_STARTED;
        response = h2_from_h1_get_response(output->from_h1);
        if (!response) {
            if (f) {
                /* This happens currently when ap_die(status, r) is invoked
                 * by a read request filter. */
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, output->c, APLOGNO(03204)
                              "h2_task_output(%s): write without response by %s "
                              "for %s %s %s",
                              output->task->id, caller, 
                              output->task->request->method, 
                              output->task->request->authority, 
                              output->task->request->path);
                output->c->aborted = 1;
            }
            if (output->task->io) {
                apr_thread_cond_broadcast(output->task->io);
            }
            return APR_ECONNABORTED;
        }
        
        if (h2_task_logio_add_bytes_out) {
            /* counter headers as if we'd do a HTTP/1.1 serialization */
            output->written = h2_util_table_bytes(response->headers, 3)+1;
            h2_task_logio_add_bytes_out(output->c, output->written);
        }
        get_trailers(output);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, output->c, APLOGNO(03348)
                      "h2_task(%s): open response to %s %s %s",
                      output->task->id, output->task->request->method, 
                      output->task->request->authority, 
                      output->task->request->path);
        return h2_mplx_out_open(output->task->mplx, output->task->stream_id, 
                                response, f, bb, output->task->io);
    }
    return APR_SUCCESS;
}

static apr_status_t write_brigade_raw(h2_task_output *output, 
                                      ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_off_t written, left;
    apr_status_t status;

    apr_brigade_length(bb, 0, &written);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, output->c,
                  "h2_task(%s): write response body (%ld bytes)", 
                  output->task->id, (long)written);
    
    status = h2_mplx_out_write(output->task->mplx, output->task->stream_id, 
                               f, output->task->blocking, bb, 
                               get_trailers(output), output->task->io);
    if (status == APR_INCOMPLETE) {
        apr_brigade_length(bb, 0, &left);
        written -= left;
        status = APR_SUCCESS;
    }

    if (status == APR_SUCCESS) {
        output->written += written;
        if (h2_task_logio_add_bytes_out) {
            h2_task_logio_add_bytes_out(output->c, written);
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
    apr_status_t status;
    
    if (APR_BRIGADE_EMPTY(bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, output->c,
                      "h2_task(%s): empty write", output->task->id);
        return APR_SUCCESS;
    }
    
    if (output->task->frozen) {
        h2_util_bb_log(output->c, output->task->stream_id, APLOG_TRACE2,
                       "frozen task output write", bb);
        return ap_save_brigade(f, &output->frozen_bb, &bb, output->c->pool);
    }
    
    status = open_if_needed(output, f, bb, "write");
    
    /* Attempt to write saved brigade first */
    if (status == APR_SUCCESS && output->bb 
        && !APR_BRIGADE_EMPTY(output->bb)) {
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
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, output->c,
                      "h2_task(%s): could not write all, saving brigade", 
                      output->task->id);
        if (!output->bb) {
            output->bb = apr_brigade_create(output->c->pool, output->c->bucket_alloc);
        }
        return ap_save_brigade(f, &output->bb, &bb, output->c->pool);
    }
    
    return status;
}

void h2_task_output_close(h2_task_output *output)
{
    open_if_needed(output, NULL, NULL, "close");
    if (output->state != H2_TASK_OUT_DONE) {
        if (output->frozen_bb && !APR_BRIGADE_EMPTY(output->frozen_bb)) {
            h2_mplx_out_write(output->task->mplx, output->task->stream_id, 
                NULL, 1, output->frozen_bb, NULL, NULL);
        }
        h2_mplx_out_close(output->task->mplx, output->task->stream_id, 
                          get_trailers(output));
        output->state = H2_TASK_OUT_DONE;
    }
}

