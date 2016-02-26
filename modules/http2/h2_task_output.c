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
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, APLOGNO(03204)
                              "h2_task_output(%s): write without response by %s "
                              "for %s %s %s",
                              output->task->id, caller, 
                              output->task->request->method, 
                              output->task->request->authority, 
                              output->task->request->path);
                f->c->aborted = 1;
            }
            if (output->task->io) {
                apr_thread_cond_broadcast(output->task->io);
            }
            return APR_ECONNABORTED;
        }
        
        if (h2_task_logio_add_bytes_out) {
            /* counter headers as if we'd do a HTTP/1.1 serialization */
            /* TODO: counter a virtual status line? */
            apr_off_t bytes_written;
            apr_brigade_length(bb, 0, &bytes_written);
            bytes_written += h2_util_table_bytes(response->headers, 3)+1;
            h2_task_logio_add_bytes_out(f->c, bytes_written);
        }
        get_trailers(output);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, APLOGNO(03204)
                      "h2_task_output(%s): open as needed %s %s %s",
                      output->task->id, output->task->request->method, 
                      output->task->request->authority, 
                      output->task->request->path);
        return h2_mplx_out_open(output->task->mplx, output->task->stream_id, 
                                response, f, bb, output->task->io);
    }
    return APR_EOF;
}

void h2_task_output_close(h2_task_output *output)
{
    open_if_needed(output, NULL, NULL, "close");
    if (output->state != H2_TASK_OUT_DONE) {
        if (output->task->frozen_out 
            && !APR_BRIGADE_EMPTY(output->task->frozen_out)) {
            h2_mplx_out_write(output->task->mplx, output->task->stream_id, 
                NULL, output->task->frozen_out, NULL, NULL);
        }
        h2_mplx_out_close(output->task->mplx, output->task->stream_id, 
                          get_trailers(output));
        output->state = H2_TASK_OUT_DONE;
    }
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
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                      "h2_task_output(%s): empty write", output->task->id);
        return APR_SUCCESS;
    }
    
    if (output->task->frozen) {
        h2_util_bb_log(output->c, output->task->stream_id, APLOG_TRACE2,
                       "frozen task output write", bb);
        return ap_save_brigade(f, &output->task->frozen_out, &bb, 
                               output->c->pool);
    }
    
    status = open_if_needed(output, f, bb, "write");
    if (status != APR_EOF) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_task_output(%s): opened and passed brigade", 
                      output->task->id);
        return status;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                  "h2_task_output(%s): write brigade", output->task->id);
    if (h2_task_logio_add_bytes_out) {
        apr_off_t bytes_written;
        apr_brigade_length(bb, 0, &bytes_written);
        h2_task_logio_add_bytes_out(f->c, bytes_written);
    }
    return h2_mplx_out_write(output->task->mplx, output->task->stream_id, 
                             f, bb, get_trailers(output), output->task->io);
}

