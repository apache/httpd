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

#include "h2_private.h"
#include "h2_conn.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_task_input.h"
#include "h2_task.h"
#include "h2_util.h"


static int is_aborted(ap_filter_t *f)
{
    return (f->c->aborted);
}

static int ser_header(void *ctx, const char *name, const char *value) 
{
    h2_task_input *input = (h2_task_input*)ctx;
    apr_brigade_printf(input->bb, NULL, NULL, "%s: %s\r\n", name, value);
    return 1;
}

h2_task_input *h2_task_input_create(h2_task *task, conn_rec *c)
{
    h2_task_input *input = apr_pcalloc(task->pool, sizeof(h2_task_input));
    if (input) {
        input->task = task;
        input->bb = NULL;
        input->block = APR_BLOCK_READ;
        
        if (task->ser_headers) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                          "h2_task_input(%s): serialize request %s %s", 
                          task->id, task->request->method, task->request->path);
            input->bb = apr_brigade_create(task->pool, c->bucket_alloc);
            apr_brigade_printf(input->bb, NULL, NULL, "%s %s HTTP/1.1\r\n", 
                               task->request->method, task->request->path);
            apr_table_do(ser_header, input, task->request->headers, NULL);
            apr_brigade_puts(input->bb, NULL, NULL, "\r\n");
            if (input->task->input_eos) {
                APR_BRIGADE_INSERT_TAIL(input->bb, apr_bucket_eos_create(c->bucket_alloc));
            }
        }
        else if (!input->task->input_eos) {
            input->bb = apr_brigade_create(task->pool, c->bucket_alloc);
        }
        else {
            /* We do not serialize and have eos already, no need to
             * create a bucket brigade. */
        }
    }
    return input;
}

void h2_task_input_block_set(h2_task_input *input, apr_read_type_e block)
{
    input->block = block;
}

apr_status_t h2_task_input_read(h2_task_input *input,
                                ap_filter_t* f,
                                apr_bucket_brigade* bb,
                                ap_input_mode_t mode,
                                apr_read_type_e block,
                                apr_off_t readbytes)
{
    apr_status_t status = APR_SUCCESS;
    apr_off_t bblen = 0;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                  "h2_task_input(%s): read, block=%d, mode=%d, readbytes=%ld", 
                  input->task->id, block, mode, (long)readbytes);
    
    if (mode == AP_MODE_INIT) {
        return ap_get_brigade(f->c->input_filters, bb, mode, block, readbytes);
    }
    
    if (is_aborted(f)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                      "h2_task_input(%s): is aborted", input->task->id);
        return APR_ECONNABORTED;
    }
    
    if (input->bb) {
        status = apr_brigade_length(input->bb, 1, &bblen);
        if (status != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, status, f->c,
                          APLOGNO(02958) "h2_task_input(%s): brigade length fail", 
                          input->task->id);
            return status;
        }
    }
    
    if ((bblen == 0) && input->task->input_eos) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                      "h2_task_input(%s): eos", input->task->id);
        return APR_EOF;
    }
    
    while (bblen == 0) {
        /* Get more data for our stream from mplx.
         */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_task_input(%s): get more data from mplx, block=%d, "
                      "readbytes=%ld, queued=%ld",
                      input->task->id, block, 
                      (long)readbytes, (long)bblen);
        
        /* Override the block mode we get called with depending on the input's
         * setting. 
         */
        status = h2_mplx_in_read(input->task->mplx, block,
                                 input->task->stream_id, input->bb, 
                                 f->r? f->r->trailers_in : NULL, 
                                 input->task->io);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_task_input(%s): mplx in read returned",
                      input->task->id);
        if (APR_STATUS_IS_EAGAIN(status) 
            && (mode == AP_MODE_GETLINE || block == APR_BLOCK_READ)) {
            /* chunked input handling does not seem to like it if we
             * return with APR_EAGAIN from a GETLINE read... 
             * upload 100k test on test-ser.example.org hangs */
            status = APR_SUCCESS;
        }
        else if (status != APR_SUCCESS) {
            return status;
        }
        
        status = apr_brigade_length(input->bb, 1, &bblen);
        if (status != APR_SUCCESS) {
            return status;
        }
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_task_input(%s): mplx in read, %ld bytes in brigade",
                      input->task->id, (long)bblen);
        if (h2_task_logio_add_bytes_in) {
            h2_task_logio_add_bytes_in(f->c, bblen);
        }
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                  "h2_task_input(%s): read, mode=%d, block=%d, "
                  "readbytes=%ld, queued=%ld",
                  input->task->id, mode, block, 
                  (long)readbytes, (long)bblen);
           
    if (!APR_BRIGADE_EMPTY(input->bb)) {
        if (mode == AP_MODE_EXHAUSTIVE) {
            /* return all we have */
            status = h2_util_move(bb, input->bb, readbytes, NULL, 
                                  "task_input_read(exhaustive)");
        }
        else if (mode == AP_MODE_READBYTES) {
            status = h2_util_move(bb, input->bb, readbytes, NULL, 
                                  "task_input_read(readbytes)");
        }
        else if (mode == AP_MODE_SPECULATIVE) {
            /* return not more than was asked for */
            status = h2_util_copy(bb, input->bb, readbytes,  
                                  "task_input_read(speculative)");
        }
        else if (mode == AP_MODE_GETLINE) {
            /* we are reading a single LF line, e.g. the HTTP headers */
            status = apr_brigade_split_line(bb, input->bb, block, 
                                            HUGE_STRING_LEN);
            if (APLOGctrace1(f->c)) {
                char buffer[1024];
                apr_size_t len = sizeof(buffer)-1;
                apr_brigade_flatten(bb, buffer, &len);
                buffer[len] = 0;
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                              "h2_task_input(%s): getline: %s",
                              input->task->id, buffer);
            }
        }
        else {
            /* Hmm, well. There is mode AP_MODE_EATCRLF, but we chose not
             * to support it. Seems to work. */
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, f->c,
                          APLOGNO(02942) 
                          "h2_task_input, unsupported READ mode %d", mode);
            status = APR_ENOTIMPL;
        }
        
        if (APLOGctrace1(f->c)) {
            apr_brigade_length(bb, 0, &bblen);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                          "h2_task_input(%s): return %ld data bytes",
                          input->task->id, (long)bblen);
        }
        return status;
    }
    
    if (is_aborted(f)) {
        return APR_ECONNABORTED;
    }
    
    status = (block == APR_NONBLOCK_READ)? APR_EAGAIN : APR_EOF;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                  "h2_task_input(%s): no data", input->task->id);
    return status;
}

