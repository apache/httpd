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

h2_task_input *h2_task_input_create(h2_task_env *env, apr_pool_t *pool, 
                                    apr_bucket_alloc_t *bucket_alloc)
{
    h2_task_input *input = apr_pcalloc(pool, sizeof(h2_task_input));
    if (input) {
        input->env = env;
        input->bb = NULL;
        
        if (env->serialize_headers) {
            input->bb = apr_brigade_create(pool, bucket_alloc);
            apr_brigade_printf(input->bb, NULL, NULL, "%s %s HTTP/1.1\r\n", 
                               env->method, env->path);
            apr_table_do(ser_header, input, env->headers, NULL);
            apr_brigade_puts(input->bb, NULL, NULL, "\r\n");
            if (input->env->input_eos) {
                APR_BRIGADE_INSERT_TAIL(input->bb, apr_bucket_eos_create(bucket_alloc));
            }
        }
        else if (!input->env->input_eos) {
            input->bb = apr_brigade_create(pool, bucket_alloc);
        }
        else {
            /* We do not serialize and have eos already, no need to
             * create a bucket brigade. */
        }
        
        if (APLOGcdebug(&env->c)) {
            char buffer[1024];
            apr_size_t len = sizeof(buffer)-1;
            if (input->bb) {
                apr_brigade_flatten(input->bb, buffer, &len);
            }
            buffer[len] = 0;
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, &env->c,
                          "h2_task_input(%s): request is: %s", 
                          env->id, buffer);
        }
    }
    return input;
}

void h2_task_input_destroy(h2_task_input *input)
{
    input->bb = NULL;
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
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c,
                  "h2_task_input(%s): read, block=%d, mode=%d, readbytes=%ld", 
                  input->env->id, block, mode, (long)readbytes);
    
    if (is_aborted(f)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                      "h2_task_input(%s): is aborted", 
                      input->env->id);
        return APR_ECONNABORTED;
    }
    
    if (mode == AP_MODE_INIT) {
        return APR_SUCCESS;
    }
    
    if (input->bb) {
        status = apr_brigade_length(input->bb, 1, &bblen);
        if (status != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, status, f->c,
                          "h2_task_input(%s): brigade length fail", 
                          input->env->id);
            return status;
        }
    }
    
    if ((bblen == 0) && input->env->input_eos) {
        return APR_EOF;
    }
    
    while ((bblen == 0) || (mode == AP_MODE_READBYTES && bblen < readbytes)) {
        /* Get more data for our stream from mplx.
         */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_task_input(%s): get more data from mplx, block=%d, "
                      "readbytes=%ld, queued=%ld",
                      input->env->id, block, 
                      (long)readbytes, (long)bblen);
        
        /* Although we sometimes get called with APR_NONBLOCK_READs, 
         we seem to  fill our buffer blocking. Otherwise we get EAGAIN,
         return that to our caller and everyone throws up their hands,
         never calling us again. */
        status = h2_mplx_in_read(input->env->mplx, APR_BLOCK_READ,
                                 input->env->stream_id, input->bb, 
                                 input->env->io);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_task_input(%s): mplx in read returned",
                      input->env->id);
        if (status != APR_SUCCESS) {
            return status;
        }
        status = apr_brigade_length(input->bb, 1, &bblen);
        if (status != APR_SUCCESS) {
            return status;
        }
        if ((bblen == 0) && (block == APR_NONBLOCK_READ)) {
            return h2_util_has_eos(input->bb, 0)? APR_EOF : APR_EAGAIN;
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                      "h2_task_input(%s): mplx in read, %ld bytes in brigade",
                      input->env->id, (long)bblen);
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                  "h2_task_input(%s): read, mode=%d, block=%d, "
                  "readbytes=%ld, queued=%ld",
                  input->env->id, mode, block, 
                  (long)readbytes, (long)bblen);
           
    if (!APR_BRIGADE_EMPTY(input->bb)) {
        if (mode == AP_MODE_EXHAUSTIVE) {
            /* return all we have */
            return h2_util_move(bb, input->bb, readbytes, 0, 
                                NULL, "task_input_read(exhaustive)");
        }
        else if (mode == AP_MODE_READBYTES) {
            return h2_util_move(bb, input->bb, readbytes, 0, 
                                NULL, "task_input_read(readbytes)");
        }
        else if (mode == AP_MODE_SPECULATIVE) {
            /* return not more than was asked for */
            return h2_util_copy(bb, input->bb, readbytes,  
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
                              input->env->id, buffer);
            }
            return status;
        }
        else {
            /* Hmm, well. There is mode AP_MODE_EATCRLF, but we chose not
             * to support it. Seems to work. */
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, f->c,
                          "h2_task_input, unsupported READ mode %d",
                          mode);
            return APR_ENOTIMPL;
        }
    }
    
    if (is_aborted(f)) {
        return APR_ECONNABORTED;
    }
    
    return (block == APR_NONBLOCK_READ)? APR_EAGAIN : APR_EOF;
}

