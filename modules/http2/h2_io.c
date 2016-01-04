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

#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>

#include "h2_private.h"
#include "h2_h2.h"
#include "h2_io.h"
#include "h2_mplx.h"
#include "h2_response.h"
#include "h2_request.h"
#include "h2_task.h"
#include "h2_util.h"

h2_io *h2_io_create(int id, apr_pool_t *pool)
{
    h2_io *io = apr_pcalloc(pool, sizeof(*io));
    if (io) {
        io->id = id;
        io->pool = pool;
        io->bucket_alloc = apr_bucket_alloc_create(pool);
    }
    return io;
}

void h2_io_destroy(h2_io *io)
{
    if (io->pool) {
        apr_pool_destroy(io->pool);
        /* gone */
    }
}

void h2_io_set_response(h2_io *io, h2_response *response) 
{
    AP_DEBUG_ASSERT(io->pool);
    AP_DEBUG_ASSERT(response);
    AP_DEBUG_ASSERT(!io->response);
    io->response = h2_response_clone(io->pool, response);
    if (response->rst_error) {
        h2_io_rst(io, response->rst_error);
    }
}


void h2_io_rst(h2_io *io, int error)
{
    io->rst_error = error;
    io->eos_in = 1;
}

int h2_io_in_has_eos_for(h2_io *io)
{
    return io->eos_in || (io->bbin && h2_util_has_eos(io->bbin, -1));
}

int h2_io_out_has_data(h2_io *io)
{
    return io->bbout && h2_util_bb_has_data_or_eos(io->bbout);
}

apr_off_t h2_io_out_length(h2_io *io)
{
    if (io->bbout) {
        apr_off_t len = 0;
        apr_brigade_length(io->bbout, 0, &len);
        return (len > 0)? len : 0;
    }
    return 0;
}

apr_status_t h2_io_in_shutdown(h2_io *io)
{
    if (io->bbin) {
        apr_off_t end_len = 0;
        apr_brigade_length(io->bbin, 1, &end_len);
        io->input_consumed += end_len;
        apr_brigade_cleanup(io->bbin);
    }
    return h2_io_in_close(io);
}


void h2_io_signal_init(h2_io *io, h2_io_op op, int timeout_secs, apr_thread_cond_t *cond)
{
    io->timed_op = op;
    io->timed_cond = cond;
    if (timeout_secs > 0) {
        io->timeout_at = apr_time_now() + apr_time_from_sec(timeout_secs);
    }
    else {
        io->timeout_at = 0; 
    }
}

void h2_io_signal_exit(h2_io *io)
{
    io->timed_cond = NULL;
    io->timeout_at = 0; 
}

apr_status_t h2_io_signal_wait(h2_mplx *m, h2_io *io)
{
    apr_status_t status;
    
    if (io->timeout_at != 0) {
        status = apr_thread_cond_timedwait(io->timed_cond, m->lock, io->timeout_at);
        if (APR_STATUS_IS_TIMEUP(status)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, m->c,  
                          "h2_mplx(%ld-%d): stream timeout expired: %s",
                          m->id, io->id, 
                          (io->timed_op == H2_IO_READ)? "read" : "write");
            h2_io_rst(io, H2_ERR_CANCEL);
        }
    }
    else {
        apr_thread_cond_wait(io->timed_cond, m->lock);
        status = APR_SUCCESS;
    }
    if (io->orphaned && status == APR_SUCCESS) {
        return APR_ECONNABORTED;
    }
    return status;
}

void h2_io_signal(h2_io *io, h2_io_op op)
{
    if (io->timed_cond && (io->timed_op == op || H2_IO_ANY == op)) {
        apr_thread_cond_signal(io->timed_cond);
    }
}

void h2_io_make_orphaned(h2_io *io, int error)
{
    io->orphaned = 1;
    if (error) {
        h2_io_rst(io, error);
    }
    /* if someone is waiting, wake him up */
    h2_io_signal(io, H2_IO_ANY);
}

static int add_trailer(void *ctx, const char *key, const char *value)
{
    apr_bucket_brigade *bb = ctx;
    apr_status_t status;
    
    status = apr_brigade_printf(bb, NULL, NULL, "%s: %s\r\n", 
                                key, value);
    return (status == APR_SUCCESS);
}

static apr_status_t append_eos(h2_io *io, apr_bucket_brigade *bb, 
                               apr_table_t *trailers)
{
    apr_status_t status = APR_SUCCESS;
    apr_table_t *t = io->request->trailers;

    if (trailers && t && !apr_is_empty_table(trailers)) {
        /* trailers passed in, transfer directly. */
        apr_table_overlap(trailers, t, APR_OVERLAP_TABLES_SET);
        t = NULL;
    }
    
    if (io->request->chunked) {
        if (t && !apr_is_empty_table(t)) {
            /* no trailers passed in, transfer via chunked */
            status = apr_brigade_puts(bb, NULL, NULL, "0\r\n");
            apr_table_do(add_trailer, bb, t, NULL);
            status = apr_brigade_puts(bb, NULL, NULL, "\r\n");
        }
        else {
            status = apr_brigade_puts(bb, NULL, NULL, "0\r\n\r\n");
        }
    }
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(io->bucket_alloc));
    return status;
}

apr_status_t h2_io_in_read(h2_io *io, apr_bucket_brigade *bb, 
                           apr_size_t maxlen, apr_table_t *trailers)
{
    apr_off_t start_len = 0;
    apr_status_t status;

    if (io->rst_error) {
        return APR_ECONNABORTED;
    }
    
    if (!io->bbin || APR_BRIGADE_EMPTY(io->bbin)) {
        if (io->eos_in) {
            if (!io->eos_in_written) {
                status = append_eos(io, bb, trailers);
                io->eos_in_written = 1;
                return status;
            }
            return APR_EOF;
        }
        return APR_EAGAIN;
    }
    
    if (io->request->chunked) {
        /* the reader expects HTTP/1.1 chunked encoding */
        status = h2_util_move(io->tmp, io->bbin, maxlen, NULL, "h2_io_in_read_chunk");
        if (status == APR_SUCCESS) {
            apr_off_t tmp_len = 0;
            
            apr_brigade_length(io->tmp, 1, &tmp_len);
            if (tmp_len > 0) {
                io->input_consumed += tmp_len;
                status = apr_brigade_printf(bb, NULL, NULL, "%lx\r\n", 
                                            (unsigned long)tmp_len);
                if (status == APR_SUCCESS) {
                    status = h2_util_move(bb, io->tmp, -1, NULL, "h2_io_in_read_tmp1");
                    if (status == APR_SUCCESS) {
                        status = apr_brigade_puts(bb, NULL, NULL, "\r\n");
                    }
                }
            }
            else {
                status = h2_util_move(bb, io->tmp, -1, NULL, "h2_io_in_read_tmp2");
            }
            apr_brigade_cleanup(io->tmp);
        }
    }
    else {
        apr_brigade_length(bb, 1, &start_len);
        
        status = h2_util_move(bb, io->bbin, maxlen, NULL, "h2_io_in_read");
        if (status == APR_SUCCESS) {
            apr_off_t end_len = 0;
            apr_brigade_length(bb, 1, &end_len);
            io->input_consumed += (end_len - start_len);
        }
    }
    
    return status;
}

apr_status_t h2_io_in_write(h2_io *io, apr_bucket_brigade *bb)
{
    if (io->rst_error) {
        return APR_ECONNABORTED;
    }
    
    if (io->eos_in) {
        return APR_EOF;
    }
    io->eos_in = h2_util_has_eos(bb, -1);
    if (!APR_BRIGADE_EMPTY(bb)) {
        if (!io->bbin) {
            io->bbin = apr_brigade_create(io->pool, io->bucket_alloc);
            io->tmp = apr_brigade_create(io->pool, io->bucket_alloc);
        }
        return h2_util_move(io->bbin, bb, -1, NULL, "h2_io_in_write");
    }
    return APR_SUCCESS;
}

apr_status_t h2_io_in_close(h2_io *io)
{
    if (io->rst_error) {
        return APR_ECONNABORTED;
    }
    
    io->eos_in = 1;
    return APR_SUCCESS;
}

apr_status_t h2_io_out_readx(h2_io *io,  
                             h2_io_data_cb *cb, void *ctx, 
                             apr_off_t *plen, int *peos)
{
    apr_status_t status;
    
    if (io->rst_error) {
        return APR_ECONNABORTED;
    }
    
    if (io->eos_out) {
        *plen = 0;
        *peos = 1;
        return APR_SUCCESS;
    }
    else if (!io->bbout) {
        *plen = 0;
        *peos = 0;
        return APR_EAGAIN;
    }
    
    if (cb == NULL) {
        /* just checking length available */
        status = h2_util_bb_avail(io->bbout, plen, peos);
    }
    else {
        status = h2_util_bb_readx(io->bbout, cb, ctx, plen, peos);
        if (status == APR_SUCCESS) {
            io->eos_out = *peos;
        }
    }
    
    return status;
}

apr_status_t h2_io_out_read_to(h2_io *io, apr_bucket_brigade *bb, 
                               apr_off_t *plen, int *peos)
{
    if (io->rst_error) {
        return APR_ECONNABORTED;
    }
    
    if (io->eos_out) {
        *plen = 0;
        *peos = 1;
        return APR_SUCCESS;
    }
    else if (!io->bbout) {
        *plen = 0;
        *peos = 0;
        return APR_EAGAIN;
    }

    io->eos_out = *peos = h2_util_has_eos(io->bbout, *plen);
    return h2_util_move(bb, io->bbout, *plen, NULL, "h2_io_read_to");
}

static void process_trailers(h2_io *io, apr_table_t *trailers)
{
    if (trailers && io->response) {
        h2_response_set_trailers(io->response, 
                                 apr_table_clone(io->pool, trailers));
    }
}

apr_status_t h2_io_out_write(h2_io *io, apr_bucket_brigade *bb, 
                             apr_size_t maxlen, apr_table_t *trailers,
                             int *pfile_handles_allowed)
{
    apr_status_t status;
    int start_allowed;
    
    if (io->rst_error) {
        return APR_ECONNABORTED;
    }

    if (io->eos_out) {
        apr_off_t len;
        /* We have already delivered an EOS bucket to a reader, no
         * sense in storing anything more here.
         */
        status = apr_brigade_length(bb, 1, &len);
        if (status == APR_SUCCESS) {
            if (len > 0) {
                /* someone tries to write real data after EOS, that
                 * does not look right. */
                status = APR_EOF;
            }
            /* cleanup, as if we had moved the data */
            apr_brigade_cleanup(bb);
        }
        return status;
    }

    process_trailers(io, trailers);
    if (!io->bbout) {
        io->bbout = apr_brigade_create(io->pool, io->bucket_alloc);
    }
    
    /* Let's move the buckets from the request processing in here, so
     * that the main thread can read them when it has time/capacity.
     *
     * Move at most "maxlen" memory bytes. If buckets remain, it is
     * the caller's responsibility to take care of this.
     *
     * We allow passing of file buckets as long as we do not have too
     * many open files already buffered. Otherwise we will run out of
     * file handles.
     */
    start_allowed = *pfile_handles_allowed;
    status = h2_util_move(io->bbout, bb, maxlen, pfile_handles_allowed, 
                          "h2_io_out_write");
    /* track # file buckets moved into our pool */
    if (start_allowed != *pfile_handles_allowed) {
        io->files_handles_owned += (start_allowed - *pfile_handles_allowed);
    }
    return status;
}


apr_status_t h2_io_out_close(h2_io *io, apr_table_t *trailers)
{
    if (io->rst_error) {
        return APR_ECONNABORTED;
    }
    if (!io->eos_out) { /* EOS has not been read yet */
        process_trailers(io, trailers);
        if (!io->bbout) {
            io->bbout = apr_brigade_create(io->pool, io->bucket_alloc);
        }
        if (!h2_util_has_eos(io->bbout, -1)) {
            APR_BRIGADE_INSERT_TAIL(io->bbout, 
                                    apr_bucket_eos_create(io->bucket_alloc));
        }
    }
    return APR_SUCCESS;
}
