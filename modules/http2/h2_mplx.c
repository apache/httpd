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
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>
#include <apr_strings.h>
#include <apr_time.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_config.h"
#include "h2_conn.h"
#include "h2_h2.h"
#include "h2_io.h"
#include "h2_io_set.h"
#include "h2_response.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_stream.h"
#include "h2_stream_set.h"
#include "h2_task.h"
#include "h2_task_input.h"
#include "h2_task_output.h"
#include "h2_task_queue.h"
#include "h2_workers.h"
#include "h2_util.h"


static int is_aborted(h2_mplx *m, apr_status_t *pstatus) {
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        *pstatus = APR_ECONNABORTED;
        return 1;
    }
    return 0;
}

static void have_out_data_for(h2_mplx *m, int stream_id);

static void h2_mplx_destroy(h2_mplx *m)
{
    AP_DEBUG_ASSERT(m);
    m->aborted = 1;
    if (m->ready_ios) {
        h2_io_set_destroy(m->ready_ios);
        m->ready_ios = NULL;
    }
    if (m->stream_ios) {
        h2_io_set_destroy(m->stream_ios);
        m->stream_ios = NULL;
    }
    
    if (m->lock) {
        apr_thread_mutex_destroy(m->lock);
        m->lock = NULL;
    }
    
    if (m->pool) {
        apr_pool_destroy(m->pool);
    }
}

/**
 * A h2_mplx needs to be thread-safe *and* if will be called by
 * the h2_session thread *and* the h2_worker threads. Therefore:
 * - calls are protected by a mutex lock, m->lock
 * - the pool needs its own allocator, since apr_allocator_t are 
 *   not re-entrant. The separate allocator works without a 
 *   separate lock since we already protect h2_mplx itself.
 *   Since HTTP/2 connections can be expected to live longer than
 *   their HTTP/1 cousins, the separate allocator seems to work better
 *   than protecting a shared h2_session one with an own lock.
 */
h2_mplx *h2_mplx_create(conn_rec *c, apr_pool_t *parent, h2_workers *workers)
{
    apr_status_t status = APR_SUCCESS;
    h2_config *conf = h2_config_get(c);
    apr_allocator_t *allocator = NULL;
    h2_mplx *m;
    AP_DEBUG_ASSERT(conf);
    
    status = apr_allocator_create(&allocator);
    if (status != APR_SUCCESS) {
        return NULL;
    }

    m = apr_pcalloc(parent, sizeof(h2_mplx));
    if (m) {
        m->id = c->id;
        APR_RING_ELEM_INIT(m, link);
        apr_atomic_set32(&m->refs, 1);
        m->c = c;
        apr_pool_create_ex(&m->pool, parent, NULL, allocator);
        if (!m->pool) {
            return NULL;
        }
        apr_allocator_owner_set(allocator, m->pool);
        
        status = apr_thread_mutex_create(&m->lock, APR_THREAD_MUTEX_DEFAULT,
                                         m->pool);
        if (status != APR_SUCCESS) {
            h2_mplx_destroy(m);
            return NULL;
        }
        
        m->bucket_alloc = apr_bucket_alloc_create(m->pool);
        
        m->q = h2_tq_create(m->pool, h2_config_geti(conf, H2_CONF_MAX_STREAMS));
        m->stream_ios = h2_io_set_create(m->pool);
        m->ready_ios = h2_io_set_create(m->pool);
        m->stream_max_mem = h2_config_geti(conf, H2_CONF_STREAM_MAX_MEM);
        m->workers = workers;
        
        m->file_handles_allowed = h2_config_geti(conf, H2_CONF_SESSION_FILES);
    }
    return m;
}

static void reference(h2_mplx *m)
{
    apr_atomic_inc32(&m->refs);
}

static void release(h2_mplx *m, int lock)
{
    if (!apr_atomic_dec32(&m->refs)) {
        if (lock) {
            apr_thread_mutex_lock(m->lock);
        }
        if (m->join_wait) {
            apr_thread_cond_signal(m->join_wait);
        }
        if (lock) {
            apr_thread_mutex_unlock(m->lock);
        }
    }
}

void h2_mplx_reference(h2_mplx *m)
{
    reference(m);
}
void h2_mplx_release(h2_mplx *m)
{
    release(m, 1);
}

static void workers_register(h2_mplx *m) {
    /* Initially, there was ref count increase for this as well, but
     * this is not needed, even harmful.
     * h2_workers is only a hub for all the h2_worker instances.
     * At the end-of-life of this h2_mplx, we always unregister at
     * the workers. The thing to manage are all the h2_worker instances
     * out there. Those may hold a reference to this h2_mplx and we cannot
     * call them to unregister.
     * 
     * Therefore: ref counting for h2_workers in not needed, ref counting
     * for h2_worker using this is critical.
     */
    h2_workers_register(m->workers, m);
}

static void workers_unregister(h2_mplx *m) {
    h2_workers_unregister(m->workers, m);
}

apr_status_t h2_mplx_release_and_join(h2_mplx *m, apr_thread_cond_t *wait)
{
    apr_status_t status;
    workers_unregister(m);

    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        release(m, 0);
        while (apr_atomic_read32(&m->refs) > 0) {
            m->join_wait = wait;
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c,
                          "h2_mplx(%ld): release_join, refs=%d, waiting...", 
                          m->id, m->refs);
            apr_thread_cond_wait(wait, m->lock);
        }
        m->join_wait = NULL;
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c,
                      "h2_mplx(%ld): release_join -> destroy", m->id);
        apr_thread_mutex_unlock(m->lock);
        h2_mplx_destroy(m);
    }
    return status;
}

void h2_mplx_abort(h2_mplx *m)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        m->aborted = 1;
        h2_io_set_destroy_all(m->stream_ios);
        apr_thread_mutex_unlock(m->lock);
    }
    workers_unregister(m);
}


static void io_destroy(h2_mplx *m, h2_io *io)
{
    if (io) {
        apr_pool_t *pool = io->pool;
        if (pool) {
            io->pool = NULL;
            apr_pool_clear(pool);
            if (m->spare_pool) {
                apr_pool_destroy(m->spare_pool);
            }
            m->spare_pool = pool;
        }
        /* The pool is cleared/destroyed which also closes all
         * allocated file handles. Give this count back to our
         * file handle pool. */
        m->file_handles_allowed += io->files_handles_owned;
        h2_io_set_remove(m->stream_ios, io);
        h2_io_set_remove(m->ready_ios, io);
        h2_io_destroy(io);
    }
}

apr_status_t h2_mplx_stream_done(h2_mplx *m, int stream_id, int rst_error)
{
    apr_status_t status;
    
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        
        if (io) {
            /* Remove io from ready set, we will never submit it */
            h2_io_set_remove(m->ready_ios, io);
            
            if (io->task_done) {
                io_destroy(m, io);
            }
            else {
                /* cleanup once task is done */
                io->zombie = 1;
                if (rst_error) {
                    /* Forward error code to fail any further attempt to
                     * write to io */
                    h2_io_rst(io, rst_error);
                }
            }
        }
        
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

void h2_mplx_task_done(h2_mplx *m, int stream_id)
{
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                      "h2_mplx(%ld): task(%d) done", m->id, stream_id);
        if (io) {
            io->task_done = 1;
            if (io->zombie) {
                io_destroy(m, io);
            }
            else {
                /* hang around until the stream deregisteres */
            }
        }
        apr_thread_mutex_unlock(m->lock);
    }
}

apr_status_t h2_mplx_in_read(h2_mplx *m, apr_read_type_e block,
                             int stream_id, apr_bucket_brigade *bb,
                             struct apr_thread_cond_t *iowait)
{
    apr_status_t status; 
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io) {
            io->input_arrived = iowait;
            status = h2_io_in_read(io, bb, 0);
            while (APR_STATUS_IS_EAGAIN(status) 
                   && !is_aborted(m, &status)
                   && block == APR_BLOCK_READ) {
                apr_thread_cond_wait(io->input_arrived, m->lock);
                status = h2_io_in_read(io, bb, 0);
            }
            io->input_arrived = NULL;
        }
        else {
            status = APR_EOF;
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

apr_status_t h2_mplx_in_write(h2_mplx *m, int stream_id, 
                              apr_bucket_brigade *bb)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io) {
            status = h2_io_in_write(io, bb);
            if (io->input_arrived) {
                apr_thread_cond_signal(io->input_arrived);
            }
        }
        else {
            status = APR_EOF;
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

apr_status_t h2_mplx_in_close(h2_mplx *m, int stream_id)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io) {
            status = h2_io_in_close(io);
            if (io->input_arrived) {
                apr_thread_cond_signal(io->input_arrived);
            }
        }
        else {
            status = APR_ECONNABORTED;
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

typedef struct {
    h2_mplx_consumed_cb *cb;
    void *cb_ctx;
    int streams_updated;
} update_ctx;

static int update_window(void *ctx, h2_io *io)
{
    if (io->input_consumed) {
        update_ctx *uctx = (update_ctx*)ctx;
        uctx->cb(uctx->cb_ctx, io->id, io->input_consumed);
        io->input_consumed = 0;
        ++uctx->streams_updated;
    }
    return 1;
}

apr_status_t h2_mplx_in_update_windows(h2_mplx *m, 
                                       h2_mplx_consumed_cb *cb, void *cb_ctx)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        update_ctx ctx;
        
        ctx.cb              = cb;
        ctx.cb_ctx          = cb_ctx;
        ctx.streams_updated = 0;

        status = APR_EAGAIN;
        h2_io_set_iter(m->stream_ios, update_window, &ctx);
        
        if (ctx.streams_updated) {
            status = APR_SUCCESS;
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

#define H2_MPLX_IO_OUT(lvl,m,io,msg) \
    do { \
        if (APLOG_C_IS_LEVEL((m)->c,lvl)) \
        h2_util_bb_log((m)->c,(io)->id,lvl,msg,(io)->bbout); \
    } while(0)


apr_status_t h2_mplx_out_readx(h2_mplx *m, int stream_id, 
                               h2_io_data_cb *cb, void *ctx, 
                               apr_size_t *plen, int *peos)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io) {
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_readx_pre");
            
            status = h2_io_out_readx(io, cb, ctx, plen, peos);
            
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_readx_post");
            if (status == APR_SUCCESS && cb && io->output_drained) {
                apr_thread_cond_signal(io->output_drained);
            }
        }
        else {
            status = APR_ECONNABORTED;
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

apr_status_t h2_mplx_out_read_to(h2_mplx *m, int stream_id, 
                                 apr_bucket_brigade *bb, 
                                 apr_size_t *plen, int *peos)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io) {
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_read_to_pre");
            
            status = h2_io_out_read_to(io, bb, plen, peos);
            
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_read_to_post");
            if (status == APR_SUCCESS && io->output_drained) {
                apr_thread_cond_signal(io->output_drained);
            }
        }
        else {
            status = APR_ECONNABORTED;
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

h2_stream *h2_mplx_next_submit(h2_mplx *m, h2_stream_set *streams)
{
    apr_status_t status;
    h2_stream *stream = NULL;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return NULL;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_pop_highest_prio(m->ready_ios);
        if (io) {
            stream = h2_stream_set_get(streams, io->id);
            if (stream) {
                if (io->rst_error) {
                    h2_stream_rst(stream, io->rst_error);
                }
                else {
                    AP_DEBUG_ASSERT(io->response);
                    h2_stream_set_response(stream, io->response, io->bbout);
                }
                
            }
            else {
                /* We have the io ready, but the stream has gone away, maybe
                 * reset by the client. Should no longer happen since such
                 * streams should clear io's from the ready queue.
                 */
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, m->c, APLOGNO(02953) 
                              "h2_mplx(%ld): stream for response %d closed, "
                              "resetting io to close request processing",
                              m->id, io->id);
                h2_io_rst(io, H2_ERR_STREAM_CLOSED);
            }
            
            if (io->output_drained) {
                apr_thread_cond_signal(io->output_drained);
            }
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return stream;
}

static apr_status_t out_write(h2_mplx *m, h2_io *io, 
                              ap_filter_t* f, apr_bucket_brigade *bb,
                              struct apr_thread_cond_t *iowait)
{
    apr_status_t status = APR_SUCCESS;
    /* We check the memory footprint queued for this stream_id
     * and block if it exceeds our configured limit.
     * We will not split buckets to enforce the limit to the last
     * byte. After all, the bucket is already in memory.
     */
    while (!APR_BRIGADE_EMPTY(bb) 
           && (status == APR_SUCCESS)
           && !is_aborted(m, &status)) {
        
        status = h2_io_out_write(io, bb, m->stream_max_mem, 
                                 &m->file_handles_allowed);
        /* Wait for data to drain until there is room again */
        while (!APR_BRIGADE_EMPTY(bb) 
               && iowait
               && status == APR_SUCCESS
               && (m->stream_max_mem <= h2_io_out_length(io))
               && !is_aborted(m, &status)) {
            io->output_drained = iowait;
            if (f) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                              "h2_mplx(%ld-%d): waiting for out drain", 
                              m->id, io->id);
            }
            apr_thread_cond_wait(io->output_drained, m->lock);
            io->output_drained = NULL;
        }
    }
    apr_brigade_cleanup(bb);
    
    return status;
}

static apr_status_t out_open(h2_mplx *m, int stream_id, h2_response *response,
                             ap_filter_t* f, apr_bucket_brigade *bb,
                             struct apr_thread_cond_t *iowait)
{
    apr_status_t status = APR_SUCCESS;
    
    h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
    if (io) {
        if (f) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c,
                          "h2_mplx(%ld-%d): open response: %s, rst=%d",
                          m->id, stream_id, response->status, 
                          response->rst_error);
        }
        
        h2_io_set_response(io, response);
        h2_io_set_add(m->ready_ios, io);
        if (bb) {
            status = out_write(m, io, f, bb, iowait);
        }
        have_out_data_for(m, stream_id);
    }
    else {
        status = APR_ECONNABORTED;
    }
    return status;
}

apr_status_t h2_mplx_out_open(h2_mplx *m, int stream_id, h2_response *response,
                              ap_filter_t* f, apr_bucket_brigade *bb,
                              struct apr_thread_cond_t *iowait)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        status = out_open(m, stream_id, response, f, bb, iowait);
        if (APLOGctrace1(m->c)) {
            h2_util_bb_log(m->c, stream_id, APLOG_TRACE1, "h2_mplx_out_open", bb);
        }
        if (m->aborted) {
            return APR_ECONNABORTED;
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}


apr_status_t h2_mplx_out_write(h2_mplx *m, int stream_id, 
                               ap_filter_t* f, apr_bucket_brigade *bb,
                               struct apr_thread_cond_t *iowait)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        if (!m->aborted) {
            h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
            if (io) {
                status = out_write(m, io, f, bb, iowait);
                H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_write");
                
                have_out_data_for(m, stream_id);
                if (m->aborted) {
                    return APR_ECONNABORTED;
                }
            }
            else {
                status = APR_ECONNABORTED;
            }
        }
        
        if (m->lock) {
            apr_thread_mutex_unlock(m->lock);
        }
    }
    return status;
}

apr_status_t h2_mplx_out_close(h2_mplx *m, int stream_id)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        if (!m->aborted) {
            h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
            if (io) {
                if (!io->response && !io->rst_error) {
                    /* In case a close comes before a response was created,
                     * insert an error one so that our streams can properly
                     * reset.
                     */
                    h2_response *r = h2_response_create(stream_id, 0, 
                                                        "500", NULL, m->pool);
                    status = out_open(m, stream_id, r, NULL, NULL, NULL);
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, m->c,
                                  "h2_mplx(%ld-%d): close, no response, no rst", 
                                  m->id, io->id);
                }
                status = h2_io_out_close(io);
                H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_close");
                
                have_out_data_for(m, stream_id);
                if (m->aborted) {
                    /* if we were the last output, the whole session might
                     * have gone down in the meantime.
                     */
                    return APR_SUCCESS;
                }
            }
            else {
                status = APR_ECONNABORTED;
            }
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

apr_status_t h2_mplx_out_rst(h2_mplx *m, int stream_id, int error)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        if (!m->aborted) {
            h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
            if (io && !io->rst_error) {
                h2_io_rst(io, error);
                if (!io->response) {
                        h2_io_set_add(m->ready_ios, io);
                }
                H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_rst");
                
                have_out_data_for(m, stream_id);
                if (io->output_drained) {
                    apr_thread_cond_signal(io->output_drained);
                }
            }
            else {
                status = APR_ECONNABORTED;
            }
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

int h2_mplx_in_has_eos_for(h2_mplx *m, int stream_id)
{
    int has_eos = 0;
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return 0;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io) {
            has_eos = h2_io_in_has_eos_for(io);
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return has_eos;
}

int h2_mplx_out_has_data_for(h2_mplx *m, int stream_id)
{
    apr_status_t status;
    int has_data = 0;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return 0;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io) {
            has_data = h2_io_out_has_data(io);
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return has_data;
}

apr_status_t h2_mplx_out_trywait(h2_mplx *m, apr_interval_time_t timeout,
                                 apr_thread_cond_t *iowait)
{
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        m->added_output = iowait;
        status = apr_thread_cond_timedwait(m->added_output, m->lock, timeout);
        if (APLOGctrace2(m->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                          "h2_mplx(%ld): trywait on data for %f ms)",
                          m->id, timeout/1000.0);
        }
        m->added_output = NULL;
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

static void have_out_data_for(h2_mplx *m, int stream_id)
{
    (void)stream_id;
    AP_DEBUG_ASSERT(m);
    if (m->added_output) {
        apr_thread_cond_signal(m->added_output);
    }
}

typedef struct {
    h2_stream_pri_cmp *cmp;
    void *ctx;
} cmp_ctx;

static int task_cmp(h2_task *t1, h2_task *t2, void *ctx)
{
    cmp_ctx *x = ctx;
    return x->cmp(t1->stream_id, t2->stream_id, x->ctx);
}

apr_status_t h2_mplx_reprioritize(h2_mplx *m, h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status;
    
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        cmp_ctx x;
        
        x.cmp = cmp;
        x.ctx = ctx;
        h2_tq_sort(m->q, task_cmp, &x);
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                      "h2_mplx(%ld): reprioritize tasks", m->id);
        apr_thread_mutex_unlock(m->lock);
    }
    workers_register(m);
    return status;
}

static h2_io *open_io(h2_mplx *m, int stream_id)
{
    apr_pool_t *io_pool = m->spare_pool;
    h2_io *io;
    
    if (!io_pool) {
        apr_pool_create(&io_pool, m->pool);
    }
    else {
        m->spare_pool = NULL;
    }
    
    io = h2_io_create(stream_id, io_pool, m->bucket_alloc);
    h2_io_set_add(m->stream_ios, io);
    
    return io;
}


apr_status_t h2_mplx_process(h2_mplx *m, int stream_id,
                             struct h2_request *r, int eos, 
                             h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status;
    
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        conn_rec *c;
        h2_io *io;
        cmp_ctx x;
        
        io = open_io(m, stream_id);
        c = h2_conn_create(m->c, io->pool);
        io->task = h2_task_create(m->id, stream_id, io->pool, m, c);
            
        status = h2_request_end_headers(r, m, io->task, eos);
        if (status == APR_SUCCESS && eos) {
            status = h2_io_in_close(io);
        }
        
        if (status == APR_SUCCESS) {
            x.cmp = cmp;
            x.ctx = ctx;
            h2_tq_add(m->q, io->task, task_cmp, &x);
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, m->c,
                      "h2_mplx(%ld-%d): process", m->c->id, stream_id);
        apr_thread_mutex_unlock(m->lock);
    }
    
    if (status == APR_SUCCESS) {
        workers_register(m);
    }
    return status;
}

h2_task *h2_mplx_pop_task(h2_mplx *m, int *has_more)
{
    h2_task *task = NULL;
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        *has_more = 0;
        return NULL;
    }
    status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        task = h2_tq_shift(m->q);
        *has_more = !h2_tq_empty(m->q);
        apr_thread_mutex_unlock(m->lock);
    }
    return task;
}

