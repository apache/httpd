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
#include "h2_io.h"
#include "h2_io_set.h"
#include "h2_response.h"
#include "h2_mplx.h"
#include "h2_stream.h"
#include "h2_stream_set.h"
#include "h2_task.h"
#include "h2_task_input.h"
#include "h2_task_output.h"
#include "h2_task_queue.h"
#include "h2_workers.h"


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
    if (m->q) {
        h2_tq_destroy(m->q);
        m->q = NULL;
    }
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
    AP_DEBUG_ASSERT(conf);
    
    apr_allocator_t *allocator = NULL;
    status = apr_allocator_create(&allocator);
    if (status != APR_SUCCESS) {
        return NULL;
    }

    h2_mplx *m = apr_pcalloc(parent, sizeof(h2_mplx));
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
        
        m->q = h2_tq_create(m->id, m->pool);
        m->stream_ios = h2_io_set_create(m->pool);
        m->ready_ios = h2_io_set_create(m->pool);
        m->closed = h2_stream_set_create(m->pool);
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

static void release(h2_mplx *m)
{
    if (!apr_atomic_dec32(&m->refs)) {
        if (m->join_wait) {
            apr_thread_cond_signal(m->join_wait);
        }
    }
}

void h2_mplx_reference(h2_mplx *m)
{
    reference(m);
}
void h2_mplx_release(h2_mplx *m)
{
    release(m);
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
    workers_unregister(m);

    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        int attempts = 0;
        
        release(m);
        while (apr_atomic_read32(&m->refs) > 0) {
            m->join_wait = wait;
            ap_log_cerror(APLOG_MARK, (attempts? APLOG_INFO : APLOG_DEBUG), 
                          0, m->c,
                          "h2_mplx(%ld): release_join, refs=%d, waiting...", 
                          m->id, m->refs);
            apr_thread_cond_timedwait(wait, m->lock, apr_time_from_sec(10));
            if (++attempts >= 6) {
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c,
                              "h2_mplx(%ld): join attempts exhausted, refs=%d", 
                              m->id, m->refs);
                break;
            }
        }
        if (m->join_wait) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c,
                          "h2_mplx(%ld): release_join -> destroy", m->id);
        }
        m->join_wait = NULL;
        apr_thread_mutex_unlock(m->lock);
        h2_mplx_destroy(m);
    }
    return status;
}

void h2_mplx_abort(h2_mplx *m)
{
    AP_DEBUG_ASSERT(m);
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        m->aborted = 1;
        h2_io_set_destroy_all(m->stream_ios);
        apr_thread_mutex_unlock(m->lock);
    }
    workers_unregister(m);
}


h2_stream *h2_mplx_open_io(h2_mplx *m, int stream_id)
{
    h2_stream *stream = NULL;

    if (m->aborted) {
        return NULL;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        apr_pool_t *stream_pool = m->spare_pool;
        
        if (!stream_pool) {
            apr_pool_create(&stream_pool, m->pool);
        }
        else {
            m->spare_pool = NULL;
        }
        
        stream = h2_stream_create(stream_id, stream_pool, m);
        stream->state = H2_STREAM_ST_OPEN;
        
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (!io) {
            io = h2_io_create(stream_id, stream_pool, m->bucket_alloc);
            h2_io_set_add(m->stream_ios, io);
        }
        status = io? APR_SUCCESS : APR_ENOMEM;
        apr_thread_mutex_unlock(m->lock);
    }
    return stream;
}

static void stream_destroy(h2_mplx *m, h2_stream *stream, h2_io *io)
{
    apr_pool_t *pool = h2_stream_detach_pool(stream);
    if (pool) {
        apr_pool_clear(pool);
        if (m->spare_pool) {
            apr_pool_destroy(m->spare_pool);
        }
        m->spare_pool = pool;
    }
    h2_stream_destroy(stream);
    if (io) {
        /* The pool is cleared/destroyed which also closes all
         * allocated file handles. Give this count back to our
         * file handle pool. */
        m->file_handles_allowed += io->files_handles_owned;
        h2_io_set_remove(m->stream_ios, io);
        h2_io_destroy(io);
    }
}

apr_status_t h2_mplx_cleanup_stream(h2_mplx *m, h2_stream *stream)
{
    AP_DEBUG_ASSERT(m);
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream->id);
        if (!io || io->task_done) {
            /* No more io or task already done -> cleanup immediately */
            stream_destroy(m, stream, io);
        }
        else {
            /* Add stream to closed set for cleanup when task is done */
            h2_stream_set_add(m->closed, stream);
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

void h2_mplx_task_done(h2_mplx *m, int stream_id)
{
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_stream *stream = h2_stream_set_get(m->closed, stream_id);
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                      "h2_mplx(%ld): task(%d) done", m->id, stream_id);
        if (stream) {
            /* stream was already closed by main connection and is in 
             * zombie state. Now that the task is done with it, we
             * can free its resources. */
            h2_stream_set_remove(m->closed, stream);
            stream_destroy(m, stream, io);
        }
        else if (io) {
            /* main connection has not finished stream. Mark task as done
             * so that eventual cleanup can start immediately. */
            io->task_done = 1;
        }
        apr_thread_mutex_unlock(m->lock);
    }
}

apr_status_t h2_mplx_in_read(h2_mplx *m, apr_read_type_e block,
                             int stream_id, apr_bucket_brigade *bb,
                             struct apr_thread_cond_t *iowait)
{
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io) {
            io->input_arrived = iowait;
            status = h2_io_in_read(io, bb, 0);
            while (status == APR_EAGAIN 
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
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
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
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
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
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        update_ctx ctx = { cb, cb_ctx, 0 };
        status = APR_EAGAIN;
        h2_io_set_iter(m->stream_ios, update_window, &ctx);
        
        if (ctx.streams_updated) {
            status = APR_SUCCESS;
        }
        apr_thread_mutex_unlock(m->lock);
    }
    return status;
}

apr_status_t h2_mplx_out_readx(h2_mplx *m, int stream_id, 
                               h2_io_data_cb *cb, void *ctx, 
                               apr_size_t *plen, int *peos)
{
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io) {
            status = h2_io_out_readx(io, cb, ctx, plen, peos);
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
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return NULL;
    }
    h2_stream *stream = NULL;
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        h2_io *io = h2_io_set_get_highest_prio(m->ready_ios);
        if (io) {
            h2_response *response = io->response;
            h2_io_set_remove(m->ready_ios, io);
            
            stream = h2_stream_set_get(streams, response->stream_id);
            if (stream) {
                h2_stream_set_response(stream, response, io->bbout);
                if (io->output_drained) {
                    apr_thread_cond_signal(io->output_drained);
                }
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, APR_NOTFOUND, m->c,
                              "h2_mplx(%ld): stream for response %d",
                              m->id, response->stream_id);
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
                          "h2_mplx(%ld-%d): open response: %s",
                          m->id, stream_id, response->headers->status);
        }
        
        h2_response_copy(io->response, response);
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
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        status = out_open(m, stream_id, response, f, bb, iowait);
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
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        if (!m->aborted) {
            h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
            if (io) {
                status = out_write(m, io, f, bb, iowait);
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
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        if (!m->aborted) {
            h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
            if (io) {
                if (!io->response->headers) {
                    /* In case a close comes before a response was created,
                     * insert an error one so that our streams can properly
                     * reset.
                     */
                    h2_response *r = h2_response_create(stream_id, 
                                                        "500", NULL, m->pool);
                    status = out_open(m, stream_id, r, NULL, NULL, NULL);
                }
                status = h2_io_out_close(io);
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

int h2_mplx_in_has_eos_for(h2_mplx *m, int stream_id)
{
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return 0;
    }
    int has_eos = 0;
    apr_status_t status = apr_thread_mutex_lock(m->lock);
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
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return 0;
    }
    int has_data = 0;
    apr_status_t status = apr_thread_mutex_lock(m->lock);
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
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        m->added_output = iowait;
        status = apr_thread_cond_timedwait(m->added_output, m->lock, timeout);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                      "h2_mplx(%ld): trywait on data for %f ms)",
                      m->id, timeout/1000.0);
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

apr_status_t h2_mplx_do_task(h2_mplx *m, struct h2_task *task)
{
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        /* TODO: needs to sort queue by priority */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                      "h2_mplx: do task(%s)", task->id);
        h2_tq_append(m->q, task);
        apr_thread_mutex_unlock(m->lock);
    }
    workers_register(m);
    return status;
}

h2_task *h2_mplx_pop_task(h2_mplx *m, int *has_more)
{
    h2_task *task = NULL;
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        *has_more = 0;
        return NULL;
    }
    apr_status_t status = apr_thread_mutex_lock(m->lock);
    if (APR_SUCCESS == status) {
        task = h2_tq_pop_first(m->q);
        if (task) {
            h2_task_set_started(task);
        }
        *has_more = !h2_tq_empty(m->q);
        apr_thread_mutex_unlock(m->lock);
    }
    return task;
}

