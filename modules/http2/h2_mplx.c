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
#include <stdlib.h>

#include <apr_queue.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>
#include <apr_strings.h>
#include <apr_time.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "mod_http2.h"

#include "h2_private.h"
#include "h2_config.h"
#include "h2_conn.h"
#include "h2_ctx.h"
#include "h2_h2.h"
#include "h2_int_queue.h"
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
#include "h2_worker.h"
#include "h2_workers.h"
#include "h2_util.h"


#define H2_MPLX_IO_OUT(lvl,m,io,msg) \
    do { \
        if (APLOG_C_IS_LEVEL((m)->c,lvl)) \
        h2_util_bb_log((m)->c,(io)->id,lvl,msg,(io)->bbout); \
    } while(0)
    
#define H2_MPLX_IO_IN(lvl,m,io,msg) \
    do { \
        if (APLOG_C_IS_LEVEL((m)->c,lvl)) \
        h2_util_bb_log((m)->c,(io)->id,lvl,msg,(io)->bbin); \
    } while(0)


/* NULL or the mutex hold by this thread, used for recursive calls
 */
static apr_threadkey_t *thread_lock;

apr_status_t h2_mplx_child_init(apr_pool_t *pool, server_rec *s)
{
    return apr_threadkey_private_create(&thread_lock, NULL, pool);
}

static apr_status_t enter_mutex(h2_mplx *m, int *pacquired)
{
    apr_status_t status;
    void *mutex = NULL;
    
    /* Enter the mutex if this thread already holds the lock or
     * if we can acquire it. Only on the later case do we unlock
     * onleaving the mutex.
     * This allow recursive entering of the mutex from the saem thread,
     * which is what we need in certain situations involving callbacks
     */
    apr_threadkey_private_get(&mutex, thread_lock);
    if (mutex == m->lock) {
        *pacquired = 0;
        return APR_SUCCESS;
    }
        
    status = apr_thread_mutex_lock(m->lock);
    *pacquired = (status == APR_SUCCESS);
    if (*pacquired) {
        apr_threadkey_private_set(m->lock, thread_lock);
    }
    return status;
}

static void leave_mutex(h2_mplx *m, int acquired)
{
    if (acquired) {
        apr_threadkey_private_set(NULL, thread_lock);
        apr_thread_mutex_unlock(m->lock);
    }
}

static int is_aborted(h2_mplx *m, apr_status_t *pstatus)
{
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        *pstatus = APR_ECONNABORTED;
        return 1;
    }
    return 0;
}

static void have_out_data_for(h2_mplx *m, int stream_id);

static void check_tx_reservation(h2_mplx *m) 
{
    if (m->tx_handles_reserved == 0) {
        m->tx_handles_reserved += h2_workers_tx_reserve(m->workers, 
            H2MIN(m->tx_chunk_size, h2_io_set_size(m->stream_ios)));
    }
}

static void check_tx_free(h2_mplx *m) 
{
    if (m->tx_handles_reserved > m->tx_chunk_size) {
        apr_size_t count = m->tx_handles_reserved - m->tx_chunk_size;
        m->tx_handles_reserved = m->tx_chunk_size;
        h2_workers_tx_free(m->workers, count);
    }
    else if (m->tx_handles_reserved 
             && (!m->stream_ios || h2_io_set_is_empty(m->stream_ios))) {
        h2_workers_tx_free(m->workers, m->tx_handles_reserved);
        m->tx_handles_reserved = 0;
    }
}

static void h2_mplx_destroy(h2_mplx *m)
{
    AP_DEBUG_ASSERT(m);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                  "h2_mplx(%ld): destroy, ios=%d", 
                  m->id, (int)h2_io_set_size(m->stream_ios));
    m->aborted = 1;
    if (m->ready_ios) {
        h2_io_set_destroy(m->ready_ios);
        m->ready_ios = NULL;
    }
    if (m->stream_ios) {
        h2_io_set_destroy(m->stream_ios);
        m->stream_ios = NULL;
    }
    
    check_tx_free(m);
    
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
h2_mplx *h2_mplx_create(conn_rec *c, apr_pool_t *parent, 
                        const h2_config *conf, 
                        apr_interval_time_t stream_timeout,
                        h2_workers *workers)
{
    apr_status_t status = APR_SUCCESS;
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
        
        status = apr_thread_cond_create(&m->request_done, m->pool);
        if (status != APR_SUCCESS) {
            h2_mplx_destroy(m);
            return NULL;
        }

        m->q = h2_iq_create(m->pool, h2_config_geti(conf, H2_CONF_MAX_STREAMS));
        m->stream_ios = h2_io_set_create(m->pool);
        m->ready_ios = h2_io_set_create(m->pool);
        m->stream_max_mem = h2_config_geti(conf, H2_CONF_STREAM_MAX_MEM);
        m->stream_timeout = stream_timeout;
        m->workers = workers;
        
        m->tx_handles_reserved = 0;
        m->tx_chunk_size = 4;
    }
    return m;
}

int h2_mplx_get_max_stream_started(h2_mplx *m)
{
    int stream_id = 0;
    int acquired;
    
    enter_mutex(m, &acquired);
    stream_id = m->max_stream_started;
    leave_mutex(m, acquired);
    
    return stream_id;
}

static void workers_register(h2_mplx *m)
{
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

static int io_process_events(h2_mplx *m, h2_io *io)
{
    if (io->input_consumed && m->input_consumed) {
        m->input_consumed(m->input_consumed_ctx, 
                          io->id, io->input_consumed);
        io->input_consumed = 0;
        return 1;
    }
    return 0;
}

static void io_destroy(h2_mplx *m, h2_io *io, int events)
{
    apr_pool_t *pool = io->pool;
    
    /* cleanup any buffered input */
    h2_io_in_shutdown(io);
    if (events) {
        /* Process outstanding events before destruction */
        io_process_events(m, io);
    }
    
    io->pool = NULL;    
    /* The pool is cleared/destroyed which also closes all
     * allocated file handles. Give this count back to our
     * file handle pool. */
    m->tx_handles_reserved += io->files_handles_owned;

    h2_io_set_remove(m->stream_ios, io);
    h2_io_set_remove(m->ready_ios, io);
    h2_io_destroy(io);
    
    if (pool) {
        apr_pool_clear(pool);
        if (m->spare_pool) {
            apr_pool_destroy(m->spare_pool);
        }
        m->spare_pool = pool;
    }

    check_tx_free(m);
}

static int io_stream_done(h2_mplx *m, h2_io *io, int rst_error) 
{
    /* Remove io from ready set, we will never submit it */
    h2_io_set_remove(m->ready_ios, io);
    if (!io->processing_started || io->processing_done) {
        /* already finished or not even started yet */
        h2_iq_remove(m->q, io->id);
        io_destroy(m, io, 1);
        return 0;
    }
    else {
        /* cleanup once task is done */
        h2_io_make_orphaned(io, rst_error);
        return 1;
    }
}

static int stream_done_iter(void *ctx, h2_io *io)
{
    return io_stream_done((h2_mplx*)ctx, io, 0);
}

apr_status_t h2_mplx_release_and_join(h2_mplx *m, apr_thread_cond_t *wait)
{
    apr_status_t status;
    int acquired;

    h2_workers_unregister(m->workers, m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        int i, wait_secs = 5;
        
        /* disable WINDOW_UPDATE callbacks */
        h2_mplx_set_consumed_cb(m, NULL, NULL);
        
        apr_thread_cond_broadcast(m->request_done);
        while (!h2_io_set_iter(m->stream_ios, stream_done_iter, m)) {
            /* iterate until all ios have been orphaned or destroyed */
        }
    
        /* Any remaining ios have handed out requests to workers that are
         * not done yet. Any operation they do on their assigned stream ios will
         * be errored ECONNRESET/ABORTED, so that should find out pretty soon.
         */
        for (i = 0; h2_io_set_size(m->stream_ios) > 0; ++i) {
            m->join_wait = wait;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          "h2_mplx(%ld): release_join, waiting on %d worker to report back", 
                          m->id, (int)h2_io_set_size(m->stream_ios));
                          
            status = apr_thread_cond_timedwait(wait, m->lock, apr_time_from_sec(wait_secs));
            if (APR_STATUS_IS_TIMEUP(status)) {
                if (i > 0) {
                    /* Oh, oh. Still we wait for assigned  workers to report that 
                     * they are done. Unless we have a bug, a worker seems to be hanging. 
                     * If we exit now, all will be deallocated and the worker, once 
                     * it does return, will walk all over freed memory...
                     */
                    ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, APLOGNO(03198)
                                  "h2_mplx(%ld): release, waiting for %d seconds now for "
                                  "all h2_workers to return, have still %d requests outstanding", 
                                  m->id, i*wait_secs, (int)h2_io_set_size(m->stream_ios));
                }
                m->aborted = 1;
                apr_thread_cond_broadcast(m->request_done);
            }
        }
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c, APLOGNO(03056)
                      "h2_mplx(%ld): release_join -> destroy", m->id);
        leave_mutex(m, acquired);
        h2_mplx_destroy(m);
        /* all gone */
    }
    return status;
}

void h2_mplx_abort(h2_mplx *m)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if (!m->aborted) {
        if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
            m->aborted = 1;
            leave_mutex(m, acquired);
        }
    }
}

apr_status_t h2_mplx_stream_done(h2_mplx *m, int stream_id, int rst_error)
{
    apr_status_t status = APR_SUCCESS;
    int acquired;
    
    /* This maybe called from inside callbacks that already hold the lock.
     * E.g. when we are streaming out DATA and the EOF triggers the stream
     * release.
     */
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);

        /* there should be an h2_io, once the stream has been scheduled
         * for processing, e.g. when we received all HEADERs. But when
         * a stream is cancelled very early, it will not exist. */
        if (io) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c, 
                          "h2_mplx(%ld-%d): marking stream as done.", 
                          m->id, stream_id);
            io_stream_done(m, io, rst_error);
        }

        leave_mutex(m, acquired);
    }
    return status;
}

static const h2_request *pop_request(h2_mplx *m)
{
    const h2_request *req = NULL;
    int sid;
    while (!m->aborted && !req && (sid = h2_iq_shift(m->q)) > 0) {
        h2_io *io = h2_io_set_get(m->stream_ios, sid);
        if (io) {
            req = io->request;
            io->processing_started = 1;
            if (sid > m->max_stream_started) {
                m->max_stream_started = sid;
            }
        }
    }
    return req;
}

void h2_mplx_request_done(h2_mplx *m, int stream_id, const h2_request **preq)
{
    int acquired;
    
    if (enter_mutex(m, &acquired) == APR_SUCCESS) {
        if (stream_id) {
            h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                          "h2_mplx(%ld): request(%d) done", m->id, stream_id);
            if (io) {
                io->processing_done = 1;
                h2_mplx_out_close(m, stream_id, NULL);
                if (io->orphaned) {
                    io_destroy(m, io, 0);
                    if (m->join_wait) {
                        apr_thread_cond_signal(m->join_wait);
                    }
                }
                else {
                    /* hang around until the stream deregisteres */
                }
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c,
                              "h2_mplx(%ld): request(%d) done, no io found", 
                              m->id, stream_id);
            }
            apr_thread_cond_broadcast(m->request_done);
        }
        
        if (preq) {
            /* someone wants another request, if we have */
            *preq = pop_request(m);
        }
        leave_mutex(m, acquired);
    }
}

apr_status_t h2_mplx_in_read(h2_mplx *m, apr_read_type_e block,
                             int stream_id, apr_bucket_brigade *bb, 
                             apr_table_t *trailers,
                             struct apr_thread_cond_t *iowait)
{
    apr_status_t status; 
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            H2_MPLX_IO_IN(APLOG_TRACE2, m, io, "h2_mplx_in_read_pre");
            
            h2_io_signal_init(io, H2_IO_READ, m->stream_timeout, iowait);
            status = h2_io_in_read(io, bb, -1, trailers);
            while (APR_STATUS_IS_EAGAIN(status) 
                   && !is_aborted(m, &status)
                   && block == APR_BLOCK_READ) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, m->c,
                              "h2_mplx(%ld-%d): wait on in data (BLOCK_READ)", 
                              m->id, stream_id);
                status = h2_io_signal_wait(m, io);
                if (status == APR_SUCCESS) {
                    status = h2_io_in_read(io, bb, -1, trailers);
                }
            }
            H2_MPLX_IO_IN(APLOG_TRACE2, m, io, "h2_mplx_in_read_post");
            h2_io_signal_exit(io);
        }
        else {
            status = APR_EOF;
        }
        leave_mutex(m, acquired);
    }
    return status;
}

apr_status_t h2_mplx_in_write(h2_mplx *m, int stream_id, 
                              apr_bucket_brigade *bb)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            H2_MPLX_IO_IN(APLOG_TRACE2, m, io, "h2_mplx_in_write_pre");
            status = h2_io_in_write(io, bb);
            H2_MPLX_IO_IN(APLOG_TRACE2, m, io, "h2_mplx_in_write_post");
            h2_io_signal(io, H2_IO_READ);
            io_process_events(m, io);
        }
        else {
            status = APR_ECONNABORTED;
        }
        leave_mutex(m, acquired);
    }
    return status;
}

apr_status_t h2_mplx_in_close(h2_mplx *m, int stream_id)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            status = h2_io_in_close(io);
            H2_MPLX_IO_IN(APLOG_TRACE2, m, io, "h2_mplx_in_close");
            h2_io_signal(io, H2_IO_READ);
            io_process_events(m, io);
        }
        else {
            status = APR_ECONNABORTED;
        }
        leave_mutex(m, acquired);
    }
    return status;
}

typedef struct {
    h2_mplx * m;
    int streams_updated;
} update_ctx;

static int update_window(void *ctx, h2_io *io)
{
    update_ctx *uctx = (update_ctx*)ctx;
    if (io_process_events(uctx->m, io)) {
        ++uctx->streams_updated;
    }
    return 1;
}

void h2_mplx_set_consumed_cb(h2_mplx *m, h2_mplx_consumed_cb *cb, void *ctx)
{
    m->input_consumed = cb;
    m->input_consumed_ctx = ctx;
}

apr_status_t h2_mplx_in_update_windows(h2_mplx *m)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if (m->aborted) {
        return APR_ECONNABORTED;
    }
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        update_ctx ctx;
        
        ctx.m               = m;
        ctx.streams_updated = 0;

        status = APR_EAGAIN;
        h2_io_set_iter(m->stream_ios, update_window, &ctx);
        
        if (ctx.streams_updated) {
            status = APR_SUCCESS;
        }
        leave_mutex(m, acquired);
    }
    return status;
}

apr_status_t h2_mplx_out_readx(h2_mplx *m, int stream_id, 
                               h2_io_data_cb *cb, void *ctx, 
                               apr_off_t *plen, int *peos,
                               apr_table_t **ptrailers)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_readx_pre");
            
            status = h2_io_out_readx(io, cb, ctx, plen, peos);
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_readx_post");
            if (status == APR_SUCCESS && cb) {
                h2_io_signal(io, H2_IO_WRITE);
            }
        }
        else {
            status = APR_ECONNABORTED;
        }
        
        *ptrailers = (*peos && io->response)? io->response->trailers : NULL;
        leave_mutex(m, acquired);
    }
    return status;
}

apr_status_t h2_mplx_out_read_to(h2_mplx *m, int stream_id, 
                                 apr_bucket_brigade *bb, 
                                 apr_off_t *plen, int *peos,
                                 apr_table_t **ptrailers)
{
    apr_status_t status;
    int acquired;

    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_read_to_pre");
            
            status = h2_io_out_read_to(io, bb, plen, peos);
            
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_read_to_post");
            if (status == APR_SUCCESS) {
                h2_io_signal(io, H2_IO_WRITE);
            }
        }
        else {
            status = APR_ECONNABORTED;
        }
        *ptrailers = (*peos && io->response)? io->response->trailers : NULL;
        leave_mutex(m, acquired);
    }
    return status;
}

h2_stream *h2_mplx_next_submit(h2_mplx *m, h2_stream_set *streams)
{
    apr_status_t status;
    h2_stream *stream = NULL;
    int acquired;

    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_pop_highest_prio(m->ready_ios);
        if (io && !m->aborted) {
            stream = h2_stream_set_get(streams, io->id);
            if (stream) {
                if (io->rst_error) {
                    h2_stream_rst(stream, io->rst_error);
                }
                else {
                    AP_DEBUG_ASSERT(io->response);
                    H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_next_submit_pre");
                    h2_stream_set_response(stream, io->response, io->bbout);
                    H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_next_submit_post");
                }
            }
            else {
                /* We have the io ready, but the stream has gone away, maybe
                 * reset by the client. Should no longer happen since such
                 * streams should clear io's from the ready queue.
                 */
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,  
                              "h2_mplx(%ld): stream for response %d closed, "
                              "resetting io to close request processing",
                              m->id, io->id);
                h2_io_make_orphaned(io, H2_ERR_STREAM_CLOSED);
                if (!io->processing_started || io->processing_done) {
                    io_destroy(m, io, 1);
                }
                else {
                    /* hang around until the h2_task is done, but
                     * shutdown input and send out any events (e.g. window
                     * updates) asap. */
                    h2_io_in_shutdown(io);
                    io_process_events(m, io);
                }
            }
            
            h2_io_signal(io, H2_IO_WRITE);
        }
        leave_mutex(m, acquired);
    }
    return stream;
}

static apr_status_t out_write(h2_mplx *m, h2_io *io, 
                              ap_filter_t* f, apr_bucket_brigade *bb,
                              apr_table_t *trailers,
                              struct apr_thread_cond_t *iowait)
{
    apr_status_t status = APR_SUCCESS;
    /* We check the memory footprint queued for this stream_id
     * and block if it exceeds our configured limit.
     * We will not split buckets to enforce the limit to the last
     * byte. After all, the bucket is already in memory.
     */
    while (status == APR_SUCCESS 
           && !APR_BRIGADE_EMPTY(bb) 
           && !is_aborted(m, &status)) {
        
        status = h2_io_out_write(io, bb, m->stream_max_mem, trailers,
                                 &m->tx_handles_reserved);
        /* Wait for data to drain until there is room again or
         * stream timeout expires */
        h2_io_signal_init(io, H2_IO_WRITE, m->stream_timeout, iowait);
        while (status == APR_SUCCESS
               && !APR_BRIGADE_EMPTY(bb) 
               && iowait
               && (m->stream_max_mem <= h2_io_out_length(io))
               && !is_aborted(m, &status)) {
            trailers = NULL;
            if (f) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, f->c,
                              "h2_mplx(%ld-%d): waiting for out drain", 
                              m->id, io->id);
            }
            status = h2_io_signal_wait(m, io);
        }
        h2_io_signal_exit(io);
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
    if (io && !io->orphaned) {
        if (f) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                          "h2_mplx(%ld-%d): open response: %d, rst=%d",
                          m->id, stream_id, response->http_status, 
                          response->rst_error);
        }
        
        h2_io_set_response(io, response);
        h2_io_set_add(m->ready_ios, io);
        if (response && response->http_status < 300) {
            /* we might see some file buckets in the output, see
             * if we have enough handles reserved. */
            check_tx_reservation(m);
        }
        if (bb) {
            status = out_write(m, io, f, bb, response->trailers, iowait);
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
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        if (m->aborted) {
            status = APR_ECONNABORTED;
        }
        else {
            status = out_open(m, stream_id, response, f, bb, iowait);
            if (APLOGctrace1(m->c)) {
                h2_util_bb_log(m->c, stream_id, APLOG_TRACE1, "h2_mplx_out_open", bb);
            }
        }
        leave_mutex(m, acquired);
    }
    return status;
}

apr_status_t h2_mplx_out_write(h2_mplx *m, int stream_id, 
                               ap_filter_t* f, apr_bucket_brigade *bb,
                               apr_table_t *trailers,
                               struct apr_thread_cond_t *iowait)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            status = out_write(m, io, f, bb, trailers, iowait);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, m->c,
                          "h2_mplx(%ld-%d): write with trailers=%s", 
                          m->id, io->id, trailers? "yes" : "no");
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_write");
            
            have_out_data_for(m, stream_id);
        }
        else {
            status = APR_ECONNABORTED;
        }
        leave_mutex(m, acquired);
    }
    return status;
}

apr_status_t h2_mplx_out_close(h2_mplx *m, int stream_id, apr_table_t *trailers)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            if (!io->response && !io->rst_error) {
                /* In case a close comes before a response was created,
                 * insert an error one so that our streams can properly
                 * reset.
                 */
                h2_response *r = h2_response_die(stream_id, APR_EGENERAL, 
                                                 io->request, m->pool);
                status = out_open(m, stream_id, r, NULL, NULL, NULL);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, m->c,
                              "h2_mplx(%ld-%d): close, no response, no rst", 
                              m->id, io->id);
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, m->c,
                          "h2_mplx(%ld-%d): close with trailers=%s", 
                          m->id, io->id, trailers? "yes" : "no");
            status = h2_io_out_close(io, trailers);
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_close");
            
            have_out_data_for(m, stream_id);
        }
        else {
            status = APR_ECONNABORTED;
        }
        leave_mutex(m, acquired);
    }
    return status;
}

apr_status_t h2_mplx_out_rst(h2_mplx *m, int stream_id, int error)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->rst_error && !io->orphaned) {
            h2_io_rst(io, error);
            if (!io->response) {
                h2_io_set_add(m->ready_ios, io);
            }
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_rst");
            
            have_out_data_for(m, stream_id);
            h2_io_signal(io, H2_IO_WRITE);
        }
        else {
            status = APR_ECONNABORTED;
        }
        leave_mutex(m, acquired);
    }
    return status;
}

int h2_mplx_in_has_eos_for(h2_mplx *m, int stream_id)
{
    int has_eos = 0;
    int acquired;
    
    apr_status_t status;
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            has_eos = h2_io_in_has_eos_for(io);
        }
        else {
            has_eos = 1;
        }
        leave_mutex(m, acquired);
    }
    return has_eos;
}

int h2_mplx_in_has_data_for(h2_mplx *m, int stream_id)
{
    apr_status_t status;
    int has_data = 0;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            has_data = h2_io_in_has_data(io);
        }
        else {
            has_data = 0;
        }
        leave_mutex(m, acquired);
    }
    return has_data;
}

int h2_mplx_out_has_data_for(h2_mplx *m, int stream_id)
{
    apr_status_t status;
    int has_data = 0;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            has_data = h2_io_out_has_data(io);
        }
        else {
            has_data = 0;
        }
        leave_mutex(m, acquired);
    }
    return has_data;
}

apr_status_t h2_mplx_out_trywait(h2_mplx *m, apr_interval_time_t timeout,
                                 apr_thread_cond_t *iowait)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        if (m->aborted) {
            status = APR_ECONNABORTED;
        }
        else {
            m->added_output = iowait;
            status = apr_thread_cond_timedwait(m->added_output, m->lock, timeout);
            if (APLOGctrace2(m->c)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                              "h2_mplx(%ld): trywait on data for %f ms)",
                              m->id, timeout/1000.0);
            }
            m->added_output = NULL;
        }
        leave_mutex(m, acquired);
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

apr_status_t h2_mplx_reprioritize(h2_mplx *m, h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        if (m->aborted) {
            status = APR_ECONNABORTED;
        }
        else {
            h2_iq_sort(m->q, cmp, ctx);
            
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          "h2_mplx(%ld): reprioritize tasks", m->id);
        }
        leave_mutex(m, acquired);
    }
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
    
    io = h2_io_create(stream_id, io_pool);
    h2_io_set_add(m->stream_ios, io);
    
    return io;
}


apr_status_t h2_mplx_process(h2_mplx *m, int stream_id, const h2_request *req, 
                             h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status;
    int was_empty = 0;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        if (m->aborted) {
            status = APR_ECONNABORTED;
        }
        else {
            h2_io *io = open_io(m, stream_id);
            io->request = req;
            
            if (!io->request->body) {
                status = h2_io_in_close(io);
            }
            
            was_empty = h2_iq_empty(m->q);
            h2_iq_add(m->q, io->id, cmp, ctx);
            
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, m->c,
                          "h2_mplx(%ld-%d): process", m->c->id, stream_id);
            H2_MPLX_IO_IN(APLOG_TRACE2, m, io, "h2_mplx_process");
        }
        leave_mutex(m, acquired);
    }
    if (status == APR_SUCCESS && was_empty) {
        workers_register(m);
    }
    return status;
}

const h2_request *h2_mplx_pop_request(h2_mplx *m, int *has_more)
{
    const h2_request *req = NULL;
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        if (m->aborted) {
            req = NULL;
            *has_more = 0;
        }
        else {
            req = pop_request(m);
            *has_more = !h2_iq_empty(m->q);
        }
        leave_mutex(m, acquired);
    }
    return req;
}


/*******************************************************************************
 * HTTP/2 request engines
 ******************************************************************************/
 
typedef struct h2_req_engine_i h2_req_engine_i;
struct h2_req_engine_i {
    h2_req_engine pub;
    conn_rec *c;               /* connection this engine is assigned to */
    h2_mplx *m;
    unsigned int shutdown : 1; /* engine is being shut down */
    apr_thread_cond_t *io;     /* condition var for waiting on data */
    apr_queue_t *queue;        /* queue of scheduled request_rec* */
    apr_size_t no_assigned;    /* # of assigned requests */
    apr_size_t no_live;        /* # of live */
    apr_size_t no_finished;    /* # of finished */
};

static apr_status_t h2_mplx_engine_schedule(h2_mplx *m, 
                                            h2_req_engine_i *engine, 
                                            request_rec *r)
{
    if (!engine->queue) {
        apr_queue_create(&engine->queue, 100, engine->pub.pool);
    }
    return apr_queue_trypush(engine->queue, r);
}


apr_status_t h2_mplx_engine_push(const char *engine_type, 
                                 request_rec *r, h2_mplx_engine_init *einit)
{
    apr_status_t status;
    h2_mplx *m;
    h2_task *task;
    int acquired;
    
    task = h2_ctx_rget_task(r);
    if (!task) {
        return APR_ECONNABORTED;
    }
    m = task->mplx;
    AP_DEBUG_ASSERT(m);
    
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, task->stream_id);
        if (!io || io->orphaned) {
            status = APR_ECONNABORTED;
        }
        else {
            h2_req_engine_i *engine = (h2_req_engine_i*)m->engine;
            
            apr_table_set(r->connection->notes, H2_TASK_ID_NOTE, task->id);
            status = APR_EOF;
            
            if (task->ser_headers) {
                /* Max compatibility, deny processing of this */
            }
            else if (engine && !strcmp(engine->pub.type, engine_type)) {
                if (engine->shutdown 
                    || engine->no_assigned >= H2MIN(engine->pub.capacity, 100)) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, status, r,
                                  "h2_mplx(%ld): engine shutdown or over %s", 
                                  m->c->id, engine->pub.id);
                    engine = NULL;
                }
                else if (h2_mplx_engine_schedule(m, engine, r) == APR_SUCCESS) {
                    /* this task will be processed in another thread,
                     * freeze any I/O for the time being. */
                    h2_task_freeze(task, r);
                    engine->no_assigned++;
                    status = APR_SUCCESS;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                                  "h2_mplx(%ld): push request %s", 
                                  m->c->id, r->the_request);
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, status, r,
                                  "h2_mplx(%ld): engine error adding req %s", 
                                  m->c->id, engine->pub.id);
                    engine = NULL;
                }
            }
            
            if (!engine && einit) {
                engine = apr_pcalloc(task->pool, sizeof(*engine));
                engine->pub.id = apr_psprintf(task->pool, "eng-%ld-%d", 
                                               m->id, m->next_eng_id++);
                engine->pub.pool = task->pool;
                engine->pub.type = apr_pstrdup(task->pool, engine_type);
                engine->c = r->connection;
                engine->m = m;
                engine->io = task->io;
                engine->no_assigned = 1;
                engine->no_live = 1;
                
                status = einit(&engine->pub, r);
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, status, r,
                              "h2_mplx(%ld): init engine %s (%s)", 
                              m->c->id, engine->pub.id, engine->pub.type);
                if (status == APR_SUCCESS) {
                    m->engine = &engine->pub;
                }
            }
        }
        
        leave_mutex(m, acquired);
    }
    return status;
}

static request_rec *get_non_frozen(apr_queue_t *equeue)
{
    request_rec *r, *first = NULL;
    h2_task *task;
    void *elem;

    if (equeue) {
        /* FIFO queue, try to find a  request_rec whose task is not frozen */
        while (apr_queue_trypop(equeue, &elem) == APR_SUCCESS) {
            r = elem;
            task = h2_ctx_rget_task(r);
            AP_DEBUG_ASSERT(task);
            if (!task->frozen) {
                return r;
            }
            apr_queue_push(equeue, r);  
            if (!first) {
                first = r;
            }
            else if (r == first) {
                return NULL; /* walked the whole queue */
            }
        }
    }
    return NULL;
}

static apr_status_t engine_pull(h2_mplx *m, h2_req_engine_i *engine, 
                                apr_read_type_e block, request_rec **pr)
{   
    request_rec *r;
    
    AP_DEBUG_ASSERT(m);
    AP_DEBUG_ASSERT(engine);
    while (1) {
        if (m->aborted) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                          "h2_mplx(%ld): mplx abort while pulling requests %s", 
                          m->id, engine->pub.id);
            *pr = NULL;
            return APR_EOF;
        }
        
        if (engine->queue && (r = get_non_frozen(engine->queue))) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "h2_mplx(%ld): request %s pulled by engine %s", 
                          m->c->id, r->the_request, engine->pub.id);
            engine->no_live++;
            *pr = r;
            return APR_SUCCESS;
        }
        else if (APR_NONBLOCK_READ == block) {
            *pr = NULL;
            return APR_EAGAIN;
        }
        else if (!engine->queue || !apr_queue_size(engine->queue)) {
            engine->shutdown = 1;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          "h2_mplx(%ld): emtpy queue, shutdown engine %s", 
                          m->id, engine->pub.id);
            *pr = NULL;
            return APR_EOF;
        }
        apr_thread_cond_timedwait(m->request_done, m->lock, 
                                  apr_time_from_msec(100));
    }
}
                                 
apr_status_t h2_mplx_engine_pull(h2_req_engine *pub_engine, 
                                 apr_read_type_e block, request_rec **pr)
{   
    h2_req_engine_i *engine = (h2_req_engine_i*)pub_engine;
    h2_mplx *m = engine->m;
    apr_status_t status;
    int acquired;
    
    *pr = NULL;
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        status = engine_pull(m, engine, block, pr);
        leave_mutex(m, acquired);
    }
    return status;
}
 
static void engine_done(h2_mplx *m, h2_req_engine_i *engine, h2_task *task, 
                        int waslive, int aborted)
{
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c,
                  "h2_mplx(%ld): task %s %s by %s", 
                  m->id, task->id, aborted? "aborted":"done", 
                  engine->pub.id);
    h2_task_output_close(task->output);
    h2_mplx_request_done(m, task->stream_id, NULL);
    apr_pool_destroy(task->pool);
    engine->no_finished++;
    if (waslive) engine->no_live--;
    engine->no_assigned--;
}
                                
void h2_mplx_engine_done(h2_req_engine *pub_engine, conn_rec *r_conn)
{
    h2_req_engine_i *engine = (h2_req_engine_i*)pub_engine;
    h2_mplx *m = engine->m;
    h2_task *task;
    int acquired;

    task = h2_ctx_cget_task(r_conn);
    if (task && (enter_mutex(m, &acquired) == APR_SUCCESS)) {
        engine_done(m, engine, task, 1, 0);
        leave_mutex(m, acquired);
    }
}
                                
void h2_mplx_engine_exit(h2_req_engine *pub_engine)
{
    h2_req_engine_i *engine = (h2_req_engine_i*)pub_engine;
    h2_mplx *m = engine->m;
    int acquired;
    
    if (enter_mutex(m, &acquired) == APR_SUCCESS) {
        if (engine->queue && apr_queue_size(engine->queue)) {
            void *entry;
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c,
                          "h2_mplx(%ld): exit engine %s (%s), "
                          "has still %d requests queued, "
                          "assigned=%ld, live=%ld, finished=%ld", 
                          m->c->id, engine->pub.id, engine->pub.type,
                          (int)apr_queue_size(engine->queue),
                          (long)engine->no_assigned, (long)engine->no_live,
                          (long)engine->no_finished);
            while (apr_queue_trypop(engine->queue, &entry) == APR_SUCCESS) {
                request_rec *r = entry;
                h2_task *task = h2_ctx_rget_task(r);
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c,
                              "h2_mplx(%ld): engine %s has queued task %s, "
                              "frozen=%d, aborting",
                              m->c->id, engine->pub.id, task->id, task->frozen);
                engine_done(m, engine, task, 0, 1);
            }
        }
        if (engine->no_assigned > 1 || engine->no_live > 1) {
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c,
                          "h2_mplx(%ld): exit engine %s (%s), "
                          "assigned=%ld, live=%ld, finished=%ld", 
                          m->c->id, engine->pub.id, engine->pub.type,
                          (long)engine->no_assigned, (long)engine->no_live,
                          (long)engine->no_finished);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          "h2_mplx(%ld): exit engine %s (%s)", 
                          m->c->id, engine->pub.id, engine->pub.type);
        }
        if (m->engine == &engine->pub) {
            m->engine = NULL; /* TODO */
        }
        leave_mutex(m, acquired);
    }
}
