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
#include "h2_ngn_shed.h"
#include "h2_request.h"
#include "h2_stream.h"
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
        apr_pool_tag(m->pool, "h2_mplx");
        apr_allocator_owner_set(allocator, m->pool);
        
        status = apr_thread_mutex_create(&m->lock, APR_THREAD_MUTEX_DEFAULT,
                                         m->pool);
        if (status != APR_SUCCESS) {
            h2_mplx_destroy(m);
            return NULL;
        }
        
        status = apr_thread_cond_create(&m->task_thawed, m->pool);
        if (status != APR_SUCCESS) {
            h2_mplx_destroy(m);
            return NULL;
        }
    
        m->bucket_alloc = apr_bucket_alloc_create(m->pool);
        m->max_streams = h2_config_geti(conf, H2_CONF_MAX_STREAMS);
        m->stream_max_mem = h2_config_geti(conf, H2_CONF_STREAM_MAX_MEM);
        m->q = h2_iq_create(m->pool, m->max_streams);
        m->stream_ios = h2_io_set_create(m->pool);
        m->ready_ios = h2_io_set_create(m->pool);
        m->stream_timeout = stream_timeout;
        m->workers = workers;
        m->workers_max = workers->max_workers;
        m->workers_def_limit = 4;
        m->workers_limit = m->workers_def_limit;
        m->last_limit_change = m->last_idle_block = apr_time_now();
        m->limit_change_interval = apr_time_from_msec(200);
        
        m->tx_handles_reserved = 0;
        m->tx_chunk_size = 4;
        
        m->spare_slaves = apr_array_make(m->pool, 10, sizeof(conn_rec*));
        
        m->ngn_shed = h2_ngn_shed_create(m->pool, m->c, m->max_streams, 
                                         m->stream_max_mem);
        h2_ngn_shed_set_ctx(m->ngn_shed , m);
    }
    return m;
}

apr_uint32_t h2_mplx_shutdown(h2_mplx *m)
{
    int acquired, max_stream_started = 0;
    
    if (enter_mutex(m, &acquired) == APR_SUCCESS) {
        max_stream_started = m->max_stream_started;
        /* Clear schedule queue, disabling existing streams from starting */ 
        h2_iq_clear(m->q);
        leave_mutex(m, acquired);
    }
    return max_stream_started;
}

static void workers_register(h2_mplx *m)
{
    /* h2_workers is only a hub for all the h2_worker instances.
     * At the end-of-life of this h2_mplx, we always unregister at
     * the workers. The thing to manage are all the h2_worker instances
     * out there. Those may hold a reference to this h2_mplx and we cannot
     * call them to unregister.
     * 
     * Therefore: ref counting for h2_workers in not needed, ref counting
     * for h2_worker using this is critical.
     */
    m->need_registration = 0;
    h2_workers_register(m->workers, m);
}

static int io_in_consumed_signal(h2_mplx *m, h2_io *io)
{
    if (io->input_consumed && m->input_consumed) {
        m->input_consumed(m->input_consumed_ctx, 
                          io->id, io->input_consumed);
        io->input_consumed = 0;
        return 1;
    }
    return 0;
}

static int io_out_consumed_signal(h2_mplx *m, h2_io *io)
{
    if (io->output_consumed && io->task && io->task->assigned) {
        h2_req_engine_out_consumed(io->task->assigned, io->task->c, 
                                   io->output_consumed);
        io->output_consumed = 0;
        return 1;
    }
    return 0;
}

static void io_destroy(h2_mplx *m, h2_io *io, int events)
{
    int reuse_slave;
    
    /* cleanup any buffered input */
    h2_io_in_shutdown(io);
    if (events) {
        /* Process outstanding events before destruction */
        io_in_consumed_signal(m, io);
    }
    
    /* The pool is cleared/destroyed which also closes all
     * allocated file handles. Give this count back to our
     * file handle pool. */
    m->tx_handles_reserved += io->files_handles_owned;

    h2_io_set_remove(m->stream_ios, io);
    h2_io_set_remove(m->ready_ios, io);
    if (m->redo_ios) {
        h2_io_set_remove(m->redo_ios, io);
    }

    reuse_slave = ((m->spare_slaves->nelts < m->spare_slaves->nalloc)
                    && !io->rst_error && io->eor);
    if (io->task) {
        conn_rec *slave = io->task->c;
        h2_task_destroy(io->task);
        io->task = NULL;
        
        if (reuse_slave && slave->keepalive == AP_CONN_KEEPALIVE) {
            apr_bucket_delete(io->eor);
            io->eor = NULL;
            APR_ARRAY_PUSH(m->spare_slaves, conn_rec*) = slave;
        }
        else {
            slave->sbh = NULL;
            h2_slave_destroy(slave, NULL);
        }
    }

    if (io->pool) {
        apr_pool_destroy(io->pool);
    }

    check_tx_free(m);
}

static int io_stream_done(h2_mplx *m, h2_io *io, int rst_error) 
{
    /* Remove io from ready set, we will never submit it */
    h2_io_set_remove(m->ready_ios, io);
    if (!io->worker_started || io->worker_done) {
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

static int stream_print(void *ctx, h2_io *io)
{
    h2_mplx *m = ctx;
    if (io && io->request) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, /* NO APLOGNO */
                      "->03198: h2_stream(%ld-%d): %s %s %s -> %s %d"
                      "[orph=%d/started=%d/done=%d/eos_in=%d/eos_out=%d]", 
                      m->id, io->id, 
                      io->request->method, io->request->authority, io->request->path,
                      io->response? "http" : (io->rst_error? "reset" : "?"),
                      io->response? io->response->http_status : io->rst_error,
                      io->orphaned, io->worker_started, io->worker_done,
                      io->eos_in, io->eos_out);
    }
    else if (io) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, /* NO APLOGNO */
                      "->03198: h2_stream(%ld-%d): NULL -> %s %d"
                      "[orph=%d/started=%d/done=%d/eos_in=%d/eos_out=%d]", 
                      m->id, io->id, 
                      io->response? "http" : (io->rst_error? "reset" : "?"),
                      io->response? io->response->http_status : io->rst_error,
                      io->orphaned, io->worker_started, io->worker_done,
                      io->eos_in, io->eos_out);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, /* NO APLOGNO */
                      "->03198: h2_stream(%ld-NULL): NULL", m->id);
    }
    return 1;
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
        
        h2_iq_clear(m->q);
        apr_thread_cond_broadcast(m->task_thawed);
        while (!h2_io_set_iter(m->stream_ios, stream_done_iter, m)) {
            /* iterate until all ios have been orphaned or destroyed */
        }
    
        /* If we still have busy workers, we cannot release our memory
         * pool yet, as slave connections have child pools of their respective
         * h2_io's.
         * Any remaining ios are processed in these workers. Any operation 
         * they do on their input/outputs will be errored ECONNRESET/ABORTED, 
         * so processing them should fail and workers *should* return.
         */
        for (i = 0; m->workers_busy > 0; ++i) {
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
                                  "%d h2_workers to return, have still %d requests outstanding", 
                                  m->id, i*wait_secs, m->workers_busy,
                                  (int)h2_io_set_size(m->stream_ios));
                    if (i == 1) {
                        h2_io_set_iter(m->stream_ios, stream_print, m);
                    }
                }
                h2_mplx_abort(m);
                apr_thread_cond_broadcast(m->task_thawed);
            }
        }
        
        if (!h2_io_set_is_empty(m->stream_ios)) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, m->c, 
                          "h2_mplx(%ld): release_join, %d streams still open", 
                          m->id, (int)h2_io_set_size(m->stream_ios));
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
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if (!m->aborted && enter_mutex(m, &acquired) == APR_SUCCESS) {
        m->aborted = 1;
        h2_ngn_shed_abort(m->ngn_shed);
        leave_mutex(m, acquired);
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
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c, 
                          "h2_mplx(%ld-%d): marking stream as done.", 
                          m->id, stream_id);
            io_stream_done(m, io, rst_error);
        }
        leave_mutex(m, acquired);
    }
    return status;
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
                              const char *data, apr_size_t len, int eos)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            H2_MPLX_IO_IN(APLOG_TRACE2, m, io, "h2_mplx_in_write_pre");
            status = h2_io_in_write(io, data, len, eos);
            H2_MPLX_IO_IN(APLOG_TRACE2, m, io, "h2_mplx_in_write_post");
            h2_io_signal(io, H2_IO_READ);
            io_in_consumed_signal(m, io);
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
            io_in_consumed_signal(m, io);
        }
        else {
            status = APR_ECONNABORTED;
        }
        leave_mutex(m, acquired);
    }
    return status;
}

void h2_mplx_set_consumed_cb(h2_mplx *m, h2_mplx_consumed_cb *cb, void *ctx)
{
    m->input_consumed = cb;
    m->input_consumed_ctx = ctx;
}

typedef struct {
    h2_mplx * m;
    int streams_updated;
} update_ctx;

static int update_window(void *ctx, h2_io *io)
{
    update_ctx *uctx = (update_ctx*)ctx;
    if (io_in_consumed_signal(uctx->m, io)) {
        ++uctx->streams_updated;
    }
    return 1;
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

apr_status_t h2_mplx_out_get_brigade(h2_mplx *m, int stream_id, 
                                     apr_bucket_brigade *bb, 
                                     apr_off_t len, apr_table_t **ptrailers)
{
    apr_status_t status;
    int acquired;

    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_get_brigade_pre");
            
            status = h2_io_out_get_brigade(io, bb, len);
            
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_get_brigade_post");
            if (status == APR_SUCCESS) {
                h2_io_signal(io, H2_IO_WRITE);
            }
        }
        else {
            status = APR_ECONNABORTED;
        }
        *ptrailers = io->response? io->response->trailers : NULL;
        leave_mutex(m, acquired);
    }
    return status;
}

h2_stream *h2_mplx_next_submit(h2_mplx *m, h2_ihash_t *streams)
{
    apr_status_t status;
    h2_stream *stream = NULL;
    int acquired;

    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_shift(m->ready_ios);
        if (io && !m->aborted) {
            stream = h2_ihash_get(streams, io->id);
            if (stream) {
                io->submitted = 1;
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
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, APLOGNO(03347)
                              "h2_mplx(%ld): stream for response %d closed, "
                              "resetting io to close request processing",
                              m->id, io->id);
                h2_io_make_orphaned(io, H2_ERR_STREAM_CLOSED);
                if (!io->worker_started || io->worker_done) {
                    io_destroy(m, io, 1);
                }
                else {
                    /* hang around until the h2_task is done, but
                     * shutdown input and send out any events (e.g. window
                     * updates) asap. */
                    h2_io_in_shutdown(io);
                    io_in_consumed_signal(m, io);
                }
            }
            
            h2_io_signal(io, H2_IO_WRITE);
        }
        leave_mutex(m, acquired);
    }
    return stream;
}

static apr_status_t out_write(h2_mplx *m, h2_io *io, 
                              ap_filter_t* f, int blocking,
                              apr_bucket_brigade *bb,
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
        
        status = h2_io_out_write(io, bb, blocking? m->stream_max_mem : INT_MAX, 
                                 &m->tx_handles_reserved);
        io_out_consumed_signal(m, io);
        
        /* Wait for data to drain until there is room again or
         * stream timeout expires */
        h2_io_signal_init(io, H2_IO_WRITE, m->stream_timeout, iowait);
        while (status == APR_SUCCESS
               && !APR_BRIGADE_EMPTY(bb) 
               && iowait
               && (m->stream_max_mem <= h2_io_out_length(io))
               && !is_aborted(m, &status)) {
            if (!blocking) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, f->c,
                              "h2_mplx(%ld-%d): incomplete write", 
                              m->id, io->id);
                return APR_INCOMPLETE;
            }
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
            status = out_write(m, io, f, 0, bb, iowait);
            if (status == APR_INCOMPLETE) {
                /* write will have transferred as much data as possible.
                   caller has to deal with non-empty brigade */
                status = APR_SUCCESS;
            }
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
                               ap_filter_t* f, int blocking,
                               apr_bucket_brigade *bb,
                               struct apr_thread_cond_t *iowait)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, stream_id);
        if (io && !io->orphaned) {
            status = out_write(m, io, f, blocking, bb, iowait);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, m->c,
                          "h2_mplx(%ld-%d): write", m->id, io->id);
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

apr_status_t h2_mplx_out_close(h2_mplx *m, int stream_id)
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
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, m->c,
                              "h2_mplx(%ld-%d): close, no response, no rst", 
                              m->id, io->id);
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, m->c,
                          "h2_mplx(%ld-%d): close with eor=%s", 
                          m->id, io->id, io->eor? "yes" : "no");
            status = h2_io_out_close(io);
            H2_MPLX_IO_OUT(APLOG_TRACE2, m, io, "h2_mplx_out_close");
            io_out_consumed_signal(m, io);
            
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

static h2_io *open_io(h2_mplx *m, int stream_id, const h2_request *request)
{
    apr_pool_t *io_pool;
    h2_io *io;
    
    apr_pool_create(&io_pool, m->pool);
    apr_pool_tag(io_pool, "h2_io");
    io = h2_io_create(stream_id, io_pool, m->bucket_alloc, request);
    h2_io_set_add(m->stream_ios, io);
    
    return io;
}


apr_status_t h2_mplx_process(h2_mplx *m, int stream_id, 
                             const h2_request *req, 
                             h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status;
    int do_registration = 0;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        if (m->aborted) {
            status = APR_ECONNABORTED;
        }
        else {
            h2_io *io = open_io(m, stream_id, req);
            
            if (!io->request->body) {
                status = h2_io_in_close(io);
            }
            
            m->need_registration = m->need_registration || h2_iq_empty(m->q);
            do_registration = (m->need_registration && m->workers_busy < m->workers_max);
            h2_iq_add(m->q, io->id, cmp, ctx);
            
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, m->c,
                          "h2_mplx(%ld-%d): process", m->c->id, stream_id);
            H2_MPLX_IO_IN(APLOG_TRACE2, m, io, "h2_mplx_process");
        }
        leave_mutex(m, acquired);
    }
    if (status == APR_SUCCESS && do_registration) {
        workers_register(m);
    }
    return status;
}

static h2_task *pop_task(h2_mplx *m)
{
    h2_task *task = NULL;
    int sid;
    while (!m->aborted && !task 
        && (m->workers_busy < m->workers_limit)
        && (sid = h2_iq_shift(m->q)) > 0) {
        h2_io *io = h2_io_set_get(m->stream_ios, sid);
        if (io && io->orphaned) {
            io_destroy(m, io, 0);
            if (m->join_wait) {
                apr_thread_cond_signal(m->join_wait);
            }
        }
        else if (io) {
            conn_rec *slave, **pslave;
            int new_conn = 0;
            
            pslave = (conn_rec **)apr_array_pop(m->spare_slaves);
            if (pslave) {
                slave = *pslave;
            }
            else {
                slave = h2_slave_create(m->c, m->pool, NULL);
                new_conn = 1;
            }
            
            slave->sbh = m->c->sbh;
            io->task = task = h2_task_create(m->id, io->request, slave, m);
            m->c->keepalives++;
            apr_table_setn(slave->notes, H2_TASK_ID_NOTE, task->id);
            if (new_conn) {
                h2_slave_run_pre_connection(slave, ap_get_conn_socket(slave));
            }
            io->worker_started = 1;
            io->started_at = apr_time_now();
            if (sid > m->max_stream_started) {
                m->max_stream_started = sid;
            }
            ++m->workers_busy;
        }
    }
    return task;
}

h2_task *h2_mplx_pop_task(h2_mplx *m, int *has_more)
{
    h2_task *task = NULL;
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        if (m->aborted) {
            *has_more = 0;
        }
        else {
            task = pop_task(m);
            *has_more = !h2_iq_empty(m->q);
        }
        
        if (has_more && !task) {
            m->need_registration = 1;
        }
        leave_mutex(m, acquired);
    }
    return task;
}

static void task_done(h2_mplx *m, h2_task *task, h2_req_engine *ngn)
{
    if (task) {
        h2_io *io = h2_io_set_get(m->stream_ios, task->stream_id);
        
        if (task->frozen) {
            /* this task was handed over to an engine for processing 
             * and the original worker has finished. That means the 
             * engine may start processing now. */
            h2_task_thaw(task);
            /* we do not want the task to block on writing response
             * bodies into the mplx. */
            /* FIXME: this implementation is incomplete. */
            h2_task_set_io_blocking(task, 0);
            apr_thread_cond_broadcast(m->task_thawed);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          "h2_mplx(%ld): task(%s) done", m->id, task->id);
            /* clean our references and report request as done. Signal
             * that we want another unless we have been aborted */
            /* TODO: this will keep a worker attached to this h2_mplx as
             * long as it has requests to handle. Might no be fair to
             * other mplx's. Perhaps leave after n requests? */
            h2_mplx_out_close(m, task->stream_id);
            
            if (ngn && io) {
                apr_off_t bytes = io->output_consumed + h2_io_out_length(io);
                if (bytes > 0) {
                    /* we need to report consumed and current buffered output
                     * to the engine. The request will be streamed out or cancelled,
                     * no more data is coming from it and the engine should update
                     * its calculations before we destroy this information. */
                    h2_req_engine_out_consumed(ngn, task->c, bytes);
                    io->output_consumed = 0;
                }
            }
            
            if (task->engine) {
                if (!h2_req_engine_is_shutdown(task->engine)) {
                    ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c,
                                  "h2_mplx(%ld): task(%s) has not-shutdown "
                                  "engine(%s)", m->id, task->id, 
                                  h2_req_engine_get_id(task->engine));
                }
                h2_ngn_shed_done_ngn(m->ngn_shed, task->engine);
            }
            
            if (io) {
                apr_time_t now = apr_time_now();
                if (!io->orphaned && m->redo_ios
                    && h2_io_set_get(m->redo_ios, io->id)) {
                    /* reset and schedule again */
                    h2_io_redo(io);
                    h2_io_set_remove(m->redo_ios, io);
                    h2_iq_add(m->q, io->id, NULL, NULL);
                }
                else {
                    io->worker_done = 1;
                    io->done_at = now;
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                                  "h2_mplx(%ld): request(%d) done, %f ms"
                                  " elapsed", m->id, io->id, 
                                  (io->done_at - io->started_at) / 1000.0);
                    if (io->started_at > m->last_idle_block) {
                        /* this task finished without causing an 'idle block', e.g.
                         * a block by flow control.
                         */
                        if (now - m->last_limit_change >= m->limit_change_interval
                            && m->workers_limit < m->workers_max) {
                            /* Well behaving stream, allow it more workers */
                            m->workers_limit = H2MIN(m->workers_limit * 2, 
                                                     m->workers_max);
                            m->last_limit_change = now;
                            m->need_registration = 1;
                            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                                          "h2_mplx(%ld): increase worker limit to %d",
                                          m->id, m->workers_limit);
                        }
                    }
                }
                
                if (io->orphaned) {
                    io_destroy(m, io, 0);
                    if (m->join_wait) {
                        apr_thread_cond_signal(m->join_wait);
                    }
                }
                else {
                    /* hang around until the stream deregisters */
                }
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c,
                              "h2_mplx(%ld): task %s without corresp. h2_io",
                              m->id, task->id);
            }
        }
    }
}

void h2_mplx_task_done(h2_mplx *m, h2_task *task, h2_task **ptask)
{
    int acquired;
    
    if (enter_mutex(m, &acquired) == APR_SUCCESS) {
        task_done(m, task, NULL);
        --m->workers_busy;
        if (ptask) {
            /* caller wants another task */
            *ptask = pop_task(m);
        }
        leave_mutex(m, acquired);
    }
}

/*******************************************************************************
 * h2_mplx DoS protection
 ******************************************************************************/

typedef struct {
    h2_mplx *m;
    h2_io *io;
    apr_time_t now;
} io_iter_ctx;

static int latest_repeatable_busy_unsubmitted_iter(void *data, h2_io *io)
{
    io_iter_ctx *ctx = data;
    if (io->worker_started && !io->worker_done
        && h2_io_is_repeatable(io)
        && !h2_io_set_get(ctx->m->redo_ios, io->id)) {
        /* this io occupies a worker, the response has not been submitted yet,
         * not been cancelled and it is a repeatable request
         * -> it can be re-scheduled later */
        if (!ctx->io || ctx->io->started_at < io->started_at) {
            /* we did not have one or this one was started later */
            ctx->io = io;
        }
    }
    return 1;
}

static h2_io *get_latest_repeatable_busy_unsubmitted_io(h2_mplx *m) 
{
    io_iter_ctx ctx;
    ctx.m = m;
    ctx.io = NULL;
    h2_io_set_iter(m->stream_ios, latest_repeatable_busy_unsubmitted_iter, &ctx);
    return ctx.io;
}

static int timed_out_busy_iter(void *data, h2_io *io)
{
    io_iter_ctx *ctx = data;
    if (io->worker_started && !io->worker_done
        && (ctx->now - io->started_at) > ctx->m->stream_timeout) {
        /* timed out stream occupying a worker, found */
        ctx->io = io;
        return 0;
    }
    return 1;
}
static h2_io *get_timed_out_busy_stream(h2_mplx *m) 
{
    io_iter_ctx ctx;
    ctx.m = m;
    ctx.io = NULL;
    ctx.now = apr_time_now();
    h2_io_set_iter(m->stream_ios, timed_out_busy_iter, &ctx);
    return ctx.io;
}

static apr_status_t unschedule_slow_ios(h2_mplx *m) 
{
    h2_io *io;
    int n;
    
    if (!m->redo_ios) {
        m->redo_ios = h2_io_set_create(m->pool);
    }
    /* Try to get rid of streams that occupy workers. Look for safe requests
     * that are repeatable. If none found, fail the connection.
     */
    n = (m->workers_busy - m->workers_limit - h2_io_set_size(m->redo_ios));
    while (n > 0 && (io = get_latest_repeatable_busy_unsubmitted_io(m))) {
        h2_io_set_add(m->redo_ios, io);
        h2_io_rst(io, H2_ERR_CANCEL);
        --n;
    }
    
    if ((m->workers_busy - h2_io_set_size(m->redo_ios)) > m->workers_limit) {
        io = get_timed_out_busy_stream(m);
        if (io) {
            /* Too many busy workers, unable to cancel enough streams
             * and with a busy, timed out stream, we tell the client
             * to go away... */
            return APR_TIMEUP;
        }
    }
    return APR_SUCCESS;
}

apr_status_t h2_mplx_idle(h2_mplx *m)
{
    apr_status_t status = APR_SUCCESS;
    apr_time_t now;            
    int acquired;
    
    if (enter_mutex(m, &acquired) == APR_SUCCESS) {
        apr_size_t scount = h2_io_set_size(m->stream_ios);
        if (scount > 0 && m->workers_busy) {
            /* If we have streams in connection state 'IDLE', meaning
             * all streams are ready to sent data out, but lack
             * WINDOW_UPDATEs. 
             * 
             * This is ok, unless we have streams that still occupy
             * h2 workers. As worker threads are a scarce resource, 
             * we need to take measures that we do not get DoSed.
             * 
             * This is what we call an 'idle block'. Limit the amount 
             * of busy workers we allow for this connection until it
             * well behaves.
             */
            now = apr_time_now();
            m->last_idle_block = now;
            if (m->workers_limit > 2 
                && now - m->last_limit_change >= m->limit_change_interval) {
                if (m->workers_limit > 16) {
                    m->workers_limit = 16;
                }
                else if (m->workers_limit > 8) {
                    m->workers_limit = 8;
                }
                else if (m->workers_limit > 4) {
                    m->workers_limit = 4;
                }
                else if (m->workers_limit > 2) {
                    m->workers_limit = 2;
                }
                m->last_limit_change = now;
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                              "h2_mplx(%ld): decrease worker limit to %d",
                              m->id, m->workers_limit);
            }
            
            if (m->workers_busy > m->workers_limit) {
                status = unschedule_slow_ios(m);
            }
        }
        leave_mutex(m, acquired);
    }
    return status;
}

/*******************************************************************************
 * HTTP/2 request engines
 ******************************************************************************/

typedef struct {
    h2_mplx * m;
    h2_req_engine *ngn;
    int streams_updated;
} ngn_update_ctx;

static int ngn_update_window(void *ctx, h2_io *io)
{
    ngn_update_ctx *uctx = ctx;
    if (io && io->task && io->task->assigned == uctx->ngn
        && io_out_consumed_signal(uctx->m, io)) {
        ++uctx->streams_updated;
    }
    return 1;
}

static apr_status_t ngn_out_update_windows(h2_mplx *m, h2_req_engine *ngn)
{
    ngn_update_ctx ctx;
        
    ctx.m = m;
    ctx.ngn = ngn;
    ctx.streams_updated = 0;
    h2_io_set_iter(m->stream_ios, ngn_update_window, &ctx);
    
    return ctx.streams_updated? APR_SUCCESS : APR_EAGAIN;
}

apr_status_t h2_mplx_req_engine_push(const char *ngn_type, 
                                     request_rec *r,
                                     http2_req_engine_init *einit)
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
    task->r = r;
    
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        h2_io *io = h2_io_set_get(m->stream_ios, task->stream_id);
        if (!io || io->orphaned) {
            status = APR_ECONNABORTED;
        }
        else {
            status = h2_ngn_shed_push_task(m->ngn_shed, ngn_type, task, einit);
        }
        leave_mutex(m, acquired);
    }
    return status;
}

apr_status_t h2_mplx_req_engine_pull(h2_req_engine *ngn, 
                                     apr_read_type_e block, 
                                     apr_uint32_t capacity, 
                                     request_rec **pr)
{   
    h2_ngn_shed *shed = h2_ngn_shed_get_shed(ngn);
    h2_mplx *m = h2_ngn_shed_get_ctx(shed);
    apr_status_t status;
    h2_task *task = NULL;
    int acquired;
    
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        int want_shutdown = (block == APR_BLOCK_READ);

        /* Take this opportunity to update output consummation 
         * for this engine */
        ngn_out_update_windows(m, ngn);
        
        if (want_shutdown && !h2_iq_empty(m->q)) {
            /* For a blocking read, check first if requests are to be
             * had and, if not, wait a short while before doing the
             * blocking, and if unsuccessful, terminating read.
             */
            status = h2_ngn_shed_pull_task(shed, ngn, capacity, 1, &task);
            if (APR_STATUS_IS_EAGAIN(status)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                              "h2_mplx(%ld): start block engine pull", m->id);
                apr_thread_cond_timedwait(m->task_thawed, m->lock, 
                                          apr_time_from_msec(20));
                status = h2_ngn_shed_pull_task(shed, ngn, capacity, 1, &task);
            }
        }
        else {
            status = h2_ngn_shed_pull_task(shed, ngn, capacity,
                                           want_shutdown, &task);
        }
        leave_mutex(m, acquired);
    }
    *pr = task? task->r : NULL;
    return status;
}
 
void h2_mplx_req_engine_done(h2_req_engine *ngn, conn_rec *r_conn)
{
    h2_task *task = h2_ctx_cget_task(r_conn);
    
    if (task) {
        h2_mplx *m = task->mplx;
        int acquired;

        if (enter_mutex(m, &acquired) == APR_SUCCESS) {
            ngn_out_update_windows(m, ngn);
            h2_ngn_shed_done_task(m->ngn_shed, ngn, task);
            if (task->engine) { 
                /* cannot report that as done until engine returns */
            }
            else {
                task_done(m, task, ngn);
            }
            /* Take this opportunity to update output consummation 
             * for this engine */
            leave_mutex(m, acquired);
        }
    }
}
                                
