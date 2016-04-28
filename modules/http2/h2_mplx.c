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
#include "h2_bucket_beam.h"
#include "h2_config.h"
#include "h2_conn.h"
#include "h2_ctx.h"
#include "h2_h2.h"
#include "h2_response.h"
#include "h2_mplx.h"
#include "h2_ngn_shed.h"
#include "h2_request.h"
#include "h2_stream.h"
#include "h2_task.h"
#include "h2_worker.h"
#include "h2_workers.h"
#include "h2_util.h"


static void h2_beam_log(h2_bucket_beam *beam, int id, const char *msg, 
                        conn_rec *c, int level)
{
    if (beam && APLOG_C_IS_LEVEL(c,level)) {
        char buffer[2048];
        apr_size_t off = 0;
        
        off += apr_snprintf(buffer+off, H2_ALEN(buffer)-off, "cl=%d, ", beam->closed);
        off += h2_util_bl_print(buffer+off, H2_ALEN(buffer)-off, "red", ", ", &beam->red);
        off += h2_util_bb_print(buffer+off, H2_ALEN(buffer)-off, "green", ", ", beam->green);
        off += h2_util_bl_print(buffer+off, H2_ALEN(buffer)-off, "hold", ", ", &beam->hold);
        off += h2_util_bl_print(buffer+off, H2_ALEN(buffer)-off, "purge", "", &beam->purge);

        ap_log_cerror(APLOG_MARK, level, 0, c, "beam(%ld-%d): %s %s", 
                      c->id, id, msg, buffer);
    }
}

/* utility for iterating over ihash task sets */
typedef struct {
    h2_mplx *m;
    h2_task *task;
    apr_time_t now;
} task_iter_ctx;

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

static void beam_leave(void *ctx, apr_thread_mutex_t *lock)
{
    leave_mutex(ctx, 1);
}

static apr_status_t beam_enter(void *ctx, h2_beam_lock *pbl)
{
    h2_mplx *m = ctx;
    int acquired;
    apr_status_t status;
    
    status = enter_mutex(m, &acquired);
    if (status == APR_SUCCESS) {
        pbl->mutex = m->lock;
        pbl->leave = acquired? beam_leave : NULL;
        pbl->leave_ctx = m;
    }
    return status;
}

static void stream_output_consumed(void *ctx, 
                                   h2_bucket_beam *beam, apr_off_t length)
{
    h2_task *task = ctx;
    if (length > 0 && task && task->assigned) {
        h2_req_engine_out_consumed(task->assigned, task->c, length); 
    }
}

static void stream_input_consumed(void *ctx, 
                                  h2_bucket_beam *beam, apr_off_t length)
{
    h2_mplx *m = ctx;
    if (m->input_consumed && length) {
        m->input_consumed(m->input_consumed_ctx, beam->id, length);
    }
}

static int can_beam_file(void *ctx, h2_bucket_beam *beam,  apr_file_t *file)
{
    h2_mplx *m = ctx;
    if (m->tx_handles_reserved > 0) {
        --m->tx_handles_reserved;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, m->c,
                      "h2_mplx(%ld-%d): beaming file %s, tx_avail %d", 
                      m->id, beam->id, beam->tag, m->tx_handles_reserved);
        return 1;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, m->c,
                  "h2_mplx(%ld-%d): can_beam_file denied on %s", 
                  m->id, beam->id, beam->tag);
    return 0;
}

static void have_out_data_for(h2_mplx *m, int stream_id);

static void check_tx_reservation(h2_mplx *m) 
{
    if (m->tx_handles_reserved <= 0) {
        m->tx_handles_reserved += h2_workers_tx_reserve(m->workers, 
            H2MIN(m->tx_chunk_size, h2_ihash_count(m->tasks)));
    }
}

static void check_tx_free(h2_mplx *m) 
{
    if (m->tx_handles_reserved > m->tx_chunk_size) {
        apr_size_t count = m->tx_handles_reserved - m->tx_chunk_size;
        m->tx_handles_reserved = m->tx_chunk_size;
        h2_workers_tx_free(m->workers, count);
    }
    else if (m->tx_handles_reserved && h2_ihash_empty(m->tasks)) {
        h2_workers_tx_free(m->workers, m->tx_handles_reserved);
        m->tx_handles_reserved = 0;
    }
}

static void h2_mplx_destroy(h2_mplx *m)
{
    AP_DEBUG_ASSERT(m);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                  "h2_mplx(%ld): destroy, tasks=%d", 
                  m->id, (int)h2_ihash_count(m->tasks));
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

        m->streams = h2_ihash_create(m->pool, offsetof(h2_stream,id));
        m->q = h2_iq_create(m->pool, m->max_streams);
        m->tasks = h2_ihash_create(m->pool, offsetof(h2_task,stream_id));
        m->ready_tasks = h2_ihash_create(m->pool, offsetof(h2_task,stream_id));

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

static void input_consumed_signal(h2_mplx *m, h2_task *task)
{
    if (task->input.beam && task->worker_started) {
        h2_beam_send(task->input.beam, NULL, 0); /* trigger updates */
    }
}

static int output_consumed_signal(h2_mplx *m, h2_task *task)
{
    if (task->output.beam && task->worker_started && task->assigned) {
        h2_beam_send(task->output.beam, NULL, 0); /* trigger updates */
    }
    return 0;
}


static void task_destroy(h2_mplx *m, h2_task *task, int events)
{
    conn_rec *slave = NULL;
    int reuse_slave = 0;
    apr_status_t status;
    
    /* cleanup any buffered input */
    status = h2_task_shutdown(task, 0);
    if (status != APR_SUCCESS){
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, status, m->c, APLOGNO() 
                      "h2_task(%s): shutdown", task->id);
    }
    
    if (events) {
        /* Process outstanding events before destruction */
        input_consumed_signal(m, task);
    }
    
    /* The pool is cleared/destroyed which also closes all
     * allocated file handles. Give this count back to our
     * file handle pool. */
    if (task->input.beam) {
        m->tx_handles_reserved += 
        h2_beam_get_files_beamed(task->input.beam);
    }
    if (task->output.beam) {
        m->tx_handles_reserved += 
        h2_beam_get_files_beamed(task->output.beam);
    }
    
    slave = task->c;
    reuse_slave = ((m->spare_slaves->nelts < m->spare_slaves->nalloc)
                   && !task->rst_error);
    
    h2_ihash_remove(m->tasks, task->stream_id);
    h2_ihash_remove(m->ready_tasks, task->stream_id);
    if (m->redo_tasks) {
        h2_ihash_remove(m->redo_tasks, task->stream_id);
    }
    h2_task_destroy(task);

    if (slave) {
        if (reuse_slave && slave->keepalive == AP_CONN_KEEPALIVE) {
            APR_ARRAY_PUSH(m->spare_slaves, conn_rec*) = slave;
        }
        else {
            slave->sbh = NULL;
            h2_slave_destroy(slave, NULL);
        }
    }
    
    check_tx_free(m);
}

static int task_stream_done(h2_mplx *m, h2_task *task, int rst_error) 
{
    /* Remove io from ready set, we will never submit it */
    h2_ihash_remove(m->ready_tasks, task->stream_id);
    if (task->worker_done) {
        /* already finished or not even started yet */
        h2_iq_remove(m->q, task->stream_id);
        task_destroy(m, task, 0);
        return 0;
    }
    else {
        /* cleanup once task is done */
        task->orphaned = 1;
        if (task->input.beam) {
            apr_status_t status;
            status = h2_beam_shutdown(task->input.beam, APR_NONBLOCK_READ);
            if (status == APR_EAGAIN) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c, 
                              "h2_stream(%ld-%d): wait on input shutdown", 
                              m->id, task->stream_id);
                status = h2_beam_shutdown(task->input.beam, APR_BLOCK_READ);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, m->c, 
                              "h2_stream(%ld-%d): input shutdown returned", 
                              m->id, task->stream_id);
            }
            task->input.beam = NULL;
        }
        if (rst_error) {
            h2_task_rst(task, rst_error);
        }
        return 1;
    }
}

static int stream_done_iter(void *ctx, void *val)
{
    return task_stream_done((h2_mplx*)ctx, val, 0);
}

static int task_print(void *ctx, void *val)
{
    h2_mplx *m = ctx;
    h2_task *task = val;
    if (task->request) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, /* NO APLOGNO */
                      "->03198: h2_stream(%s): %s %s %s -> %s %d"
                      "[orph=%d/started=%d/done=%d]", 
                      task->id, task->request->method, 
                      task->request->authority, task->request->path,
                      task->response? "http" : (task->rst_error? "reset" : "?"),
                      task->response? task->response->http_status : task->rst_error,
                      task->orphaned, task->worker_started, 
                      task->worker_done);
    }
    else if (task) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, /* NO APLOGNO */
                      "->03198: h2_stream(%ld-%d): NULL", m->id, task->stream_id);
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
        while (!h2_ihash_iter(m->tasks, stream_done_iter, m)) {
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
                          "h2_mplx(%ld): release_join, waiting on %d tasks to report back", 
                          m->id, (int)h2_ihash_count(m->tasks));
                          
            status = apr_thread_cond_timedwait(wait, m->lock, apr_time_from_sec(wait_secs));
            
            while (!h2_ihash_iter(m->tasks, stream_done_iter, m)) {
                /* iterate until all ios have been orphaned or destroyed */
            }
            if (APR_STATUS_IS_TIMEUP(status)) {
                if (i > 0) {
                    /* Oh, oh. Still we wait for assigned  workers to report that 
                     * they are done. Unless we have a bug, a worker seems to be hanging. 
                     * If we exit now, all will be deallocated and the worker, once 
                     * it does return, will walk all over freed memory...
                     */
                    ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, APLOGNO(03198)
                                  "h2_mplx(%ld): release, waiting for %d seconds now for "
                                  "%d h2_workers to return, have still %d tasks outstanding", 
                                  m->id, i*wait_secs, m->workers_busy,
                                  (int)h2_ihash_count(m->tasks));
                    if (i == 1) {
                        h2_ihash_iter(m->tasks, task_print, m);
                    }
                }
                h2_mplx_abort(m);
                apr_thread_cond_broadcast(m->task_thawed);
            }
        }
        
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c, APLOGNO(03056)
                      "h2_mplx(%ld): release_join (%d tasks left) -> destroy", 
                      m->id, (int)h2_ihash_count(m->tasks));
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
        h2_task *task = h2_ihash_get(m->tasks, stream_id);

        h2_ihash_remove(m->streams, stream_id);
        /* there should be an h2_io, once the stream has been scheduled
         * for processing, e.g. when we received all HEADERs. But when
         * a stream is cancelled very early, it will not exist. */
        if (task) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c, 
                          "h2_mplx(%ld-%d): marking stream task as done.", 
                          m->id, stream_id);
            task_stream_done(m, task, rst_error);
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

static int update_window(void *ctx, void *val)
{
    h2_mplx *m = ctx;
    input_consumed_signal(m, val);
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
        h2_ihash_iter(m->tasks, update_window, m);
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c, 
                      "h2_session(%ld): windows updated", m->id);
        status = APR_SUCCESS;
        leave_mutex(m, acquired);
    }
    return status;
}

static int task_iter_first(void *ctx, void *val)
{
    task_iter_ctx *tctx = ctx;
    h2_task *task = val;
    tctx->task = task;
    return 0;
}

h2_stream *h2_mplx_next_submit(h2_mplx *m, h2_ihash_t *streams)
{
    apr_status_t status;
    h2_stream *stream = NULL;
    int acquired;

    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        task_iter_ctx ctx;
        ctx.m = m;
        ctx.task = NULL;
        h2_ihash_iter(m->ready_tasks, task_iter_first, &ctx);
        
        if (ctx.task && !m->aborted) {
            h2_task *task = ctx.task;
            
            h2_ihash_remove(m->ready_tasks, task->stream_id);
            stream = h2_ihash_get(streams, task->stream_id);
            if (stream && task) {
                task->submitted = 1;
                if (task->rst_error) {
                    h2_stream_rst(stream, task->rst_error);
                }
                else {
                    AP_DEBUG_ASSERT(task->response);
                    h2_stream_set_response(stream, task->response, 
                                           task->output.beam);
                }
            }
            else if (task) {
                /* We have the io ready, but the stream has gone away, maybe
                 * reset by the client. Should no longer happen since such
                 * streams should clear io's from the ready queue.
                 */
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, APLOGNO(03347)
                              "h2_mplx(%s): stream for response closed, "
                              "resetting io to close request processing",
                              task->id);
                task->orphaned = 1;
                h2_task_rst(task, H2_ERR_STREAM_CLOSED);
                if (!task->worker_started || task->worker_done) {
                    task_destroy(m, task, 1);
                }
                else {
                    /* hang around until the h2_task is done, but
                     * shutdown input/output and send out any events asap. */
                    h2_task_shutdown(task, 0);
                    input_consumed_signal(m, task);
                }
            }
        }
        leave_mutex(m, acquired);
    }
    return stream;
}

static apr_status_t out_open(h2_mplx *m, int stream_id, h2_response *response)
{
    apr_status_t status = APR_SUCCESS;
    h2_task *task = h2_ihash_get(m->tasks, stream_id);
    
    if (!task || task->orphaned) {
        return APR_ECONNABORTED;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                  "h2_mplx(%s): open response: %d, rst=%d",
                  task->id, response->http_status, response->rst_error);
    
    h2_task_set_response(task, response);
    
    if (task->output.beam) {
        h2_beam_buffer_size_set(task->output.beam, m->stream_max_mem);
        h2_beam_timeout_set(task->output.beam, m->stream_timeout);
        h2_beam_on_consumed(task->output.beam, stream_output_consumed, task);
        m->tx_handles_reserved -= h2_beam_get_files_beamed(task->output.beam);
        h2_beam_on_file_beam(task->output.beam, can_beam_file, m);
        h2_beam_mutex_set(task->output.beam, beam_enter, task->cond, m);
    }
    
    h2_ihash_add(m->ready_tasks, task);
    if (response && response->http_status < 300) {
        /* we might see some file buckets in the output, see
         * if we have enough handles reserved. */
        check_tx_reservation(m);
    }
    have_out_data_for(m, stream_id);
    return status;
}

apr_status_t h2_mplx_out_open(h2_mplx *m, int stream_id, h2_response *response)
{
    apr_status_t status;
    int acquired;
    
    AP_DEBUG_ASSERT(m);
    if ((status = enter_mutex(m, &acquired)) == APR_SUCCESS) {
        if (m->aborted) {
            status = APR_ECONNABORTED;
        }
        else {
            status = out_open(m, stream_id, response);
        }
        leave_mutex(m, acquired);
    }
    return status;
}

static apr_status_t out_close(h2_mplx *m, h2_task *task)
{
    apr_status_t status = APR_SUCCESS;
    
    if (!task || task->orphaned) {
        return APR_ECONNABORTED;
    }
    
    if (!task->response && !task->rst_error) {
        /* In case a close comes before a response was created,
         * insert an error one so that our streams can properly
         * reset.
         */
        h2_response *r = h2_response_die(task->stream_id, APR_EGENERAL, 
                                         task->request, m->pool);
        status = out_open(m, task->stream_id, r);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, m->c,
                      "h2_mplx(%s): close, no response, no rst", task->id);
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, m->c,
                  "h2_mplx(%s): close", task->id);
    if (task->output.beam) {
        status = h2_beam_close(task->output.beam);
        h2_beam_log(task->output.beam, task->stream_id, "out_close", m->c, 
                    APLOG_TRACE2);
    }
    output_consumed_signal(m, task);
    have_out_data_for(m, task->stream_id);
    return status;
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

apr_status_t h2_mplx_process(h2_mplx *m, struct h2_stream *stream, 
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
            h2_beam_create(&stream->input, stream->pool, stream->id, 
                           "input", 0);
            h2_ihash_add(m->streams, stream);
            
            if (!m->need_registration) {
                m->need_registration = h2_iq_empty(m->q);
            }
            if (m->workers_busy < m->workers_max) {
                do_registration = m->need_registration;
            }
            h2_iq_add(m->q, stream->id, cmp, ctx);

            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, m->c,
                          "h2_mplx(%ld-%d): process, body=%d", 
                          m->c->id, stream->id, stream->request->body);
        }
        leave_mutex(m, acquired);
    }
    if (do_registration) {
        m->need_registration = 0;
        h2_workers_register(m->workers, m);
    }
    return status;
}

static h2_task *pop_task(h2_mplx *m)
{
    h2_task *task = NULL;
    h2_stream *stream;
    int sid;
    while (!m->aborted && !task  && (m->workers_busy < m->workers_limit)
           && (sid = h2_iq_shift(m->q)) > 0) {
        
        stream = h2_ihash_get(m->streams, sid);
        if (stream) {
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
            task = h2_task_create(slave, stream->request, stream->input, m);
            h2_ihash_add(m->tasks, task);
            
            m->c->keepalives++;
            apr_table_setn(slave->notes, H2_TASK_ID_NOTE, task->id);
            if (new_conn) {
                h2_slave_run_pre_connection(slave, ap_get_conn_socket(slave));
            }
            task->worker_started = 1;
            task->started_at = apr_time_now();
            if (sid > m->max_stream_started) {
                m->max_stream_started = sid;
            }

            if (stream->input) {
                h2_beam_timeout_set(stream->input, m->stream_timeout);
                h2_beam_on_consumed(stream->input, stream_input_consumed, m);
                h2_beam_on_file_beam(stream->input, can_beam_file, m);
                h2_beam_mutex_set(stream->input, beam_enter, task->cond, m);
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
            return;
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          "h2_mplx(%ld): task(%s) done", m->id, task->id);
            out_close(m, task);
            
            if (ngn) {
                apr_off_t bytes = 0;
                if (task->output.beam) {
                    h2_beam_send(task->output.beam, NULL, APR_NONBLOCK_READ);
                    bytes += h2_beam_get_buffered(task->output.beam);
                }
                if (bytes > 0) {
                    /* we need to report consumed and current buffered output
                     * to the engine. The request will be streamed out or cancelled,
                     * no more data is coming from it and the engine should update
                     * its calculations before we destroy this information. */
                    h2_req_engine_out_consumed(ngn, task->c, bytes);
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
            
            if (!task->orphaned && m->redo_tasks
                && h2_ihash_get(m->redo_tasks, task->stream_id)) {
                /* reset and schedule again */
                h2_task_redo(task);
                h2_ihash_remove(m->redo_tasks, task->stream_id);
                h2_iq_add(m->q, task->stream_id, NULL, NULL);
                return;
            }
            
            task->worker_done = 1;
            task->done_at = apr_time_now();
            if (task->output.beam) {
                h2_beam_on_consumed(task->output.beam, NULL, NULL);
                h2_beam_mutex_set(task->output.beam, NULL, NULL, NULL);
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          "h2_mplx(%s): request done, %f ms"
                          " elapsed", task->id, 
                          (task->done_at - task->started_at) / 1000.0);
            if (task->started_at > m->last_idle_block) {
                /* this task finished without causing an 'idle block', e.g.
                 * a block by flow control.
                 */
                if (task->done_at- m->last_limit_change >= m->limit_change_interval
                    && m->workers_limit < m->workers_max) {
                    /* Well behaving stream, allow it more workers */
                    m->workers_limit = H2MIN(m->workers_limit * 2, 
                                             m->workers_max);
                    m->last_limit_change = task->done_at;
                    m->need_registration = 1;
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                                  "h2_mplx(%ld): increase worker limit to %d",
                                  m->id, m->workers_limit);
                }
            }
            
            if (task->orphaned) {
                task_destroy(m, task, 0);
                if (m->join_wait) {
                    apr_thread_cond_signal(m->join_wait);
                }
            }
            else {
                /* hang around until the stream deregisters */
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

static int latest_repeatable_unsubmitted_iter(void *data, void *val)
{
    task_iter_ctx *ctx = data;
    h2_task *task = val;
    if (!task->worker_done && h2_task_can_redo(task) 
        && !h2_ihash_get(ctx->m->redo_tasks, task->stream_id)) {
        /* this task occupies a worker, the response has not been submitted yet,
         * not been cancelled and it is a repeatable request
         * -> it can be re-scheduled later */
        if (!ctx->task || ctx->task->started_at < task->started_at) {
            /* we did not have one or this one was started later */
            ctx->task = task;
        }
    }
    return 1;
}

static h2_task *get_latest_repeatable_unsubmitted_task(h2_mplx *m) 
{
    task_iter_ctx ctx;
    ctx.m = m;
    ctx.task = NULL;
    h2_ihash_iter(m->tasks, latest_repeatable_unsubmitted_iter, &ctx);
    return ctx.task;
}

static int timed_out_busy_iter(void *data, void *val)
{
    task_iter_ctx *ctx = data;
    h2_task *task = val;
    if (!task->worker_done
        && (ctx->now - task->started_at) > ctx->m->stream_timeout) {
        /* timed out stream occupying a worker, found */
        ctx->task = task;
        return 0;
    }
    return 1;
}

static h2_task *get_timed_out_busy_task(h2_mplx *m) 
{
    task_iter_ctx ctx;
    ctx.m = m;
    ctx.task = NULL;
    ctx.now = apr_time_now();
    h2_ihash_iter(m->tasks, timed_out_busy_iter, &ctx);
    return ctx.task;
}

static apr_status_t unschedule_slow_tasks(h2_mplx *m) 
{
    h2_task *task;
    int n;
    
    if (!m->redo_tasks) {
        m->redo_tasks = h2_ihash_create(m->pool, offsetof(h2_task, stream_id));
    }
    /* Try to get rid of streams that occupy workers. Look for safe requests
     * that are repeatable. If none found, fail the connection.
     */
    n = (m->workers_busy - m->workers_limit - h2_ihash_count(m->redo_tasks));
    while (n > 0 && (task = get_latest_repeatable_unsubmitted_task(m))) {
        h2_task_rst(task, H2_ERR_CANCEL);
        h2_ihash_add(m->redo_tasks, task);
        --n;
    }
    
    if ((m->workers_busy - h2_ihash_count(m->redo_tasks)) > m->workers_limit) {
        task = get_timed_out_busy_task(m);
        if (task) {
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
        apr_size_t scount = h2_ihash_count(m->streams);
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
                status = unschedule_slow_tasks(m);
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

static int ngn_update_window(void *ctx, void *val)
{
    ngn_update_ctx *uctx = ctx;
    h2_task *task = val;
    if (task && task->assigned == uctx->ngn
        && output_consumed_signal(uctx->m, task)) {
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
    h2_ihash_iter(m->tasks, ngn_update_window, &ctx);
    
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
        if (task->orphaned) {
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
                                
