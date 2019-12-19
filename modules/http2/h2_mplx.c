/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include <apr_atomic.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>
#include <apr_strings.h>
#include <apr_time.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include <mpm_common.h>

#include "mod_http2.h"

#include "h2.h"
#include "h2_private.h"
#include "h2_bucket_beam.h"
#include "h2_config.h"
#include "h2_conn.h"
#include "h2_ctx.h"
#include "h2_h2.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_stream.h"
#include "h2_session.h"
#include "h2_task.h"
#include "h2_workers.h"
#include "h2_util.h"


/* utility for iterating over ihash stream sets */
typedef struct {
    h2_mplx *m;
    h2_stream *stream;
    apr_time_t now;
    apr_size_t count;
} stream_iter_ctx;

static apr_status_t mplx_be_happy(h2_mplx *m);
static apr_status_t mplx_be_annoyed(h2_mplx *m);

apr_status_t h2_mplx_child_init(apr_pool_t *pool, server_rec *s)
{
    return APR_SUCCESS;
}

#define H2_MPLX_ENTER(m)    \
    do { apr_status_t rv; if ((rv = apr_thread_mutex_lock(m->lock)) != APR_SUCCESS) {\
        return rv;\
    } } while(0)

#define H2_MPLX_LEAVE(m)    \
    apr_thread_mutex_unlock(m->lock)
 
#define H2_MPLX_ENTER_ALWAYS(m)    \
    apr_thread_mutex_lock(m->lock)

#define H2_MPLX_ENTER_MAYBE(m, dolock)    \
    if (dolock) apr_thread_mutex_lock(m->lock)

#define H2_MPLX_LEAVE_MAYBE(m, dolock)    \
    if (dolock) apr_thread_mutex_unlock(m->lock)

static void check_data_for(h2_mplx *m, h2_stream *stream, int mplx_is_locked);

static void stream_output_consumed(void *ctx, 
                                   h2_bucket_beam *beam, apr_off_t length)
{
}

static void stream_input_ev(void *ctx, h2_bucket_beam *beam)
{
    h2_stream *stream = ctx;
    h2_mplx *m = stream->session->mplx;
    apr_atomic_set32(&m->event_pending, 1); 
}

static void stream_input_consumed(void *ctx, h2_bucket_beam *beam, apr_off_t length)
{
    h2_stream_in_consumed(ctx, length);
}

static void stream_joined(h2_mplx *m, h2_stream *stream)
{
    ap_assert(!h2_task_has_started(stream->task) || stream->task->worker_done);
    
    h2_ififo_remove(m->readyq, stream->id);
    h2_ihash_remove(m->shold, stream->id);
    h2_ihash_add(m->spurge, stream);
}

static void stream_cleanup(h2_mplx *m, h2_stream *stream)
{
    ap_assert(stream->state == H2_SS_CLEANUP);

    if (stream->input) {
        h2_beam_on_consumed(stream->input, NULL, NULL, NULL);
        h2_beam_abort(stream->input);
    }
    if (stream->output) {
        h2_beam_on_produced(stream->output, NULL, NULL);
        h2_beam_leave(stream->output);
    }
    
    h2_stream_cleanup(stream);

    h2_ihash_remove(m->streams, stream->id);
    h2_iq_remove(m->q, stream->id);
    
    if (!h2_task_has_started(stream->task) || stream->task->done_done) {
        stream_joined(m, stream);
    }
    else {
        h2_ififo_remove(m->readyq, stream->id);
        h2_ihash_add(m->shold, stream);
        if (stream->task) {
            stream->task->c->aborted = 1;
        }
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
h2_mplx *h2_mplx_create(conn_rec *c, server_rec *s, apr_pool_t *parent, 
                        h2_workers *workers)
{
    apr_status_t status = APR_SUCCESS;
    apr_allocator_t *allocator;
    apr_thread_mutex_t *mutex;
    h2_mplx *m;
    
    m = apr_pcalloc(parent, sizeof(h2_mplx));
    if (m) {
        m->id = c->id;
        m->c = c;
        m->s = s;
        
        /* We create a pool with its own allocator to be used for
         * processing slave connections. This is the only way to have the
         * processing independant of its parent pool in the sense that it
         * can work in another thread. Also, the new allocator needs its own
         * mutex to synchronize sub-pools.
         */
        status = apr_allocator_create(&allocator);
        if (status != APR_SUCCESS) {
            return NULL;
        }
        apr_allocator_max_free_set(allocator, ap_max_mem_free);
        apr_pool_create_ex(&m->pool, parent, NULL, allocator);
        if (!m->pool) {
            apr_allocator_destroy(allocator);
            return NULL;
        }
        apr_pool_tag(m->pool, "h2_mplx");
        apr_allocator_owner_set(allocator, m->pool);
        status = apr_thread_mutex_create(&mutex, APR_THREAD_MUTEX_DEFAULT,
                                         m->pool);
        if (status != APR_SUCCESS) {
            apr_pool_destroy(m->pool);
            return NULL;
        }
        apr_allocator_mutex_set(allocator, mutex);

        status = apr_thread_mutex_create(&m->lock, APR_THREAD_MUTEX_DEFAULT,
                                         m->pool);
        if (status != APR_SUCCESS) {
            apr_pool_destroy(m->pool);
            return NULL;
        }
        
        m->max_streams = h2_config_sgeti(s, H2_CONF_MAX_STREAMS);
        m->stream_max_mem = h2_config_sgeti(s, H2_CONF_STREAM_MAX_MEM);

        m->streams = h2_ihash_create(m->pool, offsetof(h2_stream,id));
        m->shold = h2_ihash_create(m->pool, offsetof(h2_stream,id));
        m->spurge = h2_ihash_create(m->pool, offsetof(h2_stream,id));
        m->q = h2_iq_create(m->pool, m->max_streams);

        status = h2_ififo_set_create(&m->readyq, m->pool, m->max_streams);
        if (status != APR_SUCCESS) {
            apr_pool_destroy(m->pool);
            return NULL;
        }

        m->workers = workers;
        m->max_active = workers->max_workers;
        m->limit_active = 6; /* the original h1 max parallel connections */
        m->last_mood_change = apr_time_now();
        m->mood_update_interval = apr_time_from_msec(100);
        
        m->spare_slaves = apr_array_make(m->pool, 10, sizeof(conn_rec*));
    }
    return m;
}

int h2_mplx_shutdown(h2_mplx *m)
{
    int max_stream_started = 0;
    
    H2_MPLX_ENTER(m);

    max_stream_started = m->max_stream_started;
    /* Clear schedule queue, disabling existing streams from starting */ 
    h2_iq_clear(m->q);

    H2_MPLX_LEAVE(m);
    return max_stream_started;
}

static int input_consumed_signal(h2_mplx *m, h2_stream *stream)
{
    if (stream->input) {
        return h2_beam_report_consumption(stream->input);
    }
    return 0;
}

static int report_consumption_iter(void *ctx, void *val)
{
    h2_stream *stream = val;
    h2_mplx *m = ctx;
    
    input_consumed_signal(m, stream);
    if (stream->state == H2_SS_CLOSED_L
        && (!stream->task || stream->task->worker_done)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c, 
                      H2_STRM_LOG(APLOGNO(10026), stream, "remote close missing")); 
        nghttp2_submit_rst_stream(stream->session->ngh2, NGHTTP2_FLAG_NONE, 
                                  stream->id, NGHTTP2_NO_ERROR);
    }
    return 1;
}

static int output_consumed_signal(h2_mplx *m, h2_task *task)
{
    if (task->output.beam) {
        return h2_beam_report_consumption(task->output.beam);
    }
    return 0;
}

static int stream_destroy_iter(void *ctx, void *val) 
{   
    h2_mplx *m = ctx;
    h2_stream *stream = val;

    h2_ihash_remove(m->spurge, stream->id);
    ap_assert(stream->state == H2_SS_CLEANUP);
    
    if (stream->input) {
        /* Process outstanding events before destruction */
        input_consumed_signal(m, stream);    
        h2_beam_log(stream->input, m->c, APLOG_TRACE2, "stream_destroy");
        h2_beam_destroy(stream->input);
        stream->input = NULL;
    }

    if (stream->task) {
        h2_task *task = stream->task;
        conn_rec *slave;
        int reuse_slave = 0;
        
        stream->task = NULL;
        slave = task->c;
        if (slave) {
            /* On non-serialized requests, the IO logging has not accounted for any
             * meta data send over the network: response headers and h2 frame headers. we
             * counted this on the stream and need to add this now.
             * This is supposed to happen before the EOR bucket triggers the
             * logging of the transaction. *fingers crossed* */
            if (task->request && !task->request->serialize && h2_task_logio_add_bytes_out) {
                apr_off_t unaccounted = stream->out_frame_octets - stream->out_data_octets;
                if (unaccounted > 0) {
                    h2_task_logio_add_bytes_out(slave, unaccounted);
                }
            }
        
            if (m->s->keep_alive_max == 0 || slave->keepalives < m->s->keep_alive_max) {
                reuse_slave = ((m->spare_slaves->nelts < (m->limit_active * 3 / 2))
                               && !task->rst_error);
            }
            
            if (reuse_slave) {
                h2_beam_log(task->output.beam, m->c, APLOG_DEBUG, 
                            APLOGNO(03385) "h2_task_destroy, reuse slave");    
                h2_task_destroy(task);
                APR_ARRAY_PUSH(m->spare_slaves, conn_rec*) = slave;
            }
            else {
                h2_beam_log(task->output.beam, m->c, APLOG_TRACE1, 
                            "h2_task_destroy, destroy slave");    
                h2_slave_destroy(slave);
            }
        }
    }
    h2_stream_destroy(stream);
    return 0;
}

static void purge_streams(h2_mplx *m, int lock)
{
    if (!h2_ihash_empty(m->spurge)) {
        H2_MPLX_ENTER_MAYBE(m, lock);
        while (!h2_ihash_iter(m->spurge, stream_destroy_iter, m)) {
            /* repeat until empty */
        }
        H2_MPLX_LEAVE_MAYBE(m, lock);
    }
}

typedef struct {
    h2_mplx_stream_cb *cb;
    void *ctx;
} stream_iter_ctx_t;

static int stream_iter_wrap(void *ctx, void *stream)
{
    stream_iter_ctx_t *x = ctx;
    return x->cb(stream, x->ctx);
}

apr_status_t h2_mplx_stream_do(h2_mplx *m, h2_mplx_stream_cb *cb, void *ctx)
{
    stream_iter_ctx_t x;
    
    H2_MPLX_ENTER(m);

    x.cb = cb;
    x.ctx = ctx;
    h2_ihash_iter(m->streams, stream_iter_wrap, &x);
        
    H2_MPLX_LEAVE(m);
    return APR_SUCCESS;
}

static int report_stream_iter(void *ctx, void *val) {
    h2_mplx *m = ctx;
    h2_stream *stream = val;
    h2_task *task = stream->task;
    if (APLOGctrace1(m->c)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                      H2_STRM_MSG(stream, "started=%d, scheduled=%d, ready=%d, out_buffer=%ld"), 
                      !!stream->task, stream->scheduled, h2_stream_is_ready(stream),
                      (long)h2_beam_get_buffered(stream->output));
    }
    if (task) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c, /* NO APLOGNO */
                      H2_STRM_MSG(stream, "->03198: %s %s %s"
                      "[started=%d/done=%d]"), 
                      task->request->method, task->request->authority, 
                      task->request->path, task->worker_started, 
                      task->worker_done);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c, /* NO APLOGNO */
                      H2_STRM_MSG(stream, "->03198: no task"));
    }
    return 1;
}

static int unexpected_stream_iter(void *ctx, void *val) {
    h2_mplx *m = ctx;
    h2_stream *stream = val;
    ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, /* NO APLOGNO */
                  H2_STRM_MSG(stream, "unexpected, started=%d, scheduled=%d, ready=%d"), 
                  !!stream->task, stream->scheduled, h2_stream_is_ready(stream));
    return 1;
}

static int stream_cancel_iter(void *ctx, void *val) {
    h2_mplx *m = ctx;
    h2_stream *stream = val;

    /* disabled input consumed reporting */
    if (stream->input) {
        h2_beam_on_consumed(stream->input, NULL, NULL, NULL);
    }
    /* take over event monitoring */
    h2_stream_set_monitor(stream, NULL);
    /* Reset, should transit to CLOSED state */
    h2_stream_rst(stream, H2_ERR_NO_ERROR);
    /* All connection data has been sent, simulate cleanup */
    h2_stream_dispatch(stream, H2_SEV_EOS_SENT);
    stream_cleanup(m, stream);  
    return 0;
}

void h2_mplx_release_and_join(h2_mplx *m, apr_thread_cond_t *wait)
{
    apr_status_t status;
    int i, wait_secs = 60, old_aborted;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                  "h2_mplx(%ld): start release", m->id);
    /* How to shut down a h2 connection:
     * 0. abort and tell the workers that no more tasks will come from us */
    m->aborted = 1;
    h2_workers_unregister(m->workers, m);
    
    H2_MPLX_ENTER_ALWAYS(m);

    /* While really terminating any slave connections, treat the master
     * connection as aborted. It's not as if we could send any more data
     * at this point. */
    old_aborted = m->c->aborted;
    m->c->aborted = 1;

    /* How to shut down a h2 connection:
     * 1. cancel all streams still active */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c, 
                  "h2_mplx(%ld): release, %d/%d/%d streams (total/hold/purge), %d active tasks", 
                  m->id, (int)h2_ihash_count(m->streams),
                  (int)h2_ihash_count(m->shold), (int)h2_ihash_count(m->spurge), m->tasks_active);
    while (!h2_ihash_iter(m->streams, stream_cancel_iter, m)) {
        /* until empty */
    }
    
    /* 2. no more streams should be scheduled or in the active set */
    ap_assert(h2_ihash_empty(m->streams));
    ap_assert(h2_iq_empty(m->q));
    
    /* 3. while workers are busy on this connection, meaning they
     *    are processing tasks from this connection, wait on them finishing
     *    in order to wake us and let us check again. 
     *    Eventually, this has to succeed. */    
    m->join_wait = wait;
    for (i = 0; h2_ihash_count(m->shold) > 0; ++i) {        
        status = apr_thread_cond_timedwait(wait, m->lock, apr_time_from_sec(wait_secs));
        
        if (APR_STATUS_IS_TIMEUP(status)) {
            /* This can happen if we have very long running requests
             * that do not time out on IO. */
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c, APLOGNO(03198)
                          "h2_mplx(%ld): waited %d sec for %d tasks", 
                          m->id, i*wait_secs, (int)h2_ihash_count(m->shold));
            h2_ihash_iter(m->shold, report_stream_iter, m);
        }
    }
    m->join_wait = NULL;

    /* 4. With all workers done, all streams should be in spurge */
    ap_assert(m->tasks_active == 0);
    if (!h2_ihash_empty(m->shold)) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, APLOGNO(03516)
                      "h2_mplx(%ld): unexpected %d streams in hold", 
                      m->id, (int)h2_ihash_count(m->shold));
        h2_ihash_iter(m->shold, unexpected_stream_iter, m);
    }
    
    m->c->aborted = old_aborted;
    H2_MPLX_LEAVE(m);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c, "h2_mplx(%ld): released", m->id);
}

apr_status_t h2_mplx_stream_cleanup(h2_mplx *m, h2_stream *stream)
{
    H2_MPLX_ENTER(m);
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c, 
                  H2_STRM_MSG(stream, "cleanup"));
    stream_cleanup(m, stream);        
    
    H2_MPLX_LEAVE(m);
    return APR_SUCCESS;
}

h2_stream *h2_mplx_stream_get(h2_mplx *m, int id)
{
    h2_stream *s = NULL;
    
    H2_MPLX_ENTER_ALWAYS(m);

    s = h2_ihash_get(m->streams, id);

    H2_MPLX_LEAVE(m);
    return s;
}

static void output_produced(void *ctx, h2_bucket_beam *beam, apr_off_t bytes)
{
    h2_stream *stream = ctx;
    h2_mplx *m = stream->session->mplx;
    
    check_data_for(m, stream, 0);
}

static apr_status_t out_open(h2_mplx *m, int stream_id, h2_bucket_beam *beam)
{
    h2_stream *stream = h2_ihash_get(m->streams, stream_id);
    
    if (!stream || !stream->task || m->aborted) {
        return APR_ECONNABORTED;
    }
    
    ap_assert(stream->output == NULL);
    stream->output = beam;
    
    if (APLOGctrace2(m->c)) {
        h2_beam_log(beam, m->c, APLOG_TRACE2, "out_open");
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                      "h2_mplx(%s): out open", stream->task->id);
    }
    
    h2_beam_on_consumed(stream->output, NULL, stream_output_consumed, stream);
    h2_beam_on_produced(stream->output, output_produced, stream);
    if (stream->task->output.copy_files) {
        h2_beam_on_file_beam(stream->output, h2_beam_no_files, NULL);
    }
    
    /* we might see some file buckets in the output, see
     * if we have enough handles reserved. */
    check_data_for(m, stream, 1);
    return APR_SUCCESS;
}

apr_status_t h2_mplx_out_open(h2_mplx *m, int stream_id, h2_bucket_beam *beam)
{
    apr_status_t status;
    
    H2_MPLX_ENTER(m);

    if (m->aborted) {
        status = APR_ECONNABORTED;
    }
    else {
        status = out_open(m, stream_id, beam);
    }

    H2_MPLX_LEAVE(m);
    return status;
}

static apr_status_t out_close(h2_mplx *m, h2_task *task)
{
    apr_status_t status = APR_SUCCESS;
    h2_stream *stream;
    
    if (!task) {
        return APR_ECONNABORTED;
    }
    if (task->c) {
        ++task->c->keepalives;
    }
    
    stream = h2_ihash_get(m->streams, task->stream_id);
    if (!stream) {
        return APR_ECONNABORTED;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, m->c,
                  "h2_mplx(%s): close", task->id);
    status = h2_beam_close(task->output.beam);
    h2_beam_log(task->output.beam, m->c, APLOG_TRACE2, "out_close");
    output_consumed_signal(m, task);
    check_data_for(m, stream, 1);
    return status;
}

apr_status_t h2_mplx_out_trywait(h2_mplx *m, apr_interval_time_t timeout,
                                 apr_thread_cond_t *iowait)
{
    apr_status_t status;
    
    H2_MPLX_ENTER(m);

    if (m->aborted) {
        status = APR_ECONNABORTED;
    }
    else if (h2_mplx_has_master_events(m)) {
        status = APR_SUCCESS;
    }
    else {
        purge_streams(m, 0);
        h2_ihash_iter(m->streams, report_consumption_iter, m);
        m->added_output = iowait;
        status = apr_thread_cond_timedwait(m->added_output, m->lock, timeout);
        if (APLOGctrace2(m->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                          "h2_mplx(%ld): trywait on data for %f ms)",
                          m->id, timeout/1000.0);
        }
        m->added_output = NULL;
    }

    H2_MPLX_LEAVE(m);
    return status;
}

static void check_data_for(h2_mplx *m, h2_stream *stream, int mplx_is_locked)
{
    /* If m->lock is already held, we must release during h2_ififo_push()
     * which can wait on its not_full condition, causing a deadlock because
     * no one would then be able to acquire m->lock to empty the fifo.
     */
    H2_MPLX_LEAVE_MAYBE(m, mplx_is_locked);
    if (h2_ififo_push(m->readyq, stream->id) == APR_SUCCESS) {
        H2_MPLX_ENTER_ALWAYS(m);
        apr_atomic_set32(&m->event_pending, 1);
        if (m->added_output) {
            apr_thread_cond_signal(m->added_output);
        }
        H2_MPLX_LEAVE_MAYBE(m, !mplx_is_locked);
    }
    else {
        H2_MPLX_ENTER_MAYBE(m, mplx_is_locked);
    }
}

apr_status_t h2_mplx_reprioritize(h2_mplx *m, h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status;
    
    H2_MPLX_ENTER(m);

    if (m->aborted) {
        status = APR_ECONNABORTED;
    }
    else {
        h2_iq_sort(m->q, cmp, ctx);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                      "h2_mplx(%ld): reprioritize tasks", m->id);
        status = APR_SUCCESS;
    }

    H2_MPLX_LEAVE(m);
    return status;
}

static void register_if_needed(h2_mplx *m) 
{
    if (!m->aborted && !m->is_registered && !h2_iq_empty(m->q)) {
        apr_status_t status = h2_workers_register(m->workers, m); 
        if (status == APR_SUCCESS) {
            m->is_registered = 1;
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, m->c, APLOGNO(10021)
                          "h2_mplx(%ld): register at workers", m->id);
        }
    }
}

apr_status_t h2_mplx_process(h2_mplx *m, struct h2_stream *stream, 
                             h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status;
    
    H2_MPLX_ENTER(m);

    if (m->aborted) {
        status = APR_ECONNABORTED;
    }
    else {
        status = APR_SUCCESS;
        h2_ihash_add(m->streams, stream);
        if (h2_stream_is_ready(stream)) {
            /* already have a response */
            check_data_for(m, stream, 1);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          H2_STRM_MSG(stream, "process, add to readyq")); 
        }
        else {
            h2_iq_add(m->q, stream->id, cmp, ctx);
            register_if_needed(m);                
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          H2_STRM_MSG(stream, "process, added to q")); 
        }
    }

    H2_MPLX_LEAVE(m);
    return status;
}

static h2_task *next_stream_task(h2_mplx *m)
{
    h2_stream *stream;
    int sid;
    while (!m->aborted && (m->tasks_active < m->limit_active)
           && (sid = h2_iq_shift(m->q)) > 0) {
        
        stream = h2_ihash_get(m->streams, sid);
        if (stream) {
            conn_rec *slave, **pslave;

            pslave = (conn_rec **)apr_array_pop(m->spare_slaves);
            if (pslave) {
                slave = *pslave;
                slave->aborted = 0;
            }
            else {
                slave = h2_slave_create(m->c, stream->id, m->pool);
            }
            
            if (!stream->task) {
                if (sid > m->max_stream_started) {
                    m->max_stream_started = sid;
                }
                if (stream->input) {
                    h2_beam_on_consumed(stream->input, stream_input_ev, 
                                        stream_input_consumed, stream);
                }
                
                stream->task = h2_task_create(slave, stream->id, 
                                              stream->request, m, stream->input, 
                                              stream->session->s->timeout,
                                              m->stream_max_mem);
                if (!stream->task) {
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, slave,
                                  H2_STRM_LOG(APLOGNO(02941), stream, 
                                  "create task"));
                    return NULL;
                }
            }
            
            stream->task->started_at = apr_time_now();
            ++m->tasks_active;
            return stream->task;
        }
    }
    return NULL;
}

apr_status_t h2_mplx_pop_task(h2_mplx *m, h2_task **ptask)
{
    apr_status_t rv = APR_EOF;
    
    *ptask = NULL;
    ap_assert(m);
    ap_assert(m->lock);
    
    if (APR_SUCCESS != (rv = apr_thread_mutex_lock(m->lock))) {
        return rv;
    }
    
    if (m->aborted) {
        rv = APR_EOF;
    }
    else {
        *ptask = next_stream_task(m);
        rv = (*ptask != NULL && !h2_iq_empty(m->q))? APR_EAGAIN : APR_SUCCESS;
    }
    if (APR_EAGAIN != rv) {
        m->is_registered = 0; /* h2_workers will discard this mplx */
    }
    H2_MPLX_LEAVE(m);
    return rv;
}

static void task_done(h2_mplx *m, h2_task *task)
{
    h2_stream *stream;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                  "h2_mplx(%ld): task(%s) done", m->id, task->id);
    out_close(m, task);
    
    task->worker_done = 1;
    task->done_at = apr_time_now();
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                  "h2_mplx(%s): request done, %f ms elapsed", task->id, 
                  (task->done_at - task->started_at) / 1000.0);
    
    if (task->c && !task->c->aborted && task->started_at > m->last_mood_change) {
        mplx_be_happy(m);
    }
    
    ap_assert(task->done_done == 0);

    stream = h2_ihash_get(m->streams, task->stream_id);
    if (stream) {
        /* stream not done yet. */
        if (!m->aborted && task->redo) {
            /* reset and schedule again */
            h2_task_redo(task);
            h2_iq_add(m->q, stream->id, NULL, NULL);
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, m->c,
                          H2_STRM_MSG(stream, "redo, added to q")); 
        }
        else {
            /* stream not cleaned up, stay around */
            task->done_done = 1;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                          H2_STRM_MSG(stream, "task_done, stream open")); 
            if (stream->input) {
                h2_beam_leave(stream->input);
            }

            /* more data will not arrive, resume the stream */
            check_data_for(m, stream, 1);            
        }
    }
    else if ((stream = h2_ihash_get(m->shold, task->stream_id)) != NULL) {
        /* stream is done, was just waiting for this. */
        task->done_done = 1;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                      H2_STRM_MSG(stream, "task_done, in hold"));
        if (stream->input) {
            h2_beam_leave(stream->input);
        }
        stream_joined(m, stream);
    }
    else if ((stream = h2_ihash_get(m->spurge, task->stream_id)) != NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c,   
                      H2_STRM_LOG(APLOGNO(03517), stream, "already in spurge"));
        ap_assert("stream should not be in spurge" == NULL);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c, APLOGNO(03518)
                      "h2_mplx(%s): task_done, stream not found", 
                      task->id);
        ap_assert("stream should still be available" == NULL);
    }
}

void h2_mplx_task_done(h2_mplx *m, h2_task *task, h2_task **ptask)
{
    H2_MPLX_ENTER_ALWAYS(m);

    --m->tasks_active;
    task_done(m, task);
    
    if (m->join_wait) {
        apr_thread_cond_signal(m->join_wait);
    }
    if (ptask) {
        /* caller wants another task */
        *ptask = next_stream_task(m);
    }
    register_if_needed(m);

    H2_MPLX_LEAVE(m);
}

/*******************************************************************************
 * h2_mplx DoS protection
 ******************************************************************************/

static int timed_out_busy_iter(void *data, void *val)
{
    stream_iter_ctx *ctx = data;
    h2_stream *stream = val;
    if (h2_task_has_started(stream->task) && !stream->task->worker_done
        && (ctx->now - stream->task->started_at) > stream->task->timeout) {
        /* timed out stream occupying a worker, found */
        ctx->stream = stream;
        return 0;
    }
    return 1;
}

static h2_stream *get_timed_out_busy_stream(h2_mplx *m) 
{
    stream_iter_ctx ctx;
    ctx.m = m;
    ctx.stream = NULL;
    ctx.now = apr_time_now();
    h2_ihash_iter(m->streams, timed_out_busy_iter, &ctx);
    return ctx.stream;
}

static int latest_repeatable_unsubmitted_iter(void *data, void *val)
{
    stream_iter_ctx *ctx = data;
    h2_stream *stream = val;
    
    if (!stream->task) goto leave;
    if (!h2_task_has_started(stream->task) || stream->task->worker_done) goto leave;
    if (h2_stream_is_ready(stream)) goto leave;
    if (stream->task->redo) {
        ++ctx->count;
        goto leave;
    }
    if (h2_task_can_redo(stream->task)) {
        /* this task occupies a worker, the response has not been submitted 
         * yet, not been cancelled and it is a repeatable request
         * -> we could redo it later */
        if (!ctx->stream 
            || (ctx->stream->task->started_at < stream->task->started_at)) {
            /* we did not have one or this one was started later */
            ctx->stream = stream;
        }
    }
leave:
    return 1;
}

static apr_status_t assess_task_to_throttle(h2_task **ptask, h2_mplx *m) 
{
    stream_iter_ctx ctx;
    
    /* count the running tasks already marked for redo and get one that could
     * be throttled */
    *ptask = NULL;
    ctx.m = m;
    ctx.stream = NULL;
    ctx.count = 0;
    h2_ihash_iter(m->streams, latest_repeatable_unsubmitted_iter, &ctx);
    if (m->tasks_active - ctx.count > m->limit_active) {
        /* we are above the limit of running tasks, accounting for the ones
         * already throttled. */
        if (ctx.stream && ctx.stream->task) {
            *ptask = ctx.stream->task;
            return APR_EAGAIN;
        }
        /* above limit, be seeing no candidate for easy throttling */
        if (get_timed_out_busy_stream(m)) {
            /* Too many busy workers, unable to cancel enough streams
             * and with a busy, timed out stream, we tell the client
             * to go away... */
            return APR_TIMEUP;
        }
    }
    return APR_SUCCESS;
}

static apr_status_t unschedule_slow_tasks(h2_mplx *m) 
{
    h2_task *task;
    apr_status_t rv;
    
    /* Try to get rid of streams that occupy workers. Look for safe requests
     * that are repeatable. If none found, fail the connection.
     */
    while (APR_EAGAIN == (rv = assess_task_to_throttle(&task, m))) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c, 
                      "h2_mplx(%s): unschedule, resetting task for redo later",
                      task->id);
        task->redo = 1;
        h2_task_rst(task, H2_ERR_CANCEL);
    }
    return rv;
}

static apr_status_t mplx_be_happy(h2_mplx *m)
{
    apr_time_t now;            

    --m->irritations_since;
    now = apr_time_now();
    if (m->limit_active < m->max_active 
        && (now - m->last_mood_change >= m->mood_update_interval
            || m->irritations_since < -m->limit_active)) {
        m->limit_active = H2MIN(m->limit_active * 2, m->max_active);
        m->last_mood_change = now;
        m->irritations_since = 0;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                      "h2_mplx(%ld): mood update, increasing worker limit to %d",
                      m->id, m->limit_active);
    }
    return APR_SUCCESS;
}

static apr_status_t mplx_be_annoyed(h2_mplx *m)
{
    apr_status_t status = APR_SUCCESS;
    apr_time_t now;            

    ++m->irritations_since;
    now = apr_time_now();
    if (m->limit_active > 2 && 
        ((now - m->last_mood_change >= m->mood_update_interval)
         || (m->irritations_since >= m->limit_active))) {
            
        if (m->limit_active > 16) {
            m->limit_active = 16;
        }
        else if (m->limit_active > 8) {
            m->limit_active = 8;
        }
        else if (m->limit_active > 4) {
            m->limit_active = 4;
        }
        else if (m->limit_active > 2) {
            m->limit_active = 2;
        }
        m->last_mood_change = now;
        m->irritations_since = 0;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                      "h2_mplx(%ld): mood update, decreasing worker limit to %d",
                      m->id, m->limit_active);
    }
    
    if (m->tasks_active > m->limit_active) {
        status = unschedule_slow_tasks(m);
    }
    return status;
}

apr_status_t h2_mplx_idle(h2_mplx *m)
{
    apr_status_t status = APR_SUCCESS;
    apr_size_t scount;
    
    H2_MPLX_ENTER(m);

    scount = h2_ihash_count(m->streams);
    if (scount > 0) {
        if (m->tasks_active) {
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
            status = mplx_be_annoyed(m);
        }
        else if (!h2_iq_empty(m->q)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          "h2_mplx(%ld): idle, but %d streams to process",
                          m->id, (int)h2_iq_count(m->q));
            status = APR_EAGAIN;
        }
        else {
            /* idle, have streams, but no tasks active. what are we waiting for?
             * WINDOW_UPDATEs from client? */
            h2_stream *stream = NULL;
            
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c,
                          "h2_mplx(%ld): idle, no tasks ongoing, %d streams",
                          m->id, (int)h2_ihash_count(m->streams));
            h2_ihash_shift(m->streams, (void**)&stream, 1);
            if (stream) {
                h2_ihash_add(m->streams, stream);
                if (stream->output && !stream->out_checked) {
                    /* FIXME: this looks like a race between the session thinking
                     * it is idle and the EOF on a stream not being sent.
                     * Signal to caller to leave IDLE state.
                     */
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c,
                                  H2_STRM_MSG(stream, "output closed=%d, mplx idle"
                                              ", out has %ld bytes buffered"),
                                  h2_beam_is_closed(stream->output),
                                  (long)h2_beam_get_buffered(stream->output));
                    h2_ihash_add(m->streams, stream);
                    check_data_for(m, stream, 1);
                    stream->out_checked = 1;
                    status = APR_EAGAIN;
                }
            }
        }
    }
    register_if_needed(m);

    H2_MPLX_LEAVE(m);
    return status;
}

/*******************************************************************************
 * mplx master events dispatching
 ******************************************************************************/

int h2_mplx_has_master_events(h2_mplx *m)
{
    return apr_atomic_read32(&m->event_pending) > 0;
}

apr_status_t h2_mplx_dispatch_master_events(h2_mplx *m, 
                                            stream_ev_callback *on_resume, 
                                            void *on_ctx)
{
    h2_stream *stream;
    int n, id;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c, 
                  "h2_mplx(%ld): dispatch events", m->id);        
    apr_atomic_set32(&m->event_pending, 0);

    /* update input windows for streams */
    h2_ihash_iter(m->streams, report_consumption_iter, m);    
    purge_streams(m, 1);
    
    n = h2_ififo_count(m->readyq);
    while (n > 0 
           && (h2_ififo_try_pull(m->readyq, &id) == APR_SUCCESS)) {
        --n;
        stream = h2_ihash_get(m->streams, id);
        if (stream) {
            on_resume(on_ctx, stream);
        }
    }
    
    return APR_SUCCESS;
}

apr_status_t h2_mplx_keep_active(h2_mplx *m, h2_stream *stream)
{
    check_data_for(m, stream, 0);
    return APR_SUCCESS;
}

int h2_mplx_awaits_data(h2_mplx *m)
{
    int waiting = 1;
     
    H2_MPLX_ENTER_ALWAYS(m);

    if (h2_ihash_empty(m->streams)) {
        waiting = 0;
    }
    else if (!m->tasks_active && !h2_ififo_count(m->readyq) && h2_iq_empty(m->q)) {
        waiting = 0;
    }

    H2_MPLX_LEAVE(m);
    return waiting;
}

apr_status_t h2_mplx_client_rst(h2_mplx *m, int stream_id)
{
    h2_stream *stream;
    apr_status_t status = APR_SUCCESS;
    
    H2_MPLX_ENTER_ALWAYS(m);
    stream = h2_ihash_get(m->streams, stream_id);
    if (stream && stream->task) {
        status = mplx_be_annoyed(m);
    }
    H2_MPLX_LEAVE(m);
    return status;
}
