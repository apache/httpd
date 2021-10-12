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
#include "h2_c1.h"
#include "h2_conn_ctx.h"
#include "h2_protocol.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_stream.h"
#include "h2_session.h"
#include "h2_c2.h"
#include "h2_workers.h"
#include "h2_util.h"


/* utility for iterating over ihash stream sets */
typedef struct {
    h2_mplx *m;
    h2_stream *stream;
    apr_time_t now;
    apr_size_t count;
} stream_iter_ctx;

static apr_status_t s_mplx_be_happy(h2_mplx *m, conn_rec *c, h2_conn_ctx_t *conn_ctx);
static apr_status_t m_be_annoyed(h2_mplx *m);

static apr_status_t mplx_pollset_create(h2_mplx *m);
static apr_status_t mplx_pollset_add(h2_mplx *m, h2_conn_ctx_t *conn_ctx);
static apr_status_t mplx_pollset_remove(h2_mplx *m, h2_conn_ctx_t *conn_ctx);
static apr_status_t mplx_pollset_poll(h2_mplx *m, apr_interval_time_t timeout,
                            stream_ev_callback *on_stream_input,
                            stream_ev_callback *on_stream_output,
                            void *on_ctx);

static apr_pool_t *pchild;

apr_status_t h2_mplx_c1_child_init(apr_pool_t *pool, server_rec *s)
{
    pchild = pool;
    return APR_SUCCESS;
}

#define H2_MPLX_ENTER(m)    \
    do { apr_status_t rv_lock; if ((rv_lock = apr_thread_mutex_lock(m->lock)) != APR_SUCCESS) {\
        return rv_lock;\
    } } while(0)

#define H2_MPLX_LEAVE(m)    \
    apr_thread_mutex_unlock(m->lock)
 
#define H2_MPLX_ENTER_ALWAYS(m)    \
    apr_thread_mutex_lock(m->lock)

#define H2_MPLX_ENTER_MAYBE(m, dolock)    \
    if (dolock) apr_thread_mutex_lock(m->lock)

#define H2_MPLX_LEAVE_MAYBE(m, dolock)    \
    if (dolock) apr_thread_mutex_unlock(m->lock)

static void c1_input_consumed(void *ctx, h2_bucket_beam *beam, apr_off_t length)
{
    h2_stream_in_consumed(ctx, length);
}

static int stream_is_running(h2_stream *stream)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(stream->c2);
    return conn_ctx && conn_ctx->started_at != 0 && !conn_ctx->done;
}

int h2_mplx_c1_stream_is_running(h2_mplx *m, h2_stream *stream)
{
    int rv;

    H2_MPLX_ENTER(m);
    rv = stream_is_running(stream);
    H2_MPLX_LEAVE(m);
    return rv;
}

static void c1c2_stream_joined(h2_mplx *m, h2_stream *stream)
{
    ap_assert(!stream_is_running(stream));
    
    h2_ihash_remove(m->shold, stream->id);
    APR_ARRAY_PUSH(m->spurge, h2_stream *) = stream;
}

static void m_stream_cleanup(h2_mplx *m, h2_stream *stream)
{
    h2_conn_ctx_t *c2_ctx = stream->c2? h2_conn_ctx_get(stream->c2) : NULL;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                  H2_STRM_MSG(stream, "cleanup, unsubscribing from beam events"));
    if (stream->output) {
        h2_beam_on_was_empty(stream->output, NULL, NULL);
    }
    if (stream->input) {
        h2_beam_on_received(stream->input, NULL, NULL);
        h2_beam_on_consumed(stream->input, NULL, NULL);
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                  H2_STRM_MSG(stream, "cleanup, removing from registries"));
    ap_assert(stream->state == H2_SS_CLEANUP);
    h2_stream_cleanup(stream);
    h2_ihash_remove(m->streams, stream->id);
    h2_iq_remove(m->q, stream->id);

    if (c2_ctx) {
        if (!stream_is_running(stream)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                          H2_STRM_MSG(stream, "cleanup, c2 is done, move to spurge"));
            /* processing has finished */
            APR_ARRAY_PUSH(m->spurge, h2_stream *) = stream;
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                          H2_STRM_MSG(stream, "cleanup, c2 is running, abort"));
            /* c2 is still running */
            stream->c2->aborted = 1;
            if (stream->input) {
                h2_beam_abort(stream->input, m->c1);
            }
            if (stream->output) {
                h2_beam_abort(stream->output, m->c1);
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                          H2_STRM_MSG(stream, "cleanup, c2 is done, move to shold"));
            h2_ihash_add(m->shold, stream);
        }
    }
    else {
        /* never started */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                      H2_STRM_MSG(stream, "cleanup, never started, move to spurge"));
        APR_ARRAY_PUSH(m->spurge, h2_stream *) = stream;
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
h2_mplx *h2_mplx_c1_create(h2_stream *stream0, server_rec *s, apr_pool_t *parent,
                          h2_workers *workers)
{
    h2_conn_ctx_t *conn_ctx;
    apr_status_t status = APR_SUCCESS;
    apr_allocator_t *allocator;
    apr_thread_mutex_t *mutex = NULL;
    h2_mplx *m = NULL;
    
    m = apr_pcalloc(parent, sizeof(h2_mplx));
    m->stream0 = stream0;
    m->c1 = stream0->c2;
    m->s = s;
    m->id = m->c1->id;

    /* We create a pool with its own allocator to be used for
     * processing secondary connections. This is the only way to have the
     * processing independent of its parent pool in the sense that it
     * can work in another thread. Also, the new allocator needs its own
     * mutex to synchronize sub-pools.
     */
    status = apr_allocator_create(&allocator);
    if (status != APR_SUCCESS) {
        allocator = NULL;
        goto failure;
    }

    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    apr_pool_create_ex(&m->pool, parent, NULL, allocator);
    if (!m->pool) goto failure;

    apr_pool_tag(m->pool, "h2_mplx");
    apr_allocator_owner_set(allocator, m->pool);

    status = apr_thread_mutex_create(&mutex, APR_THREAD_MUTEX_DEFAULT,
                                     m->pool);
    if (APR_SUCCESS != status) goto failure;
    apr_allocator_mutex_set(allocator, mutex);

    status = apr_thread_mutex_create(&m->lock, APR_THREAD_MUTEX_DEFAULT,
                                     m->pool);
    if (APR_SUCCESS != status) goto failure;

    status = apr_thread_cond_create(&m->join_wait, m->pool);
    if (APR_SUCCESS != status) goto failure;

    m->max_streams = h2_config_sgeti(s, H2_CONF_MAX_STREAMS);
    m->stream_max_mem = h2_config_sgeti(s, H2_CONF_STREAM_MAX_MEM);

    m->streams = h2_ihash_create(m->pool, offsetof(h2_stream,id));
    m->shold = h2_ihash_create(m->pool, offsetof(h2_stream,id));
    m->spurge = apr_array_make(m->pool, 10, sizeof(h2_stream*));
    m->q = h2_iq_create(m->pool, m->max_streams);

    m->workers = workers;
    m->processing_max = workers->max_workers;
    m->processing_limit = 6; /* the original h1 max parallel connections */
    m->last_mood_change = apr_time_now();
    m->mood_update_interval = apr_time_from_msec(100);

    status = mplx_pollset_create(m);
    if (APR_SUCCESS != status) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, m->c1, APLOGNO(10308)
                      "nghttp2: could not create pollset");
        goto failure;
    }
    m->streams_to_poll = apr_array_make(m->pool, 10, sizeof(h2_stream*));
    m->streams_ev_in = apr_array_make(m->pool, 10, sizeof(h2_stream*));
    m->streams_ev_out = apr_array_make(m->pool, 10, sizeof(h2_stream*));

#if !H2_POLL_STREAMS
    status = apr_thread_mutex_create(&m->poll_lock, APR_THREAD_MUTEX_DEFAULT,
                                     m->pool);
    if (APR_SUCCESS != status) goto failure;
    m->streams_input_read = h2_iq_create(m->pool, 10);
    m->streams_output_written = h2_iq_create(m->pool, 10);
#endif

    conn_ctx = h2_conn_ctx_get(m->c1);
    mplx_pollset_add(m, conn_ctx);

    return m;

failure:
    if (m->pool) {
        apr_pool_destroy(m->pool);
    }
    else if (allocator) {
        apr_allocator_destroy(allocator);
    }
    return NULL;
}

int h2_mplx_c1_shutdown(h2_mplx *m)
{
    int max_stream_id_started = 0;
    
    H2_MPLX_ENTER(m);

    max_stream_id_started = m->max_stream_id_started;
    /* Clear schedule queue, disabling existing streams from starting */ 
    h2_iq_clear(m->q);

    H2_MPLX_LEAVE(m);
    return max_stream_id_started;
}

typedef struct {
    h2_mplx_stream_cb *cb;
    void *ctx;
} stream_iter_ctx_t;

static int m_stream_iter_wrap(void *ctx, void *stream)
{
    stream_iter_ctx_t *x = ctx;
    return x->cb(stream, x->ctx);
}

apr_status_t h2_mplx_c1_streams_do(h2_mplx *m, h2_mplx_stream_cb *cb, void *ctx)
{
    stream_iter_ctx_t x;
    
    H2_MPLX_ENTER(m);

    x.cb = cb;
    x.ctx = ctx;
    h2_ihash_iter(m->streams, m_stream_iter_wrap, &x);
        
    H2_MPLX_LEAVE(m);
    return APR_SUCCESS;
}

static int m_report_stream_iter(void *ctx, void *val) {
    h2_mplx *m = ctx;
    h2_stream *stream = val;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(stream->c2);
    ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c1,
                  H2_STRM_MSG(stream, "started=%d, scheduled=%d, ready=%d, out_buffer=%ld"),
                  !!stream->c2, stream->scheduled, h2_stream_is_ready(stream),
                  (long)(stream->output? h2_beam_get_buffered(stream->output) : -1));
    if (conn_ctx) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c1, /* NO APLOGNO */
                      H2_STRM_MSG(stream, "->03198: %s %s %s"
                      "[started=%d/done=%d]"), 
                      conn_ctx->request->method, conn_ctx->request->authority,
                      conn_ctx->request->path, conn_ctx->started_at != 0,
                      conn_ctx->done);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c1, /* NO APLOGNO */
                      H2_STRM_MSG(stream, "->03198: not started"));
    }
    return 1;
}

static int m_unexpected_stream_iter(void *ctx, void *val) {
    h2_mplx *m = ctx;
    h2_stream *stream = val;
    ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c1, /* NO APLOGNO */
                  H2_STRM_MSG(stream, "unexpected, started=%d, scheduled=%d, ready=%d"), 
                  !!stream->c2, stream->scheduled, h2_stream_is_ready(stream));
    return 1;
}

static int m_stream_cancel_iter(void *ctx, void *val) {
    h2_mplx *m = ctx;
    h2_stream *stream = val;

    /* disable input consumed reporting */
    if (stream->input) {
        h2_beam_abort(stream->input, m->c1);
    }
    /* take over event monitoring */
    h2_stream_set_monitor(stream, NULL);
    /* Reset, should transit to CLOSED state */
    h2_stream_rst(stream, H2_ERR_NO_ERROR);
    /* All connection data has been sent, simulate cleanup */
    h2_stream_dispatch(stream, H2_SEV_EOS_SENT);
    m_stream_cleanup(m, stream);  
    return 0;
}

void h2_mplx_c1_destroy(h2_mplx *m)
{
    apr_status_t status;
    int i, wait_secs = 60, old_aborted;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                  "h2_mplx(%ld): start release", m->id);
    /* How to shut down a h2 connection:
     * 0. abort and tell the workers that no more work will come from us */
    m->aborted = 1;
    h2_workers_unregister(m->workers, m);
    
    H2_MPLX_ENTER_ALWAYS(m);

    /* While really terminating any c2 connections, treat the master
     * connection as aborted. It's not as if we could send any more data
     * at this point. */
    old_aborted = m->c1->aborted;
    m->c1->aborted = 1;

    /* How to shut down a h2 connection:
     * 1. cancel all streams still active */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                  "h2_mplx(%ld): release, %d/%d/%d streams (total/hold/purge), %d streams",
                  m->id, (int)h2_ihash_count(m->streams),
                  (int)h2_ihash_count(m->shold), m->spurge->nelts, m->processing_count);
    while (!h2_ihash_iter(m->streams, m_stream_cancel_iter, m)) {
        /* until empty */
    }
    
    /* 2. no more streams should be scheduled or in the active set */
    ap_assert(h2_ihash_empty(m->streams));
    ap_assert(h2_iq_empty(m->q));
    
    /* 3. while workers are busy on this connection, meaning they
     *    are processing streams from this connection, wait on them finishing
     *    in order to wake us and let us check again. 
     *    Eventually, this has to succeed. */    
    for (i = 0; h2_ihash_count(m->shold) > 0; ++i) {
        status = apr_thread_cond_timedwait(m->join_wait, m->lock, apr_time_from_sec(wait_secs));
        
        if (APR_STATUS_IS_TIMEUP(status)) {
            /* This can happen if we have very long running requests
             * that do not time out on IO. */
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c1, APLOGNO(03198)
                          "h2_mplx(%ld): waited %d sec for %d streams",
                          m->id, i*wait_secs, (int)h2_ihash_count(m->shold));
            h2_ihash_iter(m->shold, m_report_stream_iter, m);
        }
    }
    m->join_wait = NULL;

    /* 4. With all workers done, all streams should be in spurge */
    ap_assert(m->processing_count == 0);
    if (!h2_ihash_empty(m->shold)) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c1, APLOGNO(03516)
                      "h2_mplx(%ld): unexpected %d streams in hold", 
                      m->id, (int)h2_ihash_count(m->shold));
        h2_ihash_iter(m->shold, m_unexpected_stream_iter, m);
    }
    
    m->c1->aborted = old_aborted;
    H2_MPLX_LEAVE(m);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1, "h2_mplx(%ld): released", m->id);
}

apr_status_t h2_mplx_c1_stream_cleanup(h2_mplx *m, h2_stream *stream,
                                       int *pstream_count)
{
    H2_MPLX_ENTER(m);
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                  H2_STRM_MSG(stream, "cleanup"));
    m_stream_cleanup(m, stream);
    *pstream_count = (int)h2_ihash_count(m->streams);
    H2_MPLX_LEAVE(m);
    return APR_SUCCESS;
}

const h2_stream *h2_mplx_c2_stream_get(h2_mplx *m, int stream_id)
{
    h2_stream *s = NULL;
    
    H2_MPLX_ENTER_ALWAYS(m);
    s = h2_ihash_get(m->streams, stream_id);
    H2_MPLX_LEAVE(m);

    return s;
}

static void c1_purge_streams(h2_mplx *m)
{
    h2_stream *stream;
    int i;

    for (i = 0; i < m->spurge->nelts; ++i) {
        stream = APR_ARRAY_IDX(m->spurge, i, h2_stream*);
        ap_assert(stream->state == H2_SS_CLEANUP);
        if (stream->input) {
            h2_beam_destroy(stream->input, m->c1);
            stream->input = NULL;
        }
        if (stream->c2) {
            conn_rec *c2 = stream->c2;
            h2_conn_ctx_t *c2_ctx = h2_conn_ctx_get(c2);
            apr_status_t rv;

            stream->c2 = NULL;
            ap_assert(c2_ctx);
            rv = mplx_pollset_remove(m, c2_ctx);
            if (APR_SUCCESS != rv) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, m->c1,
                              "h2_mplx(%ld-%d): pollset_remove %d on purge",
                              m->id, stream->id, c2_ctx->stream_id);
            }
            h2_conn_ctx_destroy(c2);
            h2_c2_destroy(c2);
        }
        h2_stream_destroy(stream);
    }
    apr_array_clear(m->spurge);
}

apr_status_t h2_mplx_c1_poll(h2_mplx *m, apr_interval_time_t timeout,
                            stream_ev_callback *on_stream_input,
                            stream_ev_callback *on_stream_output,
                            void *on_ctx)
{
    apr_status_t rv;

    H2_MPLX_ENTER(m);

    if (m->aborted) {
        rv = APR_ECONNABORTED;
        goto cleanup;
    }
    /* Purge (destroy) streams outside of pollset processing.
     * Streams that are registered in the pollset, will be removed
     * when they are destroyed, but the pollset works on copies
     * of these registrations. So, if we destroy streams while
     * processing pollset events, we might access freed memory.
     */
    if (m->spurge->nelts) {
        c1_purge_streams(m);
    }
    rv = mplx_pollset_poll(m, timeout, on_stream_input, on_stream_output, on_ctx);

cleanup:
    H2_MPLX_LEAVE(m);
    return rv;
}

apr_status_t h2_mplx_c1_reprioritize(h2_mplx *m, h2_stream_pri_cmp_fn *cmp,
                                    h2_session *session)
{
    apr_status_t status;
    
    H2_MPLX_ENTER(m);

    if (m->aborted) {
        status = APR_ECONNABORTED;
    }
    else {
        h2_iq_sort(m->q, cmp, session);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                      "h2_mplx(%ld): reprioritize streams", m->id);
        status = APR_SUCCESS;
    }

    H2_MPLX_LEAVE(m);
    return status;
}

static void ms_register_if_needed(h2_mplx *m, int from_master)
{
    if (!m->aborted && !m->is_registered && !h2_iq_empty(m->q)) {
        apr_status_t status = h2_workers_register(m->workers, m); 
        if (status == APR_SUCCESS) {
            m->is_registered = 1;
        }
        else if (from_master) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, m->c1, APLOGNO(10021)
                          "h2_mplx(%ld): register at workers", m->id);
        }
    }
}

static apr_status_t c1_process_stream(h2_mplx *m,
                                      h2_stream *stream,
                                      h2_stream_pri_cmp_fn *cmp,
                                      h2_session *session)
{
    apr_status_t rv;

    if (m->aborted) {
        rv = APR_ECONNABORTED;
        goto cleanup;
    }
    if (!stream->request) {
        rv = APR_EINVAL;
        goto cleanup;
    }
    if (APLOGctrace1(m->c1)) {
        const h2_request *r = stream->request;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                      H2_STRM_MSG(stream, "process %s %s://%s%s chunked=%d"),
                      r->method, r->scheme, r->authority, r->path, r->chunked);
    }

    rv = h2_stream_setup_input(stream);
    if (APR_SUCCESS != rv) goto cleanup;

    stream->scheduled = 1;
    h2_ihash_add(m->streams, stream);
    if (h2_stream_is_ready(stream)) {
        /* already have a response */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                      H2_STRM_MSG(stream, "process, ready already"));
    }
    else {
        h2_iq_add(m->q, stream->id, cmp, session);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                      H2_STRM_MSG(stream, "process, added to q"));
    }

cleanup:
    return rv;
}

apr_status_t h2_mplx_c1_process(h2_mplx *m,
                                h2_iqueue *ready_to_process,
                                h2_stream_get_fn *get_stream,
                                h2_stream_pri_cmp_fn *stream_pri_cmp,
                                h2_session *session,
                                int *pstream_count)
{
    apr_status_t rv = APR_SUCCESS;
    int sid;

    H2_MPLX_ENTER(m);

    while ((sid = h2_iq_shift(ready_to_process)) > 0) {
        h2_stream *stream = get_stream(session, sid);
        if (stream) {
            ap_assert(!stream->scheduled);
            rv = c1_process_stream(session->mplx, stream, stream_pri_cmp, session);
            if (APR_SUCCESS != rv) {
                h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
            }
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                          "h2_stream(%ld-%d): not found to process", m->id, sid);
        }
    }
    ms_register_if_needed(m, 1);
    *pstream_count = (int)h2_ihash_count(m->streams);
#if APR_POOL_DEBUG
    do {
        apr_size_t mem_g, mem_m, mem_s, mem_w, mem_c1;

        mem_g = pchild? apr_pool_num_bytes(pchild, 1) : 0;
        mem_m = apr_pool_num_bytes(m->pool, 1);
        mem_s = apr_pool_num_bytes(session->pool, 1);
        mem_w = apr_pool_num_bytes(m->workers->pool, 1);
        mem_c1 = apr_pool_num_bytes(m->c1->pool, 1);
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, m->c1,
                      "h2_mplx(%ld): child mem=%ld, mplx mem=%ld, session mem=%ld, workers=%ld, c1=%ld",
                      m->id, (long)mem_g, (long)mem_m, (long)mem_s, (long)mem_w, (long)mem_c1);

    } while (0);
#endif

    H2_MPLX_LEAVE(m);
    return rv;
}

apr_status_t h2_mplx_c1_fwd_input(h2_mplx *m, struct h2_iqueue *input_pending,
                                  h2_stream_get_fn *get_stream,
                                  struct h2_session *session)
{
    int sid;

    H2_MPLX_ENTER(m);

    while ((sid = h2_iq_shift(input_pending)) > 0) {
        h2_stream *stream = get_stream(session, sid);
        if (stream) {
            H2_MPLX_LEAVE(m);
            h2_stream_flush_input(stream);
            H2_MPLX_ENTER(m);
        }
    }

    H2_MPLX_LEAVE(m);
    return APR_SUCCESS;
}

static void c2_beam_input_write_notify(void *ctx, h2_bucket_beam *beam)
{
    conn_rec *c = ctx;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);

    (void)beam;
    if (conn_ctx && conn_ctx->stream_id && conn_ctx->pipe_in_prod[H2_PIPE_IN]) {
        apr_file_putc(1, conn_ctx->pipe_in_prod[H2_PIPE_IN]);
    }
}

static void c2_beam_input_read_notify(void *ctx, h2_bucket_beam *beam)
{
    conn_rec *c = ctx;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);

    if (conn_ctx && conn_ctx->stream_id) {
        if (conn_ctx->pipe_in_drain[H2_PIPE_IN]) {
            apr_file_putc(1, conn_ctx->pipe_in_drain[H2_PIPE_IN]);
        }
#if !H2_POLL_STREAMS
        else {
            apr_thread_mutex_lock(conn_ctx->mplx->poll_lock);
            h2_iq_append(conn_ctx->mplx->streams_input_read, conn_ctx->stream_id);
            apr_pollset_wakeup(conn_ctx->mplx->pollset);
            apr_thread_mutex_unlock(conn_ctx->mplx->poll_lock);
        }
#endif
    }
}

static void c2_beam_output_write_notify(void *ctx, h2_bucket_beam *beam)
{
    conn_rec *c = ctx;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);

    if (conn_ctx && conn_ctx->stream_id) {
        if (conn_ctx->pipe_out_prod[H2_PIPE_IN]) {
            apr_file_putc(1, conn_ctx->pipe_out_prod[H2_PIPE_IN]);
        }
#if !H2_POLL_STREAMS
        else {
            apr_thread_mutex_lock(conn_ctx->mplx->poll_lock);
            h2_iq_append(conn_ctx->mplx->streams_output_written, conn_ctx->stream_id);
            apr_pollset_wakeup(conn_ctx->mplx->pollset);
            apr_thread_mutex_unlock(conn_ctx->mplx->poll_lock);
        }
#endif
    }
}

static apr_status_t c2_setup_io(h2_mplx *m, conn_rec *c2, h2_stream *stream)
{
    h2_conn_ctx_t *conn_ctx;
    apr_status_t rv = APR_SUCCESS;
    const char *action = "init";

    rv = h2_conn_ctx_init_for_c2(&conn_ctx, c2, m, stream);
    if (APR_SUCCESS != rv) goto cleanup;

    if (!conn_ctx->beam_out) {
        action = "create output beam";
        rv = h2_beam_create(&conn_ctx->beam_out, c2, conn_ctx->req_pool,
                            stream->id, "output", 0, c2->base_server->timeout);
        if (APR_SUCCESS != rv) goto cleanup;

        h2_beam_buffer_size_set(conn_ctx->beam_out, m->stream_max_mem);
        h2_beam_on_was_empty(conn_ctx->beam_out, c2_beam_output_write_notify, c2);
    }

    if (stream->input) {
        conn_ctx->beam_in = stream->input;
        h2_beam_on_was_empty(stream->input, c2_beam_input_write_notify, c2);
        h2_beam_on_received(stream->input, c2_beam_input_read_notify, c2);
        h2_beam_on_consumed(stream->input, c1_input_consumed, stream);
    }
    else {
        memset(&conn_ctx->pfd_in_drain, 0, sizeof(conn_ctx->pfd_in_drain));
    }

#if H2_POLL_STREAMS
    if (!conn_ctx->mplx_pool) {
        apr_pool_create(&conn_ctx->mplx_pool, m->pool);
        apr_pool_tag(conn_ctx->mplx_pool, "H2_MPLX_C2");
    }

    if (!conn_ctx->pipe_out_prod[H2_PIPE_OUT]) {
        action = "create output pipe";
        rv = apr_file_pipe_create_pools(&conn_ctx->pipe_out_prod[H2_PIPE_OUT],
                                        &conn_ctx->pipe_out_prod[H2_PIPE_IN],
                                        APR_FULL_NONBLOCK,
                                        conn_ctx->mplx_pool, c2->pool);
        if (APR_SUCCESS != rv) goto cleanup;
    }
    conn_ctx->pfd_out_prod.desc_type = APR_POLL_FILE;
    conn_ctx->pfd_out_prod.desc.f = conn_ctx->pipe_out_prod[H2_PIPE_OUT];
    conn_ctx->pfd_out_prod.reqevents = APR_POLLIN | APR_POLLERR | APR_POLLHUP;
    conn_ctx->pfd_out_prod.client_data = conn_ctx;

    if (stream->input) {
        if (!conn_ctx->pipe_in_prod[H2_PIPE_OUT]) {
            action = "create input write pipe";
            rv = apr_file_pipe_create_pools(&conn_ctx->pipe_in_prod[H2_PIPE_OUT],
                                            &conn_ctx->pipe_in_prod[H2_PIPE_IN],
                                            APR_READ_BLOCK,
                                            c2->pool, conn_ctx->mplx_pool);
            if (APR_SUCCESS != rv) goto cleanup;
        }
        if (!conn_ctx->pipe_in_drain[H2_PIPE_OUT]) {
            action = "create input read pipe";
            rv = apr_file_pipe_create_pools(&conn_ctx->pipe_in_drain[H2_PIPE_OUT],
                                            &conn_ctx->pipe_in_drain[H2_PIPE_IN],
                                            APR_FULL_NONBLOCK,
                                            c2->pool, conn_ctx->mplx_pool);
            if (APR_SUCCESS != rv) goto cleanup;
        }
        conn_ctx->pfd_in_drain.desc_type = APR_POLL_FILE;
        conn_ctx->pfd_in_drain.desc.f = conn_ctx->pipe_in_drain[H2_PIPE_OUT];
        conn_ctx->pfd_in_drain.reqevents = APR_POLLIN | APR_POLLERR | APR_POLLHUP;
        conn_ctx->pfd_in_drain.client_data = conn_ctx;
    }
#else
    memset(&conn_ctx->pfd_out_prod, 0, sizeof(conn_ctx->pfd_out_prod));
    memset(&conn_ctx->pipe_in_prod, 0, sizeof(conn_ctx->pipe_in_prod));
    memset(&conn_ctx->pipe_in_drain, 0, sizeof(conn_ctx->pipe_in_drain));
#endif

cleanup:
    stream->output = (APR_SUCCESS == rv)? conn_ctx->beam_out : NULL;
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c2,
                      H2_STRM_LOG(APLOGNO(10309), stream,
                      "error %s"), action);
    }
    return rv;
}

static conn_rec *s_next_c2(h2_mplx *m)
{
    h2_stream *stream = NULL;
    apr_status_t rv;
    int sid;
    conn_rec *c2;

    while (!m->aborted && !stream && (m->processing_count < m->processing_limit)
           && (sid = h2_iq_shift(m->q)) > 0) {
        stream = h2_ihash_get(m->streams, sid);
    }

    if (!stream) {
        if (m->processing_count >= m->processing_limit && !h2_iq_empty(m->q)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c1,
                          "h2_session(%ld): delaying request processing. "
                          "Current limit is %d and %d workers are in use.",
                          m->id, m->processing_limit, m->processing_count);
        }
        return NULL;
    }

    if (sid > m->max_stream_id_started) {
        m->max_stream_id_started = sid;
    }

    c2 = h2_c2_create(m->c1, m->pool);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, m->c1,
                  H2_STRM_MSG(stream, "created new c2"));

    rv = c2_setup_io(m, c2, stream);
    if (APR_SUCCESS != rv) {
        return NULL;
    }

    stream->c2 = c2;
    ++m->processing_count;
    APR_ARRAY_PUSH(m->streams_to_poll, h2_stream *) = stream;
    apr_pollset_wakeup(m->pollset);

    return c2;
}

apr_status_t h2_mplx_worker_pop_c2(h2_mplx *m, conn_rec **out_c)
{
    apr_status_t rv = APR_EOF;
    
    *out_c = NULL;
    ap_assert(m);
    ap_assert(m->lock);
    
    if (APR_SUCCESS != (rv = apr_thread_mutex_lock(m->lock))) {
        return rv;
    }
    
    if (m->aborted) {
        rv = APR_EOF;
    }
    else {
        *out_c = s_next_c2(m);
        rv = (*out_c != NULL && !h2_iq_empty(m->q))? APR_EAGAIN : APR_SUCCESS;
    }
    if (APR_EAGAIN != rv) {
        m->is_registered = 0; /* h2_workers will discard this mplx */
    }
    H2_MPLX_LEAVE(m);
    return rv;
}

static void s_c2_done(h2_mplx *m, conn_rec *c2, h2_conn_ctx_t *conn_ctx)
{
    h2_stream *stream;

    ap_assert(conn_ctx);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                  "h2_mplx(%s-%d): c2 done", conn_ctx->id, conn_ctx->stream_id);

    ap_assert(conn_ctx->done == 0);
    conn_ctx->done = 1;
    conn_ctx->done_at = apr_time_now();
    ++c2->keepalives;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c2,
                  "h2_mplx(%s-%d): request done, %f ms elapsed",
                  conn_ctx->id, conn_ctx->stream_id,
                  (conn_ctx->done_at - conn_ctx->started_at) / 1000.0);
    
    if (!conn_ctx->has_final_response) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, conn_ctx->last_err, c2,
                      "h2_c2(%s-%d): processing finished without final response",
                      conn_ctx->id, conn_ctx->stream_id);
        c2->aborted = 1;
    }
    else if (!c2->aborted && conn_ctx->started_at > m->last_mood_change) {
        s_mplx_be_happy(m, c2, conn_ctx);
    }
    
    stream = h2_ihash_get(m->streams, conn_ctx->stream_id);
    if (stream) {
        /* stream not done yet. trigger a potential polling on the output
         * since nothing more will happening here. */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c2,
                      H2_STRM_MSG(stream, "c2_done, stream open"));
        c2_beam_output_write_notify(c2, NULL);
    }
    else if ((stream = h2_ihash_get(m->shold, conn_ctx->stream_id)) != NULL) {
        /* stream is done, was just waiting for this. */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c2,
                      H2_STRM_MSG(stream, "c2_done, in hold"));
        c1c2_stream_joined(m, stream);
    }
    else {
        int i;

        for (i = 0; i < m->spurge->nelts; ++i) {
            if (stream == APR_ARRAY_IDX(m->spurge, i, h2_stream*)) {
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c2,
                              H2_STRM_LOG(APLOGNO(03517), stream, "already in spurge"));
                ap_assert("stream should not be in spurge" == NULL);
                return;
            }
        }

        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c2, APLOGNO(03518)
                      "h2_mplx(%s-%d): c2_done, stream not found",
                      conn_ctx->id, conn_ctx->stream_id);
        ap_assert("stream should still be available" == NULL);
    }
}

void h2_mplx_worker_c2_done(conn_rec *c2, conn_rec **out_c2)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c2);
    h2_mplx *m;

    if (!conn_ctx || !conn_ctx->mplx) return;
    m = conn_ctx->mplx;

    H2_MPLX_ENTER_ALWAYS(m);

    --m->processing_count;
    s_c2_done(m, c2, conn_ctx);
    
    if (m->join_wait) {
        apr_thread_cond_signal(m->join_wait);
    }
    if (out_c2) {
        /* caller wants another connection to process */
        *out_c2 = s_next_c2(m);
    }
    ms_register_if_needed(m, 0);

    H2_MPLX_LEAVE(m);
}

/*******************************************************************************
 * h2_mplx DoS protection
 ******************************************************************************/

static apr_status_t s_mplx_be_happy(h2_mplx *m, conn_rec *c, h2_conn_ctx_t *conn_ctx)
{
    apr_time_t now;            

    --m->irritations_since;
    now = apr_time_now();
    if (m->processing_limit < m->processing_max
        && (now - m->last_mood_change >= m->mood_update_interval
            || m->irritations_since < -m->processing_limit)) {
        m->processing_limit = H2MIN(m->processing_limit * 2, m->processing_max);
        m->last_mood_change = now;
        m->irritations_since = 0;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_mplx(%ld): mood update, increasing worker limit to %d",
                      m->id, m->processing_limit);
    }
    return APR_SUCCESS;
}

static apr_status_t m_be_annoyed(h2_mplx *m)
{
    apr_status_t status = APR_SUCCESS;
    apr_time_t now;            

    ++m->irritations_since;
    now = apr_time_now();
    if (m->processing_limit > 2 &&
        ((now - m->last_mood_change >= m->mood_update_interval)
         || (m->irritations_since >= m->processing_limit))) {
            
        if (m->processing_limit > 16) {
            m->processing_limit = 16;
        }
        else if (m->processing_limit > 8) {
            m->processing_limit = 8;
        }
        else if (m->processing_limit > 4) {
            m->processing_limit = 4;
        }
        else if (m->processing_limit > 2) {
            m->processing_limit = 2;
        }
        m->last_mood_change = now;
        m->irritations_since = 0;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                      "h2_mplx(%ld): mood update, decreasing worker limit to %d",
                      m->id, m->processing_limit);
    }
    return status;
}

/*******************************************************************************
 * mplx master events dispatching
 ******************************************************************************/

static int reset_is_acceptable(h2_stream *stream)
{
    /* client may terminate a stream via H2 RST_STREAM message at any time.
     * This is annyoing when we have committed resources (e.g. worker threads)
     * to it, so our mood (e.g. willingness to commit resources on this
     * connection in the future) goes down.
     *
     * This is a DoS protection. We do not want to make it too easy for
     * a client to eat up server resources.
     *
     * However: there are cases where a RST_STREAM is the only way to end
     * a request. This includes websockets and server-side-event streams (SSEs).
     * The responses to such requests continue forever otherwise.
     *
     */
    if (!stream_is_running(stream)) return 1;
    if (!(stream->id & 0x01)) return 1; /* stream initiated by us. acceptable. */
    if (!stream->response) return 0; /* no response headers produced yet. bad. */
    if (!stream->out_data_frames) return 0; /* no response body data sent yet. bad. */
    return 1; /* otherwise, be forgiving */
}

apr_status_t h2_mplx_c1_client_rst(h2_mplx *m, int stream_id)
{
    h2_stream *stream;
    apr_status_t status = APR_SUCCESS;

    H2_MPLX_ENTER_ALWAYS(m);
    stream = h2_ihash_get(m->streams, stream_id);
    if (stream && !reset_is_acceptable(stream)) {
        status = m_be_annoyed(m);
    }
    H2_MPLX_LEAVE(m);
    return status;
}

static apr_status_t mplx_pollset_create(h2_mplx *m)
{
    int max_pdfs;

    /* stream0 output, pdf_out+pfd_in_consume per active streams */
    max_pdfs = 1 + 2 * H2MIN(m->processing_max, m->max_streams);
    return apr_pollset_create(&m->pollset, max_pdfs, m->pool,
                              APR_POLLSET_WAKEABLE);
}

static apr_status_t mplx_pollset_add(h2_mplx *m, h2_conn_ctx_t *conn_ctx)
{
    apr_status_t rv = APR_SUCCESS;
    const char *name = "";

    if (conn_ctx->pfd_out_prod.reqevents) {
        name = "adding out";
        rv = apr_pollset_add(m->pollset, &conn_ctx->pfd_out_prod);
        if (APR_SUCCESS != rv) goto cleanup;
    }

    if (conn_ctx->pfd_in_drain.reqevents) {
        name = "adding in_read";
        rv = apr_pollset_add(m->pollset, &conn_ctx->pfd_in_drain);
    }

cleanup:
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, m->c1,
                      "h2_mplx(%ld-%d): error while adding to pollset %s",
                      m->id, conn_ctx->stream_id, name);
    }
    return rv;
}

static apr_status_t mplx_pollset_remove(h2_mplx *m, h2_conn_ctx_t *conn_ctx)
{
    apr_status_t rv = APR_SUCCESS;
    const char *name = "";

    if (conn_ctx->pfd_out_prod.reqevents) {
        rv = apr_pollset_remove(m->pollset, &conn_ctx->pfd_out_prod);
        conn_ctx->pfd_out_prod.reqevents = 0;
        if (APR_SUCCESS != rv) goto cleanup;
    }

    if (conn_ctx->pfd_in_drain.reqevents) {
        name = "in_read";
        rv = apr_pollset_remove(m->pollset, &conn_ctx->pfd_in_drain);
        conn_ctx->pfd_in_drain.reqevents = 0;
        if (APR_SUCCESS != rv) goto cleanup;
    }

cleanup:
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, m->c1,
                      "h2_mplx(%ld-%d): error removing from pollset %s",
                      m->id, conn_ctx->stream_id, name);
    }
    return rv;
}

static apr_status_t mplx_pollset_poll(h2_mplx *m, apr_interval_time_t timeout,
                            stream_ev_callback *on_stream_input,
                            stream_ev_callback *on_stream_output,
                            void *on_ctx)
{
    apr_status_t rv;
    const apr_pollfd_t *results, *pfd;
    apr_int32_t nresults, i;
    h2_conn_ctx_t *conn_ctx;
    h2_stream *stream;

    /* Make sure we are not called recursively. */
    ap_assert(!m->polling);
    m->polling = 1;
    do {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                      "h2_mplx(%ld): enter polling timeout=%d",
                      m->id, (int)apr_time_sec(timeout));

        apr_array_clear(m->streams_ev_in);
        apr_array_clear(m->streams_ev_out);

        do {
            /* add streams we started processing in the meantime */
            if (m->streams_to_poll->nelts) {
                for (i = 0; i < m->streams_to_poll->nelts; ++i) {
                    stream = APR_ARRAY_IDX(m->streams_to_poll, i, h2_stream*);
                    if (stream && stream->c2 && (conn_ctx = h2_conn_ctx_get(stream->c2))) {
                        mplx_pollset_add(m, conn_ctx);
                    }
                }
                apr_array_clear(m->streams_to_poll);
            }

#if !H2_POLL_STREAMS
            apr_thread_mutex_lock(m->poll_lock);
            if (!h2_iq_empty(m->streams_input_read)
                || !h2_iq_empty(m->streams_output_written)) {
                while ((i = h2_iq_shift(m->streams_input_read))) {
                    stream = h2_ihash_get(m->streams, i);
                    if (stream) {
                        APR_ARRAY_PUSH(m->streams_ev_in, h2_stream*) = stream;
                    }
                }
                while ((i = h2_iq_shift(m->streams_output_written))) {
                    stream = h2_ihash_get(m->streams, i);
                    if (stream) {
                        APR_ARRAY_PUSH(m->streams_ev_out, h2_stream*) = stream;
                    }
                }
                nresults = 0;
                rv = APR_SUCCESS;
                apr_thread_mutex_unlock(m->poll_lock);
                break;
            }
            apr_thread_mutex_unlock(m->poll_lock);
#endif
            H2_MPLX_LEAVE(m);
            rv = apr_pollset_poll(m->pollset, timeout >= 0? timeout : -1, &nresults, &results);
            H2_MPLX_ENTER_ALWAYS(m);

        } while (APR_STATUS_IS_EINTR(rv));

        if (APR_SUCCESS != rv) {
            if (APR_STATUS_IS_TIMEUP(rv)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                              "h2_mplx(%ld): polling timed out ",
                              m->id);
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, m->c1, APLOGNO(10310)
                              "h2_mplx(%ld): polling failed", m->id);
            }
            goto cleanup;
        }

        for (i = 0; i < nresults; i++) {
            pfd = &results[i];
            conn_ctx = pfd->client_data;

            ap_assert(conn_ctx);
            if (conn_ctx->stream_id == 0) {
                if (on_stream_input) {
                    APR_ARRAY_PUSH(m->streams_ev_in, h2_stream*) = m->stream0;
                }
                continue;
            }

            h2_util_drain_pipe(pfd->desc.f);
            stream = h2_ihash_get(m->streams, conn_ctx->stream_id);
            if (!stream) {
                stream = h2_ihash_get(m->shold, conn_ctx->stream_id);
                if (stream) {
                    /* This is normal and means that stream processing on c1 has
                     * already finished to CLEANUP and c2 is not done yet */
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, m->c1,
                                  "h2_mplx(%ld-%d): stream already in hold for poll event %hx",
                                   m->id, conn_ctx->stream_id, pfd->rtnevents);
                }
                else {
                    h2_stream *sp = NULL;
                    int j;

                    for (j = 0; j < m->spurge->nelts; ++j) {
                        sp = APR_ARRAY_IDX(m->spurge, j, h2_stream*);
                        if (sp->id == conn_ctx->stream_id) {
                            stream = sp;
                            break;
                        }
                    }

                    if (stream) {
                        /* This is normal and means that stream processing on c1 has
                         * already finished to CLEANUP and c2 is not done yet */
                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, m->c1, APLOGNO(10311)
                                      "h2_mplx(%ld-%d): stream already in purge for poll event %hx",
                                       m->id, conn_ctx->stream_id, pfd->rtnevents);
                    }
                    else {
                        /* This should not happen. When a stream has been purged,
                         * it MUST no longer appear in the pollset. Puring is done
                         * outside the poll result processing. */
                        ap_log_cerror(APLOG_MARK, APLOG_WARNING, rv, m->c1, APLOGNO(10312)
                                      "h2_mplx(%ld-%d): stream no longer known for poll event %hx"
                                      ", m->streams=%d, conn_ctx=%lx, fd=%lx",
                                       m->id, conn_ctx->stream_id, pfd->rtnevents,
                                       (int)h2_ihash_count(m->streams),
                                       (long)conn_ctx, (long)pfd->desc.f);
                        h2_ihash_iter(m->streams, m_report_stream_iter, m);
                    }
                }
                continue;
            }

            if (conn_ctx->pfd_out_prod.desc.f == pfd->desc.f) {
                /* output is available */
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                              "[%s-%d] poll output event %hx",
                              conn_ctx->id, conn_ctx->stream_id,
                              pfd->rtnevents);
                APR_ARRAY_PUSH(m->streams_ev_out, h2_stream*) = stream;
            }
            else if (conn_ctx->pfd_in_drain.desc.f == pfd->desc.f) {
                /* input has been consumed */
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                              "[%s-%d] poll input event %hx",
                              conn_ctx->id, conn_ctx->stream_id,
                              pfd->rtnevents);
                APR_ARRAY_PUSH(m->streams_ev_in, h2_stream*) = stream;
            }
        }

        if (on_stream_input && m->streams_ev_in->nelts) {
            H2_MPLX_LEAVE(m);
            for (i = 0; i < m->streams_ev_in->nelts; ++i) {
                on_stream_input(on_ctx, APR_ARRAY_IDX(m->streams_ev_in, i, h2_stream*));
            }
            H2_MPLX_ENTER_ALWAYS(m);
        }
        if (on_stream_output && m->streams_ev_out->nelts) {
            H2_MPLX_LEAVE(m);
            for (i = 0; i < m->streams_ev_out->nelts; ++i) {
                on_stream_output(on_ctx, APR_ARRAY_IDX(m->streams_ev_out, i, h2_stream*));
            }
            H2_MPLX_ENTER_ALWAYS(m);
        }
        break;
    } while(1);

cleanup:
    m->polling = 0;
    return rv;
}

