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
#include <http_connection.h>
#include <http_log.h>
#include <http_protocol.h>

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

static conn_rec *c2_prod_next(void *baton, int *phas_more);
static void c2_prod_done(void *baton, conn_rec *c2);
static void workers_shutdown(void *baton, int graceful);

static void s_mplx_be_happy(h2_mplx *m, conn_rec *c, h2_conn_ctx_t *conn_ctx);
static void m_be_annoyed(h2_mplx *m);

static apr_status_t mplx_pollset_create(h2_mplx *m);
static apr_status_t mplx_pollset_poll(h2_mplx *m, apr_interval_time_t timeout,
                            stream_ev_callback *on_stream_input,
                            stream_ev_callback *on_stream_output,
                            void *on_ctx);

static apr_pool_t *pchild;

/* APR callback invoked if allocation fails. */
static int abort_on_oom(int retcode)
{
    ap_abort_on_oom();
    return retcode; /* unreachable, hopefully. */
}

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
    return conn_ctx && apr_atomic_read32(&conn_ctx->started) != 0
        && apr_atomic_read32(&conn_ctx->done) == 0;
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
    h2_conn_ctx_t *c2_ctx = h2_conn_ctx_get(stream->c2);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                  H2_STRM_MSG(stream, "cleanup, unsubscribing from beam events"));
    if (c2_ctx) {
        if (c2_ctx->beam_out) {
            h2_beam_on_was_empty(c2_ctx->beam_out, NULL, NULL);
        }
        if (c2_ctx->beam_in) {
            h2_beam_on_send(c2_ctx->beam_in, NULL, NULL);
            h2_beam_on_received(c2_ctx->beam_in, NULL, NULL);
            h2_beam_on_eagain(c2_ctx->beam_in, NULL, NULL);
            h2_beam_on_consumed(c2_ctx->beam_in, NULL, NULL);
        }
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
            h2_c2_abort(stream->c2, m->c1);
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

static h2_c2_transit *c2_transit_create(h2_mplx *m)
{
    apr_allocator_t *allocator;
    apr_pool_t *ptrans;
    h2_c2_transit *transit;
    apr_status_t rv;

    /* We create a pool with its own allocator to be used for
     * processing a request. This is the only way to have the processing
     * independent of its parent pool in the sense that it can work in
     * another thread.
     */

    rv = apr_allocator_create(&allocator);
    if (rv == APR_SUCCESS) {
        apr_allocator_max_free_set(allocator, ap_max_mem_free);
        rv = apr_pool_create_ex(&ptrans, m->pool, NULL, allocator);
    }
    if (rv != APR_SUCCESS) {
        /* maybe the log goes through, maybe not. */
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, m->c1,
                      APLOGNO(10004) "h2_mplx: create transit pool");
        ap_abort_on_oom();
        return NULL; /* should never be reached. */
    }

    apr_allocator_owner_set(allocator, ptrans);
    apr_pool_abort_set(abort_on_oom, ptrans);
    apr_pool_tag(ptrans, "h2_c2_transit");

    transit = apr_pcalloc(ptrans, sizeof(*transit));
    transit->pool = ptrans;
    transit->bucket_alloc = apr_bucket_alloc_create(ptrans);
    return transit;
}

static void c2_transit_destroy(h2_c2_transit *transit)
{
    apr_pool_destroy(transit->pool);
}

static h2_c2_transit *c2_transit_get(h2_mplx *m)
{
    h2_c2_transit **ptransit = apr_array_pop(m->c2_transits);
    if (ptransit) {
        return *ptransit;
    }
    return c2_transit_create(m);
}

static void c2_transit_recycle(h2_mplx *m, h2_c2_transit *transit)
{
    if (m->c2_transits->nelts >= APR_INT32_MAX ||
        (apr_uint32_t)m->c2_transits->nelts >= m->max_spare_transits) {
        c2_transit_destroy(transit);
    }
    else {
        APR_ARRAY_PUSH(m->c2_transits, h2_c2_transit*) = transit;
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
h2_mplx *h2_mplx_c1_create(int child_num, apr_uint32_t id, h2_stream *stream0,
                           server_rec *s, apr_pool_t *parent,
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
    m->child_num = child_num;
    m->id = id;

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

    m->max_streams = h2_config_sgeti(s, H2_CONF_MAX_STREAMS);
    m->stream_max_mem = h2_config_sgeti(s, H2_CONF_STREAM_MAX_MEM);

    m->streams = h2_ihash_create(m->pool, offsetof(h2_stream,id));
    m->shold = h2_ihash_create(m->pool, offsetof(h2_stream,id));
    m->spurge = apr_array_make(m->pool, 10, sizeof(h2_stream*));
    m->q = h2_iq_create(m->pool, m->max_streams);

    m->workers = workers;
    m->processing_max = H2MIN(h2_workers_get_max_workers(workers), m->max_streams);
    m->processing_limit = 6; /* the original h1 max parallel connections */
    m->last_mood_change = apr_time_now();
    m->mood_update_interval = apr_time_from_msec(100);

    status = mplx_pollset_create(m);
    if (APR_SUCCESS != status) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, m->c1, APLOGNO(10308)
                      "nghttp2: could not create pollset");
        goto failure;
    }
    m->streams_ev_in = apr_array_make(m->pool, 10, sizeof(h2_stream*));
    m->streams_ev_out = apr_array_make(m->pool, 10, sizeof(h2_stream*));

    m->streams_input_read = h2_iq_create(m->pool, 10);
    m->streams_output_written = h2_iq_create(m->pool, 10);
    status = apr_thread_mutex_create(&m->poll_lock, APR_THREAD_MUTEX_DEFAULT,
                                     m->pool);
    if (APR_SUCCESS != status) goto failure;

    conn_ctx = h2_conn_ctx_get(m->c1);
    if (conn_ctx->pfd.reqevents) {
        apr_pollset_add(m->pollset, &conn_ctx->pfd);
    }

    m->max_spare_transits = 3;
    m->c2_transits = apr_array_make(m->pool, (int)m->max_spare_transits,
                                    sizeof(h2_c2_transit*));

    m->producer = h2_workers_register(workers, m->pool,
                                      apr_psprintf(m->pool, "h2-%u",
                                      (unsigned int)m->id),
                                      c2_prod_next, c2_prod_done,
                                      workers_shutdown, m);
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

typedef struct {
    int stream_count;
    int stream_want_send;
} stream_iter_aws_t;

static int m_stream_want_send_data(void *ctx, void *stream)
{
    stream_iter_aws_t *x = ctx;
    ++x->stream_count;
    if (h2_stream_wants_send_data(stream))
      ++x->stream_want_send;
    return 1;
}

int h2_mplx_c1_all_streams_want_send_data(h2_mplx *m)
{
    stream_iter_aws_t x;
    x.stream_count = 0;
    x.stream_want_send = 0;
    H2_MPLX_ENTER(m);
    h2_ihash_iter(m->streams, m_stream_want_send_data, &x);
    H2_MPLX_LEAVE(m);
    return x.stream_count && (x.stream_count == x.stream_want_send);
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
                      "[started=%u/done=%u]"),
                      conn_ctx->request->method, conn_ctx->request->authority,
                      conn_ctx->request->path,
                      apr_atomic_read32(&conn_ctx->started),
                      apr_atomic_read32(&conn_ctx->done));
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

    /* take over event monitoring */
    h2_stream_set_monitor(stream, NULL);
    /* Reset, should transit to CLOSED state */
    h2_stream_rst(stream, H2_ERR_NO_ERROR);
    /* All connection data has been sent, simulate cleanup */
    h2_stream_dispatch(stream, H2_SEV_EOS_SENT);
    m_stream_cleanup(m, stream);  
    return 0;
}

static void c1_purge_streams(h2_mplx *m);

void h2_mplx_c1_destroy(h2_mplx *m)
{
    apr_status_t status;
    unsigned int i, wait_secs = 60;
    int old_aborted;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                  H2_MPLX_MSG(m, "start release"));
    /* How to shut down a h2 connection:
     * 0. abort and tell the workers that no more work will come from us */
    m->shutdown = m->aborted = 1;

    H2_MPLX_ENTER_ALWAYS(m);

    /* While really terminating any c2 connections, treat the master
     * connection as aborted. It's not as if we could send any more data
     * at this point. */
    old_aborted = m->c1->aborted;
    m->c1->aborted = 1;

    /* How to shut down a h2 connection:
     * 1. cancel all streams still active */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                  H2_MPLX_MSG(m, "release, %u/%u/%d streams (total/hold/purge), %d streams"),
                  h2_ihash_count(m->streams),
                  h2_ihash_count(m->shold),
                  m->spurge->nelts, m->processing_count);
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
    if (!m->join_wait) {
        apr_thread_cond_create(&m->join_wait, m->pool);
    }

    for (i = 0; h2_ihash_count(m->shold) > 0; ++i) {
        status = apr_thread_cond_timedwait(m->join_wait, m->lock, apr_time_from_sec(wait_secs));
        
        if (APR_STATUS_IS_TIMEUP(status)) {
            /* This can happen if we have very long running requests
             * that do not time out on IO. */
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c1, APLOGNO(03198)
                          H2_MPLX_MSG(m, "waited %u sec for %u streams"),
                          i*wait_secs, h2_ihash_count(m->shold));
            h2_ihash_iter(m->shold, m_report_stream_iter, m);
        }
    }

    H2_MPLX_LEAVE(m);
    h2_workers_join(m->workers, m->producer);
    H2_MPLX_ENTER_ALWAYS(m);

    /* 4. With all workers done, all streams should be in spurge */
    ap_assert(m->processing_count == 0);
    if (!h2_ihash_empty(m->shold)) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, m->c1, APLOGNO(03516)
                      H2_MPLX_MSG(m, "unexpected %u streams in hold"),
                      h2_ihash_count(m->shold));
        h2_ihash_iter(m->shold, m_unexpected_stream_iter, m);
    }

    c1_purge_streams(m);

    m->c1->aborted = old_aborted;
    H2_MPLX_LEAVE(m);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                  H2_MPLX_MSG(m, "released"));
}

apr_status_t h2_mplx_c1_stream_cleanup(h2_mplx *m, h2_stream *stream,
                                       unsigned int *pstream_count)
{
    H2_MPLX_ENTER(m);
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                  H2_STRM_MSG(stream, "cleanup"));
    m_stream_cleanup(m, stream);
    *pstream_count = h2_ihash_count(m->streams);
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
            h2_c2_transit *transit;

            stream->c2 = NULL;
            ap_assert(c2_ctx);
            transit = c2_ctx->transit;
            h2_c2_destroy(c2);  /* c2_ctx is gone as well */
            if (transit) {
                c2_transit_recycle(m, transit);
            }
        }
        h2_stream_destroy(stream);
    }
    apr_array_clear(m->spurge);
}

void h2_mplx_c1_going_keepalive(h2_mplx *m)
{
    H2_MPLX_ENTER_ALWAYS(m);
    if (m->spurge->nelts) {
        c1_purge_streams(m);
    }
    H2_MPLX_LEAVE(m);
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
                      H2_MPLX_MSG(m, "reprioritize streams"));
        status = APR_SUCCESS;
    }

    H2_MPLX_LEAVE(m);
    return status;
}

static apr_status_t c1_process_stream(h2_mplx *m,
                                      h2_stream *stream,
                                      h2_stream_pri_cmp_fn *cmp,
                                      h2_session *session)
{
    apr_status_t rv = APR_SUCCESS;

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
                      H2_STRM_MSG(stream, "process %s%s%s %s%s%s%s"),
                      r->protocol? r->protocol : "",
                      r->protocol? " " : "",
                      r->method, r->scheme? r->scheme : "",
                      r->scheme? "://" : "",
                      r->authority, r->path? r->path: "");
    }

    stream->scheduled = 1;
    h2_ihash_add(m->streams, stream);
    if (h2_stream_is_ready(stream)) {
        /* already have a response */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                      H2_STRM_MSG(stream, "process, ready already"));
    }
    else {
        /* last chance to set anything up before stream is processed
         * by worker threads. */
        rv = h2_stream_prepare_processing(stream);
        if (APR_SUCCESS != rv) goto cleanup;
        h2_iq_add(m->q, stream->id, cmp, session);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, m->c1,
                      H2_STRM_MSG(stream, "process, added to q"));
    }

cleanup:
    return rv;
}

void h2_mplx_c1_process(h2_mplx *m,
                        h2_iqueue *ready_to_process,
                        h2_stream_get_fn *get_stream,
                        h2_stream_pri_cmp_fn *stream_pri_cmp,
                        h2_session *session,
                        unsigned int *pstream_count)
{
    apr_status_t rv;
    int sid;

    H2_MPLX_ENTER_ALWAYS(m);

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
                          H2_MPLX_MSG(m, "stream %d not found to process"), sid);
        }
    }
    if ((m->processing_count < m->processing_limit) && !h2_iq_empty(m->q)) {
        H2_MPLX_LEAVE(m);
        rv = h2_workers_activate(m->workers, m->producer);
        H2_MPLX_ENTER_ALWAYS(m);
        if (rv != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, m->c1, APLOGNO(10021)
                          H2_MPLX_MSG(m, "activate at workers"));
        }
    }
    *pstream_count = h2_ihash_count(m->streams);

#if APR_POOL_DEBUG
    do {
        apr_size_t mem_g, mem_m, mem_s, mem_c1;

        mem_g = pchild? apr_pool_num_bytes(pchild, 1) : 0;
        mem_m = apr_pool_num_bytes(m->pool, 1);
        mem_s = apr_pool_num_bytes(session->pool, 1);
        mem_c1 = apr_pool_num_bytes(m->c1->pool, 1);
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, m->c1,
                      H2_MPLX_MSG(m, "child mem=%ld, mplx mem=%ld, session mem=%ld, c1=%ld"),
                      (long)mem_g, (long)mem_m, (long)mem_s, (long)mem_c1);

    } while (0);
#endif

    H2_MPLX_LEAVE(m);
}

static void c2_beam_input_write_notify(void *ctx, h2_bucket_beam *beam)
{
    conn_rec *c = ctx;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);

    (void)beam;
    if (conn_ctx && conn_ctx->stream_id && conn_ctx->pipe_in[H2_PIPE_IN]) {
        apr_file_putc(1, conn_ctx->pipe_in[H2_PIPE_IN]);
    }
}

static void add_stream_poll_event(h2_mplx *m, int stream_id, h2_iqueue *q)
{
    apr_thread_mutex_lock(m->poll_lock);
    if (h2_iq_append(q, stream_id) && h2_iq_count(q) == 1) {
        /* newly added first */
        apr_pollset_wakeup(m->pollset);
    }
    apr_thread_mutex_unlock(m->poll_lock);
}

static void c2_beam_input_read_notify(void *ctx, h2_bucket_beam *beam)
{
    conn_rec *c = ctx;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);

    if (conn_ctx && conn_ctx->stream_id) {
        add_stream_poll_event(conn_ctx->mplx, conn_ctx->stream_id,
                              conn_ctx->mplx->streams_input_read);
    }
}

static void c2_beam_input_read_eagain(void *ctx, h2_bucket_beam *beam)
{
    conn_rec *c = ctx;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);
    /* installed in the input bucket beams when we use pipes.
     * Drain the pipe just before the beam returns APR_EAGAIN.
     * A clean state for allowing polling on the pipe to rest
     * when the beam is empty */
    if (conn_ctx && conn_ctx->pipe_in[H2_PIPE_OUT]) {
        h2_util_drain_pipe(conn_ctx->pipe_in[H2_PIPE_OUT]);
    }
}

static void c2_beam_output_write_notify(void *ctx, h2_bucket_beam *beam)
{
    conn_rec *c = ctx;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);

    if (conn_ctx && conn_ctx->stream_id) {
        add_stream_poll_event(conn_ctx->mplx, conn_ctx->stream_id,
                              conn_ctx->mplx->streams_output_written);
    }
}

static apr_status_t c2_setup_io(h2_mplx *m, conn_rec *c2, h2_stream *stream, h2_c2_transit *transit)
{
    h2_conn_ctx_t *conn_ctx;
    apr_status_t rv = APR_SUCCESS;
    const char *action = "init";

    rv = h2_conn_ctx_init_for_c2(&conn_ctx, c2, m, stream, transit);
    if (APR_SUCCESS != rv) goto cleanup;

    if (!conn_ctx->beam_out) {
        action = "create output beam";
        rv = h2_beam_create(&conn_ctx->beam_out, c2, conn_ctx->req_pool,
                            stream->id, "output", 0, c2->base_server->timeout);
        if (APR_SUCCESS != rv) goto cleanup;

        h2_beam_buffer_size_set(conn_ctx->beam_out, m->stream_max_mem);
        h2_beam_on_was_empty(conn_ctx->beam_out, c2_beam_output_write_notify, c2);
    }

    memset(&conn_ctx->pipe_in, 0, sizeof(conn_ctx->pipe_in));
    if (stream->input) {
        conn_ctx->beam_in = stream->input;
        h2_beam_on_send(stream->input, c2_beam_input_write_notify, c2);
        h2_beam_on_received(stream->input, c2_beam_input_read_notify, c2);
        h2_beam_on_consumed(stream->input, c1_input_consumed, stream);
#if H2_USE_PIPES
        action = "create input write pipe";
        rv = apr_file_pipe_create_pools(&conn_ctx->pipe_in[H2_PIPE_OUT],
                                        &conn_ctx->pipe_in[H2_PIPE_IN],
                                        APR_READ_BLOCK,
                                        c2->pool, c2->pool);
        if (APR_SUCCESS != rv) goto cleanup;
#endif
        h2_beam_on_eagain(stream->input, c2_beam_input_read_eagain, c2);
        if (!h2_beam_empty(stream->input))
            c2_beam_input_write_notify(c2, stream->input);
    }

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
    apr_status_t rv = APR_SUCCESS;
    apr_uint32_t sid;
    conn_rec *c2 = NULL;
    h2_c2_transit *transit = NULL;

    while (!m->aborted && !stream && (m->processing_count < m->processing_limit)
           && (sid = h2_iq_shift(m->q)) > 0) {
        stream = h2_ihash_get(m->streams, sid);
    }

    if (!stream) {
        if (m->processing_count >= m->processing_limit && !h2_iq_empty(m->q)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c1,
                          H2_MPLX_MSG(m, "delaying request processing. "
                          "Current limit is %d and %d workers are in use."),
                          m->processing_limit, m->processing_count);
        }
        goto cleanup;
    }

    if (sid > m->max_stream_id_started) {
        m->max_stream_id_started = sid;
    }

    transit = c2_transit_get(m);
#if AP_HAS_RESPONSE_BUCKETS
    c2 = ap_create_secondary_connection(transit->pool, m->c1, transit->bucket_alloc);
#else
    c2 = h2_c2_create(m->c1, transit->pool, transit->bucket_alloc);
#endif
    if (!c2) goto cleanup;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, m->c1,
                  H2_STRM_MSG(stream, "created new c2"));

    rv = c2_setup_io(m, c2, stream, transit);
    if (APR_SUCCESS != rv) goto cleanup;

    stream->c2 = c2;
    ++m->processing_count;

cleanup:
    if (APR_SUCCESS != rv && c2) {
        h2_c2_destroy(c2);
        c2 = NULL;
    }
    if (transit && !c2) {
        c2_transit_recycle(m, transit);
    }
    return c2;
}

static conn_rec *c2_prod_next(void *baton, int *phas_more)
{
    h2_mplx *m = baton;
    conn_rec *c = NULL;

    H2_MPLX_ENTER_ALWAYS(m);
    if (!m->aborted) {
        c = s_next_c2(m);
        *phas_more = (c != NULL && !h2_iq_empty(m->q));
    }
    H2_MPLX_LEAVE(m);
    return c;
}

static void s_c2_done(h2_mplx *m, conn_rec *c2, h2_conn_ctx_t *conn_ctx)
{
    h2_stream *stream;

    ap_assert(conn_ctx);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                  "h2_mplx(%s-%d): c2 done", conn_ctx->id, conn_ctx->stream_id);

    AP_DEBUG_ASSERT(apr_atomic_read32(&conn_ctx->done) == 0);
    apr_atomic_set32(&conn_ctx->done, 1);
    conn_ctx->done_at = apr_time_now();
    ++c2->keepalives;
    /* From here on, the final handling of c2 is done by c1 processing.
     * Which means we can give it c1's scoreboard handle for updates. */
    c2->sbh = m->c1->sbh;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c2,
                  "h2_mplx(%s-%d): request done, %f ms elapsed",
                  conn_ctx->id, conn_ctx->stream_id,
                  (conn_ctx->done_at - conn_ctx->started_at) / 1000.0);
    
    if (!conn_ctx->has_final_response) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, conn_ctx->last_err, c2,
                      "h2_c2(%s-%d): processing finished without final response",
                      conn_ctx->id, conn_ctx->stream_id);
        c2->aborted = 1;
        if (conn_ctx->beam_out)
          h2_beam_abort(conn_ctx->beam_out, c2);
    }
    else if (!conn_ctx->beam_out || !h2_beam_is_complete(conn_ctx->beam_out)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, conn_ctx->last_err, c2,
                      "h2_c2(%s-%d): processing finished with incomplete output",
                      conn_ctx->id, conn_ctx->stream_id);
        c2->aborted = 1;
        h2_beam_abort(conn_ctx->beam_out, c2);
    }
    else if (!c2->aborted) {
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

static void c2_prod_done(void *baton, conn_rec *c2)
{
    h2_mplx *m = baton;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c2);

    AP_DEBUG_ASSERT(conn_ctx);
    H2_MPLX_ENTER_ALWAYS(m);

    --m->processing_count;
    s_c2_done(m, c2, conn_ctx);
    if (m->join_wait) apr_thread_cond_signal(m->join_wait);

    H2_MPLX_LEAVE(m);
}

static void workers_shutdown(void *baton, int graceful)
{
    h2_mplx *m = baton;

    apr_thread_mutex_lock(m->poll_lock);
    /* time to wakeup and assess what to do */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                  H2_MPLX_MSG(m, "workers shutdown, waking pollset"));
    m->shutdown = 1;
    if (!graceful) {
        m->aborted = 1;
    }
    apr_pollset_wakeup(m->pollset);
    apr_thread_mutex_unlock(m->poll_lock);
}

/*******************************************************************************
 * h2_mplx DoS protection
 ******************************************************************************/

static void s_mplx_be_happy(h2_mplx *m, conn_rec *c, h2_conn_ctx_t *conn_ctx)
{
    apr_time_t now;            

    if (m->processing_limit < m->processing_max
        && conn_ctx->started_at > m->last_mood_change) {
        --m->irritations_since;
        if (m->processing_limit < m->processing_max
            && ((now = apr_time_now()) - m->last_mood_change >= m->mood_update_interval
                || m->irritations_since < -m->processing_limit)) {
            m->processing_limit = H2MIN(m->processing_limit * 2, m->processing_max);
            m->last_mood_change = now;
            m->irritations_since = 0;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                          H2_MPLX_MSG(m, "mood update, increasing worker limit to %d"),
                          m->processing_limit);
        }
    }
}

static void m_be_annoyed(h2_mplx *m)
{
    apr_time_t now;

    if (m->processing_limit > 2) {
        ++m->irritations_since;
        if (((now = apr_time_now()) - m->last_mood_change >= m->mood_update_interval)
            || (m->irritations_since >= m->processing_limit)) {

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
                          H2_MPLX_MSG(m, "mood update, decreasing worker limit to %d"),
                          m->processing_limit);
        }
    }
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

apr_status_t h2_mplx_c1_client_rst(h2_mplx *m, int stream_id, h2_stream *stream)
{
    apr_status_t status = APR_SUCCESS;
    int registered;

    H2_MPLX_ENTER_ALWAYS(m);
    registered = (h2_ihash_get(m->streams, stream_id) != NULL);
    if (!stream) {
      /* a RST might arrive so late, we have already forgotten
       * about it. Seems ok. */
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c1,
                    H2_MPLX_MSG(m, "RST on unknown stream %d"), stream_id);
      AP_DEBUG_ASSERT(!registered);
    }
    else if (!registered) {
      /* a RST on a stream that mplx has not been told about, but
       * which the session knows. Very early and annoying. */
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, m->c1,
                    H2_STRM_MSG(stream, "very early RST, drop"));
      h2_stream_set_monitor(stream, NULL);
      h2_stream_rst(stream, H2_ERR_STREAM_CLOSED);
      h2_stream_dispatch(stream, H2_SEV_EOS_SENT);
      m_stream_cleanup(m, stream);
      m_be_annoyed(m);
    }
    else if (!reset_is_acceptable(stream)) {
        m_be_annoyed(m);
    }
    H2_MPLX_LEAVE(m);
    return status;
}

static apr_status_t mplx_pollset_create(h2_mplx *m)
{
    /* stream0 output only */
    return apr_pollset_create(&m->pollset, 1, m->pool,
                              APR_POLLSET_WAKEABLE);
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
                      H2_MPLX_MSG(m, "enter polling timeout=%d"),
                      (int)apr_time_sec(timeout));

        apr_array_clear(m->streams_ev_in);
        apr_array_clear(m->streams_ev_out);

        do {
            /* add streams we started processing in the meantime */
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

            H2_MPLX_LEAVE(m);
            rv = apr_pollset_poll(m->pollset, timeout >= 0? timeout : -1, &nresults, &results);
            H2_MPLX_ENTER_ALWAYS(m);
            if (APR_STATUS_IS_EINTR(rv) && m->shutdown) {
                if (!m->aborted) {
                    rv = APR_SUCCESS;
                }
                goto cleanup;
            }
        } while (APR_STATUS_IS_EINTR(rv));

        if (APR_SUCCESS != rv) {
            if (APR_STATUS_IS_TIMEUP(rv)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                              H2_MPLX_MSG(m, "polling timed out "));
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, m->c1, APLOGNO(10310) \
                              H2_MPLX_MSG(m, "polling failed"));
            }
            goto cleanup;
        }

        for (i = 0; i < nresults; i++) {
            pfd = &results[i];
            conn_ctx = pfd->client_data;

            AP_DEBUG_ASSERT(conn_ctx);
            if (conn_ctx->stream_id == 0) {
                if (on_stream_input) {
                    APR_ARRAY_PUSH(m->streams_ev_in, h2_stream*) = m->stream0;
                }
                continue;
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

