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

#include <apr_lib.h>
#include <apr_atomic.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_buckets.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_util.h"
#include "h2_bucket_beam.h"

static void h2_beam_emitted(h2_bucket_beam *beam, h2_beam_proxy *proxy);

#define H2_BPROXY_NEXT(e)             APR_RING_NEXT((e), link)
#define H2_BPROXY_PREV(e)             APR_RING_PREV((e), link)
#define H2_BPROXY_REMOVE(e)           APR_RING_REMOVE((e), link)

#define H2_BPROXY_LIST_INIT(b)        APR_RING_INIT(&(b)->list, h2_beam_proxy, link);
#define H2_BPROXY_LIST_SENTINEL(b)    APR_RING_SENTINEL(&(b)->list, h2_beam_proxy, link)
#define H2_BPROXY_LIST_EMPTY(b)       APR_RING_EMPTY(&(b)->list, h2_beam_proxy, link)
#define H2_BPROXY_LIST_FIRST(b)       APR_RING_FIRST(&(b)->list)
#define H2_BPROXY_LIST_LAST(b)	      APR_RING_LAST(&(b)->list)
#define H2_PROXY_BLIST_INSERT_HEAD(b, e) do {				\
	h2_beam_proxy *ap__b = (e);                                        \
	APR_RING_INSERT_HEAD(&(b)->list, ap__b, h2_beam_proxy, link);	\
    } while (0)
#define H2_BPROXY_LIST_INSERT_TAIL(b, e) do {				\
	h2_beam_proxy *ap__b = (e);					\
	APR_RING_INSERT_TAIL(&(b)->list, ap__b, h2_beam_proxy, link);	\
    } while (0)
#define H2_BPROXY_LIST_CONCAT(a, b) do {					\
        APR_RING_CONCAT(&(a)->list, &(b)->list, h2_beam_proxy, link);	\
    } while (0)
#define H2_BPROXY_LIST_PREPEND(a, b) do {					\
        APR_RING_PREPEND(&(a)->list, &(b)->list, h2_beam_proxy, link);	\
    } while (0)


/*******************************************************************************
 * beam bucket with reference to beam and bucket it represents
 ******************************************************************************/

const apr_bucket_type_t h2_bucket_type_beam;

#define H2_BUCKET_IS_BEAM(e)     (e->type == &h2_bucket_type_beam)

struct h2_beam_proxy {
    apr_bucket_refcount refcount;
    APR_RING_ENTRY(h2_beam_proxy) link;
    h2_bucket_beam *beam;
    apr_bucket *bsender;
    apr_size_t n;
};

static const char Dummy = '\0';

static apr_status_t beam_bucket_read(apr_bucket *b, const char **str, 
                                     apr_size_t *len, apr_read_type_e block)
{
    h2_beam_proxy *d = b->data;
    if (d->bsender) {
        const char *data;
        apr_status_t status = apr_bucket_read(d->bsender, &data, len, block);
        if (status == APR_SUCCESS) {
            *str = data + b->start;
            *len = b->length;
        }
        return status;
    }
    *str = &Dummy;
    *len = 0;
    return APR_ECONNRESET;
}

static void beam_bucket_destroy(void *data)
{
    h2_beam_proxy *d = data;

    if (apr_bucket_shared_destroy(d)) {
        /* When the beam gets destroyed before this bucket, it will
         * NULLify its reference here. This is not protected by a mutex,
         * so it will not help with race conditions.
         * But it lets us shut down memory pool with circulare beam
         * references. */
        if (d->beam) {
            h2_beam_emitted(d->beam, d);
        }
        apr_bucket_free(d);
    }
}

static apr_bucket * h2_beam_bucket_make(apr_bucket *b, 
                                        h2_bucket_beam *beam,
                                        apr_bucket *bsender, apr_size_t n)
{
    h2_beam_proxy *d;

    d = apr_bucket_alloc(sizeof(*d), b->list);
    H2_BPROXY_LIST_INSERT_TAIL(&beam->proxies, d);
    d->beam = beam;
    d->bsender = bsender;
    d->n = n;
    
    b = apr_bucket_shared_make(b, d, 0, bsender? bsender->length : 0);
    b->type = &h2_bucket_type_beam;

    return b;
}

static apr_bucket *h2_beam_bucket_create(h2_bucket_beam *beam,
                                         apr_bucket *bsender,
                                         apr_bucket_alloc_t *list,
                                         apr_size_t n)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return h2_beam_bucket_make(b, beam, bsender, n);
}

const apr_bucket_type_t h2_bucket_type_beam = {
    "BEAM", 5, APR_BUCKET_DATA,
    beam_bucket_destroy,
    beam_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_shared_split,
    apr_bucket_shared_copy
};

/*******************************************************************************
 * h2_blist, a brigade without allocations
 ******************************************************************************/

static apr_array_header_t *beamers;

static apr_status_t cleanup_beamers(void *dummy)
{
    (void)dummy;
    beamers = NULL;
    return APR_SUCCESS;
}

void h2_register_bucket_beamer(h2_bucket_beamer *beamer)
{
    if (!beamers) {
        apr_pool_cleanup_register(apr_hook_global_pool, NULL,
                                  cleanup_beamers, apr_pool_cleanup_null);
        beamers = apr_array_make(apr_hook_global_pool, 10, 
                                 sizeof(h2_bucket_beamer*));
    }
    APR_ARRAY_PUSH(beamers, h2_bucket_beamer*) = beamer;
}

static apr_bucket *h2_beam_bucket(h2_bucket_beam *beam, 
                                  apr_bucket_brigade *dest,
                                  const apr_bucket *src)
{
    apr_bucket *b = NULL;
    int i;
    if (beamers) {
        for (i = 0; i < beamers->nelts && b == NULL; ++i) {
            h2_bucket_beamer *beamer;
            
            beamer = APR_ARRAY_IDX(beamers, i, h2_bucket_beamer*);
            b = beamer(beam, dest, src);
        }
    }
    return b;
}


/*******************************************************************************
 * bucket beam that can transport buckets across threads
 ******************************************************************************/

static apr_status_t enter_yellow(h2_bucket_beam *beam, h2_beam_lock *pbl)
{
    h2_beam_mutex_enter *enter = beam->m_enter;
    if (enter) {
        void *ctx = beam->m_ctx;
        if (ctx) {
            return enter(ctx, pbl);
        }
    }
    pbl->mutex = NULL;
    pbl->leave = NULL;
    return APR_SUCCESS;
}

static void leave_yellow(h2_bucket_beam *beam, h2_beam_lock *pbl)
{
    if (pbl->leave) {
        pbl->leave(pbl->leave_ctx, pbl->mutex);
    }
}

static apr_off_t bucket_mem_used(apr_bucket *b)
{
    if (APR_BUCKET_IS_FILE(b)) {
        return 0;
    }
    else {
        /* should all have determinate length */
        return b->length;
    }
}

static int report_consumption(h2_bucket_beam *beam)
{
    int rv = 0;
    if (apr_atomic_read32(&beam->cons_ev_pending)) {
        if (beam->cons_io_cb) { 
            beam->cons_io_cb(beam->cons_ctx, beam, beam->received_bytes
                             - beam->cons_bytes_reported);
            rv = 1;
        }
        beam->cons_bytes_reported = beam->received_bytes;
        apr_atomic_set32(&beam->cons_ev_pending, 0);
    }
    return rv;
}

static void report_prod_io(h2_bucket_beam *beam, int force)
{
    if (force || beam->prod_bytes_reported != beam->sent_bytes) {
        if (beam->prod_io_cb) { 
            beam->prod_io_cb(beam->prod_ctx, beam, beam->sent_bytes
                             - beam->prod_bytes_reported);
        }
        beam->prod_bytes_reported = beam->sent_bytes;
    }
}

static apr_size_t calc_buffered(h2_bucket_beam *beam)
{
    apr_size_t len = 0;
    apr_bucket *b;
    for (b = H2_BLIST_FIRST(&beam->send_list); 
         b != H2_BLIST_SENTINEL(&beam->send_list);
         b = APR_BUCKET_NEXT(b)) {
        if (b->length == ((apr_size_t)-1)) {
            /* do not count */
        }
        else if (APR_BUCKET_IS_FILE(b)) {
            /* if unread, has no real mem footprint. how to test? */
        }
        else {
            len += b->length;
        }
    }
    return len;
}

static void r_purge_sent(h2_bucket_beam *beam)
{
    apr_bucket *b;
    /* delete all sender buckets in purge brigade, needs to be called
     * from sender thread only */
    while (!H2_BLIST_EMPTY(&beam->purge_list)) {
        b = H2_BLIST_FIRST(&beam->purge_list);
        apr_bucket_delete(b);
    }
}

static apr_size_t calc_space_left(h2_bucket_beam *beam)
{
    if (beam->max_buf_size > 0) {
        apr_off_t len = calc_buffered(beam);
        return (beam->max_buf_size > len? (beam->max_buf_size - len) : 0);
    }
    return APR_SIZE_MAX;
}

static apr_status_t wait_cond(h2_bucket_beam *beam, apr_thread_mutex_t *lock)
{
    if (beam->timeout > 0) {
        return apr_thread_cond_timedwait(beam->m_cond, lock, beam->timeout);
    }
    else {
        return apr_thread_cond_wait(beam->m_cond, lock);
    }
}

static apr_status_t r_wait_space(h2_bucket_beam *beam, apr_read_type_e block,
                                 h2_beam_lock *pbl, apr_size_t *premain) 
{
    *premain = calc_space_left(beam);
    while (!beam->aborted && *premain <= 0 
           && (block == APR_BLOCK_READ) && pbl->mutex) {
        apr_status_t status;
        report_prod_io(beam, 1);
        status = wait_cond(beam, pbl->mutex);
        if (APR_STATUS_IS_TIMEUP(status)) {
            return status;
        }
        r_purge_sent(beam);
        *premain = calc_space_left(beam);
    }
    return beam->aborted? APR_ECONNABORTED : APR_SUCCESS;
}

static void h2_beam_emitted(h2_bucket_beam *beam, h2_beam_proxy *proxy)
{
    h2_beam_lock bl;
    apr_bucket *b, *next;

    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        /* even when beam buckets are split, only the one where
         * refcount drops to 0 will call us */
        H2_BPROXY_REMOVE(proxy);
        /* invoked from receiver thread, the last beam bucket for the send
         * bucket is about to be destroyed.
         * remove it from the hold, where it should be now */
        if (proxy->bsender) {
            for (b = H2_BLIST_FIRST(&beam->hold_list); 
                 b != H2_BLIST_SENTINEL(&beam->hold_list);
                 b = APR_BUCKET_NEXT(b)) {
                 if (b == proxy->bsender) {
                    break;
                 }
            }
            if (b != H2_BLIST_SENTINEL(&beam->hold_list)) {
                /* bucket is in hold as it should be, mark this one
                 * and all before it for purging. We might have placed meta
                 * buckets without a receiver proxy into the hold before it 
                 * and schedule them for purging now */
                for (b = H2_BLIST_FIRST(&beam->hold_list); 
                     b != H2_BLIST_SENTINEL(&beam->hold_list);
                     b = next) {
                    next = APR_BUCKET_NEXT(b);
                    if (b == proxy->bsender) {
                        APR_BUCKET_REMOVE(b);
                        H2_BLIST_INSERT_TAIL(&beam->purge_list, b);
                        break;
                    }
                    else if (APR_BUCKET_IS_METADATA(b)) {
                        APR_BUCKET_REMOVE(b);
                        H2_BLIST_INSERT_TAIL(&beam->purge_list, b);
                    }
                    else {
                        /* another data bucket before this one in hold. this
                         * is normal since DATA buckets need not be destroyed
                         * in order */
                    }
                }
                
                proxy->bsender = NULL;
            }
            else {
                /* it should be there unless we screwed up */
                ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, beam->send_pool, 
                              APLOGNO(03384) "h2_beam(%d-%s): emitted bucket not "
                              "in hold, n=%d", beam->id, beam->tag, 
                              (int)proxy->n);
                ap_assert(!proxy->bsender);
            }
        }
        /* notify anyone waiting on space to become available */
        if (!bl.mutex) {
            r_purge_sent(beam);
        }
        else if (beam->m_cond) {
            apr_thread_cond_broadcast(beam->m_cond);
        }
        leave_yellow(beam, &bl);
    }
}

static void h2_blist_cleanup(h2_blist *bl)
{
    apr_bucket *e;

    while (!H2_BLIST_EMPTY(bl)) {
        e = H2_BLIST_FIRST(bl);
        apr_bucket_delete(e);
    }
}

static apr_status_t beam_close(h2_bucket_beam *beam)
{
    if (!beam->closed) {
        beam->closed = 1;
        if (beam->m_cond) {
            apr_thread_cond_broadcast(beam->m_cond);
        }
    }
    return APR_SUCCESS;
}

int h2_beam_is_closed(h2_bucket_beam *beam)
{
    return beam->closed;
}

static int pool_register(h2_bucket_beam *beam, apr_pool_t *pool, 
                         apr_status_t (*cleanup)(void *))
{
    if (pool && pool != beam->pool) {
        apr_pool_pre_cleanup_register(pool, beam, cleanup);
        return 1;
    }
    return 0;
}

static int pool_kill(h2_bucket_beam *beam, apr_pool_t *pool,
                     apr_status_t (*cleanup)(void *)) {
    if (pool && pool != beam->pool) {
        apr_pool_cleanup_kill(pool, beam, cleanup);
        return 1;
    }
    return 0;
}

static apr_status_t beam_recv_cleanup(void *data)
{
    h2_bucket_beam *beam = data;
    /* receiver pool has gone away, clear references */
    beam->recv_buffer = NULL;
    beam->recv_pool = NULL;
    return APR_SUCCESS;
}

static apr_status_t beam_send_cleanup(void *data)
{
    h2_bucket_beam *beam = data;
    /* sender is going away, clear up all references to its memory */
    r_purge_sent(beam);
    h2_blist_cleanup(&beam->send_list);
    report_consumption(beam);
    while (!H2_BPROXY_LIST_EMPTY(&beam->proxies)) {
        h2_beam_proxy *proxy = H2_BPROXY_LIST_FIRST(&beam->proxies);
        H2_BPROXY_REMOVE(proxy);
        proxy->beam = NULL;
        proxy->bsender = NULL;
    }
    h2_blist_cleanup(&beam->purge_list);
    h2_blist_cleanup(&beam->hold_list);
    beam->send_pool = NULL;
    return APR_SUCCESS;
}

static void beam_set_send_pool(h2_bucket_beam *beam, apr_pool_t *pool) 
{
    if (beam->send_pool == pool || 
        (beam->send_pool && pool 
         && apr_pool_is_ancestor(beam->send_pool, pool))) {
        /* when sender is same or sub-pool of existing, stick
         * to the the pool we already have. */
        return;
    }
    pool_kill(beam, beam->send_pool, beam_send_cleanup);
    beam->send_pool = pool;
    pool_register(beam, beam->send_pool, beam_send_cleanup);
}

static apr_status_t beam_cleanup(void *data)
{
    h2_bucket_beam *beam = data;
    apr_status_t status = APR_SUCCESS;
    int safe_send = !beam->m_enter || (beam->owner == H2_BEAM_OWNER_SEND);
    int safe_recv = !beam->m_enter || (beam->owner == H2_BEAM_OWNER_RECV);
    
    /* 
     * Owner of the beam is going away, depending on which side it owns,
     * cleanup strategies will differ with multi-thread protection
     * still in place (beam->m_enter).
     *
     * In general, receiver holds references to memory from sender. 
     * Clean up receiver first, if safe, then cleanup sender, if safe.
     */
     
    /* When modify send is not safe, this means we still have multi-thread
     * protection and the owner is receiving the buckets. If the sending
     * side has not gone away, this means we could have dangling buckets
     * in our lists that never get destroyed. This should not happen. */
    ap_assert(safe_send || !beam->send_pool);
    if (!H2_BLIST_EMPTY(&beam->send_list)) {
        ap_assert(beam->send_pool);
    }
    
    if (safe_recv) {
        if (beam->recv_pool) {
            pool_kill(beam, beam->recv_pool, beam_recv_cleanup);
            beam->recv_pool = NULL;
        }
        if (beam->recv_buffer) {
            apr_brigade_destroy(beam->recv_buffer);
            beam->recv_buffer = NULL;
        }
    }
    else {
        beam->recv_buffer = NULL;
        beam->recv_pool = NULL;
    }
    
    if (safe_send && beam->send_pool) {
        pool_kill(beam, beam->send_pool, beam_send_cleanup);
        status = beam_send_cleanup(beam);
    }
    
    if (safe_recv) {
        ap_assert(H2_BPROXY_LIST_EMPTY(&beam->proxies));
        ap_assert(H2_BLIST_EMPTY(&beam->send_list));
        ap_assert(H2_BLIST_EMPTY(&beam->hold_list));
        ap_assert(H2_BLIST_EMPTY(&beam->purge_list));
    }
    return status;
}

apr_status_t h2_beam_destroy(h2_bucket_beam *beam)
{
    apr_pool_cleanup_kill(beam->pool, beam, beam_cleanup);
    return beam_cleanup(beam);
}

apr_status_t h2_beam_create(h2_bucket_beam **pbeam, apr_pool_t *pool, 
                            int id, const char *tag, 
                            h2_beam_owner_t owner,
                            apr_size_t max_buf_size)
{
    h2_bucket_beam *beam;
    apr_status_t status = APR_SUCCESS;
    
    beam = apr_pcalloc(pool, sizeof(*beam));
    if (!beam) {
        return APR_ENOMEM;
    }

    beam->id = id;
    beam->tag = tag;
    beam->pool = pool;
    beam->owner = owner;
    H2_BLIST_INIT(&beam->send_list);
    H2_BLIST_INIT(&beam->hold_list);
    H2_BLIST_INIT(&beam->purge_list);
    H2_BPROXY_LIST_INIT(&beam->proxies);
    beam->tx_mem_limits = 1;
    beam->max_buf_size = max_buf_size;
    apr_pool_pre_cleanup_register(pool, beam, beam_cleanup);

    *pbeam = beam;
    
    return status;
}

void h2_beam_buffer_size_set(h2_bucket_beam *beam, apr_size_t buffer_size)
{
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        beam->max_buf_size = buffer_size;
        leave_yellow(beam, &bl);
    }
}

apr_size_t h2_beam_buffer_size_get(h2_bucket_beam *beam)
{
    h2_beam_lock bl;
    apr_size_t buffer_size = 0;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        buffer_size = beam->max_buf_size;
        leave_yellow(beam, &bl);
    }
    return buffer_size;
}

void h2_beam_mutex_set(h2_bucket_beam *beam, 
                       h2_beam_mutex_enter m_enter,
                       apr_thread_cond_t *cond,
                       void *m_ctx)
{
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        beam->m_enter = m_enter;
        beam->m_ctx   = m_ctx;
        beam->m_cond  = cond;
        leave_yellow(beam, &bl);
    }
}

void h2_beam_timeout_set(h2_bucket_beam *beam, apr_interval_time_t timeout)
{
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        beam->timeout = timeout;
        leave_yellow(beam, &bl);
    }
}

apr_interval_time_t h2_beam_timeout_get(h2_bucket_beam *beam)
{
    h2_beam_lock bl;
    apr_interval_time_t timeout = 0;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        timeout = beam->timeout;
        leave_yellow(beam, &bl);
    }
    return timeout;
}

void h2_beam_abort(h2_bucket_beam *beam)
{
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        if (!beam->aborted) {
            beam->aborted = 1;
            r_purge_sent(beam);
            h2_blist_cleanup(&beam->send_list);
            report_consumption(beam);
        }
        if (beam->m_cond) {
            apr_thread_cond_broadcast(beam->m_cond);
        }
        leave_yellow(beam, &bl);
    }
}

apr_status_t h2_beam_close(h2_bucket_beam *beam)
{
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        r_purge_sent(beam);
        beam_close(beam);
        report_consumption(beam);
        leave_yellow(beam, &bl);
    }
    return beam->aborted? APR_ECONNABORTED : APR_SUCCESS;
}

apr_status_t h2_beam_leave(h2_bucket_beam *beam)
{
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        if (beam->recv_buffer && !APR_BRIGADE_EMPTY(beam->recv_buffer)) {
            apr_brigade_cleanup(beam->recv_buffer);
        }
        beam->aborted = 1;
        beam_close(beam);
        leave_yellow(beam, &bl);
    }
    return APR_SUCCESS;
}

apr_status_t h2_beam_wait_empty(h2_bucket_beam *beam, apr_read_type_e block)
{
    apr_status_t status;
    h2_beam_lock bl;
    
    if ((status = enter_yellow(beam, &bl)) == APR_SUCCESS) {
        while (status == APR_SUCCESS
               && !H2_BLIST_EMPTY(&beam->send_list)
               && !H2_BPROXY_LIST_EMPTY(&beam->proxies)) {
            if (block == APR_NONBLOCK_READ || !bl.mutex) {
                status = APR_EAGAIN;
                break;
            }
            if (beam->m_cond) {
                apr_thread_cond_broadcast(beam->m_cond);
            }
            status = wait_cond(beam, bl.mutex);
        }
        leave_yellow(beam, &bl);
    }
    return status;
}

static void move_to_hold(h2_bucket_beam *beam, 
                         apr_bucket_brigade *sender_bb)
{
    apr_bucket *b;
    while (sender_bb && !APR_BRIGADE_EMPTY(sender_bb)) {
        b = APR_BRIGADE_FIRST(sender_bb);
        APR_BUCKET_REMOVE(b);
        H2_BLIST_INSERT_TAIL(&beam->send_list, b);
    }
}

static apr_status_t append_bucket(h2_bucket_beam *beam, 
                                  apr_bucket *b,
                                  apr_read_type_e block,
                                  h2_beam_lock *pbl)
{
    const char *data;
    apr_size_t len;
    apr_size_t space_left = 0;
    apr_status_t status;
    
    if (APR_BUCKET_IS_METADATA(b)) {
        if (APR_BUCKET_IS_EOS(b)) {
            beam->closed = 1;
        }
        APR_BUCKET_REMOVE(b);
        H2_BLIST_INSERT_TAIL(&beam->send_list, b);
        return APR_SUCCESS;
    }
    else if (APR_BUCKET_IS_FILE(b)) {
        /* file bucket lengths do not really count */
    }
    else {
        space_left = calc_space_left(beam);
        if (space_left > 0 && b->length == ((apr_size_t)-1)) {
            const char *data;
            status = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
            if (status != APR_SUCCESS) {
                return status;
            }
        }
        
        if (space_left <= 0) {
            status = r_wait_space(beam, block, pbl, &space_left);
            if (status != APR_SUCCESS) {
                return status;
            }
            if (space_left <= 0) {
                return APR_EAGAIN;
            }
        }
        /* space available, maybe need bucket split */
    }
    

    /* The fundamental problem is that reading a sender bucket from
     * a receiver thread is a total NO GO, because the bucket might use
     * its pool/bucket_alloc from a foreign thread and that will
     * corrupt. */
    status = APR_ENOTIMPL;
    if (APR_BUCKET_IS_TRANSIENT(b)) {
        /* this takes care of transient buckets and converts them
         * into heap ones. Other bucket types might or might not be
         * affected by this. */
        status = apr_bucket_setaside(b, beam->send_pool);
    }
    else if (APR_BUCKET_IS_HEAP(b)) {
        /* For heap buckets read from a receiver thread is fine. The
         * data will be there and live until the bucket itself is
         * destroyed. */
        status = APR_SUCCESS;
    }
    else if (APR_BUCKET_IS_POOL(b)) {
        /* pool buckets are bastards that register at pool cleanup
         * to morph themselves into heap buckets. That may happen anytime,
         * even after the bucket data pointer has been read. So at
         * any time inside the receiver thread, the pool bucket memory
         * may disappear. yikes. */
        status = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (status == APR_SUCCESS) {
            apr_bucket_heap_make(b, data, len, NULL);
        }
    }
    else if (APR_BUCKET_IS_FILE(b)) {
        /* For file buckets the problem is their internal readpool that
         * is used on the first read to allocate buffer/mmap.
         * Since setting aside a file bucket will de-register the
         * file cleanup function from the previous pool, we need to
         * call that only from the sender thread.
         *
         * Currently, we do not handle file bucket with refcount > 1 as
         * the beam is then not in complete control of the file's lifetime.
         * Which results in the bug that a file get closed by the receiver
         * while the sender or the beam still have buckets using it. 
         * 
         * Additionally, we allow callbacks to prevent beaming file
         * handles across. The use case for this is to limit the number 
         * of open file handles and rather use a less efficient beam
         * transport. */
        apr_bucket_file *bf = b->data;
        apr_file_t *fd = bf->fd;
        int can_beam = (bf->refcount.refcount == 1);
        if (can_beam && beam->last_beamed != fd && beam->can_beam_fn) {
            can_beam = beam->can_beam_fn(beam->can_beam_ctx, beam, fd);
        }
        if (can_beam) {
            beam->last_beamed = fd;
            status = apr_bucket_setaside(b, beam->send_pool);
        }
        /* else: enter ENOTIMPL case below */
    }
    
    if (status == APR_ENOTIMPL) {
        /* we have no knowledge about the internals of this bucket,
         * but hope that after read, its data stays immutable for the
         * lifetime of the bucket. (see pool bucket handling above for
         * a counter example).
         * We do the read while in the sender thread, so that the bucket may
         * use pools/allocators safely. */
        if (space_left < APR_BUCKET_BUFF_SIZE) {
            space_left = APR_BUCKET_BUFF_SIZE;
        }
        if (space_left < b->length) {
            apr_bucket_split(b, space_left);
        }
        status = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (status == APR_SUCCESS) {
            status = apr_bucket_setaside(b, beam->send_pool);
        }
    }
    
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        return status;
    }
    
    APR_BUCKET_REMOVE(b);
    H2_BLIST_INSERT_TAIL(&beam->send_list, b);
    beam->sent_bytes += b->length;
    
    return APR_SUCCESS;
}

void h2_beam_send_from(h2_bucket_beam *beam, apr_pool_t *p)
{
    h2_beam_lock bl;
    /* Called from the sender thread to add buckets to the beam */
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        r_purge_sent(beam);
        beam_set_send_pool(beam, p);
        leave_yellow(beam, &bl);
    }
}

apr_status_t h2_beam_send(h2_bucket_beam *beam, 
                          apr_bucket_brigade *sender_bb, 
                          apr_read_type_e block)
{
    apr_bucket *b;
    apr_status_t status = APR_SUCCESS;
    h2_beam_lock bl;

    /* Called from the sender thread to add buckets to the beam */
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        r_purge_sent(beam);
        if (sender_bb && !beam->send_pool) {
            beam_set_send_pool(beam, sender_bb->p);
        }
        
        if (beam->aborted) {
            move_to_hold(beam, sender_bb);
            status = APR_ECONNABORTED;
        }
        else if (sender_bb) {
            int force_report = !APR_BRIGADE_EMPTY(sender_bb); 
            while (!APR_BRIGADE_EMPTY(sender_bb) && status == APR_SUCCESS) {
                b = APR_BRIGADE_FIRST(sender_bb);
                status = append_bucket(beam, b, block, &bl);
            }
            report_prod_io(beam, force_report);
            if (beam->m_cond) {
                apr_thread_cond_broadcast(beam->m_cond);
            }
        }
        report_consumption(beam);
        leave_yellow(beam, &bl);
    }
    return status;
}

apr_status_t h2_beam_receive(h2_bucket_beam *beam, 
                             apr_bucket_brigade *bb, 
                             apr_read_type_e block,
                             apr_off_t readbytes)
{
    h2_beam_lock bl;
    apr_bucket *bsender, *brecv, *ng;
    int transferred = 0;
    apr_status_t status = APR_SUCCESS;
    apr_off_t remain = readbytes;
    int transferred_buckets = 0;
    
    /* Called from the receiver thread to take buckets from the beam */
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
transfer:
        if (beam->aborted) {
            if (beam->recv_buffer && !APR_BRIGADE_EMPTY(beam->recv_buffer)) {
                apr_brigade_cleanup(beam->recv_buffer);
            }
            status = APR_ECONNABORTED;
            goto leave;
        }

        /* transfer enough buckets from our receiver brigade, if we have one */
        while (beam->recv_buffer
               && !APR_BRIGADE_EMPTY(beam->recv_buffer)
               && (readbytes <= 0 || remain >= 0)) {
            brecv = APR_BRIGADE_FIRST(beam->recv_buffer);
            if (readbytes > 0 && brecv->length > 0 && remain <= 0) {
                break;
            }            
            APR_BUCKET_REMOVE(brecv);
            APR_BRIGADE_INSERT_TAIL(bb, brecv);
            remain -= brecv->length;
            ++transferred;
        }

        /* transfer from our sender brigade, transforming sender buckets to
         * receiver ones until we have enough */
        while (!H2_BLIST_EMPTY(&beam->send_list) && (readbytes <= 0 || remain >= 0)) {
            bsender = H2_BLIST_FIRST(&beam->send_list);
            brecv = NULL;
            
            if (readbytes > 0 && bsender->length > 0 && remain <= 0) {
                break;
            }
                        
            if (APR_BUCKET_IS_METADATA(bsender)) {
                if (APR_BUCKET_IS_EOS(bsender)) {
                    brecv = apr_bucket_eos_create(bb->bucket_alloc);
                    beam->close_sent = 1;
                }
                else if (APR_BUCKET_IS_FLUSH(bsender)) {
                    brecv = apr_bucket_flush_create(bb->bucket_alloc);
                }
                else if (AP_BUCKET_IS_ERROR(bsender)) {
                    ap_bucket_error *eb = (ap_bucket_error *)bsender;
                    brecv = ap_bucket_error_create(eb->status, eb->data,
                                                    bb->p, bb->bucket_alloc);
                }
            }
            else if (APR_BUCKET_IS_FILE(bsender)) {
                /* This is set aside into the target brigade pool so that 
                 * any read operation messes with that pool and not 
                 * the sender one. */
                apr_bucket_file *f = (apr_bucket_file *)bsender->data;
                apr_file_t *fd = f->fd;
                int setaside = (f->readpool != bb->p);
                
                if (setaside) {
                    status = apr_file_setaside(&fd, fd, bb->p);
                    if (status != APR_SUCCESS) {
                        goto leave;
                    }
                    ++beam->files_beamed;
                }
                ng = apr_brigade_insert_file(bb, fd, bsender->start, bsender->length, 
                                             bb->p);
#if APR_HAS_MMAP
                /* disable mmap handling as this leads to segfaults when
                 * the underlying file is changed while memory pointer has
                 * been handed out. See also PR 59348 */
                apr_bucket_file_enable_mmap(ng, 0);
#endif
                remain -= bsender->length;
                ++transferred;
                APR_BUCKET_REMOVE(bsender);
                H2_BLIST_INSERT_TAIL(&beam->hold_list, bsender);
                ++transferred;
                continue;
            }
            else {
                /* create a "receiver" standin bucket. we took care about the
                 * underlying sender bucket and its data when we placed it into
                 * the sender brigade.
                 * the beam bucket will notify us on destruction that bsender is
                 * no longer needed. */
                brecv = h2_beam_bucket_create(beam, bsender, bb->bucket_alloc,
                                               beam->buckets_sent++);
            }
            
            /* Place the sender bucket into our hold, to be destroyed when no
             * receiver bucket references it any more. */
            APR_BUCKET_REMOVE(bsender);
            H2_BLIST_INSERT_TAIL(&beam->hold_list, bsender);
            beam->received_bytes += bsender->length;
            ++transferred_buckets;
            
            if (brecv) {
                APR_BRIGADE_INSERT_TAIL(bb, brecv);
                remain -= brecv->length;
                ++transferred;
            }
            else {
                brecv = h2_beam_bucket(beam, bb, bsender);
                while (brecv && brecv != APR_BRIGADE_SENTINEL(bb)) {
                    ++transferred;
                    remain -= brecv->length;
                    brecv = APR_BUCKET_NEXT(brecv);
                }
            }
        }

        if (readbytes > 0 && remain < 0) {
            /* too much, put some back */
            remain = readbytes;
            for (brecv = APR_BRIGADE_FIRST(bb);
                 brecv != APR_BRIGADE_SENTINEL(bb);
                 brecv = APR_BUCKET_NEXT(brecv)) {
                remain -= (beam->tx_mem_limits? bucket_mem_used(brecv) 
                           : brecv->length);
                if (remain < 0) {
                    apr_bucket_split(brecv, brecv->length+remain);
                    beam->recv_buffer = apr_brigade_split_ex(bb, 
                                                             APR_BUCKET_NEXT(brecv), 
                                                             beam->recv_buffer);
                    break;
                }
            }
        }

        if (transferred_buckets > 0) {
           apr_atomic_set32(&beam->cons_ev_pending, 1);
           if (beam->cons_ev_cb) { 
               beam->cons_ev_cb(beam->cons_ctx, beam);
            }
        }
        
        if (beam->closed 
            && (!beam->recv_buffer || APR_BRIGADE_EMPTY(beam->recv_buffer))
            && H2_BLIST_EMPTY(&beam->send_list)) {
            /* beam is closed and we have nothing more to receive */ 
            if (!beam->close_sent) {
                apr_bucket *b = apr_bucket_eos_create(bb->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, b);
                beam->close_sent = 1;
                ++transferred;
                status = APR_SUCCESS;
            }
        }
        
        if (transferred) {
            if (beam->m_cond) {
                apr_thread_cond_broadcast(beam->m_cond);
            }
            status = APR_SUCCESS;
        }
        else if (beam->closed) {
            status = APR_EOF;
        }
        else if (block == APR_BLOCK_READ && bl.mutex && beam->m_cond) {
            status = wait_cond(beam, bl.mutex);
            if (status != APR_SUCCESS) {
                goto leave;
            }
            goto transfer;
        }
        else {
            if (beam->m_cond) {
                apr_thread_cond_broadcast(beam->m_cond);
            }
            status = APR_EAGAIN;
        }
leave:        
        leave_yellow(beam, &bl);
    }
    return status;
}

void h2_beam_on_consumed(h2_bucket_beam *beam, 
                         h2_beam_ev_callback *ev_cb,
                         h2_beam_io_callback *io_cb, void *ctx)
{
    h2_beam_lock bl;
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        beam->cons_ev_cb = ev_cb;
        beam->cons_io_cb = io_cb;
        beam->cons_ctx = ctx;
        leave_yellow(beam, &bl);
    }
}

void h2_beam_on_produced(h2_bucket_beam *beam, 
                         h2_beam_io_callback *io_cb, void *ctx)
{
    h2_beam_lock bl;
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        beam->prod_io_cb = io_cb;
        beam->prod_ctx = ctx;
        leave_yellow(beam, &bl);
    }
}

void h2_beam_on_file_beam(h2_bucket_beam *beam, 
                          h2_beam_can_beam_callback *cb, void *ctx)
{
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        beam->can_beam_fn = cb;
        beam->can_beam_ctx = ctx;
        leave_yellow(beam, &bl);
    }
}


apr_off_t h2_beam_get_buffered(h2_bucket_beam *beam)
{
    apr_bucket *b;
    apr_off_t l = 0;
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        for (b = H2_BLIST_FIRST(&beam->send_list); 
            b != H2_BLIST_SENTINEL(&beam->send_list);
            b = APR_BUCKET_NEXT(b)) {
            /* should all have determinate length */
            l += b->length;
        }
        leave_yellow(beam, &bl);
    }
    return l;
}

apr_off_t h2_beam_get_mem_used(h2_bucket_beam *beam)
{
    apr_bucket *b;
    apr_off_t l = 0;
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        for (b = H2_BLIST_FIRST(&beam->send_list); 
            b != H2_BLIST_SENTINEL(&beam->send_list);
            b = APR_BUCKET_NEXT(b)) {
            l += bucket_mem_used(b);
        }
        leave_yellow(beam, &bl);
    }
    return l;
}

int h2_beam_empty(h2_bucket_beam *beam)
{
    int empty = 1;
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        empty = (H2_BLIST_EMPTY(&beam->send_list) 
                 && (!beam->recv_buffer || APR_BRIGADE_EMPTY(beam->recv_buffer)));
        leave_yellow(beam, &bl);
    }
    return empty;
}

int h2_beam_holds_proxies(h2_bucket_beam *beam)
{
    int has_proxies = 1;
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        has_proxies = !H2_BPROXY_LIST_EMPTY(&beam->proxies);
        leave_yellow(beam, &bl);
    }
    return has_proxies;
}

int h2_beam_was_received(h2_bucket_beam *beam)
{
    int happend = 0;
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        happend = (beam->received_bytes > 0);
        leave_yellow(beam, &bl);
    }
    return happend;
}

apr_size_t h2_beam_get_files_beamed(h2_bucket_beam *beam)
{
    apr_size_t n = 0;
    h2_beam_lock bl;
    
    if (enter_yellow(beam, &bl) == APR_SUCCESS) {
        n = beam->files_beamed;
        leave_yellow(beam, &bl);
    }
    return n;
}

int h2_beam_no_files(void *ctx, h2_bucket_beam *beam, apr_file_t *file)
{
    return 0;
}

int h2_beam_report_consumption(h2_bucket_beam *beam)
{
    if (apr_atomic_read32(&beam->cons_ev_pending)) {
        h2_beam_lock bl;
        if (enter_yellow(beam, &bl) == APR_SUCCESS) {
            int rv = report_consumption(beam);
            leave_yellow(beam, &bl);
            return rv;
        }
    }
    return 0;
}

void h2_beam_log(h2_bucket_beam *beam, conn_rec *c, int level, const char *msg)
{
    if (beam && APLOG_C_IS_LEVEL(c,level)) {
        ap_log_cerror(APLOG_MARK, level, 0, c, 
                      "beam(%ld-%d,%s,closed=%d,aborted=%d,empty=%d,buf=%ld): %s", 
                      c->id, beam->id, beam->tag, beam->closed, beam->aborted, 
                      h2_beam_empty(beam), (long)h2_beam_get_buffered(beam),
                      msg);
    }
}


